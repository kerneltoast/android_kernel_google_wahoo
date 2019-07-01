// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2011 Google, Inc.
 * Copyright (c) 2011-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2019 Sultan Alsawaf <sultan@kerneltoast.com>.
 */

#include <linux/dma-buf.h>
#include <linux/memblock.h>
#include <linux/miscdevice.h>
#include <linux/msm_dma_iommu_mapping.h>
#include <linux/msm_ion.h>
#include <linux/uaccess.h>

#include "ion.h"
#include "ion_priv.h"
#include "compat_ion.h"

struct ion_device {
	struct miscdevice dev;
	struct plist_head heaps;
	struct rw_semaphore heap_lock;
	long (*custom_ioctl)(struct ion_client *client, unsigned int cmd,
			     unsigned long arg);
};

struct ion_client {
	struct ion_device *dev;
	struct rb_root handles;
	struct rb_node node;
	struct idr idr;
	rwlock_t idr_lock;
	rwlock_t rb_lock;
};

struct ion_handle {
	struct ion_buffer *buffer;
	struct ion_client *client;
	struct rb_node node;
	atomic_t kmap_cnt;
	atomic_t refcount;
	int id;
};

struct ion_vma_list {
	struct list_head list;
	struct vm_area_struct *vma;
};

static struct kmem_cache *ion_sg_table_pool;
static struct kmem_cache *ion_page_pool;

static bool ion_buffer_fault_user_mappings(struct ion_buffer *buffer)
{
	return !(buffer->flags & ION_FLAG_CACHED_NEEDS_SYNC) &&
		 buffer->flags & ION_FLAG_CACHED;
}

static struct page *ion_buffer_page(struct page *page)
{
	return (struct page *)((unsigned long)page & ~(1UL));
}

static bool ion_buffer_page_is_dirty(struct page *page)
{
	return (unsigned long)page & 1UL;
}

static void ion_buffer_page_dirty(struct page **page)
{
	*page = (struct page *)((unsigned long)(*page) | 1UL);
}

static void ion_buffer_page_clean(struct page **page)
{
	*page = (struct page *)((unsigned long)(*page) & ~(1UL));
}

static struct ion_buffer *ion_buffer_create(struct ion_heap *heap,
					    struct ion_device *dev,
					    unsigned long len,
					    unsigned long align,
					    unsigned long flags)
{
	struct ion_buffer *buffer;
	struct scatterlist *sg;
	struct sg_table *table;
	int i, ret;

	buffer = kmalloc(sizeof(*buffer), GFP_KERNEL);
	if (!buffer)
		return ERR_PTR(-ENOMEM);

	*buffer = (typeof(*buffer)){
		.dev = dev,
		.heap = heap,
		.flags = flags,
		.size = len,
		.vmas = LIST_HEAD_INIT(buffer->vmas),
		.kmap_lock = __MUTEX_INITIALIZER(buffer->kmap_lock),
		.page_lock = __MUTEX_INITIALIZER(buffer->page_lock),
		.vma_lock = __MUTEX_INITIALIZER(buffer->vma_lock),
		.ref = {
			.refcount = ATOMIC_INIT(1)
		}
	};

	ret = heap->ops->allocate(heap, buffer, len, align, flags);
	if (ret) {
		if (!(heap->flags & ION_HEAP_FLAG_DEFER_FREE))
			goto free_buffer;

		ion_heap_freelist_drain(heap, 0);
		ret = heap->ops->allocate(heap, buffer, len, align, flags);
		if (ret)
			goto free_buffer;
	}

	table = heap->ops->map_dma(heap, buffer);
	if (IS_ERR_OR_NULL(table))
		goto free_heap;

	buffer->sg_table = table;
	if (ion_buffer_fault_user_mappings(buffer)) {
		int num_pages = PAGE_ALIGN(buffer->size) / PAGE_SIZE;
		int j, k = 0;

		buffer->pages = vmalloc(sizeof(*buffer->pages) * num_pages);
		if (!buffer->pages)
			goto unmap_dma;

		for_each_sg(table->sgl, sg, table->nents, i) {
			struct page *page = sg_page(sg);

			for (j = 0; j < sg->length / PAGE_SIZE; j++)
				buffer->pages[k++] = page++;
		}
	}

	for_each_sg(buffer->sg_table->sgl, sg, buffer->sg_table->nents, i) {
		sg_dma_address(sg) = sg_phys(sg);
		sg_dma_len(sg) = sg->length;
	}

	return buffer;

unmap_dma:
	heap->ops->unmap_dma(heap, buffer);
free_heap:
	heap->ops->free(buffer);
free_buffer:
	kfree(buffer);
	return ERR_PTR(-EINVAL);
}

void ion_buffer_destroy(struct ion_buffer *buffer)
{
	if (buffer->kmap_cnt > 0)
		buffer->heap->ops->unmap_kernel(buffer->heap, buffer);
	buffer->heap->ops->unmap_dma(buffer->heap, buffer);
	buffer->heap->ops->free(buffer);
	if (ion_buffer_fault_user_mappings(buffer))
		vfree(buffer->pages);
	kfree(buffer);
}

static void ion_buffer_kref_destroy(struct kref *kref)
{
	struct ion_buffer *buffer = container_of(kref, typeof(*buffer), ref);
	struct ion_heap *heap = buffer->heap;

	msm_dma_buf_freed(buffer);

	if (heap->flags & ION_HEAP_FLAG_DEFER_FREE)
		ion_heap_freelist_add(heap, buffer);
	else
		ion_buffer_destroy(buffer);
}

static struct ion_handle *ion_handle_create(struct ion_client *client,
					    struct ion_buffer *buffer)
{
	struct ion_handle *handle;

	handle = kmalloc(sizeof(*handle), GFP_KERNEL);
	if (!handle)
		return ERR_PTR(-ENOMEM);

	*handle = (typeof(*handle)){
		.buffer = buffer,
		.client = client,
		.kmap_cnt = ATOMIC_INIT(0),
		.refcount = ATOMIC_INIT(1)
	};

	return handle;
}

static void *ion_buffer_kmap_get(struct ion_buffer *buffer)
{
	void *vaddr;

	mutex_lock(&buffer->kmap_lock);
	if (buffer->kmap_cnt) {
		vaddr = buffer->vaddr;
		buffer->kmap_cnt++;
	} else {
		vaddr = buffer->heap->ops->map_kernel(buffer->heap, buffer);
		if (IS_ERR_OR_NULL(vaddr)) {
			vaddr = ERR_PTR(-EINVAL);
		} else {
			buffer->vaddr = vaddr;
			buffer->kmap_cnt++;
		}
	}
	mutex_unlock(&buffer->kmap_lock);

	return vaddr;
}

static void ion_buffer_kmap_put(struct ion_buffer *buffer)
{
	mutex_lock(&buffer->kmap_lock);
	if (!--buffer->kmap_cnt)
		buffer->heap->ops->unmap_kernel(buffer->heap, buffer);
	mutex_unlock(&buffer->kmap_lock);
}

static void *ion_handle_kmap_get(struct ion_handle *handle)
{
	struct ion_buffer *buffer = handle->buffer;
	void *objp;

	objp = ion_buffer_kmap_get(buffer);
	if (!IS_ERR(objp))
		atomic_inc(&handle->kmap_cnt);

	return objp;
}

static void ion_handle_kmap_put(struct ion_handle *handle)
{
	struct ion_buffer *buffer = handle->buffer;

	if (atomic_add_unless(&handle->kmap_cnt, -1, 0))
		ion_buffer_kmap_put(buffer);
}

static void ion_handle_get(struct ion_handle *handle)
{
	atomic_inc(&handle->refcount);
}

bool ion_handle_validate(struct ion_client *client, struct ion_handle *handle)
{
	bool found;

	read_lock(&client->idr_lock);
	found = idr_find(&client->idr, handle->id) == handle;
	read_unlock(&client->idr_lock);

	return found;
}

void *ion_map_kernel(struct ion_client *client, struct ion_handle *handle)
{
	struct ion_buffer *buffer;

	if (!ion_handle_validate(client, handle))
		return ERR_PTR(-EINVAL);

	buffer = handle->buffer;
	if (!buffer->heap->ops->map_kernel)
		return ERR_PTR(-ENODEV);

	return ion_handle_kmap_get(handle);
}

void ion_unmap_kernel(struct ion_client *client, struct ion_handle *handle)
{
	if (ion_handle_validate(client, handle))
		ion_handle_kmap_put(handle);
}

void ion_handle_put(struct ion_handle *handle)
{
	struct ion_client *client = handle->client;
	struct ion_buffer *buffer = handle->buffer;

	if (atomic_dec_return(&handle->refcount))
		return;

	write_lock(&client->idr_lock);
	idr_remove(&client->idr, handle->id);
	write_unlock(&client->idr_lock);

	write_lock(&client->rb_lock);
	rb_erase(&handle->node, &client->handles);
	write_unlock(&client->rb_lock);

	ion_handle_kmap_put(handle);
	kref_put(&buffer->ref, ion_buffer_kref_destroy);
	kfree(handle);
}

static struct ion_handle *ion_handle_lookup_get(struct ion_client *client,
						struct ion_buffer *buffer)
{
	struct rb_node **p = &client->handles.rb_node;
	struct ion_handle *entry;

	read_lock(&client->rb_lock);
	while (*p) {
		entry = rb_entry(*p, typeof(*entry), node);
		if (buffer < entry->buffer) {
			p = &(*p)->rb_left;
		} else if (buffer > entry->buffer) {
			p = &(*p)->rb_right;
		} else {
			read_unlock(&client->rb_lock);
			ion_handle_get(entry);
			return entry;
		}
	}
	read_unlock(&client->rb_lock);

	return ERR_PTR(-EINVAL);
}

struct ion_handle *ion_handle_find_by_id(struct ion_client *client, int id)
{
	struct ion_handle *handle;

	read_lock(&client->idr_lock);
	handle = idr_find(&client->idr, id);
	read_unlock(&client->idr_lock);

	return handle ? handle : ERR_PTR(-EINVAL);
}

static int ion_handle_add(struct ion_client *client, struct ion_handle *handle)
{
	struct rb_node **p = &client->handles.rb_node;
	struct ion_buffer *buffer = handle->buffer;
	struct rb_node *parent = NULL;
	struct ion_handle *entry;
	int id;

	idr_preload(GFP_KERNEL);
	write_lock(&client->idr_lock);
	id = idr_alloc(&client->idr, handle, 1, 0, GFP_NOWAIT);
	write_unlock(&client->idr_lock);
	idr_preload_end();

	if (id < 0)
		return id;

	handle->id = id;

	write_lock(&client->rb_lock);
	while (*p) {
		parent = *p;
		entry = rb_entry(parent, typeof(*entry), node);
		if (buffer < entry->buffer)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}
	rb_link_node(&handle->node, parent, p);
	rb_insert_color(&handle->node, &client->handles);
	write_unlock(&client->rb_lock);

	return 0;
}

struct ion_handle *ion_alloc(struct ion_client *client, size_t len,
			     size_t align, unsigned int heap_id_mask,
			     unsigned int flags)
{
	struct ion_device *dev = client->dev;
	struct ion_buffer *buffer = NULL;
	struct ion_handle *handle;
	struct ion_heap *heap;

	len = PAGE_ALIGN(len);
	if (!len)
		return ERR_PTR(-EINVAL);

	flags |= ION_FLAG_CACHED_NEEDS_SYNC;

	down_read(&dev->heap_lock);
	plist_for_each_entry(heap, &dev->heaps, node) {
		if (!(BIT(heap->id) & heap_id_mask))
			continue;

		buffer = ion_buffer_create(heap, dev, len, align, flags);
		if (!IS_ERR(buffer))
			break;
	}
	up_read(&dev->heap_lock);

	if (IS_ERR_OR_NULL(buffer))
		return ERR_PTR(-EINVAL);

	handle = ion_handle_create(client, buffer);
	if (IS_ERR(handle)) {
		kref_put(&buffer->ref, ion_buffer_kref_destroy);
		return ERR_PTR(-EINVAL);
	}

	if (ion_handle_add(client, handle)) {
		/* ion_handle_put will put the buffer as well */
		ion_handle_put(handle);
		return ERR_PTR(-EINVAL);
	}

	return handle;
}

void ion_free(struct ion_client *client, struct ion_handle *handle)
{
	if (ion_handle_validate(client, handle))
		ion_handle_put(handle);
}

int ion_phys(struct ion_client *client, struct ion_handle *handle,
	     ion_phys_addr_t *addr, size_t *len)
{
	struct ion_buffer *buffer;

	if (!ion_handle_validate(client, handle))
		return -EINVAL;

	buffer = handle->buffer;
	if (!buffer->heap->ops->phys)
		return -ENODEV;

	return buffer->heap->ops->phys(buffer->heap, buffer, addr, len);
}

struct ion_client *ion_client_create(struct ion_device *dev)
{
	struct ion_client *client;

	client = kmalloc(sizeof(*client), GFP_KERNEL);
	if (!client)
		return ERR_PTR(-ENOMEM);

	*client = (typeof(*client)){
		.dev = dev,
		.handles = RB_ROOT,
		.idr = IDR_INIT(client->idr),
		.idr_lock = __RW_LOCK_UNLOCKED(client->idr_lock),
		.rb_lock = __RW_LOCK_UNLOCKED(client->rb_lock)
	};

	return client;
}

void ion_client_destroy(struct ion_client *client)
{
	struct ion_handle *handle;
	struct rb_node *n;

	while ((n = rb_first(&client->handles))) {
		handle = rb_entry(n, typeof(*handle), node);
		ion_handle_put(handle);
	}

	idr_destroy(&client->idr);
	kfree(client);
}

int ion_handle_get_flags(struct ion_client *client, struct ion_handle *handle,
			 unsigned long *flags)
{
	struct ion_buffer *buffer;

	if (!ion_handle_validate(client, handle))
		return -EINVAL;

	buffer = handle->buffer;
	*flags = buffer->flags;
	return 0;
}

int ion_handle_get_size(struct ion_client *client, struct ion_handle *handle,
			size_t *size)
{
	struct ion_buffer *buffer;

	if (!ion_handle_validate(client, handle))
		return -EINVAL;

	buffer = handle->buffer;
	*size = buffer->size;
	return 0;
}

struct sg_table *ion_sg_table(struct ion_client *client,
			      struct ion_handle *handle)
{
	struct ion_buffer *buffer;
	struct sg_table *table;

	if (!ion_handle_validate(client, handle))
		return ERR_PTR(-EINVAL);

	buffer = handle->buffer;
	table = buffer->sg_table;
	return table;
}

static struct scatterlist *ion_sg_alloc(unsigned int nents, gfp_t gfp_mask)
{
	if (nents == SG_MAX_SINGLE_ALLOC)
		return kmem_cache_alloc(ion_page_pool, gfp_mask);

	return kmalloc(nents * sizeof(struct scatterlist), gfp_mask);
}

static void ion_sg_free(struct scatterlist *sg, unsigned int nents)
{
	if (nents == SG_MAX_SINGLE_ALLOC)
		kmem_cache_free(ion_page_pool, sg);
	else
		kfree(sg);
}

static int ion_sg_alloc_table(struct sg_table *table, unsigned int nents,
			      gfp_t gfp_mask)
{
	return __sg_alloc_table(table, nents, SG_MAX_SINGLE_ALLOC, NULL,
				gfp_mask, ion_sg_alloc);
}

static void ion_sg_free_table(struct sg_table *table)
{
	__sg_free_table(table, SG_MAX_SINGLE_ALLOC, false, ion_sg_free);
}

struct sg_table *ion_create_chunked_sg_table(phys_addr_t buffer_base,
					     size_t chunk_size,
					     size_t total_size)
{
	struct scatterlist *sg;
	struct sg_table *table;
	int i, n_chunks, ret;

	table = kmem_cache_alloc(ion_sg_table_pool, GFP_KERNEL);
	if (!table)
		return ERR_PTR(-ENOMEM);

	n_chunks = DIV_ROUND_UP(total_size, chunk_size);
	ret = ion_sg_alloc_table(table, n_chunks, GFP_KERNEL);
	if (ret)
		goto free_table;

	for_each_sg(table->sgl, sg, table->nents, i) {
		sg_dma_address(sg) = buffer_base + i * chunk_size;
		sg->length = chunk_size;
	}

	return table;

free_table:
	kmem_cache_free(ion_sg_table_pool, table);
	return ERR_PTR(ret);
}

static struct sg_table *ion_dupe_sg_table(struct sg_table *orig_table)
{
	struct scatterlist *sg, *sg_orig;
	struct sg_table *table;
	int i, ret;

	table = kmem_cache_alloc(ion_sg_table_pool, GFP_KERNEL);
	if (!table)
		return NULL;

	ret = ion_sg_alloc_table(table, orig_table->nents, GFP_KERNEL);
	if (ret) {
		kmem_cache_free(ion_sg_table_pool, table);
		return NULL;
	}

	sg_orig = orig_table->sgl;
	for_each_sg(table->sgl, sg, table->nents, i) {
		*sg = *sg_orig;
		sg_orig = sg_next(sg_orig);
	}

	return table;
}

void ion_pages_sync_for_device(struct device *dev, struct page *page,
			       size_t size, enum dma_data_direction dir)
{
	struct scatterlist sg;

	sg_init_table(&sg, 1);
	sg_set_page(&sg, page, size, 0);
	sg_dma_address(&sg) = page_to_phys(page);
	dma_sync_sg_for_device(dev, &sg, 1, dir);
}

static void ion_buffer_sync_for_device(struct ion_buffer *buffer,
				       struct device *dev,
				       enum dma_data_direction dir)
{
	struct ion_vma_list *vma_list;
	int i, pages;

	if (!ion_buffer_fault_user_mappings(buffer))
		return;

	pages = PAGE_ALIGN(buffer->size) / PAGE_SIZE;
	mutex_lock(&buffer->page_lock);
	for (i = 0; i < pages; i++) {
		struct page *page = buffer->pages[i];

		if (ion_buffer_page_is_dirty(page))
			ion_pages_sync_for_device(dev, ion_buffer_page(page),
						  PAGE_SIZE, dir);

		ion_buffer_page_clean(buffer->pages + i);
	}
	mutex_unlock(&buffer->page_lock);

	mutex_lock(&buffer->vma_lock);
	list_for_each_entry(vma_list, &buffer->vmas, list) {
		struct vm_area_struct *vma = vma_list->vma;

		zap_page_range(vma, vma->vm_start, vma->vm_end - vma->vm_start,
			       NULL);
	}
	mutex_unlock(&buffer->vma_lock);
}

static struct sg_table *ion_map_dma_buf(struct dma_buf_attachment *attachment,
					enum dma_data_direction direction)
{
	struct dma_buf *dmabuf = attachment->dmabuf;
	struct ion_buffer *buffer = dmabuf->priv;
	struct sg_table *table;

	table = ion_dupe_sg_table(buffer->sg_table);
	if (!table)
		return NULL;

	ion_buffer_sync_for_device(buffer, attachment->dev, direction);
	return table;
}

static void ion_unmap_dma_buf(struct dma_buf_attachment *attachment,
			      struct sg_table *table,
			      enum dma_data_direction direction)
{
	ion_sg_free_table(table);
	kmem_cache_free(ion_sg_table_pool, table);
}

static int ion_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct ion_buffer *buffer = vma->vm_private_data;
	unsigned long pfn;
	int ret;

	mutex_lock(&buffer->page_lock);
	ion_buffer_page_dirty(buffer->pages + vmf->pgoff);
	pfn = page_to_pfn(ion_buffer_page(buffer->pages[vmf->pgoff]));
	ret = vm_insert_pfn(vma, (unsigned long)vmf->virtual_address, pfn);
	mutex_unlock(&buffer->page_lock);

	return ret ? VM_FAULT_ERROR : VM_FAULT_NOPAGE;
}

static void ion_vm_open(struct vm_area_struct *vma)
{
	struct ion_buffer *buffer = vma->vm_private_data;
	struct ion_vma_list *vma_list;

	vma_list = kmalloc(sizeof(*vma_list), GFP_KERNEL);
	if (!vma_list)
		return;

	vma_list->vma = vma;

	mutex_lock(&buffer->vma_lock);
	list_add(&vma_list->list, &buffer->vmas);
	mutex_unlock(&buffer->vma_lock);
}

static void ion_vm_close(struct vm_area_struct *vma)
{
	struct ion_buffer *buffer = vma->vm_private_data;
	struct ion_vma_list *vma_list;

	mutex_lock(&buffer->vma_lock);
	list_for_each_entry(vma_list, &buffer->vmas, list) {
		if (vma_list->vma == vma) {
			list_del(&vma_list->list);
			break;
		}
	}
	mutex_unlock(&buffer->vma_lock);

	if (buffer->heap->ops->unmap_user)
		buffer->heap->ops->unmap_user(buffer->heap, buffer);

	kfree(vma_list);
}

static const struct vm_operations_struct ion_vma_ops = {
	.open = ion_vm_open,
	.close = ion_vm_close,
	.fault = ion_vm_fault
};

static int ion_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct ion_buffer *buffer = dmabuf->priv;

	if (!buffer->heap->ops->map_user)
		return -EINVAL;

	if (ion_buffer_fault_user_mappings(buffer)) {
		vma->vm_flags |= VM_IO | VM_PFNMAP | VM_DONTEXPAND |
				 VM_DONTDUMP | VM_MIXEDMAP;
		vma->vm_private_data = buffer;
		vma->vm_ops = &ion_vma_ops;
		ion_vm_open(vma);
		return 0;
	}

	if (!(buffer->flags & ION_FLAG_CACHED))
		vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

	return buffer->heap->ops->map_user(buffer->heap, buffer, vma);
}

static void ion_dma_buf_release(struct dma_buf *dmabuf)
{
	struct ion_buffer *buffer = dmabuf->priv;

	kref_put(&buffer->ref, ion_buffer_kref_destroy);
}

static void *ion_dma_buf_kmap(struct dma_buf *dmabuf, unsigned long offset)
{
	struct ion_buffer *buffer = dmabuf->priv;

	return buffer->vaddr + offset * PAGE_SIZE;
}

static int ion_dma_buf_begin_cpu_access(struct dma_buf *dmabuf, size_t start,
					size_t len,
					enum dma_data_direction direction)
{
	struct ion_buffer *buffer = dmabuf->priv;

	if (!buffer->heap->ops->map_kernel)
		return -ENODEV;

	return PTR_RET(ion_buffer_kmap_get(buffer));
}

static void ion_dma_buf_end_cpu_access(struct dma_buf *dmabuf, size_t start,
				       size_t len,
				       enum dma_data_direction direction)
{
	struct ion_buffer *buffer = dmabuf->priv;

	ion_buffer_kmap_put(buffer);
}

static const struct dma_buf_ops dma_buf_ops = {
	.map_dma_buf = ion_map_dma_buf,
	.unmap_dma_buf = ion_unmap_dma_buf,
	.mmap = ion_mmap,
	.release = ion_dma_buf_release,
	.begin_cpu_access = ion_dma_buf_begin_cpu_access,
	.end_cpu_access = ion_dma_buf_end_cpu_access,
	.kmap_atomic = ion_dma_buf_kmap,
	.kmap = ion_dma_buf_kmap
};

struct dma_buf *ion_share_dma_buf(struct ion_client *client,
				  struct ion_handle *handle)
{
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct ion_buffer *buffer;
	struct dma_buf *dmabuf;

	if (!ion_handle_validate(client, handle))
		return ERR_PTR(-EINVAL);

	buffer = handle->buffer;

	exp_info.ops = &dma_buf_ops;
	exp_info.size = buffer->size;
	exp_info.flags = O_RDWR;
	exp_info.priv = buffer;

	dmabuf = dma_buf_export(&exp_info);
	if (!IS_ERR(dmabuf))
		kref_get(&buffer->ref);

	return dmabuf;
}

int ion_share_dma_buf_fd(struct ion_client *client, struct ion_handle *handle)
{
	struct dma_buf *dmabuf;
	int fd;

	dmabuf = ion_share_dma_buf(client, handle);
	if (IS_ERR(dmabuf))
		return PTR_ERR(dmabuf);

	fd = dma_buf_fd(dmabuf, O_CLOEXEC);
	if (fd < 0)
		dma_buf_put(dmabuf);

	return fd;
}

struct ion_handle *ion_import_dma_buf(struct ion_client *client, int fd)
{
	struct ion_buffer *buffer;
	struct ion_handle *handle;
	struct dma_buf *dmabuf;
	int ret;

	dmabuf = dma_buf_get(fd);
	if (IS_ERR(dmabuf))
		return ERR_CAST(dmabuf);

	if (dmabuf->ops != &dma_buf_ops)
		goto put_dmabuf;

	buffer = dmabuf->priv;
	handle = ion_handle_lookup_get(client, buffer);
	if (IS_ERR(handle)) {
		handle = ion_handle_create(client, buffer);
		if (IS_ERR(handle))
			goto put_dmabuf;

		kref_get(&buffer->ref);
		ret = ion_handle_add(client, handle);
		if (ret)
			goto put_handle;
	}

	dma_buf_put(dmabuf);
	return handle;

put_handle:
	/* ion_handle_put will put the buffer as well */
	ion_handle_put(handle);
put_dmabuf:
	dma_buf_put(dmabuf);
	return ERR_PTR(-EINVAL);
}

static int ion_sync_for_device(struct ion_client *client, int fd)
{
	struct ion_buffer *buffer;
	struct dma_buf *dmabuf;

	dmabuf = dma_buf_get(fd);
	if (IS_ERR(dmabuf))
		return PTR_ERR(dmabuf);

	if (dmabuf->ops != &dma_buf_ops)
		goto put_dmabuf;

	buffer = dmabuf->priv;
	dma_sync_sg_for_device(NULL, buffer->sg_table->sgl,
			       buffer->sg_table->nents, DMA_BIDIRECTIONAL);
	dma_buf_put(dmabuf);
	return 0;

put_dmabuf:
	dma_buf_put(dmabuf);
	return -EINVAL;
}

static long ion_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	union {
		struct ion_fd_data fd;
		struct ion_allocation_data allocation;
		struct ion_handle_data handle;
		struct ion_custom_data custom;
	} data;
	struct ion_client *client = file->private_data;
	struct ion_device *dev = client->dev;
	struct ion_handle *handle;

	if (_IOC_SIZE(cmd) > sizeof(data))
		return -EINVAL;

	switch (cmd) {
	case ION_IOC_ALLOC:
	case ION_IOC_FREE:
	case ION_IOC_SHARE:
	case ION_IOC_MAP:
	case ION_IOC_IMPORT:
	case ION_IOC_SYNC:
	case ION_IOC_CUSTOM:
		if (copy_from_user(&data, (void __user *)arg, _IOC_SIZE(cmd)))
			return -EFAULT;
		break;
	}

	switch (cmd) {
	case ION_IOC_ALLOC:
		handle = ion_alloc(client, data.allocation.len,
				   data.allocation.align,
				   data.allocation.heap_id_mask,
				   data.allocation.flags);
		if (IS_ERR(handle))
			return PTR_ERR(handle);

		data.allocation.handle = handle->id;
		break;
	case ION_IOC_FREE:
		handle = ion_handle_find_by_id(client, data.handle.handle);
		if (IS_ERR(handle))
			return PTR_ERR(handle);

		ion_handle_put(handle);
		break;
	case ION_IOC_SHARE:
	case ION_IOC_MAP:
		handle = ion_handle_find_by_id(client, data.handle.handle);
		if (IS_ERR(handle))
			return PTR_ERR(handle);

		data.fd.fd = ion_share_dma_buf_fd(client, handle);
		if (data.fd.fd < 0)
			return data.fd.fd;
		break;
	case ION_IOC_IMPORT:
		handle = ion_import_dma_buf(client, data.fd.fd);
		if (IS_ERR(handle))
			return PTR_ERR(handle);

		data.handle.handle = handle->id;
		break;
	case ION_IOC_SYNC:
		return ion_sync_for_device(client, data.fd.fd);
	case ION_IOC_CUSTOM:
		if (dev->custom_ioctl)
			return dev->custom_ioctl(client, data.custom.cmd,
						 data.custom.arg);
		return -ENOTTY;
	case ION_IOC_CLEAN_CACHES:
	case ION_IOC_INV_CACHES:
	case ION_IOC_CLEAN_INV_CACHES:
		return client->dev->custom_ioctl(client, cmd, arg);
	default:
		return -ENOTTY;
	}

	switch (cmd) {
	case ION_IOC_ALLOC:
	case ION_IOC_SHARE:
	case ION_IOC_MAP:
	case ION_IOC_IMPORT:
		if (copy_to_user((void __user *)arg, &data, _IOC_SIZE(cmd))) {
			if (cmd == ION_IOC_ALLOC)
				ion_handle_put(handle);
			return -EFAULT;
		}
		break;
	}

	return 0;
}

static int ion_release(struct inode *inode, struct file *file)
{
	struct ion_client *client = file->private_data;

	ion_client_destroy(client);
	return 0;
}

static int ion_open(struct inode *inode, struct file *file)
{
	struct miscdevice *miscdev = file->private_data;
	struct ion_device *dev = container_of(miscdev, typeof(*dev), dev);
	struct ion_client *client;

	client = ion_client_create(dev);
	if (IS_ERR(client))
		return PTR_ERR(client);

	file->private_data = client;
	return 0;
}

static const struct file_operations ion_fops = {
	.owner = THIS_MODULE,
	.open = ion_open,
	.release = ion_release,
	.unlocked_ioctl = ion_ioctl,
	.compat_ioctl = compat_ion_ioctl
};

void ion_device_add_heap(struct ion_device *dev, struct ion_heap *heap)
{
	spin_lock_init(&heap->free_lock);
	heap->free_list_size = 0;

	if (heap->flags & ION_HEAP_FLAG_DEFER_FREE)
		ion_heap_init_deferred_free(heap);

	if (heap->flags & ION_HEAP_FLAG_DEFER_FREE || heap->ops->shrink)
		ion_heap_init_shrinker(heap);

	heap->dev = dev;
	plist_node_init(&heap->node, -heap->id);

	down_write(&dev->heap_lock);
	plist_add(&heap->node, &dev->heaps);
	up_write(&dev->heap_lock);
}

int ion_walk_heaps(struct ion_client *client, int heap_id,
		   enum ion_heap_type type, void *data,
		   int (*f)(struct ion_heap *heap, void *data))
{
	struct ion_device *dev = client->dev;
	struct ion_heap *heap;
	int ret = 0;

	down_write(&dev->heap_lock);
	plist_for_each_entry(heap, &dev->heaps, node) {
		if (heap->type == type && ION_HEAP(heap->id) == heap_id) {
			ret = f(heap, data);
			break;
		}
	}
	up_write(&dev->heap_lock);

	return ret;
}

struct ion_device *ion_device_create(long (*custom_ioctl)
				     (struct ion_client *client,
				      unsigned int cmd, unsigned long arg))
{
	struct ion_device *dev;
	int ret;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return ERR_PTR(-ENOMEM);

	ion_sg_table_pool = KMEM_CACHE(sg_table, SLAB_HWCACHE_ALIGN);
	if (!ion_sg_table_pool)
		goto free_dev;

	ion_page_pool = kmem_cache_create("ion_page", PAGE_SIZE, PAGE_SIZE,
					  SLAB_HWCACHE_ALIGN, NULL);
	if (!ion_page_pool)
		goto free_table_pool;

	dev->dev.minor = MISC_DYNAMIC_MINOR;
	dev->dev.name = "ion";
	dev->dev.fops = &ion_fops;
	dev->dev.parent = NULL;
	ret = misc_register(&dev->dev);
	if (ret)
		goto free_page_pool;

	dev->custom_ioctl = custom_ioctl;
	init_rwsem(&dev->heap_lock);
	plist_head_init(&dev->heaps);
	return dev;

free_page_pool:
	kmem_cache_destroy(ion_page_pool);
free_table_pool:
	kmem_cache_destroy(ion_sg_table_pool);
free_dev:
	kfree(dev);
	return ERR_PTR(-ENOMEM);
}

void __init ion_reserve(struct ion_platform_data *data)
{
	phys_addr_t paddr;
	int i;

	for (i = 0; i < data->nr; i++) {
		if (!data->heaps[i].size)
			continue;

		if (data->heaps[i].base) {
			memblock_reserve(data->heaps[i].base,
					 data->heaps[i].size);
		} else {
			paddr = memblock_alloc_base(data->heaps[i].size,
						    data->heaps[i].align,
						    MEMBLOCK_ALLOC_ANYWHERE);
			if (paddr)
				data->heaps[i].base = paddr;
		}
	}
}

struct ion_buffer *get_buffer(struct ion_handle *handle)
{
	struct ion_buffer *buffer = handle->buffer;

	return buffer;
}
