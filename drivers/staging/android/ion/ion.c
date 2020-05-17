// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2011 Google, Inc.
 * Copyright (c) 2011-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2019 Sultan Alsawaf <sultan@kerneltoast.com>.
 */

#include <linux/miscdevice.h>
#include <linux/msm_ion.h>
#include <linux/uaccess.h>
#include "compat_ion.h"
#include "ion_priv.h"

struct ion_device {
	struct miscdevice dev;
	struct plist_head heaps;
	struct rw_semaphore heap_rwsem;
	long (*custom_ioctl)(struct ion_client *client, unsigned int cmd,
			     unsigned long arg);
};

struct ion_client {
	struct ion_device *idev;
	struct idr handle_idr;
	struct latch_tree_root handle_root;
	spinlock_t idr_lock;
	spinlock_t rb_lock;
};

static void ion_buffer_free_work(struct work_struct *work)
{
	struct ion_buffer *buffer = container_of(work, typeof(*buffer), free);
	struct ion_heap *heap = buffer->heap;

	msm_dma_buf_freed(&buffer->iommu_data);
	if (buffer->kmap_refcount)
		heap->ops->unmap_kernel(heap, buffer);
	heap->ops->unmap_dma(heap, buffer);
	heap->ops->free(buffer);
	kfree(buffer);
}

static struct ion_buffer *ion_buffer_create(struct ion_heap *heap, size_t len,
					    size_t align, unsigned int flags)
{
	struct ion_buffer *buffer;
	struct scatterlist *sg;
	unsigned int i;

	buffer = kmalloc(sizeof(*buffer), GFP_KERNEL);
	if (!buffer)
		return ERR_PTR(-ENOMEM);

	*buffer = (typeof(*buffer)){
		.flags = flags,
		.heap = heap,
		.size = len,
		.refcount = ATOMIC_INIT(1),
		.kmap_lock = __MUTEX_INITIALIZER(buffer->kmap_lock),
		.free = __WORK_INITIALIZER(buffer->free, ion_buffer_free_work),
		.iommu_data = {
			.map_list = LIST_HEAD_INIT(buffer->iommu_data.map_list),
			.lock = __MUTEX_INITIALIZER(buffer->iommu_data.lock)
		}
	};

	if (heap->ops->allocate(heap, buffer, len, align, flags)) {
		if (!(heap->flags & ION_HEAP_FLAG_DEFER_FREE))
			goto free_buffer;

		drain_workqueue(heap->wq);
		if (heap->ops->allocate(heap, buffer, len, align, flags))
			goto free_buffer;
	}

	buffer->sg_table = heap->ops->map_dma(heap, buffer);
	if (IS_ERR_OR_NULL(buffer->sg_table))
		goto free_heap;

	for_each_sg(buffer->sg_table->sgl, sg, buffer->sg_table->nents, i) {
		sg_dma_address(sg) = sg_phys(sg);
		sg_dma_len(sg) = sg->length;
	}

	return buffer;

free_heap:
	heap->ops->free(buffer);
free_buffer:
	kfree(buffer);
	return ERR_PTR(-EINVAL);
}

void ion_buffer_put(struct ion_buffer *buffer)
{
	struct ion_heap *heap = buffer->heap;

	if (atomic_dec_and_test(&buffer->refcount)) {
		if (heap->flags & ION_HEAP_FLAG_DEFER_FREE)
			queue_work(heap->wq, &buffer->free);
		else
			ion_buffer_free_work(&buffer->free);
	}
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
		.refcount = ATOMIC_INIT(1)
	};

	idr_preload(GFP_KERNEL);
	spin_lock(&client->idr_lock);
	handle->id = idr_alloc(&client->handle_idr, handle, 1, 0, GFP_ATOMIC);
	spin_unlock(&client->idr_lock);
	idr_preload_end();
	if (handle->id < 0) {
		kfree(handle);
		return ERR_PTR(-ENOMEM);
	}

	return handle;
}

void ion_handle_put(struct ion_handle *handle, int count)
{
	struct ion_buffer *buffer = handle->buffer;
	struct ion_client *client = handle->client;

	if (!atomic_sub_return(count, &handle->refcount)) {
		spin_lock(&client->idr_lock);
		idr_remove(&client->handle_idr, handle->id);
		spin_unlock(&client->idr_lock);

		spin_lock(&client->rb_lock);
		latch_tree_erase(&handle->rnode, &client->handle_root, NULL);
		spin_unlock(&client->rb_lock);

		ion_buffer_put(buffer);
		kfree_rcu(handle, rcu);
	}
}

void *__ion_map_kernel(struct ion_buffer *buffer)
{
	struct ion_heap *heap = buffer->heap;
	void *vaddr;

	if (!heap->ops->map_kernel)
		return ERR_PTR(-ENODEV);

	mutex_lock(&buffer->kmap_lock);
	if (buffer->kmap_refcount) {
		vaddr = buffer->vaddr;
		buffer->kmap_refcount++;
	} else {
		vaddr = heap->ops->map_kernel(heap, buffer);
		if (IS_ERR_OR_NULL(vaddr)) {
			vaddr = ERR_PTR(-EINVAL);
		} else {
			buffer->vaddr = vaddr;
			buffer->kmap_refcount++;
		}
	}
	mutex_unlock(&buffer->kmap_lock);

	return vaddr;
}

void __ion_unmap_kernel(struct ion_buffer *buffer)
{
	struct ion_heap *heap = buffer->heap;

	mutex_lock(&buffer->kmap_lock);
	if (!--buffer->kmap_refcount)
		heap->ops->unmap_kernel(heap, buffer);
	mutex_unlock(&buffer->kmap_lock);
}

struct ion_buffer *__ion_alloc(struct ion_device *idev, size_t len,
			       size_t align, unsigned int heap_id_mask,
			       unsigned int flags)
{
	struct ion_buffer *buffer;
	struct ion_heap *heap;

	len = PAGE_ALIGN(len);
	if (!len)
		return ERR_PTR(-EINVAL);

	down_read(&idev->heap_rwsem);
	plist_for_each_entry(heap, &idev->heaps, node) {
		if (BIT(heap->id) & heap_id_mask) {
			buffer = ion_buffer_create(heap, len, align, flags);
			if (!IS_ERR(buffer)) {
				up_read(&idev->heap_rwsem);
				return buffer;
			}
		}
	}
	up_read(&idev->heap_rwsem);

	return ERR_PTR(-EINVAL);
}

int __ion_phys(struct ion_buffer *buffer, ion_phys_addr_t *addr, size_t *len)
{
	struct ion_heap *heap = buffer->heap;

	if (!heap->ops->phys)
		return -ENODEV;

	return heap->ops->phys(heap, buffer, addr, len);
}

static struct sg_table *ion_dup_sg_table(struct sg_table *orig_table)
{
	unsigned int nents = orig_table->nents;
	struct scatterlist *sg_d, *sg_s;
	struct sg_table *table;

	table = kmalloc(sizeof(*table), GFP_KERNEL);
	if (!table)
		return NULL;

	if (sg_alloc_table(table, nents, GFP_KERNEL)) {
		kfree(table);
		return NULL;
	}

	for (sg_d = table->sgl, sg_s = orig_table->sgl;
	     nents > SG_MAX_SINGLE_ALLOC; nents -= SG_MAX_SINGLE_ALLOC - 1,
	     sg_d = sg_chain_ptr(&sg_d[SG_MAX_SINGLE_ALLOC - 1]),
	     sg_s = sg_chain_ptr(&sg_s[SG_MAX_SINGLE_ALLOC - 1]))
		memcpy(sg_d, sg_s, (SG_MAX_SINGLE_ALLOC - 1) * sizeof(*sg_d));

	if (nents)
		memcpy(sg_d, sg_s, nents * sizeof(*sg_d));

	return table;
}

static struct sg_table *ion_map_dma_buf(struct dma_buf_attachment *attachment,
					enum dma_data_direction dir)
{
	struct dma_buf *dmabuf = attachment->dmabuf;
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);

	return ion_dup_sg_table(buffer->sg_table);
}

static void ion_unmap_dma_buf(struct dma_buf_attachment *attachment,
			      struct sg_table *table,
			      enum dma_data_direction dir)
{
	sg_free_table(table);
	kfree(table);
}

static int ion_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_heap *heap = buffer->heap;

	if (!heap->ops->map_user)
		return -EINVAL;

	if (!(buffer->flags & ION_FLAG_CACHED))
		vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

	return heap->ops->map_user(heap, buffer, vma);
}

static void ion_dma_buf_release(struct dma_buf *dmabuf)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);

	ion_buffer_put(buffer);
}

static void *ion_dma_buf_kmap(struct dma_buf *dmabuf, unsigned long offset)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);

	return buffer->vaddr + offset * PAGE_SIZE;
}

static int ion_dma_buf_begin_cpu_access(struct dma_buf *dmabuf, size_t start,
					size_t len, enum dma_data_direction dir)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);

	return PTR_RET(__ion_map_kernel(buffer));
}

static void ion_dma_buf_end_cpu_access(struct dma_buf *dmabuf, size_t start,
				       size_t len, enum dma_data_direction dir)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);

	__ion_unmap_kernel(buffer);
}

static const struct dma_buf_ops ion_dma_buf_ops = {
	.map_dma_buf = ion_map_dma_buf,
	.unmap_dma_buf = ion_unmap_dma_buf,
	.mmap = ion_mmap,
	.release = ion_dma_buf_release,
	.begin_cpu_access = ion_dma_buf_begin_cpu_access,
	.end_cpu_access = ion_dma_buf_end_cpu_access,
	.kmap_atomic = ion_dma_buf_kmap,
	.kmap = ion_dma_buf_kmap
};

struct dma_buf *__ion_share_dma_buf(struct ion_buffer *buffer)
{
	struct dma_buf_export_info exp_info = {
		.ops = &ion_dma_buf_ops,
		.size = buffer->size,
		.flags = O_RDWR,
		.priv = &buffer->iommu_data
	};
	struct dma_buf *dmabuf;

	dmabuf = dma_buf_export(&exp_info);
	if (!IS_ERR(dmabuf))
		atomic_inc(&buffer->refcount);

	return dmabuf;
}

int __ion_share_dma_buf_fd(struct ion_buffer *buffer)
{
	struct dma_buf *dmabuf;
	int fd;

	dmabuf = __ion_share_dma_buf(buffer);
	if (IS_ERR(dmabuf))
		return PTR_ERR(dmabuf);

	fd = dma_buf_fd(dmabuf, O_CLOEXEC);
	if (fd < 0)
		dma_buf_put(dmabuf);

	return fd;
}

struct ion_buffer *__ion_import_dma_buf(int fd)
{
	struct ion_buffer *buffer;
	struct dma_buf *dmabuf;

	dmabuf = dma_buf_get(fd);
	if (IS_ERR(dmabuf))
		return ERR_CAST(dmabuf);

	buffer = container_of(dmabuf->priv, typeof(*buffer), iommu_data);
	atomic_inc(&buffer->refcount);
	dma_buf_put(dmabuf);
	return buffer;
}

struct ion_handle *ion_handle_get_by_id(struct ion_client *client, int id)
{
	struct ion_handle *handle, *ret = ERR_PTR(-EINVAL);

	rcu_read_lock();
	handle = idr_find(&client->handle_idr, id);
	if (handle) {
		if (atomic_inc_not_zero(&handle->refcount))
			ret = handle;
	}
	rcu_read_unlock();

	return ret;
}

static __always_inline bool
ion_tree_less(struct latch_tree_node *a, struct latch_tree_node *b)
{
	struct ion_handle *a_handle = container_of(a, typeof(*a_handle), rnode);
	struct ion_handle *b_handle = container_of(b, typeof(*b_handle), rnode);

	return a_handle->buffer < b_handle->buffer;
}

static __always_inline int
ion_tree_comp(void *key, struct latch_tree_node *n)
{
	struct ion_handle *handle = container_of(n, typeof(*handle), rnode);

	if ((struct ion_buffer *)key < handle->buffer)
		return -1;

	if ((struct ion_buffer *)key > handle->buffer)
		return 1;

	return 0;
}

static const struct latch_tree_ops ion_tree_ops = {
	.less = ion_tree_less,
	.comp = ion_tree_comp
};

static void ion_handle_rb_add(struct ion_client *client,
			      struct ion_handle *handle)
{
	spin_lock(&client->rb_lock);
	latch_tree_insert(&handle->rnode, &client->handle_root, &ion_tree_ops);
	spin_unlock(&client->rb_lock);
}

static struct ion_handle *ion_handle_get_by_buffer(struct ion_client *client,
						   struct ion_buffer *buffer)
{
	struct ion_handle *handle, *ret = ERR_PTR(-EINVAL);
	struct latch_tree_node *entry;

	rcu_read_lock();
	entry = latch_tree_find(buffer, &client->handle_root, &ion_tree_ops);
	if (entry) {
		handle = container_of(entry, typeof(*handle), rnode);
		if (atomic_inc_not_zero(&handle->refcount))
			ret = handle;
	}
	rcu_read_unlock();

	return ret;
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
	struct ion_device *idev = client->idev;
	struct ion_buffer *buffer;
	struct ion_handle *handle;
	struct dma_buf *dmabuf;
	int *output;

	if (_IOC_SIZE(cmd) > sizeof(data))
		return -EINVAL;

	switch (cmd) {
	case ION_IOC_CUSTOM:
		if (!idev->custom_ioctl)
			return -ENOTTY;
	case ION_IOC_ALLOC:
	case ION_IOC_FREE:
	case ION_IOC_SHARE:
	case ION_IOC_MAP:
	case ION_IOC_IMPORT:
		if (copy_from_user(&data, (void __user *)arg, _IOC_SIZE(cmd)))
			return -EFAULT;
		break;
	}

	switch (cmd) {
	case ION_IOC_ALLOC:
		buffer = __ion_alloc(idev, data.allocation.len,
				     data.allocation.align,
				     data.allocation.heap_id_mask,
				     data.allocation.flags);
		if (IS_ERR(buffer))
			return PTR_ERR(buffer);

		handle = ion_handle_create(client, buffer);
		if (IS_ERR(handle)) {
			ion_buffer_put(buffer);
			return PTR_ERR(handle);
		}

		output = &handle->id;
		arg += offsetof(struct ion_allocation_data, handle);
		break;
	case ION_IOC_FREE:
		handle = ion_handle_get_by_id(client, data.handle.handle);
		if (IS_ERR(handle))
			return PTR_ERR(handle);

		ion_handle_put(handle, 2);
		return 0;
	case ION_IOC_SHARE:
	case ION_IOC_MAP:
		handle = ion_handle_get_by_id(client, data.handle.handle);
		if (IS_ERR(handle))
			return PTR_ERR(handle);

		data.fd.fd = __ion_share_dma_buf_fd(handle->buffer);
		ion_handle_put(handle, 1);
		if (data.fd.fd < 0)
			return data.fd.fd;

		output = &data.fd.fd;
		arg += offsetof(struct ion_fd_data, fd);
		break;
	case ION_IOC_IMPORT:
		buffer = __ion_import_dma_buf(data.fd.fd);
		if (IS_ERR(buffer))
			return PTR_ERR(buffer);

		handle = ion_handle_get_by_buffer(client, buffer);
		if (IS_ERR(handle)) {
			handle = ion_handle_create(client, buffer);
			if (IS_ERR(handle)) {
				ion_buffer_put(buffer);
				return PTR_ERR(handle);
			}
			ion_handle_rb_add(client, handle);
		} else {
			ion_buffer_put(buffer);
		}

		output = &handle->id;
		arg += offsetof(struct ion_handle_data, handle);
		break;
	case ION_IOC_CUSTOM:
		return idev->custom_ioctl(client, data.custom.cmd,
					  data.custom.arg);
	default:
		return -ENOTTY;
	}

	if (copy_to_user((void __user *)arg, output, sizeof(*output))) {
		switch (cmd) {
		case ION_IOC_ALLOC:
		case ION_IOC_IMPORT:
			ion_handle_put(handle, 1);
			break;
		case ION_IOC_SHARE:
		case ION_IOC_MAP:
			dmabuf = dma_buf_get(data.fd.fd);
			dma_buf_put(dmabuf);
			dma_buf_put(dmabuf);
			break;
		}

		return -EFAULT;
	}

	return 0;
}

static int ion_open(struct inode *inode, struct file *file)
{
	struct miscdevice *miscdev = file->private_data;
	struct ion_device *idev = container_of(miscdev, typeof(*idev), dev);
	struct ion_client *client;

	client = kmalloc(sizeof(*client), GFP_KERNEL);
	if (!client)
		return -ENOMEM;

	*client = (typeof(*client)){
		.idev = idev,
		.handle_idr = IDR_INIT(client->handle_idr),
		.idr_lock = __SPIN_LOCK_UNLOCKED(client->idr_lock),
		.rb_lock = __SPIN_LOCK_UNLOCKED(client->rb_lock)
	};

	file->private_data = client;
	return 0;
}

static int ion_release(struct inode *inode, struct file *file)
{
	struct ion_client *client = file->private_data;
	struct ion_handle *handle;
	int id;

	idr_for_each_entry(&client->handle_idr, handle, id) {
		ion_buffer_put(handle->buffer);
		kfree(handle);
	}
	idr_destroy(&client->handle_idr);
	kfree(client);
	return 0;
}

static const struct file_operations ion_fops = {
	.open = ion_open,
	.release = ion_release,
	.unlocked_ioctl = ion_ioctl,
	.compat_ioctl = compat_ion_ioctl
};

void ion_device_add_heap(struct ion_device *idev, struct ion_heap *heap)
{
	if (heap->flags & ION_HEAP_FLAG_DEFER_FREE) {
		heap->wq = alloc_workqueue("%s", WQ_UNBOUND,
					   WQ_UNBOUND_MAX_ACTIVE, heap->name);
		BUG_ON(!heap->wq);
	}

	if (heap->ops->shrink)
		ion_heap_init_shrinker(heap);

	plist_node_init(&heap->node, -heap->id);

	down_write(&idev->heap_rwsem);
	plist_add(&heap->node, &idev->heaps);
	up_write(&idev->heap_rwsem);
}

int ion_walk_heaps(struct ion_client *client, int heap_id,
		   enum ion_heap_type type, void *data,
		   int (*f)(struct ion_heap *heap, void *data))
{
	struct ion_device *idev = client->idev;
	struct ion_heap *heap;
	int ret = 0;

	down_write(&idev->heap_rwsem);
	plist_for_each_entry(heap, &idev->heaps, node) {
		if (heap->type == type && ION_HEAP(heap->id) == heap_id) {
			ret = f(heap, data);
			break;
		}
	}
	up_write(&idev->heap_rwsem);

	return ret;
}

struct ion_device *ion_device_create(long (*custom_ioctl)
				     (struct ion_client *client,
				      unsigned int cmd, unsigned long arg))
{
	struct ion_device *idev;
	int ret;

	idev = kmalloc(sizeof(*idev), GFP_KERNEL);
	if (!idev)
		return ERR_PTR(-ENOMEM);

	*idev = (typeof(*idev)){
		.custom_ioctl = custom_ioctl,
		.heaps = PLIST_HEAD_INIT(idev->heaps),
		.heap_rwsem = __RWSEM_INITIALIZER(idev->heap_rwsem),
		.dev = {
			.minor = MISC_DYNAMIC_MINOR,
			.name = "ion",
			.fops = &ion_fops
		},
	};

	ret = misc_register(&idev->dev);
	if (ret) {
		kfree(idev);
		return ERR_PTR(ret);
	}

	return idev;
}
