/*
 * drivers/staging/android/ion/ion.h
 *
 * Copyright (C) 2011 Google, Inc.
 * Copyright (c) 2011-2014, The Linux Foundation. All rights reserved.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef _LINUX_ION_H
#define _LINUX_ION_H

#include <linux/err.h>
#include <linux/memblock.h>
#include <linux/msm_dma_iommu_mapping.h>
#include "../uapi/ion.h"

struct ion_handle;
struct ion_device;
struct ion_heap;
struct ion_mapper;
struct ion_client;
struct ion_buffer;

struct ion_buffer {
	struct ion_heap *heap;
	struct sg_table *sg_table;
	struct mutex kmap_lock;
	struct work_struct free;
	atomic_t refcount;
	void *priv_virt;
	void *vaddr;
	unsigned int flags;
	unsigned int private_flags;
	size_t size;
	int kmap_refcount;
	struct msm_iommu_data iommu_data;
};

/* This should be removed some day when phys_addr_t's are fully
   plumbed in the kernel, and all instances of ion_phys_addr_t should
   be converted to phys_addr_t.  For the time being many kernel interfaces
   do not accept phys_addr_t's that would have to */
#define ion_phys_addr_t dma_addr_t

/**
 * struct ion_platform_heap - defines a heap in the given platform
 * @type:	type of the heap from ion_heap_type enum
 * @id:		unique identifier for heap.  When allocating higher numbers
 *		will be allocated from first.  At allocation these are passed
 *		as a bit mask and therefore can not exceed ION_NUM_HEAP_IDS.
 * @name:	used for debug purposes
 * @base:	base address of heap in physical memory if applicable
 * @size:	size of the heap in bytes if applicable
 * @has_outer_cache:    set to 1 if outer cache is used, 0 otherwise.
 * @extra_data:	Extra data specific to each heap type
 * @priv:	heap private data
 * @align:	required alignment in physical memory if applicable
 * @priv:	private info passed from the board file
 *
 * Provided by the board file.
 */
struct ion_platform_heap {
	enum ion_heap_type type;
	unsigned int id;
	const char *name;
	ion_phys_addr_t base;
	size_t size;
	unsigned int has_outer_cache;
	void *extra_data;
	ion_phys_addr_t align;
	void *priv;
};

/**
 * struct ion_platform_data - array of platform heaps passed from board file
 * @has_outer_cache:    set to 1 if outer cache is used, 0 otherwise.
 * @nr:    number of structures in the array
 * @heaps: array of platform_heap structions
 *
 * Provided by the board file in the form of platform data to a platform device.
 */
struct ion_platform_data {
	unsigned int has_outer_cache;
	int nr;
	struct ion_platform_heap *heaps;
};

#ifdef CONFIG_ION

/**
 * ion_reserve() - reserve memory for ion heaps if applicable
 * @data:	platform data specifying starting physical address and
 *		size
 *
 * Calls memblock reserve to set aside memory for heaps that are
 * located at specific memory addresses or of specific sizes not
 * managed by the kernel
 */
static inline void ion_reserve(struct ion_platform_data *data)
{
	int i;

	for (i = 0; i < data->nr; i++) {
		struct ion_platform_heap *pheap = &data->heaps[i];

		if (pheap->size) {
			if (pheap->base)
				memblock_reserve(pheap->base, pheap->size);
			else
				pheap->base = memblock_alloc_base(pheap->size,
					pheap->align, MEMBLOCK_ALLOC_ANYWHERE);
		}
	}
}

/**
 * ion_client_create() -  allocate a client and returns it
 * @dev:		the global ion device
 */
static inline struct ion_client *ion_client_create(void *idev)
{
	return idev;
}

/**
 * ion_client_destroy() -  free's a client and all it's handles
 * @client:	the client
 *
 * Free the provided client and all it's resources including
 * any handles it is holding.
 */
static inline void ion_client_destroy(struct ion_client *client)
{
}

/**
 * ion_alloc - allocate ion memory
 * @client:		the client
 * @len:		size of the allocation
 * @align:		requested allocation alignment, lots of hardware blocks
 *			have alignment requirements of some kind
 * @heap_id_mask:	mask of heaps to allocate from, if multiple bits are set
 *			heaps will be tried in order from highest to lowest
 *			id
 * @flags:		heap flags, the low 16 bits are consumed by ion, the
 *			high 16 bits are passed on to the respective heap and
 *			can be heap custom
 *
 * Allocate memory in one of the heaps provided in heap mask and return
 * an opaque handle to it.
 */
struct ion_buffer *__ion_alloc(struct ion_device *idev, size_t len,
			       size_t align, unsigned int heap_id_mask,
			       unsigned int flags);
static inline void *ion_alloc(void *client, size_t len, size_t align,
			      unsigned int heap_id_mask, unsigned int flags)
{
	return __ion_alloc(client, len, align, heap_id_mask, flags);
}

/**
 * ion_free - free a handle
 * @client:	the client
 * @handle:	the handle to free
 *
 * Free the provided handle.
 */
void ion_buffer_put(struct ion_buffer *buffer);
static inline void ion_free(struct ion_client *client, void *handle)
{
	ion_buffer_put(handle);
}

/**
 * ion_phys - returns the physical address and len of a handle
 * @client:	the client
 * @handle:	the handle
 * @addr:	a pointer to put the address in
 * @len:	a pointer to put the length in
 *
 * This function queries the heap for a particular handle to get the
 * handle's physical address.  It't output is only correct if
 * a heap returns physically contiguous memory -- in other cases
 * this api should not be implemented -- ion_sg_table should be used
 * instead.  Returns -EINVAL if the handle is invalid.  This has
 * no implications on the reference counting of the handle --
 * the returned value may not be valid if the caller is not
 * holding a reference.
 */
int __ion_phys(struct ion_buffer *buffer, ion_phys_addr_t *addr, size_t *len);
static inline int ion_phys(struct ion_client *client, void *handle,
			   ion_phys_addr_t *addr, size_t *len)
{
	return __ion_phys(handle, addr, len);
}

/**
 * ion_map_kernel - create mapping for the given handle
 * @client:	the client
 * @handle:	handle to map
 *
 * Map the given handle into the kernel and return a kernel address that
 * can be used to access this address.
 */
void *__ion_map_kernel(struct ion_buffer *buffer);
static inline void *ion_map_kernel(struct ion_client *client, void *handle)
{
	return __ion_map_kernel(handle);
}

/**
 * ion_unmap_kernel() - destroy a kernel mapping for a handle
 * @client:	the client
 * @handle:	handle to unmap
 */
void __ion_unmap_kernel(struct ion_buffer *buffer);
static inline void ion_unmap_kernel(struct ion_client *client, void *handle)
{
	__ion_unmap_kernel(handle);
}

/**
 * ion_share_dma_buf() - share buffer as dma-buf
 * @client:	the client
 * @handle:	the handle
 */
struct dma_buf *__ion_share_dma_buf(struct ion_buffer *buffer);
static inline struct dma_buf *ion_share_dma_buf(struct ion_client *client,
						void *handle)
{
	return __ion_share_dma_buf(handle);
}

/**
 * ion_share_dma_buf_fd() - given an ion client, create a dma-buf fd
 * @client:	the client
 * @handle:	the handle
 */
int __ion_share_dma_buf_fd(struct ion_buffer *buffer);
static inline int ion_share_dma_buf_fd(struct ion_client *client, void *handle)
{
	return __ion_share_dma_buf_fd(handle);
}

/**
 * ion_import_dma_buf() - given an dma-buf fd from the ion exporter get handle
 * @client:	the client
 * @fd:		the dma-buf fd
 *
 * Given an dma-buf fd that was allocated through ion via ion_share_dma_buf,
 * import that fd and return a handle representing it.  If a dma-buf from
 * another exporter is passed in this function will return ERR_PTR(-EINVAL)
 */
struct ion_buffer *__ion_import_dma_buf(int fd);
static inline void *ion_import_dma_buf(struct ion_client *client, int fd)
{
	return __ion_import_dma_buf(fd);
}

#else
static inline void ion_reserve(struct ion_platform_data *data)
{

}

static inline struct ion_client *ion_client_create(
	struct ion_device *dev, unsigned int heap_id_mask, const char *name)
{
	return ERR_PTR(-ENODEV);
}

static inline void ion_client_destroy(struct ion_client *client) { }

static inline struct ion_handle *ion_alloc(struct ion_client *client,
					size_t len, size_t align,
					unsigned int heap_id_mask,
					unsigned int flags)
{
	return ERR_PTR(-ENODEV);
}

static inline void ion_free(struct ion_client *client,
	struct ion_handle *handle) { }


static inline int ion_phys(struct ion_client *client,
	struct ion_handle *handle, ion_phys_addr_t *addr, size_t *len)
{
	return -ENODEV;
}

static inline struct sg_table *ion_sg_table(struct ion_client *client,
			      struct ion_handle *handle)
{
	return ERR_PTR(-ENODEV);
}

static inline void *ion_map_kernel(struct ion_client *client,
	struct ion_handle *handle)
{
	return ERR_PTR(-ENODEV);
}

static inline void ion_unmap_kernel(struct ion_client *client,
	struct ion_handle *handle) { }

static inline int ion_share_dma_buf(struct ion_client *client, struct ion_handle *handle)
{
	return -ENODEV;
}

static inline struct ion_handle *ion_import_dma_buf(struct ion_client *client, int fd)
{
	return ERR_PTR(-ENODEV);
}

static inline int ion_handle_get_flags(struct ion_client *client,
	struct ion_handle *handle, unsigned long *flags)
{
	return -ENODEV;
}

#endif /* CONFIG_ION */
#endif /* _LINUX_ION_H */
