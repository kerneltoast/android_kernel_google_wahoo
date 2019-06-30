// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2016, The Linux Foundation. All rights reserved.
 * Copyright (C) 2019 Sultan Alsawaf <sultan@kerneltoast.com>.
 */

#include <linux/dma-buf.h>
#include <linux/rbtree.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <asm/barrier.h>

struct msm_iommu_meta {
	struct rb_node node;
	struct list_head maps;
	atomic_t refcount;
	rwlock_t lock;
	void *buffer;
};

struct msm_iommu_map {
	struct device *dev;
	struct msm_iommu_meta *meta;
	struct list_head lnode;
	struct scatterlist sgl;
	enum dma_data_direction dir;
	unsigned int nents;
	atomic_t refcount;
};

static struct rb_root iommu_root;
static DEFINE_RWLOCK(rb_tree_lock);

static void msm_iommu_meta_add(struct msm_iommu_meta *new_meta)
{
	struct rb_root *root = &iommu_root;
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct msm_iommu_meta *meta;

	write_lock(&rb_tree_lock);
	while (*p) {
		parent = *p;
		meta = rb_entry(parent, typeof(*meta), node);
		if (new_meta->buffer < meta->buffer)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}
	rb_link_node(&new_meta->node, parent, p);
	rb_insert_color(&new_meta->node, root);
	write_unlock(&rb_tree_lock);
}

static struct msm_iommu_meta *msm_iommu_meta_lookup(void *buffer)
{
	struct rb_root *root = &iommu_root;
	struct rb_node **p = &root->rb_node;
	struct msm_iommu_meta *meta;

	read_lock(&rb_tree_lock);
	while (*p) {
		meta = rb_entry(*p, typeof(*meta), node);
		if (buffer < meta->buffer) {
			p = &(*p)->rb_left;
		} else if (buffer > meta->buffer) {
			p = &(*p)->rb_right;
		} else {
			read_unlock(&rb_tree_lock);
			return meta;
		}
	}
	read_unlock(&rb_tree_lock);

	return NULL;
}

static void msm_iommu_map_add(struct msm_iommu_meta *meta,
			      struct msm_iommu_map *map)
{
	write_lock(&meta->lock);
	list_add(&map->lnode, &meta->maps);
	write_unlock(&meta->lock);
}

static struct msm_iommu_map *msm_iommu_map_lookup(struct msm_iommu_meta *meta,
						  struct device *dev)
{
	struct msm_iommu_map *map;

	list_for_each_entry(map, &meta->maps, lnode) {
		if (map->dev == dev)
			return map;
	}

	return NULL;
}

static void msm_iommu_meta_put(struct msm_iommu_meta *meta, int count)
{
	struct rb_root *root = &iommu_root;

	if (atomic_sub_return(count, &meta->refcount))
		return;

	write_lock(&rb_tree_lock);
	rb_erase(&meta->node, root);
	write_unlock(&rb_tree_lock);

	kfree(meta);
}

static struct msm_iommu_meta *msm_iommu_meta_create(struct dma_buf *dma_buf,
						    bool get_extra_ref)
{
	struct msm_iommu_meta *meta;

	meta = kmalloc(sizeof(*meta), GFP_KERNEL);
	if (!meta)
		return NULL;

	*meta = (typeof(*meta)){
		.buffer = dma_buf->priv,
		.refcount = ATOMIC_INIT(1 + !!get_extra_ref),
		.lock = __RW_LOCK_UNLOCKED(&meta->lock),
		.maps = LIST_HEAD_INIT(meta->maps)
	};

	msm_iommu_meta_add(meta);
	return meta;
}

int msm_dma_map_sg_attrs(struct device *dev, struct scatterlist *sg, int nents,
			 enum dma_data_direction dir, struct dma_buf *dma_buf,
			 struct dma_attrs *attrs)
{
	bool late_unmap = !dma_get_attr(DMA_ATTR_NO_DELAYED_UNMAP, attrs);
	bool extra_meta_ref_taken = false;
	struct msm_iommu_meta *meta;
	struct msm_iommu_map *map;
	int ret;

	if (IS_ERR_OR_NULL(dev)) {
		pr_err("%s: dev pointer is invalid\n", __func__);
		return -EINVAL;
	}

	if (IS_ERR_OR_NULL(sg)) {
		pr_err("%s: sg table pointer is invalid\n", __func__);
		return -EINVAL;
	}

	if (IS_ERR_OR_NULL(dma_buf)) {
		pr_err("%s: dma_buf pointer is invalid\n", __func__);
		return -EINVAL;
	}

	meta = msm_iommu_meta_lookup(dma_buf->priv);
	if (meta) {
		atomic_inc(&meta->refcount);
	} else {
		meta = msm_iommu_meta_create(dma_buf, late_unmap);
		if (!meta)
			return -ENOMEM;

		if (late_unmap)
			extra_meta_ref_taken = true;
	}

	read_lock(&meta->lock);
	map = msm_iommu_map_lookup(meta, dev);
	if (map)
		atomic_inc(&map->refcount);
	read_unlock(&meta->lock);

	if (map) {
		sg->dma_address = map->sgl.dma_address;
		sg->dma_length = map->sgl.dma_length;

		/*
		 * Ensure all outstanding changes for coherent buffers are
		 * applied to the cache before any DMA occurs.
		 */
		if (is_device_dma_coherent(dev))
			dmb(ish);
	} else {
		map = kmalloc(sizeof(*map), GFP_KERNEL);
		if (!map) {
			ret = -ENOMEM;
			goto release_meta;
		}

		ret = dma_map_sg_attrs(dev, sg, nents, dir, attrs);
		if (ret != nents) {
			kfree(map);
			goto release_meta;
		}

		*map = (typeof(*map)){
			.dev = dev,
			.meta = meta,
			.lnode = LIST_HEAD_INIT(map->lnode),
			.refcount = ATOMIC_INIT(1 + !!late_unmap),
			.sgl = {
				.dma_address = sg->dma_address,
				.dma_length = sg->dma_length
			}
		};

		msm_iommu_map_add(meta, map);
	}

	return nents;

release_meta:
	msm_iommu_meta_put(meta, 1 + !!extra_meta_ref_taken);
	return ret;
}

void msm_dma_unmap_sg(struct device *dev, struct scatterlist *sgl, int nents,
		      enum dma_data_direction dir, struct dma_buf *dma_buf)
{
	struct msm_iommu_meta *meta;
	struct msm_iommu_map *map;
	bool free_map;

	meta = msm_iommu_meta_lookup(dma_buf->priv);
	if (!meta)
		return;

	write_lock(&meta->lock);
	map = msm_iommu_map_lookup(meta, dev);
	if (!map) {
		write_unlock(&meta->lock);
		return;
	}

	map->dir = dir;
	free_map = atomic_dec_and_test(&map->refcount);
	if (free_map)
		list_del(&map->lnode);
	write_unlock(&meta->lock);

	if (free_map) {
		dma_unmap_sg(map->dev, &map->sgl, map->nents, map->dir);
		kfree(map);
	}

	msm_iommu_meta_put(meta, 1);
}

int msm_dma_unmap_all_for_dev(struct device *dev)
{
	struct msm_iommu_map *map, *map_next;
	struct rb_root *root = &iommu_root;
	struct msm_iommu_meta *meta;
	struct rb_node *meta_node;
	LIST_HEAD(unmap_list);
	int ret = 0;

	read_lock(&rb_tree_lock);
	meta_node = rb_first(root);
	while (meta_node) {
		meta = rb_entry(meta_node, typeof(*meta), node);
		write_lock(&meta->lock);
		list_for_each_entry_safe(map, map_next, &meta->maps, lnode) {
			if (map->dev != dev)
				continue;

			/* Do the actual unmapping outside of the locks */
			if (atomic_dec_and_test(&map->refcount))
				list_move_tail(&map->lnode, &unmap_list);
			else
				ret = -EINVAL;
		}
		write_unlock(&meta->lock);
		meta_node = rb_next(meta_node);
	}
	read_unlock(&rb_tree_lock);

	list_for_each_entry_safe(map, map_next, &unmap_list, lnode) {
		dma_unmap_sg(map->dev, &map->sgl, map->nents, map->dir);
		kfree(map);
	}

	return ret;
}

/* Only to be called by ION code when a buffer is freed */
void msm_dma_buf_freed(void *buffer)
{
	struct msm_iommu_map *map, *map_next;
	struct msm_iommu_meta *meta;
	LIST_HEAD(unmap_list);

	meta = msm_iommu_meta_lookup(buffer);
	if (!meta)
		return;

	write_lock(&meta->lock);
	list_for_each_entry_safe(map, map_next, &meta->maps, lnode) {
		/* Do the actual unmapping outside of the lock */
		if (atomic_dec_and_test(&map->refcount))
			list_move_tail(&map->lnode, &unmap_list);
		else
			list_del_init(&map->lnode);
	}
	write_unlock(&meta->lock);

	list_for_each_entry_safe(map, map_next, &unmap_list, lnode) {
		dma_unmap_sg(map->dev, &map->sgl, map->nents, map->dir);
		kfree(map);
	}

	msm_iommu_meta_put(meta, 1);
}
