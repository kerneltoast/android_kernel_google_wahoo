// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2016, The Linux Foundation. All rights reserved.
 * Copyright (C) 2019 Sultan Alsawaf <sultan@kerneltoast.com>.
 */

#include <linux/dma-buf.h>
#include <linux/msm_dma_iommu_mapping.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <asm/barrier.h>

struct msm_iommu_map {
	struct device *dev;
	struct msm_iommu_data *data;
	struct list_head data_node;
	struct list_head dev_node;
	struct scatterlist sg;
	enum dma_data_direction dir;
	int nents;
	int refcount;
};

static struct msm_iommu_map *msm_iommu_map_lookup(struct msm_iommu_data *data,
						  struct device *dev)
{
	struct msm_iommu_map *map;

	list_for_each_entry(map, &data->map_list, data_node) {
		if (map->dev == dev)
			return map;
	}

	return NULL;
}

static void msm_iommu_map_free(struct msm_iommu_map *map)
{
	list_del(&map->data_node);
	list_del(&map->dev_node);
	dma_unmap_sg(map->dev, &map->sg, map->nents, map->dir);
	kfree(map);
}

int msm_dma_map_sg_attrs(struct device *dev, struct scatterlist *sg, int nents,
			 enum dma_data_direction dir, struct dma_buf *dmabuf,
			 struct dma_attrs *attrs)
{
	int not_lazy = dma_get_attr(DMA_ATTR_NO_DELAYED_UNMAP, attrs);
	struct msm_iommu_data *data = dmabuf->priv;
	struct msm_iommu_map *map;

	mutex_lock(&dev->iommu_map_lock);
	mutex_lock(&data->lock);
	map = msm_iommu_map_lookup(data, dev);
	if (map) {
		map->refcount++;
		sg->dma_address = map->sg.dma_address;
		sg->dma_length = map->sg.dma_length;
		if (is_device_dma_coherent(dev))
			dmb(ish);
	} else {
		nents = dma_map_sg_attrs(dev, sg, nents, dir, attrs);
		if (nents) {
			map = kmalloc(sizeof(*map), GFP_KERNEL | __GFP_NOFAIL);
			map->data = data;
			map->dev = dev;
			map->dir = dir;
			map->nents = nents;
			map->refcount = 2 - not_lazy;
			map->sg.dma_address = sg->dma_address;
			map->sg.dma_length = sg->dma_length;
			list_add(&map->data_node, &data->map_list);
			list_add(&map->dev_node, &dev->iommu_map_list);
		}
	}
	mutex_unlock(&data->lock);
	mutex_unlock(&dev->iommu_map_lock);

	return nents;
}

void msm_dma_unmap_sg(struct device *dev, struct scatterlist *sg, int nents,
		      enum dma_data_direction dir, struct dma_buf *dmabuf)
{
	struct msm_iommu_data *data = dmabuf->priv;
	struct msm_iommu_map *map;

	mutex_lock(&dev->iommu_map_lock);
	mutex_lock(&data->lock);
	map = msm_iommu_map_lookup(data, dev);
	if (map && !--map->refcount)
		msm_iommu_map_free(map);
	mutex_unlock(&data->lock);
	mutex_unlock(&dev->iommu_map_lock);
}

void msm_dma_unmap_all_for_dev(struct device *dev)
{
	struct msm_iommu_map *map, *tmp;

	mutex_lock(&dev->iommu_map_lock);
	list_for_each_entry_safe(map, tmp, &dev->iommu_map_list, dev_node) {
		struct msm_iommu_data *data = map->data;

		mutex_lock(&data->lock);
		msm_iommu_map_free(map);
		mutex_unlock(&data->lock);
	}
	mutex_unlock(&dev->iommu_map_lock);
}

void msm_dma_buf_freed(struct msm_iommu_data *data)
{
	struct msm_iommu_map *map, *tmp;
	int retry = 0;

	do {
		mutex_lock(&data->lock);
		list_for_each_entry_safe(map, tmp, &data->map_list, data_node) {
			struct device *dev = map->dev;

			if (!mutex_trylock(&dev->iommu_map_lock)) {
				retry = 1;
				break;
			}

			msm_iommu_map_free(map);
			mutex_unlock(&dev->iommu_map_lock);
		}
		mutex_unlock(&data->lock);
	} while (retry--);
}
