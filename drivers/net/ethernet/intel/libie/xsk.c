// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2023 Intel Corporation. */

#include <linux/net/intel/libie/xsk.h>

#define LIBIE_XSK_DMA_ATTR	(DMA_ATTR_WEAK_ORDERING |	\
				 DMA_ATTR_SKIP_CPU_SYNC)

int libie_xsk_enable_pool(struct net_device *dev, u32 qid, unsigned long *map)
{
	struct xsk_buff_pool *pool;
	int ret;

	if (qid >= min(dev->real_num_rx_queues, dev->real_num_tx_queues))
		return -EINVAL;

	pool = xsk_get_pool_from_qid(dev, qid);
	if (!pool)
		return -EINVAL;

	ret = xsk_pool_dma_map(pool, dev->dev.parent, LIBIE_XSK_DMA_ATTR);
	if (ret)
		return ret;

	set_bit(qid, map);

	return 0;
}
EXPORT_SYMBOL_NS_GPL(libie_xsk_enable_pool, LIBIE);

int libie_xsk_disable_pool(struct net_device *dev, u32 qid,
			   unsigned long *map)
{
	struct xsk_buff_pool *pool;

	if (qid >= min(dev->real_num_rx_queues, dev->real_num_tx_queues))
		return -EINVAL;

	pool = xsk_get_pool_from_qid(dev, qid);
	if (!pool)
		return -EINVAL;

	xsk_pool_dma_unmap(pool, LIBIE_XSK_DMA_ATTR);

	clear_bit(qid, map);

	return 0;
}
EXPORT_SYMBOL_NS_GPL(libie_xsk_disable_pool, LIBIE);
