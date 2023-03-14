// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2024 Intel Corporation */

#include <linux/etherdevice.h>
#include <linux/ethtool.h>

#include <net/libeth/netdev.h>
#include <net/libeth/types.h>

#include "priv.h"

struct net_device *__libeth_netdev_alloc(u32 priv, u32 rqs, u32 sqs,
					 u32 xdpsqs)
{
	struct net_device *dev;

	dev = alloc_etherdev_mqs(priv, sqs, rqs);
	if (!dev)
		return NULL;

	if (!libeth_stats_init_priv(dev, rqs, sqs, xdpsqs))
		goto err_netdev;

	return dev;

err_netdev:
	free_netdev(dev);

	return NULL;
}
EXPORT_SYMBOL_NS_GPL(__libeth_netdev_alloc, LIBETH);

void libeth_netdev_free(struct net_device *dev)
{
	libeth_stats_free_priv(dev);
	free_netdev(dev);
}
EXPORT_SYMBOL_NS_GPL(libeth_netdev_free, LIBETH);

int __libeth_set_real_num_queues(struct net_device *dev, u32 rqs, u32 sqs,
				 u32 xdpsqs)
{
	struct libeth_netdev_priv *priv = netdev_priv(dev);
	int ret;

	ret = netif_set_real_num_rx_queues(dev, rqs);
	if (ret)
		return ret;

	ret = netif_set_real_num_tx_queues(dev, sqs);
	if (ret)
		return ret;

	priv->curr_xdpsqs = xdpsqs;

	return 0;
}
EXPORT_SYMBOL_NS_GPL(__libeth_set_real_num_queues, LIBETH);

/* Ethtool */

int libeth_ethtool_get_sset_count(struct net_device *dev, int sset)
{
	if (sset != ETH_SS_STATS)
		return -EINVAL;

	return libeth_stats_get_sset_count(dev);
}
EXPORT_SYMBOL_NS_GPL(libeth_ethtool_get_sset_count, LIBETH);

void libeth_ethtool_get_strings(struct net_device *dev, u32 sset, u8 *data)
{
	if (sset != ETH_SS_STATS)
		return;

	libeth_stats_get_strings(dev, data);
}
EXPORT_SYMBOL_NS_GPL(libeth_ethtool_get_strings, LIBETH);

void libeth_ethtool_get_stats(struct net_device *dev,
			      struct ethtool_stats *stats,
			      u64 *data)
{
	libeth_stats_get_data(dev, data);
}
EXPORT_SYMBOL_NS_GPL(libeth_ethtool_get_stats, LIBETH);

/* Module */

MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION("Common Ethernet library");
MODULE_LICENSE("GPL");
