// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2023 Intel Corporation. */

#include <linux/net/intel/libie/xdp.h>

/* XDP SQ sharing */

DEFINE_STATIC_KEY_FALSE(libie_xdp_sq_share);
EXPORT_SYMBOL_NS_GPL(libie_xdp_sq_share, LIBIE);

void __libie_xdp_sq_get(struct libie_xdp_sq_lock *lock,
			const struct net_device *dev)
{
	bool warn;

	spin_lock_init(&lock->lock);
	lock->share = true;

	warn = !static_key_enabled(&libie_xdp_sq_share);
	static_branch_inc_cpuslocked(&libie_xdp_sq_share);

	if (warn)
		netdev_warn(dev, "XDP SQ sharing enabled, possible XDP_TX/XDP_REDIRECT slowdown\n");
}
EXPORT_SYMBOL_NS_GPL(__libie_xdp_sq_get, LIBIE);

void __libie_xdp_sq_put(struct libie_xdp_sq_lock *lock,
			const struct net_device *dev)
{
	static_branch_dec_cpuslocked(&libie_xdp_sq_share);

	if (!static_key_enabled(&libie_xdp_sq_share))
		netdev_notice(dev, "XDP SQ sharing disabled\n");

	lock->share = false;
}
EXPORT_SYMBOL_NS_GPL(__libie_xdp_sq_put, LIBIE);

/* ``XDP_TX`` bulking */

void libie_xdp_tx_return_bulk(const struct libie_xdp_tx_frame *bq, u32 count)
{
	for (u32 i = 0; i < count; i++)
		libie_xdp_return_va(bq[i].data, true);
}
EXPORT_SYMBOL_NS_GPL(libie_xdp_tx_return_bulk, LIBIE);
