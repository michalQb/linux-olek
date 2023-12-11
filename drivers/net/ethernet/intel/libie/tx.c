// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2023 Intel Corporation. */

#include <linux/net/intel/libie/xdp.h>

void libie_tx_complete_any(struct libie_tx_buffer *buf, struct device *dev,
			   struct xdp_frame_bulk *bq, u32 *xdp_tx_active,
			   struct libie_sq_onstack_stats *ss)
{
	if (buf->type > LIBIE_TX_BUF_SKB)
		libie_xdp_complete_tx_buf(buf, dev, false, bq, xdp_tx_active,
					  ss);
	else
		libie_tx_complete_buf(buf, dev, false, ss);
}
EXPORT_SYMBOL_NS_GPL(libie_tx_complete_any, LIBIE);
