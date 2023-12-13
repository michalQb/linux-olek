/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright(c) 2023 Intel Corporation. */

#ifndef __LIBIE_TX_H
#define __LIBIE_TX_H

#include <linux/net/intel/libie/stats.h>
#include <linux/skbuff.h>

/**
 * enum libie_tx_buf_type - type of &libie_tx_buf to act on Tx completion
 * @LIBIE_TX_BUF_EMPTY: unused OR XSk frame, no action required
 * @LIBIE_TX_BUF_SLAB: kmalloc-allocated buffer, unmap and kfree()
 * @LIBIE_TX_BUF_FRAG: mapped skb OR &xdp_buff frag, only unmap DMA
 * @LIBIE_TX_BUF_SKB: &sk_buff, unmap and consume_skb(), update stats
 * @LIBIE_TX_BUF_XDP_TX: &skb_shared_info, page_pool_put_full_page(), stats
 * @LIBIE_TX_BUF_XDP_XMIT: &xdp_frame, unmap and xdp_return_frame(), stats
 * @LIBIE_TX_BUF_XSK_TX: &xdp_buff on XSk queue, xsk_buff_free(), stats
 */
enum libie_tx_buf_type {
	LIBIE_TX_BUF_EMPTY	= 0U,
	LIBIE_TX_BUF_SLAB,
	LIBIE_TX_BUF_FRAG,
	LIBIE_TX_BUF_SKB,
	LIBIE_TX_BUF_XDP_TX,
	LIBIE_TX_BUF_XDP_XMIT,
	LIBIE_TX_BUF_XSK_TX,
};

struct libie_tx_buffer {
	void			*next_to_watch;
	union {
		void			*raw;
		struct sk_buff		*skb;
		struct skb_shared_info	*sinfo;
		struct xdp_frame	*xdpf;
		struct xdp_buff		*xdp;
	};

	DEFINE_DMA_UNMAP_ADDR(dma);
	DEFINE_DMA_UNMAP_LEN(len);

	u32			bytecount;
	u16			gso_segs;
	enum libie_tx_buf_type	type:16;

	u32			priv;
} __aligned_largest;

static inline void libie_tx_complete_buf(struct libie_tx_buffer *buf,
					 struct device *dev, bool napi,
					 struct libie_sq_onstack_stats *ss)
{
	switch (buf->type) {
	case LIBIE_TX_BUF_EMPTY:
		return;
	case LIBIE_TX_BUF_SLAB:
	case LIBIE_TX_BUF_FRAG:
	case LIBIE_TX_BUF_SKB:
		dma_unmap_page(dev, dma_unmap_addr(buf, dma),
			       dma_unmap_len(buf, len),
			       DMA_TO_DEVICE);
		break;
	default:
		break;
	}

	switch (buf->type) {
	case LIBIE_TX_BUF_SLAB:
		kfree(buf->raw);
		break;
	case LIBIE_TX_BUF_SKB:
		ss->packets += buf->gso_segs;
		ss->bytes += buf->bytecount;

		napi_consume_skb(buf->skb, napi);
		break;
	default:
		break;
	}

	buf->type = LIBIE_TX_BUF_EMPTY;
}

#endif /* __LIBIE_TX_H */
