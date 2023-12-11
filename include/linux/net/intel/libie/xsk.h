/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright(c) 2023 Intel Corporation. */

#ifndef __LIBIE_XSK_H
#define __LIBIE_XSK_H

#include <linux/net/intel/libie/xdp.h>

/* ``XDP_TX`` bulking */

#define libie_xsk_tx_init_bulk(bq, prog, dev, xdpqs, num)		\
	__libie_xdp_tx_init_bulk(bq, rcu_dereference(prog), dev,	\
				 (xdpqs)[libie_xdp_sq_id(num)])

static inline void libie_xsk_tx_queue_bulk(struct libie_xdp_tx_bulk *bq,
					   struct xdp_buff *xdp)
{
	bq->bulk[bq->count++] = (typeof(*bq->bulk)){
		.xsk	= xdp,
		.len	= xdp->data_end - xdp->data,
	};
}

static inline struct libie_xdp_tx_desc
libie_xsk_tx_fill_buf(const struct libie_xdp_tx_frame *frm,
		      const struct libie_xdp_tx_queue *sq)
{
	struct libie_xdp_tx_desc desc = {
		.len	= frm->len,
	};
	struct xdp_buff *xdp = frm->xsk;
	struct libie_tx_buffer *tx_buf;

	desc.addr = xsk_buff_xdp_get_dma(xdp);
	xsk_buff_raw_dma_sync_for_device(sq->pool, desc.addr, desc.len);

	tx_buf = &sq->tx_buf[sq->cached_ntu];
	tx_buf->type = LIBIE_TX_BUF_XSK_TX;
	tx_buf->gso_segs = 1;
	tx_buf->bytecount = desc.len;
	tx_buf->xdp = xdp;

	return desc;
}

#define libie_xsk_tx_flush_bulk(bq, prep, xmit)				 \
	__libie_xdp_tx_flush_bulk(bq, prep, libie_xsk_tx_fill_buf, xmit)

/* XSk xmit implementation */

#define libie_xsk_xmit_init_bulk(bq, xdpq)				 \
	__libie_xdp_tx_init_bulk(bq, NULL, NULL, xdpq)

static inline struct libie_xdp_tx_desc
libie_xsk_xmit_fill_buf(const struct libie_xdp_tx_frame *frm,
			const struct libie_xdp_tx_queue *sq)
{
	struct libie_xdp_tx_desc desc = {
		.len	= frm->desc.len,
	};

	desc.addr = xsk_buff_raw_get_dma(sq->pool, frm->desc.addr);
	xsk_buff_raw_dma_sync_for_device(sq->pool, desc.addr, desc.len);

	return desc;
}

static __always_inline bool
libie_xsk_xmit_do_bulk(void *xdpq, struct xsk_buff_pool *pool, u32 budget,
		       u32 (*prep)(void *xdpq, struct libie_xdp_tx_queue *sq),
		       void (*xmit)(struct libie_xdp_tx_desc desc,
				    const struct libie_xdp_tx_queue *sq),
		       void (*finalize)(void *xdpq, bool tail))
{
	struct libie_xdp_tx_bulk bq;
	u32 n, batched;

	n = xsk_tx_peek_release_desc_batch(pool, budget);
	if (unlikely(!n))
		return true;

	batched = ALIGN_DOWN(n, LIBIE_XDP_TX_BULK);

	libie_xsk_xmit_init_bulk(&bq, xdpq);
	bq.count = LIBIE_XDP_TX_BULK;

	for (u32 i = 0; i < batched; i += LIBIE_XDP_TX_BULK) {
		unsafe_memcpy(bq.bulk, &pool->tx_descs[i], sizeof(bq.bulk),
			      "false-positive, xdp_desc and libie_xdp_tx_frame are compatible");
		libie_xdp_tx_xmit_bulk(&bq, prep, libie_xsk_xmit_fill_buf,
				       xmit);
	}

	bq.count = n - batched;
	if (bq.count) {
		unsafe_memcpy(bq.bulk, &pool->tx_descs[batched],
			      bq.count * sizeof(*bq.bulk),
			      "false-positive, xdp_desc and libie_xdp_tx_frame are compatible");
		libie_xdp_tx_xmit_bulk(&bq, prep, libie_xsk_xmit_fill_buf,
				       xmit);
	}

	finalize(bq.xdpq, true);

	if (xsk_uses_need_wakeup(pool))
		xsk_set_tx_need_wakeup(pool);

	return n < budget;
}

/* Rx polling path */

static inline struct xdp_buff *libie_xsk_process_buff(struct xdp_buff **arr,
						      u32 id, u32 len)
{
	struct xdp_buff_xsk *xskb = container_of(arr[id], typeof(*xskb), xdp);
	struct xdp_buff *xdp = &xskb->xdp;

	if (unlikely(!len)) {
		xsk_buff_free(xdp);
		return NULL;
	}

	xsk_buff_set_size(xdp, len);
	xsk_buff_dma_sync_for_cpu(xdp, xskb->pool);

	net_prefetch(xdp->data);

	return xdp;
}

/**
 * __libie_xsk_run_prog - run XDP program on an XDP buffer
 * @xdp: XDP buffer to run the prog on
 * @bq: buffer bulk for ``XDP_TX`` queueing
 *
 * Return: LIBIE_XDP_{PASS,DROP,ABORTED,TX,REDIRECT} depending on the prog's
 * verdict.
 */
static inline u32 __libie_xsk_run_prog(struct xdp_buff *xdp,
				       struct libie_xdp_tx_bulk *bq)
{
	const struct bpf_prog *prog = bq->prog;
	u32 act, drop = LIBIE_XDP_DROP;
	struct xdp_buff_xsk *xsk;
	int ret;

	act = bpf_prog_run_xdp(prog, xdp);
	if (unlikely(act != XDP_REDIRECT))
		goto rest;

	ret = xdp_do_redirect(bq->dev, xdp, prog);
	if (unlikely(ret))
		goto check_err;

	return LIBIE_XDP_REDIRECT;

rest:
	switch (act) {
	case XDP_ABORTED:
err:
		trace_xdp_exception(bq->dev, prog, act);
		fallthrough;
	case XDP_DROP:
		xsk_buff_free(xdp);

		return drop;
	case XDP_PASS:
		return LIBIE_XDP_PASS;
	case XDP_TX:
		libie_xsk_tx_queue_bulk(bq, xdp);

		return LIBIE_XDP_TX;
	default:
		bpf_warn_invalid_xdp_action(bq->dev, prog, act);
		goto err;
	}

check_err:
	xsk = container_of(xdp, typeof(*xsk), xdp);
	if (xsk_uses_need_wakeup(xsk->pool) && ret == -ENOBUFS)
		drop = LIBIE_XDP_ABORTED;

	goto err;
}

#define libie_xsk_run_prog(xdp, bq, fl)					\
	__libie_xdp_run_flush(xdp, bq, __libie_xsk_run_prog, fl)

/* Externals */

int libie_xsk_enable_pool(struct net_device *dev, u32 qid, unsigned long *map);
int libie_xsk_disable_pool(struct net_device *dev, u32 qid,
			   unsigned long *map);

#endif /* __LIBIE_XSK_H */
