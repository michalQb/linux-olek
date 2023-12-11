/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 Intel Corporation */

#ifndef __LIBETH_XSK_H
#define __LIBETH_XSK_H

#include <net/libeth/xdp.h>
#include <net/xdp_sock_drv.h>

/* ``XDP_TXMD_FLAGS_VALID`` is defined only under ``CONFIG_XDP_SOCKETS`` */
#ifdef XDP_TXMD_FLAGS_VALID
static_assert(XDP_TXMD_FLAGS_VALID <= LIBETH_XDP_TX_XSKMD);
#endif

/* ``XDP_TX`` bulking */

static inline bool libeth_xsk_tx_queue_head(struct libeth_xdp_tx_bulk *bq,
					    struct libeth_xdp_buff *xdp)
{
	bq->bulk[bq->count++] = (typeof(*bq->bulk)){
		.xsk	= xdp,
		__libeth_xdp_tx_len(xdp->base.data_end - xdp->data,
				    LIBETH_XDP_TX_FIRST),
	};

	if (!xdp_buff_has_frags(&xdp->base))
		return false;

	bq->bulk[bq->count - 1].flags |= LIBETH_XDP_TX_MULTI;

	return true;
}

static inline void libeth_xsk_tx_queue_frag(struct libeth_xdp_tx_bulk *bq,
					    struct libeth_xdp_buff *frag)
{
	bq->bulk[bq->count++] = (typeof(*bq->bulk)){
		.xsk	= frag,
		__libeth_xdp_tx_len(frag->base.data_end - frag->data),
	};
}

static __always_inline bool
libeth_xsk_tx_queue_bulk(struct libeth_xdp_tx_bulk *bq,
			 struct libeth_xdp_buff *xdp,
			 bool (*flush_bulk)(struct libeth_xdp_tx_bulk *bq,
					    u32 flags))
{
	bool ret = true;

	if (unlikely(bq->count == LIBETH_XDP_TX_BULK) &&
	    unlikely(!flush_bulk(bq, LIBETH_XDP_TX_XSK))) {
		libeth_xsk_buff_free_slow(xdp);
		return false;
	}

	if (!libeth_xsk_tx_queue_head(bq, xdp))
		goto out;

	for (const struct libeth_xdp_buff *head = xdp; ; ) {
		xdp = container_of(xsk_buff_get_frag(&head->base),
				   typeof(*xdp), base);
		if (!xdp)
			break;

		if (unlikely(bq->count == LIBETH_XDP_TX_BULK) &&
		    unlikely(!flush_bulk(bq, LIBETH_XDP_TX_XSK))) {
			ret = false;
			break;
		}

		libeth_xsk_tx_queue_frag(bq, xdp);
	};

out:
	bq->bulk[bq->count - 1].flags |= LIBETH_XDP_TX_LAST;

	return ret;
}

static inline struct libeth_xdp_tx_desc
libeth_xsk_tx_fill_buf(struct libeth_xdp_tx_frame frm, u32 i,
		       const struct libeth_xdpsq *sq, u64 priv)
{
	struct libeth_xdp_buff *xdp = frm.xsk;
	struct libeth_xdp_tx_desc desc = {
		.addr	= xsk_buff_xdp_get_dma(&xdp->base),
		.opts	= frm.opts,
	};
	struct libeth_sqe *sqe;

	xsk_buff_raw_dma_sync_for_device(sq->pool, desc.addr, desc.len);

	sqe = &sq->sqes[i];
	sqe->xsk = xdp;

	if (!(desc.flags & LIBETH_XDP_TX_FIRST)) {
		sqe->type = LIBETH_SQE_XSK_TX_FRAG;
		return desc;
	}

	sqe->type = LIBETH_SQE_XSK_TX;
	libeth_xdp_tx_fill_stats(sqe, &desc,
				 xdp_get_shared_info_from_buff(&xdp->base));

	return desc;
}

#define libeth_xsk_tx_flush_bulk(bq, flags, prep, xmit)			     \
	__libeth_xdp_tx_flush_bulk(bq, (flags) | LIBETH_XDP_TX_XSK, prep,    \
				   libeth_xsk_tx_fill_buf, xmit)

/* XSk TMO */

static inline void libeth_xsktmo_req_csum(u16 csum_start, u16 csum_offset,
					  void *priv)
{
	((struct libeth_xdp_tx_desc *)priv)->flags |= LIBETH_XDP_TX_CSUM;
}

/* Only to inline the callbacks below, use @libeth_xsktmo in drivers instead */
static const struct xsk_tx_metadata_ops __libeth_xsktmo = {
	.tmo_request_checksum	= libeth_xsktmo_req_csum,
};

static __always_inline struct libeth_xdp_tx_desc
__libeth_xsk_xmit_fill_buf_md(const struct xdp_desc *xdesc,
			      const struct libeth_xdpsq *sq,
			      u64 priv)
{
	const struct xsk_tx_metadata_ops *tmo = libeth_xdp_priv_to_ptr(priv);
	struct libeth_xdp_tx_desc desc;
	struct xdp_desc_ctx ctx;

	ctx = xsk_buff_raw_get_ctx(sq->pool, xdesc->addr);
	desc = (typeof(desc)){
		.addr	= ctx.dma,
		__libeth_xdp_tx_len(xdesc->len),
	};

	BUILD_BUG_ON(!__builtin_constant_p(tmo == libeth_xsktmo));
	tmo = tmo == libeth_xsktmo ? &__libeth_xsktmo : tmo;

	xsk_tx_metadata_request(ctx.meta, tmo, &desc);

	return desc;
}

/* XSk xmit implementation */

static inline struct libeth_xdp_tx_desc
__libeth_xsk_xmit_fill_buf(const struct xdp_desc *xdesc,
			   const struct libeth_xdpsq *sq)
{
	return (struct libeth_xdp_tx_desc){
		.addr	= xsk_buff_raw_get_dma(sq->pool, xdesc->addr),
		__libeth_xdp_tx_len(xdesc->len),
	};
}

static __always_inline struct libeth_xdp_tx_desc
libeth_xsk_xmit_fill_buf(struct libeth_xdp_tx_frame frm, u32 i,
			 const struct libeth_xdpsq *sq, u64 priv)
{
	struct libeth_xdp_tx_desc desc;

	if (priv)
		desc = __libeth_xsk_xmit_fill_buf_md(&frm.desc, sq, priv);
	else
		desc = __libeth_xsk_xmit_fill_buf(&frm.desc, sq);

	desc.flags |= xsk_is_eop_desc(&frm.desc) ? LIBETH_XDP_TX_LAST : 0;

	xsk_buff_raw_dma_sync_for_device(sq->pool, desc.addr, desc.len);

	return desc;
}

static __always_inline bool
libeth_xsk_xmit_do_bulk(struct xsk_buff_pool *pool, void *xdpsq, u32 budget,
			const struct xsk_tx_metadata_ops *tmo,
			u32 (*prep)(void *xdpsq, struct libeth_xdpsq *sq),
			void (*xmit)(struct libeth_xdp_tx_desc desc, u32 i,
				     const struct libeth_xdpsq *sq, u64 priv),
			void (*finalize)(void *xdpsq, bool sent, bool flush))
{
	const struct libeth_xdp_tx_frame *bulk;
	bool wake;
	u32 n;

	wake = xsk_uses_need_wakeup(pool);
	if (wake)
		xsk_clear_tx_need_wakeup(pool);

	n = xsk_tx_peek_release_desc_batch(pool, budget);
	bulk = (typeof(bulk))pool->tx_descs;

	libeth_xdp_tx_xmit_bulk(bulk, xdpsq, n, true,
				libeth_xdp_ptr_to_priv(tmo), prep,
				libeth_xsk_xmit_fill_buf, xmit);
	finalize(xdpsq, n, true);

	if (wake)
		xsk_set_tx_need_wakeup(pool);

	return n < budget;
}

/* Rx polling path */

#define libeth_xsk_tx_init_bulk(bq, prog, dev, xdpsqs, num)		     \
	__libeth_xdp_tx_init_bulk(bq, prog, dev, xdpsqs, num, true,	     \
				  __UNIQUE_ID(bq_), __UNIQUE_ID(nqs_))

struct libeth_xdp_buff *libeth_xsk_buff_add_frag(struct libeth_xdp_buff *head,
						 struct libeth_xdp_buff *xdp);

static inline struct libeth_xdp_buff *
libeth_xsk_process_buff(struct libeth_xdp_buff *head,
			struct libeth_xdp_buff *xdp, u32 len)
{
	if (unlikely(!len)) {
		libeth_xsk_buff_free_slow(xdp);
		return head;
	}

	xsk_buff_set_size(&xdp->base, len);
	xsk_buff_dma_sync_for_cpu(&xdp->base);

	if (head)
		return libeth_xsk_buff_add_frag(head, xdp);

	prefetch(xdp->data);

	return xdp;
}

u32 __libeth_xsk_run_prog_slow(struct libeth_xdp_buff *xdp,
			       const struct libeth_xdp_tx_bulk *bq,
			       enum xdp_action act, int ret);

/**
 * __libeth_xsk_run_prog - run XDP program on an XDP buffer
 * @xdp: XDP buffer to run the prog on
 * @bq: buffer bulk for ``XDP_TX`` queueing
 *
 * Return: LIBETH_XDP_{PASS,DROP,ABORTED,TX,REDIRECT} depending on the prog's
 * verdict.
 */
static __always_inline u32
__libeth_xsk_run_prog(struct libeth_xdp_buff *xdp,
		      const struct libeth_xdp_tx_bulk *bq)
{
	enum xdp_action act;
	int ret = 0;

	act = bpf_prog_run_xdp(bq->prog, &xdp->base);
	if (unlikely(act != XDP_REDIRECT))
rest:
		return __libeth_xsk_run_prog_slow(xdp, bq, act, ret);

	ret = xdp_do_redirect(bq->dev, &xdp->base, bq->prog);
	if (unlikely(ret))
		goto rest;

	return LIBETH_XDP_REDIRECT;
}

#define libeth_xsk_run_prog(xdp, bq, fl)				     \
	__libeth_xdp_run_flush(xdp, bq, __libeth_xsk_run_prog,		     \
			       libeth_xsk_tx_queue_bulk, fl)

static __always_inline bool
__libeth_xsk_run_pass(struct libeth_xdp_buff *xdp,
		      struct libeth_xdp_tx_bulk *bq, struct napi_struct *napi,
		      struct libeth_rq_napi_stats *ss, const void *md,
		      void (*prep)(struct libeth_xdp_buff *xdp,
				   const void *md),
		      u32 (*run)(struct libeth_xdp_buff *xdp,
				 struct libeth_xdp_tx_bulk *bq),
		      bool (*populate)(struct sk_buff *skb,
				       const struct libeth_xdp_buff *xdp,
				       struct libeth_rq_napi_stats *ss))
{
	struct sk_buff *skb;
	u32 act;

	ss->bytes += xdp_get_buff_len(&xdp->base) + ETH_FCS_LEN;
	ss->packets++;

	if (prep && (!__builtin_constant_p(!!md) || md))
		prep(xdp, md);

	act = run(xdp, bq);
	if (unlikely(act == LIBETH_XDP_ABORTED))
		return false;
	else if (likely(act != LIBETH_XDP_PASS))
		return true;

	skb = xdp_build_skb_from_zc(&xdp->base);
	if (unlikely(!skb)) {
		libeth_xsk_buff_free_slow(xdp);
		return true;
	}

	if (unlikely(!populate(skb, xdp, ss))) {
		napi_consume_skb(skb, true);
		return true;
	}

	napi_gro_receive(napi, skb);

	return true;
}

#define libeth_xsk_run_pass(xdp, bq, napi, ss, desc, run, populate)	     \
	__libeth_xsk_run_pass(xdp, bq, napi, ss, desc, libeth_xdp_prep_desc, \
			      run, populate)

#define libeth_xsk_finalize_rx(bq, flush, finalize)			     \
	__libeth_xdp_finalize_rx(bq, LIBETH_XDP_TX_XSK, flush, finalize)

/* Helpers to reduce boilerplate code in drivers */

#define LIBETH_XSK_DEFINE_FLUSH_TX(name, prep, xmit)			     \
	__LIBETH_XDP_DEFINE_FLUSH_TX(name, prep, xmit, xsk)

#define LIBETH_XSK_DEFINE_RUN_PROG(name, flush)				     \
	u32 __LIBETH_XDP_DEFINE_RUN_PROG(name, flush, xsk)

#define LIBETH_XSK_DEFINE_RUN_PASS(name, run, populate)			     \
	bool __LIBETH_XDP_DEFINE_RUN_PASS(name, run, populate, xsk)

#define LIBETH_XSK_DEFINE_RUN(name, run, flush, populate)		     \
	__LIBETH_XDP_DEFINE_RUN(name, run, flush, populate, XSK)

#define LIBETH_XSK_DEFINE_FINALIZE(name, flush, finalize)		     \
	__LIBETH_XDP_DEFINE_FINALIZE(name, flush, finalize, xsk)

/* Refill */

struct libeth_xskfq {
	struct_group_tagged(libeth_xskfq_fp, fp,
		struct xsk_buff_pool	*pool;
		struct libeth_xdp_buff	**fqes;
		void			*descs;

		u32			ntu;
		u32			count;
	);

	/* Cold fields */
	u32			pending;
	u32			thresh;

	u32			buf_len;
	int			nid;
};

int libeth_xskfq_create(struct libeth_xskfq *fq);
void libeth_xskfq_destroy(struct libeth_xskfq *fq);

#define libeth_xsk_buff_xdp_get_dma(xdp)				     \
	xsk_buff_xdp_get_dma(&(xdp)->base)

static __always_inline u32
libeth_xskfqe_alloc(struct libeth_xskfq_fp *fq, u32 n,
		    void (*fill)(const struct libeth_xskfq_fp *fq, u32 i))
{
	u32 this, ret, done = 0;
	struct xdp_buff **xskb;

	this = fq->count - fq->ntu;
	if (likely(this > n))
		this = n;

again:
	xskb = (typeof(xskb))&fq->fqes[fq->ntu];
	ret = xsk_buff_alloc_batch(fq->pool, xskb, this);

	for (u32 i = 0, ntu = fq->ntu; likely(i < ret); i++)
		fill(fq, ntu + i);

	done += ret;
	fq->ntu += ret;

	if (likely(fq->ntu < fq->count) || unlikely(ret < this))
		goto out;

	fq->ntu = 0;

	if (this < n) {
		this = n - this;
		goto again;
	}

out:
	return done;
}

/* .ndo_xsk_wakeup */

void libeth_xsk_init_wakeup(call_single_data_t *csd, struct napi_struct *napi);
void libeth_xsk_wakeup(call_single_data_t *csd, u32 qid);

/* Pool setup */

int libeth_xsk_setup_pool(struct net_device *dev, u32 qid, bool enable);

#endif /* __LIBETH_XSK_H */
