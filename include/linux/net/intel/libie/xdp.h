/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright(c) 2023 Intel Corporation. */

#ifndef __LIBIE_XDP_H
#define __LIBIE_XDP_H

#include <linux/bpf_trace.h>
#include <linux/net/intel/libie/rx.h>
#include <linux/net/intel/libie/tx.h>

#include <net/xdp_sock_drv.h>

/* Defined as bits to be able to use them as a mask */
enum {
	LIBIE_XDP_PASS			= 0U,
	LIBIE_XDP_DROP			= BIT(0),
	LIBIE_XDP_TX			= BIT(1),
	LIBIE_XDP_REDIRECT		= BIT(2),
};

/* XDP SQ sharing */

struct libie_xdp_sq_lock {
	spinlock_t			lock;
	bool				share;
};

DECLARE_STATIC_KEY_FALSE(libie_xdp_sq_share);

static inline u32 libie_xdp_get_sq_num(u32 txq, u32 max)
{
	return min(nr_cpu_ids, max - txq);
}

static inline bool libie_xdp_sq_shared(u32 xdpq)
{
	return xdpq < nr_cpu_ids;
}

static inline u32 libie_xdp_sq_id(u32 num)
{
	u32 ret = smp_processor_id();

	if (static_branch_unlikely(&libie_xdp_sq_share) &&
	    libie_xdp_sq_shared(num))
		ret %= num;

	return ret;
}

void __libie_xdp_sq_get(struct libie_xdp_sq_lock *lock,
			const struct net_device *dev);
void __libie_xdp_sq_put(struct libie_xdp_sq_lock *lock,
			const struct net_device *dev);

static inline void libie_xdp_sq_get(struct libie_xdp_sq_lock *lock,
				    const struct net_device *dev,
				    bool share)
{
	if (unlikely(share))
		__libie_xdp_sq_get(lock, dev);
}

static inline void libie_xdp_sq_put(struct libie_xdp_sq_lock *lock,
				    const struct net_device *dev)
{
	if (static_branch_unlikely(&libie_xdp_sq_share) && lock->share)
		__libie_xdp_sq_put(lock, dev);
}

static inline void __acquires(&lock->lock)
libie_xdp_sq_lock(struct libie_xdp_sq_lock *lock)
{
	if (static_branch_unlikely(&libie_xdp_sq_share) && lock->share)
		spin_lock(&lock->lock);
}

static inline void __releases(&lock->lock)
libie_xdp_sq_unlock(struct libie_xdp_sq_lock *lock)
{
	if (static_branch_unlikely(&libie_xdp_sq_share) && lock->share)
		spin_unlock(&lock->lock);
}

/* ``XDP_TX`` bulking */

#define LIBIE_XDP_TX_BULK		XDP_BULK_QUEUE_SIZE
#define LIBIE_XDP_TX_BATCH		8

#ifdef __clang__
#define libie_xdp_tx_for		_Pragma("clang loop unroll_count(8)") for
#elif __GNUC__ >= 8
#define libie_xdp_tx_for		_Pragma("GCC unroll (8)") for
#else
#define libie_xdp_tx_for		for
#endif

struct libie_xdp_tx_frame {
	union {
		struct {
			void				*data;
			u16				len;

			enum xdp_buff_flags		flags:16;
			u32				soff;
		};
		struct {
			struct xdp_frame		*xdpf;
			dma_addr_t			dma;
		};
	};
};

struct libie_xdp_tx_bulk {
	const struct bpf_prog		*prog;
	const struct net_device		*dev;
	void				*xdpq;

	u32				act_mask;
	u32				count;
	struct libie_xdp_tx_frame	bulk[LIBIE_XDP_TX_BULK];
};

struct libie_xdp_tx_queue {
	struct device			*dev;
	struct libie_tx_buffer		*tx_buf;
	void				*desc_ring;

	struct libie_xdp_sq_lock	*xdp_lock;
	u16				*next_to_use;
	u32				desc_count;
};

struct libie_xdp_tx_desc {
	dma_addr_t			addr;
	u32				len;
};

static inline void __libie_xdp_tx_init_bulk(struct libie_xdp_tx_bulk *bq,
					    const struct bpf_prog *prog,
					    const struct net_device *dev,
					    void *xdpq)
{
	bq->prog = prog;
	bq->dev = dev;
	bq->xdpq = xdpq;

	bq->act_mask = 0;
	bq->count = 0;
}

#define _libie_xdp_tx_init_bulk(bq, prog, dev, xdpqs, num, uniq) ({	  \
	const struct bpf_prog *uniq = rcu_dereference(prog);		  \
									  \
	if (uniq)							  \
		__libie_xdp_tx_init_bulk(bq, uniq, dev,			  \
					 &(xdpqs)[libie_xdp_sq_id(num)]); \
})

#define libie_xdp_tx_init_bulk(bq, prog, dev, xdpqs, num)		  \
	_libie_xdp_tx_init_bulk(bq, prog, dev, xdpqs, num,		  \
				__UNIQUE_ID(prog_))

static inline void libie_xdp_tx_queue_bulk(struct libie_xdp_tx_bulk *bq,
					   const struct xdp_buff *xdp)
{
	bq->bulk[bq->count++] = (typeof(*bq->bulk)){
		.data	= xdp->data,
		.len	= xdp->data_end - xdp->data,
		.soff	= xdp_data_hard_end(xdp) - xdp->data,
		.flags	= xdp->flags,
	};
}

static inline struct libie_xdp_tx_desc
libie_xdp_tx_fill_buf(const struct libie_xdp_tx_frame *frm,
		      const struct libie_xdp_tx_queue *sq)
{
	struct libie_tx_buffer *tx_buf;
	dma_addr_t dma;

	dma = page_pool_dma_sync_va_for_device(frm->data, frm->len);

	tx_buf = &sq->tx_buf[*sq->next_to_use];
	tx_buf->type = LIBIE_TX_BUF_XDP_TX;
	tx_buf->gso_segs = 1;
	tx_buf->bytecount = frm->len;
	tx_buf->sinfo = frm->data + frm->soff;

	dma_unmap_addr_set(tx_buf, dma, dma);
	dma_unmap_len_set(tx_buf, len, frm->len);

	return (struct libie_xdp_tx_desc){
		.addr	= dma,
		.len	= frm->len,
	};
}

static __always_inline u32
libie_xdp_tx_xmit_bulk(const struct libie_xdp_tx_bulk *bq,
		       u32 (*prep)(void *xdpq, struct libie_xdp_tx_queue *sq),
		       struct libie_xdp_tx_desc
		       (*fill)(const struct libie_xdp_tx_frame *frm,
			       const struct libie_xdp_tx_queue *sq),
		       void (*xmit)(struct libie_xdp_tx_desc desc,
				    const struct libie_xdp_tx_queue *sq))
{
	u32 this, batched, leftover, off = 0;
	struct libie_xdp_tx_queue sq;
	u32 free, count, ntu, i = 0;

	free = prep(bq->xdpq, &sq);
	count = min3(bq->count, free, LIBIE_XDP_TX_BULK);
	ntu = *sq.next_to_use;

again:
	this = sq.desc_count - ntu;
	if (likely(this > count))
		this = count;

	batched = ALIGN_DOWN(this, LIBIE_XDP_TX_BATCH);
	leftover = this - batched;

	for ( ; i < off + batched; i += LIBIE_XDP_TX_BATCH) {
		libie_xdp_tx_for (u32 j = 0; j < LIBIE_XDP_TX_BATCH; j++) {
			struct libie_xdp_tx_desc desc;

			desc = fill(&bq->bulk[i + j], &sq);
			xmit(desc, &sq);

			ntu++;
		}
	}

	for ( ; i < off + batched + leftover; i++) {
		struct libie_xdp_tx_desc desc;

		desc = fill(&bq->bulk[i], &sq);
		xmit(desc, &sq);

		ntu++;
	}

	if (likely(ntu < sq.desc_count))
		goto out;

	ntu = 0;

	count -= this;
	if (count) {
		off = i;
		goto again;
	}

out:
	*sq.next_to_use = ntu;
	libie_xdp_sq_unlock(sq.xdp_lock);

	return i;
}

void libie_xdp_tx_return_bulk(const struct libie_xdp_tx_frame *bq, u32 count);

static __always_inline bool
libie_xdp_tx_flush_bulk(struct libie_xdp_tx_bulk *bq,
			u32 (*prep)(void *xdpq, struct libie_xdp_tx_queue *sq),
			void (*xmit)(struct libie_xdp_tx_desc desc,
				     const struct libie_xdp_tx_queue *sq))
{
	u32 sent, drops;
	int err = 0;

	sent = libie_xdp_tx_xmit_bulk(bq, prep, libie_xdp_tx_fill_buf, xmit);
	drops = bq->count - sent;
	bq->count = 0;

	if (unlikely(drops)) {
		trace_xdp_exception(bq->dev, bq->prog, XDP_TX);
		err = -ENXIO;

		libie_xdp_tx_return_bulk(&bq->bulk[sent], drops);
	}

	trace_xdp_bulk_tx(bq->dev, sent, drops, err);

	return likely(sent);
}

/* .ndo_xdp_xmit() implementation */

static inline bool libie_xdp_xmit_queue_bulk(struct libie_xdp_tx_bulk *bq,
					     struct xdp_frame *xdpf)
{
	struct device *dev = bq->dev->dev.parent;
	dma_addr_t dma;

	dma = dma_map_single(dev, xdpf->data, xdpf->len, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, dma))
		return false;

	bq->bulk[bq->count++] = (typeof(*bq->bulk)){
		.xdpf		= xdpf,
		.dma		= dma,
	};

	return true;
}

static inline struct libie_xdp_tx_desc
libie_xdp_xmit_fill_buf(const struct libie_xdp_tx_frame *frm,
			const struct libie_xdp_tx_queue *sq)
{
	struct xdp_frame *xdpf = frm->xdpf;
	struct libie_tx_buffer *tx_buf;

	tx_buf = &sq->tx_buf[*sq->next_to_use];
	tx_buf->type = LIBIE_TX_BUF_XDP_XMIT;
	tx_buf->gso_segs = 1;
	tx_buf->bytecount = xdpf->len;
	tx_buf->xdpf = xdpf;

	dma_unmap_addr_set(tx_buf, dma, frm->dma);
	dma_unmap_len_set(tx_buf, len, xdpf->len);

	return (struct libie_xdp_tx_desc){
		.addr	= frm->dma,
		.len	= xdpf->len,
	};
}

static __always_inline int
__libie_xdp_xmit_do_bulk(struct libie_xdp_tx_bulk *bq,
			 struct xdp_frame **frames, u32 n, u32 flags,
			 u32 (*prep)(void *xdpq,
				     struct libie_xdp_tx_queue *sq),
			 void (*xmit)(struct libie_xdp_tx_desc desc,
				      const struct libie_xdp_tx_queue *sq),
			 void (*finalize)(void *xdpq, bool tail))
{
	int err = -ENXIO;
	u32 nxmit = 0;

	if (unlikely(flags & ~XDP_XMIT_FLAGS_MASK))
		return -EINVAL;

	for (u32 i = 0; i < n; i++) {
		if (!libie_xdp_xmit_queue_bulk(bq, frames[i]))
			break;
	}

	if (unlikely(!bq->count))
		goto out;

	nxmit = libie_xdp_tx_xmit_bulk(bq, prep, libie_xdp_xmit_fill_buf,
				       xmit);
	if (unlikely(!nxmit))
		goto out;

	finalize(bq->xdpq, flags & XDP_XMIT_FLUSH);

	if (likely(nxmit == n))
		err = 0;

out:
	trace_xdp_bulk_tx(bq->dev, nxmit, n - nxmit, err);

	return nxmit;
}

#define libie_xdp_xmit_init_bulk(bq, dev, xdpqs, num)			      \
	__libie_xdp_tx_init_bulk(bq, NULL, dev,				      \
				 &(xdpqs)[libie_xdp_sq_id(num)])

#define _libie_xdp_xmit_do_bulk(dev, n, fr, fl, xqs, nqs, pr, xm, fin, un) ({ \
	struct libie_xdp_tx_bulk un;					      \
									      \
	libie_xdp_xmit_init_bulk(&un, dev, xqs, nqs);			      \
	__libie_xdp_xmit_do_bulk(&un, fr, n, fl, pr, xm, fin);		      \
})
#define libie_xdp_xmit_do_bulk(dev, n, fr, fl, xqs, nqs, pr, xm, fin)	      \
	_libie_xdp_xmit_do_bulk(dev, n, fr, fl, xqs, nqs, pr, xm, fin,	      \
				__UNIQUE_ID(bq_))

/* Rx polling path */

/**
 * libie_xdp_process_buf - process an Rx buffer
 * @xdp: XDP buffer to attach the buffer to
 * @buf: Rx buffer to process
 * @len: received data length from the descriptor
 *
 * Return: false if the descriptor must be skipped, true otherwise.
 */
static inline bool libie_xdp_process_buf(struct xdp_buff *xdp,
					 const struct libie_rx_buffer *buf,
					 u32 len)
{
	if (!libie_rx_sync_for_cpu(buf, len))
		return false;

	if (!xdp->data) {
		xdp->flags = 0;
		xdp->frame_sz = buf->truesize;

		xdp_prepare_buff(xdp, page_address(buf->page) + buf->offset,
				 buf->page->pp->p.offset, len, true);
	} else if (!xdp_buff_add_frag(xdp, buf->page,
				      buf->offset + buf->page->pp->p.offset,
				      len, buf->truesize)) {
		xdp_return_buff(xdp);
		xdp->data = NULL;

		return false;
	}

	return true;
}

/**
 * libie_run_xdp - run XDP program on an XDP buffer
 * @xdp: XDP buffer to run the prog on
 * @bq: buffer bulk for ``XDP_TX`` queueing
 *
 * Return: LIBIE_XDP_{PASS,DROP,TX,REDIRECT} depending on the prog's verdict.
 */
static inline u32 __libie_xdp_run(struct xdp_buff *xdp,
				  struct libie_xdp_tx_bulk *bq,
				  bool xsk)
{
	const struct bpf_prog *prog = bq->prog;
	u32 act;

	if (!xsk && !prog)
		return LIBIE_XDP_PASS;

	act = bpf_prog_run_xdp(prog, xdp);
	if (xsk && likely(act == XDP_REDIRECT))
		goto redir;

	switch (act) {
	case XDP_ABORTED:
err:
		trace_xdp_exception(xdp->rxq->dev, prog, act);
		fallthrough;
	case XDP_DROP:
		xdp_return_buff(xdp);
		xdp->data = NULL;

		return LIBIE_XDP_DROP;
	case XDP_PASS:
		return LIBIE_XDP_PASS;
	case XDP_TX:
		libie_xdp_tx_queue_bulk(bq, xdp);
		xdp->data = NULL;

		return LIBIE_XDP_TX;
	case XDP_REDIRECT:
redir:
		if (unlikely(xdp_do_redirect(xdp->rxq->dev, xdp, prog)))
			goto err;

		xdp->data = NULL;

		return LIBIE_XDP_REDIRECT;
	default:
		bpf_warn_invalid_xdp_action(xdp->rxq->dev, prog, act);
		goto err;
	}
}

static __always_inline bool
libie_xdp_run(struct xdp_buff *xdp, struct libie_xdp_tx_bulk *bq,
	      bool (*flush_bulk)(struct libie_xdp_tx_bulk *), bool xsk)
{
	u32 act;

	act = __libie_xdp_run(xdp, bq, xsk);
	if (act == LIBIE_XDP_TX &&
	    unlikely(bq->count == LIBIE_XDP_TX_BULK && !flush_bulk(bq)))
		act = LIBIE_XDP_DROP;

	bq->act_mask |= act;

	return act == LIBIE_XDP_PASS;
}

static __always_inline void
libie_xdp_finalize_rx(struct libie_xdp_tx_bulk *bq,
		      bool (*flush_bulk)(struct libie_xdp_tx_bulk *),
		      void (*finalize)(void *xdpq, bool tail))
{
	if (bq->act_mask & LIBIE_XDP_TX) {
		if (bq->count)
			flush_bulk(bq);
		finalize(bq->xdpq, true);
	}
	if (bq->act_mask & LIBIE_XDP_REDIRECT)
		xdp_do_flush();
}

/* Tx buffer completion */

static inline void libie_xdp_return_sinfo(const struct libie_tx_buffer *buf,
					  bool napi)
{
	const struct skb_shared_info *sinfo = buf->sinfo;
	struct page *page;

	if (likely(buf->gso_segs == 1))
		goto return_head;

	for (u32 i = 0; i < sinfo->nr_frags; i++) {
		page = skb_frag_page(&sinfo->frags[i]);
		page_pool_put_full_page(page->pp, page, napi);
	}

return_head:
	page = virt_to_page(sinfo);
	page_pool_put_full_page(page->pp, page, napi);
}

static inline void libie_xdp_complete_tx_buf(struct libie_tx_buffer *buf,
					     struct device *dev, bool napi,
					     struct xdp_frame_bulk *bq,
					     struct libie_sq_onstack_stats *ss)
{
	switch (buf->type) {
	case LIBIE_TX_BUF_EMPTY:
		return;
	case LIBIE_TX_BUF_XDP_TX:
		libie_xdp_return_sinfo(buf, napi);
		break;
	case LIBIE_TX_BUF_XDP_XMIT:
		dma_unmap_page(dev, dma_unmap_addr(buf, dma),
			       dma_unmap_len(buf, len), DMA_TO_DEVICE);
		xdp_return_frame_bulk(buf->xdpf, bq);
		break;
	case LIBIE_TX_BUF_XSK_TX:
		xsk_buff_free(buf->xdp);
		break;
	default:
		break;
	}

	ss->packets += buf->gso_segs;
	ss->bytes += buf->bytecount;

	buf->type = LIBIE_TX_BUF_EMPTY;
}

#endif /* __LIBIE_XDP_H */
