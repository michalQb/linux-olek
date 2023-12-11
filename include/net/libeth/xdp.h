/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 Intel Corporation */

#ifndef __LIBETH_XDP_H
#define __LIBETH_XDP_H

#include <linux/bpf_trace.h>

#include <net/libeth/rx.h>
#include <net/libeth/tx.h>

/* Defined as bits to be able to use them as a mask */
enum {
	LIBETH_XDP_PASS			= 0U,
	LIBETH_XDP_DROP			= BIT(0),
	LIBETH_XDP_ABORTED		= BIT(1),
	LIBETH_XDP_TX			= BIT(2),
	LIBETH_XDP_REDIRECT		= BIT(3),
};

/* XDPSQ sharing */

DECLARE_STATIC_KEY_FALSE(libeth_xdpsq_share);

static inline u32 libeth_xdpsq_num(u32 rxq, u32 txq, u32 max)
{
	return min(max(nr_cpu_ids, rxq), max - txq);
}

static inline bool libeth_xdpsq_shared(u32 num)
{
	return num < nr_cpu_ids;
}

static inline u32 libeth_xdpsq_id(u32 qid)
{
	u32 ret = raw_smp_processor_id();

	if (static_branch_unlikely(&libeth_xdpsq_share) &&
	    libeth_xdpsq_shared(qid))
		ret %= qid;

	return ret;
}

void __libeth_xdpsq_get(struct libeth_xdpsq_lock *lock,
			const struct net_device *dev);
void __libeth_xdpsq_put(struct libeth_xdpsq_lock *lock,
			const struct net_device *dev);

#define libeth_xdpsq_get_start		cpus_read_lock
#define libeth_xdpsq_get_end		cpus_read_unlock

static inline void libeth_xdpsq_get(struct libeth_xdpsq_lock *lock,
				    const struct net_device *dev,
				    bool share)
{
	if (unlikely(share))
		__libeth_xdpsq_get(lock, dev);
}

static inline void libeth_xdpsq_put(struct libeth_xdpsq_lock *lock,
				    const struct net_device *dev)
{
	if (static_branch_unlikely(&libeth_xdpsq_share) && lock->share)
		__libeth_xdpsq_put(lock, dev);
}

void __acquires(&lock->lock)
__libeth_xdpsq_lock(struct libeth_xdpsq_lock *lock);
void __releases(&lock->lock)
__libeth_xdpsq_unlock(struct libeth_xdpsq_lock *lock);

static inline void libeth_xdpsq_lock(struct libeth_xdpsq_lock *lock)
{
	if (static_branch_unlikely(&libeth_xdpsq_share) && lock->share)
		__libeth_xdpsq_lock(lock);
}

static inline void libeth_xdpsq_unlock(struct libeth_xdpsq_lock *lock)
{
	if (static_branch_unlikely(&libeth_xdpsq_share) && lock->share)
		__libeth_xdpsq_unlock(lock);
}

/* XDPSQ clean-up timers */

void libeth_xdpsq_init_timer(struct libeth_xdpsq_timer *timer, void *xdpsq,
			     struct libeth_xdpsq_lock *lock,
			     void (*poll)(struct work_struct *work));

static inline void libeth_xdpsq_deinit_timer(struct libeth_xdpsq_timer *timer)
{
	cancel_delayed_work_sync(&timer->dwork);
}

static inline void libeth_xdpsq_queue_timer(struct libeth_xdpsq_timer *timer)
{
	mod_delayed_work_on(raw_smp_processor_id(), system_bh_highpri_wq,
			    &timer->dwork, HZ);
}

static __always_inline void
libeth_xdpsq_run_timer(struct work_struct *work,
		       u32 (*poll)(void *xdpsq, u32 budget))
{
	struct libeth_xdpsq_timer *timer = container_of(work, typeof(*timer),
							dwork.work);

	libeth_xdpsq_lock(timer->lock);

	if (poll(timer->xdpsq, U32_MAX))
		libeth_xdpsq_queue_timer(timer);

	libeth_xdpsq_unlock(timer->lock);
}

/* Common Tx bits */

enum {
	LIBETH_XDP_TX_BULK		= DEV_MAP_BULK_SIZE,
	LIBETH_XDP_TX_BATCH		= 8,

	LIBETH_XDP_TX_DROP		= BIT(0),
	LIBETH_XDP_TX_NDO		= BIT(1),
	LIBETH_XDP_TX_XSK		= BIT(2),
};

enum {
	LIBETH_XDP_TX_LEN		= GENMASK(15, 0),

	LIBETH_XDP_TX_TSTAMP		= XDP_TXMD_FLAGS_TIMESTAMP,
	LIBETH_XDP_TX_CSUM		= XDP_TXMD_FLAGS_CHECKSUM,
	LIBETH_XDP_TX_XSKMD		= LIBETH_XDP_TX_LEN,

	LIBETH_XDP_TX_FIRST		= BIT(16),
	LIBETH_XDP_TX_LAST		= BIT(17),
	LIBETH_XDP_TX_MULTI		= BIT(18),

	LIBETH_XDP_TX_FLAGS		= GENMASK(31, 16),
};

struct libeth_xdp_tx_frame {
	union {
		/* XDP_TX */
		struct {
			void				*data;
			u32				len_fl;
			u32				soff;
		};

		/* XDP_TX frag */
		skb_frag_t			frag;

		/* .ndo_xdp_xmit(), XSk XDP_TX */
		struct {
			union {
				struct xdp_frame		*xdpf;
				dma_addr_t			dma;

				struct libeth_xdp_buff		*xsk;
			};
			union {
				struct {
					u32				len;
					u32				flags;
				};
				aligned_u64			opts;
			};
		};

		/* XSk xmit */
		struct xdp_desc			desc;
	};
} __aligned(sizeof(struct xdp_desc));
static_assert(offsetof(struct libeth_xdp_tx_frame, frag.len) ==
	      offsetof(struct libeth_xdp_tx_frame, len_fl));
static_assert(sizeof(struct libeth_xdp_tx_frame) == sizeof(struct xdp_desc));

struct libeth_xdp_tx_bulk {
	const struct bpf_prog		*prog;
	struct net_device		*dev;
	void				*xdpsq;

	u32				act_mask;
	u32				count;
	struct libeth_xdp_tx_frame	bulk[LIBETH_XDP_TX_BULK];
} __aligned(sizeof(struct libeth_xdp_tx_frame));

struct libeth_xdpsq {
	struct xsk_buff_pool		*pool;
	struct libeth_sqe		*sqes;
	void				*descs;

	u32				*ntu;
	u32				count;

	u32				*pending;
	u32				*xdp_tx;
	struct libeth_xdpsq_lock	*lock;
};

struct libeth_xdp_tx_desc {
	dma_addr_t			addr;
	union {
		struct {
			u32				len;
			u32				flags;
		};
		aligned_u64			opts;
	};
} __aligned_largest;

#define libeth_xdp_ptr_to_priv(ptr) ({					      \
	typecheck_pointer(ptr);						      \
	((u64)(uintptr_t)(ptr));					      \
})
#define libeth_xdp_priv_to_ptr(priv) ({					      \
	static_assert(__same_type(priv, u64));				      \
	((const void *)(uintptr_t)(priv));				      \
})

/* On 64-bit systems, assigning one u64 is faster than two u32s. When ::len
 * occupies lowest 32 bits (LE), whole ::opts can be assigned directly instead.
 */
#ifdef __LITTLE_ENDIAN
#define __LIBETH_WORD_ACCESS		1
#endif
#ifdef __LIBETH_WORD_ACCESS
#define __libeth_xdp_tx_len(flen, ...)					      \
	.opts = ((flen) | FIELD_PREP(GENMASK_ULL(63, 32), (__VA_ARGS__ + 0)))
#else
#define __libeth_xdp_tx_len(flen, ...)					      \
	.len = (flen), .flags = (__VA_ARGS__ + 0)
#endif

static __always_inline u32
libeth_xdp_tx_xmit_bulk(const struct libeth_xdp_tx_frame *bulk, void *xdpsq,
			u32 n, bool unroll, u64 priv,
			u32 (*prep)(void *xdpsq, struct libeth_xdpsq *sq),
			struct libeth_xdp_tx_desc
			(*fill)(struct libeth_xdp_tx_frame frm, u32 i,
				const struct libeth_xdpsq *sq, u64 priv),
			void (*xmit)(struct libeth_xdp_tx_desc desc, u32 i,
				     const struct libeth_xdpsq *sq, u64 priv))
{
	u32 this, batched, off = 0;
	struct libeth_xdpsq sq;
	u32 ntu, i = 0;

	n = min(n, prep(xdpsq, &sq));
	if (unlikely(!n))
		goto unlock;

	ntu = *sq.ntu;

	this = sq.count - ntu;
	if (likely(this > n))
		this = n;

again:
	if (!unroll)
		goto linear;

	batched = ALIGN_DOWN(this, LIBETH_XDP_TX_BATCH);

	for ( ; i < off + batched; i += LIBETH_XDP_TX_BATCH) {
		u32 base = ntu + i - off;

		unrolled_count(LIBETH_XDP_TX_BATCH)
		for (u32 j = 0; j < LIBETH_XDP_TX_BATCH; j++)
			xmit(fill(bulk[i + j], base + j, &sq, priv),
			     base + j, &sq, priv);
	}

	if (batched < this) {
linear:
		for ( ; i < off + this; i++)
			xmit(fill(bulk[i], ntu + i - off, &sq, priv),
			     ntu + i - off, &sq, priv);
	}

	ntu += this;
	if (likely(ntu < sq.count))
		goto out;

	ntu = 0;

	if (i < n) {
		this = n - i;
		off = i;

		goto again;
	}

out:
	*sq.ntu = ntu;
	*sq.pending += n;
	if (sq.xdp_tx)
		*sq.xdp_tx += n;

unlock:
	libeth_xdpsq_unlock(sq.lock);

	return n;
}

/* ``XDP_TX`` bulking */

void libeth_xdp_return_buff_slow(struct libeth_xdp_buff *xdp);

static inline bool libeth_xdp_tx_queue_head(struct libeth_xdp_tx_bulk *bq,
					    const struct libeth_xdp_buff *xdp)
{
	const struct xdp_buff *base = &xdp->base;

	bq->bulk[bq->count++] = (typeof(*bq->bulk)){
		.data	= xdp->data,
		.len_fl	= (base->data_end - xdp->data) | LIBETH_XDP_TX_FIRST,
		.soff	= xdp_data_hard_end(base) - xdp->data,
	};

	if (!xdp_buff_has_frags(base))
		return false;

	bq->bulk[bq->count - 1].len_fl |= LIBETH_XDP_TX_MULTI;

	return true;
}

static inline void libeth_xdp_tx_queue_frag(struct libeth_xdp_tx_bulk *bq,
					    const skb_frag_t *frag)
{
	bq->bulk[bq->count++].frag = *frag;
}

static __always_inline bool
libeth_xdp_tx_queue_bulk(struct libeth_xdp_tx_bulk *bq,
			 struct libeth_xdp_buff *xdp,
			 bool (*flush_bulk)(struct libeth_xdp_tx_bulk *bq,
					    u32 flags))
{
	const struct skb_shared_info *sinfo;
	bool ret = true;
	u32 nr_frags;

	if (unlikely(bq->count == LIBETH_XDP_TX_BULK) &&
	    unlikely(!flush_bulk(bq, 0))) {
		libeth_xdp_return_buff_slow(xdp);
		return false;
	}

	if (!libeth_xdp_tx_queue_head(bq, xdp))
		goto out;

	sinfo = xdp_get_shared_info_from_buff(&xdp->base);
	nr_frags = sinfo->nr_frags;

	for (u32 i = 0; i < nr_frags; i++) {
		if (unlikely(bq->count == LIBETH_XDP_TX_BULK) &&
		    unlikely(!flush_bulk(bq, 0))) {
			ret = false;
			break;
		}

		libeth_xdp_tx_queue_frag(bq, &sinfo->frags[i]);
	};

out:
	bq->bulk[bq->count - 1].len_fl |= LIBETH_XDP_TX_LAST;
	xdp->data = NULL;

	return ret;
}

#define __libeth_xdp_tx_fill_stats(sqe, desc, sinfo, ue, ud, us) do {	      \
	const struct libeth_xdp_tx_desc *ud = (desc);			      \
	const struct skb_shared_info *us;				      \
	struct libeth_sqe *ue = (sqe);					      \
									      \
	ue->nr_frags = 1;						      \
	ue->bytes = ud->len;						      \
									      \
	if (ud->flags & LIBETH_XDP_TX_MULTI) {				      \
		us = (sinfo);						      \
		ue->nr_frags += us->nr_frags;				      \
		ue->bytes += us->xdp_frags_size;			      \
	}								      \
} while (0)
#define libeth_xdp_tx_fill_stats(sqe, desc, sinfo)			      \
	__libeth_xdp_tx_fill_stats(sqe, desc, sinfo, __UNIQUE_ID(sqe_),	      \
				   __UNIQUE_ID(desc_), __UNIQUE_ID(sinfo_))

static inline struct libeth_xdp_tx_desc
libeth_xdp_tx_fill_buf(struct libeth_xdp_tx_frame frm, u32 i,
		       const struct libeth_xdpsq *sq, u64 priv)
{
	struct libeth_xdp_tx_desc desc;
	struct skb_shared_info *sinfo;
	skb_frag_t *frag = &frm.frag;
	struct libeth_sqe *sqe;

	if (frm.len_fl & LIBETH_XDP_TX_FIRST) {
		sinfo = frm.data + frm.soff;
		skb_frag_fill_page_desc(frag, virt_to_page(frm.data),
					offset_in_page(frm.data),
					frm.len_fl);
	} else {
		sinfo = NULL;
	}

	desc = (typeof(desc)){
		.addr	= page_pool_get_dma_addr(skb_frag_page(frag)) +
			  skb_frag_off(frag),
		.len	= skb_frag_size(frag) & LIBETH_XDP_TX_LEN,
		.flags	= skb_frag_size(frag) & LIBETH_XDP_TX_FLAGS,
	};

	dma_sync_single_for_device(skb_frag_page(frag)->pp->p.dev, desc.addr,
				   desc.len, DMA_BIDIRECTIONAL);

	if (!sinfo)
		return desc;

	sqe = &sq->sqes[i];
	sqe->type = LIBETH_SQE_XDP_TX;
	sqe->sinfo = sinfo;
	libeth_xdp_tx_fill_stats(sqe, &desc, sinfo);

	return desc;
}

void libeth_xdp_tx_exception(struct libeth_xdp_tx_bulk *bq, u32 sent,
			     u32 flags);

static __always_inline bool
__libeth_xdp_tx_flush_bulk(struct libeth_xdp_tx_bulk *bq, u32 flags,
			   u32 (*prep)(void *xdpsq, struct libeth_xdpsq *sq),
			   struct libeth_xdp_tx_desc
			   (*fill)(struct libeth_xdp_tx_frame frm, u32 i,
				   const struct libeth_xdpsq *sq, u64 priv),
			   void (*xmit)(struct libeth_xdp_tx_desc desc, u32 i,
					const struct libeth_xdpsq *sq,
					u64 priv))
{
	u32 sent, drops;
	int err = 0;

	sent = libeth_xdp_tx_xmit_bulk(bq->bulk, bq->xdpsq,
				       min(bq->count, LIBETH_XDP_TX_BULK),
				       false, 0, prep, fill, xmit);
	drops = bq->count - sent;

	if (unlikely(drops)) {
		libeth_xdp_tx_exception(bq, sent, flags);
		err = -ENXIO;
	} else {
		bq->count = 0;
	}

	trace_xdp_bulk_tx(bq->dev, sent, drops, err);

	return likely(sent);
}

#define libeth_xdp_tx_flush_bulk(bq, flags, prep, xmit)			      \
	__libeth_xdp_tx_flush_bulk(bq, flags, prep, libeth_xdp_tx_fill_buf,   \
				   xmit)

/* .ndo_xdp_xmit() implementation */

static inline void __libeth_xdp_xmit_init_bulk(struct libeth_xdp_tx_bulk *bq,
					       struct net_device *dev,
					       void *xdpsq)
{
	bq->dev = dev;
	bq->xdpsq = xdpsq;
	bq->count = 0;
}

#define libeth_xdp_xmit_init_bulk(bq, dev, xdpsqs, num)			      \
	__libeth_xdp_xmit_init_bulk(bq, dev, (xdpsqs)[libeth_xdpsq_id(num)])

static inline void *__libeth_xdp_xmit_frame_dma(const struct xdp_frame *xdpf)
{
	void *addr = (void *)(xdpf + 1);

	if (!IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) &&
	    __alignof(*xdpf) < sizeof(dma_addr_t))
		addr = PTR_ALIGN(addr, sizeof(dma_addr_t));

	return addr;
}

#define libeth_xdp_xmit_frame_dma(xf)					      \
	_Generic((xf),							      \
		 const struct xdp_frame *:				      \
			(const dma_addr_t *)__libeth_xdp_xmit_frame_dma(xf),  \
		 struct xdp_frame *:					      \
			(dma_addr_t *)__libeth_xdp_xmit_frame_dma(xf)	      \
	)

static inline u32 libeth_xdp_xmit_queue_head(struct libeth_xdp_tx_bulk *bq,
					     struct xdp_frame *xdpf,
					     struct device *dev)
{
	dma_addr_t dma;

	dma = dma_map_single(dev, xdpf->data, xdpf->len, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, dma))
		return LIBETH_XDP_DROP;

	*libeth_xdp_xmit_frame_dma(xdpf) = dma;

	bq->bulk[bq->count++] = (typeof(*bq->bulk)){
		.xdpf	= xdpf,
		__libeth_xdp_tx_len(xdpf->len, LIBETH_XDP_TX_FIRST),
	};

	if (!xdp_frame_has_frags(xdpf))
		return LIBETH_XDP_PASS;

	bq->bulk[bq->count - 1].flags |= LIBETH_XDP_TX_MULTI;

	return LIBETH_XDP_TX;
}

static inline bool libeth_xdp_xmit_queue_frag(struct libeth_xdp_tx_bulk *bq,
					      const skb_frag_t *frag,
					      struct device *dev)
{
	dma_addr_t dma;

	dma = skb_frag_dma_map_tx(dev, frag);
	if (dma_mapping_error(dev, dma))
		return false;

	bq->bulk[bq->count++] = (typeof(*bq->bulk)){
		.dma	= dma,
		__libeth_xdp_tx_len(skb_frag_size(frag)),
	};

	return true;
}

static __always_inline u32
libeth_xdp_xmit_queue_bulk(struct libeth_xdp_tx_bulk *bq,
			   struct xdp_frame *xdpf,
			   bool (*flush_bulk)(struct libeth_xdp_tx_bulk *bq,
					      u32 flags))
{
	u32 head, nr_frags, i, ret = LIBETH_XDP_TX;
	struct device *dev = bq->dev->dev.parent;
	const struct skb_shared_info *sinfo;

	if (unlikely(bq->count == LIBETH_XDP_TX_BULK) &&
	    unlikely(!flush_bulk(bq, LIBETH_XDP_TX_NDO)))
		return LIBETH_XDP_DROP;

	head = libeth_xdp_xmit_queue_head(bq, xdpf, dev);
	if (head == LIBETH_XDP_PASS)
		goto out;
	else if (head == LIBETH_XDP_DROP)
		return LIBETH_XDP_DROP;

	sinfo = xdp_get_shared_info_from_frame(xdpf);
	nr_frags = sinfo->nr_frags;

	for (i = 0; i < nr_frags; i++) {
		if (unlikely(bq->count == LIBETH_XDP_TX_BULK) &&
		    unlikely(!flush_bulk(bq, LIBETH_XDP_TX_NDO)))
			break;

		if (!libeth_xdp_xmit_queue_frag(bq, &sinfo->frags[i], dev))
			break;
	};

	if (unlikely(i < nr_frags))
		ret = LIBETH_XDP_ABORTED;

out:
	bq->bulk[bq->count - 1].flags |= LIBETH_XDP_TX_LAST;

	return ret;
}

static inline struct libeth_xdp_tx_desc
libeth_xdp_xmit_fill_buf(struct libeth_xdp_tx_frame frm, u32 i,
			 const struct libeth_xdpsq *sq, u64 priv)
{
	struct libeth_xdp_tx_desc desc;
	struct libeth_sqe *sqe;
	struct xdp_frame *xdpf;

	if (frm.flags & LIBETH_XDP_TX_FIRST) {
		xdpf = frm.xdpf;
		desc.addr = *libeth_xdp_xmit_frame_dma(xdpf);
	} else {
		xdpf = NULL;
		desc.addr = frm.dma;
	}
	desc.opts = frm.opts;

	sqe = &sq->sqes[i];
	dma_unmap_addr_set(sqe, dma, desc.addr);
	dma_unmap_len_set(sqe, len, desc.len);

	if (!xdpf) {
		sqe->type = LIBETH_SQE_XDP_XMIT_FRAG;
		return desc;
	}

	sqe->type = LIBETH_SQE_XDP_XMIT;
	sqe->xdpf = xdpf;
	libeth_xdp_tx_fill_stats(sqe, &desc,
				 xdp_get_shared_info_from_frame(xdpf));

	return desc;
}

#define libeth_xdp_xmit_flush_bulk(bq, flags, prep, xmit)		      \
	__libeth_xdp_tx_flush_bulk(bq, (flags) | LIBETH_XDP_TX_NDO, prep,     \
				   libeth_xdp_xmit_fill_buf, xmit);

u32 libeth_xdp_xmit_return_bulk(const struct libeth_xdp_tx_frame *bq,
				u32 count, const struct net_device *dev);

static __always_inline int
__libeth_xdp_xmit_do_bulk(struct libeth_xdp_tx_bulk *bq,
			  struct xdp_frame **frames, u32 n, u32 flags,
			  bool (*flush_bulk)(struct libeth_xdp_tx_bulk *bq,
					     u32 flags),
			  void (*finalize)(void *xdpsq, bool sent, bool flush))
{
	u32 nxmit = 0;

	if (unlikely(flags & ~XDP_XMIT_FLAGS_MASK))
		return -EINVAL;

	for (u32 i = 0; likely(i < n); i++) {
		u32 ret;

		ret = libeth_xdp_xmit_queue_bulk(bq, frames[i], flush_bulk);
		if (unlikely(ret != LIBETH_XDP_TX)) {
			nxmit += ret == LIBETH_XDP_ABORTED;
			break;
		} else {
			nxmit++;
		}
	}

	if (bq->count) {
		flush_bulk(bq, LIBETH_XDP_TX_NDO);
		if (unlikely(bq->count))
			nxmit -= libeth_xdp_xmit_return_bulk(bq->bulk,
							     bq->count,
							     bq->dev);
	}

	finalize(bq->xdpsq, nxmit, flags & XDP_XMIT_FLUSH);

	return nxmit;
}

#define _libeth_xdp_xmit_do_bulk(d, n, fr, f, xqs, nqs, fl, fin, ub, ur, un)  \
({									      \
	u32 un = (nqs);							      \
	int ur;								      \
									      \
	if (likely(un)) {						      \
		struct libeth_xdp_tx_bulk ub;				      \
									      \
		libeth_xdp_xmit_init_bulk(&ub, d, xqs, un);		      \
		ur = __libeth_xdp_xmit_do_bulk(&ub, fr, n, f, fl, fin);	      \
	} else {							      \
		ur = -ENXIO;						      \
	}								      \
									      \
	ur;								      \
})
#define libeth_xdp_xmit_do_bulk(dev, n, fr, f, xqs, nqs, fl, fin)	      \
	_libeth_xdp_xmit_do_bulk(dev, n, fr, f, xqs, nqs, fl, fin,	      \
				 __UNIQUE_ID(bq_), __UNIQUE_ID(ret_),	      \
				 __UNIQUE_ID(nqs_))

/* Rx polling path */

#define __libeth_xdp_tx_init_bulk(bq, pr, d, xdpsqs, num, xsk, ub, un) do {   \
	typeof(bq) ub = (bq);						      \
	u32 un = (num);							      \
									      \
	if (un || (xsk)) {						      \
		ub->prog = rcu_dereference(pr);				      \
		ub->dev = (d);						      \
		ub->xdpsq = (xdpsqs)[libeth_xdpsq_id(un)];		      \
	} else {							      \
		ub->prog = NULL;					      \
	}								      \
									      \
	ub->act_mask = 0;						      \
	ub->count = 0;							      \
} while (0)
#define libeth_xdp_tx_init_bulk(bq, prog, dev, xdpsqs, num)		      \
	__libeth_xdp_tx_init_bulk(bq, prog, dev, xdpsqs, num, false,	      \
				  __UNIQUE_ID(bq_), __UNIQUE_ID(nqs_))

void libeth_xdp_load_stash(struct libeth_xdp_buff *dst,
			   const struct libeth_xdp_buff_stash *src);
void libeth_xdp_save_stash(struct libeth_xdp_buff_stash *dst,
			   const struct libeth_xdp_buff *src);
void __libeth_xdp_return_stash(struct libeth_xdp_buff_stash *stash);

static inline void
libeth_xdp_init_buff(struct libeth_xdp_buff *dst,
		     const struct libeth_xdp_buff_stash *src,
		     struct xdp_rxq_info *rxq)
{
	if (likely(!src->data))
		dst->data = NULL;
	else
		libeth_xdp_load_stash(dst, src);

	dst->base.rxq = rxq;
}

static inline void libeth_xdp_save_buff(struct libeth_xdp_buff_stash *dst,
					const struct libeth_xdp_buff *src)
{
	if (likely(!src->data))
		dst->data = NULL;
	else
		libeth_xdp_save_stash(dst, src);
}

static inline void libeth_xdp_return_stash(struct libeth_xdp_buff_stash *stash)
{
	if (stash->data)
		__libeth_xdp_return_stash(stash);
}

static inline void libeth_xdp_return_va(const void *data, bool napi)
{
	struct page *page = virt_to_page(data);

	page_pool_put_full_page(page->pp, page, napi);
}

static inline void libeth_xdp_return_frags(const struct skb_shared_info *sinfo,
					   bool napi)
{
	for (u32 i = 0; i < sinfo->nr_frags; i++) {
		struct page *page = skb_frag_page(&sinfo->frags[i]);

		page_pool_put_full_page(page->pp, page, napi);
	}
}

static inline void libeth_xdp_return_buff(struct libeth_xdp_buff *xdp)
{
	if (!xdp_buff_has_frags(&xdp->base))
		goto out;

	libeth_xdp_return_frags(xdp_get_shared_info_from_buff(&xdp->base),
				true);

out:
	libeth_xdp_return_va(xdp->data, true);
	xdp->data = NULL;
}

bool libeth_xdp_buff_add_frag(struct libeth_xdp_buff *xdp,
			      const struct libeth_fqe *fqe,
			      u32 len);

static inline void libeth_xdp_prepare_buff(struct libeth_xdp_buff *xdp,
					   const struct libeth_fqe *fqe,
					   u32 len)
{
	const struct page *page = fqe->page;

#ifdef __LIBETH_WORD_ACCESS
	static_assert(offsetofend(typeof(xdp->base), flags) -
		      offsetof(typeof(xdp->base), frame_sz) ==
		      sizeof(u64));

	*(u64 *)&xdp->base.frame_sz = fqe->truesize;
#else
	xdp_init_buff(&xdp->base, fqe->truesize, xdp->base.rxq);
#endif
	xdp_prepare_buff(&xdp->base, page_address(page) + fqe->offset,
			 page->pp->p.offset, len, true);
}

/**
 * libeth_xdp_process_buff - process an Rx buffer
 * @xdp: XDP buffer to attach the buffer to
 * @fqe: Rx buffer to process
 * @len: received data length from the descriptor
 *
 * Return: false if the descriptor must be skipped, true otherwise.
 */
static inline bool libeth_xdp_process_buff(struct libeth_xdp_buff *xdp,
					   const struct libeth_fqe *fqe,
					   u32 len)
{
	if (!libeth_rx_sync_for_cpu(fqe, len))
		return false;

	if (xdp->data)
		return libeth_xdp_buff_add_frag(xdp, fqe, len);

	libeth_xdp_prepare_buff(xdp, fqe, len);

	prefetch(xdp->data);

	return true;
}

u32 libeth_xdp_prog_exception(const struct libeth_xdp_tx_bulk *bq,
			      struct libeth_xdp_buff *xdp,
			      enum xdp_action act, int ret);

/**
 * __libeth_xdp_run_prog - run XDP program on an XDP buffer
 * @xdp: XDP buffer to run the prog on
 * @bq: buffer bulk for ``XDP_TX`` queueing
 *
 * Return: LIBETH_XDP_{PASS,DROP,TX,REDIRECT} depending on the prog's verdict.
 */
static __always_inline u32
__libeth_xdp_run_prog(struct libeth_xdp_buff *xdp,
		      const struct libeth_xdp_tx_bulk *bq)
{
	enum xdp_action act;

	act = bpf_prog_run_xdp(bq->prog, &xdp->base);
	if (unlikely(act < XDP_DROP || act > XDP_REDIRECT))
		goto out;

	switch (act) {
	case XDP_PASS:
		return LIBETH_XDP_PASS;
	case XDP_DROP:
		libeth_xdp_return_buff(xdp);

		return LIBETH_XDP_DROP;
	case XDP_TX:
		return LIBETH_XDP_TX;
	case XDP_REDIRECT:
		if (unlikely(xdp_do_redirect(bq->dev, &xdp->base, bq->prog)))
			break;

		xdp->data = NULL;

		return LIBETH_XDP_REDIRECT;
	default:
		break;
	}

out:
	return libeth_xdp_prog_exception(bq, xdp, act, 0);
}

static __always_inline u32
__libeth_xdp_run_flush(struct libeth_xdp_buff *xdp,
		       struct libeth_xdp_tx_bulk *bq,
		       u32 (*run)(struct libeth_xdp_buff *xdp,
				  const struct libeth_xdp_tx_bulk *bq),
		       bool (*queue)(struct libeth_xdp_tx_bulk *bq,
				     struct libeth_xdp_buff *xdp,
				     bool (*flush_bulk)
					  (struct libeth_xdp_tx_bulk *bq,
					   u32 flags)),
		       bool (*flush_bulk)(struct libeth_xdp_tx_bulk *bq,
					  u32 flags))
{
	u32 act;

	act = run(xdp, bq);
	if (act == LIBETH_XDP_TX && unlikely(!queue(bq, xdp, flush_bulk)))
		act = LIBETH_XDP_DROP;

	bq->act_mask |= act;

	return act;
}

#define libeth_xdp_run_prog(xdp, bq, fl)				      \
	(__libeth_xdp_run_flush(xdp, bq, __libeth_xdp_run_prog,		      \
			        libeth_xdp_tx_queue_bulk,		      \
			        fl) == LIBETH_XDP_PASS)

static __always_inline void
__libeth_xdp_run_pass(struct libeth_xdp_buff *xdp,
		      struct libeth_xdp_tx_bulk *bq, struct napi_struct *napi,
		      struct libeth_rq_napi_stats *ss, const void *md,
		      void (*prep)(struct libeth_xdp_buff *xdp,
				   const void *md),
		      bool (*run)(struct libeth_xdp_buff *xdp,
				  struct libeth_xdp_tx_bulk *bq),
		      bool (*populate)(struct sk_buff *skb,
				       const struct libeth_xdp_buff *xdp,
				       struct libeth_rq_napi_stats *ss))
{
	struct sk_buff *skb;

	ss->bytes += xdp_get_buff_len(&xdp->base) + ETH_FCS_LEN;
	ss->packets++;

	if (prep && (!__builtin_constant_p(!!md) || md))
		prep(xdp, md);

	if (!bq || !run || !bq->prog)
		goto build;

	if (!run(xdp, bq))
		return;

build:
	skb = xdp_build_skb_from_buff(&xdp->base);
	if (unlikely(!skb)) {
		libeth_xdp_return_buff_slow(xdp);
		return;
	}

	xdp->data = NULL;

	if (unlikely(!populate(skb, xdp, ss))) {
		napi_consume_skb(skb, true);
		return;
	}

	napi_gro_receive(napi, skb);
}

static inline void libeth_xdp_prep_desc(struct libeth_xdp_buff *xdp,
					const void *desc)
{
	xdp->desc = desc;
}

#define libeth_xdp_run_pass(xdp, bq, napi, ss, desc, run, populate)	      \
	__libeth_xdp_run_pass(xdp, bq, napi, ss, desc, libeth_xdp_prep_desc,  \
			      run, populate)

static __always_inline void
__libeth_xdp_finalize_rx(struct libeth_xdp_tx_bulk *bq, u32 flags,
			 bool (*flush_bulk)(struct libeth_xdp_tx_bulk *bq,
					    u32 flags),
			 void (*finalize)(void *xdpsq, bool sent, bool flush))
{
	if (bq->act_mask & LIBETH_XDP_TX) {
		if (bq->count)
			flush_bulk(bq, flags | LIBETH_XDP_TX_DROP);
		finalize(bq->xdpsq, true, true);
	}
	if (bq->act_mask & LIBETH_XDP_REDIRECT)
		xdp_do_flush();
}
#define libeth_xdp_finalize_rx(bq, flush, finalize)			      \
	__libeth_xdp_finalize_rx(bq, 0, flush, finalize)

/* Helpers to reduce boilerplate code in drivers */

#define LIBETH_XDP_DEFINE_START()					      \
	__diag_push();							      \
	__diag_ignore(GCC, 8, "-Wold-style-declaration",		      \
		      "Allow specifying \'static\' after the return type")

#define LIBETH_XDP_DEFINE_TIMER(name, poll)				      \
void name(struct work_struct *work)					      \
{									      \
	libeth_xdpsq_run_timer(work, poll);				      \
}

#define __LIBETH_XDP_DEFINE_FLUSH_TX(name, prep, xmit, pfx)		      \
bool name(struct libeth_xdp_tx_bulk *bq, u32 flags)			      \
{									      \
	return libeth_##pfx##_tx_flush_bulk(bq, flags, prep, xmit);	      \
}
#define LIBETH_XDP_DEFINE_FLUSH_TX(name, prep, xmit)			      \
	__LIBETH_XDP_DEFINE_FLUSH_TX(name, prep, xmit, xdp)

#define LIBETH_XDP_DEFINE_FLUSH_XMIT(name, prep, xmit)			      \
bool name(struct libeth_xdp_tx_bulk *bq, u32 flags)			      \
{									      \
	return libeth_xdp_xmit_flush_bulk(bq, flags, prep, xmit);	      \
}

#define __LIBETH_XDP_DEFINE_RUN_PROG(name, flush, pfx)			      \
name(struct libeth_xdp_buff *xdp, struct libeth_xdp_tx_bulk *bq)	      \
{									      \
	return libeth_##pfx##_run_prog(xdp, bq, flush);			      \
}
#define LIBETH_XDP_DEFINE_RUN_PROG(name, flush)				      \
	bool __LIBETH_XDP_DEFINE_RUN_PROG(name, flush, xdp)

#define __LIBETH_XDP_DEFINE_RUN_PASS(name, run, populate, pfx)		      \
name(struct libeth_xdp_buff *xdp, struct libeth_xdp_tx_bulk *bq,	      \
     struct napi_struct *napi, struct libeth_rq_napi_stats *ss,		      \
     const void *desc)							      \
{									      \
	return libeth_##pfx##_run_pass(xdp, bq, napi, ss, desc, run,	      \
				       populate);			      \
}
#define LIBETH_XDP_DEFINE_RUN_PASS(name, run, populate)			      \
	void __LIBETH_XDP_DEFINE_RUN_PASS(name, run, populate, xdp)

#define __LIBETH_XDP_DEFINE_RUN(name, run, flush, populate, pfx)	      \
	LIBETH_##pfx##_DEFINE_RUN_PROG(static run, flush);		      \
	LIBETH_##pfx##_DEFINE_RUN_PASS(name, run, populate)
#define LIBETH_XDP_DEFINE_RUN(name, run, flush, populate)		      \
	__LIBETH_XDP_DEFINE_RUN(name, run, flush, populate, XDP)

#define __LIBETH_XDP_DEFINE_FINALIZE(name, flush, finalize, pfx)	      \
void name(struct libeth_xdp_tx_bulk *bq)				      \
{									      \
	libeth_##pfx##_finalize_rx(bq, flush, finalize);		      \
}
#define LIBETH_XDP_DEFINE_FINALIZE(name, flush, finalize)		      \
	__LIBETH_XDP_DEFINE_FINALIZE(name, flush, finalize, xdp)

#define LIBETH_XDP_DEFINE_END()		__diag_pop()

/* XMO */

#define libeth_xdp_buff_to_rq(xdp, type, member)			      \
	container_of_const((xdp)->base.rxq, type, member)

static inline int libeth_xdpmo_rx_hash(u32 *hash,
				       enum xdp_rss_hash_type *rss_type,
				       u32 val, struct libeth_rx_pt pt)
{
	if (unlikely(!val))
		return -ENODATA;

	*hash = val;
	*rss_type = pt.hash_type;

	return 0;
}

/* Tx buffer completion */

void libeth_xdp_return_buff_bulk(const struct skb_shared_info *sinfo,
				 struct xdp_frame_bulk *bq, bool frags);
void libeth_xsk_buff_free_slow(struct libeth_xdp_buff *xdp);

static __always_inline void
__libeth_xdp_complete_tx(struct libeth_sqe *sqe, struct libeth_cq_pp *cp,
			 typeof(libeth_xdp_return_buff_bulk) bulk,
			 typeof(libeth_xsk_buff_free_slow) xsk)
{
	enum libeth_sqe_type type = sqe->type;

	switch (type) {
	case LIBETH_SQE_EMPTY:
		return;
	case LIBETH_SQE_XDP_XMIT:
	case LIBETH_SQE_XDP_XMIT_FRAG:
		dma_unmap_page(cp->dev, dma_unmap_addr(sqe, dma),
			       dma_unmap_len(sqe, len), DMA_TO_DEVICE);
		break;
	default:
		break;
	}

	switch (type) {
	case LIBETH_SQE_XDP_TX:
		bulk(sqe->sinfo, cp->bq, sqe->nr_frags != 1);
		break;
	case LIBETH_SQE_XDP_XMIT:
		xdp_return_frame_bulk(sqe->xdpf, cp->bq);
		break;
	case LIBETH_SQE_XSK_TX:
	case LIBETH_SQE_XSK_TX_FRAG:
		xsk(sqe->xsk);
		break;
	default:
		break;
	}

	switch (type) {
	case LIBETH_SQE_XDP_TX:
	case LIBETH_SQE_XDP_XMIT:
	case LIBETH_SQE_XSK_TX:
		cp->xdp_tx -= sqe->nr_frags;

		cp->xss->packets++;
		cp->xss->bytes += sqe->bytes + ETH_FCS_LEN;
		break;
	default:
		break;
	}

	sqe->type = LIBETH_SQE_EMPTY;
}

static inline void libeth_xdp_complete_tx(struct libeth_sqe *sqe,
					  struct libeth_cq_pp *cp)
{
	__libeth_xdp_complete_tx(sqe, cp, libeth_xdp_return_buff_bulk,
				 libeth_xsk_buff_free_slow);
}

/* Misc */

u32 libeth_xdp_queue_threshold(u32 count);
void __libeth_xdp_set_features(struct net_device *dev,
			       const struct xdp_metadata_ops *xmo,
			       u32 zc_segs,
			       const struct xsk_tx_metadata_ops *tmo);

static inline void libeth_xdp_set_redirect(struct net_device *dev, bool enable)
{
	if (enable)
		xdp_features_set_redirect_target(dev, true);
	else
		xdp_features_clear_redirect_target(dev);
}

#define __libeth_xdp_feat0(dev)						      \
	__libeth_xdp_set_features(dev, NULL, 0, NULL)
#define __libeth_xdp_feat1(dev, xmo)					      \
	__libeth_xdp_set_features(dev, xmo, 0, NULL)
#define __libeth_xdp_feat2(dev, xmo, zc_segs)				      \
	__libeth_xdp_set_features(dev, xmo, zc_segs, NULL)
#define __libeth_xdp_feat3(dev, xmo, zc_segs, tmo)			      \
	__libeth_xdp_set_features(dev, xmo, zc_segs, tmo)

#define libeth_xdp_set_features(dev, ...)				      \
	CONCATENATE(__libeth_xdp_feat,					      \
		    COUNT_ARGS(__VA_ARGS__))(dev, ##__VA_ARGS__)
#define libeth_xdp_set_features_noredir(dev, ...) do {			      \
	libeth_xdp_set_features(dev, ##__VA_ARGS__);			      \
	libeth_xdp_set_redirect(dev, false);				      \
} while (0)

#define libeth_xsktmo			((const void *)true)

#endif /* __LIBETH_XDP_H */
