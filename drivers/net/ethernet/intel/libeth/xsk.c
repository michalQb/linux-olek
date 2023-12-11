// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2024 Intel Corporation */

#include <net/libeth/xsk.h>

#include "priv.h"

/* ``XDP_TX`` bulking */

void __cold libeth_xsk_tx_return_bulk(const struct libeth_xdp_tx_frame *bq,
				      u32 count)
{
	for (u32 i = 0; i < count; i++)
		libeth_xsk_buff_free_slow(bq[i].xsk);
}

/* XSk TMO */

const struct xsk_tx_metadata_ops libeth_xsktmo_slow = {
	.tmo_request_checksum	= libeth_xsktmo_req_csum,
};

/* Rx polling path */

void libeth_xsk_buff_free_slow(struct libeth_xdp_buff *xdp)
{
	xsk_buff_free(&xdp->base);
}
EXPORT_SYMBOL_NS_GPL(libeth_xsk_buff_free_slow, LIBETH_XDP);

struct libeth_xdp_buff *libeth_xsk_buff_add_frag(struct libeth_xdp_buff *head,
						 struct libeth_xdp_buff *xdp)
{
	if (!xsk_buff_add_frag(&head->base, &xdp->base))
		goto free;

	return head;

free:
	libeth_xsk_buff_free_slow(xdp);
	libeth_xsk_buff_free_slow(head);

	return NULL;
}
EXPORT_SYMBOL_NS_GPL(libeth_xsk_buff_add_frag, LIBETH_XDP);

u32 __libeth_xsk_run_prog_slow(struct libeth_xdp_buff *xdp,
			       const struct libeth_xdp_tx_bulk *bq,
			       enum xdp_action act, int ret)
{
	switch (act) {
	case XDP_DROP:
		xsk_buff_free(&xdp->base);

		return LIBETH_XDP_DROP;
	case XDP_TX:
		return LIBETH_XDP_TX;
	case XDP_PASS:
		return LIBETH_XDP_PASS;
	default:
		break;
	}

	return libeth_xdp_prog_exception(bq, xdp, act, ret);
}
EXPORT_SYMBOL_NS_GPL(__libeth_xsk_run_prog_slow, LIBETH_XDP);

u32 __cold libeth_xsk_prog_exception(struct libeth_xdp_buff *xdp,
				     enum xdp_action act, int ret)
{
	const struct xdp_buff_xsk *xsk;
	u32 __ret = LIBETH_XDP_DROP;

	if (act != XDP_REDIRECT)
		goto drop;

	xsk = container_of(&xdp->base, typeof(*xsk), xdp);
	if (xsk_uses_need_wakeup(xsk->pool) && ret == -ENOBUFS)
		__ret = LIBETH_XDP_ABORTED;

drop:
	libeth_xsk_buff_free_slow(xdp);

	return __ret;
}

/* Refill */

int libeth_xskfq_create(struct libeth_xskfq *fq)
{
	fq->fqes = kvcalloc_node(fq->count, sizeof(*fq->fqes), GFP_KERNEL,
				 fq->nid);
	if (!fq->fqes)
		return -ENOMEM;

	fq->pending = fq->count;
	fq->thresh = libeth_xdp_queue_threshold(fq->count);
	fq->buf_len = xsk_pool_get_rx_frame_size(fq->pool);

	return 0;
}
EXPORT_SYMBOL_NS_GPL(libeth_xskfq_create, LIBETH_XDP);

void libeth_xskfq_destroy(struct libeth_xskfq *fq)
{
	fq->buf_len = 0;
	fq->thresh = 0;
	fq->pending = 0;

	kvfree(fq->fqes);
}
EXPORT_SYMBOL_NS_GPL(libeth_xskfq_destroy, LIBETH_XDP);

/* .ndo_xsk_wakeup */

static void libeth_xsk_napi_sched(void *info)
{
	__napi_schedule_irqoff(info);
}

void libeth_xsk_init_wakeup(call_single_data_t *csd, struct napi_struct *napi)
{
	INIT_CSD(csd, libeth_xsk_napi_sched, napi);
}
EXPORT_SYMBOL_NS_GPL(libeth_xsk_init_wakeup, LIBETH_XDP);

void libeth_xsk_wakeup(call_single_data_t *csd, u32 qid)
{
	struct napi_struct *napi = csd->info;

	if (napi_if_scheduled_mark_missed(napi) ||
	    unlikely(!napi_schedule_prep(napi)))
		return;

	if (qid != raw_smp_processor_id())
		smp_call_function_single_async(qid, csd);
	else
		__napi_schedule(napi);
}
EXPORT_SYMBOL_NS_GPL(libeth_xsk_wakeup, LIBETH_XDP);

/* Pool setup */

#define LIBETH_XSK_DMA_ATTR					\
	(DMA_ATTR_WEAK_ORDERING | DMA_ATTR_SKIP_CPU_SYNC)

int libeth_xsk_setup_pool(struct net_device *dev, u32 qid, bool enable)
{
	struct xsk_buff_pool *pool;

	pool = xsk_get_pool_from_qid(dev, qid);
	if (!pool)
		return -EINVAL;

	if (enable)
		return xsk_pool_dma_map(pool, dev->dev.parent,
					LIBETH_XSK_DMA_ATTR);
	else
		xsk_pool_dma_unmap(pool, LIBETH_XSK_DMA_ATTR);

	return 0;
}
EXPORT_SYMBOL_NS_GPL(libeth_xsk_setup_pool, LIBETH_XDP);
