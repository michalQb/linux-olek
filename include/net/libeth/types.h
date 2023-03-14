/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 Intel Corporation */

#ifndef __LIBETH_TYPES_H
#define __LIBETH_TYPES_H

#include <linux/u64_stats_sync.h>

struct libeth_netdev_priv {
	u32				curr_xdpsqs;
	u32				max_xdpsqs;

	u16				last_rqs;
	u16				last_sqs;
	u16				last_xdpsqs;

	struct libeth_rq_base_stats	*base_rqs;
	struct libeth_sq_base_stats	*base_sqs;
	struct libeth_xdpsq_base_stats	*base_xdpsqs;

	const struct libeth_rq_stats	**live_rqs;
	const struct libeth_sq_stats	**live_sqs;
	const struct libeth_xdpsq_stats	**live_xdpsqs;

	/* Driver private data, ____cacheline_aligned */
} ____cacheline_aligned;

#define libeth_netdev_priv_assert(t, f)					    \
	static_assert(__same_type(struct libeth_netdev_priv,		    \
				  typeof_member(t, f)) && !offsetof(t, f))

/* Stats */

/* Use 32-byte alignment to reduce false sharing. The first ~4 fields usually
 * are the hottest and the stats update helpers are unrolled by this count.
 */
#define __libeth_stats_aligned		__aligned(4 * sizeof(u64_stats_t))

#define ___live(s)			u64_stats_t	s;

/* Rx per-queue stats:
 * packets: packets received on this queue
 * bytes: bytes received on this queue
 * fragments: number of processed descriptors carrying only a fragment
 * alloc_page_fail: number of Rx page allocation fails
 * build_skb_fail: number of build_skb() fails
 */

#define LIBETH_DECLARE_RQ_NAPI_STATS(act)				    \
	act(bytes)							    \
	act(packets)							    \
	act(fragments)							    \
	act(hsplit)							    \
	act(gro_hw)

#define LIBETH_DECLARE_RQ_FAIL_STATS(act)				    \
	act(dma_errs)							    \
	act(csum_errs)							    \
	act(hsplit_errs)						    \
	act(alloc_fail)							    \
	act(build_fail)

#define LIBETH_DECLARE_RQ_STATS(act)					    \
	LIBETH_DECLARE_RQ_NAPI_STATS(act)				    \
	LIBETH_DECLARE_RQ_FAIL_STATS(act)

struct libeth_rq_stats {
	struct u64_stats_sync		syncp;

	union {
		struct {
			struct_group(napi,
				LIBETH_DECLARE_RQ_NAPI_STATS(___live);
			);
			LIBETH_DECLARE_RQ_FAIL_STATS(___live);
		};
		DECLARE_FLEX_ARRAY(u64_stats_t, raw);
	} __aligned(sizeof(u64_stats_t));
} __libeth_stats_aligned;

/* Tx per-queue stats:
 * packets: packets sent from this queue
 * bytes: bytes sent from this queue
 * busy: number of xmit failures due to the ring being full
 * stops: number times the ring was stopped from the driver
 * restarts: number times it was started after being stopped
 * linearized: number of skbs linearized due to HW limits
 */

#define LIBETH_DECLARE_SQ_NAPI_STATS(act)				    \
	act(bytes)							    \
	act(packets)

#define LIBETH_DECLARE_SQ_XMIT_STATS(act)				    \
	act(fragments)							    \
	act(tso)							    \
	act(uso)

#define LIBETH_DECLARE_SQ_FAIL_STATS(act)				    \
	act(linearized)							    \
	act(dma_map_errs)						    \
	act(drops)							    \
	act(busy)							    \
	act(stops)							    \
	act(restarts)

#define LIBETH_DECLARE_SQ_STATS(act)					    \
	LIBETH_DECLARE_SQ_NAPI_STATS(act)				    \
	LIBETH_DECLARE_SQ_XMIT_STATS(act)				    \
	LIBETH_DECLARE_SQ_FAIL_STATS(act)

struct libeth_sq_stats {
	struct u64_stats_sync		syncp;

	union {
		struct {
			struct_group(napi,
				LIBETH_DECLARE_SQ_NAPI_STATS(___live);
			);
			struct_group(xmit,
				LIBETH_DECLARE_SQ_XMIT_STATS(___live);
			);
			LIBETH_DECLARE_SQ_FAIL_STATS(___live);
		};
		DECLARE_FLEX_ARRAY(u64_stats_t, raw);
	} __aligned(sizeof(u64_stats_t));
} __libeth_stats_aligned;

#define LIBETH_DECLARE_XDPSQ_NAPI_STATS(act)				    \
	LIBETH_DECLARE_SQ_NAPI_STATS(act)				    \
	act(fragments)

#define LIBETH_DECLARE_XDPSQ_FAIL_STATS(act)				    \
	act(dma_map_errs)						    \
	act(drops)							    \
	act(busy)

#define LIBETH_DECLARE_XDPSQ_STATS(act)					    \
	LIBETH_DECLARE_XDPSQ_NAPI_STATS(act)				    \
	LIBETH_DECLARE_XDPSQ_FAIL_STATS(act)

struct libeth_xdpsq_stats {
	struct u64_stats_sync		syncp;

	union {
		struct {
			struct_group(napi,
				LIBETH_DECLARE_XDPSQ_NAPI_STATS(___live);
			);
			LIBETH_DECLARE_XDPSQ_FAIL_STATS(___live);
		};
		DECLARE_FLEX_ARRAY(u64_stats_t, raw);
	} __aligned(sizeof(u64_stats_t));
} __libeth_stats_aligned;

#undef ___live

#endif /* __LIBETH_TYPES_H */
