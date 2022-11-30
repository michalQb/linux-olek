/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2022 Intel Corporation. */

#ifndef _IAVF_XSK_H_
#define _IAVF_XSK_H_

#define PKTS_PER_BATCH 8

#ifdef __clang__
#define loop_unrolled_for _Pragma("clang loop unroll_count(8)") for
#elif __GNUC__ >= 8
#define loop_unrolled_for _Pragma("GCC unroll 8") for
#else
#define loop_unrolled_for for
#endif

struct iavf_adapter;
struct iavf_ring;

int iavf_xsk_pool_setup(struct iavf_adapter *adapter,
			struct xsk_buff_pool *pool, u16 qid);

int iavf_xsk_wakeup(struct net_device *netdev, u32 queue_id,
		    u32 __always_unused flags);
bool iavf_xmit_zc(struct iavf_ring *xdp_ring);
void iavf_xsk_clean_xdp_ring(struct iavf_ring *xdp_ring);

void iavf_xsk_clean_rx_ring(struct iavf_ring *rx_ring);
int iavf_clean_rx_irq_zc(struct iavf_ring *rx_ring, int budget);
void iavf_check_alloc_rx_buffers_zc(struct iavf_adapter *adapter,
				    struct iavf_ring *rx_ring, u16 count);

#endif /* !_IAVF_XSK_H_ */
