/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023 Intel Corporation */

#ifndef _IDPF_XSK_H_
#define _IDPF_XSK_H_

#include <linux/types.h>
#include <net/xdp_sock_drv.h>

#define IDPF_XSK_PKTS_PER_BATCH 8

#ifdef __clang__
#define loop_unrolled_for _Pragma("clang loop unroll_count(8)") for
#elif __GNUC__ >= 8
#define loop_unrolled_for _Pragma("GCC unroll 8") for
#else
#define loop_unrolled_for for
#endif

struct idpf_vport;
struct idpf_queue;
struct net_device;
struct xsk_buff_pool;

int idpf_xsk_pool_setup(struct idpf_vport *vport,
			struct xsk_buff_pool *pool, u32 qid);
int idpf_xsk_splitq_wakeup(struct net_device *netdev, u32 q_id,
			   u32 __always_unused flags);
bool idpf_xmit_zc(struct idpf_queue *complq);
void idpf_xsk_clean_xdpq(struct idpf_queue *xdpq);
void idpf_xsk_setup_xdpq(struct idpf_queue *xdpq);
void idpf_xsk_setup_rxbufq(struct idpf_queue *rxbufq, bool bufq);
void idpf_xsk_rel_rx_buf(struct idpf_queue *rxbufq);
int idpf_check_alloc_rx_buffers_zc(struct idpf_queue *rxbufq);
int idpf_clean_rx_irq_zc(struct idpf_queue *rxq, int budget);

#endif /* !_IDPF_XSK_H_ */
