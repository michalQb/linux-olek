/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023 Intel Corporation */

#ifndef _IDPF_XSK_H_
#define _IDPF_XSK_H_

#include <linux/types.h>

enum virtchnl2_queue_type;

struct idpf_queue;
struct idpf_vport;
struct xsk_buff_pool;

void idpf_xsk_setup_queue(struct idpf_queue *q, enum virtchnl2_queue_type t);
void idpf_xsk_clear_queue(struct idpf_queue *q);

int idpf_check_alloc_rx_buffers_zc(struct idpf_queue *rxbufq);
void idpf_xsk_buf_rel(struct idpf_queue *rxbufq);
void idpf_xsk_clean_xdpq(struct idpf_queue *xdpq);

int idpf_clean_rx_irq_zc(struct idpf_queue *rxq, int budget);
bool idpf_xmit_zc(struct idpf_queue *complq);

int idpf_xsk_pool_setup(struct idpf_vport *vport, struct xsk_buff_pool *pool,
			u32 qid);

#endif /* !_IDPF_XSK_H_ */
