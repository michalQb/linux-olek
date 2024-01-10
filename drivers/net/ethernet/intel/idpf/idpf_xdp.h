/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023 Intel Corporation */

#ifndef _IDPF_XDP_H_
#define _IDPF_XDP_H_

#include <linux/net/intel/libie/xdp.h>

struct idpf_vport;

int idpf_xdp_rxq_info_init(struct idpf_queue *rxq);
int idpf_xdp_rxq_info_deinit(struct idpf_queue *rxq);
int idpf_xdp_rxq_info_init_all(const struct idpf_vport *vport);
void idpf_xdp_rxq_info_deinit_all(const struct idpf_vport *vport);
void idpf_copy_xdp_prog_to_qs(const struct idpf_vport *vport,
			      struct bpf_prog *xdp_prog);

void idpf_vport_xdpq_get(const struct idpf_vport *vport);
void idpf_vport_xdpq_put(const struct idpf_vport *vport);

bool __idpf_xdp_run_prog(struct xdp_buff *xdp, struct libie_xdp_tx_bulk *bq);
void __idpf_xdp_finalize_rx(struct libie_xdp_tx_bulk *bq);

static inline bool idpf_xdp_run_prog(struct xdp_buff *xdp,
				     struct libie_xdp_tx_bulk *bq)
{
	return bq->prog ? __idpf_xdp_run_prog(xdp, bq) : true;
}

static inline void idpf_xdp_finalize_rx(struct libie_xdp_tx_bulk *bq)
{
	if (bq->act_mask >= LIBIE_XDP_TX)
		__idpf_xdp_finalize_rx(bq);
}

int idpf_xdp_xmit(struct net_device *dev, int n, struct xdp_frame **frames,
		  u32 flags);
int idpf_xdp(struct net_device *netdev, struct netdev_bpf *xdp);

#endif /* _IDPF_XDP_H_ */
