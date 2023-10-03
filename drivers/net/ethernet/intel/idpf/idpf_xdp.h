/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023 Intel Corporation */

#ifndef _IDPF_XDP_H_
#define _IDPF_XDP_H_

struct idpf_vport;

int idpf_xdp_rxq_info_init_all(const struct idpf_vport *vport);
void idpf_xdp_rxq_info_deinit_all(const struct idpf_vport *vport);

void idpf_vport_xdpq_get(const struct idpf_vport *vport);
void idpf_vport_xdpq_put(const struct idpf_vport *vport);

#endif /* _IDPF_XDP_H_ */
