/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023 Intel Corporation */

#ifndef _IDPF_XSK_H_
#define _IDPF_XSK_H_

#include <linux/types.h>

struct idpf_vport;
struct xsk_buff_pool;

int idpf_xsk_pool_setup(struct idpf_vport *vport, struct xsk_buff_pool *pool,
			u32 qid);

#endif /* !_IDPF_XSK_H_ */
