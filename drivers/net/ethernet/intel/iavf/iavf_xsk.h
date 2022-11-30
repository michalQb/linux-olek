/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2022 Intel Corporation. */

#ifndef _IAVF_XSK_H_
#define _IAVF_XSK_H_

struct iavf_adapter;

int iavf_xsk_pool_setup(struct iavf_adapter *adapter,
			struct xsk_buff_pool *pool, u16 qid);

#endif /* !_IAVF_XSK_H_ */
