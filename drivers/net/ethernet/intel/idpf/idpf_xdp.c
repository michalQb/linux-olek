// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2023 Intel Corporation */

#include "idpf.h"
#include "idpf_xdp.h"

static int idpf_rxq_for_each(const struct idpf_vport *vport,
			     int (*fn)(struct idpf_queue *rxq, void *arg),
			     void *arg)
{
	bool splitq = idpf_is_queue_model_split(vport->rxq_model);

	for (u32 i = 0; i < vport->num_rxq_grp; i++) {
		const struct idpf_rxq_group *rx_qgrp = &vport->rxq_grps[i];
		u32 num_rxq;

		if (splitq)
			num_rxq = rx_qgrp->splitq.num_rxq_sets;
		else
			num_rxq = rx_qgrp->singleq.num_rxq;

		for (u32 j = 0; j < num_rxq; j++) {
			struct idpf_queue *q;
			int err;

			if (splitq)
				q = &rx_qgrp->splitq.rxq_sets[j]->rxq;
			else
				q = rx_qgrp->singleq.rxqs[j];

			err = fn(q, arg);
			if (err)
				return err;
		}
	}

	return 0;
}

/**
 * idpf_xdp_rxq_info_init - Setup XDP RxQ info for a given Rx queue
 * @rxq: Rx queue for which the resources are setup
 * @arg: flag indicating if the HW works in split queue mode
 *
 * Return: 0 on success, negative on failure.
 */
static int idpf_xdp_rxq_info_init(struct idpf_queue *rxq, void *arg)
{
	const struct idpf_vport *vport = rxq->vport;
	const struct page_pool *pp;
	int err;

	err = __xdp_rxq_info_reg(&rxq->xdp_rxq, vport->netdev, rxq->idx,
				 rxq->q_vector->napi.napi_id,
				 rxq->rx_buf_size);
	if (err)
		return err;

	pp = arg ? rxq->rxq_grp->splitq.bufq_sets[0].bufq.pp : rxq->pp;
	xdp_rxq_info_attach_page_pool(&rxq->xdp_rxq, pp);

	rxq->xdpqs = &vport->txqs[vport->xdp_txq_offset];
	rxq->num_xdp_txq = vport->num_xdp_txq;

	return 0;
}

/**
 * idpf_xdp_rxq_info_init_all - initialize RxQ info for all Rx queues in vport
 * @vport: vport to setup the info
 *
 * Return: 0 on success, negative on failure.
 */
int idpf_xdp_rxq_info_init_all(const struct idpf_vport *vport)
{
	void *arg;

	arg = (void *)(size_t)idpf_is_queue_model_split(vport->rxq_model);

	return idpf_rxq_for_each(vport, idpf_xdp_rxq_info_init, arg);
}

/**
 * idpf_xdp_rxq_info_deinit - Deinit XDP RxQ info for a given Rx queue
 * @rxq: Rx queue for which the resources are destroyed
 */
static int idpf_xdp_rxq_info_deinit(struct idpf_queue *rxq, void *arg)
{
	rxq->xdpqs = NULL;
	rxq->num_xdp_txq = 0;

	xdp_rxq_info_detach_mem_model(&rxq->xdp_rxq);
	xdp_rxq_info_unreg(&rxq->xdp_rxq);

	return 0;
}

/**
 * idpf_xdp_rxq_info_deinit_all - deinit RxQ info for all Rx queues in vport
 * @vport: vport to setup the info
 */
void idpf_xdp_rxq_info_deinit_all(const struct idpf_vport *vport)
{
	idpf_rxq_for_each(vport, idpf_xdp_rxq_info_deinit, NULL);
}

void idpf_vport_xdpq_get(const struct idpf_vport *vport)
{
	if (!idpf_xdp_is_prog_ena(vport))
		return;

	cpus_read_lock();

	for (u32 j = vport->xdp_txq_offset; j < vport->num_txq; j++) {
		struct idpf_queue *xdpq = vport->txqs[j];

		__clear_bit(__IDPF_Q_FLOW_SCH_EN, xdpq->flags);
		__clear_bit(__IDPF_Q_FLOW_SCH_EN,
			    xdpq->txq_grp->complq->flags);
		__set_bit(__IDPF_Q_XDP, xdpq->flags);
		__set_bit(__IDPF_Q_XDP, xdpq->txq_grp->complq->flags);

		libie_xdp_sq_get(&xdpq->xdp_lock, vport->netdev,
				 vport->xdpq_share);
	}

	cpus_read_unlock();
}

void idpf_vport_xdpq_put(const struct idpf_vport *vport)
{
	if (!idpf_xdp_is_prog_ena(vport))
		return;

	cpus_read_lock();

	for (u32 j = vport->xdp_txq_offset; j < vport->num_txq; j++) {
		struct idpf_queue *xdpq = vport->txqs[j];

		if (!__test_and_clear_bit(__IDPF_Q_XDP, xdpq->flags))
			continue;

		libie_xdp_sq_put(&xdpq->xdp_lock, vport->netdev);
	}

	cpus_read_unlock();
}
