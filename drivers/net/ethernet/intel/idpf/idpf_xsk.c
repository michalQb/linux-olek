// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2023 Intel Corporation */

#include <net/xdp_sock_drv.h>
#include <net/xdp_sock.h>
#include "idpf.h"
#include "idpf_xsk.h"

/**
 * idpf_set_xsk_pool - set xsk_pool pointer from netdev to the queue structure
 * @q: queue to use
 *
 * Assigns pointer to xsk_pool field in queue struct if it is supported in
 * netdev, NULL otherwise.
 */
void idpf_set_xsk_pool(struct idpf_queue *q)
{
	struct idpf_vport_user_config_data *cfg_data;
	struct idpf_vport *vport = q->vport;
	bool is_rx = false;
	int qid;

	cfg_data = &vport->adapter->vport_config[vport->idx]->user_config;
	if (!idpf_xdp_is_prog_ena(q->vport)) {
		q->xsk_pool = NULL;
		return;
	}

	switch (q->q_type) {
	case VIRTCHNL2_QUEUE_TYPE_RX:
		is_rx = true;
		qid = q->idx;
		break;
	case VIRTCHNL2_QUEUE_TYPE_RX_BUFFER:
		is_rx = true;
		qid = q->rxq_grp->splitq.rxq_sets[0]->rxq.idx;
		break;
	case VIRTCHNL2_QUEUE_TYPE_TX:
		qid = q->idx - q->vport->xdp_txq_offset;
		break;
	case VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION:
		q->xsk_pool = NULL;
		return;
	}

	if (!test_bit(qid, cfg_data->af_xdp_zc_qps)) {
		q->xsk_pool = NULL;
		return;
	}

	q->xsk_pool = xsk_get_pool_from_qid(q->vport->netdev, qid);

	if (is_rx && q->xsk_pool && !xsk_buff_can_alloc(q->xsk_pool, 1))
		q->xsk_pool = NULL;
}

/**
 * idpf_qp_cfg_qs - Configure all queues contained from a given array.
 * @vport: vport structure
 * @qs: an array of queues to configure
 * @num_qs: number of queues in the 'qs' array
 *
 * Returns 0 in case of success, false otherwise.
 */
static int
idpf_qp_cfg_qs(struct idpf_vport *vport, struct idpf_queue **qs, int num_qs)
{
	bool splitq = idpf_is_queue_model_split(vport->rxq_model);
	int i, err = 0;

	for (i = 0; i < num_qs; i++) {
		struct idpf_queue *q = qs[i];

		switch (q->q_type) {
		case VIRTCHNL2_QUEUE_TYPE_RX:
			idpf_set_xsk_pool(q);
			err = idpf_rx_desc_alloc(q, false, vport->rxq_model);
			if (err) {
				netdev_err(vport->netdev, "Could not allocate buffer for RX queue.\n");
				break;
			}
			if (!splitq)
				err = idpf_rx_bufs_init(q);
			break;
		case VIRTCHNL2_QUEUE_TYPE_RX_BUFFER:
			idpf_set_xsk_pool(q);
			err = idpf_rx_desc_alloc(q, true, vport->rxq_model);
			if (err)
				break;
			err = idpf_rx_bufs_init(q);
			break;
		case VIRTCHNL2_QUEUE_TYPE_TX:
			err = idpf_tx_desc_alloc(q, true);
			if (test_bit(__IDPF_Q_XDP, q->flags))
				idpf_set_xsk_pool(q);
			break;
		case VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION:
			err = idpf_tx_desc_alloc(q, false);
			break;
		}

		if (err)
			return err;
	}

	return err;
}

/**
 * idpf_qp_clean_qs - Clean all queues contained from a given array.
 * @vport: vport structure
 * @qs: an array of queues to clean
 * @num_qs: number of queues in the 'qs' array
 */
static void
idpf_qp_clean_qs(struct idpf_vport *vport, struct idpf_queue **qs, int num_qs)
{
	int i;

	for (i = 0; i < num_qs; i++) {
		struct idpf_queue *q = qs[i];

		switch (q->q_type) {
		case VIRTCHNL2_QUEUE_TYPE_RX:
			idpf_rx_desc_rel(q, false, vport->rxq_model);
			break;
		case VIRTCHNL2_QUEUE_TYPE_RX_BUFFER:
			idpf_rx_desc_rel(q, true, vport->rxq_model);
			break;
		case VIRTCHNL2_QUEUE_TYPE_TX:
			idpf_tx_desc_rel(q, true);
			q->txq_grp->num_completions_pending = 0;
			writel(q->next_to_use, q->tail);
			break;
		case VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION:
			idpf_tx_desc_rel(q, false);
			q->num_completions = 0;
			break;
		}
	}
}

/**
 * idpf_qvec_toggle_napi - Enables/disables NAPI for a given q_vector
 * @vport: vport structure
 * @q_vector: q_vector that has NAPI context
 * @enable: true for enable, false for disable
 */
static void
idpf_qvec_toggle_napi(struct idpf_vport *vport, struct idpf_q_vector *q_vector,
		      bool enable)
{
	if (!vport->netdev || !q_vector)
		return;

	if (enable)
		napi_enable(&q_vector->napi);
	else
		napi_disable(&q_vector->napi);
}

/**
 * idpf_qvec_dis_irq - Disable IRQ for given queue vector
 * @q_vector: queue vector
 */
static void
idpf_qvec_dis_irq(struct idpf_q_vector *q_vector)
{
	writel(0, q_vector->intr_reg.dyn_ctl);
}

/**
 * idpf_qvec_ena_irq - Enable IRQ for given queue vector
 * @q_vector: queue vector
 */
static void
idpf_qvec_ena_irq(struct idpf_q_vector *q_vector)
{
	/* Write the default ITR values */
	if (q_vector->num_rxq)
		idpf_vport_intr_write_itr(q_vector, q_vector->rx_itr_value,
					  false);
	if (q_vector->num_txq)
		idpf_vport_intr_write_itr(q_vector, q_vector->tx_itr_value,
					  true);
	if (q_vector->num_rxq || q_vector->num_txq)
		idpf_vport_intr_update_itr_ena_irq(q_vector);
}

/**
 * idpf_insert_txqs_from_grp - Insert all tx and buffer queues from txq group
 *			       to a given array.
 * @vport: vport structure
 * @txq: pointer to a tx queue
 * @qs: pointer to an element of array where tx queues should be inserted
 *
 * Returns the number of queues that has been inserted to an output 'qs'
 * array.
 * Note that the caller of this function must ensure that there is enough space
 * in the 'qs' array to insert all the queues from the rx queue group.
 */
static int
idpf_insert_txqs_from_grp(struct idpf_vport *vport,
			  struct idpf_queue *txq,
			  struct idpf_queue **qs)
{
	int qs_idx = 0;

	if (!idpf_is_queue_model_split(vport->txq_model)) {
		qs[qs_idx++] = txq;
	} else {
		struct idpf_txq_group *txq_grp = txq->txq_grp;
		int i;

		for (i = 0; i < txq_grp->num_txq; i++)
			qs[qs_idx++] = txq_grp->txqs[i];

		for (i = 0; i < IDPF_COMPLQ_PER_GROUP; i++)
			qs[qs_idx++] = &txq_grp->complq[i];
	}

	return qs_idx;
}

/**
 * idpf_insert_rxqs_from_grp - Insert all rx and buffer queues from rxq group
 *			       to a given array.
 * @vport: vport structure
 * @rxq: pointer to a rx queue
 * @qs: pointer to an element of array where rx queues should be inserted
 *
 * Returns the number of queues that has been inserted to an output 'qs'
 * array.
 * Note that the caller of this function must ensure that there is enough space
 * in the 'qs' array to insert all the queues from the rx queue group.
 */
static int
idpf_insert_rxqs_from_grp(struct idpf_vport *vport,
			  struct idpf_queue *rxq,
			  struct idpf_queue **qs)
{
	int qs_idx = 0;

	if (!idpf_is_queue_model_split(vport->rxq_model)) {
		qs[qs_idx++] = rxq;
	} else {
		struct idpf_rxq_group *rxq_grp = rxq->rxq_grp;
		int i;

		for (i = 0; i < rxq_grp->splitq.num_rxq_sets; i++)
			qs[qs_idx++] = &rxq_grp->splitq.rxq_sets[i]->rxq;

		for (i = 0; i < vport->num_bufqs_per_qgrp; i++)
			qs[qs_idx++] = &rxq_grp->splitq.bufq_sets[i].bufq;
	}

	return qs_idx;
}

/**
 * idpf_count_rxqs_in_grp - Returns the number of rx queues in rx queue group
 *			    containing a given rx queue.
 * @vport: vport structure
 * @rxq: pointer to a rx queue
 *
 * Returns the number of rx queues in the rx queue group associated with
 * a given rx queue. Or, in case of singleq mode, 1, because rx queues
 * are not grouped.
 */
static int
idpf_count_rxqs_in_grp(struct idpf_vport *vport, struct idpf_queue *rxq)
{
	if (!idpf_is_queue_model_split(vport->rxq_model))
		return 1;

	return rxq->rxq_grp->splitq.num_rxq_sets + vport->num_bufqs_per_qgrp;
}

/**
 * idpf_count_txqs_in_grp - Returns the number of tx queues in tx queue group
 *			    containing a given tx queue.
 * @vport: vport structure
 * @txq: pointer to a tx queue
 *
 * Returns the number of tx queues in the tx queue group associated with
 * a given tx queue. Or, in case of singleq mode, 1, because tx queues
 * are not grouped.
 */
static int
idpf_count_txqs_in_grp(struct idpf_vport *vport, struct idpf_queue *txq)
{
	if (!idpf_is_queue_model_split(vport->txq_model))
		return 1;

	return txq->txq_grp->num_txq + IDPF_COMPLQ_PER_GROUP;
}

/**
 * idpf_create_queue_list - Creates a list of queues associated with a given
 *			    queue index.
 * @vport: vport structure
 * @q_idx: index of queue pair to establish XSK socket
 * @num_qs: number of queues in returned array.
 *
 * Returns a pointer to a dynamically allocated array of pointers to all
 * queues associated with a given queue index (q_idx).
 * Please note that the caller is responsible to free the memory allocated
 * by this function using 'kfree()'.
 * NULL-pointer will be returned in case of error.
 */
static struct idpf_queue **
idpf_create_queue_list(struct idpf_vport *vport, u16 q_idx, int *num_qs)
{
	struct idpf_queue *rxq, *txq, *xdpq = NULL;
	struct idpf_queue **qs;
	int qs_idx;

	*num_qs = 0;

	if (q_idx >= vport->num_rxq || q_idx >= vport->num_txq)
		return NULL;

	rxq = idpf_find_rxq(vport, q_idx);
	txq = idpf_find_txq(vport, q_idx);

	*num_qs += idpf_count_rxqs_in_grp(vport, rxq);
	*num_qs += idpf_count_txqs_in_grp(vport, txq);

	if (idpf_xdp_is_prog_ena(vport)) {
		xdpq = vport->txqs[q_idx + vport->xdp_txq_offset];
		*num_qs += idpf_count_txqs_in_grp(vport, xdpq);
	}

	qs = (struct idpf_queue **)kzalloc((*num_qs) * sizeof(*qs), GFP_KERNEL);
	if (!qs) {
		*num_qs = 0;
		return NULL;
	}

	qs_idx = 0;
	qs_idx += idpf_insert_txqs_from_grp(vport, txq, &qs[qs_idx]);

	if (xdpq)
		qs_idx += idpf_insert_txqs_from_grp(vport, xdpq, &qs[qs_idx]);

	qs_idx += idpf_insert_rxqs_from_grp(vport, rxq, &qs[qs_idx]);

	if (*num_qs != qs_idx) {
		kfree(qs);
		*num_qs = 0;
		qs = NULL;
	}

	return qs;
}

/**
 * idpf_qp_dis - Disables queues associated with a queue pair
 * @vport: vport structure
 * @q_vector: interrupt vector mapped to a given queue pair
 * @qs: array of pointers to queues to enable
 * @num_qs: number of queues in 'qs' array
 * @q_idx: index of queue pair to enable
 *
 * Returns 0 on success, negative on failure.
 */
static int idpf_qp_dis(struct idpf_vport *vport, struct idpf_q_vector *q_vector,
		       struct idpf_queue **qs, int num_qs, u16 q_idx)
{
	int err = 0;

	netif_tx_stop_queue(netdev_get_tx_queue(vport->netdev, q_idx));

	err = idpf_send_disable_vport_msg(vport);
	if (err) {
		netdev_err(vport->netdev, "Could not disable vport, error = %d\n",
			   err);
		goto err_send_msg;
	}
	err = idpf_send_disable_selected_queues_msg(vport, qs, num_qs);
	if (err) {
		netdev_err(vport->netdev, "Could not disable queues for index %d, error = %d\n",
			   q_idx, err);
		goto err_send_msg;
	}
	idpf_qvec_toggle_napi(vport, q_vector, false);
	idpf_qvec_dis_irq(q_vector);
	idpf_qp_clean_qs(vport, qs, num_qs);

	return 0;

err_send_msg:
	netif_tx_start_queue(netdev_get_tx_queue(vport->netdev, q_idx));

	return err;
}

/**
 * idpf_qp_ena - Enables queues associated with a queue pair
 * @vport: vport structure
 * @q_vector: interrupt vector mapped to a given queue pair
 * @qs: array of pointers to queues to enable
 * @num_qs: number of queues in 'qs' array
 * @q_idx: index of queue pair to enable
 *
 * Returns 0 on success, negative on failure.
 */
static int idpf_qp_ena(struct idpf_vport *vport, struct idpf_q_vector *q_vector,
		       struct idpf_queue **qs, int num_qs, u16 q_idx)
{
	int err;

	err = idpf_qp_cfg_qs(vport, qs, num_qs);
	if (err) {
		netdev_err(vport->netdev, "Could not initialize queues for index %d, error = %d\n",
			   q_idx, err);
		return err;
	}

	idpf_qvec_toggle_napi(vport, q_vector, true);
	idpf_qvec_ena_irq(q_vector);

	err = idpf_send_config_selected_queues_msg(vport, qs, num_qs);
	if (err) {
		netdev_err(vport->netdev, "Could not configure queues for index %d, error = %d\n",
			   q_idx, err);
		return err;
	}

	err = idpf_send_enable_selected_queues_msg(vport, qs, num_qs);
	if (err) {
		netdev_err(vport->netdev, "Could not enable queues for index %d, error = %d\n",
			   q_idx, err);
		return err;
	}

	err = idpf_send_enable_vport_msg(vport);
	if (err) {
		netdev_err(vport->netdev, "Could not enable vport, error = %d\n",
			   err);
		return err;
	}

	netif_tx_start_queue(netdev_get_tx_queue(vport->netdev, q_idx));

	return 0;
}

/**
 * idpf_xsk_pool_disable - disables a BUFF POOL region
 * @vport: vport to allocate the buffer pool on
 * @qid: queue id
 *
 * Returns 0 on success, negative on error
 */
static int idpf_xsk_pool_disable(struct idpf_vport *vport, u16 qid)
{
	struct idpf_vport_user_config_data *cfg_data;
	struct xsk_buff_pool *pool;
	if (!vport->rxq_grps)
		return -EINVAL;
	pool = xsk_get_pool_from_qid(vport->netdev, qid);
	if (!pool)
		return -EINVAL;

	xsk_pool_dma_unmap(pool, IDPF_RX_DMA_ATTR);

	cfg_data = &vport->adapter->vport_config[vport->idx]->user_config;
	clear_bit(qid, cfg_data->af_xdp_zc_qps);

	return 0;
}
/**
 * idpf_xsk_pool_enable - enables a BUFF POOL region
 * @vport: vport to allocate the buffer pool on
 * @pool: pointer to a requested BUFF POOL region
 * @qid: queue id
 *
 * Returns 0 on success, negative on error
 */
static int idpf_xsk_pool_enable(struct idpf_vport *vport,
				struct xsk_buff_pool *pool, u16 qid)
{
	struct idpf_vport_user_config_data *cfg_data;
	int err;

	if (qid >= vport->netdev->real_num_rx_queues ||
	    qid >= vport->netdev->real_num_tx_queues)
		return -EINVAL;

	err = xsk_pool_dma_map(pool, &vport->adapter->pdev->dev,
			       IDPF_RX_DMA_ATTR);
	if (err)
		return err;

	cfg_data = &vport->adapter->vport_config[vport->idx]->user_config;
	set_bit(qid, cfg_data->af_xdp_zc_qps);
	return 0;
}

/**
 * idpf_xsk_pool_setup - enable/disable a BUFF POOL region
 * @vport: current vport of interest
 * @pool: pointer to a requested BUFF POOL region
 * @qid: queue id
 *
 * Returns 0 on success, negative on failure
 */
int idpf_xsk_pool_setup(struct idpf_vport *vport, struct xsk_buff_pool *pool,
			u32 qid)
{
	struct idpf_queue *rxq = idpf_find_rxq(vport, qid);
	struct idpf_q_vector *q_vector = rxq->q_vector;
	bool if_running, pool_present = !!pool;
	int err = 0, pool_failure = 0, num_qs;
	struct idpf_queue **qs;

	if_running = netif_running(vport->netdev) &&
		     idpf_xdp_is_prog_ena(vport);

	if (if_running) {
		qs = idpf_create_queue_list(vport, qid, &num_qs);
		if (!qs) {
			err = -ENOMEM;
			goto xsk_exit;
		}

		err = idpf_qp_dis(vport, q_vector, qs, num_qs, qid);
		if (err) {
			netdev_err(vport->netdev, "Cannot disable queues for XSK setup, error = %d\n",
				   err);
			goto xsk_pool_if_up;
		}
	}

	pool_failure = pool_present ? idpf_xsk_pool_enable(vport, pool, qid) :
				      idpf_xsk_pool_disable(vport, qid);

	if (!idpf_xdp_is_prog_ena(vport))
		netdev_warn(vport->netdev, "RSS may schedule pkts to q occupied by AF XDP\n");

xsk_pool_if_up:
	if (if_running) {
		err = idpf_qp_ena(vport, q_vector, qs, num_qs, qid);
		if (!err && pool_present)
			napi_schedule(&rxq->q_vector->napi);
		else if (err)
			netdev_err(vport->netdev,
				   "Could not enable queues after XSK setup, error = %d\n",
				   err);
		kfree(qs);
	}

	if (pool_failure) {
		netdev_err(vport->netdev, "Could not %sable BUFF POOL, error = %d\n",
			   pool_present ? "en" : "dis", pool_failure);
		err = pool_failure;
	}

xsk_exit:
	return err;
}
