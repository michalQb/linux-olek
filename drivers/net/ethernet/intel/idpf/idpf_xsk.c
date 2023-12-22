// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2023 Intel Corporation */

#include <net/xdp_sock.h>
#include "idpf.h"
#include "idpf_xsk.h"

/**
 * idpf_set_xsk_pool - set xsk_pool pointer from netdev to the queue structure
 * @q: queue to use
 * @q_type: queue type according to VC
 *
 * Assigns pointer to xsk_pool field in queue struct if it is supported in
 * netdev, NULL otherwise.
 */
void idpf_set_xsk_pool(struct idpf_queue *q, u32 q_type)
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

	switch (q_type) {
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
 * idpf_xsk_setup_xdpq - Setup XDP queue depending on its XSK configuration
 * @xdpq: xdp queue to be configured
 */
void idpf_xsk_setup_xdpq(struct idpf_queue *xdpq)
{
	struct idpf_queue *complq = xdpq->txq_grp->complq;

	idpf_set_xsk_pool(xdpq, VIRTCHNL2_QUEUE_TYPE_TX);
	if (xdpq->xsk_pool) {
		set_bit(__IDPF_Q_XSK, xdpq->flags);
		set_bit(__IDPF_Q_XSK, complq->flags);
	} else {
		clear_bit(__IDPF_Q_XSK, xdpq->flags);
		clear_bit(__IDPF_Q_XSK, complq->flags);
	}
}

/**
 * idpf_xsk_setup_rxbufq - Setup or buffer queue depending on its XSK configuration
 * @rxbufq: rx or buffer queue to be configured
 * @bufq: flag indicating if the queue is buffer queue
 */
void idpf_xsk_setup_rxbufq(struct idpf_queue *rxbufq, bool bufq)
{
	u32 q_type = bufq ? VIRTCHNL2_QUEUE_TYPE_RX_BUFFER :
			    VIRTCHNL2_QUEUE_TYPE_RX;
	struct idpf_rxq_group *rxq_grp = rxbufq->rxq_grp;
	struct idpf_vport *vport = rxbufq->vport;

	idpf_set_xsk_pool(rxbufq, q_type);
	if (rxbufq->xsk_pool) {
		set_bit(__IDPF_Q_XSK, rxbufq->flags);
		rxq_grp->splitq.num_bufq_sets = IDPF_SINGLE_BUFQ_PER_RXQ_GRP;
		if (bufq)
			rxbufq->desc_count = vport->rxq_desc_count;
	} else {
		clear_bit(__IDPF_Q_XSK, rxbufq->flags);
		rxq_grp->splitq.num_bufq_sets = vport->num_bufqs_per_qgrp;
		if (bufq)
			rxbufq->desc_count = vport->bufq_desc_count[rxbufq->idx];
	}
}

void idpf_xsk_setup_all_rxbufqs(struct idpf_vport *vport)
{
	struct idpf_rxq_group *rx_qgrp;
	u16 num_rxq;
	int i, j;

	if (!vport->rxq_grps)
		return;

	for (i = 0; i < vport->num_rxq_grp; i++) {
		rx_qgrp = &vport->rxq_grps[i];

		if (!idpf_is_queue_model_split(vport->rxq_model)) {
			for (j = 0; j < rx_qgrp->singleq.num_rxq; j++)
				idpf_xsk_setup_rxbufq(rx_qgrp->singleq.rxqs[j],
						      false);
			continue;
		}

		num_rxq = rx_qgrp->splitq.num_rxq_sets;
		for (j = 0; j < num_rxq; j++)
			idpf_xsk_setup_rxbufq(&rx_qgrp->splitq.rxq_sets[j]->rxq,
					      false);

		if (!rx_qgrp->splitq.bufq_sets)
			continue;

		for (j = 0; j < vport->num_bufqs_per_qgrp; j++) {
			struct idpf_bufq_set *bufq_set =
					&rx_qgrp->splitq.bufq_sets[j];

			idpf_xsk_setup_rxbufq(&bufq_set->bufq, true);
		}
	}
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
			err = idpf_rx_desc_alloc(q, false, vport->rxq_model);
			if (err) {
				netdev_err(vport->netdev, "Could not allocate buffer for RX queue.\n");
				break;
			}
			if (!splitq)
				err = idpf_rx_bufs_init(q);
			break;
		case VIRTCHNL2_QUEUE_TYPE_RX_BUFFER:
			err = idpf_rx_desc_alloc(q, true, vport->rxq_model);
			if (err)
				break;
			err = idpf_rx_bufs_init(q);
			break;
		case VIRTCHNL2_QUEUE_TYPE_TX:
			err = idpf_tx_desc_alloc(q, true);
			if (test_bit(__IDPF_Q_XDP, q->flags))
				idpf_xsk_setup_xdpq(q);
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
 * idpf_trigger_sw_intr - trigger a software interrupt
 * @hw: pointer to the HW structure
 * @q_vector: interrupt vector to trigger the software interrupt for
 */
static void
idpf_trigger_sw_intr(struct idpf_hw *hw, struct idpf_q_vector *q_vector)
{
	struct idpf_intr_reg *intr = &q_vector->intr_reg;
	u32 val;

	val = intr->dyn_ctl_intena_m |
	      intr->dyn_ctl_itridx_m |    /* set no itr*/
	      intr->dyn_ctl_swint_trig_m |
	      intr->dyn_ctl_sw_itridx_ena_m;

	writel(val, intr->dyn_ctl);
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

		for (i = 0; i < rxq_grp->splitq.num_bufq_sets; i++)
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

	return rxq->rxq_grp->splitq.num_rxq_sets +
	       rxq->rxq_grp->splitq.num_bufq_sets;
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

static struct idpf_queue **
idpf_refresh_queue_list(struct idpf_vport *vport, u16 idx,
			struct idpf_queue **qs, int *num_qs)
{
	struct idpf_queue *rxq = idpf_find_rxq(vport, idx);
	struct idpf_rxq_group *rxq_grp = rxq->rxq_grp;
	int i;

	idpf_xsk_setup_rxbufq(rxq, false);

	for (i = 0; i < rxq_grp->splitq.num_bufq_sets; i++) {
		struct idpf_queue *bufq = &rxq_grp->splitq.bufq_sets[i].bufq;

		idpf_xsk_setup_rxbufq(bufq, true);
	}

	kfree(qs);
	qs = NULL;

	qs = idpf_create_queue_list(vport, idx, num_qs);
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

	qs = idpf_refresh_queue_list(vport, q_idx, qs, &num_qs);
	if (!qs)
		return -ENOMEM;

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
	bool if_running, pool_present = !!pool;
	int err = 0, pool_failure = 0, num_qs;
	struct idpf_q_vector *q_vector;
	struct idpf_queue *rxq;
	struct idpf_queue **qs;

	if_running = netif_running(vport->netdev) &&
		     idpf_xdp_is_prog_ena(vport);

	if (if_running) {
		rxq = idpf_find_rxq(vport, qid);
		q_vector = rxq->q_vector;

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

/**
 * idpf_clean_xdp_tx_buf - Free and unmap XDP Tx buffer
 * @xdpq: XDP Tx queue
 * @tx_buf: Tx buffer to clean
 */
static void
idpf_clean_xdp_tx_buf(struct idpf_queue *xdpq, struct idpf_tx_buf *tx_buf)
{
	switch (tx_buf->xdp_type) {
	case IDPF_XDP_BUFFER_FRAME:
		dma_unmap_single(xdpq->dev, dma_unmap_addr(tx_buf, dma),
				 dma_unmap_len(tx_buf, len), DMA_TO_DEVICE);
		dma_unmap_len_set(tx_buf, len, 0);
		xdp_return_frame(tx_buf->xdpf);
		tx_buf->xdpf = NULL;
		break;
	case IDPF_XDP_BUFFER_TX:
		xsk_buff_free(tx_buf->xdp);
		break;
	}

	xdpq->xdp_tx_active--;
	tx_buf->xdp_type = IDPF_XDP_BUFFER_NONE;
}

/**
 * idpf_clean_xdp_irq_zc - produce AF_XDP descriptors to CQ
 * @complq: completion queue associated with zero-copy Tx queue
 */
static void idpf_clean_xdp_irq_zc(struct idpf_queue *complq)
{
	struct idpf_splitq_4b_tx_compl_desc *last_rs_desc;
	int complq_budget = complq->desc_count;
	u32 ntc = complq->next_to_clean;
	struct idpf_queue *xdpq = NULL;
	u32 done_frames = 0;
	u32 xsk_frames = 0;
	u32 tx_ntc, cnt;
	bool gen_flag;
	int head, i;

	last_rs_desc = IDPF_SPLITQ_4B_TX_COMPLQ_DESC(complq, ntc);
	gen_flag = test_bit(__IDPF_Q_GEN_CHK, complq->flags);

	do {
		int ctype = idpf_parse_compl_desc(last_rs_desc, complq,
						  &xdpq, gen_flag);
		switch (ctype) {
		case IDPF_TXD_COMPLT_RS:
			if (!test_bit(__IDPF_Q_XSK, xdpq->flags)) {
				dev_err(&xdpq->vport->adapter->pdev->dev,
					"Found TxQ is not XSK queue\n");
				goto fetch_next_desc;
			}
			break;
		case IDPF_TXD_COMPLT_SW_MARKER:
			idpf_tx_handle_sw_marker(xdpq);
			break;
		case -ENODATA:
			goto clean_xdpq;
		case -EINVAL:
			goto fetch_next_desc;
		default:
			dev_err(&xdpq->vport->adapter->pdev->dev,
				"Unsupported completion type for XSK\n");
			goto fetch_next_desc;
		}

		head = le16_to_cpu(last_rs_desc->q_head_compl_tag.q_head);
fetch_next_desc:
		last_rs_desc++;
		ntc++;
		if (unlikely(ntc == complq->desc_count)) {
			ntc = 0;
			last_rs_desc = IDPF_SPLITQ_4B_TX_COMPLQ_DESC(complq, 0);
			gen_flag = !gen_flag;
			change_bit(__IDPF_Q_GEN_CHK, complq->flags);
		}
		prefetch(last_rs_desc);
		complq_budget--;
	} while (likely(complq_budget));

clean_xdpq:
	complq->next_to_clean = ntc;

	if (!xdpq)
		return;

	cnt = xdpq->desc_count;
	tx_ntc = xdpq->next_to_clean;
	done_frames = head >= tx_ntc ? head - tx_ntc :
				       head + cnt - tx_ntc;
	if (!done_frames)
		return;

	if (likely(!xdpq->xdp_tx_active)) {
		xsk_frames = done_frames;
		goto skip;
	}

	for (i = 0; i < done_frames; i++) {
		struct idpf_tx_buf *tx_buf = &xdpq->tx_buf[tx_ntc];

		if (tx_buf->xdp_type)
			idpf_clean_xdp_tx_buf(xdpq, tx_buf);
		else
			xsk_frames++;

		tx_ntc++;
		if (tx_ntc >= cnt)
			tx_ntc = 0;
	}
skip:
	xdpq->next_to_clean += done_frames;
	if (xdpq->next_to_clean >= cnt)
		xdpq->next_to_clean -= cnt;
	if (xsk_frames)
		xsk_tx_completed(xdpq->xsk_pool, xsk_frames);
}

/**
 * idpf_xmit_pkt - produce a single HW Tx descriptor out of AF_XDP descriptor
 * @xdpq: XDP queue to produce the HW Tx descriptor on
 * @desc: AF_XDP descriptor to pull the DMA address and length from
 * @total_bytes: bytes accumulator that will be used for stats update
 */
static void idpf_xmit_pkt(struct idpf_queue *xdpq, struct xdp_desc *desc,
			  unsigned int *total_bytes)
{
	struct idpf_tx_splitq_params tx_params = {
		(enum idpf_tx_desc_dtype_value)0, 0, { }, { }
	};
	union idpf_tx_flex_desc *tx_desc;
	dma_addr_t dma;

	dma = xsk_buff_raw_get_dma(xdpq->xsk_pool, desc->addr);
	xsk_buff_raw_dma_sync_for_device(xdpq->xsk_pool, dma, desc->len);

	tx_desc = IDPF_FLEX_TX_DESC(xdpq, xdpq->next_to_use++);
	tx_desc->q.buf_addr = cpu_to_le64(dma);
	tx_params.dtype = IDPF_TX_DESC_DTYPE_FLEX_L2TAG1_L2TAG2;
	tx_params.eop_cmd = IDPF_TX_DESC_CMD_EOP;

	idpf_tx_splitq_build_desc(tx_desc, &tx_params,
				  tx_params.eop_cmd |
				  tx_params.offload.td_cmd,
				  desc->len);
	*total_bytes += desc->len;
}

/**
 * idpf_xmit_pkt_batch - produce a batch of HW Tx descriptors out of AF_XDP descriptors
 * @xdpq: XDP queue to produce the HW Tx descriptors on
 * @descs: AF_XDP descriptors to pull the DMA addresses and lengths from
 * @total_bytes: bytes accumulator that will be used for stats update
 */
static void idpf_xmit_pkt_batch(struct idpf_queue *xdpq,
				struct xdp_desc *descs,
				unsigned int *total_bytes)
{
	struct idpf_tx_splitq_params tx_params = {
		(enum idpf_tx_desc_dtype_value)0, 0, { }, { }
	};
	union idpf_tx_flex_desc *tx_desc;
	u32 ntu = xdpq->next_to_use;
	u32 i;

	loop_unrolled_for(i = 0; i < IDPF_XSK_PKTS_PER_BATCH; i++) {
		dma_addr_t dma;

		dma = xsk_buff_raw_get_dma(xdpq->xsk_pool, descs[i].addr);
		xsk_buff_raw_dma_sync_for_device(xdpq->xsk_pool, dma,
						 descs[i].len);

		tx_desc = IDPF_FLEX_TX_DESC(xdpq, ntu++);
		tx_desc->q.buf_addr = cpu_to_le64(dma);
		tx_params.dtype = IDPF_TX_DESC_DTYPE_FLEX_L2TAG1_L2TAG2;
		tx_params.eop_cmd = IDPF_TX_DESC_CMD_EOP;

		idpf_tx_splitq_build_desc(tx_desc, &tx_params,
					  tx_params.eop_cmd |
					  tx_params.offload.td_cmd,
					  descs[i].len);
		*total_bytes += descs[i].len;
	}
	xdpq->next_to_use = ntu;
}

/**
 * idpf_fill_tx_hw_queue - produce the number of Tx descriptors onto queue
 * @xdpq: XDP queue to produce the HW Tx descriptors on
 * @descs: AF_XDP descriptors to pull the DMA addresses and lengths from
 * @nb_pkts: count of packets to be send
 * @total_bytes: bytes accumulator that will be used for stats update
 */
static void idpf_fill_tx_hw_queue(struct idpf_queue *xdpq,
				  struct xdp_desc *descs, u32 nb_pkts,
				  unsigned int *total_bytes)
{
	u32 batched, leftover, i;

	batched = ALIGN_DOWN(nb_pkts, IDPF_XSK_PKTS_PER_BATCH);
	leftover = nb_pkts & (IDPF_XSK_PKTS_PER_BATCH - 1);

	for (i = 0; i < batched; i += IDPF_XSK_PKTS_PER_BATCH)
		idpf_xmit_pkt_batch(xdpq, &descs[i], total_bytes);
	for (; i < batched + leftover; i++)
		idpf_xmit_pkt(xdpq, &descs[i], total_bytes);
}

/**
 * idpf_xmit_xdpq_zc - take entries from XSK Tx queue and place them onto HW Tx queue
 * @xdpq: XDP queue to produce the HW Tx descriptors on
 *
 * Returns true if there is no more work that needs to be done, false otherwise
 */
static bool idpf_xmit_xdpq_zc(struct idpf_queue *xdpq)
{
	struct xdp_desc *descs = xdpq->xsk_pool->tx_descs;
	struct idpf_cleaned_stats stats = { };
	u32 nb_processed = 0;
	int budget;

	budget = IDPF_DESC_UNUSED(xdpq);
	budget = min_t(u16, budget, xdpq->desc_count / 4);

	stats.packets = xsk_tx_peek_release_desc_batch(xdpq->xsk_pool,
						       budget);
	if (!stats.packets)
		return true;

	if (xdpq->next_to_use + stats.packets >= xdpq->desc_count) {
		nb_processed = xdpq->desc_count - xdpq->next_to_use;
		idpf_fill_tx_hw_queue(xdpq, descs, nb_processed,
				      &stats.bytes);
		xdpq->next_to_use = 0;
		xdpq->compl_tag_cur_gen = IDPF_TX_ADJ_COMPL_TAG_GEN(xdpq);
	}

	idpf_fill_tx_hw_queue(xdpq, &descs[nb_processed],
			      stats.packets - nb_processed, &stats.bytes);

	idpf_set_rs_bit(xdpq);
	//idpf_update_tx_ring_stats(xdpq, &stats);
	idpf_xdpq_update_tail(xdpq);

	if (xsk_uses_need_wakeup(xdpq->xsk_pool))
		xsk_set_tx_need_wakeup(xdpq->xsk_pool);

	return stats.packets < budget;
}

/**
 * idpf_xmit_zc - perform xmit from all XDP queues assigned to the completion queue
 * @complq: Completion queue associated with one or more XDP queues
 *
 * Returns true if there is no more work that needs to be done, false otherwise
 */
bool idpf_xmit_zc(struct idpf_queue *complq)
{
	struct idpf_txq_group *xdpq_grp = complq->txq_grp;
	bool result = true;
	int i;

	idpf_clean_xdp_irq_zc(complq);

	for (i = 0; i < xdpq_grp->num_txq; i++)
		result &= idpf_xmit_xdpq_zc(xdpq_grp->txqs[i]);

	return result;
}

/**
 * idpf_xsk_wakeup - Implements ndo_xsk_wakeup
 * @netdev: net_device
 * @queue_id: queue to wake up
 * @flags: ignored in our case, since we have Rx and Tx in the same NAPI
 *
 * Returns negative on error, zero otherwise.
 */
int idpf_xsk_splitq_wakeup(struct net_device *netdev, u32 q_id,
			   u32 __always_unused flags)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);
	struct idpf_vport *vport = np->vport;
	struct idpf_q_vector *q_vector;
	struct idpf_queue *q;
	int idx;


	if (idpf_vport_ctrl_is_locked(netdev))
		return -EBUSY;

	if (unlikely(!vport->link_up))
		return -ENETDOWN;

	if (unlikely(!idpf_xdp_is_prog_ena(vport)))
		return -ENXIO;

	idx = q_id + vport->xdp_txq_offset;

	if (unlikely(idx >= vport->num_txq))
		return -ENXIO;

	if (unlikely(!test_bit(__IDPF_Q_XSK, vport->txqs[idx]->flags)))
		return -ENXIO;

	q = vport->txqs[idx];
	q_vector = q->txq_grp->complq->q_vector;

	if (!napi_if_scheduled_mark_missed(&q_vector->napi))
		idpf_trigger_sw_intr(&vport->adapter->hw, q_vector);

	return 0;
}

/**
 * idpf_xsk_clean_xdpq - Clean the XDP Tx queue and its buffer pool queues
 * @xdpq: XDP_Tx queue
 */
void idpf_xsk_clean_xdpq(struct idpf_queue *xdpq)
{
	u32 ntc = xdpq->next_to_clean, ntu = xdpq->next_to_use;
	u32 xsk_frames = 0;

	while (ntc != ntu) {
		struct idpf_tx_buf *tx_buf = &xdpq->tx_buf[ntc];

		if (tx_buf->xdp_type)
			idpf_clean_xdp_tx_buf(xdpq, tx_buf);
		else
			xsk_frames++;

		tx_buf->page = NULL;

		ntc++;
		if (ntc >= xdpq->desc_count)
			ntc = 0;
	}

	if (xsk_frames)
		xsk_tx_completed(xdpq->xsk_pool, xsk_frames);
}

/**
 * idpf_init_rx_descs_zc - pick buffers from XSK buffer pool and use it
 * @pool: XSK Buffer pool to pull the buffers from
 * @xdp: SW ring of xdp_buff that will hold the buffers
 * @buf_desc: Pointer to buffer descriptors that will be filled
 * @first_buf_id: ID of the first buffer to be filled
 * @count: The number of buffers to allocate
 *
 * This function allocates a number of Rx buffers from the fill queue
 * or the internal recycle mechanism and places them on the buffer queue.
 *
 * Note that queue wrap should be handled by caller of this function.
 *
 * Returns the amount of allocated Rx descriptors
 */
static u32 idpf_init_rx_descs_zc(struct xsk_buff_pool *pool,
				 struct xdp_buff **xdp,
				 struct virtchnl2_splitq_rx_buf_desc *buf_desc,
				 u32 first_buf_id,
				 u32 count)
{
	dma_addr_t dma;
	u32 num_buffs;
	u32 i;

	num_buffs = xsk_buff_alloc_batch(pool, xdp, count);
	for (i = 0; i < num_buffs; i++) {
		dma = xsk_buff_xdp_get_dma(*xdp);
		buf_desc->pkt_addr = cpu_to_le64(dma);
		buf_desc->qword0.buf_id = cpu_to_le16(i + first_buf_id);

		buf_desc++;
		xdp++;
	}

	return num_buffs;
}

static struct xdp_buff **idpf_get_xdp_buff(struct idpf_queue *q, u32 idx)
{
	return &q->xdp_buf[idx];
}

/**
 * __idpf_alloc_rx_buffers_zc - allocate a number of Rx buffers
 * @rxbufq: buffer queue
 * @count: The number of buffers to allocate
 *
 * Place the @count of descriptors onto buffer queue. Handle the queue wrap
 * for case where space from next_to_use up to the end of ring is less
 * than @count. Finally do a tail bump.
 *
 * Returns true if all allocations were successful, false if any fail.
 */
static bool __idpf_alloc_rx_buffers_zc(struct idpf_queue *rxbufq, u32 count)
{
	struct virtchnl2_splitq_rx_buf_desc *buf_desc;
	u32 nb_buffs_extra = 0, nb_buffs = 0;
	u32 ntu = rxbufq->next_to_use;
	u32 total_count = count;
	struct xdp_buff **xdp;

	buf_desc = IDPF_SPLITQ_RX_BUF_DESC(rxbufq, ntu);
	xdp = idpf_get_xdp_buff(rxbufq, ntu);

	if (ntu + count >= rxbufq->desc_count) {
		nb_buffs_extra = idpf_init_rx_descs_zc(rxbufq->xsk_pool, xdp,
						       buf_desc,
						       ntu,
						       rxbufq->desc_count - ntu);
		if (nb_buffs_extra != rxbufq->desc_count - ntu) {
			ntu += nb_buffs_extra;
			goto exit;
		}
		buf_desc = IDPF_SPLITQ_RX_BUF_DESC(rxbufq, 0);
		xdp = idpf_get_xdp_buff(rxbufq, 0);
		ntu = 0;
		count -= nb_buffs_extra;
		idpf_rx_buf_hw_update(rxbufq, 0);

		if (!count)
			goto exit;
	}

	nb_buffs = idpf_init_rx_descs_zc(rxbufq->xsk_pool, xdp,
					 buf_desc, ntu, count);

	ntu += nb_buffs;
	if (ntu == rxbufq->desc_count)
		ntu = 0;

exit:
	if (rxbufq->next_to_use != ntu)
		idpf_rx_buf_hw_update(rxbufq, ntu);

	rxbufq->next_to_alloc = ntu;

	return total_count == (nb_buffs_extra + nb_buffs);
}

/**
 * idpf_alloc_rx_buffers_zc - allocate a number of Rx buffers
 * @rxbufq: buffer queue
 * @count: The number of buffers to allocate
 *
 * Wrapper for internal allocation routine; figure out how many tail
 * bumps should take place based on the given threshold
 *
 * Returns true if all calls to internal alloc routine succeeded
 */
static bool idpf_alloc_rx_buffers_zc(struct idpf_queue *rxbufq, u32 count)
{
	u32 rx_thresh = IDPF_QUEUE_QUARTER(rxbufq);
	u32 leftover, i, tail_bumps;

	tail_bumps = count / rx_thresh;
	leftover = count - (tail_bumps * rx_thresh);

	for (i = 0; i < tail_bumps; i++)
		if (!__idpf_alloc_rx_buffers_zc(rxbufq, rx_thresh))
			return false;
	return __idpf_alloc_rx_buffers_zc(rxbufq, leftover);
}

/**
 * idpf_check_alloc_rx_buffers_zc - allocate a number of Rx buffers with logs
 * @adapter: board private structure
 * @rxbufq: buffer queue
 *
 * Wrapper for internal allocation routine; Prints out logs, if allocation
 * did not go as expected
 */
int idpf_check_alloc_rx_buffers_zc(struct idpf_queue *rxbufq)
{
	struct net_device *netdev = rxbufq->vport->netdev;
	u32 count = IDPF_DESC_UNUSED(rxbufq);

	rxbufq->xdp_buf = kcalloc(rxbufq->desc_count, sizeof(*rxbufq->xdp_buf),
				  GFP_KERNEL);

	if (!xsk_buff_can_alloc(rxbufq->xsk_pool, count)) {
		netdev_warn(netdev, "XSK buffer pool does not provide enough addresses to fill %d buffers on Rx queue %d\n",
			    count, rxbufq->idx);
		netdev_warn(netdev, "Change Rx queue/fill queue size to avoid performance issues\n");
	}

	if (!idpf_alloc_rx_buffers_zc(rxbufq, count))
		netdev_warn(netdev, "Failed to allocate some buffers on XSK buffer pool enabled Rx queue %d\n",
			    rxbufq->idx);
	return 0;
}

/**
 * idpf_xsk_clean_rxbufq - clean buffer pool queues connected to a given Rx queue
 * @rxbufq: queue to be cleaned
 */
void idpf_xsk_clean_rxbufq(struct idpf_queue *rxbufq)
{
	u16 ntc = rxbufq->next_to_clean;
	u16 ntu = rxbufq->next_to_use;

	while (ntc != ntu) {
		struct xdp_buff *xdp = *idpf_get_xdp_buff(rxbufq, ntc);

		xsk_buff_free(xdp);
		ntc++;
		if (ntc >= rxbufq->desc_count)
			ntc = 0;
	}
}

/**
 * idpf_xmit_xdp_tx_zc - AF_XDP ZC handler for XDP_TX
 * @xdp: XDP buffer to xmit
 * @xdpq: XDP queue to produce descriptor onto
 *
 * Returns 0 for successfully produced desc,
 * -EBUSY if there was not enough space on XDP queue.
 */
static int idpf_xmit_xdp_tx_zc(struct xdp_buff *xdp,
			       struct idpf_queue *xdpq)
{
	struct idpf_tx_splitq_params tx_params = { };
	u32 size = xdp->data_end - xdp->data;
	union idpf_tx_flex_desc *tx_desc;
	struct idpf_tx_buf *tx_buf;
	u32 ntu = xdpq->next_to_use;
	dma_addr_t dma;

	if (IDPF_DESC_UNUSED(xdpq) < IDPF_QUEUE_QUARTER(xdpq))
		idpf_clean_xdp_irq_zc(xdpq);

	if (unlikely(!IDPF_DESC_UNUSED(xdpq)))
		return -EBUSY;

	dma = xsk_buff_xdp_get_dma(xdp);
	xsk_buff_raw_dma_sync_for_device(xdpq->xsk_pool, dma, size);

	tx_buf = &xdpq->tx_buf[ntu];
	tx_buf->bytecount = size;
	tx_buf->gso_segs = 1;
	tx_buf->xdp_type = IDPF_XDP_BUFFER_TX;
	tx_buf->xdp = xdp;

	tx_desc = IDPF_FLEX_TX_DESC(xdpq, ntu);
	tx_desc->q.buf_addr = cpu_to_le64(dma);

	tx_params.dtype = IDPF_TX_DESC_DTYPE_FLEX_L2TAG1_L2TAG2;
	tx_params.eop_cmd = IDPF_TX_DESC_CMD_EOP;

	idpf_tx_splitq_build_desc(tx_desc, &tx_params,
				  tx_params.eop_cmd | tx_params.offload.td_cmd,
				  size);

	xdpq->xdp_tx_active++;

	if (++ntu == xdpq->desc_count)
		ntu = 0;
	xdpq->next_to_use = ntu;

	return 0;
}

/**
 * idpf_run_xdp_zc - Run XDP program and perform resulting action for ZC
 * @rxbufq: RX buffer queue to transact packets on
 * @xdp: a prepared XDP buffer
 * @xdp_prog: an XDP program assigned to the interface
 * @xdpq: XDP TX queue assigned to the RX queue
 * @rxq_xdp_act: Logical OR of flags of XDP actions that require finalization
 *
 * Returns resulting XDP action.
 */
static unsigned int
idpf_run_xdp_zc(struct idpf_queue *rxbufq, struct xdp_buff *xdp,
		struct bpf_prog *xdp_prog, struct idpf_queue *xdpq,
		u32 *rxq_xdp_act)
{
	unsigned int xdp_act;
	int err;

	xdp_act = bpf_prog_run_xdp(xdp_prog, xdp);

	if (likely(xdp_act == XDP_REDIRECT)) {
		err = xdp_do_redirect(rxbufq->vport->netdev, xdp, xdp_prog);
		if (likely(!err)) {
			*rxq_xdp_act |= IDPF_XDP_ACT_FINALIZE_REDIR;
			return XDP_REDIRECT;
		}

		if (xsk_uses_need_wakeup(rxbufq->xsk_pool) && err == -ENOBUFS)
			*rxq_xdp_act |= IDPF_XDP_ACT_STOP_NOW;

		goto xdp_err;
	}

	switch (xdp_act) {
	case XDP_TX:
		err = idpf_xmit_xdp_tx_zc(xdp, xdpq);
		if (unlikely(err))
			goto xdp_err;

		*rxq_xdp_act |= IDPF_XDP_ACT_FINALIZE_TX;
		break;
	default:
		bpf_warn_invalid_xdp_action(rxbufq->vport->netdev, xdp_prog,
					    xdp_act);

		fallthrough;
	case XDP_ABORTED:
xdp_err:
		trace_xdp_exception(rxbufq->vport->netdev, xdp_prog, xdp_act);

		fallthrough;
	case XDP_DROP:
		xsk_buff_free(xdp);

		return XDP_DROP;
	}

	return xdp_act;
}

/**
 * idpf_clean_rx_irq_zc - consumes packets from the hardware queue
 * @rxq: AF_XDP Rx queue
 * @budget: NAPI budget
 *
 * Returns number of processed packets on success, remaining budget on failure.
 */
int idpf_clean_rx_irq_zc(struct idpf_queue *rxq, int budget)
{
	int total_rx_bytes = 0, total_rx_pkts = 0;
	struct idpf_queue *rx_bufq = NULL;
	u32 ntc = rxq->next_to_clean;
	struct bpf_prog *xdp_prog;
	struct idpf_queue *xdpq;
	bool failure = false;
	u32 rxq_xdp_act = 0;
	u32 to_refill;
	u16 buf_id;

	xdp_prog = rcu_dereference(rxq->xdp_prog);
	xdpq = rxq->xdpq;

	while (likely(total_rx_pkts < budget)) {
		struct virtchnl2_rx_flex_desc_adv_nic_3 *rx_desc;
		union virtchnl2_rx_desc *desc;
		unsigned int pkt_len = 0;
		struct xdp_buff *xdp;
		u16 gen_id;
		int bufq_id;
		u8 rxdid;

		desc = IDPF_RX_DESC(rxq, ntc);
		rx_desc = (struct virtchnl2_rx_flex_desc_adv_nic_3 *)desc;

		dma_rmb();

		/* if the descriptor isn't done, no work yet to do */
		gen_id = le16_to_cpu(rx_desc->pktlen_gen_bufq_id);
		gen_id = FIELD_GET(VIRTCHNL2_RX_FLEX_DESC_ADV_GEN_M, gen_id);

		if (test_bit(__IDPF_Q_GEN_CHK, rxq->flags) != gen_id)
			break;

		rxdid = FIELD_GET(VIRTCHNL2_RX_FLEX_DESC_ADV_RXDID_M,
				  rx_desc->rxdid_ucast);
		if (rxdid != VIRTCHNL2_RXDID_2_FLEX_SPLITQ) {
			IDPF_RX_BUMP_NTC(rxq, ntc);
			u64_stats_update_begin(&rxq->stats_sync);
			u64_stats_inc(&rxq->q_stats.rx.bad_descs);
			u64_stats_update_end(&rxq->stats_sync);
			continue;
		}

		pkt_len = le16_to_cpu(rx_desc->pktlen_gen_bufq_id);
		pkt_len = FIELD_GET(VIRTCHNL2_RX_FLEX_DESC_ADV_LEN_PBUF_M,
				    pkt_len);

		bufq_id = le16_to_cpu(rx_desc->pktlen_gen_bufq_id);
		bufq_id = FIELD_GET(VIRTCHNL2_RX_FLEX_DESC_ADV_BUFQ_ID_M,
				    bufq_id);

		rx_bufq = &rxq->rxq_grp->splitq.bufq_sets[bufq_id].bufq;
		buf_id = le16_to_cpu(rx_desc->buf_id);

		xdp = *idpf_get_xdp_buff(rx_bufq, buf_id);

		if (unlikely(!pkt_len)) {
			xsk_buff_free(xdp);
			goto next;
		}

		xsk_buff_set_size(xdp, pkt_len);
		xsk_buff_dma_sync_for_cpu(xdp, rxq->xsk_pool);

		idpf_run_xdp_zc(rx_bufq, xdp, xdp_prog, xdpq,
				&rxq_xdp_act);

		if (unlikely(rxq_xdp_act & IDPF_XDP_ACT_STOP_NOW)) {
			failure = true;
			break;
		}

		total_rx_bytes += pkt_len;
next:
		total_rx_pkts++;
		IDPF_RX_BUMP_NTC(rxq, ntc);
	}

	rxq->next_to_clean = ntc;
	idpf_finalize_xdp_rx(xdpq, rxq_xdp_act);

	u64_stats_update_begin(&rxq->stats_sync);
	u64_stats_add(&rxq->q_stats.rx.packets, total_rx_pkts);
	u64_stats_add(&rxq->q_stats.rx.bytes, total_rx_bytes);
	u64_stats_update_end(&rxq->stats_sync);

	if (!rx_bufq)
		goto skip_refill;

	IDPF_RX_BUMP_NTC(rx_bufq, buf_id);
	rx_bufq->next_to_clean = buf_id;

	to_refill = IDPF_DESC_UNUSED(rx_bufq);
	if (to_refill > IDPF_QUEUE_QUARTER(rx_bufq))
		failure |= !idpf_alloc_rx_buffers_zc(rx_bufq, to_refill);

skip_refill:
	if (xsk_uses_need_wakeup(rxq->xsk_pool)) {
		if (failure || rxq->next_to_clean == rxq->next_to_use)
			xsk_set_rx_need_wakeup(rxq->xsk_pool);
		else
			xsk_clear_rx_need_wakeup(rxq->xsk_pool);

		return total_rx_pkts;
	}

	return unlikely(failure) ? budget : total_rx_pkts;
}
