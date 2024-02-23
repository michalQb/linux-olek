// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2023 Intel Corporation */

#include "idpf.h"
#include "idpf_xdp.h"
#include "idpf_xsk.h"

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
 * __idpf_xdp_rxq_info_init - Setup XDP RxQ info for a given Rx queue
 * @rxq: Rx queue for which the resources are setup
 * @arg: flag indicating if the HW works in split queue mode
 *
 * Return: 0 on success, negative on failure.
 */
static int __idpf_xdp_rxq_info_init(struct idpf_queue *rxq, void *arg)
{
	const struct idpf_vport *vport = rxq->vport;
	int err;

	err = __xdp_rxq_info_reg(&rxq->xdp_rxq, vport->netdev, rxq->idx,
				 rxq->q_vector->napi.napi_id,
				 rxq->rx_buf_size);
	if (err)
		return err;

	if (test_bit(__IDPF_Q_XSK, rxq->flags)) {
		err = xdp_rxq_info_reg_mem_model(&rxq->xdp_rxq,
						 MEM_TYPE_XSK_BUFF_POOL,
						 NULL);
		xsk_pool_set_rxq_info(rxq->xsk_rx, &rxq->xdp_rxq);
	} else {
		const struct page_pool *pp;

		pp = arg ? rxq->rxq_grp->splitq.bufq_sets[0].bufq.pp : rxq->pp;
		xdp_rxq_info_attach_page_pool(&rxq->xdp_rxq, pp);
	}
	if (err)
		goto unreg;

	rxq->xdpqs = &vport->txqs[vport->xdp_txq_offset];
	rxq->num_xdp_txq = vport->num_xdp_txq;

	return 0;

unreg:
	xdp_rxq_info_unreg(&rxq->xdp_rxq);

	return err;
}

int idpf_xdp_rxq_info_init(struct idpf_queue *rxq)
{
	struct idpf_vport *vport = rxq->vport;
	void *arg;

	arg = (void *)(size_t)idpf_is_queue_model_split(vport->rxq_model);
	return __idpf_xdp_rxq_info_init(rxq, arg);
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

	return idpf_rxq_for_each(vport, __idpf_xdp_rxq_info_init, arg);
}

/**
 * __idpf_xdp_rxq_info_deinit - Deinit XDP RxQ info for a given Rx queue
 * @rxq: Rx queue for which the resources are destroyed
 */
static int __idpf_xdp_rxq_info_deinit(struct idpf_queue *rxq, void *arg)
{
	rxq->xdpqs = NULL;
	rxq->num_xdp_txq = 0;

	if (!test_bit(__IDPF_Q_XSK, rxq->flags))
		xdp_rxq_info_detach_mem_model(&rxq->xdp_rxq);

	xdp_rxq_info_unreg(&rxq->xdp_rxq);

	return 0;
}

int idpf_xdp_rxq_info_deinit(struct idpf_queue *rxq)
{
	return __idpf_xdp_rxq_info_deinit(rxq, NULL);
}

/**
 * idpf_xdp_rxq_info_deinit_all - deinit RxQ info for all Rx queues in vport
 * @vport: vport to setup the info
 */
void idpf_xdp_rxq_info_deinit_all(const struct idpf_vport *vport)
{
	idpf_rxq_for_each(vport, __idpf_xdp_rxq_info_deinit, NULL);
}

static int idpf_xdp_rxq_assign_prog(struct idpf_queue *rxq, void *arg)
{
	struct mutex *lock = &rxq->vport->adapter->vport_ctrl_lock;
	struct bpf_prog *prog = arg;
	struct bpf_prog *old;

	if (prog)
		bpf_prog_inc(prog);

	old = rcu_replace_pointer(rxq->xdp_prog, prog, lockdep_is_held(lock));
	if (old)
		bpf_prog_put(old);

	return 0;
}

/**
 * idpf_copy_xdp_prog_to_qs - set pointers to xdp program for each Rx queue
 * @vport: vport to setup XDP for
 * @xdp_prog: XDP program that should be copied to all Rx queues
 */
void idpf_copy_xdp_prog_to_qs(const struct idpf_vport *vport,
			      struct bpf_prog *xdp_prog)
{
	idpf_rxq_for_each(vport, idpf_xdp_rxq_assign_prog, xdp_prog);
}

static int idpf_rx_napi_schedule(struct idpf_queue *rxq, void *arg)
{
	if (test_bit(__IDPF_Q_XSK, rxq->flags))
		napi_schedule(&rxq->q_vector->napi);

	return 0;
}

/**
 * idpf_vport_rx_napi_schedule - Schedule napi on RX queues from vport
 * @vport: vport to schedule napi on
 */
static void idpf_vport_rx_napi_schedule(const struct idpf_vport *vport)
{
	idpf_rxq_for_each(vport, idpf_rx_napi_schedule, NULL);
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

/**
 * idpf_clean_xdp_irq - Reclaim a batch of TX resources from completed XDP_TX
 * @xdpq: XDP Tx queue
 *
 * Returns number of cleaned descriptors.
 */
static u32 idpf_clean_xdp_irq(struct idpf_queue *xdpq)
{
	struct idpf_queue *complq = xdpq->txq_grp->complq, *txq;
	struct idpf_splitq_4b_tx_compl_desc *last_rs_desc;
	struct libie_sq_onstack_stats ss = { };
	int complq_budget = complq->desc_count;
	u32 tx_ntc = xdpq->next_to_clean;
	u32 ntc = complq->next_to_clean;
	u32 cnt = xdpq->desc_count;
	u32 done_frames = 0, i = 0;
	struct xdp_frame_bulk bq;
	int head = tx_ntc;
	bool gen_flag;

	last_rs_desc = &complq->comp_4b[ntc];
	gen_flag = test_bit(__IDPF_Q_GEN_CHK, complq->flags);

	do {
		int ctype = idpf_parse_compl_desc(last_rs_desc, complq,
						  &txq, gen_flag);
		if (likely(ctype == IDPF_TXD_COMPLT_RS)) {
			head = le16_to_cpu(last_rs_desc->q_head_compl_tag.q_head);
			goto fetch_next_desc;
		}

		switch (ctype) {
		case -ENODATA:
			goto exit_xdp_irq;
		case -EINVAL:
			break;
		default:
			dev_err(&xdpq->vport->adapter->pdev->dev,
				"Unsupported completion type for XDP\n");
			break;
		}

fetch_next_desc:
		last_rs_desc++;
		ntc++;
		if (unlikely(ntc == complq->desc_count)) {
			ntc = 0;
			last_rs_desc = &complq->comp_4b[0];
			gen_flag = !gen_flag;
			change_bit(__IDPF_Q_GEN_CHK, complq->flags);
		}
		prefetch(last_rs_desc);
		complq_budget--;
	} while (likely(complq_budget));

exit_xdp_irq:
	complq->next_to_clean = ntc;
	done_frames = head >= tx_ntc ? head - tx_ntc :
				       head + cnt - tx_ntc;

	xdp_frame_bulk_init(&bq);

	for (i = 0; i < done_frames; i++) {
		libie_xdp_complete_tx_buf(&xdpq->tx_buf[tx_ntc], xdpq->dev,
					  true, &bq, &xdpq->xdp_tx_active,
					  &ss);

		if (unlikely(++tx_ntc == cnt))
			tx_ntc = 0;
	}

	xdp_flush_frame_bulk(&bq);
	xdpq->next_to_clean = tx_ntc;

	libie_sq_napi_stats_add((struct libie_sq_stats *)&xdpq->q_stats.tx,
				&ss);

	return i;
}

static u32 idpf_xdp_tx_prep(void *_xdpq, struct libie_xdp_tx_queue *sq)
{
	struct idpf_queue *xdpq = _xdpq;
	u32 free;

	libie_xdp_sq_lock(&xdpq->xdp_lock);

	free = IDPF_DESC_UNUSED(xdpq);
	if (unlikely(free < IDPF_QUEUE_QUARTER(xdpq)))
		free += idpf_clean_xdp_irq(xdpq);

	*sq = (struct libie_xdp_tx_queue){
		.tx_buf		= xdpq->tx_buf,
		.desc_ring	= xdpq->desc_ring,
		.desc_count	= xdpq->desc_count,
		.xdp_lock	= &xdpq->xdp_lock,
		.next_to_use	= &xdpq->next_to_use,
		.xdp_tx_active	= &xdpq->xdp_tx_active,
	};

	return free;
}

static void idpf_xdp_tx_xmit(struct libie_xdp_tx_desc desc,
			     const struct libie_xdp_tx_queue *sq)
{
	union idpf_tx_flex_desc *tx_desc = sq->desc_ring;
	struct idpf_tx_splitq_params tx_params = {
		.dtype		= IDPF_TX_DESC_DTYPE_FLEX_L2TAG1_L2TAG2,
		.eop_cmd	= IDPF_TX_DESC_CMD_EOP,
	};

	tx_desc = &tx_desc[sq->cached_ntu];
	tx_desc->q.buf_addr = cpu_to_le64(desc.addr);

	idpf_tx_splitq_build_desc(tx_desc, &tx_params,
				  tx_params.eop_cmd | tx_params.offload.td_cmd,
				  desc.len);
}

static bool idpf_xdp_tx_flush_bulk(struct libie_xdp_tx_bulk *bq)
{
	return libie_xdp_tx_flush_bulk(bq, idpf_xdp_tx_prep, idpf_xdp_tx_xmit);
}

void __idpf_xdp_finalize_rx(struct libie_xdp_tx_bulk *bq)
{
	libie_xdp_finalize_rx(bq, idpf_xdp_tx_flush_bulk,
			      idpf_xdp_tx_finalize);
}

bool __idpf_xdp_run_prog(struct xdp_buff *xdp, struct libie_xdp_tx_bulk *bq)
{
	return libie_xdp_run_prog(xdp, bq, idpf_xdp_tx_flush_bulk);
}

/**
 * idpf_xdp_xmit - submit packets to xdp ring for transmission
 * @dev: netdev
 * @n: number of xdp frames to be transmitted
 * @frames: xdp frames to be transmitted
 * @flags: transmit flags
 *
 * Returns number of frames successfully sent. Frames that fail are
 * free'ed via XDP return API.
 * For error cases, a negative errno code is returned and no-frames
 * are transmitted (caller must handle freeing frames).
 */
int idpf_xdp_xmit(struct net_device *dev, int n, struct xdp_frame **frames,
		  u32 flags)
{
	struct idpf_netdev_priv *np = netdev_priv(dev);
	struct idpf_vport *vport = np->vport;

	if (unlikely(!netif_carrier_ok(dev) || !vport->link_up))
		return -ENETDOWN;
	if (unlikely(!idpf_xdp_is_prog_ena(vport)))
		return -ENXIO;

	return libie_xdp_xmit_do_bulk(dev, n, frames, flags,
				      &vport->txqs[vport->xdp_txq_offset],
				      vport->num_xdp_txq, idpf_xdp_tx_prep,
				      idpf_xdp_tx_xmit, idpf_xdp_tx_finalize);
}

/**
 * idpf_xdp_reconfig_queues - reconfigure queues after the XDP setup
 * @vport: vport to load or unload XDP for
 */
static int idpf_xdp_reconfig_queues(struct idpf_vport *vport)
{
	int err;

	err = idpf_vport_adjust_qs(vport);
	if (err) {
		netdev_err(vport->netdev,
			   "Could not adjust queue number for XDP\n");
		return err;
	}
	idpf_vport_calc_num_q_desc(vport);

	err = idpf_vport_queues_alloc(vport);
	if (err) {
		netdev_err(vport->netdev,
			   "Could not allocate queues for XDP\n");
		return err;
	}

	err = idpf_send_add_queues_msg(vport, vport->num_txq,
				       vport->num_complq,
				       vport->num_rxq, vport->num_bufq);
	if (err) {
		netdev_err(vport->netdev,
			   "Could not add queues for XDP, VC message sent failed\n");
		return err;
	}

	idpf_vport_alloc_vec_indexes(vport);

	return 0;
}

/**
 * idpf_assign_bpf_prog - Assign a given BPF program to vport
 * @current_prog: pointer to XDP program in user config data
 * @prog: BPF program to be assigned to vport
 */
static void idpf_assign_bpf_prog(struct bpf_prog **current_prog,
				 struct bpf_prog *prog)
{
	struct bpf_prog *old_prog = *current_prog;

	*current_prog = prog;
	if (old_prog)
		bpf_prog_put(old_prog);
}

/**
 * idpf_xdp_setup_prog - Add or remove XDP eBPF program
 * @vport: vport to setup XDP for
 * @prog: XDP program
 * @extack: netlink extended ack
 */
static int
idpf_xdp_setup_prog(struct idpf_vport *vport, struct bpf_prog *prog,
		    struct netlink_ext_ack *extack)
{
	struct idpf_netdev_priv *np = netdev_priv(vport->netdev);
	bool needs_reconfig, vport_is_up;
	struct bpf_prog **current_prog;
	u16 idx = vport->idx;
	int err;

	vport_is_up = np->state == __IDPF_VPORT_UP;

	current_prog = &vport->adapter->vport_config[idx]->user_config.xdp_prog;
	needs_reconfig = !!(*current_prog) != !!prog;

	if (!needs_reconfig) {
		idpf_copy_xdp_prog_to_qs(vport, prog);
		idpf_assign_bpf_prog(current_prog, prog);

		return 0;
	}

	if (!vport_is_up) {
		idpf_send_delete_queues_msg(vport);
	} else {
		set_bit(IDPF_VPORT_DEL_QUEUES, vport->flags);
		idpf_vport_stop(vport);
	}

	idpf_deinit_rss(vport);

	idpf_assign_bpf_prog(current_prog, prog);

	err = idpf_xdp_reconfig_queues(vport);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "Could not reconfigure the queues after XDP setup\n");
		return err;
	}

	if (prog)
		xdp_features_set_redirect_target(vport->netdev, false);
	else
		xdp_features_clear_redirect_target(vport->netdev);

	if (vport_is_up) {
		err = idpf_vport_open(vport, false);
		if (err) {
			NL_SET_ERR_MSG_MOD(extack, "Could not re-open the vport after XDP setup\n");
			return err;
		}

		if (prog)
			idpf_vport_rx_napi_schedule(vport);
	}

	return 0;
}

/**
 * idpf_xdp - implements XDP handler
 * @netdev: netdevice
 * @xdp: XDP command
 */
int idpf_xdp(struct net_device *netdev, struct netdev_bpf *xdp)
{
	struct idpf_vport *vport;
	int err;

	idpf_vport_ctrl_lock(netdev);
	vport = idpf_netdev_to_vport(netdev);

	switch (xdp->command) {
	case XDP_SETUP_PROG:
		err = idpf_xdp_setup_prog(vport, xdp->prog, xdp->extack);
		break;
	case XDP_SETUP_XSK_POOL:
		err = idpf_xsk_pool_setup(vport, xdp->xsk.pool,
					  xdp->xsk.queue_id);
		break;
	default:
		err = -EINVAL;
	}

	idpf_vport_ctrl_unlock(netdev);
	return err;
}
