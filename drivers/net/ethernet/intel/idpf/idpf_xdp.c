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

	if (vport_is_up) {
		err = idpf_vport_open(vport, false);
		if (err) {
			NL_SET_ERR_MSG_MOD(extack, "Could not re-open the vport after XDP setup\n");
			return err;
		}
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
	default:
		err = -EINVAL;
	}

	idpf_vport_ctrl_unlock(netdev);
	return err;
}
