// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2023 Intel Corporation */

#include "idpf.h"

/**
 * idpf_recv_event_msg - Receive virtchnl event message
 * @vport: virtual port structure
 * @ctlq_msg: message to copy from
 *
 * Receive virtchnl event message
 */
static void idpf_recv_event_msg(struct idpf_vport *vport,
				struct idpf_ctlq_msg *ctlq_msg)
{
	struct idpf_netdev_priv *np = netdev_priv(vport->netdev);
	struct virtchnl2_event *v2e;
	bool link_status;
	u32 event;

	v2e = (struct virtchnl2_event *)ctlq_msg->ctx.indirect.payload->va;
	event = le32_to_cpu(v2e->event);

	switch (event) {
	case VIRTCHNL2_EVENT_LINK_CHANGE:
		vport->link_speed_mbps = le32_to_cpu(v2e->link_speed);
		link_status = v2e->link_status;

		if (vport->link_up == link_status)
			break;

		vport->link_up = link_status;
		if (np->state == __IDPF_VPORT_UP) {
			if (vport->link_up) {
				netif_carrier_on(vport->netdev);
				netif_tx_start_all_queues(vport->netdev);
			} else {
				netif_tx_stop_all_queues(vport->netdev);
				netif_carrier_off(vport->netdev);
			}
		}
		break;
	default:
		dev_err(&vport->adapter->pdev->dev,
			"Unknown event %d from PF\n", event);
		break;
	}
}

/**
 * idpf_mb_clean - Reclaim the send mailbox queue entries
 * @adapter: Driver specific private structure
 *
 * Reclaim the send mailbox queue entries to be used to send further messages
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_mb_clean(struct idpf_adapter *adapter)
{
	u16 i, num_q_msg = IDPF_DFLT_MBX_Q_LEN;
	struct idpf_ctlq_msg **q_msg;
	struct idpf_dma_mem *dma_mem;
	int err;

	q_msg = kcalloc(num_q_msg, sizeof(struct idpf_ctlq_msg *), GFP_ATOMIC);
	if (!q_msg)
		return -ENOMEM;

	err = idpf_ctlq_clean_sq(adapter->hw.asq, &num_q_msg, q_msg);
	if (err)
		goto err_kfree;

	for (i = 0; i < num_q_msg; i++) {
		if (!q_msg[i])
			continue;
		dma_mem = q_msg[i]->ctx.indirect.payload;
		if (dma_mem)
			dma_free_coherent(&adapter->pdev->dev, dma_mem->size,
					  dma_mem->va, dma_mem->pa);
		kfree(q_msg[i]);
		kfree(dma_mem);
	}

err_kfree:
	kfree(q_msg);

	return err;
}

/**
 * idpf_send_mb_msg - Send message over mailbox
 * @adapter: Driver specific private structure
 * @op: virtchnl opcode
 * @msg_size: size of the payload
 * @msg: pointer to buffer holding the payload
 *
 * Will prepare the control queue message and initiates the send api
 *
 * Returns 0 on success, negative on failure
 */
int idpf_send_mb_msg(struct idpf_adapter *adapter, u32 op,
		     u16 msg_size, u8 *msg)
{
	struct idpf_ctlq_msg *ctlq_msg;
	struct idpf_dma_mem *dma_mem;
	int err;

	/* If we are here and a reset is detected nothing much can be
	 * done. This thread should silently abort and expected to
	 * be corrected with a new run either by user or driver
	 * flows after reset
	 */
	if (idpf_is_reset_detected(adapter))
		return 0;

	err = idpf_mb_clean(adapter);
	if (err)
		return err;

	ctlq_msg = kzalloc(sizeof(*ctlq_msg), GFP_ATOMIC);
	if (!ctlq_msg)
		return -ENOMEM;

	dma_mem = kzalloc(sizeof(*dma_mem), GFP_ATOMIC);
	if (!dma_mem) {
		err = -ENOMEM;
		goto dma_mem_error;
	}

	ctlq_msg->opcode = idpf_mbq_opc_send_msg_to_cp;
	ctlq_msg->func_id = 0;
	ctlq_msg->data_len = msg_size;
	ctlq_msg->cookie.mbx.chnl_opcode = op;
	ctlq_msg->cookie.mbx.chnl_retval = 0;
	dma_mem->size = IDPF_CTLQ_MAX_BUF_LEN;
	dma_mem->va = dma_alloc_coherent(&adapter->pdev->dev, dma_mem->size,
					 &dma_mem->pa, GFP_ATOMIC);
	if (!dma_mem->va) {
		err = -ENOMEM;
		goto dma_alloc_error;
	}
	memcpy(dma_mem->va, msg, msg_size);
	ctlq_msg->ctx.indirect.payload = dma_mem;

	err = idpf_ctlq_send(&adapter->hw, adapter->hw.asq, 1, ctlq_msg);
	if (err)
		goto send_error;

	return 0;

send_error:
	dma_free_coherent(&adapter->pdev->dev, dma_mem->size, dma_mem->va,
			  dma_mem->pa);
dma_alloc_error:
	kfree(dma_mem);
dma_mem_error:
	kfree(ctlq_msg);

	return err;
}

/**
 * idpf_find_vport - Find vport pointer from control queue message
 * @adapter: driver specific private structure
 * @vport: address of vport pointer to copy the vport from adapters vport list
 * @ctlq_msg: control queue message
 *
 * Return 0 on success, error value on failure. Also this function does check
 * for the opcodes which expect to receive payload and return error value if
 * it is not the case.
 */
static int idpf_find_vport(struct idpf_adapter *adapter,
			   struct idpf_vport **vport,
			   struct idpf_ctlq_msg *ctlq_msg)
{
	bool no_op = false, vid_found = false;
	int i, err = 0;
	char *vc_msg;
	u32 v_id;

	vc_msg = kcalloc(IDPF_CTLQ_MAX_BUF_LEN, sizeof(char), GFP_KERNEL);
	if (!vc_msg)
		return -ENOMEM;

	if (ctlq_msg->data_len) {
		size_t payload_size = ctlq_msg->ctx.indirect.payload->size;

		if (!payload_size) {
			dev_err(&adapter->pdev->dev, "Failed to receive payload buffer\n");
			kfree(vc_msg);

			return -EINVAL;
		}

		memcpy(vc_msg, ctlq_msg->ctx.indirect.payload->va,
		       min_t(size_t, payload_size, IDPF_CTLQ_MAX_BUF_LEN));
	}

	switch (ctlq_msg->cookie.mbx.chnl_opcode) {
	case VIRTCHNL2_OP_VERSION:
	case VIRTCHNL2_OP_GET_CAPS:
	case VIRTCHNL2_OP_CREATE_VPORT:
	case VIRTCHNL2_OP_SET_SRIOV_VFS:
	case VIRTCHNL2_OP_ALLOC_VECTORS:
	case VIRTCHNL2_OP_DEALLOC_VECTORS:
	case VIRTCHNL2_OP_GET_PTYPE_INFO:
		goto free_vc_msg;
	case VIRTCHNL2_OP_ENABLE_VPORT:
	case VIRTCHNL2_OP_DISABLE_VPORT:
	case VIRTCHNL2_OP_DESTROY_VPORT:
		v_id = le32_to_cpu(((struct virtchnl2_vport *)vc_msg)->vport_id);
		break;
	case VIRTCHNL2_OP_CONFIG_TX_QUEUES:
		v_id = le32_to_cpu(((struct virtchnl2_config_tx_queues *)vc_msg)->vport_id);
		break;
	case VIRTCHNL2_OP_CONFIG_RX_QUEUES:
		v_id = le32_to_cpu(((struct virtchnl2_config_rx_queues *)vc_msg)->vport_id);
		break;
	case VIRTCHNL2_OP_ENABLE_QUEUES:
	case VIRTCHNL2_OP_DISABLE_QUEUES:
	case VIRTCHNL2_OP_DEL_QUEUES:
		v_id = le32_to_cpu(((struct virtchnl2_del_ena_dis_queues *)vc_msg)->vport_id);
		break;
	case VIRTCHNL2_OP_ADD_QUEUES:
		v_id = le32_to_cpu(((struct virtchnl2_add_queues *)vc_msg)->vport_id);
		break;
	case VIRTCHNL2_OP_MAP_QUEUE_VECTOR:
	case VIRTCHNL2_OP_UNMAP_QUEUE_VECTOR:
		v_id = le32_to_cpu(((struct virtchnl2_queue_vector_maps *)vc_msg)->vport_id);
		break;
	case VIRTCHNL2_OP_GET_STATS:
		v_id = le32_to_cpu(((struct virtchnl2_vport_stats *)vc_msg)->vport_id);
		break;
	case VIRTCHNL2_OP_GET_RSS_LUT:
	case VIRTCHNL2_OP_SET_RSS_LUT:
		v_id = le32_to_cpu(((struct virtchnl2_rss_lut *)vc_msg)->vport_id);
		break;
	case VIRTCHNL2_OP_GET_RSS_KEY:
	case VIRTCHNL2_OP_SET_RSS_KEY:
		v_id = le32_to_cpu(((struct virtchnl2_rss_key *)vc_msg)->vport_id);
		break;
	case VIRTCHNL2_OP_EVENT:
		v_id = le32_to_cpu(((struct virtchnl2_event *)vc_msg)->vport_id);
		break;
	case VIRTCHNL2_OP_LOOPBACK:
		v_id = le32_to_cpu(((struct virtchnl2_loopback *)vc_msg)->vport_id);
		break;
	case VIRTCHNL2_OP_CONFIG_PROMISCUOUS_MODE:
		v_id = le32_to_cpu(((struct virtchnl2_promisc_info *)vc_msg)->vport_id);
		break;
	case VIRTCHNL2_OP_ADD_MAC_ADDR:
	case VIRTCHNL2_OP_DEL_MAC_ADDR:
		v_id = le32_to_cpu(((struct virtchnl2_mac_addr_list *)vc_msg)->vport_id);
		break;
	default:
		no_op = true;
		break;
	}

	if (no_op)
		goto free_vc_msg;

	for (i = 0; i < idpf_get_max_vports(adapter); i++) {
		if (adapter->vport_ids[i] == v_id) {
			vid_found = true;
			break;
		}
	}

	if (vid_found)
		*vport = adapter->vports[i];
	else
		err = -EINVAL;

free_vc_msg:
	kfree(vc_msg);

	return err;
}

/**
 * idpf_copy_data_to_vc_buf - Copy the virtchnl response data into the buffer.
 * @adapter: driver specific private structure
 * @vport: virtual port structure
 * @ctlq_msg: msg to copy from
 * @err_enum: err bit to set on error
 *
 * Copies the payload from ctlq_msg into virtchnl buffer. Returns 0 on success,
 * negative on failure.
 */
static int idpf_copy_data_to_vc_buf(struct idpf_adapter *adapter,
				    struct idpf_vport *vport,
				    struct idpf_ctlq_msg *ctlq_msg,
				    enum idpf_vport_vc_state err_enum)
{
	if (ctlq_msg->cookie.mbx.chnl_retval) {
		if (vport)
			set_bit(err_enum, vport->vc_state);
		else
			set_bit(err_enum, adapter->vc_state);

		return -EINVAL;
	}

	if (vport)
		memcpy(vport->vc_msg, ctlq_msg->ctx.indirect.payload->va,
		       min_t(int, ctlq_msg->ctx.indirect.payload->size,
			     IDPF_CTLQ_MAX_BUF_LEN));
	else
		memcpy(adapter->vc_msg, ctlq_msg->ctx.indirect.payload->va,
		       min_t(int, ctlq_msg->ctx.indirect.payload->size,
			     IDPF_CTLQ_MAX_BUF_LEN));

	return 0;
}

/**
 * idpf_recv_vchnl_op - helper function with common logic when handling the
 * reception of VIRTCHNL OPs.
 * @adapter: driver specific private structure
 * @vport: virtual port structure
 * @ctlq_msg: msg to copy from
 * @state: state bit used on timeout check
 * @err_state: err bit to set on error
 */
static void idpf_recv_vchnl_op(struct idpf_adapter *adapter,
			       struct idpf_vport *vport,
			       struct idpf_ctlq_msg *ctlq_msg,
			       enum idpf_vport_vc_state state,
			       enum idpf_vport_vc_state err_state)
{
	wait_queue_head_t *vchnl_wq;
	int err;

	if (vport)
		vchnl_wq = &vport->vchnl_wq;
	else
		vchnl_wq = &adapter->vchnl_wq;

	err = idpf_copy_data_to_vc_buf(adapter, vport, ctlq_msg, err_state);
	if (wq_has_sleeper(vchnl_wq)) {
		if (vport)
			set_bit(state, vport->vc_state);
		else
			set_bit(state, adapter->vc_state);

		wake_up(vchnl_wq);
	} else {
		if (!err) {
			dev_warn(&adapter->pdev->dev, "opcode %d received without waiting thread\n",
				 ctlq_msg->cookie.mbx.chnl_opcode);
		} else {
			/* Clear the errors since there is no sleeper to pass
			 * them on
			 */
			if (vport)
				clear_bit(err_state, vport->vc_state);
			else
				clear_bit(err_state, adapter->vc_state);
		}
	}
}

/**
 * idpf_recv_mb_msg - Receive message over mailbox
 * @adapter: Driver specific private structure
 * @op: virtchannel operation code
 * @msg: Received message holding buffer
 * @msg_size: message size
 *
 * Will receive control queue message and posts the receive buffer. Returns 0
 * on success and negative on failure.
 */
int idpf_recv_mb_msg(struct idpf_adapter *adapter, u32 op,
		     void *msg, int msg_size)
{
	struct idpf_vport *vport = NULL;
	struct idpf_ctlq_msg ctlq_msg;
	struct idpf_dma_mem *dma_mem;
	bool work_done = false;
	int num_retry = 2000;
	u16 num_q_msg;
	int err;

	while (1) {
		struct idpf_vport_config *vport_config;
		int payload_size = 0;

		/* Try to get one message */
		num_q_msg = 1;
		dma_mem = NULL;
		err = idpf_ctlq_recv(adapter->hw.arq, &num_q_msg, &ctlq_msg);
		/* If no message then decide if we have to retry based on
		 * opcode
		 */
		if (err || !num_q_msg) {
			/* Increasing num_retry to consider the delayed
			 * responses because of large number of VF's mailbox
			 * messages. If the mailbox message is received from
			 * the other side, we come out of the sleep cycle
			 * immediately else we wait for more time.
			 */
			if (!op || !num_retry--)
				break;
			if (test_bit(IDPF_REMOVE_IN_PROG, adapter->flags)) {
				err = -EIO;
				break;
			}
			msleep(20);
			continue;
		}

		/* If we are here a message is received. Check if we are looking
		 * for a specific message based on opcode. If it is different
		 * ignore and post buffers
		 */
		if (op && ctlq_msg.cookie.mbx.chnl_opcode != op)
			goto post_buffs;

		err = idpf_find_vport(adapter, &vport, &ctlq_msg);
		if (err)
			goto post_buffs;

		if (ctlq_msg.data_len)
			payload_size = ctlq_msg.ctx.indirect.payload->size;

		/* All conditions are met. Either a message requested is
		 * received or we received a message to be processed
		 */
		switch (ctlq_msg.cookie.mbx.chnl_opcode) {
		case VIRTCHNL2_OP_VERSION:
		case VIRTCHNL2_OP_GET_CAPS:
			if (ctlq_msg.cookie.mbx.chnl_retval) {
				dev_err(&adapter->pdev->dev, "Failure initializing, vc op: %u retval: %u\n",
					ctlq_msg.cookie.mbx.chnl_opcode,
					ctlq_msg.cookie.mbx.chnl_retval);
				err = -EBADMSG;
			} else if (msg) {
				memcpy(msg, ctlq_msg.ctx.indirect.payload->va,
				       min_t(int, payload_size, msg_size));
			}
			work_done = true;
			break;
		case VIRTCHNL2_OP_CREATE_VPORT:
			idpf_recv_vchnl_op(adapter, NULL, &ctlq_msg,
					   IDPF_VC_CREATE_VPORT,
					   IDPF_VC_CREATE_VPORT_ERR);
			break;
		case VIRTCHNL2_OP_ENABLE_VPORT:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_ENA_VPORT,
					   IDPF_VC_ENA_VPORT_ERR);
			break;
		case VIRTCHNL2_OP_DISABLE_VPORT:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_DIS_VPORT,
					   IDPF_VC_DIS_VPORT_ERR);
			break;
		case VIRTCHNL2_OP_DESTROY_VPORT:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_DESTROY_VPORT,
					   IDPF_VC_DESTROY_VPORT_ERR);
			break;
		case VIRTCHNL2_OP_CONFIG_TX_QUEUES:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_CONFIG_TXQ,
					   IDPF_VC_CONFIG_TXQ_ERR);
			break;
		case VIRTCHNL2_OP_CONFIG_RX_QUEUES:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_CONFIG_RXQ,
					   IDPF_VC_CONFIG_RXQ_ERR);
			break;
		case VIRTCHNL2_OP_ENABLE_QUEUES:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_ENA_QUEUES,
					   IDPF_VC_ENA_QUEUES_ERR);
			break;
		case VIRTCHNL2_OP_DISABLE_QUEUES:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_DIS_QUEUES,
					   IDPF_VC_DIS_QUEUES_ERR);
			break;
		case VIRTCHNL2_OP_ADD_QUEUES:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_ADD_QUEUES,
					   IDPF_VC_ADD_QUEUES_ERR);
			break;
		case VIRTCHNL2_OP_DEL_QUEUES:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_DEL_QUEUES,
					   IDPF_VC_DEL_QUEUES_ERR);
			break;
		case VIRTCHNL2_OP_MAP_QUEUE_VECTOR:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_MAP_IRQ,
					   IDPF_VC_MAP_IRQ_ERR);
			break;
		case VIRTCHNL2_OP_UNMAP_QUEUE_VECTOR:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_UNMAP_IRQ,
					   IDPF_VC_UNMAP_IRQ_ERR);
			break;
		case VIRTCHNL2_OP_GET_STATS:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_GET_STATS,
					   IDPF_VC_GET_STATS_ERR);
			break;
		case VIRTCHNL2_OP_GET_RSS_LUT:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_GET_RSS_LUT,
					   IDPF_VC_GET_RSS_LUT_ERR);
			break;
		case VIRTCHNL2_OP_SET_RSS_LUT:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_SET_RSS_LUT,
					   IDPF_VC_SET_RSS_LUT_ERR);
			break;
		case VIRTCHNL2_OP_GET_RSS_KEY:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_GET_RSS_KEY,
					   IDPF_VC_GET_RSS_KEY_ERR);
			break;
		case VIRTCHNL2_OP_SET_RSS_KEY:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_SET_RSS_KEY,
					   IDPF_VC_SET_RSS_KEY_ERR);
			break;
		case VIRTCHNL2_OP_SET_SRIOV_VFS:
			idpf_recv_vchnl_op(adapter, NULL, &ctlq_msg,
					   IDPF_VC_SET_SRIOV_VFS,
					   IDPF_VC_SET_SRIOV_VFS_ERR);
			break;
		case VIRTCHNL2_OP_ALLOC_VECTORS:
			idpf_recv_vchnl_op(adapter, NULL, &ctlq_msg,
					   IDPF_VC_ALLOC_VECTORS,
					   IDPF_VC_ALLOC_VECTORS_ERR);
			break;
		case VIRTCHNL2_OP_DEALLOC_VECTORS:
			idpf_recv_vchnl_op(adapter, NULL, &ctlq_msg,
					   IDPF_VC_DEALLOC_VECTORS,
					   IDPF_VC_DEALLOC_VECTORS_ERR);
			break;
		case VIRTCHNL2_OP_GET_PTYPE_INFO:
			idpf_recv_vchnl_op(adapter, NULL, &ctlq_msg,
					   IDPF_VC_GET_PTYPE_INFO,
					   IDPF_VC_GET_PTYPE_INFO_ERR);
			break;
		case VIRTCHNL2_OP_LOOPBACK:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_LOOPBACK_STATE,
					   IDPF_VC_LOOPBACK_STATE_ERR);
			break;
		case VIRTCHNL2_OP_CONFIG_PROMISCUOUS_MODE:
			/* This message can only be sent asynchronously. As
			 * such we'll have lost the context in which it was
			 * called and thus can only really report if it looks
			 * like an error occurred. Don't bother setting ERR bit
			 * or waking chnl_wq since no work queue will be waiting
			 * to read the message.
			 */
			if (ctlq_msg.cookie.mbx.chnl_retval) {
				dev_err(&adapter->pdev->dev, "Failed to set promiscuous mode: %d\n",
					ctlq_msg.cookie.mbx.chnl_retval);
			}
			break;
		case VIRTCHNL2_OP_ADD_MAC_ADDR:
			vport_config = adapter->vport_config[vport->idx];
			if (test_and_clear_bit(IDPF_VPORT_ADD_MAC_REQ,
					       vport_config->flags)) {
				/* Message was sent asynchronously. We don't
				 * normally print errors here, instead
				 * prefer to handle errors in the function
				 * calling wait_for_event. However, if
				 * asynchronous, the context in which the
				 * message was sent is lost. We can't really do
				 * anything about at it this point, but we
				 * should at a minimum indicate that it looks
				 * like something went wrong. Also don't bother
				 * setting ERR bit or waking vchnl_wq since no
				 * one will be waiting to read the async
				 * message.
				 */
				if (ctlq_msg.cookie.mbx.chnl_retval)
					dev_err(&adapter->pdev->dev, "Failed to add MAC address: %d\n",
						ctlq_msg.cookie.mbx.chnl_retval);
				break;
			}
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_ADD_MAC_ADDR,
					   IDPF_VC_ADD_MAC_ADDR_ERR);
			break;
		case VIRTCHNL2_OP_DEL_MAC_ADDR:
			vport_config = adapter->vport_config[vport->idx];
			if (test_and_clear_bit(IDPF_VPORT_DEL_MAC_REQ,
					       vport_config->flags)) {
				/* Message was sent asynchronously like the
				 * VIRTCHNL2_OP_ADD_MAC_ADDR
				 */
				if (ctlq_msg.cookie.mbx.chnl_retval)
					dev_err(&adapter->pdev->dev, "Failed to delete MAC address: %d\n",
						ctlq_msg.cookie.mbx.chnl_retval);
				break;
			}
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_DEL_MAC_ADDR,
					   IDPF_VC_DEL_MAC_ADDR_ERR);
			break;
		case VIRTCHNL2_OP_EVENT:
			idpf_recv_event_msg(vport, &ctlq_msg);
			break;
		default:
			dev_warn(&adapter->pdev->dev,
				 "Unhandled virtchnl response %d\n",
				 ctlq_msg.cookie.mbx.chnl_opcode);
			break;
		}

post_buffs:
		if (ctlq_msg.data_len)
			dma_mem = ctlq_msg.ctx.indirect.payload;
		else
			num_q_msg = 0;

		err = idpf_ctlq_post_rx_buffs(&adapter->hw, adapter->hw.arq,
					      &num_q_msg, &dma_mem);
		/* If post failed clear the only buffer we supplied */
		if (err && dma_mem)
			dma_free_coherent(&adapter->pdev->dev, dma_mem->size,
					  dma_mem->va, dma_mem->pa);

		/* Applies only if we are looking for a specific opcode */
		if (work_done)
			break;
	}

	return err;
}

/**
 * __idpf_wait_for_event - wrapper function for wait on virtchannel response
 * @adapter: Driver private data structure
 * @vport: virtual port structure
 * @state: check on state upon timeout
 * @err_check: check if this specific error bit is set
 * @timeout: Max time to wait
 *
 * Checks if state is set upon expiry of timeout.  Returns 0 on success,
 * negative on failure.
 */
static int __idpf_wait_for_event(struct idpf_adapter *adapter,
				 struct idpf_vport *vport,
				 enum idpf_vport_vc_state state,
				 enum idpf_vport_vc_state err_check,
				 int timeout)
{
	int time_to_wait, num_waits;
	wait_queue_head_t *vchnl_wq;
	unsigned long *vc_state;

	time_to_wait = ((timeout <= IDPF_MAX_WAIT) ? timeout : IDPF_MAX_WAIT);
	num_waits = ((timeout <= IDPF_MAX_WAIT) ? 1 : timeout / IDPF_MAX_WAIT);

	if (vport) {
		vchnl_wq = &vport->vchnl_wq;
		vc_state = vport->vc_state;
	} else {
		vchnl_wq = &adapter->vchnl_wq;
		vc_state = adapter->vc_state;
	}

	while (num_waits) {
		int event;

		/* If we are here and a reset is detected do not wait but
		 * return. Reset timing is out of drivers control. So
		 * while we are cleaning resources as part of reset if the
		 * underlying HW mailbox is gone, wait on mailbox messages
		 * is not meaningful
		 */
		if (idpf_is_reset_detected(adapter))
			return 0;

		event = wait_event_timeout(*vchnl_wq,
					   test_and_clear_bit(state, vc_state),
					   msecs_to_jiffies(time_to_wait));
		if (event) {
			if (test_and_clear_bit(err_check, vc_state)) {
				dev_err(&adapter->pdev->dev, "VC response error %s\n",
					idpf_vport_vc_state_str[err_check]);

				return -EINVAL;
			}

			return 0;
		}
		num_waits--;
	}

	/* Timeout occurred */
	dev_err(&adapter->pdev->dev, "VC timeout, state = %s\n",
		idpf_vport_vc_state_str[state]);

	return -ETIMEDOUT;
}

/**
 * idpf_min_wait_for_event - wait for virtchannel response
 * @adapter: Driver private data structure
 * @vport: virtual port structure
 * @state: check on state upon timeout
 * @err_check: check if this specific error bit is set
 *
 * Returns 0 on success, negative on failure.
 */
static int idpf_min_wait_for_event(struct idpf_adapter *adapter,
				   struct idpf_vport *vport,
				   enum idpf_vport_vc_state state,
				   enum idpf_vport_vc_state err_check)
{
	return __idpf_wait_for_event(adapter, vport, state, err_check,
				     IDPF_WAIT_FOR_EVENT_TIMEO_MIN);
}

/**
 * idpf_wait_for_event - wait for virtchannel response
 * @adapter: Driver private data structure
 * @vport: virtual port structure
 * @state: check on state upon timeout after 500ms
 * @err_check: check if this specific error bit is set
 *
 * Returns 0 on success, negative on failure.
 */
static int idpf_wait_for_event(struct idpf_adapter *adapter,
			       struct idpf_vport *vport,
			       enum idpf_vport_vc_state state,
			       enum idpf_vport_vc_state err_check)
{
	/* Increasing the timeout in __IDPF_INIT_SW flow to consider large
	 * number of VF's mailbox message responses. When a message is received
	 * on mailbox, this thread is woken up by the idpf_recv_mb_msg before
	 * the timeout expires. Only in the error case i.e. if no message is
	 * received on mailbox, we wait for the complete timeout which is
	 * less likely to happen.
	 */
	return __idpf_wait_for_event(adapter, vport, state, err_check,
				     IDPF_WAIT_FOR_EVENT_TIMEO);
}

/**
 * idpf_wait_for_selected_marker_events - wait for software marker response
 *					  for selected tx queues
 * @vport: virtual port data structure
 * @qs: array of tx queues on which the function should wait for marker events
 * @num_qs: number of queues contained in the 'qs' array
 *
 * Returns 0 success, negative on failure.
 */
static int idpf_wait_for_selected_marker_events(struct idpf_vport *vport,
						struct idpf_queue **qs,
						int num_qs)
{
	bool markers_rcvd = true;
	int i;

	for (i = 0; i < num_qs; i++) {
		struct idpf_queue *txq = qs[i];

		set_bit(__IDPF_Q_SW_MARKER, txq->flags);
		idpf_wait_for_sw_marker_completion(txq);

		markers_rcvd &= !test_bit(__IDPF_Q_SW_MARKER, txq->flags);
	}

	if (markers_rcvd)
		return 0;

	dev_warn(&vport->adapter->pdev->dev, "Failed to receive marker packets\n");

	return -ETIMEDOUT;
}

/**
 * idpf_wait_for_marker_event - wait for software marker response
 * @vport: virtual port data structure
 *
 * Returns 0 success, negative on failure.
 **/
static int idpf_wait_for_marker_event(struct idpf_vport *vport)
{
	return idpf_wait_for_selected_marker_events(vport,
						    vport->txqs,
						    vport->num_txq);
}

/**
 * idpf_send_ver_msg - send virtchnl version message
 * @adapter: Driver specific private structure
 *
 * Send virtchnl version message.  Returns 0 on success, negative on failure.
 */
static int idpf_send_ver_msg(struct idpf_adapter *adapter)
{
	struct virtchnl2_version_info vvi;

	if (adapter->virt_ver_maj) {
		vvi.major = cpu_to_le32(adapter->virt_ver_maj);
		vvi.minor = cpu_to_le32(adapter->virt_ver_min);
	} else {
		vvi.major = cpu_to_le32(IDPF_VIRTCHNL_VERSION_MAJOR);
		vvi.minor = cpu_to_le32(IDPF_VIRTCHNL_VERSION_MINOR);
	}

	return idpf_send_mb_msg(adapter, VIRTCHNL2_OP_VERSION, sizeof(vvi),
				(u8 *)&vvi);
}

/**
 * idpf_recv_ver_msg - Receive virtchnl version message
 * @adapter: Driver specific private structure
 *
 * Receive virtchnl version message. Returns 0 on success, -EAGAIN if we need
 * to send version message again, otherwise negative on failure.
 */
static int idpf_recv_ver_msg(struct idpf_adapter *adapter)
{
	struct virtchnl2_version_info vvi;
	u32 major, minor;
	int err;

	err = idpf_recv_mb_msg(adapter, VIRTCHNL2_OP_VERSION, &vvi,
			       sizeof(vvi));
	if (err)
		return err;

	major = le32_to_cpu(vvi.major);
	minor = le32_to_cpu(vvi.minor);

	if (major > IDPF_VIRTCHNL_VERSION_MAJOR) {
		dev_warn(&adapter->pdev->dev,
			 "Virtchnl major version (%d) greater than supported\n",
			 major);

		return -EINVAL;
	}

	if (major == IDPF_VIRTCHNL_VERSION_MAJOR &&
	    minor > IDPF_VIRTCHNL_VERSION_MINOR)
		dev_warn(&adapter->pdev->dev,
			 "Virtchnl minor version (%d) didn't match\n", minor);

	/* If we have a mismatch, resend version to update receiver on what
	 * version we will use.
	 */
	if (!adapter->virt_ver_maj &&
	    major != IDPF_VIRTCHNL_VERSION_MAJOR &&
	    minor != IDPF_VIRTCHNL_VERSION_MINOR)
		err = -EAGAIN;

	adapter->virt_ver_maj = major;
	adapter->virt_ver_min = minor;

	return err;
}

/**
 * idpf_send_get_caps_msg - Send virtchnl get capabilities message
 * @adapter: Driver specific private structure
 *
 * Send virtchl get capabilities message. Returns 0 on success, negative on
 * failure.
 */
static int idpf_send_get_caps_msg(struct idpf_adapter *adapter)
{
	struct virtchnl2_get_capabilities caps = { };

	caps.csum_caps =
		cpu_to_le32(VIRTCHNL2_CAP_TX_CSUM_L3_IPV4	|
			    VIRTCHNL2_CAP_TX_CSUM_L4_IPV4_TCP	|
			    VIRTCHNL2_CAP_TX_CSUM_L4_IPV4_UDP	|
			    VIRTCHNL2_CAP_TX_CSUM_L4_IPV4_SCTP	|
			    VIRTCHNL2_CAP_TX_CSUM_L4_IPV6_TCP	|
			    VIRTCHNL2_CAP_TX_CSUM_L4_IPV6_UDP	|
			    VIRTCHNL2_CAP_TX_CSUM_L4_IPV6_SCTP	|
			    VIRTCHNL2_CAP_RX_CSUM_L3_IPV4	|
			    VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_TCP	|
			    VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_UDP	|
			    VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_SCTP	|
			    VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_TCP	|
			    VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_UDP	|
			    VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_SCTP	|
			    VIRTCHNL2_CAP_TX_CSUM_L3_SINGLE_TUNNEL |
			    VIRTCHNL2_CAP_RX_CSUM_L3_SINGLE_TUNNEL |
			    VIRTCHNL2_CAP_TX_CSUM_L4_SINGLE_TUNNEL |
			    VIRTCHNL2_CAP_RX_CSUM_L4_SINGLE_TUNNEL |
			    VIRTCHNL2_CAP_RX_CSUM_GENERIC);

	caps.seg_caps =
		cpu_to_le32(VIRTCHNL2_CAP_SEG_IPV4_TCP		|
			    VIRTCHNL2_CAP_SEG_IPV4_UDP		|
			    VIRTCHNL2_CAP_SEG_IPV4_SCTP		|
			    VIRTCHNL2_CAP_SEG_IPV6_TCP		|
			    VIRTCHNL2_CAP_SEG_IPV6_UDP		|
			    VIRTCHNL2_CAP_SEG_IPV6_SCTP		|
			    VIRTCHNL2_CAP_SEG_TX_SINGLE_TUNNEL);

	caps.rss_caps =
		cpu_to_le64(VIRTCHNL2_CAP_RSS_IPV4_TCP		|
			    VIRTCHNL2_CAP_RSS_IPV4_UDP		|
			    VIRTCHNL2_CAP_RSS_IPV4_SCTP		|
			    VIRTCHNL2_CAP_RSS_IPV4_OTHER	|
			    VIRTCHNL2_CAP_RSS_IPV6_TCP		|
			    VIRTCHNL2_CAP_RSS_IPV6_UDP		|
			    VIRTCHNL2_CAP_RSS_IPV6_SCTP		|
			    VIRTCHNL2_CAP_RSS_IPV6_OTHER);

	caps.hsplit_caps =
		cpu_to_le32(VIRTCHNL2_CAP_RX_HSPLIT_AT_L4V4	|
			    VIRTCHNL2_CAP_RX_HSPLIT_AT_L4V6);

	caps.rsc_caps =
		cpu_to_le32(VIRTCHNL2_CAP_RSC_IPV4_TCP		|
			    VIRTCHNL2_CAP_RSC_IPV6_TCP);

	caps.other_caps =
		cpu_to_le64(VIRTCHNL2_CAP_SRIOV			|
			    VIRTCHNL2_CAP_MACFILTER		|
			    VIRTCHNL2_CAP_SPLITQ_QSCHED		|
			    VIRTCHNL2_CAP_PROMISC		|
			    VIRTCHNL2_CAP_LOOPBACK);

	return idpf_send_mb_msg(adapter, VIRTCHNL2_OP_GET_CAPS, sizeof(caps),
				(u8 *)&caps);
}

/**
 * idpf_recv_get_caps_msg - Receive virtchnl get capabilities message
 * @adapter: Driver specific private structure
 *
 * Receive virtchnl get capabilities message. Returns 0 on success, negative on
 * failure.
 */
static int idpf_recv_get_caps_msg(struct idpf_adapter *adapter)
{
	return idpf_recv_mb_msg(adapter, VIRTCHNL2_OP_GET_CAPS, &adapter->caps,
				sizeof(struct virtchnl2_get_capabilities));
}

/**
 * idpf_vport_alloc_max_qs - Allocate max queues for a vport
 * @adapter: Driver specific private structure
 * @max_q: vport max queue structure
 */
int idpf_vport_alloc_max_qs(struct idpf_adapter *adapter,
			    struct idpf_vport_max_q *max_q)
{
	struct idpf_avail_queue_info *avail_queues = &adapter->avail_queues;
	struct virtchnl2_get_capabilities *caps = &adapter->caps;
	u16 default_vports = idpf_get_default_vports(adapter);
	int max_rx_q, max_tx_q;

	mutex_lock(&adapter->queue_lock);

	max_rx_q = le16_to_cpu(caps->max_rx_q) / default_vports;
	max_tx_q = le16_to_cpu(caps->max_tx_q) / default_vports;
	if (adapter->num_alloc_vports < default_vports) {
		max_q->max_rxq = min_t(u16, max_rx_q, IDPF_MAX_Q);
		max_q->max_txq = min_t(u16, max_tx_q, IDPF_MAX_Q);
	} else {
		max_q->max_rxq = IDPF_MIN_Q;
		max_q->max_txq = IDPF_MIN_Q;
	}
	max_q->max_bufq = max_q->max_rxq * IDPF_MAX_BUFQS_PER_RXQ_GRP;
	max_q->max_complq = max_q->max_txq;

	if (avail_queues->avail_rxq < max_q->max_rxq ||
	    avail_queues->avail_txq < max_q->max_txq ||
	    avail_queues->avail_bufq < max_q->max_bufq ||
	    avail_queues->avail_complq < max_q->max_complq) {
		mutex_unlock(&adapter->queue_lock);

		return -EINVAL;
	}

	avail_queues->avail_rxq -= max_q->max_rxq;
	avail_queues->avail_txq -= max_q->max_txq;
	avail_queues->avail_bufq -= max_q->max_bufq;
	avail_queues->avail_complq -= max_q->max_complq;

	mutex_unlock(&adapter->queue_lock);

	return 0;
}

/**
 * idpf_vport_dealloc_max_qs - Deallocate max queues of a vport
 * @adapter: Driver specific private structure
 * @max_q: vport max queue structure
 */
void idpf_vport_dealloc_max_qs(struct idpf_adapter *adapter,
			       struct idpf_vport_max_q *max_q)
{
	struct idpf_avail_queue_info *avail_queues;

	mutex_lock(&adapter->queue_lock);
	avail_queues = &adapter->avail_queues;

	avail_queues->avail_rxq += max_q->max_rxq;
	avail_queues->avail_txq += max_q->max_txq;
	avail_queues->avail_bufq += max_q->max_bufq;
	avail_queues->avail_complq += max_q->max_complq;

	mutex_unlock(&adapter->queue_lock);
}

/**
 * idpf_init_avail_queues - Initialize available queues on the device
 * @adapter: Driver specific private structure
 */
static void idpf_init_avail_queues(struct idpf_adapter *adapter)
{
	struct idpf_avail_queue_info *avail_queues = &adapter->avail_queues;
	struct virtchnl2_get_capabilities *caps = &adapter->caps;

	avail_queues->avail_rxq = le16_to_cpu(caps->max_rx_q);
	avail_queues->avail_txq = le16_to_cpu(caps->max_tx_q);
	avail_queues->avail_bufq = le16_to_cpu(caps->max_rx_bufq);
	avail_queues->avail_complq = le16_to_cpu(caps->max_tx_complq);
}

/**
 * idpf_get_reg_intr_vecs - Get vector queue register offset
 * @vport: virtual port structure
 * @reg_vals: Register offsets to store in
 *
 * Returns number of registers that got populated
 */
int idpf_get_reg_intr_vecs(struct idpf_vport *vport,
			   struct idpf_vec_regs *reg_vals)
{
	struct virtchnl2_vector_chunks *chunks;
	struct idpf_vec_regs reg_val;
	u16 num_vchunks, num_vec;
	int num_regs = 0, i, j;

	chunks = &vport->adapter->req_vec_chunks->vchunks;
	num_vchunks = le16_to_cpu(chunks->num_vchunks);

	for (j = 0; j < num_vchunks; j++) {
		struct virtchnl2_vector_chunk *chunk;
		u32 dynctl_reg_spacing;
		u32 itrn_reg_spacing;

		chunk = &chunks->vchunks[j];
		num_vec = le16_to_cpu(chunk->num_vectors);
		reg_val.dyn_ctl_reg = le32_to_cpu(chunk->dynctl_reg_start);
		reg_val.itrn_reg = le32_to_cpu(chunk->itrn_reg_start);
		reg_val.itrn_index_spacing = le32_to_cpu(chunk->itrn_index_spacing);

		dynctl_reg_spacing = le32_to_cpu(chunk->dynctl_reg_spacing);
		itrn_reg_spacing = le32_to_cpu(chunk->itrn_reg_spacing);

		for (i = 0; i < num_vec; i++) {
			reg_vals[num_regs].dyn_ctl_reg = reg_val.dyn_ctl_reg;
			reg_vals[num_regs].itrn_reg = reg_val.itrn_reg;
			reg_vals[num_regs].itrn_index_spacing =
						reg_val.itrn_index_spacing;

			reg_val.dyn_ctl_reg += dynctl_reg_spacing;
			reg_val.itrn_reg += itrn_reg_spacing;
			num_regs++;
		}
	}

	return num_regs;
}

/**
 * idpf_vport_get_q_reg - Get the queue registers for the vport
 * @reg_vals: register values needing to be set
 * @num_regs: amount we expect to fill
 * @q_type: queue model
 * @chunks: queue regs received over mailbox
 *
 * This function parses the queue register offsets from the queue register
 * chunk information, with a specific queue type and stores it into the array
 * passed as an argument. It returns the actual number of queue registers that
 * are filled.
 */
static int idpf_vport_get_q_reg(u32 *reg_vals, int num_regs, u32 q_type,
				struct virtchnl2_queue_reg_chunks *chunks)
{
	u16 num_chunks = le16_to_cpu(chunks->num_chunks);
	int reg_filled = 0, i;
	u32 reg_val;

	while (num_chunks--) {
		struct virtchnl2_queue_reg_chunk *chunk;
		u16 num_q;

		chunk = &chunks->chunks[num_chunks];
		if (le32_to_cpu(chunk->type) != q_type)
			continue;

		num_q = le32_to_cpu(chunk->num_queues);
		reg_val = le64_to_cpu(chunk->qtail_reg_start);
		for (i = 0; i < num_q && reg_filled < num_regs ; i++) {
			reg_vals[reg_filled++] = reg_val;
			reg_val += le32_to_cpu(chunk->qtail_reg_spacing);
		}
	}

	return reg_filled;
}

/**
 * __idpf_queue_reg_init - initialize queue registers
 * @vport: virtual port structure
 * @reg_vals: registers we are initializing
 * @num_regs: how many registers there are in total
 * @q_type: queue model
 *
 * Return number of queues that are initialized
 */
static int __idpf_queue_reg_init(struct idpf_vport *vport, u32 *reg_vals,
				 int num_regs, u32 q_type)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct idpf_queue *q;
	int i, j, k = 0;

	switch (q_type) {
	case VIRTCHNL2_QUEUE_TYPE_TX:
		for (i = 0; i < vport->num_txq_grp; i++) {
			struct idpf_txq_group *tx_qgrp = &vport->txq_grps[i];

			for (j = 0; j < tx_qgrp->num_txq && k < num_regs; j++, k++)
				tx_qgrp->txqs[j]->tail =
					idpf_get_reg_addr(adapter, reg_vals[k]);
		}
		break;
	case VIRTCHNL2_QUEUE_TYPE_RX:
		for (i = 0; i < vport->num_rxq_grp; i++) {
			struct idpf_rxq_group *rx_qgrp = &vport->rxq_grps[i];
			u16 num_rxq = rx_qgrp->singleq.num_rxq;

			for (j = 0; j < num_rxq && k < num_regs; j++, k++) {
				q = rx_qgrp->singleq.rxqs[j];
				q->tail = idpf_get_reg_addr(adapter,
							    reg_vals[k]);
			}
		}
		break;
	case VIRTCHNL2_QUEUE_TYPE_RX_BUFFER:
		for (i = 0; i < vport->num_rxq_grp; i++) {
			struct idpf_rxq_group *rx_qgrp = &vport->rxq_grps[i];
			u8 num_bufqs = vport->num_bufqs_per_qgrp;

			for (j = 0; j < num_bufqs && k < num_regs; j++, k++) {
				q = &rx_qgrp->splitq.bufq_sets[j].bufq;
				q->tail = idpf_get_reg_addr(adapter,
							    reg_vals[k]);
			}
		}
		break;
	default:
		break;
	}

	return k;
}

/**
 * idpf_queue_reg_init - initialize queue registers
 * @vport: virtual port structure
 *
 * Return 0 on success, negative on failure
 */
int idpf_queue_reg_init(struct idpf_vport *vport)
{
	struct virtchnl2_create_vport *vport_params;
	struct virtchnl2_queue_reg_chunks *chunks;
	struct idpf_vport_config *vport_config;
	u16 vport_idx = vport->idx;
	int num_regs, ret = 0;
	u32 *reg_vals;

	/* We may never deal with more than 256 same type of queues */
	reg_vals = kzalloc(sizeof(void *) * IDPF_LARGE_MAX_Q, GFP_KERNEL);
	if (!reg_vals)
		return -ENOMEM;

	vport_config = vport->adapter->vport_config[vport_idx];
	if (vport_config->req_qs_chunks) {
		struct virtchnl2_add_queues *vc_aq =
		  (struct virtchnl2_add_queues *)vport_config->req_qs_chunks;
		chunks = &vc_aq->chunks;
	} else {
		vport_params = vport->adapter->vport_params_recvd[vport_idx];
		chunks = &vport_params->chunks;
	}

	/* Initialize Tx queue tail register address */
	num_regs = idpf_vport_get_q_reg(reg_vals, IDPF_LARGE_MAX_Q,
					VIRTCHNL2_QUEUE_TYPE_TX,
					chunks);
	if (num_regs < vport->num_txq) {
		ret = -EINVAL;
		goto free_reg_vals;
	}

	num_regs = __idpf_queue_reg_init(vport, reg_vals, num_regs,
					 VIRTCHNL2_QUEUE_TYPE_TX);
	if (num_regs < vport->num_txq) {
		ret = -EINVAL;
		goto free_reg_vals;
	}

	/* Initialize Rx/buffer queue tail register address based on Rx queue
	 * model
	 */
	if (idpf_is_queue_model_split(vport->rxq_model)) {
		num_regs = idpf_vport_get_q_reg(reg_vals, IDPF_LARGE_MAX_Q,
						VIRTCHNL2_QUEUE_TYPE_RX_BUFFER,
						chunks);
		if (num_regs < vport->num_bufq) {
			ret = -EINVAL;
			goto free_reg_vals;
		}

		num_regs = __idpf_queue_reg_init(vport, reg_vals, num_regs,
						 VIRTCHNL2_QUEUE_TYPE_RX_BUFFER);
		if (num_regs < vport->num_bufq) {
			ret = -EINVAL;
			goto free_reg_vals;
		}
	} else {
		num_regs = idpf_vport_get_q_reg(reg_vals, IDPF_LARGE_MAX_Q,
						VIRTCHNL2_QUEUE_TYPE_RX,
						chunks);
		if (num_regs < vport->num_rxq) {
			ret = -EINVAL;
			goto free_reg_vals;
		}

		num_regs = __idpf_queue_reg_init(vport, reg_vals, num_regs,
						 VIRTCHNL2_QUEUE_TYPE_RX);
		if (num_regs < vport->num_rxq) {
			ret = -EINVAL;
			goto free_reg_vals;
		}
	}

free_reg_vals:
	kfree(reg_vals);

	return ret;
}

/**
 * idpf_send_create_vport_msg - Send virtchnl create vport message
 * @adapter: Driver specific private structure
 * @max_q: vport max queue info
 *
 * send virtchnl creae vport message
 *
 * Returns 0 on success, negative on failure
 */
int idpf_send_create_vport_msg(struct idpf_adapter *adapter,
			       struct idpf_vport_max_q *max_q)
{
	struct virtchnl2_create_vport *vport_msg;
	u16 idx = adapter->next_vport;
	int err, buf_size;

	buf_size = sizeof(struct virtchnl2_create_vport);
	if (!adapter->vport_params_reqd[idx]) {
		adapter->vport_params_reqd[idx] = kzalloc(buf_size,
							  GFP_KERNEL);
		if (!adapter->vport_params_reqd[idx])
			return -ENOMEM;
	}

	vport_msg = adapter->vport_params_reqd[idx];
	vport_msg->vport_type = cpu_to_le16(VIRTCHNL2_VPORT_TYPE_DEFAULT);
	vport_msg->vport_index = cpu_to_le16(idx);

	if (adapter->req_tx_splitq)
		vport_msg->txq_model = cpu_to_le16(VIRTCHNL2_QUEUE_MODEL_SPLIT);
	else
		vport_msg->txq_model = cpu_to_le16(VIRTCHNL2_QUEUE_MODEL_SINGLE);

	if (adapter->req_rx_splitq)
		vport_msg->rxq_model = cpu_to_le16(VIRTCHNL2_QUEUE_MODEL_SPLIT);
	else
		vport_msg->rxq_model = cpu_to_le16(VIRTCHNL2_QUEUE_MODEL_SINGLE);

	err = idpf_vport_calc_total_qs(adapter, idx, vport_msg, max_q);
	if (err) {
		dev_err(&adapter->pdev->dev, "Enough queues are not available");

		return err;
	}

	mutex_lock(&adapter->vc_buf_lock);

	err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_CREATE_VPORT, buf_size,
			       (u8 *)vport_msg);
	if (err)
		goto rel_lock;

	err = idpf_wait_for_event(adapter, NULL, IDPF_VC_CREATE_VPORT,
				  IDPF_VC_CREATE_VPORT_ERR);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to receive create vport message");

		goto rel_lock;
	}

	if (!adapter->vport_params_recvd[idx]) {
		adapter->vport_params_recvd[idx] = kzalloc(IDPF_CTLQ_MAX_BUF_LEN,
							   GFP_KERNEL);
		if (!adapter->vport_params_recvd[idx]) {
			err = -ENOMEM;
			goto rel_lock;
		}
	}

	vport_msg = adapter->vport_params_recvd[idx];
	memcpy(vport_msg, adapter->vc_msg, IDPF_CTLQ_MAX_BUF_LEN);

rel_lock:
	mutex_unlock(&adapter->vc_buf_lock);

	return err;
}

/**
 * idpf_check_supported_desc_ids - Verify we have required descriptor support
 * @vport: virtual port structure
 *
 * Return 0 on success, error on failure
 */
int idpf_check_supported_desc_ids(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_create_vport *vport_msg;
	u64 rx_desc_ids, tx_desc_ids;

	vport_msg = adapter->vport_params_recvd[vport->idx];

	rx_desc_ids = le64_to_cpu(vport_msg->rx_desc_ids);
	tx_desc_ids = le64_to_cpu(vport_msg->tx_desc_ids);

	if (vport->rxq_model == VIRTCHNL2_QUEUE_MODEL_SPLIT) {
		if (!(rx_desc_ids & VIRTCHNL2_RXDID_2_FLEX_SPLITQ_M)) {
			dev_info(&adapter->pdev->dev, "Minimum RX descriptor support not provided, using the default\n");
			vport_msg->rx_desc_ids = cpu_to_le64(VIRTCHNL2_RXDID_2_FLEX_SPLITQ_M);
		}
	} else {
		if (!(rx_desc_ids & VIRTCHNL2_RXDID_2_FLEX_SQ_NIC_M))
			vport->base_rxd = true;
	}

	if (vport->txq_model != VIRTCHNL2_QUEUE_MODEL_SPLIT)
		return 0;

	if ((tx_desc_ids & MIN_SUPPORT_TXDID) != MIN_SUPPORT_TXDID) {
		dev_info(&adapter->pdev->dev, "Minimum TX descriptor support not provided, using the default\n");
		vport_msg->tx_desc_ids = cpu_to_le64(MIN_SUPPORT_TXDID);
	}

	return 0;
}

/**
 * idpf_send_destroy_vport_msg - Send virtchnl destroy vport message
 * @vport: virtual port data structure
 *
 * Send virtchnl destroy vport message.  Returns 0 on success, negative on
 * failure.
 */
int idpf_send_destroy_vport_msg(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_vport v_id;
	int err;

	v_id.vport_id = cpu_to_le32(vport->vport_id);

	mutex_lock(&vport->vc_buf_lock);

	err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_DESTROY_VPORT,
			       sizeof(v_id), (u8 *)&v_id);
	if (err)
		goto rel_lock;

	err = idpf_min_wait_for_event(adapter, vport, IDPF_VC_DESTROY_VPORT,
				      IDPF_VC_DESTROY_VPORT_ERR);

rel_lock:
	mutex_unlock(&vport->vc_buf_lock);

	return err;
}

/**
 * idpf_send_enable_vport_msg - Send virtchnl enable vport message
 * @vport: virtual port data structure
 *
 * Send enable vport virtchnl message.  Returns 0 on success, negative on
 * failure.
 */
int idpf_send_enable_vport_msg(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_vport v_id;
	int err;

	v_id.vport_id = cpu_to_le32(vport->vport_id);

	mutex_lock(&vport->vc_buf_lock);

	err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_ENABLE_VPORT,
			       sizeof(v_id), (u8 *)&v_id);
	if (err)
		goto rel_lock;

	err = idpf_wait_for_event(adapter, vport, IDPF_VC_ENA_VPORT,
				  IDPF_VC_ENA_VPORT_ERR);

rel_lock:
	mutex_unlock(&vport->vc_buf_lock);

	return err;
}

/**
 * idpf_send_disable_vport_msg - Send virtchnl disable vport message
 * @vport: virtual port data structure
 *
 * Send disable vport virtchnl message.  Returns 0 on success, negative on
 * failure.
 */
int idpf_send_disable_vport_msg(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_vport v_id;
	int err;

	v_id.vport_id = cpu_to_le32(vport->vport_id);

	mutex_lock(&vport->vc_buf_lock);

	err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_DISABLE_VPORT,
			       sizeof(v_id), (u8 *)&v_id);
	if (err)
		goto rel_lock;

	err = idpf_min_wait_for_event(adapter, vport, IDPF_VC_DIS_VPORT,
				      IDPF_VC_DIS_VPORT_ERR);

rel_lock:
	mutex_unlock(&vport->vc_buf_lock);

	return err;
}

struct idpf_chunked_msg_params {
	u32 op;
	enum idpf_vport_vc_state state;
	enum idpf_vport_vc_state err_check;
	int timeout;
	int config_sz;
	int chunk_sz;
	int (*prepare_msg)(struct idpf_vport *, u8 *, u8 *, int);
	u32 num_chunks;
	u8 *chunks;
};

/**
 * idpf_send_chunked_msg - Send a VC message consisting of chunks.
 * @vport: virtual port data structure
 * @xn_params: parameters for this particular transaction including
 * @prep_msg: pointer to the helper function for preparing the VC message
 * @config_data_size: size of the message config data
 * @num_chunks: number of chunks in the message
 * @chunk_size: size of single message chunk
 * @chunks: pointer to a buffer containig chunks of the message
 *
 * Helper function for preparing the message describing queues to be enabled
 * or disabled.
 * Returns the total size of the prepared message.
 */
static int idpf_send_chunked_msg(struct idpf_vport *vport,
				 struct idpf_chunked_msg_params *params)
{
	u32 num_msgs, max_chunks, left_chunks, max_buf_sz;
	u32 num_chunks = params->num_chunks;
	int err = 0, i;
	u8 *msg_buf;

	max_chunks = min_t(u32, IDPF_NUM_CHUNKS_PER_MSG(params->config_sz,
							params->chunk_sz),
							params->num_chunks);
	max_buf_sz = params->config_sz + max_chunks * params->chunk_sz;
	num_msgs = DIV_ROUND_UP(params->num_chunks, max_chunks);

	msg_buf = kzalloc(max_buf_sz, GFP_KERNEL);
	if (!msg_buf) {
		err = -ENOMEM;
		goto error;
	}

	mutex_lock(&vport->vc_buf_lock);

	left_chunks = num_chunks;
	for (i = 0; i < num_msgs; i++) {
		u8 *chunks = params->chunks;
		int buf_sz, msg_size;
		u8 *first_chunk;

		num_chunks = min(max_chunks, left_chunks);
		first_chunk = chunks + (i * params->chunk_sz * max_chunks);
		msg_size = params->chunk_sz * num_chunks + params->config_sz;

		buf_sz = params->prepare_msg(vport, msg_buf, first_chunk,
					     num_chunks);
		if (buf_sz != msg_size) {
			err = -EINVAL;
			goto msg_error;
		}

		err = idpf_send_mb_msg(vport->adapter, params->op,
				       buf_sz, msg_buf);
		if (err)
			goto msg_error;

		err = __idpf_wait_for_event(vport->adapter, vport,
					    params->state, params->err_check,
					    params->timeout);
		if (err)
			goto msg_error;

		left_chunks -= num_chunks;
	}

	if (left_chunks != 0)
		err = -EINVAL;
msg_error:
	mutex_unlock(&vport->vc_buf_lock);
	kfree(msg_buf);
error:
	return err;
}

/**
 * idpf_fill_txcomplq_config_chunk - Fill the chunk describing the tx queue.
 * @vport: virtual port data structure
 * @q: tx queue to be inserted into VC chunk
 * @qi: pointer to the buffer containing the VC chunk
 */
static void idpf_fill_txcomplq_config_chunk(struct idpf_vport *vport,
					    struct idpf_queue *q,
					    struct virtchnl2_txq_info *qi)
{
	qi->queue_id = cpu_to_le32(q->q_id);
	qi->model = cpu_to_le16(vport->txq_model);
	qi->type = cpu_to_le32(q->q_type);
	qi->ring_len = cpu_to_le16(q->desc_count);
	qi->dma_ring_addr = cpu_to_le64(q->dma);

	if (!idpf_is_queue_model_split(vport->txq_model))
		return;

	if (test_bit(__IDPF_Q_FLOW_SCH_EN, q->flags))
		qi->sched_mode = cpu_to_le16(VIRTCHNL2_TXQ_SCHED_MODE_FLOW);
	else
		qi->sched_mode = cpu_to_le16(VIRTCHNL2_TXQ_SCHED_MODE_QUEUE);

	if (q->q_type != VIRTCHNL2_QUEUE_TYPE_TX)
		return;

	qi->tx_compl_queue_id = cpu_to_le16(q->txq_grp->complq->q_id);
	qi->relative_queue_id = cpu_to_le16(q->relative_q_id);
}

/**
 * idpf_prepare_cfg_txqs_msg - Prepare message to configure selected tx queues.
 * @vport: virtual port data structure
 * @msg_buf: buffer containing the message
 * @first_chunk: pointer to the first chunk describing the tx queue
 * @num_chunks: number of chunks in the message
 *
 * Helper function for preparing the message describing configuration of
 * tx queues.
 * Returns the total size of the prepared message.
 */
static int idpf_prepare_cfg_txqs_msg(struct idpf_vport *vport,
				     u8 *msg_buf, u8 *first_chunk,
				     int num_chunks)
{
	int chunk_size = sizeof(struct virtchnl2_txq_info);
	struct virtchnl2_config_tx_queues *ctq;

	ctq = (struct virtchnl2_config_tx_queues *)msg_buf;
	ctq->vport_id = cpu_to_le32(vport->vport_id);
	ctq->num_qinfo = cpu_to_le16(num_chunks);

	memcpy(ctq->qinfo, first_chunk, num_chunks * chunk_size);

	return (chunk_size * num_chunks + sizeof(*ctq));
}

/**
 * idpf_send_config_selected_tx_queues_msg - Send virtchnl config tx queues
 * message for selected tx queues only.
 * @vport: virtual port data structure
 * @qs: array of tx queues to be configured
 * @num_q: number of tx queues contained in 'qs' array
 *
 * Send config queues virtchnl message for queues contained in 'qs' array.
 * The 'qs' array can contain tx queues (or completion queues) only.
 * Returns 0 on success, negative on failure.
 */
static int idpf_send_config_selected_tx_queues_msg(struct idpf_vport *vport,
						   struct idpf_queue **qs,
						   int num_q)
{
	struct idpf_chunked_msg_params params = { };
	struct virtchnl2_txq_info *qi;
	int err, i;

	qi = (struct virtchnl2_txq_info *)
		kcalloc(num_q, sizeof(struct virtchnl2_txq_info), GFP_KERNEL);
	if (!qi)
		return -ENOMEM;

	params.op = VIRTCHNL2_OP_CONFIG_TX_QUEUES;
	params.state = IDPF_VC_CONFIG_TXQ;
	params.err_check = IDPF_VC_CONFIG_TXQ_ERR;
	params.timeout = IDPF_WAIT_FOR_EVENT_TIMEO;
	params.config_sz = sizeof(struct virtchnl2_config_tx_queues);
	params.chunk_sz = sizeof(struct virtchnl2_txq_info);
	params.prepare_msg = &idpf_prepare_cfg_txqs_msg;
	params.num_chunks = num_q;
	params.chunks = (u8 *)qi;

	for (i = 0; i < num_q; i++)
		idpf_fill_txcomplq_config_chunk(vport, qs[i], &qi[i]);

	err = idpf_send_chunked_msg(vport, &params);

	kfree(qi);
	return err;
}

/**
 * idpf_send_config_tx_queues_msg - Send virtchnl config tx queues message
 * @vport: virtual port data structure
 *
 * Send config tx queues virtchnl message. Returns 0 on success, negative on
 * failure.
 */
static int idpf_send_config_tx_queues_msg(struct idpf_vport *vport)
{
	int totqs, err = 0, i, k = 0;
	struct idpf_queue **qs;

	totqs = vport->num_txq + vport->num_complq;
	qs = (struct idpf_queue **)kzalloc(totqs * sizeof(*qs), GFP_KERNEL);
	if (!qs)
		return -ENOMEM;

	/* Populate the queue info buffer with all queue context info */
	for (i = 0; i < vport->num_txq_grp; i++) {
		struct idpf_txq_group *tx_qgrp = &vport->txq_grps[i];
		int j;

		for (j = 0; j < tx_qgrp->num_txq; j++, k++)
			qs[k] = tx_qgrp->txqs[j];

		if (idpf_is_queue_model_split(vport->txq_model))
			qs[k++] = tx_qgrp->complq;
	}

	/* Make sure accounting agrees */
	if (k != totqs) {
		err = -EINVAL;
		goto error;
	}

	err = idpf_send_config_selected_tx_queues_msg(vport, qs, totqs);
error:
	kfree(qs);
	return err;
}

/**
 * idpf_fill_bufq_config_chunk - Fill the chunk describing the rx or buf queue.
 * @vport: virtual port data structure
 * @rxbufq: rx or buffer queue to be inserted into VC chunk
 * @qi: pointer to the buffer containing the VC chunk
 */
static void idpf_fill_rxbufq_config_chunk(struct idpf_vport *vport,
					  struct idpf_queue *q,
					  struct virtchnl2_rxq_info *qi)
{
	const struct idpf_bufq_set *sets;

	qi->queue_id = cpu_to_le32(q->q_id);
	qi->model = cpu_to_le16(vport->rxq_model);
	qi->type = cpu_to_le32(q->q_type);
	qi->ring_len = cpu_to_le16(q->desc_count);
	qi->dma_ring_addr = cpu_to_le64(q->dma);
	qi->data_buffer_size = cpu_to_le32(q->rx_buf_size);
	qi->rx_buffer_low_watermark =
		cpu_to_le16(q->rx_buffer_low_watermark);
	if (idpf_is_feature_ena(vport, NETIF_F_GRO_HW))
		qi->qflags |= cpu_to_le16(VIRTCHNL2_RXQ_RSC);

	if (q->q_type == VIRTCHNL2_QUEUE_TYPE_RX_BUFFER) {
		qi->desc_ids = cpu_to_le64(VIRTCHNL2_RXDID_2_FLEX_SPLITQ_M);
		qi->buffer_notif_stride = q->rx_buf_stride;
	}

	if (q->q_type != VIRTCHNL2_QUEUE_TYPE_RX)
		return;

	qi->max_pkt_size = cpu_to_le32(q->rx_max_pkt_size);
	qi->qflags |= cpu_to_le16(VIRTCHNL2_RX_DESC_SIZE_32BYTE);
	qi->desc_ids = cpu_to_le64(q->rxdids);

	if (!idpf_is_queue_model_split(vport->rxq_model))
		return;

	sets = q->rxq_grp->splitq.bufq_sets;

	/* In splitq mode, RXQ buffer size should be set to that of the first
	 * buffer queue associated with this RXQ.
	 */
	q->rx_buf_size = sets[0].bufq.rx_buf_size;
	qi->data_buffer_size = cpu_to_le32(q->rx_buf_size);

	qi->rx_bufq1_id = cpu_to_le16(sets[0].bufq.q_id);
	if (vport->num_bufqs_per_qgrp > IDPF_SINGLE_BUFQ_PER_RXQ_GRP) {
		qi->bufq2_ena = IDPF_BUFQ2_ENA;
		qi->rx_bufq2_id = cpu_to_le16(sets[1].bufq.q_id);
	}

	q->rx_hbuf_size = sets[0].bufq.rx_hbuf_size;

	if (q->rx_hsplit_en) {
		qi->qflags |= cpu_to_le16(VIRTCHNL2_RXQ_HDR_SPLIT);
		qi->hdr_buffer_size = cpu_to_le16(q->rx_hbuf_size);
	}
}

/**
 * idpf_prepare_cfg_rxqs_msg - Prepare message to configure selected rx queues.
 * @vport: virtual port data structure
 * @msg_buf: buffer containing the message
 * @first_chunk: pointer to the first chunk describing the rx queue
 * @num_chunks: number of chunks in the message
 *
 * Helper function for preparing the message describing configuration of
 * rx queues.
 * Returns the total size of the prepared message.
 */
static int idpf_prepare_cfg_rxqs_msg(struct idpf_vport *vport,
				     u8 *msg_buf, u8 *first_chunk,
				     int num_chunks)
{
	int chunk_size = sizeof(struct virtchnl2_rxq_info);
	struct virtchnl2_config_rx_queues *crq;

	crq = (struct virtchnl2_config_rx_queues *)msg_buf;

	crq->vport_id = cpu_to_le32(vport->vport_id);
	crq->num_qinfo = cpu_to_le16(num_chunks);

	memcpy(crq->qinfo, first_chunk, num_chunks * chunk_size);

	return (chunk_size * num_chunks + sizeof(*crq));
}

/**
 * idpf_send_config_selected_rx_queues_msg - Send virtchnl config rx queues
 * message for selected rx queues only.
 * @vport: virtual port data structure
 * @qs: array of rx queues to be configured
 * @num_q: number of rx queues contained in 'qs' array
 *
 * Send config queues virtchnl message for queues contained in 'qs' array.
 * The 'qs' array can contain rx queues (or buffer queues) only.
 * Returns 0 on success, negative on failure.
 */
static int idpf_send_config_selected_rx_queues_msg(struct idpf_vport *vport,
						   struct idpf_queue **qs,
						   int num_q)
{
	struct idpf_chunked_msg_params params = { };
	struct virtchnl2_rxq_info *qi;
	int err, i;

	qi = (struct virtchnl2_rxq_info *)
		kcalloc(num_q, sizeof(struct virtchnl2_rxq_info), GFP_KERNEL);
	if (!qi) {
		err = -ENOMEM;
		goto alloc_error;
	}

	params.op = VIRTCHNL2_OP_CONFIG_RX_QUEUES;
	params.state = IDPF_VC_CONFIG_RXQ;
	params.err_check = IDPF_VC_CONFIG_RXQ_ERR;
	params.timeout = IDPF_WAIT_FOR_EVENT_TIMEO;
	params.config_sz = sizeof(struct virtchnl2_config_rx_queues);
	params.chunk_sz = sizeof(struct virtchnl2_rxq_info);
	params.prepare_msg = &idpf_prepare_cfg_rxqs_msg;
	params.num_chunks = num_q;
	params.chunks = (u8 *)qi;

	for (i = 0; i < num_q; i++)
		idpf_fill_rxbufq_config_chunk(vport, qs[i], &qi[i]);

	err = idpf_send_chunked_msg(vport, &params);
	kfree(qi);
alloc_error:
	return err;
}

/**
 * idpf_send_config_rx_queues_msg - Send virtchnl config rx queues message
 * @vport: virtual port data structure
 *
 * Send config rx queues virtchnl message.  Returns 0 on success, negative on
 * failure.
 */
static int idpf_send_config_rx_queues_msg(struct idpf_vport *vport)
{
	int totqs, err = 0, i, k = 0;
	struct idpf_queue **qs;

	totqs = vport->num_rxq + vport->num_bufq;
	qs = (struct idpf_queue **)kzalloc(totqs * sizeof(*qs), GFP_KERNEL);
	if (!qs)
		return -ENOMEM;

	/* Populate the queue info buffer with all queue context info */
	for (i = 0; i < vport->num_rxq_grp; i++) {
		struct idpf_rxq_group *rx_qgrp = &vport->rxq_grps[i];
		int num_rxq;
		int j;

		if (!idpf_is_queue_model_split(vport->rxq_model))
			goto setup_rxqs;

		for (j = 0; j < vport->num_bufqs_per_qgrp; j++, k++)
			qs[k] = &rx_qgrp->splitq.bufq_sets[j].bufq;

setup_rxqs:
		if (idpf_is_queue_model_split(vport->rxq_model))
			num_rxq = rx_qgrp->splitq.num_rxq_sets;
		else
			num_rxq = rx_qgrp->singleq.num_rxq;

		for (j = 0; j < num_rxq; j++, k++)
			if (!idpf_is_queue_model_split(vport->rxq_model))
				qs[k] = rx_qgrp->singleq.rxqs[j];
			else
				qs[k] = &rx_qgrp->splitq.rxq_sets[j]->rxq;
	}

	/* Make sure accounting agrees */
	if (k != totqs) {
		err = -EINVAL;
		goto error;
	}

	err = idpf_send_config_selected_rx_queues_msg(vport, qs, totqs);

error:
	kfree(qs);
	return err;
}

/**
 * idpf_prepare_ena_dis_qs_msg - Prepare message to enable/disable selected
 * queues.
 * @vport: virtual port data structure
 * @msg_buf: buffer containing the message
 * @first_chunk: pointer to the first chunk describing the queue
 * @num_chunks: number of chunks in the message
 *
 * Helper function for preparing the message describing queues to be enabled
 * or disabled.
 * Returns the total size of the prepared message.
 */
static int idpf_prepare_ena_dis_qs_msg(struct idpf_vport *vport,
				       u8 *msg_buf, u8 *first_chunk,
				       int num_chunks)
{
	int chunk_size = sizeof(struct virtchnl2_queue_chunk);
	struct virtchnl2_del_ena_dis_queues *eq;

	eq = (struct virtchnl2_del_ena_dis_queues *)msg_buf;

	eq->vport_id = cpu_to_le32(vport->vport_id);
	eq->chunks.num_chunks = cpu_to_le16(num_chunks);

	memcpy(eq->chunks.chunks, first_chunk, num_chunks * chunk_size);

	return (chunk_size * num_chunks + sizeof(*eq));
}

/**
 * idpf_send_ena_dis_selected_qs_msg - Send virtchnl enable or disable
 * queues message for selected queues only
 * @vport: virtual port data structure
 * @qs: array containing pointers to queues to be enabled/disabled
 * @num_q: number of queues contained in 'qs' array.
 * @ena: if true enable, false disable
 *
 * Send enable or disable queues virtchnl message for queues contained
 * in 'qs' array.
 * The 'qs' array can contain pointers to both rx and tx queues.
 * Returns 0 on success, negative on failure.
 */
static int idpf_send_ena_dis_selected_qs_msg(struct idpf_vport *vport,
					     struct idpf_queue **qs,
					     int num_q,
					     u32 vc_op)
{
	bool en = vc_op == VIRTCHNL2_OP_ENABLE_QUEUES;
	struct idpf_chunked_msg_params params = { };
	struct virtchnl2_queue_chunk *qc;
	int err, i;

	qc = (struct virtchnl2_queue_chunk *)kzalloc(sizeof(*qc) * num_q,
						     GFP_KERNEL);
	if (!qc) {
		err = -ENOMEM;
		goto alloc_error;
	}

	params.op = vc_op;
	params.state = en ? IDPF_VC_ENA_QUEUES : IDPF_VC_DIS_QUEUES;
	params.err_check = en ? IDPF_VC_ENA_QUEUES_ERR : IDPF_VC_DIS_QUEUES_ERR;
	params.timeout = en ? IDPF_WAIT_FOR_EVENT_TIMEO :
			      IDPF_WAIT_FOR_EVENT_TIMEO_MIN;
	params.config_sz = sizeof(struct virtchnl2_del_ena_dis_queues);
	params.chunk_sz = sizeof(struct virtchnl2_queue_chunk);
	params.prepare_msg = &idpf_prepare_ena_dis_qs_msg;
	params.num_chunks = num_q;
	params.chunks = (u8 *)qc;

	for (i = 0; i < num_q; i++) {
		struct idpf_queue *q = qs[i];

		qc[i].start_queue_id = cpu_to_le32(q->q_id);
		qc[i].type = cpu_to_le32(q->q_type);
		qc[i].num_queues = cpu_to_le32(IDPF_NUMQ_PER_CHUNK);
	}

	err = idpf_send_chunked_msg(vport, &params);
	kfree(qc);
alloc_error:
	return err;
}

/**
 * idpf_send_ena_dis_queues_msg - Send virtchnl enable or disable
 * queues message
 * @vport: virtual port data structure
 * @vc_op: virtchnl op code to send
 *
 * Send enable or disable queues virtchnl message. Returns 0 on success,
 * negative on failure.
 */
static int idpf_send_ena_dis_queues_msg(struct idpf_vport *vport, u32 vc_op)
{
	int num_txq, num_rxq, num_q, err = 0;
	struct idpf_queue **qs;
	int i, j, k = 0;

	num_txq = vport->num_txq + vport->num_complq;
	num_rxq = vport->num_rxq + vport->num_bufq;
	num_q = num_txq + num_rxq;

	qs = (struct idpf_queue **)kzalloc(num_q * sizeof(*qs), GFP_KERNEL);
	if (!qs)
		return -ENOMEM;

	for (i = 0; i < vport->num_txq_grp; i++) {
		struct idpf_txq_group *tx_qgrp = &vport->txq_grps[i];

		for (j = 0; j < tx_qgrp->num_txq; j++, k++)
			qs[k] = tx_qgrp->txqs[j];
	}
	if (vport->num_txq != k) {
		err = -EINVAL;
		goto error;
	}

	if (!idpf_is_queue_model_split(vport->txq_model))
		goto setup_rx;

	for (i = 0; i < vport->num_txq_grp; i++, k++)
		qs[k] = vport->txq_grps[i].complq;

	if (vport->num_complq != (k - vport->num_txq)) {
		err = -EINVAL;
		goto error;
	}

setup_rx:
	for (i = 0; i < vport->num_rxq_grp; i++) {
		struct idpf_rxq_group *rx_qgrp = &vport->rxq_grps[i];

		if (idpf_is_queue_model_split(vport->rxq_model))
			num_rxq = rx_qgrp->splitq.num_rxq_sets;
		else
			num_rxq = rx_qgrp->singleq.num_rxq;

		for (j = 0; j < num_rxq; j++, k++) {
			if (idpf_is_queue_model_split(vport->rxq_model))
				qs[k] = &rx_qgrp->splitq.rxq_sets[j]->rxq;
			else
				qs[k] = rx_qgrp->singleq.rxqs[j];
		}
	}
	if (vport->num_rxq != k - (vport->num_txq + vport->num_complq)) {
		err = -EINVAL;
		goto error;
	}

	if (!idpf_is_queue_model_split(vport->rxq_model))
		goto send_msg;

	for (i = 0; i < vport->num_rxq_grp; i++) {
		struct idpf_rxq_group *rx_qgrp = &vport->rxq_grps[i];

		for (j = 0; j < vport->num_bufqs_per_qgrp; j++, k++)
			qs[k] = &rx_qgrp->splitq.bufq_sets[j].bufq;
	}
	if (vport->num_bufq != k - (vport->num_txq +
				    vport->num_complq +
				    vport->num_rxq)) {
		err = -EINVAL;
		goto error;
	}

send_msg:
	err = idpf_send_ena_dis_selected_qs_msg(vport, qs, num_q, vc_op);
error:
	kfree(qs);
	return err;
}

/**
 * idpf_prep_map_unmap_sel_queue_vector_msg - Prepare message to map or unmap
 * selected queues to the interrupt vector.
 * @vport: virtual port data structure
 * @msg_buf: buffer containing the message
 * @first_chunk: pointer to the first chunk describing the vector mapping
 * @num_chunks: number of chunks in the message
 *
 * Helper function for preparing the message describing mapping queues to
 * q_vectors.
 * Returns the total size of the prepared message.
 */
static int
idpf_prep_map_unmap_sel_queue_vector_msg(struct idpf_vport *vport,
					 u8 *msg_buf, u8 *first_chunk,
					 int num_chunks)
{
	int chunk_size = sizeof(struct virtchnl2_queue_vector);
	struct virtchnl2_queue_vector_maps *vqvm;

	vqvm = (struct virtchnl2_queue_vector_maps *)msg_buf;

	vqvm->vport_id = cpu_to_le32(vport->vport_id);
	vqvm->num_qv_maps = cpu_to_le16(num_chunks);

	memcpy(vqvm->qv_maps, first_chunk, num_chunks * chunk_size);

	return chunk_size * num_chunks + sizeof(*vqvm);
}

/**
 * idpf_send_map_unmap_sel_queue_vector_msg - Send virtchnl map or unmap
 * selected queue vector message
 * @vport: virtual port data structure
 * @qs: array of queues to be mapped/unmapped
 * @num_q: number of queues in 'qs' array
 * @map: true for map and false for unmap
 *
 * Send map or unmap queue vector virtchnl message for selected queues only.
 * Returns 0 on success, negative on failure.
 */
static int idpf_send_map_unmap_sel_queue_vector_msg(struct idpf_vport *vport,
						    struct idpf_queue **qs,
						    int num_q,
						    bool map)
{
	struct idpf_chunked_msg_params params = { };
	struct virtchnl2_queue_vector *vqv;
	int err, i;

	vqv = (struct virtchnl2_queue_vector *)kzalloc(sizeof(*vqv) * num_q,
						       GFP_KERNEL);
	if (!vqv) {
		err = -ENOMEM;
		goto alloc_error;
	}

	params.op = map ? VIRTCHNL2_OP_MAP_QUEUE_VECTOR :
			  VIRTCHNL2_OP_UNMAP_QUEUE_VECTOR;
	params.state = map ? IDPF_VC_MAP_IRQ : IDPF_VC_UNMAP_IRQ;
	params.err_check = map ? IDPF_VC_MAP_IRQ_ERR : IDPF_VC_UNMAP_IRQ_ERR;
	params.timeout = map ? IDPF_WAIT_FOR_EVENT_TIMEO :
			       IDPF_WAIT_FOR_EVENT_TIMEO_MIN;
	params.config_sz = sizeof(struct virtchnl2_queue_vector_maps);
	params.chunk_sz = sizeof(struct virtchnl2_queue_vector);
	params.prepare_msg = &idpf_prep_map_unmap_sel_queue_vector_msg;
	params.num_chunks = num_q;
	params.chunks = (u8 *)vqv;

	for (i = 0; i < num_q; i++) {
		const struct idpf_q_vector *vec;
		struct idpf_queue *q = qs[i];
		u32 vector_id, itr_idx;

		vqv[i].queue_type = cpu_to_le32(q->q_type);
		vqv[i].queue_id = cpu_to_le32(q->q_id);

		if (q->q_type != VIRTCHNL2_QUEUE_TYPE_TX) {
			vector_id = q->q_vector->v_idx;
			itr_idx = q->q_vector->rx_itr_idx;

			goto fill;
		}

		if (idpf_is_queue_model_split(vport->txq_model))
			vec = q->txq_grp->complq->q_vector;
		else
			vec = q->q_vector;

		if (vec) {
			vector_id = vec->v_idx;
			itr_idx = vec->tx_itr_idx;
		} else {
			vector_id = 0;
			itr_idx = VIRTCHNL2_ITR_IDX_1;
		}

fill:
		vqv[i].vector_id = cpu_to_le16(vector_id);
		vqv[i].itr_idx = cpu_to_le32(itr_idx);
	}

	err = idpf_send_chunked_msg(vport, &params);
	kfree(vqv);
alloc_error:
	return err;
}

/**
 * idpf_send_map_unmap_queue_vector_msg - Send virtchnl map or unmap queue
 * vector message
 * @vport: virtual port data structure
 * @map: true for map and false for unmap
 *
 * Send map or unmap queue vector virtchnl message.  Returns 0 on success,
 * negative on failure.
 */
int idpf_send_map_unmap_queue_vector_msg(struct idpf_vport *vport, bool map)
{
	struct idpf_queue **qs;
	int num_q, err = 0;
	int i, j, k = 0;

	num_q = vport->num_txq + vport->num_rxq;

	qs = (struct idpf_queue **)kzalloc(num_q * sizeof(*qs), GFP_KERNEL);
	if (!qs)
		return -ENOMEM;

	for (i = 0; i < vport->num_txq_grp; i++) {
		struct idpf_txq_group *tx_qgrp = &vport->txq_grps[i];

		for (j = 0; j < tx_qgrp->num_txq; j++, k++)
			qs[k] = tx_qgrp->txqs[j];
	}

	if (vport->num_txq != k) {
		err = -EINVAL;
		goto error;
	}

	for (i = 0; i < vport->num_rxq_grp; i++) {
		struct idpf_rxq_group *rx_qgrp = &vport->rxq_grps[i];
		int num_rxq;

		if (idpf_is_queue_model_split(vport->rxq_model))
			num_rxq = rx_qgrp->splitq.num_rxq_sets;
		else
			num_rxq = rx_qgrp->singleq.num_rxq;

		for (j = 0; j < num_rxq; j++, k++) {
			struct idpf_queue *rxq;

			if (idpf_is_queue_model_split(vport->rxq_model))
				rxq = &rx_qgrp->splitq.rxq_sets[j]->rxq;
			else
				rxq = rx_qgrp->singleq.rxqs[j];

			qs[k] = rxq;
		}
	}

	if (idpf_is_queue_model_split(vport->txq_model)) {
		if (vport->num_rxq != k - vport->num_complq) {
			err = -EINVAL;
			goto error;
		}
	} else {
		if (vport->num_rxq != k - vport->num_txq) {
			err = -EINVAL;
			goto error;
		}
	}

	err = idpf_send_map_unmap_sel_queue_vector_msg(vport, qs, num_q, map);
error:
	kfree(qs);
	return err;
}

/**
 * idpf_send_enable_queues_msg - send enable queues virtchnl message
 * @vport: Virtual port private data structure
 *
 * Will send enable queues virtchnl message.  Returns 0 on success, negative on
 * failure.
 */
int idpf_send_enable_queues_msg(struct idpf_vport *vport)
{
	return idpf_send_ena_dis_queues_msg(vport, VIRTCHNL2_OP_ENABLE_QUEUES);
}

/**
 * idpf_send_disable_queues_msg - send disable queues virtchnl message
 * @vport: Virtual port private data structure
 *
 * Will send disable queues virtchnl message.  Returns 0 on success, negative
 * on failure.
 */
int idpf_send_disable_queues_msg(struct idpf_vport *vport)
{
	int err;

	err = idpf_send_ena_dis_queues_msg(vport, VIRTCHNL2_OP_DISABLE_QUEUES);
	if (err)
		return err;

	return idpf_wait_for_marker_event(vport);
}

/**
 * idpf_send_enable_selected_queues_msg - send enable queues virtchnl message
 * for selected queues only
 * @vport: Virtual port private data structure
 * @qs: array containing queues to be enabled
 * @num_q: number of queues in the 'qs' array
 *
 * Will send enable queues virtchnl message for queues contained in 'qs' table.
 * Returns 0 on success, negative on failure.
 */
int idpf_send_enable_selected_queues_msg(struct idpf_vport *vport,
					 struct idpf_queue **qs,
					 int num_q)
{
	return idpf_send_ena_dis_selected_qs_msg(vport, qs, num_q,
						 VIRTCHNL2_OP_ENABLE_QUEUES);
}

/**
 * idpf_send_disable_selected_queues_msg - send disable queues virtchnl message
 * for selected queues only
 * @vport: Virtual port private data structure
 * @qs: array containing queues to be disabled
 * @num_q: number of queues in the 'qs' array
 *
 * Will send disable queues virtchnl message for queues contained in 'qs' table.
 * Returns 0 on success, negative on failure.
 */
int idpf_send_disable_selected_queues_msg(struct idpf_vport *vport,
					  struct idpf_queue **qs,
					  int num_q)
{
	struct idpf_queue **tx_qs;
	int err, i, tx_idx = 0;

	err = idpf_send_ena_dis_selected_qs_msg(vport, qs, num_q,
						VIRTCHNL2_OP_DISABLE_QUEUES);
	if (err)
		return err;

	tx_qs = (struct idpf_queue **)kzalloc(num_q * sizeof(*qs), GFP_KERNEL);
	if (!tx_qs)
		return -ENOMEM;

	for (i = 0; i < num_q; i++)
		if (qs[i]->q_type == VIRTCHNL2_QUEUE_TYPE_TX)
			tx_qs[tx_idx++] = qs[i];

	err = idpf_wait_for_selected_marker_events(vport, tx_qs, tx_idx);

	kfree(tx_qs);
	return err;
}

/**
 * idpf_send_config_selected_queues_msg - Send virtchnl config queues message
 * for selected queues only.
 * @vport: virtual port data structure
 * @qs: array of queues to be configured
 * @num_q: number of queues contained in 'qs' array
 *
 * Send config queues virtchnl message for queues contained in 'qs' array.
 * The 'qs' array can contain both RX or TX queues.
 * Returns 0 on success, negative on failure.
 */
int idpf_send_config_selected_queues_msg(struct idpf_vport *vport,
					 struct idpf_queue **qs,
					 int num_q)
{
	int num_rxq = 0, num_txq = 0, i, err;
	struct idpf_queue **txqs, **rxqs;

	txqs = (struct idpf_queue **)kzalloc(num_q * sizeof(*qs), GFP_KERNEL);
	if (!txqs)
		return -ENOMEM;

	rxqs = (struct idpf_queue **)kzalloc(num_q * sizeof(*qs), GFP_KERNEL);
	if (!rxqs) {
		err = -ENOMEM;
		goto rxq_alloc_err;
	}

	for (i = 0; i < num_q; i++) {
		struct idpf_queue *q = qs[i];

		if (q->q_type == VIRTCHNL2_QUEUE_TYPE_TX ||
		    q->q_type == VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION) {
			txqs[num_txq] = q;
			num_txq++;
		}
		else if (q->q_type == VIRTCHNL2_QUEUE_TYPE_RX ||
			 q->q_type == VIRTCHNL2_QUEUE_TYPE_RX_BUFFER) {
			rxqs[num_rxq] = q;
			num_rxq++;
		}
	}

	err = idpf_send_config_selected_tx_queues_msg(vport, txqs, num_txq);
	if (err)
		goto send_txq_err;

	err = idpf_send_config_selected_rx_queues_msg(vport, rxqs, num_rxq);

send_txq_err:
	kfree(rxqs);
rxq_alloc_err:
	kfree(txqs);

	return err;
}

/**
 * idpf_convert_reg_to_queue_chunks - Copy queue chunk information to the right
 * structure
 * @dchunks: Destination chunks to store data to
 * @schunks: Source chunks to copy data from
 * @num_chunks: number of chunks to copy
 */
static void idpf_convert_reg_to_queue_chunks(struct virtchnl2_queue_chunk *dchunks,
					     struct virtchnl2_queue_reg_chunk *schunks,
					     u16 num_chunks)
{
	u16 i;

	for (i = 0; i < num_chunks; i++) {
		dchunks[i].type = schunks[i].type;
		dchunks[i].start_queue_id = schunks[i].start_queue_id;
		dchunks[i].num_queues = schunks[i].num_queues;
	}
}

/**
 * idpf_send_delete_queues_msg - send delete queues virtchnl message
 * @vport: Virtual port private data structure
 *
 * Will send delete queues virtchnl message. Return 0 on success, negative on
 * failure.
 */
int idpf_send_delete_queues_msg(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_create_vport *vport_params;
	struct virtchnl2_queue_reg_chunks *chunks;
	struct virtchnl2_del_ena_dis_queues *eq;
	struct idpf_vport_config *vport_config;
	u16 vport_idx = vport->idx;
	int buf_size, err;
	u16 num_chunks;

	vport_config = adapter->vport_config[vport_idx];
	if (vport_config->req_qs_chunks) {
		struct virtchnl2_add_queues *vc_aq =
			(struct virtchnl2_add_queues *)vport_config->req_qs_chunks;
		chunks = &vc_aq->chunks;
	} else {
		vport_params = adapter->vport_params_recvd[vport_idx];
		chunks = &vport_params->chunks;
	}

	num_chunks = le16_to_cpu(chunks->num_chunks);
	buf_size = struct_size(eq, chunks.chunks, num_chunks);

	eq = kzalloc(buf_size, GFP_KERNEL);
	if (!eq)
		return -ENOMEM;

	eq->vport_id = cpu_to_le32(vport->vport_id);
	eq->chunks.num_chunks = cpu_to_le16(num_chunks);

	idpf_convert_reg_to_queue_chunks(eq->chunks.chunks, chunks->chunks,
					 num_chunks);

	mutex_lock(&vport->vc_buf_lock);

	err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_DEL_QUEUES,
			       buf_size, (u8 *)eq);
	if (err)
		goto rel_lock;

	err = idpf_min_wait_for_event(adapter, vport, IDPF_VC_DEL_QUEUES,
				      IDPF_VC_DEL_QUEUES_ERR);

rel_lock:
	mutex_unlock(&vport->vc_buf_lock);
	kfree(eq);

	return err;
}

/**
 * idpf_send_config_queues_msg - Send config queues virtchnl message
 * @vport: Virtual port private data structure
 *
 * Will send config queues virtchnl message. Returns 0 on success, negative on
 * failure.
 */
int idpf_send_config_queues_msg(struct idpf_vport *vport)
{
	int err;

	err = idpf_send_config_tx_queues_msg(vport);
	if (err)
		return err;

	return idpf_send_config_rx_queues_msg(vport);
}

/**
 * idpf_send_add_queues_msg - Send virtchnl add queues message
 * @vport: Virtual port private data structure
 * @num_tx_q: number of transmit queues
 * @num_complq: number of transmit completion queues
 * @num_rx_q: number of receive queues
 * @num_rx_bufq: number of receive buffer queues
 *
 * Returns 0 on success, negative on failure. vport _MUST_ be const here as
 * we should not change any fields within vport itself in this function.
 */
int idpf_send_add_queues_msg(const struct idpf_vport *vport, u16 num_tx_q,
			     u16 num_complq, u16 num_rx_q, u16 num_rx_bufq)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct idpf_vport_config *vport_config;
	struct virtchnl2_add_queues aq = { };
	struct virtchnl2_add_queues *vc_msg;
	u16 vport_idx = vport->idx;
	int size, err;

	vport_config = adapter->vport_config[vport_idx];

	aq.vport_id = cpu_to_le32(vport->vport_id);
	aq.num_tx_q = cpu_to_le16(num_tx_q);
	aq.num_tx_complq = cpu_to_le16(num_complq);
	aq.num_rx_q = cpu_to_le16(num_rx_q);
	aq.num_rx_bufq = cpu_to_le16(num_rx_bufq);

	mutex_lock(&((struct idpf_vport *)vport)->vc_buf_lock);

	err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_ADD_QUEUES,
			       sizeof(struct virtchnl2_add_queues), (u8 *)&aq);
	if (err)
		goto rel_lock;

	/* We want vport to be const to prevent incidental code changes making
	 * changes to the vport config. We're making a special exception here
	 * to discard const to use the virtchnl.
	 */
	err = idpf_wait_for_event(adapter, (struct idpf_vport *)vport,
				  IDPF_VC_ADD_QUEUES, IDPF_VC_ADD_QUEUES_ERR);
	if (err)
		goto rel_lock;

	kfree(vport_config->req_qs_chunks);
	vport_config->req_qs_chunks = NULL;

	vc_msg = (struct virtchnl2_add_queues *)vport->vc_msg;
	/* compare vc_msg num queues with vport num queues */
	if (le16_to_cpu(vc_msg->num_tx_q) != num_tx_q ||
	    le16_to_cpu(vc_msg->num_rx_q) != num_rx_q ||
	    le16_to_cpu(vc_msg->num_tx_complq) != num_complq ||
	    le16_to_cpu(vc_msg->num_rx_bufq) != num_rx_bufq) {
		err = -EINVAL;
		goto rel_lock;
	}

	size = struct_size(vc_msg, chunks.chunks,
			   le16_to_cpu(vc_msg->chunks.num_chunks));
	vport_config->req_qs_chunks = kmemdup(vc_msg, size, GFP_KERNEL);
	if (!vport_config->req_qs_chunks) {
		err = -ENOMEM;
		goto rel_lock;
	}

rel_lock:
	mutex_unlock(&((struct idpf_vport *)vport)->vc_buf_lock);

	return err;
}

/**
 * idpf_send_alloc_vectors_msg - Send virtchnl alloc vectors message
 * @adapter: Driver specific private structure
 * @num_vectors: number of vectors to be allocated
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_alloc_vectors_msg(struct idpf_adapter *adapter, u16 num_vectors)
{
	struct virtchnl2_alloc_vectors *alloc_vec, *rcvd_vec;
	struct virtchnl2_alloc_vectors ac = { };
	u16 num_vchunks;
	int size, err;

	ac.num_vectors = cpu_to_le16(num_vectors);

	mutex_lock(&adapter->vc_buf_lock);

	err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_ALLOC_VECTORS,
			       sizeof(ac), (u8 *)&ac);
	if (err)
		goto rel_lock;

	err = idpf_wait_for_event(adapter, NULL, IDPF_VC_ALLOC_VECTORS,
				  IDPF_VC_ALLOC_VECTORS_ERR);
	if (err)
		goto rel_lock;

	rcvd_vec = (struct virtchnl2_alloc_vectors *)adapter->vc_msg;
	num_vchunks = le16_to_cpu(rcvd_vec->vchunks.num_vchunks);

	size = struct_size(rcvd_vec, vchunks.vchunks, num_vchunks);
	if (size > sizeof(adapter->vc_msg)) {
		err = -EINVAL;
		goto rel_lock;
	}

	kfree(adapter->req_vec_chunks);
	adapter->req_vec_chunks = NULL;
	adapter->req_vec_chunks = kmemdup(adapter->vc_msg, size, GFP_KERNEL);
	if (!adapter->req_vec_chunks) {
		err = -ENOMEM;
		goto rel_lock;
	}

	alloc_vec = adapter->req_vec_chunks;
	if (le16_to_cpu(alloc_vec->num_vectors) < num_vectors) {
		kfree(adapter->req_vec_chunks);
		adapter->req_vec_chunks = NULL;
		err = -EINVAL;
	}

rel_lock:
	mutex_unlock(&adapter->vc_buf_lock);

	return err;
}

/**
 * idpf_send_dealloc_vectors_msg - Send virtchnl de allocate vectors message
 * @adapter: Driver specific private structure
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_dealloc_vectors_msg(struct idpf_adapter *adapter)
{
	struct virtchnl2_alloc_vectors *ac = adapter->req_vec_chunks;
	struct virtchnl2_vector_chunks *vcs = &ac->vchunks;
	int buf_size, err;

	buf_size = struct_size(vcs, vchunks, le16_to_cpu(vcs->num_vchunks));

	mutex_lock(&adapter->vc_buf_lock);

	err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_DEALLOC_VECTORS, buf_size,
			       (u8 *)vcs);
	if (err)
		goto rel_lock;

	err = idpf_min_wait_for_event(adapter, NULL, IDPF_VC_DEALLOC_VECTORS,
				      IDPF_VC_DEALLOC_VECTORS_ERR);
	if (err)
		goto rel_lock;

	kfree(adapter->req_vec_chunks);
	adapter->req_vec_chunks = NULL;

rel_lock:
	mutex_unlock(&adapter->vc_buf_lock);

	return err;
}

/**
 * idpf_get_max_vfs - Get max number of vfs supported
 * @adapter: Driver specific private structure
 *
 * Returns max number of VFs
 */
static int idpf_get_max_vfs(struct idpf_adapter *adapter)
{
	return le16_to_cpu(adapter->caps.max_sriov_vfs);
}

/**
 * idpf_send_set_sriov_vfs_msg - Send virtchnl set sriov vfs message
 * @adapter: Driver specific private structure
 * @num_vfs: number of virtual functions to be created
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_set_sriov_vfs_msg(struct idpf_adapter *adapter, u16 num_vfs)
{
	struct virtchnl2_sriov_vfs_info svi = { };
	int err;

	svi.num_vfs = cpu_to_le16(num_vfs);

	mutex_lock(&adapter->vc_buf_lock);

	err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_SET_SRIOV_VFS,
			       sizeof(svi), (u8 *)&svi);
	if (err)
		goto rel_lock;

	err = idpf_wait_for_event(adapter, NULL, IDPF_VC_SET_SRIOV_VFS,
				  IDPF_VC_SET_SRIOV_VFS_ERR);

rel_lock:
	mutex_unlock(&adapter->vc_buf_lock);

	return err;
}

/**
 * idpf_send_get_stats_msg - Send virtchnl get statistics message
 * @vport: vport to get stats for
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_get_stats_msg(struct idpf_vport *vport)
{
	struct idpf_netdev_priv *np = netdev_priv(vport->netdev);
	struct rtnl_link_stats64 *netstats = &np->netstats;
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_vport_stats stats_msg = { };
	struct virtchnl2_vport_stats *stats;
	int err;

	/* Don't send get_stats message if the link is down */
	if (np->state <= __IDPF_VPORT_DOWN)
		return 0;

	stats_msg.vport_id = cpu_to_le32(vport->vport_id);

	mutex_lock(&vport->vc_buf_lock);

	err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_GET_STATS,
			       sizeof(struct virtchnl2_vport_stats),
			       (u8 *)&stats_msg);
	if (err)
		goto rel_lock;

	err = idpf_wait_for_event(adapter, vport, IDPF_VC_GET_STATS,
				  IDPF_VC_GET_STATS_ERR);
	if (err)
		goto rel_lock;

	stats = (struct virtchnl2_vport_stats *)vport->vc_msg;

	spin_lock_bh(&np->stats_lock);

	netstats->rx_packets = le64_to_cpu(stats->rx_unicast) +
			       le64_to_cpu(stats->rx_multicast) +
			       le64_to_cpu(stats->rx_broadcast);
	netstats->rx_bytes = le64_to_cpu(stats->rx_bytes);
	netstats->rx_dropped = le64_to_cpu(stats->rx_discards);
	netstats->rx_over_errors = le64_to_cpu(stats->rx_overflow_drop);
	netstats->rx_length_errors = le64_to_cpu(stats->rx_invalid_frame_length);

	netstats->tx_packets = le64_to_cpu(stats->tx_unicast) +
			       le64_to_cpu(stats->tx_multicast) +
			       le64_to_cpu(stats->tx_broadcast);
	netstats->tx_bytes = le64_to_cpu(stats->tx_bytes);
	netstats->tx_errors = le64_to_cpu(stats->tx_errors);
	netstats->tx_dropped = le64_to_cpu(stats->tx_discards);

	vport->port_stats.vport_stats = *stats;

	spin_unlock_bh(&np->stats_lock);

rel_lock:
	mutex_unlock(&vport->vc_buf_lock);

	return err;
}

/**
 * idpf_send_get_set_rss_lut_msg - Send virtchnl get or set rss lut message
 * @vport: virtual port data structure
 * @get: flag to set or get rss look up table
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_get_set_rss_lut_msg(struct idpf_vport *vport, bool get)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_rss_lut *recv_rl;
	struct idpf_rss_data *rss_data;
	struct virtchnl2_rss_lut *rl;
	int buf_size, lut_buf_size;
	int i, err;

	rss_data = &adapter->vport_config[vport->idx]->user_config.rss_data;
	buf_size = struct_size(rl, lut, rss_data->rss_lut_size);
	rl = kzalloc(buf_size, GFP_KERNEL);
	if (!rl)
		return -ENOMEM;

	rl->vport_id = cpu_to_le32(vport->vport_id);
	mutex_lock(&vport->vc_buf_lock);

	if (!get) {
		rl->lut_entries = cpu_to_le16(rss_data->rss_lut_size);
		for (i = 0; i < rss_data->rss_lut_size; i++)
			rl->lut[i] = cpu_to_le32(rss_data->rss_lut[i]);

		err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_SET_RSS_LUT,
				       buf_size, (u8 *)rl);
		if (err)
			goto free_mem;

		err = idpf_wait_for_event(adapter, vport, IDPF_VC_SET_RSS_LUT,
					  IDPF_VC_SET_RSS_LUT_ERR);

		goto free_mem;
	}

	err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_GET_RSS_LUT,
			       buf_size, (u8 *)rl);
	if (err)
		goto free_mem;

	err = idpf_wait_for_event(adapter, vport, IDPF_VC_GET_RSS_LUT,
				  IDPF_VC_GET_RSS_LUT_ERR);
	if (err)
		goto free_mem;

	recv_rl = (struct virtchnl2_rss_lut *)vport->vc_msg;
	if (rss_data->rss_lut_size == le16_to_cpu(recv_rl->lut_entries))
		goto do_memcpy;

	rss_data->rss_lut_size = le16_to_cpu(recv_rl->lut_entries);
	kfree(rss_data->rss_lut);

	lut_buf_size = rss_data->rss_lut_size * sizeof(u32);
	rss_data->rss_lut = kzalloc(lut_buf_size, GFP_KERNEL);
	if (!rss_data->rss_lut) {
		rss_data->rss_lut_size = 0;
		err = -ENOMEM;
		goto free_mem;
	}

do_memcpy:
	memcpy(rss_data->rss_lut, vport->vc_msg, rss_data->rss_lut_size);
free_mem:
	mutex_unlock(&vport->vc_buf_lock);
	kfree(rl);

	return err;
}

/**
 * idpf_send_get_set_rss_key_msg - Send virtchnl get or set rss key message
 * @vport: virtual port data structure
 * @get: flag to set or get rss look up table
 *
 * Returns 0 on success, negative on failure
 */
int idpf_send_get_set_rss_key_msg(struct idpf_vport *vport, bool get)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_rss_key *recv_rk;
	struct idpf_rss_data *rss_data;
	struct virtchnl2_rss_key *rk;
	int i, buf_size, err;

	rss_data = &adapter->vport_config[vport->idx]->user_config.rss_data;
	buf_size = struct_size(rk, key_flex, rss_data->rss_key_size);
	rk = kzalloc(buf_size, GFP_KERNEL);
	if (!rk)
		return -ENOMEM;

	rk->vport_id = cpu_to_le32(vport->vport_id);
	mutex_lock(&vport->vc_buf_lock);

	if (get) {
		err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_GET_RSS_KEY,
				       buf_size, (u8 *)rk);
		if (err)
			goto error;

		err = idpf_wait_for_event(adapter, vport, IDPF_VC_GET_RSS_KEY,
					  IDPF_VC_GET_RSS_KEY_ERR);
		if (err)
			goto error;

		recv_rk = (struct virtchnl2_rss_key *)vport->vc_msg;
		if (rss_data->rss_key_size !=
		    le16_to_cpu(recv_rk->key_len)) {
			rss_data->rss_key_size =
				min_t(u16, NETDEV_RSS_KEY_LEN,
				      le16_to_cpu(recv_rk->key_len));
			kfree(rss_data->rss_key);
			rss_data->rss_key = kzalloc(rss_data->rss_key_size,
						    GFP_KERNEL);
			if (!rss_data->rss_key) {
				rss_data->rss_key_size = 0;
				err = -ENOMEM;
				goto error;
			}
		}
		memcpy(rss_data->rss_key, recv_rk->key_flex,
		       rss_data->rss_key_size);
	} else {
		rk->key_len = cpu_to_le16(rss_data->rss_key_size);
		for (i = 0; i < rss_data->rss_key_size; i++)
			rk->key_flex[i] = rss_data->rss_key[i];

		err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_SET_RSS_KEY,
				       buf_size, (u8 *)rk);
		if (err)
			goto error;

		err = idpf_wait_for_event(adapter, vport, IDPF_VC_SET_RSS_KEY,
					  IDPF_VC_SET_RSS_KEY_ERR);
	}

error:
	mutex_unlock(&vport->vc_buf_lock);
	kfree(rk);

	return err;
}

/**
 * idpf_fill_ptype_lookup - Fill L3 specific fields in ptype lookup table
 * @ptype: ptype lookup table
 * @pstate: state machine for ptype lookup table
 * @ipv4: ipv4 or ipv6
 * @frag: fragmentation allowed
 *
 */
static void idpf_fill_ptype_lookup(struct libie_rx_ptype_parsed *ptype,
				   struct idpf_ptype_state *pstate,
				   bool ipv4, bool frag)
{
	if (!pstate->outer_ip || !pstate->outer_frag) {
		pstate->outer_ip = true;

		if (ipv4)
			ptype->outer_ip = LIBIE_RX_PTYPE_OUTER_IPV4;
		else
			ptype->outer_ip = LIBIE_RX_PTYPE_OUTER_IPV6;

		if (frag) {
			ptype->outer_frag = LIBIE_RX_PTYPE_FRAG;
			pstate->outer_frag = true;
		}
	} else {
		ptype->tunnel_type = LIBIE_RX_PTYPE_TUNNEL_IP_IP;
		pstate->tunnel_state = IDPF_PTYPE_TUNNEL_IP;

		if (ipv4)
			ptype->tunnel_end_prot =
					LIBIE_RX_PTYPE_TUNNEL_END_IPV4;
		else
			ptype->tunnel_end_prot =
					LIBIE_RX_PTYPE_TUNNEL_END_IPV6;

		if (frag)
			ptype->tunnel_end_frag = LIBIE_RX_PTYPE_FRAG;
	}
}

static void idpf_finalize_ptype_lookup(struct libie_rx_ptype_parsed *ptype)
{
	if (ptype->payload_layer == LIBIE_RX_PTYPE_PAYLOAD_L2 &&
	    ptype->inner_prot)
		ptype->payload_layer = LIBIE_RX_PTYPE_PAYLOAD_L4;
	else if (ptype->payload_layer == LIBIE_RX_PTYPE_PAYLOAD_L2 &&
		 ptype->outer_ip)
		ptype->payload_layer = LIBIE_RX_PTYPE_PAYLOAD_L3;
	else if (ptype->outer_ip == LIBIE_RX_PTYPE_OUTER_L2)
		ptype->payload_layer = LIBIE_RX_PTYPE_PAYLOAD_L2;
	else
		ptype->payload_layer = LIBIE_RX_PTYPE_PAYLOAD_NONE;
}

/**
 * idpf_send_get_rx_ptype_msg - Send virtchnl for ptype info
 * @vport: virtual port data structure
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_get_rx_ptype_msg(struct idpf_vport *vport)
{
	struct libie_rx_ptype_parsed *ptype_lkup = vport->rx_ptype_lkup;
	struct virtchnl2_get_ptype_info get_ptype_info;
	int max_ptype, ptypes_recvd = 0, ptype_offset;
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_get_ptype_info *ptype_info;
	u16 next_ptype_id = 0;
	int err = 0, i, j, k;

	if (idpf_is_queue_model_split(vport->rxq_model))
		max_ptype = IDPF_RX_MAX_PTYPE;
	else
		max_ptype = IDPF_RX_MAX_BASE_PTYPE;

	memset(vport->rx_ptype_lkup, 0, sizeof(vport->rx_ptype_lkup));

	ptype_info = kzalloc(IDPF_CTLQ_MAX_BUF_LEN, GFP_KERNEL);
	if (!ptype_info)
		return -ENOMEM;

	mutex_lock(&adapter->vc_buf_lock);

	while (next_ptype_id < max_ptype) {
		get_ptype_info.start_ptype_id = cpu_to_le16(next_ptype_id);

		if ((next_ptype_id + IDPF_RX_MAX_PTYPES_PER_BUF) > max_ptype)
			get_ptype_info.num_ptypes =
				cpu_to_le16(max_ptype - next_ptype_id);
		else
			get_ptype_info.num_ptypes =
				cpu_to_le16(IDPF_RX_MAX_PTYPES_PER_BUF);

		err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_GET_PTYPE_INFO,
				       sizeof(struct virtchnl2_get_ptype_info),
				       (u8 *)&get_ptype_info);
		if (err)
			goto vc_buf_unlock;

		err = idpf_wait_for_event(adapter, NULL, IDPF_VC_GET_PTYPE_INFO,
					  IDPF_VC_GET_PTYPE_INFO_ERR);
		if (err)
			goto vc_buf_unlock;

		memcpy(ptype_info, adapter->vc_msg, IDPF_CTLQ_MAX_BUF_LEN);

		ptypes_recvd += le16_to_cpu(ptype_info->num_ptypes);
		if (ptypes_recvd > max_ptype) {
			err = -EINVAL;
			goto vc_buf_unlock;
		}

		next_ptype_id = le16_to_cpu(get_ptype_info.start_ptype_id) +
				le16_to_cpu(get_ptype_info.num_ptypes);

		ptype_offset = IDPF_RX_PTYPE_HDR_SZ;

		for (i = 0; i < le16_to_cpu(ptype_info->num_ptypes); i++) {
			struct idpf_ptype_state pstate = { };
			struct virtchnl2_ptype *ptype;
			u16 id;

			ptype = (struct virtchnl2_ptype *)
					((u8 *)ptype_info + ptype_offset);

			ptype_offset += IDPF_GET_PTYPE_SIZE(ptype);
			if (ptype_offset > IDPF_CTLQ_MAX_BUF_LEN) {
				err = -EINVAL;
				goto vc_buf_unlock;
			}

			/* 0xFFFF indicates end of ptypes */
			if (le16_to_cpu(ptype->ptype_id_10) ==
							IDPF_INVALID_PTYPE_ID) {
				err = 0;
				goto vc_buf_unlock;
			}

			if (idpf_is_queue_model_split(vport->rxq_model))
				k = le16_to_cpu(ptype->ptype_id_10);
			else
				k = ptype->ptype_id_8;

			for (j = 0; j < ptype->proto_id_count; j++) {
				id = le16_to_cpu(ptype->proto_id[j]);
				switch (id) {
				case VIRTCHNL2_PROTO_HDR_GRE:
					if (pstate.tunnel_state ==
							IDPF_PTYPE_TUNNEL_IP) {
						ptype_lkup[k].tunnel_type =
						LIBIE_RX_PTYPE_TUNNEL_IP_GRENAT;
						pstate.tunnel_state |=
						IDPF_PTYPE_TUNNEL_IP_GRENAT;
					}
					break;
				case VIRTCHNL2_PROTO_HDR_MAC:
					ptype_lkup[k].outer_ip =
						LIBIE_RX_PTYPE_OUTER_L2;
					if (pstate.tunnel_state ==
							IDPF_TUN_IP_GRE) {
						ptype_lkup[k].tunnel_type =
						LIBIE_RX_PTYPE_TUNNEL_IP_GRENAT_MAC;
						pstate.tunnel_state |=
						IDPF_PTYPE_TUNNEL_IP_GRENAT_MAC;
					}
					break;
				case VIRTCHNL2_PROTO_HDR_IPV4:
					idpf_fill_ptype_lookup(&ptype_lkup[k],
							       &pstate, true,
							       false);
					break;
				case VIRTCHNL2_PROTO_HDR_IPV6:
					idpf_fill_ptype_lookup(&ptype_lkup[k],
							       &pstate, false,
							       false);
					break;
				case VIRTCHNL2_PROTO_HDR_IPV4_FRAG:
					idpf_fill_ptype_lookup(&ptype_lkup[k],
							       &pstate, true,
							       true);
					break;
				case VIRTCHNL2_PROTO_HDR_IPV6_FRAG:
					idpf_fill_ptype_lookup(&ptype_lkup[k],
							       &pstate, false,
							       true);
					break;
				case VIRTCHNL2_PROTO_HDR_UDP:
					ptype_lkup[k].inner_prot =
					LIBIE_RX_PTYPE_INNER_UDP;
					break;
				case VIRTCHNL2_PROTO_HDR_TCP:
					ptype_lkup[k].inner_prot =
					LIBIE_RX_PTYPE_INNER_TCP;
					break;
				case VIRTCHNL2_PROTO_HDR_SCTP:
					ptype_lkup[k].inner_prot =
					LIBIE_RX_PTYPE_INNER_SCTP;
					break;
				case VIRTCHNL2_PROTO_HDR_ICMP:
					ptype_lkup[k].inner_prot =
					LIBIE_RX_PTYPE_INNER_ICMP;
					break;
				case VIRTCHNL2_PROTO_HDR_PAY:
					ptype_lkup[k].payload_layer =
						LIBIE_RX_PTYPE_PAYLOAD_L2;
					break;
				case VIRTCHNL2_PROTO_HDR_ICMPV6:
				case VIRTCHNL2_PROTO_HDR_IPV6_EH:
				case VIRTCHNL2_PROTO_HDR_PRE_MAC:
				case VIRTCHNL2_PROTO_HDR_POST_MAC:
				case VIRTCHNL2_PROTO_HDR_ETHERTYPE:
				case VIRTCHNL2_PROTO_HDR_SVLAN:
				case VIRTCHNL2_PROTO_HDR_CVLAN:
				case VIRTCHNL2_PROTO_HDR_MPLS:
				case VIRTCHNL2_PROTO_HDR_MMPLS:
				case VIRTCHNL2_PROTO_HDR_PTP:
				case VIRTCHNL2_PROTO_HDR_CTRL:
				case VIRTCHNL2_PROTO_HDR_LLDP:
				case VIRTCHNL2_PROTO_HDR_ARP:
				case VIRTCHNL2_PROTO_HDR_ECP:
				case VIRTCHNL2_PROTO_HDR_EAPOL:
				case VIRTCHNL2_PROTO_HDR_PPPOD:
				case VIRTCHNL2_PROTO_HDR_PPPOE:
				case VIRTCHNL2_PROTO_HDR_IGMP:
				case VIRTCHNL2_PROTO_HDR_AH:
				case VIRTCHNL2_PROTO_HDR_ESP:
				case VIRTCHNL2_PROTO_HDR_IKE:
				case VIRTCHNL2_PROTO_HDR_NATT_KEEP:
				case VIRTCHNL2_PROTO_HDR_L2TPV2:
				case VIRTCHNL2_PROTO_HDR_L2TPV2_CONTROL:
				case VIRTCHNL2_PROTO_HDR_L2TPV3:
				case VIRTCHNL2_PROTO_HDR_GTP:
				case VIRTCHNL2_PROTO_HDR_GTP_EH:
				case VIRTCHNL2_PROTO_HDR_GTPCV2:
				case VIRTCHNL2_PROTO_HDR_GTPC_TEID:
				case VIRTCHNL2_PROTO_HDR_GTPU:
				case VIRTCHNL2_PROTO_HDR_GTPU_UL:
				case VIRTCHNL2_PROTO_HDR_GTPU_DL:
				case VIRTCHNL2_PROTO_HDR_ECPRI:
				case VIRTCHNL2_PROTO_HDR_VRRP:
				case VIRTCHNL2_PROTO_HDR_OSPF:
				case VIRTCHNL2_PROTO_HDR_TUN:
				case VIRTCHNL2_PROTO_HDR_NVGRE:
				case VIRTCHNL2_PROTO_HDR_VXLAN:
				case VIRTCHNL2_PROTO_HDR_VXLAN_GPE:
				case VIRTCHNL2_PROTO_HDR_GENEVE:
				case VIRTCHNL2_PROTO_HDR_NSH:
				case VIRTCHNL2_PROTO_HDR_QUIC:
				case VIRTCHNL2_PROTO_HDR_PFCP:
				case VIRTCHNL2_PROTO_HDR_PFCP_NODE:
				case VIRTCHNL2_PROTO_HDR_PFCP_SESSION:
				case VIRTCHNL2_PROTO_HDR_RTP:
				case VIRTCHNL2_PROTO_HDR_NO_PROTO:
					break;
				default:
					break;
				}
			}

			idpf_finalize_ptype_lookup(&ptype_lkup[k]);
		}
	}

vc_buf_unlock:
	mutex_unlock(&adapter->vc_buf_lock);
	kfree(ptype_info);

	return err;
}

/**
 * idpf_send_ena_dis_loopback_msg - Send virtchnl enable/disable loopback
 *				    message
 * @vport: virtual port data structure
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_ena_dis_loopback_msg(struct idpf_vport *vport)
{
	struct virtchnl2_loopback loopback;
	int err;

	loopback.vport_id = cpu_to_le32(vport->vport_id);
	loopback.enable = idpf_is_feature_ena(vport, NETIF_F_LOOPBACK);

	mutex_lock(&vport->vc_buf_lock);

	err = idpf_send_mb_msg(vport->adapter, VIRTCHNL2_OP_LOOPBACK,
			       sizeof(loopback), (u8 *)&loopback);
	if (err)
		goto rel_lock;

	err = idpf_wait_for_event(vport->adapter, vport,
				  IDPF_VC_LOOPBACK_STATE,
				  IDPF_VC_LOOPBACK_STATE_ERR);

rel_lock:
	mutex_unlock(&vport->vc_buf_lock);

	return err;
}

/**
 * idpf_find_ctlq - Given a type and id, find ctlq info
 * @hw: hardware struct
 * @type: type of ctrlq to find
 * @id: ctlq id to find
 *
 * Returns pointer to found ctlq info struct, NULL otherwise.
 */
static struct idpf_ctlq_info *idpf_find_ctlq(struct idpf_hw *hw,
					     enum idpf_ctlq_type type, int id)
{
	struct idpf_ctlq_info *cq, *tmp;

	list_for_each_entry_safe(cq, tmp, &hw->cq_list_head, cq_list)
		if (cq->q_id == id && cq->cq_type == type)
			return cq;

	return NULL;
}

/**
 * idpf_init_dflt_mbx - Setup default mailbox parameters and make request
 * @adapter: adapter info struct
 *
 * Returns 0 on success, negative otherwise
 */
int idpf_init_dflt_mbx(struct idpf_adapter *adapter)
{
	struct idpf_ctlq_create_info ctlq_info[] = {
		{
			.type = IDPF_CTLQ_TYPE_MAILBOX_TX,
			.id = IDPF_DFLT_MBX_ID,
			.len = IDPF_DFLT_MBX_Q_LEN,
			.buf_size = IDPF_CTLQ_MAX_BUF_LEN
		},
		{
			.type = IDPF_CTLQ_TYPE_MAILBOX_RX,
			.id = IDPF_DFLT_MBX_ID,
			.len = IDPF_DFLT_MBX_Q_LEN,
			.buf_size = IDPF_CTLQ_MAX_BUF_LEN
		}
	};
	struct idpf_hw *hw = &adapter->hw;
	int err;

	adapter->dev_ops.reg_ops.ctlq_reg_init(ctlq_info);

	err = idpf_ctlq_init(hw, IDPF_NUM_DFLT_MBX_Q, ctlq_info);
	if (err)
		return err;

	hw->asq = idpf_find_ctlq(hw, IDPF_CTLQ_TYPE_MAILBOX_TX,
				 IDPF_DFLT_MBX_ID);
	hw->arq = idpf_find_ctlq(hw, IDPF_CTLQ_TYPE_MAILBOX_RX,
				 IDPF_DFLT_MBX_ID);

	if (!hw->asq || !hw->arq) {
		idpf_ctlq_deinit(hw);

		return -ENOENT;
	}

	adapter->state = __IDPF_STARTUP;

	return 0;
}

/**
 * idpf_deinit_dflt_mbx - Free up ctlqs setup
 * @adapter: Driver specific private data structure
 */
void idpf_deinit_dflt_mbx(struct idpf_adapter *adapter)
{
	if (adapter->hw.arq && adapter->hw.asq) {
		idpf_mb_clean(adapter);
		idpf_ctlq_deinit(&adapter->hw);
	}
	adapter->hw.arq = NULL;
	adapter->hw.asq = NULL;
}

/**
 * idpf_vport_params_buf_rel - Release memory for MailBox resources
 * @adapter: Driver specific private data structure
 *
 * Will release memory to hold the vport parameters received on MailBox
 */
static void idpf_vport_params_buf_rel(struct idpf_adapter *adapter)
{
	kfree(adapter->vport_params_recvd);
	adapter->vport_params_recvd = NULL;
	kfree(adapter->vport_params_reqd);
	adapter->vport_params_reqd = NULL;
	kfree(adapter->vport_ids);
	adapter->vport_ids = NULL;
}

/**
 * idpf_vport_params_buf_alloc - Allocate memory for MailBox resources
 * @adapter: Driver specific private data structure
 *
 * Will alloc memory to hold the vport parameters received on MailBox
 */
static int idpf_vport_params_buf_alloc(struct idpf_adapter *adapter)
{
	u16 num_max_vports = idpf_get_max_vports(adapter);

	adapter->vport_params_reqd = kcalloc(num_max_vports,
					     sizeof(*adapter->vport_params_reqd),
					     GFP_KERNEL);
	if (!adapter->vport_params_reqd)
		return -ENOMEM;

	adapter->vport_params_recvd = kcalloc(num_max_vports,
					      sizeof(*adapter->vport_params_recvd),
					      GFP_KERNEL);
	if (!adapter->vport_params_recvd)
		goto err_mem;

	adapter->vport_ids = kcalloc(num_max_vports, sizeof(u32), GFP_KERNEL);
	if (!adapter->vport_ids)
		goto err_mem;

	if (adapter->vport_config)
		return 0;

	adapter->vport_config = kcalloc(num_max_vports,
					sizeof(*adapter->vport_config),
					GFP_KERNEL);
	if (!adapter->vport_config)
		goto err_mem;

	return 0;

err_mem:
	idpf_vport_params_buf_rel(adapter);

	return -ENOMEM;
}

/**
 * idpf_vc_core_init - Initialize state machine and get driver specific
 * resources
 * @adapter: Driver specific private structure
 *
 * This function will initialize the state machine and request all necessary
 * resources required by the device driver. Once the state machine is
 * initialized, allocate memory to store vport specific information and also
 * requests required interrupts.
 *
 * Returns 0 on success, -EAGAIN function will get called again,
 * otherwise negative on failure.
 */
int idpf_vc_core_init(struct idpf_adapter *adapter)
{
	int task_delay = 30;
	u16 num_max_vports;
	int err = 0;

	while (adapter->state != __IDPF_INIT_SW) {
		switch (adapter->state) {
		case __IDPF_STARTUP:
			if (idpf_send_ver_msg(adapter))
				goto init_failed;
			adapter->state = __IDPF_VER_CHECK;
			goto restart;
		case __IDPF_VER_CHECK:
			err = idpf_recv_ver_msg(adapter);
			if (err == -EIO) {
				return err;
			} else if (err == -EAGAIN) {
				adapter->state = __IDPF_STARTUP;
				goto restart;
			} else if (err) {
				goto init_failed;
			}
			if (idpf_send_get_caps_msg(adapter))
				goto init_failed;
			adapter->state = __IDPF_GET_CAPS;
			goto restart;
		case __IDPF_GET_CAPS:
			if (idpf_recv_get_caps_msg(adapter))
				goto init_failed;
			adapter->state = __IDPF_INIT_SW;
			break;
		default:
			dev_err(&adapter->pdev->dev, "Device is in bad state: %d\n",
				adapter->state);
			goto init_failed;
		}
		break;
restart:
		/* Give enough time before proceeding further with
		 * state machine
		 */
		msleep(task_delay);
	}

	pci_sriov_set_totalvfs(adapter->pdev, idpf_get_max_vfs(adapter));
	num_max_vports = idpf_get_max_vports(adapter);
	adapter->max_vports = num_max_vports;
	adapter->vports = kcalloc(num_max_vports, sizeof(*adapter->vports),
				  GFP_KERNEL);
	if (!adapter->vports)
		return -ENOMEM;

	if (!adapter->netdevs) {
		adapter->netdevs = kcalloc(num_max_vports,
					   sizeof(struct net_device *),
					   GFP_KERNEL);
		if (!adapter->netdevs) {
			err = -ENOMEM;
			goto err_netdev_alloc;
		}
	}

	err = idpf_vport_params_buf_alloc(adapter);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to alloc vport params buffer: %d\n",
			err);
		goto err_netdev_alloc;
	}

	/* Start the mailbox task before requesting vectors. This will ensure
	 * vector information response from mailbox is handled
	 */
	queue_delayed_work(adapter->mbx_wq, &adapter->mbx_task, 0);

	queue_delayed_work(adapter->serv_wq, &adapter->serv_task,
			   msecs_to_jiffies(5 * (adapter->pdev->devfn & 0x07)));

	err = idpf_intr_req(adapter);
	if (err) {
		dev_err(&adapter->pdev->dev, "failed to enable interrupt vectors: %d\n",
			err);
		goto err_intr_req;
	}

	idpf_init_avail_queues(adapter);

	/* Skew the delay for init tasks for each function based on fn number
	 * to prevent every function from making the same call simultaneously.
	 */
	queue_delayed_work(adapter->init_wq, &adapter->init_task,
			   msecs_to_jiffies(5 * (adapter->pdev->devfn & 0x07)));

	goto no_err;

err_intr_req:
	cancel_delayed_work_sync(&adapter->serv_task);
	cancel_delayed_work_sync(&adapter->mbx_task);
	idpf_vport_params_buf_rel(adapter);
err_netdev_alloc:
	kfree(adapter->vports);
	adapter->vports = NULL;
no_err:
	return err;

init_failed:
	/* Don't retry if we're trying to go down, just bail. */
	if (test_bit(IDPF_REMOVE_IN_PROG, adapter->flags))
		return err;

	if (++adapter->mb_wait_count > IDPF_MB_MAX_ERR) {
		dev_err(&adapter->pdev->dev, "Failed to establish mailbox communications with hardware\n");

		return -EFAULT;
	}
	/* If it reached here, it is possible that mailbox queue initialization
	 * register writes might not have taken effect. Retry to initialize
	 * the mailbox again
	 */
	adapter->state = __IDPF_STARTUP;
	idpf_deinit_dflt_mbx(adapter);
	set_bit(IDPF_HR_DRV_LOAD, adapter->flags);
	queue_delayed_work(adapter->vc_event_wq, &adapter->vc_event_task,
			   msecs_to_jiffies(task_delay));

	return -EAGAIN;
}

/**
 * idpf_vc_core_deinit - Device deinit routine
 * @adapter: Driver specific private structure
 *
 */
void idpf_vc_core_deinit(struct idpf_adapter *adapter)
{
	int i;

	idpf_deinit_task(adapter);
	idpf_intr_rel(adapter);
	/* Set all bits as we dont know on which vc_state the vhnl_wq is
	 * waiting on and wakeup the virtchnl workqueue even if it is waiting
	 * for the response as we are going down
	 */
	for (i = 0; i < IDPF_VC_NBITS; i++)
		set_bit(i, adapter->vc_state);
	wake_up(&adapter->vchnl_wq);

	cancel_delayed_work_sync(&adapter->serv_task);
	cancel_delayed_work_sync(&adapter->mbx_task);

	idpf_vport_params_buf_rel(adapter);

	/* Clear all the bits */
	for (i = 0; i < IDPF_VC_NBITS; i++)
		clear_bit(i, adapter->vc_state);

	kfree(adapter->vports);
	adapter->vports = NULL;
}

/**
 * idpf_vport_alloc_vec_indexes - Get relative vector indexes
 * @vport: virtual port data struct
 *
 * This function requests the vector information required for the vport and
 * stores the vector indexes received from the 'global vector distribution'
 * in the vport's queue vectors array.
 *
 * Return 0 on success, error on failure
 */
int idpf_vport_alloc_vec_indexes(struct idpf_vport *vport)
{
	struct idpf_vector_info vec_info;
	int num_alloc_vecs;

	vec_info.num_curr_vecs = vport->num_q_vectors;
	vec_info.num_req_vecs = max(vport->num_txq, vport->num_rxq);
	vec_info.default_vport = vport->default_vport;
	vec_info.index = vport->idx;

	/* Additional XDP Tx queues share the q_vector with regular Tx and Rx
	 * queues to which they are assigned. Also, XDP shall request additional
	 * Tx queues via VIRTCHNL. Therefore, to avoid exceeding over
	 * "vport->q_vector_idxs array", do not request empty q_vectors
	 * for XDP Tx queues.
	 */
	if (idpf_xdp_is_prog_ena(vport))
		vec_info.num_req_vecs = max_t(u16,
					      vport->num_txq - vport->num_xdp_txq,
					      vport->num_rxq);

	num_alloc_vecs = idpf_req_rel_vector_indexes(vport->adapter,
						     vport->q_vector_idxs,
						     &vec_info);
	if (num_alloc_vecs <= 0) {
		dev_err(&vport->adapter->pdev->dev, "Vector distribution failed: %d\n",
			num_alloc_vecs);
		return -EINVAL;
	}

	vport->num_q_vectors = num_alloc_vecs;

	return 0;
}

/**
 * idpf_vport_init - Initialize virtual port
 * @vport: virtual port to be initialized
 * @max_q: vport max queue info
 *
 * Will initialize vport with the info received through MB earlier
 */
void idpf_vport_init(struct idpf_vport *vport, struct idpf_vport_max_q *max_q)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_create_vport *vport_msg;
	struct idpf_vport_config *vport_config;
	u16 tx_itr[] = {2, 8, 64, 128, 256};
	u16 rx_itr[] = {2, 8, 32, 96, 128};
	struct idpf_rss_data *rss_data;
	u16 idx = vport->idx;

	vport_config = adapter->vport_config[idx];
	rss_data = &vport_config->user_config.rss_data;
	vport_msg = adapter->vport_params_recvd[idx];

	vport_config->max_q.max_txq = max_q->max_txq;
	vport_config->max_q.max_rxq = max_q->max_rxq;
	vport_config->max_q.max_complq = max_q->max_complq;
	vport_config->max_q.max_bufq = max_q->max_bufq;

	vport->txq_model = le16_to_cpu(vport_msg->txq_model);
	vport->rxq_model = le16_to_cpu(vport_msg->rxq_model);
	vport->vport_type = le16_to_cpu(vport_msg->vport_type);
	vport->vport_id = le32_to_cpu(vport_msg->vport_id);

	rss_data->rss_key_size = min_t(u16, NETDEV_RSS_KEY_LEN,
				       le16_to_cpu(vport_msg->rss_key_size));
	rss_data->rss_lut_size = le16_to_cpu(vport_msg->rss_lut_size);

	ether_addr_copy(vport->default_mac_addr, vport_msg->default_mac_addr);
	vport->max_mtu = le16_to_cpu(vport_msg->max_mtu) - LIBIE_RX_LL_LEN;

	/* Initialize Tx and Rx profiles for Dynamic Interrupt Moderation */
	memcpy(vport->rx_itr_profile, rx_itr, IDPF_DIM_PROFILE_SLOTS);
	memcpy(vport->tx_itr_profile, tx_itr, IDPF_DIM_PROFILE_SLOTS);

	idpf_vport_set_hsplit(vport, ETHTOOL_TCP_DATA_SPLIT_ENABLED);

	idpf_vport_init_num_qs(vport, vport_msg);
	idpf_vport_calc_num_q_desc(vport);
	idpf_vport_calc_num_q_groups(vport);
	idpf_vport_alloc_vec_indexes(vport);

	vport->crc_enable = adapter->crc_enable;
}

/**
 * idpf_get_vec_ids - Initialize vector id from Mailbox parameters
 * @adapter: adapter structure to get the mailbox vector id
 * @vecids: Array of vector ids
 * @num_vecids: number of vector ids
 * @chunks: vector ids received over mailbox
 *
 * Will initialize the mailbox vector id which is received from the
 * get capabilities and data queue vector ids with ids received as
 * mailbox parameters.
 * Returns number of ids filled
 */
int idpf_get_vec_ids(struct idpf_adapter *adapter,
		     u16 *vecids, int num_vecids,
		     struct virtchnl2_vector_chunks *chunks)
{
	u16 num_chunks = le16_to_cpu(chunks->num_vchunks);
	int num_vecid_filled = 0;
	int i, j;

	vecids[num_vecid_filled] = adapter->mb_vector.v_idx;
	num_vecid_filled++;

	for (j = 0; j < num_chunks; j++) {
		struct virtchnl2_vector_chunk *chunk;
		u16 start_vecid, num_vec;

		chunk = &chunks->vchunks[j];
		num_vec = le16_to_cpu(chunk->num_vectors);
		start_vecid = le16_to_cpu(chunk->start_vector_id);

		for (i = 0; i < num_vec; i++) {
			if ((num_vecid_filled + i) < num_vecids) {
				vecids[num_vecid_filled + i] = start_vecid;
				start_vecid++;
			} else {
				break;
			}
		}
		num_vecid_filled = num_vecid_filled + i;
	}

	return num_vecid_filled;
}

/**
 * idpf_vport_get_queue_ids - Initialize queue id from Mailbox parameters
 * @qids: Array of queue ids
 * @num_qids: number of queue ids
 * @q_type: queue model
 * @chunks: queue ids received over mailbox
 *
 * Will initialize all queue ids with ids received as mailbox parameters
 * Returns number of ids filled
 */
static int idpf_vport_get_queue_ids(u32 *qids, int num_qids, u16 q_type,
				    struct virtchnl2_queue_reg_chunks *chunks)
{
	u16 num_chunks = le16_to_cpu(chunks->num_chunks);
	u32 num_q_id_filled = 0, i;
	u32 start_q_id, num_q;

	while (num_chunks--) {
		struct virtchnl2_queue_reg_chunk *chunk;

		chunk = &chunks->chunks[num_chunks];
		if (le32_to_cpu(chunk->type) != q_type)
			continue;

		num_q = le32_to_cpu(chunk->num_queues);
		start_q_id = le32_to_cpu(chunk->start_queue_id);

		for (i = 0; i < num_q; i++) {
			if ((num_q_id_filled + i) < num_qids) {
				qids[num_q_id_filled + i] = start_q_id;
				start_q_id++;
			} else {
				break;
			}
		}
		num_q_id_filled = num_q_id_filled + i;
	}

	return num_q_id_filled;
}

/**
 * __idpf_vport_queue_ids_init - Initialize queue ids from Mailbox parameters
 * @vport: virtual port for which the queues ids are initialized
 * @qids: queue ids
 * @num_qids: number of queue ids
 * @q_type: type of queue
 *
 * Will initialize all queue ids with ids received as mailbox
 * parameters. Returns number of queue ids initialized.
 */
static int __idpf_vport_queue_ids_init(struct idpf_vport *vport,
				       const u32 *qids,
				       int num_qids,
				       u32 q_type)
{
	struct idpf_queue *q;
	int i, j, k = 0;

	switch (q_type) {
	case VIRTCHNL2_QUEUE_TYPE_TX:
		for (i = 0; i < vport->num_txq_grp; i++) {
			struct idpf_txq_group *tx_qgrp = &vport->txq_grps[i];

			for (j = 0; j < tx_qgrp->num_txq && k < num_qids; j++, k++) {
				tx_qgrp->txqs[j]->q_id = qids[k];
				tx_qgrp->txqs[j]->q_type =
					VIRTCHNL2_QUEUE_TYPE_TX;
			}
		}
		break;
	case VIRTCHNL2_QUEUE_TYPE_RX:
		for (i = 0; i < vport->num_rxq_grp; i++) {
			struct idpf_rxq_group *rx_qgrp = &vport->rxq_grps[i];
			u16 num_rxq;

			if (idpf_is_queue_model_split(vport->rxq_model))
				num_rxq = rx_qgrp->splitq.num_rxq_sets;
			else
				num_rxq = rx_qgrp->singleq.num_rxq;

			for (j = 0; j < num_rxq && k < num_qids; j++, k++) {
				if (idpf_is_queue_model_split(vport->rxq_model))
					q = &rx_qgrp->splitq.rxq_sets[j]->rxq;
				else
					q = rx_qgrp->singleq.rxqs[j];
				q->q_id = qids[k];
				q->q_type = VIRTCHNL2_QUEUE_TYPE_RX;
			}
		}
		break;
	case VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION:
		for (i = 0; i < vport->num_txq_grp && k < num_qids; i++, k++) {
			struct idpf_txq_group *tx_qgrp = &vport->txq_grps[i];

			tx_qgrp->complq->q_id = qids[k];
			tx_qgrp->complq->q_type =
				VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION;
		}
		break;
	case VIRTCHNL2_QUEUE_TYPE_RX_BUFFER:
		for (i = 0; i < vport->num_rxq_grp; i++) {
			struct idpf_rxq_group *rx_qgrp = &vport->rxq_grps[i];
			u8 num_bufqs = vport->num_bufqs_per_qgrp;

			for (j = 0; j < num_bufqs && k < num_qids; j++, k++) {
				q = &rx_qgrp->splitq.bufq_sets[j].bufq;
				q->q_id = qids[k];
				q->q_type = VIRTCHNL2_QUEUE_TYPE_RX_BUFFER;
			}
		}
		break;
	default:
		break;
	}

	return k;
}

/**
 * idpf_vport_queue_ids_init - Initialize queue ids from Mailbox parameters
 * @vport: virtual port for which the queues ids are initialized
 *
 * Will initialize all queue ids with ids received as mailbox parameters.
 * Returns 0 on success, negative if all the queues are not initialized.
 */
int idpf_vport_queue_ids_init(struct idpf_vport *vport)
{
	struct virtchnl2_create_vport *vport_params;
	struct virtchnl2_queue_reg_chunks *chunks;
	struct idpf_vport_config *vport_config;
	u16 vport_idx = vport->idx;
	int num_ids, err = 0;
	u16 q_type;
	u32 *qids;

	vport_config = vport->adapter->vport_config[vport_idx];
	if (vport_config->req_qs_chunks) {
		struct virtchnl2_add_queues *vc_aq =
			(struct virtchnl2_add_queues *)vport_config->req_qs_chunks;
		chunks = &vc_aq->chunks;
	} else {
		vport_params = vport->adapter->vport_params_recvd[vport_idx];
		chunks = &vport_params->chunks;
	}

	qids = kcalloc(IDPF_MAX_QIDS, sizeof(u32), GFP_KERNEL);
	if (!qids)
		return -ENOMEM;

	num_ids = idpf_vport_get_queue_ids(qids, IDPF_MAX_QIDS,
					   VIRTCHNL2_QUEUE_TYPE_TX,
					   chunks);
	if (num_ids < vport->num_txq) {
		err = -EINVAL;
		goto mem_rel;
	}
	num_ids = __idpf_vport_queue_ids_init(vport, qids, num_ids,
					      VIRTCHNL2_QUEUE_TYPE_TX);
	if (num_ids < vport->num_txq) {
		err = -EINVAL;
		goto mem_rel;
	}

	num_ids = idpf_vport_get_queue_ids(qids, IDPF_MAX_QIDS,
					   VIRTCHNL2_QUEUE_TYPE_RX,
					   chunks);
	if (num_ids < vport->num_rxq) {
		err = -EINVAL;
		goto mem_rel;
	}
	num_ids = __idpf_vport_queue_ids_init(vport, qids, num_ids,
					      VIRTCHNL2_QUEUE_TYPE_RX);
	if (num_ids < vport->num_rxq) {
		err = -EINVAL;
		goto mem_rel;
	}

	if (!idpf_is_queue_model_split(vport->txq_model))
		goto check_rxq;

	q_type = VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION;
	num_ids = idpf_vport_get_queue_ids(qids, IDPF_MAX_QIDS, q_type, chunks);
	if (num_ids < vport->num_complq) {
		err = -EINVAL;
		goto mem_rel;
	}
	num_ids = __idpf_vport_queue_ids_init(vport, qids, num_ids, q_type);
	if (num_ids < vport->num_complq) {
		err = -EINVAL;
		goto mem_rel;
	}

check_rxq:
	if (!idpf_is_queue_model_split(vport->rxq_model))
		goto mem_rel;

	q_type = VIRTCHNL2_QUEUE_TYPE_RX_BUFFER;
	num_ids = idpf_vport_get_queue_ids(qids, IDPF_MAX_QIDS, q_type, chunks);
	if (num_ids < vport->num_bufq) {
		err = -EINVAL;
		goto mem_rel;
	}
	num_ids = __idpf_vport_queue_ids_init(vport, qids, num_ids, q_type);
	if (num_ids < vport->num_bufq)
		err = -EINVAL;

mem_rel:
	kfree(qids);

	return err;
}

/**
 * idpf_vport_adjust_qs - Adjust to new requested queues
 * @vport: virtual port data struct
 *
 * Renegotiate queues.  Returns 0 on success, negative on failure.
 */
int idpf_vport_adjust_qs(struct idpf_vport *vport)
{
	struct virtchnl2_create_vport vport_msg;
	int err;

	vport_msg.txq_model = cpu_to_le16(vport->txq_model);
	vport_msg.rxq_model = cpu_to_le16(vport->rxq_model);
	err = idpf_vport_calc_total_qs(vport->adapter, vport->idx, &vport_msg,
				       NULL);
	if (err)
		return err;

	idpf_vport_init_num_qs(vport, &vport_msg);
	idpf_vport_calc_num_q_groups(vport);

	return 0;
}

/**
 * idpf_is_capability_ena - Default implementation of capability checking
 * @adapter: Private data struct
 * @all: all or one flag
 * @field: caps field to check for flags
 * @flag: flag to check
 *
 * Return true if all capabilities are supported, false otherwise
 */
bool idpf_is_capability_ena(struct idpf_adapter *adapter, bool all,
			    enum idpf_cap_field field, u64 flag)
{
	u8 *caps = (u8 *)&adapter->caps;
	u32 *cap_field;

	if (!caps)
		return false;

	if (field == IDPF_BASE_CAPS)
		return false;

	cap_field = (u32 *)(caps + field);

	if (all)
		return (*cap_field & flag) == flag;
	else
		return !!(*cap_field & flag);
}

/**
 * idpf_get_vport_id: Get vport id
 * @vport: virtual port structure
 *
 * Return vport id from the adapter persistent data
 */
u32 idpf_get_vport_id(struct idpf_vport *vport)
{
	struct virtchnl2_create_vport *vport_msg;

	vport_msg = vport->adapter->vport_params_recvd[vport->idx];

	return le32_to_cpu(vport_msg->vport_id);
}

/**
 * idpf_add_del_mac_filters - Add/del mac filters
 * @vport: Virtual port data structure
 * @np: Netdev private structure
 * @add: Add or delete flag
 * @async: Don't wait for return message
 *
 * Returns 0 on success, error on failure.
 **/
int idpf_add_del_mac_filters(struct idpf_vport *vport,
			     struct idpf_netdev_priv *np,
			     bool add, bool async)
{
	struct virtchnl2_mac_addr_list *ma_list = NULL;
	struct idpf_adapter *adapter = np->adapter;
	struct idpf_vport_config *vport_config;
	enum idpf_vport_config_flags mac_flag;
	struct pci_dev *pdev = adapter->pdev;
	enum idpf_vport_vc_state vc, vc_err;
	struct virtchnl2_mac_addr *mac_addr;
	struct idpf_mac_filter *f, *tmp;
	u32 num_msgs, total_filters = 0;
	int i = 0, k, err = 0;
	u32 vop;

	vport_config = adapter->vport_config[np->vport_idx];
	spin_lock_bh(&vport_config->mac_filter_list_lock);

	/* Find the number of newly added filters */
	list_for_each_entry(f, &vport_config->user_config.mac_filter_list,
			    list) {
		if (add && f->add)
			total_filters++;
		else if (!add && f->remove)
			total_filters++;
	}

	if (!total_filters) {
		spin_unlock_bh(&vport_config->mac_filter_list_lock);

		return 0;
	}

	/* Fill all the new filters into virtchannel message */
	mac_addr = kcalloc(total_filters, sizeof(struct virtchnl2_mac_addr),
			   GFP_ATOMIC);
	if (!mac_addr) {
		err = -ENOMEM;
		spin_unlock_bh(&vport_config->mac_filter_list_lock);
		goto error;
	}

	list_for_each_entry_safe(f, tmp, &vport_config->user_config.mac_filter_list,
				 list) {
		if (add && f->add) {
			ether_addr_copy(mac_addr[i].addr, f->macaddr);
			i++;
			f->add = false;
			if (i == total_filters)
				break;
		}
		if (!add && f->remove) {
			ether_addr_copy(mac_addr[i].addr, f->macaddr);
			i++;
			f->remove = false;
			if (i == total_filters)
				break;
		}
	}

	spin_unlock_bh(&vport_config->mac_filter_list_lock);

	if (add) {
		vop = VIRTCHNL2_OP_ADD_MAC_ADDR;
		vc = IDPF_VC_ADD_MAC_ADDR;
		vc_err = IDPF_VC_ADD_MAC_ADDR_ERR;
		mac_flag = IDPF_VPORT_ADD_MAC_REQ;
	} else {
		vop = VIRTCHNL2_OP_DEL_MAC_ADDR;
		vc = IDPF_VC_DEL_MAC_ADDR;
		vc_err = IDPF_VC_DEL_MAC_ADDR_ERR;
		mac_flag = IDPF_VPORT_DEL_MAC_REQ;
	}

	/* Chunk up the filters into multiple messages to avoid
	 * sending a control queue message buffer that is too large
	 */
	num_msgs = DIV_ROUND_UP(total_filters, IDPF_NUM_FILTERS_PER_MSG);

	if (!async)
		mutex_lock(&vport->vc_buf_lock);

	for (i = 0, k = 0; i < num_msgs; i++) {
		u32 entries_size, buf_size, num_entries;

		num_entries = min_t(u32, total_filters,
				    IDPF_NUM_FILTERS_PER_MSG);
		entries_size = sizeof(struct virtchnl2_mac_addr) * num_entries;
		buf_size = struct_size(ma_list, mac_addr_list, num_entries);

		if (!ma_list || num_entries != IDPF_NUM_FILTERS_PER_MSG) {
			kfree(ma_list);
			ma_list = kzalloc(buf_size, GFP_ATOMIC);
			if (!ma_list) {
				err = -ENOMEM;
				goto list_prep_error;
			}
		} else {
			memset(ma_list, 0, buf_size);
		}

		ma_list->vport_id = cpu_to_le32(np->vport_id);
		ma_list->num_mac_addr = cpu_to_le16(num_entries);
		memcpy(ma_list->mac_addr_list, &mac_addr[k], entries_size);

		if (async)
			set_bit(mac_flag, vport_config->flags);

		err = idpf_send_mb_msg(adapter, vop, buf_size, (u8 *)ma_list);
		if (err)
			goto mbx_error;

		if (!async) {
			err = idpf_wait_for_event(adapter, vport, vc, vc_err);
			if (err)
				goto mbx_error;
		}

		k += num_entries;
		total_filters -= num_entries;
	}

mbx_error:
	if (!async)
		mutex_unlock(&vport->vc_buf_lock);
	kfree(ma_list);
list_prep_error:
	kfree(mac_addr);
error:
	if (err)
		dev_err(&pdev->dev, "Failed to add or del mac filters %d", err);

	return err;
}

/**
 * idpf_set_promiscuous - set promiscuous and send message to mailbox
 * @adapter: Driver specific private structure
 * @config_data: Vport specific config data
 * @vport_id: Vport identifier
 *
 * Request to enable promiscuous mode for the vport. Message is sent
 * asynchronously and won't wait for response.  Returns 0 on success, negative
 * on failure;
 */
int idpf_set_promiscuous(struct idpf_adapter *adapter,
			 struct idpf_vport_user_config_data *config_data,
			 u32 vport_id)
{
	struct virtchnl2_promisc_info vpi;
	u16 flags = 0;
	int err;

	if (test_bit(__IDPF_PROMISC_UC, config_data->user_flags))
		flags |= VIRTCHNL2_UNICAST_PROMISC;
	if (test_bit(__IDPF_PROMISC_MC, config_data->user_flags))
		flags |= VIRTCHNL2_MULTICAST_PROMISC;

	vpi.vport_id = cpu_to_le32(vport_id);
	vpi.flags = cpu_to_le16(flags);

	err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_CONFIG_PROMISCUOUS_MODE,
			       sizeof(struct virtchnl2_promisc_info),
			       (u8 *)&vpi);

	return err;
}
