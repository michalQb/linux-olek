// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2025 Intel Corporation */

#include "ixd.h"

#define IXD_DFLT_MBX_Q_LEN 64

/**
 * ixd_init_ctlq_create_info - Initialize control queue info for creation
 * @info: destination
 * @type: type of the queue to create
 * @ctlq_reg: register assigned to the control queue
 */
static void ixd_init_ctlq_create_info(struct libie_ctlq_create_info *info,
				      enum virtchnl2_queue_type type,
				      const struct libie_ctlq_reg *ctlq_reg)
{
	*info = (struct libie_ctlq_create_info) {
		.type = type,
		.id = -1,
		.reg = *ctlq_reg,
		.len = IXD_DFLT_MBX_Q_LEN,
	};
}

/**
 * ixd_init_libie_xn_params - Initialize xn transaction manager creation info
 * @params: destination
 * @adapter: adapter info struct
 * @ctlqs: list of the managed queues to create
 * @num_queues: length of the queue list
 */
static void ixd_init_libie_xn_params(struct libie_ctlq_xn_init_params *params,
				     struct ixd_adapter *adapter,
				      struct libie_ctlq_create_info *ctlqs,
				      uint num_queues)
{
	*params = (struct libie_ctlq_xn_init_params){
		.cctlq_info = ctlqs,
		.ctx = &adapter->cp_ctx,
		.num_qs = num_queues,
	};
}

/**
 * ixd_adapter_fill_dflt_ctlqs - Find default control queues and store them
 * @adapter: adapter info struct
 */
static void ixd_adapter_fill_dflt_ctlqs(struct ixd_adapter *adapter)
{
	guard(spinlock)(&adapter->cp_ctx.ctlqs_lock);
	struct libie_ctlq_info *cq;

	list_for_each_entry(cq, &adapter->cp_ctx.ctlqs, list) {
		if (cq->qid != -1)
			continue;
		if (cq->type == VIRTCHNL2_QUEUE_TYPE_RX)
			adapter->arq = cq;
		else if (cq->type == VIRTCHNL2_QUEUE_TYPE_TX)
			adapter->asq = cq;
	}
}

/**
 * ixd_init_dflt_mbx - Setup default mailbox parameters and make request
 * @adapter: adapter info struct
 *
 * Return: %0 on success, negative errno code on failure
 */
int ixd_init_dflt_mbx(struct ixd_adapter *adapter)
{
	struct libie_ctlq_create_info ctlqs_info[2];
	struct libie_ctlq_xn_init_params xn_params;
	struct libie_ctlq_reg ctlq_reg_tx;
	struct libie_ctlq_reg ctlq_reg_rx;
	int err;

	ixd_ctlq_reg_init(adapter, &ctlq_reg_tx, &ctlq_reg_rx);
	ixd_init_ctlq_create_info(&ctlqs_info[0], VIRTCHNL2_QUEUE_TYPE_TX,
				  &ctlq_reg_tx);
	ixd_init_ctlq_create_info(&ctlqs_info[1], VIRTCHNL2_QUEUE_TYPE_RX,
				  &ctlq_reg_rx);
	ixd_init_libie_xn_params(&xn_params, adapter, ctlqs_info,
				 ARRAY_SIZE(ctlqs_info));
	err = libie_ctlq_xn_init(&xn_params);
	if (err)
		return err;
	adapter->xnm = xn_params.xnm;

	ixd_adapter_fill_dflt_ctlqs(adapter);

	if (!adapter->asq || !adapter->arq) {
		libie_ctlq_xn_deinit(adapter->xnm, &adapter->cp_ctx);
		return -ENOENT;
	}

	return 0;
}

/**
 * ixd_deinit_dflt_mbx - Deinitialize default mailbox
 * @adapter: adapter info struct
 */
void ixd_deinit_dflt_mbx(struct ixd_adapter *adapter)
{
	if (adapter->arq || adapter->asq)
		libie_ctlq_xn_deinit(adapter->xnm, &adapter->cp_ctx);

	adapter->arq = NULL;
	adapter->asq = NULL;
	adapter->xnm = NULL;
}

/**
 * ixd_init_task - Initialize after reset
 * @work: init work struct
 */
void ixd_init_task(struct work_struct *work)
{
	struct ixd_adapter *adapter;
	int err;

	adapter = container_of(work, struct ixd_adapter,
			       init_task.init_work.work);

	if (!ixd_check_reset_complete(adapter)) {
		if (++adapter->init_task.reset_retries < 10)
			queue_delayed_work(system_unbound_wq,
					   &adapter->init_task.init_work,
					   msecs_to_jiffies(500));
		else
			dev_err(ixd_to_dev(adapter),
				"Device reset failed. The driver was unable to contact the device's firmware. Check that the FW is running.\n");
		return;
	}

	adapter->init_task.reset_retries = 0;
	err = ixd_init_dflt_mbx(adapter);
	if (err)
		dev_err(ixd_to_dev(adapter),
			"Failed to initialize the default mailbox: %pe\n",
			ERR_PTR(err));
}
