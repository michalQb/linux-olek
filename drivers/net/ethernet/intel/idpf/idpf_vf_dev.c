// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2023 Intel Corporation */

#include "idpf.h"
#include "idpf_lan_vf_regs.h"
#include "idpf_virtchnl.h"

#define IDPF_VF_ITR_IDX_SPACING		0x40

/**
 * idpf_vf_ctlq_reg_init - initialize default mailbox registers
 * @mmio: struct that contains MMIO region info
 * @cci: struct where the register offset pointer to be copied to
 */
static void idpf_vf_ctlq_reg_init(struct libie_mmio_info *mmio,
				  struct libie_ctlq_create_info *cci)
{
	struct libie_ctlq_reg *tx_reg = &cci[LIBIE_CTLQ_TYPE_TX].reg;
	struct libie_ctlq_reg *rx_reg = &cci[LIBIE_CTLQ_TYPE_RX].reg;

	tx_reg->head		= libie_pci_get_mmio_addr(mmio, VF_ATQH);
	tx_reg->tail		= libie_pci_get_mmio_addr(mmio, VF_ATQT);
	tx_reg->len		= libie_pci_get_mmio_addr(mmio, VF_ATQLEN);
	tx_reg->addr_high	= libie_pci_get_mmio_addr(mmio, VF_ATQBAH);
	tx_reg->addr_low	= libie_pci_get_mmio_addr(mmio, VF_ATQBAL);
	tx_reg->len_mask	= VF_ATQLEN_ATQLEN_M;
	tx_reg->len_ena_mask	= VF_ATQLEN_ATQENABLE_M;
	tx_reg->head_mask	= VF_ATQH_ATQH_M;

	rx_reg->head		= libie_pci_get_mmio_addr(mmio, VF_ARQH);
	rx_reg->tail		= libie_pci_get_mmio_addr(mmio, VF_ARQT);
	rx_reg->len		= libie_pci_get_mmio_addr(mmio, VF_ARQLEN);
	rx_reg->addr_high	= libie_pci_get_mmio_addr(mmio, VF_ARQBAH);
	rx_reg->addr_low	= libie_pci_get_mmio_addr(mmio, VF_ARQBAL);
	rx_reg->len_mask	= VF_ARQLEN_ARQLEN_M;
	rx_reg->len_ena_mask	= VF_ARQLEN_ARQENABLE_M;
	rx_reg->head_mask	= VF_ARQH_ARQH_M;
}

/**
 * idpf_vf_mb_intr_reg_init - Initialize the mailbox register
 * @adapter: adapter structure
 */
static void idpf_vf_mb_intr_reg_init(struct idpf_adapter *adapter)
{
	struct libie_mmio_info *mmio = &adapter->ctlq_ctx.mmio_info;
	struct idpf_intr_reg *intr = &adapter->mb_vector.intr_reg;
	u32 dyn_ctl = le32_to_cpu(adapter->caps.mailbox_dyn_ctl);

	intr->dyn_ctl = libie_pci_get_mmio_addr(mmio, dyn_ctl);
	intr->dyn_ctl_intena_m = VF_INT_DYN_CTL0_INTENA_M;
	intr->dyn_ctl_itridx_m = VF_INT_DYN_CTL0_ITR_INDX_M;
	intr->icr_ena = libie_pci_get_mmio_addr(mmio, VF_INT_ICR0_ENA1);
	intr->icr_ena_ctlq_m = VF_INT_ICR0_ENA1_ADMINQ_M;
}

/**
 * idpf_vf_intr_reg_init - Initialize interrupt registers
 * @vport: virtual port structure
 * @rsrc: pointer to queue and vector resources
 */
static int idpf_vf_intr_reg_init(struct idpf_vport *vport,
				 struct idpf_q_vec_rsrc *rsrc)
{
	struct idpf_adapter *adapter = vport->adapter;
	u16 num_vecs = rsrc->num_q_vectors;
	struct idpf_vec_regs *reg_vals;
	struct libie_mmio_info *mmio;
	int num_regs, i, err = 0;
	u32 rx_itr, tx_itr;
	u16 total_vecs;

	total_vecs = idpf_get_reserved_vecs(vport->adapter);
	reg_vals = kcalloc(total_vecs, sizeof(struct idpf_vec_regs),
			   GFP_KERNEL);
	if (!reg_vals)
		return -ENOMEM;

	num_regs = idpf_get_reg_intr_vecs(adapter, reg_vals);
	if (num_regs < num_vecs) {
		err = -EINVAL;
		goto free_reg_vals;
	}

	mmio = &adapter->ctlq_ctx.mmio_info;

	for (i = 0; i < num_vecs; i++) {
		struct idpf_q_vector *q_vector = &rsrc->q_vectors[i];
		u16 vec_id = rsrc->q_vector_idxs[i] - IDPF_MBX_Q_VEC;
		struct idpf_intr_reg *intr = &q_vector->intr_reg;
		struct idpf_vec_regs *reg = &reg_vals[vec_id];
		u32 spacing;

		intr->dyn_ctl =	libie_pci_get_mmio_addr(mmio,
							reg->dyn_ctl_reg);
		intr->dyn_ctl_intena_m = VF_INT_DYN_CTLN_INTENA_M;
		intr->dyn_ctl_intena_msk_m = VF_INT_DYN_CTLN_INTENA_MSK_M;
		intr->dyn_ctl_itridx_s = VF_INT_DYN_CTLN_ITR_INDX_S;
		intr->dyn_ctl_intrvl_s = VF_INT_DYN_CTLN_INTERVAL_S;
		intr->dyn_ctl_wb_on_itr_m = VF_INT_DYN_CTLN_WB_ON_ITR_M;
		intr->dyn_ctl_swint_trig_m = VF_INT_DYN_CTLN_SWINT_TRIG_M;
		intr->dyn_ctl_sw_itridx_ena_m =
			VF_INT_DYN_CTLN_SW_ITR_INDX_ENA_M;

		spacing = IDPF_ITR_IDX_SPACING(reg->itrn_index_spacing,
					       IDPF_VF_ITR_IDX_SPACING);
		rx_itr = VF_INT_ITRN_ADDR(VIRTCHNL2_ITR_IDX_0,
					  reg->itrn_reg, spacing);
		tx_itr = VF_INT_ITRN_ADDR(VIRTCHNL2_ITR_IDX_1,
					  reg->itrn_reg, spacing);
		intr->rx_itr = libie_pci_get_mmio_addr(mmio, rx_itr);
		intr->tx_itr = libie_pci_get_mmio_addr(mmio, tx_itr);
	}

free_reg_vals:
	kfree(reg_vals);

	return err;
}

/**
 * idpf_vf_reset_reg_init - Initialize reset registers
 * @adapter: Driver specific private structure
 */
static void idpf_vf_reset_reg_init(struct idpf_adapter *adapter)
{
	adapter->reset_reg.rstat =
		libie_pci_get_mmio_addr(&adapter->ctlq_ctx.mmio_info,
					VFGEN_RSTAT);
	adapter->reset_reg.rstat_m = VFGEN_RSTAT_VFR_STATE_M;
}

/**
 * idpf_vf_trigger_reset - trigger reset
 * @adapter: Driver specific private structure
 * @trig_cause: Reason to trigger a reset
 */
static void idpf_vf_trigger_reset(struct idpf_adapter *adapter,
				  enum idpf_flags trig_cause)
{
	struct libie_ctlq_xn_send_params xn_params = {
		.chnl_opcode	= VIRTCHNL2_OP_RESET_VF,
	};
	/* Do not send VIRTCHNL2_OP_RESET_VF message on driver unload */
	if (trig_cause == IDPF_HR_FUNC_RESET &&
	    !test_bit(IDPF_REMOVE_IN_PROG, adapter->flags))
		idpf_send_mb_msg(adapter, &xn_params, NULL, 0);
}

/**
 * idpf_vf_reg_ops_init - Initialize register API function pointers
 * @adapter: Driver specific private structure
 */
static void idpf_vf_reg_ops_init(struct idpf_adapter *adapter)
{
	adapter->dev_ops.reg_ops.ctlq_reg_init = idpf_vf_ctlq_reg_init;
	adapter->dev_ops.reg_ops.intr_reg_init = idpf_vf_intr_reg_init;
	adapter->dev_ops.reg_ops.mb_intr_reg_init = idpf_vf_mb_intr_reg_init;
	adapter->dev_ops.reg_ops.reset_reg_init = idpf_vf_reset_reg_init;
	adapter->dev_ops.reg_ops.trigger_reset = idpf_vf_trigger_reset;
}

/**
 * idpf_vf_dev_ops_init - Initialize device API function pointers
 * @adapter: Driver specific private structure
 */
void idpf_vf_dev_ops_init(struct idpf_adapter *adapter)
{
	idpf_vf_reg_ops_init(adapter);
}
