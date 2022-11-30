// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 Intel Corporation. */

#include <linux/net/intel/libie/rx.h>
#include <net/xdp_sock_drv.h>
#include <net/xdp_sock.h>
#include "iavf.h"
#include "iavf_xsk.h"

#define IAVF_CRIT_LOCK_WAIT_TIMEOUT_MS	1000
#define IAVF_VC_MSG_TIMEOUT_MS		3000

/**
 * iavf_max_xdp_queues_count - Returns the maximal number of XDP queues
 *			       that can be created for current configuration
 *			       of a given adapter.
 * @adapter: adapter where XDP socket will be set up
 */
static u32
iavf_max_xdp_queues_count(struct iavf_adapter *adapter)
{
	u32 max_qp_num = adapter->vsi_res->num_queue_pairs;
	u32 num_active_queues = adapter->num_active_queues;

	return num_active_queues * 2 > max_qp_num ? max_qp_num / 2 :
						    num_active_queues;
}

/**
 * iavf_qp_clean_rings - Cleans all the rings of a given index
 * @adapter: adapter that contains rings of interest
 * @q_idx: ring index in array
 */
static void
iavf_qp_clean_rings(struct iavf_adapter *adapter, u16 q_idx)
{
	iavf_clean_tx_ring(&adapter->tx_rings[q_idx]);
	if (iavf_adapter_xdp_active(adapter)) {
		synchronize_rcu();
		iavf_clean_tx_ring(&adapter->xdp_rings[q_idx]);
	}
	iavf_clean_rx_ring(&adapter->rx_rings[q_idx]);
}

/**
 * iavf_qvec_toggle_napi - Enables/disables NAPI for a given q_vector
 * @adapter: adapter that has netdev
 * @q_vector: q_vector that has NAPI context
 * @enable: true for enable, false for disable
 */
static void
iavf_qvec_toggle_napi(struct iavf_adapter *adapter,
		      struct iavf_q_vector *q_vector, bool enable)
{
	if (!adapter->vsi.netdev || !q_vector)
		return;

	if (enable)
		napi_enable(&q_vector->napi);
	else
		napi_disable(&q_vector->napi);
}

/**
 * iavf_qvec_dis_irq - Mask off queue interrupt generation on given ring
 * @adapter: the adapter that contains queue vector being un-configured
 * @q_vector: queue vector
 */
static void
iavf_qvec_dis_irq(struct iavf_adapter *adapter, struct iavf_q_vector *q_vector)
{
	int base = adapter->vsi.base_vector;
	struct iavf_hw *hw = &adapter->hw;
	u16 reg = q_vector->reg_idx;

	wr32(hw, IAVF_VFINT_DYN_CTLN1(reg), 0);
	synchronize_irq(adapter->msix_entries[reg + base].vector);
	iavf_flush(hw);
}

/**
 * iavf_qvec_ena_irq - Enable IRQ for given queue vector
 * @adapter: the adapter that contains queue vector
 * @q_vector: queue vector
 */
static void
iavf_qvec_ena_irq(struct iavf_adapter *adapter, struct iavf_q_vector *q_vector)
{
	struct iavf_hw *hw = &adapter->hw;

	if (adapter)
		if (adapter->state == __IAVF_DOWN)
			return;

	wr32(hw, IAVF_VFINT_DYN_CTLN1(q_vector->reg_idx),
	     IAVF_VFINT_DYN_CTLN1_INTENA_MASK |
	     IAVF_VFINT_DYN_CTLN1_ITR_INDX_MASK);

	iavf_flush(hw);
}

/**
 * iavf_qp_dis - Disables a queue pair
 * @adapter: adapter of interest
 * @q_idx: ring index in array
 *
 * Returns 0 on success, negative on failure.
 */
static int iavf_qp_dis(struct iavf_adapter *adapter, u16 q_idx)
{
	struct iavf_vsi *vsi = &adapter->vsi;
	struct iavf_ring *rx_ring, *xdp_ring;
	struct iavf_q_vector *q_vector;
	u32 rx_queues, tx_queues;
	int err;

	if (q_idx >= adapter->num_active_queues)
		return -EINVAL;

	rx_ring = &adapter->rx_rings[q_idx];
	q_vector = rx_ring->q_vector;

	rx_queues = BIT(q_idx);
	tx_queues = rx_queues;

	netif_tx_stop_queue(netdev_get_tx_queue(vsi->netdev, q_idx));

	iavf_qvec_toggle_napi(adapter, q_vector, false);
	iavf_qvec_dis_irq(adapter, q_vector);

	xdp_ring = &adapter->xdp_rings[q_idx];

	tx_queues |= BIT(xdp_ring->queue_index);

	err = iavf_disable_selected_queues(adapter, rx_queues, tx_queues, true);
	if (err)
		goto dis_exit;

	iavf_qp_clean_rings(adapter, q_idx);
dis_exit:
	return err;
}

/**
 * iavf_qp_ena - Enables a queue pair
 * @adapter: adapter of interest
 * @q_idx: ring index in array
 *
 * Returns 0 on success, negative on failure.
 */
static int iavf_qp_ena(struct iavf_adapter *adapter, u16 q_idx)
{
	struct iavf_vsi *vsi = &adapter->vsi;
	struct iavf_ring *rx_ring, *xdp_ring;
	struct iavf_q_vector *q_vector;
	u32 rx_queues, tx_queues;
	int ret, err = 0;

	if (q_idx >= adapter->num_active_queues)
		return -EINVAL;

	xdp_ring = &adapter->xdp_rings[q_idx];
	rx_ring = &adapter->rx_rings[q_idx];
	q_vector = rx_ring->q_vector;

	rx_queues = BIT(q_idx);
	tx_queues = rx_queues;
	tx_queues |= BIT(xdp_ring->queue_index);

	iavf_configure_rx_ring(adapter, rx_ring);

	/* Use 'tx_queues' mask as a queue pair mask to configure
	 * also an extra XDP Tx queue.
	 */
	err = iavf_configure_selected_queues(adapter, tx_queues, true);
	if (err)
		goto ena_exit;

	err = iavf_enable_selected_queues(adapter, rx_queues, tx_queues, true);
	if (err)
		goto ena_exit;

	ret = iavf_poll_for_link_status(adapter, IAVF_XDP_LINK_TIMEOUT_MS);
	if (ret < 0) {
		err = ret;
		dev_err(&adapter->pdev->dev,
			"cannot bring the link up, error: %d\n", err);
		goto ena_exit;
	} else if (!ret) {
		err = -EBUSY;
		dev_err(&adapter->pdev->dev,
			"pf returned link down status, error: %d\n", err);
		goto ena_exit;
	}

	iavf_qvec_toggle_napi(adapter, q_vector, true);
	iavf_qvec_ena_irq(adapter, q_vector);

	netif_tx_start_queue(netdev_get_tx_queue(vsi->netdev, q_idx));
ena_exit:
	return err;
}

/**
 * iavf_xsk_pool_disable - disable a buffer pool region
 * @adapter: Current adapter
 * @qid: queue ID
 *
 * Returns 0 on success, negative on failure
 */
static int iavf_xsk_pool_disable(struct iavf_adapter *adapter, u16 qid)
{
	struct xsk_buff_pool *pool = xsk_get_pool_from_qid(adapter->vsi.netdev,
							   qid);
	if (!pool)
		return -EINVAL;

	clear_bit(qid, adapter->af_xdp_zc_qps);
	xsk_pool_dma_unmap(pool, LIBIE_RX_DMA_ATTR);

	return 0;
}

/**
 * iavf_xsk_pool_enable - enable a buffer pool region
 * @adapter: Current adapter
 * @pool: pointer to a requested buffer pool region
 * @qid: queue ID
 *
 * Returns 0 on success, negative on failure
 */
static int
iavf_xsk_pool_enable(struct iavf_adapter *adapter, struct xsk_buff_pool *pool,
		     u16 qid)
{
	struct iavf_vsi *vsi = &adapter->vsi;
	int err;

	if (qid >= vsi->netdev->real_num_rx_queues ||
	    qid >= vsi->netdev->real_num_tx_queues)
		return -EINVAL;

	err = xsk_pool_dma_map(pool, &adapter->pdev->dev, LIBIE_RX_DMA_ATTR);
	if (err)
		return err;

	set_bit(qid, adapter->af_xdp_zc_qps);

	return 0;
}

/**
 * iavf_xsk_pool_setup - enable/disable a buffer pool region depending
 * 			 on its state
 * @adapter: Current adapter
 * @pool: buffer pool to enable/associate to a ring, NULL to disable
 * @qid: queue ID
 *
 * Returns 0 on success, negative on failure
 */
int iavf_xsk_pool_setup(struct iavf_adapter *adapter,
			struct xsk_buff_pool *pool, u32 qid)
{
	bool if_running, pool_present = !!pool;
	struct iavf_vsi *vsi = &adapter->vsi;
	int ret = 0, pool_failure = 0;

	if (qid >= iavf_max_xdp_queues_count(adapter)) {
		netdev_err(vsi->netdev, "Wrong queue index for XDP.\n");
		pool_failure = -EINVAL;
		goto failure;
	}

	if_running = netif_running(vsi->netdev) &&
		     iavf_adapter_xdp_active(adapter);

	if (if_running) {
		if (iavf_lock_timeout(&adapter->crit_lock,
				      IAVF_CRIT_LOCK_WAIT_TIMEOUT_MS))
			return -EBUSY;

		ret = iavf_process_pending_pf_msg(adapter,
						  IAVF_VC_MSG_TIMEOUT_MS);
		if (ret)
			goto xsk_pool_if_up;

		ret = iavf_qp_dis(adapter, qid);
		if (ret) {
			netdev_err(vsi->netdev, "iavf_qp_dis error = %d\n", ret);
			goto xsk_pool_if_up;
		}
	}

	pool_failure = pool_present ? iavf_xsk_pool_enable(adapter, pool, qid) :
				      iavf_xsk_pool_disable(adapter, qid);

xsk_pool_if_up:
	if (if_running) {
		ret = iavf_qp_ena(adapter, qid);
		mutex_unlock(&adapter->crit_lock);
		if (!ret && pool_present)
			napi_schedule(&adapter->rx_rings[qid].q_vector->napi);
		else if (ret)
			netdev_err(vsi->netdev, "iavf_qp_ena error = %d\n", ret);
	}

failure:
	if (pool_failure) {
		netdev_err(vsi->netdev, "Could not %sable buffer pool, error = %d\n",
			   pool_present ? "en" : "dis", pool_failure);
		return pool_failure;
	}

	return ret;
}
