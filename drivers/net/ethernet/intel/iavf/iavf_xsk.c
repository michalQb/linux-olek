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
 * iavf_trigger_sw_intr - trigger a software interrupt
 * @adapter: adapter of interest
 * @q_vector: interrupt vector to trigger the software interrupt for
 */
static void
iavf_trigger_sw_intr(struct iavf_adapter *adapter,
		     struct iavf_q_vector *q_vector)
{
        struct iavf_hw *hw = &adapter->hw;

        wr32(hw, IAVF_VFINT_DYN_CTLN1(q_vector->reg_idx),
             (IAVF_VFINT_DYN_CTLN1_INTENA_MASK |
              IAVF_VFINT_DYN_CTLN1_ITR_INDX_MASK |
              IAVF_VFINT_DYN_CTLN1_SWINT_TRIG_MASK |
              IAVF_VFINT_DYN_CTLN1_SW_ITR_INDX_ENA_MASK));

        iavf_flush(hw);
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

	iavf_xsk_setup_xdp_ring(xdp_ring);

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

/**
 * iavf_clean_xdp_tx_buf - Free and unmap XDP Tx buffer
 * @xdp_ring: XDP Tx ring
 * @tx_buf: Tx buffer to clean
 */
static void
iavf_clean_xdp_tx_buf(struct iavf_ring *xdp_ring, struct iavf_tx_buffer *tx_buf)
{
	switch (tx_buf->xdp_type) {
	case IAVF_XDP_BUFFER_FRAME:
		dma_unmap_single(xdp_ring->dev, dma_unmap_addr(tx_buf, dma),
				 dma_unmap_len(tx_buf, len), DMA_TO_DEVICE);
		dma_unmap_len_set(tx_buf, len, 0);
		xdp_return_frame(tx_buf->xdpf);
		tx_buf->xdpf = NULL;
		break;
	}

	xdp_ring->xdp_tx_active--;
	tx_buf->xdp_type = IAVF_XDP_BUFFER_NONE;
}

/**
 * iavf_clean_xdp_irq_zc - produce AF_XDP descriptors to CQ
 * @xdp_ring: XDP Tx ring
 */
static void iavf_clean_xdp_irq_zc(struct iavf_ring *xdp_ring)
{
	u16 ntc = xdp_ring->next_to_clean;
	struct iavf_tx_buffer *tx_buf;
	struct iavf_tx_desc *tx_desc;
	u16 cnt = xdp_ring->count;
	u16 done_frames = 0;
	u16 xsk_frames = 0;
	u16 last_rs;
	int i;

	last_rs = xdp_ring->next_to_use ? xdp_ring->next_to_use - 1 : cnt - 1;
	tx_desc = IAVF_TX_DESC(xdp_ring, last_rs);
	if ((tx_desc->cmd_type_offset_bsz &
	    cpu_to_le64(IAVF_TX_DESC_DTYPE_DESC_DONE))) {
		if (last_rs >= ntc)
			done_frames = last_rs - ntc + 1;
		else
			done_frames = last_rs + cnt - ntc + 1;
	}

	if (!done_frames)
		return;

	if (likely(!xdp_ring->xdp_tx_active)) {
		xsk_frames = done_frames;
		goto skip;
	}

	ntc = xdp_ring->next_to_clean;
	for (i = 0; i < done_frames; i++) {
		tx_buf = &xdp_ring->tx_bi[ntc];

		if (tx_buf->xdp_type)
			iavf_clean_xdp_tx_buf(xdp_ring, tx_buf);
		else
			xsk_frames++;

		ntc++;
		if (ntc >= xdp_ring->count)
			ntc = 0;
	}
skip:
	tx_desc->cmd_type_offset_bsz = 0;
	xdp_ring->next_to_clean += done_frames;
	if (xdp_ring->next_to_clean >= cnt)
		xdp_ring->next_to_clean -= cnt;
	if (xsk_frames)
		xsk_tx_completed(xdp_ring->xsk_pool, xsk_frames);
}

/**
 * iavf_xmit_pkt - produce a single HW Tx descriptor out of AF_XDP descriptor
 * @xdp_ring: XDP ring to produce the HW Tx descriptor on
 * @desc: AF_XDP descriptor to pull the DMA address and length from
 * @total_bytes: bytes accumulator that will be used for stats update
 */
static void iavf_xmit_pkt(struct iavf_ring *xdp_ring, struct xdp_desc *desc,
			  unsigned int *total_bytes)
{
	struct iavf_tx_desc *tx_desc;
	dma_addr_t dma;

	dma = xsk_buff_raw_get_dma(xdp_ring->xsk_pool, desc->addr);
	xsk_buff_raw_dma_sync_for_device(xdp_ring->xsk_pool, dma, desc->len);

	tx_desc = IAVF_TX_DESC(xdp_ring, xdp_ring->next_to_use++);
	tx_desc->buffer_addr = cpu_to_le64(dma);
	tx_desc->cmd_type_offset_bsz = iavf_build_ctob(IAVF_TX_DESC_CMD_EOP,
						       0, desc->len, 0);

	*total_bytes += desc->len;
}

/**
 * iavf_xmit_pkt_batch - produce a batch of HW Tx descriptors out
 * 			 of AF_XDP descriptors
 * @xdp_ring: XDP ring to produce the HW Tx descriptors on
 * @descs: AF_XDP descriptors to pull the DMA addresses and lengths from
 * @total_bytes: bytes accumulator that will be used for stats update
 */
static void iavf_xmit_pkt_batch(struct iavf_ring *xdp_ring,
				struct xdp_desc *descs,
				unsigned int *total_bytes)
{
	u16 ntu = xdp_ring->next_to_use;
	struct iavf_tx_desc *tx_desc;
	u32 i;

	loop_unrolled_for(i = 0; i < PKTS_PER_BATCH; i++) {
		dma_addr_t dma;

		dma = xsk_buff_raw_get_dma(xdp_ring->xsk_pool, descs[i].addr);
		xsk_buff_raw_dma_sync_for_device(xdp_ring->xsk_pool, dma,
						 descs[i].len);

		tx_desc = IAVF_TX_DESC(xdp_ring, ntu++);
		tx_desc->buffer_addr = cpu_to_le64(dma);
		tx_desc->cmd_type_offset_bsz =
			iavf_build_ctob(IAVF_TX_DESC_CMD_EOP, 0,
					descs[i].len, 0);

		*total_bytes += descs[i].len;
	}

	xdp_ring->next_to_use = ntu;
}

/**
 * iavf_fill_tx_hw_ring - produce the number of Tx descriptors onto ring
 * @xdp_ring: XDP ring to produce the HW Tx descriptors on
 * @descs: AF_XDP descriptors to pull the DMA addresses and lengths from
 * @nb_pkts: count of packets to be send
 * @total_bytes: bytes accumulator that will be used for stats update
 */
static void iavf_fill_tx_hw_ring(struct iavf_ring *xdp_ring,
				 struct xdp_desc *descs, u32 nb_pkts,
				 unsigned int *total_bytes)
{
	u32 batched, leftover, i;

	batched = ALIGN_DOWN(nb_pkts, PKTS_PER_BATCH);
	leftover = nb_pkts & (PKTS_PER_BATCH - 1);

	for (i = 0; i < batched; i += PKTS_PER_BATCH)
		iavf_xmit_pkt_batch(xdp_ring, &descs[i], total_bytes);
	for (; i < batched + leftover; i++)
		iavf_xmit_pkt(xdp_ring, &descs[i], total_bytes);
}

/**
 * iavf_xmit_zc - take entries from XSK Tx ring and place them onto HW Tx ring
 * @xdp_ring: XDP ring to produce the HW Tx descriptors on
 *
 * Returns true if there is no more work that needs to be done, false otherwise
 */
bool iavf_xmit_zc(struct iavf_ring *xdp_ring)
{
	struct xdp_desc *descs = xdp_ring->xsk_pool->tx_descs;
	struct libie_sq_onstack_stats stats = { };
	u32 nb_processed = 0;
	int budget;

	iavf_clean_xdp_irq_zc(xdp_ring);

	budget = IAVF_DESC_UNUSED(xdp_ring);
	budget = min_t(u16, budget, IAVF_RING_QUARTER(xdp_ring));

	stats.packets = xsk_tx_peek_release_desc_batch(xdp_ring->xsk_pool,
						       budget);
	if (!stats.packets)
		return true;

	if (xdp_ring->next_to_use + stats.packets >= xdp_ring->count) {
		nb_processed = xdp_ring->count - xdp_ring->next_to_use;
		iavf_fill_tx_hw_ring(xdp_ring, descs, nb_processed,
				     &stats.bytes);
		xdp_ring->next_to_use = 0;
	}

	iavf_fill_tx_hw_ring(xdp_ring, &descs[nb_processed],
			     stats.packets - nb_processed, &stats.bytes);

	iavf_set_rs_bit(xdp_ring);
	iavf_xdp_ring_update_tail(xdp_ring);
	iavf_update_tx_ring_stats(xdp_ring, &stats);

	if (xsk_uses_need_wakeup(xdp_ring->xsk_pool))
		xsk_set_tx_need_wakeup(xdp_ring->xsk_pool);

	return stats.packets < budget;
}

/**
 * iavf_xsk_wakeup - Implements ndo_xsk_wakeup
 * @netdev: net_device
 * @queue_id: queue to wake up
 * @flags: ignored in our case, since we have Rx and Tx in the same NAPI
 *
 * Returns negative on error, zero otherwise.
 */
int iavf_xsk_wakeup(struct net_device *netdev, u32 queue_id, u32 flags)
{
	struct iavf_adapter *adapter = netdev_priv(netdev);
	struct iavf_q_vector *q_vector;
	struct iavf_ring *ring;

	if (adapter->state == __IAVF_DOWN ||
	    adapter->state == __IAVF_RESETTING)
		return -ENETDOWN;

	if (!iavf_adapter_xdp_active(adapter))
		return -EINVAL;

	if (queue_id >= adapter->num_active_queues)
		return -EINVAL;

	ring = &adapter->rx_rings[queue_id];

	if (!(ring->xdp_ring->flags & IAVF_TXRX_FLAGS_XSK))
		return -EINVAL;

	q_vector = ring->q_vector;
	if (!napi_if_scheduled_mark_missed(&q_vector->napi))
		iavf_trigger_sw_intr(adapter, q_vector);

	return 0;
}

static u32 iavf_get_xdp_tx_qid(struct iavf_ring *ring)
{
	struct iavf_adapter *adapter = ring->vsi->back;

	return ring->queue_index - adapter->num_active_queues;
}

static struct xsk_buff_pool *iavf_tx_xsk_pool(struct iavf_ring *ring)
{
	struct iavf_adapter *adapter = ring->vsi->back;
	u32 qid;

	if (!iavf_adapter_xdp_active(adapter) ||
	    !(ring->flags & IAVF_TXRX_FLAGS_XDP))
		return NULL;

	qid = iavf_get_xdp_tx_qid(ring);
	if (!test_bit(qid, adapter->af_xdp_zc_qps))
		return NULL;

	return xsk_get_pool_from_qid(adapter->netdev, qid);
}

void iavf_xsk_setup_xdp_ring(struct iavf_ring *xdp_ring)
{
	struct xsk_buff_pool *pool;

	pool = iavf_tx_xsk_pool(xdp_ring);
	if (pool) {
		xdp_ring->xsk_pool = pool;
		xdp_ring->flags |= IAVF_TXRX_FLAGS_XSK;
	} else {
		xdp_ring->dev = &xdp_ring->vsi->back->pdev->dev;
		xdp_ring->flags &= ~IAVF_TXRX_FLAGS_XSK;
	}
}

/**
 * iavf_xsk_clean_xdp_ring - Clean the XDP Tx ring and its buffer pool queues
 * @xdp_ring: XDP_Tx ring
 */
void iavf_xsk_clean_xdp_ring(struct iavf_ring *xdp_ring)
{
	u16 ntc = xdp_ring->next_to_clean, ntu = xdp_ring->next_to_use;
	u32 xsk_frames = 0;

	while (ntc != ntu) {
		struct iavf_tx_buffer *tx_buf = &xdp_ring->tx_bi[ntc];

		if (tx_buf->xdp_type)
			iavf_clean_xdp_tx_buf(xdp_ring, tx_buf);
		else
			xsk_frames++;

		tx_buf->page = NULL;

		ntc++;
		if (ntc >= xdp_ring->count)
			ntc = 0;
	}

	if (xsk_frames)
		xsk_tx_completed(xdp_ring->xsk_pool, xsk_frames);
}
