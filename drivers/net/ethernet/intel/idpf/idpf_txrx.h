/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2023 Intel Corporation */

#ifndef _IDPF_TXRX_H_
#define _IDPF_TXRX_H_

#include <linux/net/intel/libie/xdp.h>

#include <net/page_pool/helpers.h>
#include <net/tcp.h>
#include <net/netdev_queues.h>

#define IDPF_LARGE_MAX_Q			256
#define IDPF_MAX_Q				16
#define IDPF_MIN_Q				2
/* Mailbox Queue */
#define IDPF_MAX_MBXQ				1

#define IDPF_MIN_TXQ_DESC			64
#define IDPF_MIN_RXQ_DESC			64
#define IDPF_MIN_TXQ_COMPLQ_DESC		256
#define IDPF_MAX_QIDS				256

/* Number of descriptors in a queue should be a multiple of 32. RX queue
 * descriptors alone should be a multiple of IDPF_REQ_RXQ_DESC_MULTIPLE
 * to achieve BufQ descriptors aligned to 32
 */
#define IDPF_REQ_DESC_MULTIPLE			32
#define IDPF_REQ_RXQ_DESC_MULTIPLE (IDPF_MAX_BUFQS_PER_RXQ_GRP * 32)
#define IDPF_MIN_TX_DESC_NEEDED (MAX_SKB_FRAGS + 6)
#define IDPF_TX_WAKE_THRESH ((u16)IDPF_MIN_TX_DESC_NEEDED * 2)

#define IDPF_MAX_DESCS				8160
#define IDPF_MAX_TXQ_DESC ALIGN_DOWN(IDPF_MAX_DESCS, IDPF_REQ_DESC_MULTIPLE)
#define IDPF_MAX_RXQ_DESC ALIGN_DOWN(IDPF_MAX_DESCS, IDPF_REQ_RXQ_DESC_MULTIPLE)
#define MIN_SUPPORT_TXDID (\
	VIRTCHNL2_TXDID_FLEX_FLOW_SCHED |\
	VIRTCHNL2_TXDID_FLEX_TSO_CTX)

#define IDPF_DFLT_SINGLEQ_TX_Q_GROUPS		1
#define IDPF_DFLT_SINGLEQ_RX_Q_GROUPS		1
#define IDPF_DFLT_SINGLEQ_TXQ_PER_GROUP		4
#define IDPF_DFLT_SINGLEQ_RXQ_PER_GROUP		4

#define IDPF_COMPLQ_PER_GROUP			1
#define IDPF_SINGLE_BUFQ_PER_RXQ_GRP		1
#define IDPF_MAX_BUFQS_PER_RXQ_GRP		2
#define IDPF_BUFQ2_ENA				1
#define IDPF_NUMQ_PER_CHUNK			1

#define IDPF_DFLT_SPLITQ_TXQ_PER_GROUP		1
#define IDPF_DFLT_SPLITQ_RXQ_PER_GROUP		1

/* Default vector sharing */
#define IDPF_MBX_Q_VEC		1
#define IDPF_MIN_Q_VEC		1

#define IDPF_DFLT_TX_Q_DESC_COUNT		512
#define IDPF_DFLT_TX_COMPLQ_DESC_COUNT		512
#define IDPF_DFLT_RX_Q_DESC_COUNT		512

/* IMPORTANT: We absolutely _cannot_ have more buffers in the system than a
 * given RX completion queue has descriptors. This includes _ALL_ buffer
 * queues. E.g.: If you have two buffer queues of 512 descriptors and buffers,
 * you have a total of 1024 buffers so your RX queue _must_ have at least that
 * many descriptors. This macro divides a given number of RX descriptors by
 * number of buffer queues to calculate how many descriptors each buffer queue
 * can have without overrunning the RX queue.
 *
 * If you give hardware more buffers than completion descriptors what will
 * happen is that if hardware gets a chance to post more than ring wrap of
 * descriptors before SW gets an interrupt and overwrites SW head, the gen bit
 * in the descriptor will be wrong. Any overwritten descriptors' buffers will
 * be gone forever and SW has no reasonable way to tell that this has happened.
 * From SW perspective, when we finally get an interrupt, it looks like we're
 * still waiting for descriptor to be done, stalling forever.
 */
#define IDPF_RX_BUFQ_DESC_COUNT(RXD, NUM_BUFQ)	((RXD) / (NUM_BUFQ))

#define IDPF_RX_BUFQ_WORKING_SET(rxq)		((rxq)->desc_count - 1)

#define IDPF_RX_BUMP_NTC(rxq, ntc)				\
do {								\
	if (unlikely(++(ntc) == (rxq)->desc_count)) {		\
		ntc = 0;					\
		change_bit(__IDPF_Q_GEN_CHK, (rxq)->flags);	\
	}							\
} while (0)

#define IDPF_SINGLEQ_BUMP_RING_IDX(q, idx)			\
do {								\
	if (unlikely(++(idx) == (q)->desc_count))		\
		idx = 0;					\
} while (0)

#define IDPF_RX_BUF_STRIDE			32
#define IDPF_RX_BUF_POST_STRIDE			16
#define IDPF_LOW_WATERMARK			64

#define IDPF_TX_TSO_MIN_MSS			88

/* Minimum number of descriptors between 2 descriptors with the RE bit set;
 * only relevant in flow scheduling mode
 */
#define IDPF_TX_SPLITQ_RE_MIN_GAP	64

#define IDPF_RX_BI_BUFID_S		0
#define IDPF_RX_BI_BUFID_M		GENMASK(14, 0)
#define IDPF_RX_BI_GEN_S		15
#define IDPF_RX_BI_GEN_M		BIT(IDPF_RX_BI_GEN_S)
#define IDPF_RXD_EOF_SPLITQ		VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_EOF_M
#define IDPF_RXD_EOF_SINGLEQ		VIRTCHNL2_RX_BASE_DESC_STATUS_EOF_M

#define IDPF_DESC_UNUSED(txq)     \
	((((txq)->next_to_clean > (txq)->next_to_use) ? 0 : (txq)->desc_count) + \
	(txq)->next_to_clean - (txq)->next_to_use - 1)

#define IDPF_TX_BUF_RSV_UNUSED(txq)	((txq)->buf_stack.top)
#define IDPF_TX_BUF_RSV_LOW(txq)	(IDPF_TX_BUF_RSV_UNUSED(txq) < \
					 (txq)->desc_count >> 2)

#define IDPF_TX_COMPLQ_OVERFLOW_THRESH(txcq)	((txcq)->desc_count >> 1)
/* Determine the absolute number of completions pending, i.e. the number of
 * completions that are expected to arrive on the TX completion queue.
 */
#define IDPF_TX_COMPLQ_PENDING(txq)	\
	(((txq)->num_completions_pending >= (txq)->complq->num_completions ? \
	0 : U64_MAX) + \
	(txq)->num_completions_pending - (txq)->complq->num_completions)

#define IDPF_TX_SPLITQ_COMPL_TAG_WIDTH	16
#define IDPF_SPLITQ_TX_INVAL_COMPL_TAG	-1
/* Adjust the generation for the completion tag and wrap if necessary */
#define IDPF_TX_ADJ_COMPL_TAG_GEN(txq) \
	((++(txq)->compl_tag_cur_gen) >= (txq)->compl_tag_gen_max ? \
	0 : (txq)->compl_tag_cur_gen)

#define IDPF_QUEUE_QUARTER(Q)		((Q)->desc_count >> 2)

#define IDPF_TXD_LAST_DESC_CMD (IDPF_TX_DESC_CMD_EOP | IDPF_TX_DESC_CMD_RS)

#define IDPF_TX_FLAGS_TSO		BIT(0)
#define IDPF_TX_FLAGS_IPV4		BIT(1)
#define IDPF_TX_FLAGS_IPV6		BIT(2)
#define IDPF_TX_FLAGS_TUNNEL		BIT(3)

union idpf_tx_flex_desc {
	struct idpf_flex_tx_desc q; /* queue based scheduling */
	struct idpf_flex_tx_sched_desc flow; /* flow based scheduling */
};

#define idpf_tx_buf libie_tx_buffer

struct idpf_tx_stash {
	struct hlist_node hlist;
	struct idpf_tx_buf buf;
};

/**
 * struct idpf_buf_lifo - LIFO for managing OOO completions
 * @top: Used to know how many buffers are left
 * @size: Total size of LIFO
 * @bufs: Backing array
 */
struct idpf_buf_lifo {
	u16 top;
	u16 size;
	struct idpf_tx_stash **bufs;
};

/**
 * struct idpf_tx_offload_params - Offload parameters for a given packet
 * @tx_flags: Feature flags enabled for this packet
 * @hdr_offsets: Offset parameter for single queue model
 * @cd_tunneling: Type of tunneling enabled for single queue model
 * @tso_len: Total length of payload to segment
 * @mss: Segment size
 * @tso_segs: Number of segments to be sent
 * @tso_hdr_len: Length of headers to be duplicated
 * @td_cmd: Command field to be inserted into descriptor
 */
struct idpf_tx_offload_params {
	u32 tx_flags;

	u32 hdr_offsets;
	u32 cd_tunneling;

	u32 tso_len;
	u16 mss;
	u16 tso_segs;
	u16 tso_hdr_len;

	u16 td_cmd;
};

/**
 * struct idpf_tx_splitq_params
 * @dtype: General descriptor info
 * @eop_cmd: Type of EOP
 * @compl_tag: Associated tag for completion
 * @td_tag: Descriptor tunneling tag
 * @offload: Offload parameters
 */
struct idpf_tx_splitq_params {
	enum idpf_tx_desc_dtype_value dtype;
	u16 eop_cmd;
	union {
		u16 compl_tag;
		u16 td_tag;
	};

	struct idpf_tx_offload_params offload;
};

enum idpf_tx_ctx_desc_eipt_offload {
	IDPF_TX_CTX_EXT_IP_NONE         = 0x0,
	IDPF_TX_CTX_EXT_IP_IPV6         = 0x1,
	IDPF_TX_CTX_EXT_IP_IPV4_NO_CSUM = 0x2,
	IDPF_TX_CTX_EXT_IP_IPV4         = 0x3
};

/* Checksum offload bits decoded from the receive descriptor. */
struct idpf_rx_csum_decoded {
	u32 l3l4p : 1;
	u32 ipe : 1;
	u32 eipe : 1;
	u32 eudpe : 1;
	u32 ipv6exadd : 1;
	u32 l4e : 1;
	u32 pprs : 1;
	u32 nat : 1;
	u32 raw_csum_inv : 1;
	u32 raw_csum : 16;
};

struct idpf_rx_extracted {
	unsigned int size;
	u16 rx_ptype;
};

#define IDPF_TX_COMPLQ_CLEAN_BUDGET	256
#define IDPF_TX_MIN_PKT_LEN		17
#define IDPF_TX_DESCS_FOR_SKB_DATA_PTR	1
#define IDPF_TX_DESCS_PER_CACHE_LINE	(L1_CACHE_BYTES / \
					 sizeof(struct idpf_flex_tx_desc))
#define IDPF_TX_DESCS_FOR_CTX		1
/* TX descriptors needed, worst case */
#define IDPF_TX_DESC_NEEDED (MAX_SKB_FRAGS + IDPF_TX_DESCS_FOR_CTX + \
			     IDPF_TX_DESCS_PER_CACHE_LINE + \
			     IDPF_TX_DESCS_FOR_SKB_DATA_PTR)

/* The size limit for a transmit buffer in a descriptor is (16K - 1).
 * In order to align with the read requests we will align the value to
 * the nearest 4K which represents our maximum read request size.
 */
#define IDPF_TX_MAX_READ_REQ_SIZE	SZ_4K
#define IDPF_TX_MAX_DESC_DATA		(SZ_16K - 1)
#define IDPF_TX_MAX_DESC_DATA_ALIGNED \
	ALIGN_DOWN(IDPF_TX_MAX_DESC_DATA, IDPF_TX_MAX_READ_REQ_SIZE)

#define idpf_rx_buf libie_rx_buffer

#define IDPF_RX_MAX_PTYPE_PROTO_IDS    32
#define IDPF_RX_MAX_PTYPE_SZ	(sizeof(struct virtchnl2_ptype) + \
				 (sizeof(u16) * IDPF_RX_MAX_PTYPE_PROTO_IDS))
#define IDPF_RX_PTYPE_HDR_SZ	sizeof(struct virtchnl2_get_ptype_info)
#define IDPF_RX_MAX_PTYPES_PER_BUF	\
	DIV_ROUND_DOWN_ULL((IDPF_CTLQ_MAX_BUF_LEN - IDPF_RX_PTYPE_HDR_SZ), \
			   IDPF_RX_MAX_PTYPE_SZ)

#define IDPF_GET_PTYPE_SIZE(p) struct_size((p), proto_id, (p)->proto_id_count)

#define IDPF_TUN_IP_GRE (\
	IDPF_PTYPE_TUNNEL_IP |\
	IDPF_PTYPE_TUNNEL_IP_GRENAT)

#define IDPF_TUN_IP_GRE_MAC (\
	IDPF_TUN_IP_GRE |\
	IDPF_PTYPE_TUNNEL_IP_GRENAT_MAC)

#define IDPF_RX_MAX_PTYPE	1024
#define IDPF_RX_MAX_BASE_PTYPE	256
#define IDPF_INVALID_PTYPE_ID	0xFFFF

enum idpf_tunnel_state {
	IDPF_PTYPE_TUNNEL_IP                    = BIT(0),
	IDPF_PTYPE_TUNNEL_IP_GRENAT             = BIT(1),
	IDPF_PTYPE_TUNNEL_IP_GRENAT_MAC         = BIT(2),
};

struct idpf_ptype_state {
	bool outer_ip:1;
	bool outer_frag:1;
	u8 tunnel_state:6;
};

/**
 * enum idpf_queue_flags_t
 * @__IDPF_Q_GEN_CHK: Queues operating in splitq mode use a generation bit to
 *		      identify new descriptor writebacks on the ring. HW sets
 *		      the gen bit to 1 on the first writeback of any given
 *		      descriptor. After the ring wraps, HW sets the gen bit of
 *		      those descriptors to 0, and continues flipping
 *		      0->1 or 1->0 on each ring wrap. SW maintains its own
 *		      gen bit to know what value will indicate writebacks on
 *		      the next pass around the ring. E.g. it is initialized
 *		      to 1 and knows that reading a gen bit of 1 in any
 *		      descriptor on the initial pass of the ring indicates a
 *		      writeback. It also flips on every ring wrap.
 * @__IDPF_RFLQ_GEN_CHK: Refill queues are SW only, so Q_GEN acts as the HW bit
 *			 and RFLGQ_GEN is the SW bit.
 * @__IDPF_Q_FLOW_SCH_EN: Enable flow scheduling
 * @__IDPF_Q_SW_MARKER: Used to indicate TX queue marker completions
 * @__IDPF_Q_FLAGS_NBITS: Must be last
 * @__IDPF_Q_XSK: Queue used to handle the AF_XDP socket
 */
enum idpf_queue_flags_t {
	__IDPF_Q_GEN_CHK,
	__IDPF_RFLQ_GEN_CHK,
	__IDPF_Q_FLOW_SCH_EN,
	__IDPF_Q_SW_MARKER,
	__IDPF_Q_XDP,
	__IDPF_Q_XSK,

	__IDPF_Q_FLAGS_NBITS,
};

/**
 * struct idpf_vec_regs
 * @dyn_ctl_reg: Dynamic control interrupt register offset
 * @itrn_reg: Interrupt Throttling Rate register offset
 * @itrn_index_spacing: Register spacing between ITR registers of the same
 *			vector
 */
struct idpf_vec_regs {
	u32 dyn_ctl_reg;
	u32 itrn_reg;
	u32 itrn_index_spacing;
};

/**
 * struct idpf_intr_reg
 * @dyn_ctl: Dynamic control interrupt register
 * @dyn_ctl_intena_m: Mask for dyn_ctl interrupt enable
 * @dyn_ctl_intena_msk_m: Mask for dyn_ctl interrupt enable mask
 * @dyn_ctl_itridx_s: Register bit offset for ITR index
 * @dyn_ctl_itridx_m: Mask for ITR index
 * @dyn_ctl_intrvl_s: Register bit offset for ITR interval
 * @dyn_ctl_wb_on_itr_m: Mask for WB on ITR feature
 * @dyn_ctl_swint_trig_m: Mask for SW ITR trigger register
 * @dyn_ctl_sw_itridx_ena_m: Mask for SW ITR enable index
 * @rx_itr: RX ITR register
 * @tx_itr: TX ITR register
 * @icr_ena: Interrupt cause register offset
 * @icr_ena_ctlq_m: Mask for ICR
 */
struct idpf_intr_reg {
	void __iomem *dyn_ctl;
	u32 dyn_ctl_intena_m;
	u32 dyn_ctl_intena_msk_m;
	u32 dyn_ctl_itridx_s;
	u32 dyn_ctl_itridx_m;
	u32 dyn_ctl_intrvl_s;
	u32 dyn_ctl_wb_on_itr_m;
	u32 dyn_ctl_swint_trig_m;
	u32 dyn_ctl_sw_itridx_ena_m;
	void __iomem *rx_itr;
	void __iomem *tx_itr;
	void __iomem *icr_ena;
	u32 icr_ena_ctlq_m;
};

/**
 * struct idpf_q_vector
 * @vport: Vport back pointer
 * @affinity_mask: CPU affinity mask
 * @napi: napi handler
 * @v_idx: Vector index
 * @wb_on_itr: WB on ITR enabled or not
 * @intr_reg: See struct idpf_intr_reg
 * @num_txq: Number of TX queues
 * @tx: Array of TX queues to service
 * @tx_dim: Data for TX net_dim algorithm
 * @tx_itr_value: TX interrupt throttling rate
 * @tx_intr_mode: Dynamic ITR or not
 * @tx_itr_idx: TX ITR index
 * @num_rxq: Number of RX queues
 * @rx: Array of RX queues to service
 * @rx_dim: Data for RX net_dim algorithm
 * @rx_itr_value: RX interrupt throttling rate
 * @rx_intr_mode: Dynamic ITR or not
 * @rx_itr_idx: RX ITR index
 * @num_bufq: Number of buffer queues
 * @bufq: Array of buffer queues to service
 * @total_events: Number of interrupts processed
 * @name: Queue vector name
 */
struct idpf_q_vector {
	struct idpf_vport *vport;
	cpumask_t affinity_mask;
	struct napi_struct napi;
	u16 v_idx;
	bool wb_on_itr;
	struct idpf_intr_reg intr_reg;

	u16 num_txq;
	struct idpf_queue **tx;
	struct dim tx_dim;
	u16 tx_itr_value;
	bool tx_intr_mode;
	u32 tx_itr_idx;

	u16 num_rxq;
	struct idpf_queue **rx;
	struct dim rx_dim;
	u16 rx_itr_value;
	bool rx_intr_mode;
	u32 rx_itr_idx;

	u16 num_bufq;
	struct idpf_queue **bufq;

	u16 total_events;
	char *name;
};

struct idpf_rx_queue_stats {
	u64_stats_t packets;
	u64_stats_t bytes;
	u64_stats_t rsc_pkts;
	u64_stats_t hw_csum_err;
	u64_stats_t hsplit_pkts;
	u64_stats_t hsplit_buf_ovf;
	u64_stats_t bad_descs;
};

struct idpf_tx_queue_stats {
	u64_stats_t packets;
	u64_stats_t bytes;
	u64_stats_t lso_pkts;
	u64_stats_t linearize;
	u64_stats_t q_busy;
	u64_stats_t skb_drops;
	u64_stats_t dma_map_errs;
};

#define idpf_cleaned_stats libie_sq_onstack_stats

union idpf_queue_stats {
	struct idpf_rx_queue_stats rx;
	struct idpf_tx_queue_stats tx;
};

#define IDPF_ITR_DYNAMIC	1
#define IDPF_ITR_MAX		0x1FE0
#define IDPF_ITR_20K		0x0032
#define IDPF_ITR_GRAN_S		1	/* Assume ITR granularity is 2us */
#define IDPF_ITR_MASK		0x1FFE  /* ITR register value alignment mask */
#define ITR_REG_ALIGN(setting)	((setting) & IDPF_ITR_MASK)
#define IDPF_ITR_IS_DYNAMIC(itr_mode) (itr_mode)
#define IDPF_ITR_TX_DEF		IDPF_ITR_20K
#define IDPF_ITR_RX_DEF		IDPF_ITR_20K
/* Index used for 'No ITR' update in DYN_CTL register */
#define IDPF_NO_ITR_UPDATE_IDX	3
#define IDPF_ITR_IDX_SPACING(spacing, dflt)	(spacing ? spacing : dflt)
#define IDPF_DIM_DEFAULT_PROFILE_IX		1

/**
 * struct idpf_queue
 * @dev: Device back pointer for DMA mapping
 * @vport: Back pointer to associated vport
 * @txq_grp: See struct idpf_txq_group
 * @rxq_grp: See struct idpf_rxq_group
 * @idx: For buffer queue, it is used as group id, either 0 or 1. On clean,
 *	 buffer queue uses this index to determine which group of refill queues
 *	 to clean.
 *	 For TX queue, it is used as index to map between TX queue group and
 *	 hot path TX pointers stored in vport. Used in both singleq/splitq.
 *	 For RX queue, it is used to index to total RX queue across groups and
 *	 used for skb reporting.
 * @tail: Tail offset. Used for both queue models single and split. In splitq
 *	  model relevant only for TX queue and RX queue.
 * @tx_buf: See struct idpf_tx_buf
 * @rx_buf: Struct with RX buffer related members
 * @rx_buf.buf: See struct idpf_rx_buf
 * @rx_buf.hdr_buf_pa: DMA handle
 * @rx_buf.hdr_buf_va: Virtual address
 * @pp: Page pool pointer
 * @skb: Pointer to the skb
 * @q_type: Queue type (TX, RX, TX completion, RX buffer)
 * @q_id: Queue id
 * @desc_count: Number of descriptors
 * @next_to_use: Next descriptor to use. Relevant in both split & single txq
 *		 and bufq.
 * @next_to_clean: Next descriptor to clean. In split queue model, only
 *		   relevant to TX completion queue and RX queue.
 * @next_to_alloc: RX buffer to allocate at. Used only for RX. In splitq model
 *		   only relevant to RX queue.
 * @flags: See enum idpf_queue_flags_t
 * @q_stats: See union idpf_queue_stats
 * @stats_sync: See struct u64_stats_sync
 * @cleaned_bytes: Splitq only, TXQ only: When a TX completion is received on
 *		   the TX completion queue, it can be for any TXQ associated
 *		   with that completion queue. This means we can clean up to
 *		   N TXQs during a single call to clean the completion queue.
 *		   cleaned_bytes|pkts tracks the clean stats per TXQ during
 *		   that single call to clean the completion queue. By doing so,
 *		   we can update BQL with aggregate cleaned stats for each TXQ
 *		   only once at the end of the cleaning routine.
 * @cleaned_pkts: Number of packets cleaned for the above said case
 * @rx_hsplit_en: RX headsplit enable
 * @rx_hbuf_size: Header buffer size
 * @rx_buf_size: Buffer size
 * @rx_max_pkt_size: RX max packet size
 * @rx_buf_stride: RX buffer stride
 * @rx_buffer_low_watermark: RX buffer low watermark
 * @rxdids: Supported RX descriptor ids
 * @q_vector: Backreference to associated vector
 * @size: Length of descriptor ring in bytes
 * @dma: Physical address of ring
 * @desc_ring: Descriptor ring memory
 * @xsk_pool: Pointer to a description of a buffer pool for AF_XDP socket
 * @tx_max_bufs: Max buffers that can be transmitted with scatter-gather
 * @tx_min_pkt_len: Min supported packet length
 * @num_completions: Only relevant for TX completion queue. It tracks the
 *		     number of completions received to compare against the
 *		     number of completions pending, as accumulated by the
 *		     TX queues.
 * @buf_stack: Stack of empty buffers to store buffer info for out of order
 *	       buffer completions. See struct idpf_buf_lifo.
 * @compl_tag_bufid_m: Completion tag buffer id mask
 * @compl_tag_gen_s: Completion tag generation bit
 *	The format of the completion tag will change based on the TXQ
 *	descriptor ring size so that we can maintain roughly the same level
 *	of "uniqueness" across all descriptor sizes. For example, if the
 *	TXQ descriptor ring size is 64 (the minimum size supported), the
 *	completion tag will be formatted as below:
 *	15                 6 5         0
 *	--------------------------------
 *	|    GEN=0-1023     |IDX = 0-63|
 *	--------------------------------
 *
 *	This gives us 64*1024 = 65536 possible unique values. Similarly, if
 *	the TXQ descriptor ring size is 8160 (the maximum size supported),
 *	the completion tag will be formatted as below:
 *	15 13 12                       0
 *	--------------------------------
 *	|GEN |       IDX = 0-8159      |
 *	--------------------------------
 *
 *	This gives us 8*8160 = 65280 possible unique values.
 * @compl_tag_cur_gen: Used to keep track of current completion tag generation
 * @compl_tag_gen_max: To determine when compl_tag_cur_gen should be reset
 * @sched_buf_hash: Hash table to stores buffers
 */
struct idpf_queue {
	struct idpf_vport *vport;
	union {
		struct idpf_txq_group *txq_grp;
		struct idpf_rxq_group *rxq_grp;
	};
	void __iomem *tail;
	union {
		struct {
			struct idpf_tx_buf *tx_buf;
			struct libie_xdp_sq_lock xdp_lock;
		};
		u32 num_xdp_txq;
		struct {
			struct libie_rx_buffer *hdr_buf;
			struct idpf_rx_buf *buf;
		} rx_buf;
		struct xdp_buff **xsk;
	};
	union {
		struct page_pool *hdr_pp;
		struct idpf_queue **xdpqs;
		struct xsk_buff_pool *xsk_tx;
	};
	union {
		struct page_pool *pp;
		struct device *dev;
		struct xsk_buff_pool *xsk_rx;
	};
	union {
		union virtchnl2_rx_desc *rx;

		struct virtchnl2_singleq_rx_buf_desc *single_buf;
		struct virtchnl2_splitq_rx_buf_desc *split_buf;

		struct idpf_base_tx_desc *base_tx;
		struct idpf_base_tx_ctx_desc *base_ctx;
		union idpf_tx_flex_desc *flex_tx;
		struct idpf_flex_tx_ctx_desc *flex_ctx;

		struct idpf_splitq_tx_compl_desc *comp;
		struct idpf_splitq_4b_tx_compl_desc *comp_4b;

		void *desc_ring;
	};

	union {
		u32 hdr_truesize;
		u32 xdp_tx_active;
	};
	u32 truesize;
	u16 idx;
	u16 q_type;
	u32 q_id;
	u16 desc_count;

	u16 next_to_use;
	u16 next_to_clean;
	u16 next_to_alloc;
	DECLARE_BITMAP(flags, __IDPF_Q_FLAGS_NBITS);

	struct idpf_q_vector *q_vector;

	union idpf_queue_stats q_stats;
	struct u64_stats_sync stats_sync;

	union {
		/* Rx */
		struct {
			u64 rxdids;
			u8 rx_buffer_low_watermark;
			bool rx_hsplit_en:1;
			u16 rx_hbuf_size;
			u16 rx_buf_size;
			u16 rx_max_pkt_size;
			u16 rx_buf_stride;
		};
		/* Tx */
		struct {
			u32 cleaned_bytes;
			u16 cleaned_pkts;

			u16 tx_max_bufs;
			u8 tx_min_pkt_len;

			u32 num_completions;

			struct idpf_buf_lifo buf_stack;
		};
	};

	union {
		/* Rx */
		struct {
			struct xdp_rxq_info xdp_rxq;

			struct bpf_prog __rcu *xdp_prog;
			struct xdp_buff xdp;
		};

		/* Tx */
		struct {
			u16 compl_tag_bufid_m;
			u16 compl_tag_gen_s;

			u16 compl_tag_cur_gen;
			u16 compl_tag_gen_max;

			struct idpf_txq_hash *sched_buf_hash;
		};
	};

	/* Slowpath */

	dma_addr_t dma;
	unsigned int size;

	u32 relative_q_id;
} ____cacheline_internodealigned_in_smp;

/**
 * struct idpf_sw_queue
 * @next_to_clean: Next descriptor to clean
 * @next_to_alloc: Buffer to allocate at
 * @flags: See enum idpf_queue_flags_t
 * @ring: Pointer to the ring
 * @desc_count: Descriptor count
 * @dev: Device back pointer for DMA mapping
 *
 * Software queues are used in splitq mode to manage buffers between rxq
 * producer and the bufq consumer.  These are required in order to maintain a
 * lockless buffer management system and are strictly software only constructs.
 */
struct idpf_sw_queue {
	u16 next_to_clean;
	u16 next_to_alloc;
	DECLARE_BITMAP(flags, __IDPF_Q_FLAGS_NBITS);
	u16 *ring;
	u16 desc_count;
	struct device *dev;
} ____cacheline_internodealigned_in_smp;

/**
 * struct idpf_rxq_set
 * @rxq: RX queue
 * @refillq0: Pointer to refill queue 0
 * @refillq1: Pointer to refill queue 1
 *
 * Splitq only.  idpf_rxq_set associates an rxq with at an array of refillqs.
 * Each rxq needs a refillq to return used buffers back to the respective bufq.
 * Bufqs then clean these refillqs for buffers to give to hardware.
 */
struct idpf_rxq_set {
	struct idpf_queue rxq;
	struct idpf_sw_queue *refillq0;
	struct idpf_sw_queue *refillq1;
};

/**
 * struct idpf_bufq_set
 * @bufq: Buffer queue
 * @num_refillqs: Number of refill queues. This is always equal to num_rxq_sets
 *		  in idpf_rxq_group.
 * @refillqs: Pointer to refill queues array.
 *
 * Splitq only. idpf_bufq_set associates a bufq to an array of refillqs.
 * In this bufq_set, there will be one refillq for each rxq in this rxq_group.
 * Used buffers received by rxqs will be put on refillqs which bufqs will
 * clean to return new buffers back to hardware.
 *
 * Buffers needed by some number of rxqs associated in this rxq_group are
 * managed by at most two bufqs (depending on performance configuration).
 */
struct idpf_bufq_set {
	struct idpf_queue bufq;
	int num_refillqs;
	struct idpf_sw_queue *refillqs;
};

/**
 * struct idpf_rxq_group
 * @vport: Vport back pointer
 * @singleq: Struct with single queue related members
 * @singleq.num_rxq: Number of RX queues associated
 * @singleq.rxqs: Array of RX queue pointers
 * @splitq: Struct with split queue related members
 * @splitq.num_rxq_sets: Number of RX queue sets
 * @splitq.rxq_sets: Array of RX queue sets
 * @splitq.bufq_sets: Buffer queue set pointer
 *
 * In singleq mode, an rxq_group is simply an array of rxqs.  In splitq, a
 * rxq_group contains all the rxqs, bufqs and refillqs needed to
 * manage buffers in splitq mode.
 */
struct idpf_rxq_group {
	struct idpf_vport *vport;

	union {
		struct {
			u16 num_rxq;
			struct idpf_queue *rxqs[IDPF_LARGE_MAX_Q];
		} singleq;
		struct {
			u16 num_rxq_sets;
			u16 num_bufq_sets;
			struct idpf_rxq_set *rxq_sets[IDPF_LARGE_MAX_Q];
			struct idpf_bufq_set *bufq_sets;
		} splitq;
	};
};

struct idpf_txq_hash {
	DECLARE_HASHTABLE(hash, 12);
};

/**
 * struct idpf_txq_group
 * @vport: Vport back pointer
 * @num_txq: Number of TX queues associated
 * @txqs: Array of TX queue pointers
 * @complq: Associated completion queue pointer, split queue only
 * @num_completions_pending: Total number of completions pending for the
 *			     completion queue, acculumated for all TX queues
 *			     associated with that completion queue.
 *
 * Between singleq and splitq, a txq_group is largely the same except for the
 * complq. In splitq a single complq is responsible for handling completions
 * for some number of txqs associated in this txq_group.
 */
struct idpf_txq_group {
	struct idpf_vport *vport;

	u16 num_txq;
	struct idpf_queue *txqs[IDPF_LARGE_MAX_Q];
	struct idpf_txq_hash *hashes;

	struct idpf_queue *complq;

	u32 num_completions_pending;
};

/**
 * idpf_size_to_txd_count - Get number of descriptors needed for large Tx frag
 * @size: transmit request size in bytes
 *
 * In the case where a large frag (>= 16K) needs to be split across multiple
 * descriptors, we need to assume that we can have no more than 12K of data
 * per descriptor due to hardware alignment restrictions (4K alignment).
 */
static inline u32 idpf_size_to_txd_count(unsigned int size)
{
	return DIV_ROUND_UP(size, IDPF_TX_MAX_DESC_DATA_ALIGNED);
}

/**
 * idpf_tx_singleq_build_ctob - populate command tag offset and size
 * @td_cmd: Command to be filled in desc
 * @td_offset: Offset to be filled in desc
 * @size: Size of the buffer
 * @td_tag: td tag to be filled
 *
 * Returns the 64 bit value populated with the input parameters
 */
static inline __le64 idpf_tx_singleq_build_ctob(u64 td_cmd, u64 td_offset,
						unsigned int size, u64 td_tag)
{
	return cpu_to_le64(IDPF_TX_DESC_DTYPE_DATA |
			   (td_cmd << IDPF_TXD_QW1_CMD_S) |
			   (td_offset << IDPF_TXD_QW1_OFFSET_S) |
			   ((u64)size << IDPF_TXD_QW1_TX_BUF_SZ_S) |
			   (td_tag << IDPF_TXD_QW1_L2TAG1_S));
}

void idpf_tx_splitq_build_ctb(union idpf_tx_flex_desc *desc,
			      struct idpf_tx_splitq_params *params,
			      u16 td_cmd, u16 size);
void idpf_tx_splitq_build_flow_desc(union idpf_tx_flex_desc *desc,
				    struct idpf_tx_splitq_params *params,
				    u16 td_cmd, u16 size);
/**
 * idpf_tx_splitq_build_desc - determine which type of data descriptor to build
 * @desc: descriptor to populate
 * @params: pointer to tx params struct
 * @td_cmd: command to be filled in desc
 * @size: size of buffer
 */
static inline void idpf_tx_splitq_build_desc(union idpf_tx_flex_desc *desc,
					     struct idpf_tx_splitq_params *params,
					     u16 td_cmd, u16 size)
{
	if (params->dtype == IDPF_TX_DESC_DTYPE_FLEX_L2TAG1_L2TAG2)
		idpf_tx_splitq_build_ctb(desc, params, td_cmd, size);
	else
		idpf_tx_splitq_build_flow_desc(desc, params, td_cmd, size);
}

/**
 * idpf_parse_compl_desc - Parse the completion descriptor
 * @desc: completion descriptor to be parsed
 * @complq: completion queue containing the descriptor
 * @txq: returns corresponding Tx queue for a given descriptor
 * @gen_flag: current generation flag in the completion queue
 *
 * Returns completion type from descriptor or negative value in case of error:
 * 	-ENODATA if there is no completion descriptor to be cleaned
 * 	-EINVAL  if no Tx queue has been found for the completion queue
 */
static inline int
idpf_parse_compl_desc(const struct idpf_splitq_4b_tx_compl_desc *desc,
		      const struct idpf_queue *complq, struct idpf_queue **txq,
		      bool gen_flag)
{
	struct idpf_queue *target;
	u32 rel_tx_qid, comptype;

	/* if the descriptor isn't done, no work yet to do */
	comptype = le16_to_cpu(desc->qid_comptype_gen);
	if (!!(comptype & IDPF_TXD_COMPLQ_GEN_M) != gen_flag)
		return -ENODATA;

	/* Find necessary info of TX queue to clean buffers */
	rel_tx_qid = FIELD_GET(IDPF_TXD_COMPLQ_QID_M, comptype);
	target = likely(rel_tx_qid < complq->txq_grp->num_txq) ?
		 complq->txq_grp->txqs[rel_tx_qid] : NULL;

	if (!target)
		return -EINVAL;

	*txq = target;

	/* Determine completion type */
	return FIELD_GET(IDPF_TXD_COMPLQ_COMPL_TYPE_M, comptype);
}

/**
 * idpf_vport_intr_set_wb_on_itr - enable descriptor writeback on disabled interrupts
 * @q_vector: pointer to queue vector struct
 */
static inline void idpf_vport_intr_set_wb_on_itr(struct idpf_q_vector *q_vector)
{
	struct idpf_intr_reg *reg;

	if (q_vector->wb_on_itr)
		return;

	reg = &q_vector->intr_reg;

	writel(reg->dyn_ctl_wb_on_itr_m | reg->dyn_ctl_intena_msk_m |
	       IDPF_NO_ITR_UPDATE_IDX << reg->dyn_ctl_itridx_s,
	       reg->dyn_ctl);

	q_vector->wb_on_itr = true;
}

int idpf_vport_singleq_napi_poll(struct napi_struct *napi, int budget);
void idpf_vport_init_num_qs(struct idpf_vport *vport,
			    struct virtchnl2_create_vport *vport_msg);
void idpf_vport_calc_num_q_desc(struct idpf_vport *vport);
int idpf_vport_calc_total_qs(struct idpf_adapter *adapter, u16 vport_index,
			     struct virtchnl2_create_vport *vport_msg,
			     struct idpf_vport_max_q *max_q);
void idpf_vport_calc_num_q_groups(struct idpf_vport *vport);
int idpf_vport_queues_alloc(struct idpf_vport *vport);
void idpf_vport_queues_rel(struct idpf_vport *vport);
void idpf_vport_intr_rel(struct idpf_vport *vport);
int idpf_vport_intr_alloc(struct idpf_vport *vport);
void idpf_vport_intr_update_itr_ena_irq(struct idpf_q_vector *q_vector);
void idpf_vport_intr_deinit(struct idpf_vport *vport);
int idpf_vport_intr_init(struct idpf_vport *vport);
int idpf_config_rss(struct idpf_vport *vport);
int idpf_init_rss(struct idpf_vport *vport);
void idpf_deinit_rss(struct idpf_vport *vport);
int idpf_rx_bufs_init_all(struct idpf_vport *vport);
bool idpf_init_rx_buf_hw_alloc(struct idpf_queue *rxq, struct idpf_rx_buf *buf);
void idpf_rx_buf_hw_update(struct idpf_queue *rxq, u32 val);
void idpf_tx_buf_hw_update(struct idpf_queue *tx_q, u32 val,
			   bool xmit_more);
unsigned int idpf_size_to_txd_count(unsigned int size);
netdev_tx_t idpf_tx_drop_skb(struct idpf_queue *tx_q, struct sk_buff *skb);
void idpf_tx_dma_map_error(struct idpf_queue *txq, struct sk_buff *skb,
			   struct idpf_tx_buf *first, u16 ring_idx);
unsigned int idpf_tx_desc_count_required(struct idpf_queue *txq,
					 struct sk_buff *skb);
bool idpf_chk_linearize(struct sk_buff *skb, unsigned int max_bufs,
			unsigned int count);
int idpf_tx_maybe_stop_common(struct idpf_queue *tx_q, unsigned int size);
void idpf_tx_timeout(struct net_device *netdev, unsigned int txqueue);
netdev_tx_t idpf_tx_splitq_start(struct sk_buff *skb,
				 struct net_device *netdev);
netdev_tx_t idpf_tx_singleq_start(struct sk_buff *skb,
				  struct net_device *netdev);
bool idpf_rx_singleq_buf_hw_alloc_all(struct idpf_queue *rxq,
				      u16 cleaned_count);

struct virtchnl2_rx_flex_desc_adv_nic_3;

int idpf_rx_process_skb_fields(struct idpf_queue *rxq, struct sk_buff *skb,
			       const struct virtchnl2_rx_flex_desc_adv_nic_3 *rx_desc);
int idpf_tso(struct sk_buff *skb, struct idpf_tx_offload_params *off);
int idpf_rx_desc_alloc(struct idpf_queue *rxq, bool bufq, s32 q_model);
void idpf_rx_desc_rel(struct idpf_queue *rxq, bool bufq, s32 q_model);
int idpf_tx_desc_alloc(struct idpf_queue *tx_q, bool bufq);
void idpf_tx_desc_rel(struct idpf_queue *txq, bool bufq);
int idpf_rx_bufs_init(struct idpf_queue *rxbufq, enum libie_rx_buf_type type);
void idpf_wait_for_sw_marker_completion(struct idpf_queue *txq);

/**
 * idpf_xdpq_update_tail - Updates the XDP Tx queue tail register
 * @xdpq: XDP Tx queue
 *
 * This function updates the XDP Tx queue tail register.
 */
static inline void idpf_xdpq_update_tail(const struct idpf_queue *xdpq)
{
	/* Force memory writes to complete before letting h/w
	 * know there are new descriptors to fetch.
	 */
	wmb();
	writel_relaxed(xdpq->next_to_use, xdpq->tail);
}

/**
 * idpf_set_rs_bit - set RS bit on last produced descriptor.
 * @xdpq: XDP queue to produce the HW Tx descriptors on
 *
 * Returns the index of descriptor RS bit was set on (one behind current NTU).
 */
static inline void idpf_set_rs_bit(const struct idpf_queue *xdpq)
{
	int rs_idx = xdpq->next_to_use ? xdpq->next_to_use - 1 :
					 xdpq->desc_count - 1;
	union idpf_tx_flex_desc *tx_desc;

	tx_desc = &xdpq->flex_tx[rs_idx];
	tx_desc->q.qw1.cmd_dtype |= le16_encode_bits(IDPF_TXD_LAST_DESC_CMD,
						     IDPF_FLEX_TXD_QW1_CMD_M);
}

/**
 * idpf_xdp_tx_finalize - Bump XDP Tx tail and/or flush redirect map
 * @xdpq: XDP Tx queue
 *
 * This function bumps XDP Tx tail and should be called when a batch of packets
 * has been processed in the napi loop.
 */
static inline void idpf_xdp_tx_finalize(void *_xdpq, bool tail)
{
	struct idpf_queue *xdpq = _xdpq;

	libie_xdp_sq_lock(&xdpq->xdp_lock);

	idpf_set_rs_bit(xdpq);
	if (tail)
		idpf_xdpq_update_tail(xdpq);

	libie_xdp_sq_unlock(&xdpq->xdp_lock);
}

#endif /* !_IDPF_TXRX_H_ */
