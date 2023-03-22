/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2013 - 2018 Intel Corporation. */

#ifndef _IAVF_TXRX_H_
#define _IAVF_TXRX_H_

/* Interrupt Throttling and Rate Limiting Goodies */
#define IAVF_DEFAULT_IRQ_WORK      256

/* The datasheet for the X710 and XL710 indicate that the maximum value for
 * the ITR is 8160usec which is then called out as 0xFF0 with a 2usec
 * resolution. 8160 is 0x1FE0 when written out in hex. So instead of storing
 * the register value which is divided by 2 lets use the actual values and
 * avoid an excessive amount of translation.
 */
#define IAVF_ITR_DYNAMIC	0x8000	/* use top bit as a flag */
#define IAVF_ITR_MASK		0x1FFE	/* mask for ITR register value */
#define IAVF_MIN_ITR		     2	/* reg uses 2 usec resolution */
#define IAVF_ITR_100K		    10	/* all values below must be even */
#define IAVF_ITR_50K		    20
#define IAVF_ITR_20K		    50
#define IAVF_ITR_18K		    60
#define IAVF_ITR_8K		   122
#define IAVF_MAX_ITR		  8160	/* maximum value as per datasheet */
#define ITR_TO_REG(setting) ((setting) & ~IAVF_ITR_DYNAMIC)
#define ITR_REG_ALIGN(setting) __ALIGN_MASK(setting, ~IAVF_ITR_MASK)
#define ITR_IS_DYNAMIC(setting) (!!((setting) & IAVF_ITR_DYNAMIC))

#define IAVF_ITR_RX_DEF		(IAVF_ITR_20K | IAVF_ITR_DYNAMIC)
#define IAVF_ITR_TX_DEF		(IAVF_ITR_20K | IAVF_ITR_DYNAMIC)

/* 0x40 is the enable bit for interrupt rate limiting, and must be set if
 * the value of the rate limit is non-zero
 */
#define INTRL_ENA                  BIT(6)
#define IAVF_MAX_INTRL             0x3B    /* reg uses 4 usec resolution */
#define INTRL_REG_TO_USEC(intrl) ((intrl & ~INTRL_ENA) << 2)
#define INTRL_USEC_TO_REG(set) ((set) ? ((set) >> 2) | INTRL_ENA : 0)
#define IAVF_INTRL_8K              125     /* 8000 ints/sec */
#define IAVF_INTRL_62K             16      /* 62500 ints/sec */
#define IAVF_INTRL_83K             12      /* 83333 ints/sec */

#define IAVF_QUEUE_END_OF_LIST 0x7FF

/* this enum matches hardware bits and is meant to be used by DYN_CTLN
 * registers and QINT registers or more generally anywhere in the manual
 * mentioning ITR_INDX, ITR_NONE cannot be used as an index 'n' into any
 * register but instead is a special value meaning "don't update" ITR0/1/2.
 */
enum iavf_dyn_idx_t {
	IAVF_IDX_ITR0 = 0,
	IAVF_IDX_ITR1 = 1,
	IAVF_IDX_ITR2 = 2,
	IAVF_ITR_NONE = 3	/* ITR_NONE must not be used as an index */
};

/* these are indexes into ITRN registers */
#define IAVF_RX_ITR    IAVF_IDX_ITR0
#define IAVF_TX_ITR    IAVF_IDX_ITR1
#define IAVF_PE_ITR    IAVF_IDX_ITR2

/* Supported RSS offloads */
#define IAVF_DEFAULT_RSS_HENA ( \
	BIT_ULL(IAVF_FILTER_PCTYPE_NONF_IPV4_UDP) | \
	BIT_ULL(IAVF_FILTER_PCTYPE_NONF_IPV4_SCTP) | \
	BIT_ULL(IAVF_FILTER_PCTYPE_NONF_IPV4_TCP) | \
	BIT_ULL(IAVF_FILTER_PCTYPE_NONF_IPV4_OTHER) | \
	BIT_ULL(IAVF_FILTER_PCTYPE_FRAG_IPV4) | \
	BIT_ULL(IAVF_FILTER_PCTYPE_NONF_IPV6_UDP) | \
	BIT_ULL(IAVF_FILTER_PCTYPE_NONF_IPV6_TCP) | \
	BIT_ULL(IAVF_FILTER_PCTYPE_NONF_IPV6_SCTP) | \
	BIT_ULL(IAVF_FILTER_PCTYPE_NONF_IPV6_OTHER) | \
	BIT_ULL(IAVF_FILTER_PCTYPE_FRAG_IPV6) | \
	BIT_ULL(IAVF_FILTER_PCTYPE_L2_PAYLOAD))

#define IAVF_DEFAULT_RSS_HENA_EXPANDED (IAVF_DEFAULT_RSS_HENA | \
	BIT_ULL(IAVF_FILTER_PCTYPE_NONF_IPV4_TCP_SYN_NO_ACK) | \
	BIT_ULL(IAVF_FILTER_PCTYPE_NONF_UNICAST_IPV4_UDP) | \
	BIT_ULL(IAVF_FILTER_PCTYPE_NONF_MULTICAST_IPV4_UDP) | \
	BIT_ULL(IAVF_FILTER_PCTYPE_NONF_IPV6_TCP_SYN_NO_ACK) | \
	BIT_ULL(IAVF_FILTER_PCTYPE_NONF_UNICAST_IPV6_UDP) | \
	BIT_ULL(IAVF_FILTER_PCTYPE_NONF_MULTICAST_IPV6_UDP))

#define iavf_rx_desc iavf_32byte_rx_desc

/**
 * iavf_test_staterr - tests bits in Rx descriptor status and error fields
 * @qword: `wb.qword1.status_error_len` from the descriptor
 * @stat_err: bit number to mask
 *
 * This function does some fast chicanery in order to return the
 * value of the mask which is really only used for boolean tests.
 * The status_error_len doesn't need to be shifted because it begins
 * at offset zero.
 */
static inline bool iavf_test_staterr(u64 qword, const u64 stat_err)
{
	return !!(qword & BIT_ULL(stat_err));
}

/* How many Rx Buffers do we bundle into one write to the hardware ? */
#define IAVF_RX_INCREMENT(r, i) \
	do {					\
		(i)++;				\
		if ((i) == (r)->count)		\
			i = 0;			\
		r->next_to_clean = i;		\
	} while (0)

#define IAVF_RX_NEXT_DESC(r, i, n)		\
	do {					\
		(i)++;				\
		if ((i) == (r)->count)		\
			i = 0;			\
		(n) = IAVF_RX_DESC((r), (i));	\
	} while (0)

#define IAVF_RX_NEXT_DESC_PREFETCH(r, i, n)		\
	do {						\
		IAVF_RX_NEXT_DESC((r), (i), (n));	\
		prefetch((n));				\
	} while (0)

#define IAVF_MAX_BUFFER_TXD	8
#define IAVF_MIN_TX_LEN		17

/* The size limit for a transmit buffer in a descriptor is (16K - 1).
 * In order to align with the read requests we will align the value to
 * the nearest 4K which represents our maximum read request size.
 */
#define IAVF_MAX_READ_REQ_SIZE		4096
#define IAVF_MAX_DATA_PER_TXD		(16 * 1024 - 1)
#define IAVF_MAX_DATA_PER_TXD_ALIGNED \
	(IAVF_MAX_DATA_PER_TXD & ~(IAVF_MAX_READ_REQ_SIZE - 1))

/**
 * iavf_txd_use_count  - estimate the number of descriptors needed for Tx
 * @size: transmit request size in bytes
 *
 * Due to hardware alignment restrictions (4K alignment), we need to
 * assume that we can have no more than 12K of data per descriptor, even
 * though each descriptor can take up to 16K - 1 bytes of aligned memory.
 * Thus, we need to divide by 12K. But division is slow! Instead,
 * we decompose the operation into shifts and one relatively cheap
 * multiply operation.
 *
 * To divide by 12K, we first divide by 4K, then divide by 3:
 *     To divide by 4K, shift right by 12 bits
 *     To divide by 3, multiply by 85, then divide by 256
 *     (Divide by 256 is done by shifting right by 8 bits)
 * Finally, we add one to round up. Because 256 isn't an exact multiple of
 * 3, we'll underestimate near each multiple of 12K. This is actually more
 * accurate as we have 4K - 1 of wiggle room that we can fit into the last
 * segment.  For our purposes this is accurate out to 1M which is orders of
 * magnitude greater than our largest possible GSO size.
 *
 * This would then be implemented as:
 *     return (((size >> 12) * 85) >> 8) + 1;
 *
 * Since multiplication and division are commutative, we can reorder
 * operations into:
 *     return ((size * 85) >> 20) + 1;
 */
static inline unsigned int iavf_txd_use_count(unsigned int size)
{
	return ((size * 85) >> 20) + 1;
}

/* Tx Descriptors needed, worst case */
#define DESC_NEEDED (MAX_SKB_FRAGS + 6)
#define IAVF_MIN_DESC_PENDING	4

#define IAVF_TX_FLAGS_HW_VLAN			BIT(1)
#define IAVF_TX_FLAGS_SW_VLAN			BIT(2)
#define IAVF_TX_FLAGS_TSO			BIT(3)
#define IAVF_TX_FLAGS_IPV4			BIT(4)
#define IAVF_TX_FLAGS_IPV6			BIT(5)
#define IAVF_TX_FLAGS_FCCRC			BIT(6)
#define IAVF_TX_FLAGS_FSO			BIT(7)
/* BIT(9) is free, was IAVF_TX_FLAGS_FD_SB */
#define IAVF_TX_FLAGS_VXLAN_TUNNEL		BIT(10)
#define IAVF_TX_FLAGS_HW_OUTER_SINGLE_VLAN	BIT(11)
#define IAVF_TX_FLAGS_VLAN_MASK			0xffff0000
#define IAVF_TX_FLAGS_VLAN_PRIO_MASK		0xe0000000
#define IAVF_TX_FLAGS_VLAN_PRIO_SHIFT		29
#define IAVF_TX_FLAGS_VLAN_SHIFT		16

struct iavf_tx_buffer {

	/* Track the last frame in batch/packet */
	union {
		struct iavf_tx_desc *next_to_watch;	/* on skb TX queue */
		u16 rs_desc_idx;			/* on XDP queue */
	};
	union {
		struct sk_buff *skb;
		void *raw_buf;
	};
	unsigned int bytecount;
	unsigned short gso_segs;

	DEFINE_DMA_UNMAP_ADDR(dma);
	DEFINE_DMA_UNMAP_LEN(len);
	u32 tx_flags;
};

struct iavf_queue_stats {
	u64 packets;
	u64 bytes;
};

struct iavf_tx_queue_stats {
	u64 restart_queue;
	u64 tx_busy;
	u64 tx_done_old;
	u64 tx_linearize;
	u64 tx_force_wb;
	int prev_pkt_ctr;
	u64 tx_lost_interrupt;
};

struct iavf_rx_queue_stats {
	u64 non_eop_descs;
	u64 alloc_page_failed;
	u64 alloc_buff_failed;
};

enum iavf_ring_state_t {
	__IAVF_TX_FDIR_INIT_DONE,
	__IAVF_TX_XPS_INIT_DONE,
	__IAVF_RING_STATE_NBITS /* must be last */
};

/* some useful defines for virtchannel interface, which
 * is the only remaining user of header split
 */
#define IAVF_RX_DTYPE_NO_SPLIT      0
#define IAVF_RX_DTYPE_HEADER_SPLIT  1
#define IAVF_RX_DTYPE_SPLIT_ALWAYS  2
#define IAVF_RX_SPLIT_L2      0x1
#define IAVF_RX_SPLIT_IP      0x2
#define IAVF_RX_SPLIT_TCP_UDP 0x4
#define IAVF_RX_SPLIT_SCTP    0x8

/* struct that defines a descriptor ring, associated with a VSI */
struct iavf_ring {
	struct iavf_ring *next;		/* pointer to next ring in q_vector */
	void *desc;			/* Descriptor ring memory */
	union {
		struct xsk_buff_pool *xsk_pool; /* Used on XSk queue pairs */
		struct page_pool *pool;	/* Used for Rx page management */
		struct device *dev;	/* Used for DMA mapping on Tx */
	};
	struct net_device *netdev;	/* netdev ring maps to */
	union {
		struct iavf_tx_buffer *tx_bi;
		struct xdp_buff **xdp_buff;
		struct page **rx_pages;
	};
	DECLARE_BITMAP(state, __IAVF_RING_STATE_NBITS);
	u8 __iomem *tail;
	u16 queue_index;		/* Queue number of ring */
	u8 dcb_tc;			/* Traffic class of ring */

	/* high bit set means dynamic, use accessors routines to read/write.
	 * hardware only supports 2us resolution for the ITR registers.
	 * these values always store the USER setting, and must be converted
	 * before programming to a register.
	 */
	u16 itr_setting;

	u16 reg_idx;			/* HW register index of the ring */
	u16 count;			/* Number of descriptors */

	/* used in interrupt processing */
	u16 next_to_use;
	u16 next_to_clean;

	u8 atr_sample_rate;
	u8 atr_count;

	bool ring_active;		/* is ring online or not */
	bool arm_wb;		/* do something to arm write back */
	u8 packet_stride;

	u16 flags;
#define IAVF_TXR_FLAGS_WB_ON_ITR		BIT(0)
#define IAVF_TXRX_FLAGS_ARM_WB			BIT(1)
#define IAVF_TXRX_FLAGS_XDP			BIT(2)
#define IAVF_TXRX_FLAGS_VLAN_TAG_LOC_L2TAG1	BIT(3)
#define IAVF_TXR_FLAGS_VLAN_TAG_LOC_L2TAG2	BIT(4)
#define IAVF_RXR_FLAGS_VLAN_TAG_LOC_L2TAG2_2	BIT(5)
#define IAVF_TXRX_FLAGS_XSK			BIT(6)

	/* stats structs */
	struct iavf_queue_stats	stats;
	struct u64_stats_sync syncp;
	union {
		struct iavf_tx_queue_stats tx_stats;
		struct iavf_rx_queue_stats rx_stats;
	};

	unsigned int size;		/* length of descriptor ring in bytes */
	dma_addr_t dma;			/* physical address of ring */

	struct iavf_vsi *vsi;		/* Backreference to associated VSI */
	struct iavf_q_vector *q_vector;	/* Backreference to associated vector */

	struct rcu_head rcu;		/* to avoid race on free */

	union {
		struct sk_buff *skb;	/* When iavf_clean_rx_ring_irq() must
					 * return before it sees the EOP for
					 * the current packet, we save that skb
					 * here and resume receiving this
					 * packet the next time
					 * iavf_clean_rx_ring_irq() is called
					 * for this ring.
					 */
		spinlock_t tx_lock;	/* Protect XDP TX ring, when shared */
	};

	union {
		struct bpf_prog __rcu *xdp_prog;
		u16 xdp_tx_active;		/* TODO: comment */
	};
	struct iavf_ring *xdp_ring;
	struct xdp_rxq_info xdp_rxq;
} ____cacheline_internodealigned_in_smp;

#define IAVF_RING_QUARTER(R)		((R)->count >> 2)
#define IAVF_RX_DESC(R, i) (&(((union iavf_32byte_rx_desc *)((R)->desc))[i]))
#define IAVF_TX_DESC(R, i) (&(((struct iavf_tx_desc *)((R)->desc))[i]))
#define IAVF_TX_CTXTDESC(R, i) \
	(&(((struct iavf_tx_context_desc *)((R)->desc))[i]))

#define IAVF_ITR_ADAPTIVE_MIN_INC	0x0002
#define IAVF_ITR_ADAPTIVE_MIN_USECS	0x0002
#define IAVF_ITR_ADAPTIVE_MAX_USECS	0x007e
#define IAVF_ITR_ADAPTIVE_LATENCY	0x8000
#define IAVF_ITR_ADAPTIVE_BULK		0x0000
#define ITR_IS_BULK(x) (!((x) & IAVF_ITR_ADAPTIVE_LATENCY))

struct iavf_ring_container {
	struct iavf_ring *ring;		/* pointer to linked list of ring(s) */
	unsigned long next_update;	/* jiffies value of next update */
	unsigned int total_bytes;	/* total bytes processed this int */
	unsigned int total_packets;	/* total packets processed this int */
	u16 count;
	u16 target_itr;			/* target ITR setting for ring(s) */
	u16 current_itr;		/* current ITR setting for ring(s) */
};

/* iterator for handling rings in ring container */
#define iavf_for_each_ring(pos, head) \
	for (pos = (head).ring; pos != NULL; pos = pos->next)

void iavf_alloc_rx_pages(struct iavf_ring *rxr);
netdev_tx_t iavf_xmit_frame(struct sk_buff *skb, struct net_device *netdev);
void iavf_clean_tx_ring(struct iavf_ring *tx_ring);
void iavf_clean_rx_ring(struct iavf_ring *rx_ring);
int iavf_setup_tx_descriptors(struct iavf_ring *tx_ring);
int iavf_setup_rx_descriptors(struct iavf_ring *rx_ring);
void iavf_free_tx_resources(struct iavf_ring *tx_ring);
void iavf_free_rx_resources(struct iavf_ring *rx_ring);
int iavf_napi_poll(struct napi_struct *napi, int budget);
void iavf_force_wb(struct iavf_vsi *vsi, struct iavf_q_vector *q_vector);
u32 iavf_get_tx_pending(struct iavf_ring *ring, bool in_sw);
void iavf_detect_recover_hung(struct iavf_vsi *vsi);
int __iavf_maybe_stop_tx(struct iavf_ring *tx_ring, int size);
bool __iavf_chk_linearize(struct sk_buff *skb);

DECLARE_STATIC_KEY_FALSE(iavf_xdp_locking_key);

void iavf_process_skb_fields(const struct iavf_ring *rx_ring,
			     const union iavf_rx_desc *rx_desc,
			     struct sk_buff *skb, u64 qword);
int iavf_xdp_xmit(struct net_device *dev, int n, struct xdp_frame **frames,
		  u32 flags);

static inline __le64 iavf_build_ctob(u32 td_cmd, u32 td_offset,
				     unsigned int size, u32 td_tag)
{
	return cpu_to_le64(IAVF_TX_DESC_DTYPE_DATA |
			   ((u64)td_cmd  << IAVF_TXD_QW1_CMD_SHIFT) |
			   ((u64)td_offset << IAVF_TXD_QW1_OFFSET_SHIFT) |
			   ((u64)size  << IAVF_TXD_QW1_TX_BUF_SZ_SHIFT) |
			   ((u64)td_tag  << IAVF_TXD_QW1_L2TAG1_SHIFT));
}

/**
 * iavf_xmit_descriptor_count - calculate number of Tx descriptors needed
 * @skb:     send buffer
 *
 * Returns number of data descriptors needed for this skb. Returns 0 to indicate
 * there is not enough descriptors available in this ring since we need at least
 * one descriptor.
 **/
static inline int iavf_xmit_descriptor_count(struct sk_buff *skb)
{
	const skb_frag_t *frag = &skb_shinfo(skb)->frags[0];
	unsigned int nr_frags = skb_shinfo(skb)->nr_frags;
	int count = 0, size = skb_headlen(skb);

	for (;;) {
		count += iavf_txd_use_count(size);

		if (!nr_frags--)
			break;

		size = skb_frag_size(frag++);
	}

	return count;
}

/**
 * iavf_maybe_stop_tx - 1st level check for Tx stop conditions
 * @tx_ring: the ring to be checked
 * @size:    the size buffer we want to assure is available
 *
 * Returns 0 if stop is not needed
 **/
static inline int iavf_maybe_stop_tx(struct iavf_ring *tx_ring, int size)
{
	if (likely(IAVF_DESC_UNUSED(tx_ring) >= size))
		return 0;
	return __iavf_maybe_stop_tx(tx_ring, size);
}

/**
 * iavf_chk_linearize - Check if there are more than 8 fragments per packet
 * @skb:      send buffer
 * @count:    number of buffers used
 *
 * Note: Our HW can't scatter-gather more than 8 fragments to build
 * a packet on the wire and so we need to figure out the cases where we
 * need to linearize the skb.
 **/
static inline bool iavf_chk_linearize(struct sk_buff *skb, int count)
{
	/* Both TSO and single send will work if count is less than 8 */
	if (likely(count < IAVF_MAX_BUFFER_TXD))
		return false;

	if (skb_is_gso(skb))
		return __iavf_chk_linearize(skb);

	/* we can support up to 8 data buffers for a single send */
	return count != IAVF_MAX_BUFFER_TXD;
}
/**
 * txring_txq - helper to convert from a ring to a queue
 * @ring: Tx ring to find the netdev equivalent of
 **/
static inline struct netdev_queue *txring_txq(const struct iavf_ring *ring)
{
	return netdev_get_tx_queue(ring->netdev, ring->queue_index);
}

/**
 * iavf_xdp_ring_update_tail - Updates the XDP Tx ring tail register
 * @xdp_ring: XDP Tx ring
 *
 * Notify hardware the new descriptor is ready to be transmitted
 */
static inline void iavf_xdp_ring_update_tail(const struct iavf_ring *xdp_ring)
{
	/* Force memory writes to complete before letting h/w
	 * know there are new descriptors to fetch.
	 */
	wmb();
	writel_relaxed(xdp_ring->next_to_use, xdp_ring->tail);
}

/**
 * iavf_update_tx_ring_stats - Update TX ring stats after transmit completes
 * @tx_ring: TX descriptor ring
 * @tc: TODO
 * @total_pkts: Number of packets transmitted since the last update
 * @total_bytes: Number of bytes transmitted since the last update
 **/
static inline void __iavf_update_tx_ring_stats(struct iavf_ring *tx_ring,
					       struct iavf_ring_container *tc,
					       u32 total_pkts, u32 total_bytes)
{
	u64_stats_update_begin(&tx_ring->syncp);
	tx_ring->stats.bytes += total_bytes;
	tx_ring->stats.packets += total_pkts;
	u64_stats_update_end(&tx_ring->syncp);
	tc->total_bytes += total_bytes;
	tc->total_packets += total_pkts;
}

#define iavf_update_tx_ring_stats(r, p, b) \
	__iavf_update_tx_ring_stats(r, &(r)->q_vector->tx, p, b)

/**
 * iavf_update_rx_ring_stats - Update RX ring stats
 * @rx_ring: ring to bump
 * @rc: TODO
 * @rx_bytes: number of bytes processed since last update
 * @rx_packets: number of packets processed since last update
 **/
static inline void __iavf_update_rx_ring_stats(struct iavf_ring *rx_ring,
					       struct iavf_ring_container *rc,
					       u32 rx_bytes, u32 rx_packets)
{
	u64_stats_update_begin(&rx_ring->syncp);
	rx_ring->stats.packets += rx_packets;
	rx_ring->stats.bytes += rx_bytes;
	u64_stats_update_end(&rx_ring->syncp);
	rc->total_packets += rx_packets;
	rc->total_bytes += rx_bytes;
}

#define iavf_update_rx_ring_stats(r, p, b) \
	__iavf_update_rx_ring_stats(r, &(r)->q_vector->rx, p, b)

/**
 * iavf_release_rx_desc - Store the new tail and head values
 * @rx_ring: ring to bump
 * @val: new head index
 **/
static inline void iavf_release_rx_desc(struct iavf_ring *rx_ring, u32 val)
{
	rx_ring->next_to_use = val;

	/* Force memory writes to complete before letting h/w
	 * know there are new descriptors to fetch.  (Only
	 * applicable for weak-ordered memory model archs,
	 * such as IA-64).
	 */
	wmb();
	writel(val, rx_ring->tail);
}

#define IAVF_RXQ_XDP_ACT_FINALIZE_TX	BIT(0)
#define IAVF_RXQ_XDP_ACT_FINALIZE_REDIR	BIT(1)
#define IAVF_RXQ_XDP_ACT_STOP_NOW	BIT(2)

/**
 * iavf_set_rs_bit - set RS bit on last produced descriptor.
 * @xdp_ring: XDP ring to produce the HW Tx descriptors on
 *
 * Returns the index of descriptor RS bit was set on (one behind current NTU).
 */
static inline u16 iavf_set_rs_bit(struct iavf_ring *xdp_ring)
{
	u16 rs_idx = xdp_ring->next_to_use ? xdp_ring->next_to_use - 1 :
					     xdp_ring->count - 1;
	struct iavf_tx_desc *tx_desc;

	tx_desc = IAVF_TX_DESC(xdp_ring, rs_idx);
	tx_desc->cmd_type_offset_bsz |=
		cpu_to_le64(IAVF_TX_DESC_CMD_RS << IAVF_TXD_QW1_CMD_SHIFT);

	return rs_idx;
}

/**
 * iavf_finalize_xdp_rx - Finalize XDP actions once per RX ring clean
 * @xdp_ring: XDP TX queue assigned to a given RX ring
 * @rxq_xdp_act: Logical OR of flags of XDP actions that require finalization
 * @first_idx: index of the first frame in the transmitted batch on XDP queue
 **/
static inline void iavf_finalize_xdp_rx(struct iavf_ring *xdp_ring,
					u16 rxq_xdp_act, u32 first_idx)
{
	struct iavf_tx_buffer *tx_buf = &xdp_ring->tx_bi[first_idx];

	if (rxq_xdp_act & IAVF_RXQ_XDP_ACT_FINALIZE_REDIR)
		xdp_do_flush_map();
	if (rxq_xdp_act & IAVF_RXQ_XDP_ACT_FINALIZE_TX) {
		if (static_branch_unlikely(&iavf_xdp_locking_key))
			spin_lock(&xdp_ring->tx_lock);
		tx_buf->rs_desc_idx = iavf_set_rs_bit(xdp_ring);
		iavf_xdp_ring_update_tail(xdp_ring);
		if (static_branch_unlikely(&iavf_xdp_locking_key))
			spin_unlock(&xdp_ring->tx_lock);
	}
}

static inline bool iavf_ring_is_xdp(struct iavf_ring *ring)
{
	return !!(ring->flags & IAVF_TXRX_FLAGS_XDP);
}

#endif /* _IAVF_TXRX_H_ */
