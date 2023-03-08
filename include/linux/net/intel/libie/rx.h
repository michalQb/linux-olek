/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright(c) 2023 Intel Corporation. */

#ifndef __LIBIE_RX_H
#define __LIBIE_RX_H

#include <net/xdp.h>

/* O(1) converting i40e/ice/iavf's 8/10-bit hardware packet type to a parsed
 * bitfield struct.
 */

struct libie_rx_ptype_parsed {
	u16			outer_ip:2;
	u16			outer_frag:1;
	u16			tunnel_type:3;
	u16			tunnel_end_prot:2;
	u16			tunnel_end_frag:1;
	u16			inner_prot:3;
	u16			payload_layer:2;

	enum xdp_rss_hash_type	hash_type:16;
};

enum libie_rx_ptype_outer_ip {
	LIBIE_RX_PTYPE_OUTER_L2				= 0U,
	LIBIE_RX_PTYPE_OUTER_IPV4,
	LIBIE_RX_PTYPE_OUTER_IPV6,
};

enum libie_rx_ptype_outer_fragmented {
	LIBIE_RX_PTYPE_NOT_FRAG				= 0U,
	LIBIE_RX_PTYPE_FRAG,
};

enum libie_rx_ptype_tunnel_type {
	LIBIE_RX_PTYPE_TUNNEL_IP_NONE			= 0U,
	LIBIE_RX_PTYPE_TUNNEL_IP_IP,
	LIBIE_RX_PTYPE_TUNNEL_IP_GRENAT,
	LIBIE_RX_PTYPE_TUNNEL_IP_GRENAT_MAC,
	LIBIE_RX_PTYPE_TUNNEL_IP_GRENAT_MAC_VLAN,
};

enum libie_rx_ptype_tunnel_end_prot {
	LIBIE_RX_PTYPE_TUNNEL_END_NONE			= 0U,
	LIBIE_RX_PTYPE_TUNNEL_END_IPV4,
	LIBIE_RX_PTYPE_TUNNEL_END_IPV6,
};

enum libie_rx_ptype_inner_prot {
	LIBIE_RX_PTYPE_INNER_NONE			= 0U,
	LIBIE_RX_PTYPE_INNER_UDP,
	LIBIE_RX_PTYPE_INNER_TCP,
	LIBIE_RX_PTYPE_INNER_SCTP,
	LIBIE_RX_PTYPE_INNER_ICMP,
	LIBIE_RX_PTYPE_INNER_TIMESYNC,
};

enum libie_rx_ptype_payload_layer {
	LIBIE_RX_PTYPE_PAYLOAD_NONE			= PKT_HASH_TYPE_NONE,
	LIBIE_RX_PTYPE_PAYLOAD_L2			= PKT_HASH_TYPE_L2,
	LIBIE_RX_PTYPE_PAYLOAD_L3			= PKT_HASH_TYPE_L3,
	LIBIE_RX_PTYPE_PAYLOAD_L4			= PKT_HASH_TYPE_L4,
};

#define LIBIE_RX_PTYPE_NUM				154

extern const struct libie_rx_ptype_parsed
libie_rx_ptype_lut[LIBIE_RX_PTYPE_NUM];

/**
 * libie_parse_rx_ptype - convert HW packet type to software bitfield structure
 * @ptype: 10-bit hardware packet type value from the descriptor
 *
 * ```libie_rx_ptype_lut``` must be accessed only using this wrapper.
 *
 * Return: parsed bitfield struct corresponding to the provided ptype.
 */
static inline struct libie_rx_ptype_parsed libie_parse_rx_ptype(u32 ptype)
{
	if (unlikely(ptype >= LIBIE_RX_PTYPE_NUM))
		ptype = 0;

	return libie_rx_ptype_lut[ptype];
}

/* libie_has_*() can be used to quickly check whether the HW metadata is
 * available to avoid further expensive processing such as descriptor reads.
 * They already check for the corresponding netdev feature to be enabled,
 * thus can be used as drop-in replacements.
 */

static inline bool libie_has_rx_checksum(const struct net_device *dev,
					 struct libie_rx_ptype_parsed parsed)
{
	/* Non-zero _INNER* is only possible when _OUTER_IPV* is set,
	 * it is enough to check only for the L4 type.
	 */
	return likely(parsed.inner_prot > LIBIE_RX_PTYPE_INNER_NONE &&
		      (dev->features & NETIF_F_RXCSUM));
}

static inline bool libie_has_rx_hash(const struct net_device *dev,
				     struct libie_rx_ptype_parsed parsed)
{
	return likely(parsed.payload_layer > LIBIE_RX_PTYPE_PAYLOAD_NONE &&
		      (dev->features & NETIF_F_RXHASH));
}

/**
 * libie_skb_set_hash - fill in skb hash value basing on the parsed ptype
 * @skb: skb to fill the hash in
 * @hash: 32-bit hash value from the descriptor
 * @parsed: parsed packet type
 */
static inline void libie_skb_set_hash(struct sk_buff *skb, u32 hash,
				      struct libie_rx_ptype_parsed parsed)
{
	skb_set_hash(skb, hash, parsed.payload_layer);
}

#endif /* __LIBIE_RX_H */
