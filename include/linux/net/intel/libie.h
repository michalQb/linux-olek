/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __LINUX_INTEL_LIBIE_H
#define __LINUX_INTEL_LIBIE_H

#include <linux/netdevice.h>

/* O(1) converting i40e/ice/iavf's 8/10-bit hardware packet type to a parsed
 * bitfield struct.
 */

struct libie_rx_ptype_parsed {
	u32	outer_ip:1;
	u32	outer_ip_ver:2;
	u32	outer_frag:1;
	u32	tunnel_type:3;
	u32	tunnel_end_prot:2;
	u32	tunnel_end_frag:1;
	u32	inner_prot:4;
	u32	payload_layer:3;
};

enum libie_rx_ptype_outer_ip {
	LIBIE_RX_PTYPE_OUTER_L2				= 0U,
	LIBIE_RX_PTYPE_OUTER_IP,
};

enum libie_rx_ptype_outer_ip_ver {
	LIBIE_RX_PTYPE_OUTER_NONE			= 0U,
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
	LIBIE_RX_PTYPE_INNER_PROT_NONE			= 0U,
	LIBIE_RX_PTYPE_INNER_PROT_UDP,
	LIBIE_RX_PTYPE_INNER_PROT_TCP,
	LIBIE_RX_PTYPE_INNER_PROT_SCTP,
	LIBIE_RX_PTYPE_INNER_PROT_ICMP,
	LIBIE_RX_PTYPE_INNER_PROT_TIMESYNC,
};

enum libie_rx_ptype_payload_layer {
	LIBIE_RX_PTYPE_PAYLOAD_LAYER_NONE		= PKT_HASH_TYPE_NONE,
	LIBIE_RX_PTYPE_PAYLOAD_LAYER_PAY2		= PKT_HASH_TYPE_L2,
	LIBIE_RX_PTYPE_PAYLOAD_LAYER_PAY3		= PKT_HASH_TYPE_L3,
	LIBIE_RX_PTYPE_PAYLOAD_LAYER_PAY4		= PKT_HASH_TYPE_L4,
};

#define LIBIE_RX_PTYPE_NUM				154

extern const struct libie_rx_ptype_parsed
libie_rx_ptype_lut[LIBIE_RX_PTYPE_NUM];

static inline struct libie_rx_ptype_parsed libie_parse_rx_ptype(u32 ptype)
{
	if (unlikely(ptype >= LIBIE_RX_PTYPE_NUM))
		return (struct libie_rx_ptype_parsed){ };

	return libie_rx_ptype_lut[ptype];
}

/* libie_has_*() can be used to quickly check whether the HW metadata is
 * available to avoid further expensive processing such as descriptor reads.
 */

static inline bool libie_has_rx_checksum(const struct net_device *dev,
					 struct libie_rx_ptype_parsed parsed)
{
	/* _INNER_PROT_{SCTP,TCP,UDP} are possible only when _OUTER_IP is set,
	 * it is enough to check only for the L4 type.
	 */
	switch (parsed.inner_prot) {
	case LIBIE_RX_PTYPE_INNER_PROT_TCP:
	case LIBIE_RX_PTYPE_INNER_PROT_UDP:
	case LIBIE_RX_PTYPE_INNER_PROT_SCTP:
		break;
	default:
		return false;
	}

	return dev->features & NETIF_F_RXCSUM;
}

static inline bool libie_has_rx_hash(const struct net_device *dev,
				     struct libie_rx_ptype_parsed parsed)
{
	if (parsed.payload_layer < LIBIE_RX_PTYPE_PAYLOAD_LAYER_PAY2)
		return false;

	return dev->features & NETIF_F_RXHASH;
}

static inline void libie_set_skb_hash(struct sk_buff *skb, u32 hash,
				      struct libie_rx_ptype_parsed parsed)
{
	skb_set_hash(skb, hash, parsed.payload_layer);
}

#endif /* __LINUX_INTEL_LIBIE_H */
