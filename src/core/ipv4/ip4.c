/**
 * @file
 * This is the IPv4 layer implementation for incoming and outgoing IP traffic.
 *
 */

/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the dpIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#include "dpip/opt.h"

#include "dpip/ip.h"
#include "dpip/def.h"
#include "dpip/inet_chksum.h"
#include "dpip/netif.h"
#include "dpip/icmp.h"
#include "dpip/priv/tcp_priv.h"
#include "dpip/stats.h"
#include "dpip/prot/iana.h"

#include <string.h>

#ifdef DPIP_HOOK_FILENAME
#include DPIP_HOOK_FILENAME
#endif

/** Set this to 0 in the rare case of wanting to call an extra function to
 * generate the IP checksum (in contrast to calculating it on-the-fly). */
#ifndef DPIP_INLINE_IP_CHKSUM
#if DPIP_CHECKSUM_CTRL_PER_NETIF
#define DPIP_INLINE_IP_CHKSUM   0
#else /* DPIP_CHECKSUM_CTRL_PER_NETIF */
#define DPIP_INLINE_IP_CHKSUM   1
#endif /* DPIP_CHECKSUM_CTRL_PER_NETIF */
#endif

#if DPIP_INLINE_IP_CHKSUM && CHECKSUM_GEN_IP
#define CHECKSUM_GEN_IP_INLINE  1
#else
#define CHECKSUM_GEN_IP_INLINE  0
#endif

/** The IP header ID of the next outgoing IP packet */
static u16_t ip_id;

#if DPIP_MULTICAST_TX_OPTIONS
/** The default netif used for multicast */
static struct netif *ip4_default_multicast_netif;

/**
 * @ingroup ip4
 * Set a default netif for IPv4 multicast. */
void ip4_set_default_multicast_netif(struct netif *default_multicast_netif)
{
	ip4_default_multicast_netif = default_multicast_netif;
}
#endif /* DPIP_MULTICAST_TX_OPTIONS */

#ifdef DPIP_HOOK_IP4_ROUTE_SRC
/**
 * Source based IPv4 routing must be fully implemented in
 * DPIP_HOOK_IP4_ROUTE_SRC(). This function only provides the parameters.
 */
struct netif *ip4_route_src(const ip4_addr_t *src, const ip4_addr_t *dest)
{
	if (src != NULL) {
		/* when src==NULL, the hook is called from ip4_route(dest) */
		struct netif *netif = DPIP_HOOK_IP4_ROUTE_SRC(src, dest);
		if (netif != NULL) {
			return netif;
		}
	}
	return ip4_route(dest);
}
#endif /* DPIP_HOOK_IP4_ROUTE_SRC */

/**
 * Finds the appropriate network interface for a given IP address. It
 * searches the list of network interfaces linearly. A match is found
 * if the masked IP address of the network interface equals the masked
 * IP address given to the function.
 *
 * @param dest the destination IP address for which to find the route
 * @return the netif on which to send to reach dest
 */
struct netif *ip4_route(const ip4_addr_t *dest)
{
#if !DPIP_SINGLE_NETIF
	struct netif *netif;

#if DPIP_MULTICAST_TX_OPTIONS
	/* Use administratively selected interface for multicast by default */
	if (ip4_addr_ismulticast(dest) && ip4_default_multicast_netif) {
		return ip4_default_multicast_netif;
	}
#endif /* DPIP_MULTICAST_TX_OPTIONS */

	/* bug #54569: in case DPIP_SINGLE_NETIF=1 and DPIP_DEBUGF() disabled, the following loop is optimized away */
	DPIP_UNUSED_ARG(dest);

	/* iterate through netifs */
	NETIF_FOREACH(netif) {
		/* is the netif up, does it have a link and a valid address? */
		if (netif_is_up(netif) && netif_is_link_up(netif)
		    && !ip4_addr_isany_val(*netif_ip4_addr(netif))) {
			/* network mask matches? */
			if (ip4_addr_net_eq
			    (dest, netif_ip4_addr(netif),
			     netif_ip4_netmask(netif))) {
				/* return netif on which to forward IP packet */
				return netif;
			}
			/* gateway matches on a non broadcast interface? (i.e. peer in a point to point interface) */
			if (((netif->flags & NETIF_FLAG_BROADCAST) == 0)
			    && ip4_addr_eq(dest, netif_ip4_gw(netif))) {
				/* return netif on which to forward IP packet */
				return netif;
			}
		}
	}

#ifdef DPIP_HOOK_IP4_ROUTE_SRC
	netif = DPIP_HOOK_IP4_ROUTE_SRC(NULL, dest);
	if (netif != NULL) {
		return netif;
	}
#elif defined(DPIP_HOOK_IP4_ROUTE)
	netif = DPIP_HOOK_IP4_ROUTE(dest);
	if (netif != NULL) {
		return netif;
	}
#endif
#endif /* !DPIP_SINGLE_NETIF */

	if ((netif_default == NULL) || !netif_is_up(netif_default)
	    || !netif_is_link_up(netif_default)
	    || ip4_addr_isany_val(*netif_ip4_addr(netif_default))
	    || ip4_addr_isloopback(dest)) {
		/* No matching netif found and default netif is not usable.
		   If this is not good enough for you, use DPIP_HOOK_IP4_ROUTE() */
		DPIP_DEBUGF(IP_DEBUG | DPIP_DBG_LEVEL_SERIOUS,
			    ("ip4_route: No route to %" U16_F ".%" U16_F ".%"
			     U16_F ".%" U16_F "\n", ip4_addr1_16(dest),
			     ip4_addr2_16(dest), ip4_addr3_16(dest),
			     ip4_addr4_16(dest)));
		IP_STATS_INC(ip.rterr);
		MIB2_STATS_INC(mib2.ipoutnoroutes);
		return NULL;
	}

	return netif_default;
}

#if IP_FORWARD
/**
 * Determine whether an IP address is in a reserved set of addresses
 * that may not be forwarded, or whether datagrams to that destination
 * may be forwarded.
 * @param p the packet to forward
 * @return 1: can forward 0: discard
 */
static int ip4_canforward(struct rte_mbuf *p, struct ip_data *ip_data_p)
{
	DPIP_UNUSED_ARG(p);

	u32_t addr =
	    dpip_htonl(ip4_addr_get_u32(ip4_current_dest_addr(ip_data_p)));

#ifdef DPIP_HOOK_IP4_CANFORWARD
	int ret = DPIP_HOOK_IP4_CANFORWARD(p, addr);
	if (ret >= 0) {
		return ret;
	}
#endif /* DPIP_HOOK_IP4_CANFORWARD */

#if 0
	if (p->flags & PBUF_FLAG_LLBCAST) {
		/* don't route link-layer broadcasts */
		return 0;
	}
	if ((p->flags & PBUF_FLAG_LLMCAST) || IP_MULTICAST(addr)) {
		/* don't route link-layer multicasts (use DPIP_HOOK_IP4_CANFORWARD instead) */
		return 0;
	}
#endif
	if (IP_EXPERIMENTAL(addr)) {
		return 0;
	}
	if (IP_CLASSA(addr)) {
		u32_t net = addr & IP_CLASSA_NET;
		if ((net == 0)
		    || (net == ((u32_t) IP_LOOPBACKNET << IP_CLASSA_NSHIFT))) {
			/* don't route loopback packets */
			return 0;
		}
	}
	return 1;
}

/**
 * Forwards an IP packet. It finds an appropriate route for the
 * packet, decrements the TTL value of the packet, adjusts the
 * checksum and outputs the packet on the appropriate interface.
 *
 * @param p the packet to forward (p->payload points to IP header)
 * @param iphdr the IP header of the input packet
 * @param inp the netif on which this packet was received
 */
static void
ip4_forward(struct rte_mbuf *p, struct ip_data *ip_data_p, struct ip_hdr *iphdr,
	    struct netif *inp)
{
	struct netif *netif;

	DPIP_UNUSED_ARG(inp);

	if (!ip4_canforward(p, ip_data_p)) {
		goto return_noroute;
	}

	/* RFC3927 2.7: do not forward link-local addresses */
	if (ip4_addr_islinklocal(ip4_current_dest_addr(ip_data_p))) {
		DPIP_DEBUGF(IP_DEBUG,
			    ("ip4_forward: not forwarding LLA %" U16_F ".%"
			     U16_F ".%" U16_F ".%" U16_F "\n",
			     ip4_addr1_16(ip4_current_dest_addr(ip_data_p)),
			     ip4_addr2_16(ip4_current_dest_addr(ip_data_p)),
			     ip4_addr3_16(ip4_current_dest_addr(ip_data_p)),
			     ip4_addr4_16(ip4_current_dest_addr(ip_data_p))));
		goto return_noroute;
	}

	/* Find network interface where to forward this IP packet to. */
	netif =
	    ip4_route_src(ip4_current_src_addr(ip_data_p),
			  ip4_current_dest_addr(ip_data_p));
	if (netif == NULL) {
		DPIP_DEBUGF(IP_DEBUG,
			    ("ip4_forward: no forwarding route for %" U16_F ".%"
			     U16_F ".%" U16_F ".%" U16_F " found\n",
			     ip4_addr1_16(ip4_current_dest_addr(ip_data_p)),
			     ip4_addr2_16(ip4_current_dest_addr(ip_data_p)),
			     ip4_addr3_16(ip4_current_dest_addr(ip_data_p)),
			     ip4_addr4_16(ip4_current_dest_addr(ip_data_p))));
		/* @todo: send ICMP_DUR_NET? */
		goto return_noroute;
	}
#if !IP_FORWARD_ALLOW_TX_ON_RX_NETIF
	/* Do not forward packets onto the same network interface on which
	 * they arrived. */
	if (netif == inp) {
		DPIP_DEBUGF(IP_DEBUG,
			    ("ip4_forward: not bouncing packets back on incoming interface.\n"));
		goto return_noroute;
	}
#endif /* IP_FORWARD_ALLOW_TX_ON_RX_NETIF */

	/* decrement TTL */
	IPH_TTL_SET(iphdr, IPH_TTL(iphdr) - 1);
	/* send ICMP if TTL == 0 */
	if (IPH_TTL(iphdr) == 0) {
		MIB2_STATS_INC(mib2.ipinhdrerrors);
		/* Don't send ICMP messages in response to ICMP messages */
		if (IPH_PROTO(iphdr) != IP_PROTO_ICMP) {
			icmp_time_exceeded(p, ICMP_TE_TTL);
		}
		return;
	}

	/* Incrementally update the IP checksum. */
	if (IPH_CHKSUM(iphdr) >= PP_HTONS(0xffffU - 0x100)) {
		IPH_CHKSUM_SET(iphdr,
			       (u16_t) (IPH_CHKSUM(iphdr) + PP_HTONS(0x100) +
					1));
	} else {
		IPH_CHKSUM_SET(iphdr,
			       (u16_t) (IPH_CHKSUM(iphdr) + PP_HTONS(0x100)));
	}

	/* Take care of setting checksums to 0 for checksum offload netifs */
	if (CHECKSUM_GEN_IP
	    || NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_GEN_IP)) {
		IPH_CHKSUM_SET(iphdr, 0);
	}
	switch (IPH_PROTO(iphdr)) {
#if DPIP_UDP
#if DPIP_UDPLITE
	case IP_PROTO_UDPLITE:
#endif
	case IP_PROTO_UDP:
		if (CHECKSUM_GEN_UDP
		    || NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_GEN_UDP)) {
			((struct udp_hdr *)((u8_t *) iphdr +
					    IPH_HL_BYTES(iphdr)))->chksum = 0;
		}
		break;
#endif
#if DPIP_TCP
	case IP_PROTO_TCP:
		if (CHECKSUM_GEN_TCP
		    || NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_GEN_TCP)) {
			((struct tcp_hdr *)((u8_t *) iphdr +
					    IPH_HL_BYTES(iphdr)))->chksum = 0;
		}
		break;
#endif
	case IP_PROTO_ICMP:
		if (CHECKSUM_GEN_ICMP
		    || NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_GEN_ICMP)) {
			((struct icmp_hdr *)((u8_t *) iphdr +
					     IPH_HL_BYTES(iphdr)))->chksum = 0;
		}
		break;
	default:
		/* there's really nothing to do here other than satisfying 'switch-default' */
		break;
	}

	DPIP_DEBUGF(IP_DEBUG,
		    ("ip4_forward: forwarding packet to %" U16_F ".%" U16_F ".%"
		     U16_F ".%" U16_F "\n",
		     ip4_addr1_16(ip4_current_dest_addr(ip_data_p)),
		     ip4_addr2_16(ip4_current_dest_addr(ip_data_p)),
		     ip4_addr3_16(ip4_current_dest_addr(ip_data_p)),
		     ip4_addr4_16(ip4_current_dest_addr(ip_data_p))));

	IP_STATS_INC(ip.fw);
	MIB2_STATS_INC(mib2.ipforwdatagrams);
	IP_STATS_INC(ip.xmit);

	/* don't fragment if interface has mtu set to 0 [loopif] */
	if (netif->mtu && (rte_pktmbuf_pkt_len(p) > netif->mtu)) {
		if ((IPH_OFFSET(iphdr) & PP_NTOHS(DPIP_IP_DF)) == 0) {
#if IP_FRAG
			ip4_frag(p, netif, ip4_current_dest_addr(ip_data_p));
#else /* IP_FRAG */
			/* @todo: send ICMP Destination Unreachable code 13 "Communication administratively prohibited"? */
#endif /* IP_FRAG */
		} else {
			/* send ICMP Destination Unreachable code 4: "Fragmentation Needed and DF Set" */
			icmp_dest_unreach(p, ICMP_DUR_FRAG);
		}
		return;
	}
	/* transmit mbuf on chosen interface */
	netif->output(netif, p, ip4_current_dest_addr(ip_data_p));
	return;
 return_noroute:
	MIB2_STATS_INC(mib2.ipoutnoroutes);
}
#endif /* IP_FORWARD */

/** Return true if the current input packet should be accepted on this netif */
static int ip4_input_accept(struct netif *netif, struct ip_data *ip_data_p)
{
	DPIP_DEBUGF(IP_DEBUG,
		    ("ip_input: iphdr->dest 0x%" X32_F " netif->ip_addr 0x%"
		     X32_F " (0x%" X32_F ", 0x%" X32_F ", 0x%" X32_F ")\n",
		     ip4_addr_get_u32(ip4_current_dest_addr(ip_data_p)),
		     ip4_addr_get_u32(netif_ip4_addr(netif)),
		     ip4_addr_get_u32(ip4_current_dest_addr(ip_data_p)) &
		     ip4_addr_get_u32(netif_ip4_netmask(netif)),
		     ip4_addr_get_u32(netif_ip4_addr(netif)) &
		     ip4_addr_get_u32(netif_ip4_netmask(netif)),
		     ip4_addr_get_u32(ip4_current_dest_addr(ip_data_p)) &
		     ~ip4_addr_get_u32(netif_ip4_netmask(netif))));

	/* interface is up and configured? */
	if ((netif_is_up(netif))
	    && (!ip4_addr_isany_val(*netif_ip4_addr(netif)))) {
		/* unicast to this interface address? */
		if (ip4_addr_eq
		    (ip4_current_dest_addr(ip_data_p), netif_ip4_addr(netif)) ||
		    /* or broadcast on this interface network address? */
		    ip4_addr_isbroadcast(ip4_current_dest_addr(ip_data_p),
					 netif)) {
			DPIP_DEBUGF(IP_DEBUG,
				    ("ip4_input: packet accepted on interface %c%c\n",
				     netif->name[0], netif->name[1]));
			/* accept on this netif */
			return 1;
		}
	}
	return 0;
}

/**
 * This function is called by the network interface device driver when
 * an IP packet is received. The function does the basic checks of the
 * IP header such as packet size being at least larger than the header
 * size etc. If the packet was not destined for us, the packet is
 * forwarded (using ip_forward). The IP checksum is always checked.
 *
 * Finally, the packet is sent to the upper layer protocol input function.
 *
 * @param p the received IP packet (p->payload points to IP header)
 * @param inp the netif on which this packet was received
 * @return ERR_OK if the packet was processed (could return ERR_* if it wasn't
 *         processed, but currently always returns ERR_OK)
 */
err_t ip4_input(struct rte_mbuf *p, struct netif *inp)
{
	const struct ip_hdr *iphdr;
	struct netif *netif;
	u16_t iphdr_hlen;
	u16_t iphdr_len;
#if DPIP_RAW
	raw_input_state_t raw_status;
#endif /* DPIP_RAW */
	struct ip_data ip_data;

	IP_STATS_INC(ip.recv);
	MIB2_STATS_INC(mib2.ipinreceives);

	/* identify the IP header */
	iphdr = rte_pktmbuf_mtod(p, struct ip_hdr *);
	if (IPH_V(iphdr) != 4) {
		DPIP_DEBUGF(IP_DEBUG | DPIP_DBG_LEVEL_WARNING,
			    ("IP packet dropped due to bad version number %"
			     U16_F "\n", (u16_t) IPH_V(iphdr)));
		ip4_debug_print(p);
		rte_pktmbuf_free(p);
		IP_STATS_INC(ip.err);
		IP_STATS_INC(ip.drop);
		MIB2_STATS_INC(mib2.ipinhdrerrors);
		return ERR_OK;
	}

	/* obtain IP header length in bytes */
	iphdr_hlen = IPH_HL_BYTES(iphdr);
	/* obtain ip length in bytes */
	iphdr_len = dpip_ntohs(IPH_LEN(iphdr));

	/* Trim pbuf. This is especially required for packets < 60 bytes. */
	if (iphdr_len < rte_pktmbuf_pkt_len(p)) {
		pbuf_realloc(p, iphdr_len);
	}

	/* header length exceeds first mbuf length, or ip length exceeds total mbuf length? */
	if ((iphdr_hlen > rte_pktmbuf_data_len(p))
	    || (iphdr_len > rte_pktmbuf_pkt_len(p)) || (iphdr_hlen < IP_HLEN)) {
		if (iphdr_hlen < IP_HLEN) {
			DPIP_DEBUGF(IP_DEBUG | DPIP_DBG_LEVEL_SERIOUS,
				    ("ip4_input: short IP header (%" U16_F
				     " bytes) received, IP packet dropped\n",
				     iphdr_hlen));
		}
		if (iphdr_hlen > rte_pktmbuf_data_len(p)) {
			DPIP_DEBUGF(IP_DEBUG | DPIP_DBG_LEVEL_SERIOUS,
				    ("IP header (len %" U16_F
				     ") does not fit in first mbuf (len %" U16_F
				     "), IP packet dropped.\n", iphdr_hlen,
				     rte_pktmbuf_data_len(p)));
		}
		if (iphdr_len > rte_pktmbuf_pkt_len(p)) {
			DPIP_DEBUGF(IP_DEBUG | DPIP_DBG_LEVEL_SERIOUS,
				    ("IP (len %" U16_F
				     ") is longer than mbuf (len %" U16_F
				     "), IP packet dropped.\n", iphdr_len,
				     rte_pktmbuf_pkt_len(p)));
		}
		/* free (drop) packet mbufs */
		rte_pktmbuf_free(p);
		IP_STATS_INC(ip.lenerr);
		IP_STATS_INC(ip.drop);
		MIB2_STATS_INC(mib2.ipindiscards);
		return ERR_OK;
	}

	/* verify checksum */
#if CHECKSUM_CHECK_IP
	IF__NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_CHECK_IP) {
		if (inet_chksum(iphdr, iphdr_hlen) != 0) {

			DPIP_DEBUGF(IP_DEBUG | DPIP_DBG_LEVEL_SERIOUS,
				    ("Checksum (0x%" X16_F
				     ") failed, IP packet dropped.\n",
				     inet_chksum(iphdr, iphdr_hlen)));
			ip4_debug_print(p);
			rte_pktmbuf_free(p);
			IP_STATS_INC(ip.chkerr);
			IP_STATS_INC(ip.drop);
			MIB2_STATS_INC(mib2.ipinhdrerrors);
			return ERR_OK;
		}
	}
#endif

	/* copy IP addresses to aligned ip_addr_t */
	ip_addr_copy_from_ip4(ip_data.current_iphdr_dest, iphdr->dest);
	ip_addr_copy_from_ip4(ip_data.current_iphdr_src, iphdr->src);

	/* match packet against an interface, i.e. is this packet for us? */
	if (ip4_addr_ismulticast(ip4_current_dest_addr(&ip_data))) {
		if ((netif_is_up(inp))
		    && (!ip4_addr_isany_val(*netif_ip4_addr(inp)))) {
			netif = inp;
		} else {
			netif = NULL;
		}
	} else {
		/* start trying with inp. if that's not acceptable, start walking the
		   list of configured netifs. */
		if (ip4_input_accept(inp, &ip_data)) {
			netif = inp;
		} else {
			netif = NULL;
#if !DPIP_SINGLE_NETIF
			NETIF_FOREACH(netif) {
				if (netif == inp) {
					/* we checked that before already */
					continue;
				}
				if (ip4_input_accept(netif, &ip_data)) {
					break;
				}
			}
#endif /* !DPIP_SINGLE_NETIF */
		}
	}

	{
		if ((ip4_addr_isbroadcast(ip4_current_src_addr(&ip_data), inp))
		    || (ip4_addr_ismulticast(ip4_current_src_addr(&ip_data)))) {
			/* packet source is not valid */
			DPIP_DEBUGF(IP_DEBUG | DPIP_DBG_TRACE |
				    DPIP_DBG_LEVEL_WARNING,
				    ("ip4_input: packet source is not valid.\n"));
			/* free (drop) packet mbufs */
			rte_pktmbuf_free(p);
			IP_STATS_INC(ip.drop);
			MIB2_STATS_INC(mib2.ipinaddrerrors);
			MIB2_STATS_INC(mib2.ipindiscards);
			return ERR_OK;
		}
	}

	/* packet not for us? */
	if (netif == NULL) {
		/* packet not for us, route or discard */
		DPIP_DEBUGF(IP_DEBUG | DPIP_DBG_TRACE,
			    ("ip4_input: packet not for us.\n"));
#if IP_FORWARD
		/* non-broadcast packet? */
		if (!ip4_addr_isbroadcast(ip4_current_dest_addr(&ip_data), inp)) {
			/* try to forward IP packet on (other) interfaces */
			ip4_forward(p, &ip_data,
				    rte_pktmbuf_mtod(p, struct ip_hdr *), inp);
		} else
#endif /* IP_FORWARD */
		{
			IP_STATS_INC(ip.drop);
			MIB2_STATS_INC(mib2.ipinaddrerrors);
			MIB2_STATS_INC(mib2.ipindiscards);
		}
		rte_pktmbuf_free(p);
		return ERR_OK;
	}
	/* packet consists of multiple fragments? */
	if ((IPH_OFFSET(iphdr) & PP_HTONS(DPIP_IP_OFFMASK | DPIP_IP_MF)) != 0) {
#if IP_REASSEMBLY		/* packet fragment reassembly code present? */
		DPIP_DEBUGF(IP_DEBUG,
			    ("IP packet is a fragment (id=0x%04" X16_F
			     " tot_len=%" U16_F " len=%" U16_F " MF=%" U16_F
			     " offset=%" U16_F "), calling ip4_reass()\n",
			     dpip_ntohs(IPH_ID(iphdr)), rte_pktmbuf_pkt_len(p),
			     dpip_ntohs(IPH_LEN(iphdr)),
			     (u16_t) ! !(IPH_OFFSET(iphdr) &
					 PP_HTONS(DPIP_IP_MF)),
			     (u16_t) ((dpip_ntohs(IPH_OFFSET(iphdr)) &
				       DPIP_IP_OFFMASK) * 8)));
		/* reassemble the packet */
		p = ip4_reass(p);
		/* packet not fully reassembled yet? */
		if (p == NULL) {
			return ERR_OK;
		}
		iphdr = rte_pktmbuf_mtod(p, const struct ip_hdr *);
#else /* IP_REASSEMBLY == 0, no packet fragment reassembly code present */
		rte_pktmbuf_free(p);
		DPIP_DEBUGF(IP_DEBUG | DPIP_DBG_LEVEL_SERIOUS,
			    ("IP packet dropped since it was fragmented (0x%"
			     X16_F ") (while IP_REASSEMBLY == 0).\n",
			     dpip_ntohs(IPH_OFFSET(iphdr))));
		IP_STATS_INC(ip.opterr);
		IP_STATS_INC(ip.drop);
		/* unsupported protocol feature */
		MIB2_STATS_INC(mib2.ipinunknownprotos);
		return ERR_OK;
#endif /* IP_REASSEMBLY */
	}

#if IP_OPTIONS_ALLOWED == 0	/* no support for IP options in the IP header? */

	if (iphdr_hlen > IP_HLEN) {
		DPIP_DEBUGF(IP_DEBUG | DPIP_DBG_LEVEL_SERIOUS,
			    ("IP packet dropped since there were IP options (while IP_OPTIONS_ALLOWED == 0).\n"));
		rte_pktmbuf_free(p);
		IP_STATS_INC(ip.opterr);
		IP_STATS_INC(ip.drop);
		/* unsupported protocol feature */
		MIB2_STATS_INC(mib2.ipinunknownprotos);
		return ERR_OK;
	}
#endif /* IP_OPTIONS_ALLOWED == 0 */

	/* send to upper layers */
	DPIP_DEBUGF(IP_DEBUG, ("ip4_input: \n"));
	ip4_debug_print(p);
	DPIP_DEBUGF(IP_DEBUG,
		    ("ip4_input: data_len(p) %" U16_F " pkt_len(p) %" U16_F
		     "\n", rte_pktmbuf_data_len(p), rte_pktmbuf_pkt_len(p)));

	ip_data.current_netif = netif;
	ip_data.current_ip4_header = iphdr;
	ip_data.current_ip_header_tot_len = IPH_HL_BYTES(iphdr);

#if DPIP_RAW
	/* raw input did not eat the packet? */
	raw_status = raw_input(p, inp);
	if (raw_status != RAW_INPUT_EATEN)
#endif /* DPIP_RAW */
	{
		rte_pktmbuf_adj(p, iphdr_hlen);	/* Move to payload, no check necessary. */

		switch (IPH_PROTO(iphdr)) {
#if DPIP_UDP
		case IP_PROTO_UDP:
#if DPIP_UDPLITE
		case IP_PROTO_UDPLITE:
#endif /* DPIP_UDPLITE */
			MIB2_STATS_INC(mib2.ipindelivers);
			udp_input(p, inp);
			break;
#endif /* DPIP_UDP */
#if DPIP_TCP
		case IP_PROTO_TCP:
			MIB2_STATS_INC(mib2.ipindelivers);
			tcp_input(p, inp, &ip_data);
			break;
#endif /* DPIP_TCP */
		case IP_PROTO_ICMP:
			MIB2_STATS_INC(mib2.ipindelivers);
			icmp_input(p, inp, &ip_data);
			break;
		default:
#if DPIP_RAW
			if (raw_status == RAW_INPUT_DELIVERED) {
				MIB2_STATS_INC(mib2.ipindelivers);
			} else
#endif /* DPIP_RAW */
			{
				/* send ICMP destination protocol unreachable unless is was a broadcast */
				if (!ip4_addr_isbroadcast
				    (ip4_current_dest_addr(&ip_data), netif)
				    &&
				    !ip4_addr_ismulticast(ip4_current_dest_addr
							  (&ip_data))) {
					rte_pktmbuf_prepend(p, (s16_t) iphdr_hlen);	/* Move to ip header, no check necessary. */
					icmp_dest_unreach(p, ICMP_DUR_PROTO);
				}

				DPIP_DEBUGF(IP_DEBUG | DPIP_DBG_LEVEL_SERIOUS,
					    ("Unsupported transport protocol %"
					     U16_F "\n",
					     (u16_t) IPH_PROTO(iphdr)));

				IP_STATS_INC(ip.proterr);
				IP_STATS_INC(ip.drop);
				MIB2_STATS_INC(mib2.ipinunknownprotos);
			}
			rte_pktmbuf_free(p);
			break;
		}
	}

	return ERR_OK;
}

/**
 * Sends an IP packet on a network interface. This function constructs
 * the IP header and calculates the IP header checksum. If the source
 * IP address is NULL, the IP address of the outgoing network
 * interface is filled in as source address.
 * If the destination IP address is DPIP_IP_HDRINCL, p is assumed to already
 * include an IP header and p->payload points to it instead of the data.
 *
 * @param p the packet to send (p->payload points to the data, e.g. next
            protocol header; if dest == DPIP_IP_HDRINCL, p already includes an
            IP header and p->payload points to that IP header)
 * @param src the source IP address to send from (if src == IP4_ADDR_ANY, the
 *         IP  address of the netif used to send is used as source address)
 * @param dest the destination IP address to send the packet to
 * @param ttl the TTL value to be set in the IP header
 * @param tos the TOS value to be set in the IP header
 * @param proto the PROTOCOL to be set in the IP header
 * @param netif the netif on which to send this packet
 * @return ERR_OK if the packet was sent OK
 *         ERR_BUF if p doesn't have enough space for IP/LINK headers
 *         returns errors returned by netif->output
 *
 * @note ip_id: RFC791 "some host may be able to simply use
 *  unique identifiers independent of destination"
 */
err_t
ip4_output_if(struct rte_mbuf *p, const ip4_addr_t *src, const ip4_addr_t *dest,
	      u8_t ttl, u8_t tos, u8_t proto, struct netif *netif)
{
	const ip4_addr_t *src_used = src;
	if (dest != DPIP_IP_HDRINCL) {
		if (ip4_addr_isany(src)) {
			src_used = netif_ip4_addr(netif);
		}
	}

	return ip4_output_if_src(p, src_used, dest, ttl, tos, proto, netif);
}

/**
 * Same as ip_output_if() but 'src' address is not replaced by netif address
 * when it is 'any'.
 */
err_t
ip4_output_if_src(struct rte_mbuf *p, const ip4_addr_t *src,
		  const ip4_addr_t *dest, u8_t ttl, u8_t tos, u8_t proto,
		  struct netif *netif)
{
	struct ip_hdr *iphdr;
	ip4_addr_t dest_addr;
#if CHECKSUM_GEN_IP_INLINE
	u32_t chk_sum = 0;
#endif /* CHECKSUM_GEN_IP_INLINE */

	DPIP_IP_CHECK_PBUF_REF_COUNT_FOR_TX(p);

	MIB2_STATS_INC(mib2.ipoutrequests);

	/* Should the IP header be generated or is it already included in p? */
	if (dest != DPIP_IP_HDRINCL) {
		u16_t ip_hlen = IP_HLEN;
		/* generate IP header */
		if (rte_pktmbuf_prepend(p, IP_HLEN) == NULL) {
			DPIP_DEBUGF(IP_DEBUG | DPIP_DBG_LEVEL_SERIOUS,
				    ("ip4_output: not enough room for IP header in mbuf\n"));

			IP_STATS_INC(ip.err);
			MIB2_STATS_INC(mib2.ipoutdiscards);
			return ERR_BUF;
		}

		iphdr = rte_pktmbuf_mtod(p, struct ip_hdr *);
		DPIP_ASSERT("check that first mbuf can hold struct ip_hdr",
			    (rte_pktmbuf_data_len(p) >= sizeof(struct ip_hdr)));

		IPH_TTL_SET(iphdr, ttl);
		IPH_PROTO_SET(iphdr, proto);
#if CHECKSUM_GEN_IP_INLINE
		chk_sum += PP_NTOHS(proto | (ttl << 8));
#endif /* CHECKSUM_GEN_IP_INLINE */

		/* dest cannot be NULL here */
		ip4_addr_copy(iphdr->dest, *dest);
#if CHECKSUM_GEN_IP_INLINE
		chk_sum += ip4_addr_get_u32(&iphdr->dest) & 0xFFFF;
		chk_sum += ip4_addr_get_u32(&iphdr->dest) >> 16;
#endif /* CHECKSUM_GEN_IP_INLINE */

		IPH_VHL_SET(iphdr, 4, ip_hlen / 4);
		IPH_TOS_SET(iphdr, tos);
#if CHECKSUM_GEN_IP_INLINE
		chk_sum += PP_NTOHS(tos | (iphdr->_v_hl << 8));
#endif /* CHECKSUM_GEN_IP_INLINE */
		IPH_LEN_SET(iphdr, dpip_htons(rte_pktmbuf_pkt_len(p)));
#if CHECKSUM_GEN_IP_INLINE
		chk_sum += iphdr->_len;
#endif /* CHECKSUM_GEN_IP_INLINE */
		IPH_OFFSET_SET(iphdr, 0);
		IPH_ID_SET(iphdr, dpip_htons(ip_id));
#if CHECKSUM_GEN_IP_INLINE
		chk_sum += iphdr->_id;
#endif /* CHECKSUM_GEN_IP_INLINE */
		++ip_id;

		if (src == NULL) {
			ip4_addr_copy(iphdr->src, *IP4_ADDR_ANY4);
		} else {
			/* src cannot be NULL here */
			ip4_addr_copy(iphdr->src, *src);
		}

#if CHECKSUM_GEN_IP_INLINE
		chk_sum += ip4_addr_get_u32(&iphdr->src) & 0xFFFF;
		chk_sum += ip4_addr_get_u32(&iphdr->src) >> 16;
		chk_sum = (chk_sum >> 16) + (chk_sum & 0xFFFF);
		chk_sum = (chk_sum >> 16) + chk_sum;
		chk_sum = ~chk_sum;
		IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_IP) {
			iphdr->_chksum = (u16_t) chk_sum;	/* network order */
		}
#if DPIP_CHECKSUM_CTRL_PER_NETIF
		else {
			IPH_CHKSUM_SET(iphdr, 0);
		}
#endif /* DPIP_CHECKSUM_CTRL_PER_NETIF */
#else /* CHECKSUM_GEN_IP_INLINE */
		IPH_CHKSUM_SET(iphdr, 0);
#if CHECKSUM_GEN_IP
		IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_IP) {
			IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, ip_hlen));
		}
#endif /* CHECKSUM_GEN_IP */
#endif /* CHECKSUM_GEN_IP_INLINE */
	} else {
		/* IP header already included in p */
		if (rte_pktmbuf_data_len(p) < IP_HLEN) {
			DPIP_DEBUGF(IP_DEBUG | DPIP_DBG_LEVEL_SERIOUS,
				    ("ip4_output: DPIP_IP_HDRINCL but mbuf is too short\n"));
			IP_STATS_INC(ip.err);
			MIB2_STATS_INC(mib2.ipoutdiscards);
			return ERR_BUF;
		}
		iphdr = rte_pktmbuf_mtod(p, struct ip_hdr *);
		ip4_addr_copy(dest_addr, iphdr->dest);
		dest = &dest_addr;
	}

	IP_STATS_INC(ip.xmit);

	DPIP_DEBUGF(IP_DEBUG,
		    ("ip4_output_if: %c%c%" U16_F "\n", netif->name[0],
		     netif->name[1], (u16_t) netif->num));
	ip4_debug_print(p);

#if IP_FRAG
	/* don't fragment if interface has mtu set to 0 [loopif] */
	if (netif->mtu && (rte_pktmbuf_pkt_len(p) > netif->mtu)) {
		return ip4_frag(p, netif, dest);
	}
#endif /* IP_FRAG */

	DPIP_DEBUGF(IP_DEBUG, ("ip4_output_if: call netif->output()\n"));
	return netif->output(netif, p, dest);
}

/**
 * Simple interface to ip_output_if. It finds the outgoing network
 * interface and calls upon ip_output_if to do the actual work.
 *
 * @param p the packet to send (p->payload points to the data, e.g. next
            protocol header; if dest == DPIP_IP_HDRINCL, p already includes an
            IP header and p->payload points to that IP header)
 * @param src the source IP address to send from (if src == IP4_ADDR_ANY, the
 *         IP  address of the netif used to send is used as source address)
 * @param dest the destination IP address to send the packet to
 * @param ttl the TTL value to be set in the IP header
 * @param tos the TOS value to be set in the IP header
 * @param proto the PROTOCOL to be set in the IP header
 *
 * @return ERR_RTE if no route is found
 *         see ip_output_if() for more return values
 */
err_t
ip4_output(struct rte_mbuf *p, const ip4_addr_t *src, const ip4_addr_t *dest,
	   u8_t ttl, u8_t tos, u8_t proto)
{
	struct netif *netif;

	DPIP_IP_CHECK_PBUF_REF_COUNT_FOR_TX(p);

	if ((netif = ip4_route_src(src, dest)) == NULL) {
		DPIP_DEBUGF(IP_DEBUG,
			    ("ip4_output: No route to %" U16_F ".%" U16_F ".%"
			     U16_F ".%" U16_F "\n", ip4_addr1_16(dest),
			     ip4_addr2_16(dest), ip4_addr3_16(dest),
			     ip4_addr4_16(dest)));
		IP_STATS_INC(ip.rterr);
		return ERR_RTE;
	}

	return ip4_output_if(p, src, dest, ttl, tos, proto, netif);
}

#if DPIP_NETIF_USE_HINTS
/** Like ip_output, but takes and addr_hint pointer that is passed on to netif->addr_hint
 *  before calling ip_output_if.
 *
 * @param p the packet to send (p->payload points to the data, e.g. next
            protocol header; if dest == DPIP_IP_HDRINCL, p already includes an
            IP header and p->payload points to that IP header)
 * @param src the source IP address to send from (if src == IP4_ADDR_ANY, the
 *         IP  address of the netif used to send is used as source address)
 * @param dest the destination IP address to send the packet to
 * @param ttl the TTL value to be set in the IP header
 * @param tos the TOS value to be set in the IP header
 * @param proto the PROTOCOL to be set in the IP header
 * @param netif_hint netif output hint pointer set to netif->hint before
 *        calling ip_output_if()
 *
 * @return ERR_RTE if no route is found
 *         see ip_output_if() for more return values
 */
err_t
ip4_output_hinted(struct rte_mbuf *p, const ip4_addr_t *src,
		  const ip4_addr_t *dest, u8_t ttl, u8_t tos, u8_t proto,
		  struct netif_hint *netif_hint)
{
	struct netif *netif;
	err_t err;

	DPIP_IP_CHECK_PBUF_REF_COUNT_FOR_TX(p);

	if ((netif = ip4_route_src(src, dest)) == NULL) {
		DPIP_DEBUGF(IP_DEBUG,
			    ("ip4_output: No route to %" U16_F ".%" U16_F ".%"
			     U16_F ".%" U16_F "\n", ip4_addr1_16(dest),
			     ip4_addr2_16(dest), ip4_addr3_16(dest),
			     ip4_addr4_16(dest)));
		IP_STATS_INC(ip.rterr);
		return ERR_RTE;
	}

	NETIF_SET_HINTS(netif, netif_hint);
	err = ip4_output_if(p, src, dest, ttl, tos, proto, netif);
	NETIF_RESET_HINTS(netif);

	return err;
}
#endif /* DPIP_NETIF_USE_HINTS */

#if IP_DEBUG
/* Print an IP header by using DPIP_DEBUGF
 * @param p an IP packet, p->payload pointing to the IP header
 */
void ip4_debug_print(struct rte_mbuf *p)
{
	struct ip_hdr *iphdr = rte_pktmbuf_mtod(p, struct ip_hdr *);

	DPIP_DEBUGF(IP_DEBUG, ("IP header:\n"));
	DPIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
	DPIP_DEBUGF(IP_DEBUG,
		    ("|%2" S16_F " |%2" S16_F " |  0x%02" X16_F " |     %5"
		     U16_F "     | (v, hl, tos, len)\n", (u16_t) IPH_V(iphdr),
		     (u16_t) IPH_HL(iphdr), (u16_t) IPH_TOS(iphdr),
		     dpip_ntohs(IPH_LEN(iphdr))));
	DPIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
	DPIP_DEBUGF(IP_DEBUG,
		    ("|    %5" U16_F "      |%" U16_F "%" U16_F "%" U16_F
		     "|    %4" U16_F "   | (id, flags, offset)\n",
		     dpip_ntohs(IPH_ID(iphdr)),
		     (u16_t) (dpip_ntohs(IPH_OFFSET(iphdr)) >> 15 & 1),
		     (u16_t) (dpip_ntohs(IPH_OFFSET(iphdr)) >> 14 & 1),
		     (u16_t) (dpip_ntohs(IPH_OFFSET(iphdr)) >> 13 & 1),
		     (u16_t) (dpip_ntohs(IPH_OFFSET(iphdr)) &
			      DPIP_IP_OFFMASK)));
	DPIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
	DPIP_DEBUGF(IP_DEBUG,
		    ("|  %3" U16_F "  |  %3" U16_F "  |    0x%04" X16_F
		     "     | (ttl, proto, chksum)\n", (u16_t) IPH_TTL(iphdr),
		     (u16_t) IPH_PROTO(iphdr), dpip_ntohs(IPH_CHKSUM(iphdr))));
	DPIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
	DPIP_DEBUGF(IP_DEBUG,
		    ("|  %3" U16_F "  |  %3" U16_F "  |  %3" U16_F "  |  %3"
		     U16_F "  | (src)\n", ip4_addr1_16_val(iphdr->src),
		     ip4_addr2_16_val(iphdr->src), ip4_addr3_16_val(iphdr->src),
		     ip4_addr4_16_val(iphdr->src)));
	DPIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
	DPIP_DEBUGF(IP_DEBUG,
		    ("|  %3" U16_F "  |  %3" U16_F "  |  %3" U16_F "  |  %3"
		     U16_F "  | (dest)\n", ip4_addr1_16_val(iphdr->dest),
		     ip4_addr2_16_val(iphdr->dest),
		     ip4_addr3_16_val(iphdr->dest),
		     ip4_addr4_16_val(iphdr->dest)));
	DPIP_DEBUGF(IP_DEBUG, ("+-------------------------------+\n"));
}
#endif /* IP_DEBUG */
