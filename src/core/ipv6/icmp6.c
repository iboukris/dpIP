/**
 * @file
 *
 * IPv6 version of ICMP, as per RFC 4443.
 */

/*
 * Copyright (c) 2010 Inico Technologies Ltd.
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
 * Author: Ivan Delamer <delamer@inicotech.com>
 *
 *
 * Please coordinate changes and requests with Ivan Delamer
 * <delamer@inicotech.com>
 */

#include "dpip/opt.h"

#include "dpip/icmp6.h"
#include "dpip/prot/icmp6.h"
#include "dpip/ip6.h"
#include "dpip/ip6_addr.h"
#include "dpip/inet_chksum.h"
#include "dpip/pbuf.h"
#include "dpip/netif.h"
#include "dpip/nd6.h"
#include "dpip/ip.h"
#include "dpip/stats.h"

#include <string.h>

#if !DPIP_ICMP6_DATASIZE || (DPIP_ICMP6_DATASIZE > (IP6_MIN_MTU_LENGTH - IP6_HLEN - ICMP6_HLEN))
#undef DPIP_ICMP6_DATASIZE
#define DPIP_ICMP6_DATASIZE   (IP6_MIN_MTU_LENGTH - IP6_HLEN - ICMP6_HLEN)
#endif

/* Forward declarations */
static void icmp6_send_response(struct rte_mbuf *p, struct ip_data *ip_data_p,
				u8_t code, u32_t data, u8_t type);
static void icmp6_send_response_with_addrs(struct rte_mbuf *p, u8_t code,
					   u32_t data, u8_t type,
					   const ip6_addr_t * src_addr,
					   const ip6_addr_t * dest_addr);
static void icmp6_send_response_with_addrs_and_netif(struct rte_mbuf *p,
						     u8_t code, u32_t data,
						     u8_t type,
						     const ip6_addr_t *
						     src_addr,
						     const ip6_addr_t *
						     dest_addr,
						     struct netif *netif);

/**
 * Process an input ICMPv6 message. Called by ip6_input.
 *
 * Will generate a reply for echo requests. Other messages are forwarded
 * to nd6_input, or mld6_input.
 *
 * @param p the mld packet, p->payload pointing to the icmpv6 header
 * @param inp the netif on which this packet was received
 */
void
icmp6_input(struct rte_mbuf *p, struct netif *inp, struct ip_data *ip_data_p)
{
	struct icmp6_hdr *icmp6hdr;
	struct rte_mbuf *r;
	const ip6_addr_t *reply_src;

	ICMP6_STATS_INC(icmp6.recv);

	/* Check that ICMPv6 header fits in payload */
	if (rte_pktmbuf_data_len(p) < sizeof(struct icmp6_hdr)) {
		/* drop short packets */
		rte_pktmbuf_free(p);
		ICMP6_STATS_INC(icmp6.lenerr);
		ICMP6_STATS_INC(icmp6.drop);
		return;
	}

	icmp6hdr = rte_pktmbuf_mtod(p, struct icmp6_hdr *);

#if CHECKSUM_CHECK_ICMP6
	IF__NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_CHECK_ICMP6) {
		if (ip6_chksum_pseudo
		    (p, IP6_NEXTH_ICMP6, rte_pktmbuf_pkt_len(p),
		     ip6_current_src_addr(ip_data_p),
		     ip6_current_dest_addr(ip_data_p)) != 0) {
			/* Checksum failed */
			rte_pktmbuf_free(p);
			ICMP6_STATS_INC(icmp6.chkerr);
			ICMP6_STATS_INC(icmp6.drop);
			return;
		}
	}
#endif /* CHECKSUM_CHECK_ICMP6 */

	switch (icmp6hdr->type) {
	case ICMP6_TYPE_NA:	/* Neighbor advertisement */
	case ICMP6_TYPE_NS:	/* Neighbor solicitation */
	case ICMP6_TYPE_RA:	/* Router advertisement */
	case ICMP6_TYPE_RD:	/* Redirect */
	case ICMP6_TYPE_PTB:	/* Packet too big */
		nd6_input(p, ip_data_p, inp);
		return;
	case ICMP6_TYPE_RS:
#if DPIP_IPV6_FORWARD
		/* @todo implement router functionality */
#endif
		break;
	case ICMP6_TYPE_EREQ:
#if !DPIP_MULTICAST_PING
		/* multicast destination address? */
		if (ip6_addr_ismulticast(ip6_current_dest_addr(ip_data_p))) {
			/* drop */
			rte_pktmbuf_free(p);
			ICMP6_STATS_INC(icmp6.drop);
			return;
		}
#endif /* DPIP_MULTICAST_PING */

		/* Allocate reply. */
		r = pbuf_alloc(PBUF_IP, rte_pktmbuf_pkt_len(p), PBUF_RAM);
		if (r == NULL) {
			/* drop */
			rte_pktmbuf_free(p);
			ICMP6_STATS_INC(icmp6.memerr);
			return;
		}

		/* Copy echo request. */
		if (pbuf_copy(r, p) != ERR_OK) {
			/* drop */
			rte_pktmbuf_free(p);
			rte_pktmbuf_free(r);
			ICMP6_STATS_INC(icmp6.err);
			return;
		}

		/* Determine reply source IPv6 address. */
#if DPIP_MULTICAST_PING
		if (ip6_addr_ismulticast(ip6_current_dest_addr(ip_data_p))) {
			reply_src =
			    ip_2_ip6(ip6_select_source_address
				     (inp, ip6_current_src_addr(ip_data_p)));
			if (reply_src == NULL) {
				/* drop */
				rte_pktmbuf_free(p);
				rte_pktmbuf_free(r);
				ICMP6_STATS_INC(icmp6.rterr);
				return;
			}
		} else
#endif /* DPIP_MULTICAST_PING */
		{
			reply_src = ip6_current_dest_addr(ip_data_p);
		}

		/* Set fields in reply. */
		rte_pktmbuf_mtod(r, struct icmp6_echo_hdr *)->type =
		    ICMP6_TYPE_EREP;
		rte_pktmbuf_mtod(r, struct icmp6_echo_hdr *)->chksum = 0;
#if CHECKSUM_GEN_ICMP6
		IF__NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_GEN_ICMP6) {
			rte_pktmbuf_mtod(r, struct icmp6_echo_hdr *)->chksum =
			    ip6_chksum_pseudo(r, IP6_NEXTH_ICMP6,
					      rte_pktmbuf_pkt_len(r), reply_src,
					      ip6_current_src_addr(ip_data_p));
		}
#endif /* CHECKSUM_GEN_ICMP6 */

		/* Send reply. */
		ICMP6_STATS_INC(icmp6.xmit);
		ip6_output_if(r, reply_src, ip6_current_src_addr(ip_data_p),
			      DPIP_ICMP6_HL, 0, IP6_NEXTH_ICMP6, inp);
		rte_pktmbuf_free(r);

		break;
	default:
		ICMP6_STATS_INC(icmp6.proterr);
		ICMP6_STATS_INC(icmp6.drop);
		break;
	}

	rte_pktmbuf_free(p);
}

/**
 * Send an icmpv6 'destination unreachable' packet.
 *
 * This function must be used only in direct response to a packet that is being
 * received right now. Otherwise, address zones would be lost.
 *
 * @param p the input packet for which the 'unreachable' should be sent,
 *          p->payload pointing to the IPv6 header
 * @param c ICMPv6 code for the unreachable type
 */
void
icmp6_dest_unreach(struct rte_mbuf *p, struct ip_data *ip_data_p,
		   enum icmp6_dur_code c)
{
	icmp6_send_response(p, ip_data_p, c, 0, ICMP6_TYPE_DUR);
}

/**
 * Send an icmpv6 'packet too big' packet.
 *
 * This function must be used only in direct response to a packet that is being
 * received right now. Otherwise, address zones would be lost.
 *
 * @param p the input packet for which the 'packet too big' should be sent,
 *          p->payload pointing to the IPv6 header
 * @param mtu the maximum mtu that we can accept
 */
void
icmp6_packet_too_big(struct rte_mbuf *p, struct ip_data *ip_data_p, u32_t mtu)
{
	icmp6_send_response(p, ip_data_p, 0, mtu, ICMP6_TYPE_PTB);
}

/**
 * Send an icmpv6 'time exceeded' packet.
 *
 * This function must be used only in direct response to a packet that is being
 * received right now. Otherwise, address zones would be lost.
 *
 * @param p the input packet for which the 'time exceeded' should be sent,
 *          p->payload pointing to the IPv6 header
 * @param c ICMPv6 code for the time exceeded type
 */
void
icmp6_time_exceeded(struct rte_mbuf *p, struct ip_data *ip_data_p,
		    enum icmp6_te_code c)
{
	icmp6_send_response(p, ip_data_p, c, 0, ICMP6_TYPE_TE);
}

/**
 * Send an icmpv6 'time exceeded' packet, with explicit source and destination
 * addresses.
 *
 * This function may be used to send a response sometime after receiving the
 * packet for which this response is meant. The provided source and destination
 * addresses are used primarily to retain their zone information.
 *
 * @param p the input packet for which the 'time exceeded' should be sent,
 *          p->payload pointing to the IPv6 header
 * @param c ICMPv6 code for the time exceeded type
 * @param src_addr source address of the original packet, with zone information
 * @param dest_addr destination address of the original packet, with zone
 *                  information
 */
void
icmp6_time_exceeded_with_addrs(struct rte_mbuf *p, enum icmp6_te_code c,
			       const ip6_addr_t *src_addr,
			       const ip6_addr_t *dest_addr)
{
	icmp6_send_response_with_addrs(p, c, 0, ICMP6_TYPE_TE, src_addr,
				       dest_addr);
}

/**
 * Send an icmpv6 'parameter problem' packet.
 *
 * This function must be used only in direct response to a packet that is being
 * received right now. Otherwise, address zones would be lost and the calculated
 * offset would be wrong (calculated against ip6_current_header()).
 *
 * @param p the input packet for which the 'param problem' should be sent,
 *          p->payload pointing to the IP header
 * @param c ICMPv6 code for the param problem type
 * @param pointer the pointer to the byte where the parameter is found
 */
void
icmp6_param_problem(struct rte_mbuf *p, struct ip_data *ip_data_p,
		    enum icmp6_pp_code c, const void *pointer)
{
	u32_t pointer_u32 =
	    (u32_t) ((const u8_t *)pointer -
		     (const u8_t *)ip6_current_header(ip_data_p));
	icmp6_send_response(p, ip_data_p, c, pointer_u32, ICMP6_TYPE_PP);
}

/**
 * Send an ICMPv6 packet in response to an incoming packet.
 * The packet is sent *to* ip_current_src_addr() on ip_current_netif().
 *
 * @param p the input packet for which the response should be sent,
 *          p->payload pointing to the IPv6 header
 * @param code Code of the ICMPv6 header
 * @param data Additional 32-bit parameter in the ICMPv6 header
 * @param type Type of the ICMPv6 header
 */
static void
icmp6_send_response(struct rte_mbuf *p, struct ip_data *ip_data_p,
		    u8_t code, u32_t data, u8_t type)
{
	const struct ip6_addr *reply_src, *reply_dest;
	struct netif *netif = ip_current_netif(ip_data_p);

	DPIP_ASSERT("icmpv6 packet not a direct response", netif != NULL);
	reply_dest = ip6_current_src_addr(ip_data_p);

	/* Select an address to use as source. */
	reply_src = ip_2_ip6(ip6_select_source_address(netif, reply_dest));
	if (reply_src == NULL) {
		ICMP6_STATS_INC(icmp6.rterr);
		return;
	}
	icmp6_send_response_with_addrs_and_netif(p, code, data, type, reply_src,
						 reply_dest, netif);
}

/**
 * Send an ICMPv6 packet in response to an incoming packet.
 *
 * Call this function if the packet is NOT sent as a direct response to an
 * incoming packet, but rather sometime later (e.g. for a fragment reassembly
 * timeout). The caller must provide the zoned source and destination addresses
 * from the original packet with the src_addr and dest_addr parameters. The
 * reason for this approach is that while the addresses themselves are part of
 * the original packet, their zone information is not, thus possibly resulting
 * in a link-local response being sent over the wrong link.
 *
 * @param p the input packet for which the response should be sent,
 *          p->payload pointing to the IPv6 header
 * @param code Code of the ICMPv6 header
 * @param data Additional 32-bit parameter in the ICMPv6 header
 * @param type Type of the ICMPv6 header
 * @param src_addr original source address
 * @param dest_addr original destination address
 */
static void
icmp6_send_response_with_addrs(struct rte_mbuf *p, u8_t code, u32_t data,
			       u8_t type, const ip6_addr_t *src_addr,
			       const ip6_addr_t *dest_addr)
{
	const struct ip6_addr *reply_src, *reply_dest;
	struct netif *netif;

	/* Get the destination address and netif for this ICMP message. */
	DPIP_ASSERT("must provide both source and destination",
		    src_addr != NULL);
	DPIP_ASSERT("must provide both source and destination",
		    dest_addr != NULL);

	/* Special case, as ip6_current_xxx is either NULL, or points
	   to a different packet than the one that expired. */
	IP6_ADDR_ZONECHECK(src_addr);
	IP6_ADDR_ZONECHECK(dest_addr);
	/* Swap source and destination for the reply. */
	reply_dest = src_addr;
	reply_src = dest_addr;
	netif = ip6_route(reply_src, reply_dest);
	if (netif == NULL) {
		ICMP6_STATS_INC(icmp6.rterr);
		return;
	}
	icmp6_send_response_with_addrs_and_netif(p, code, data, type, reply_src,
						 reply_dest, netif);
}

/**
 * Send an ICMPv6 packet (with srd/dst address and netif given).
 *
 * @param p the input packet for which the response should be sent,
 *          p->payload pointing to the IPv6 header
 * @param code Code of the ICMPv6 header
 * @param data Additional 32-bit parameter in the ICMPv6 header
 * @param type Type of the ICMPv6 header
 * @param reply_src source address of the packet to send
 * @param reply_dest destination address of the packet to send
 * @param netif netif to send the packet
 */
static void
icmp6_send_response_with_addrs_and_netif(struct rte_mbuf *p, u8_t code,
					 u32_t data, u8_t type,
					 const ip6_addr_t *reply_src,
					 const ip6_addr_t *reply_dest,
					 struct netif *netif)
{
	struct rte_mbuf *q;
	struct icmp6_hdr *icmp6hdr;
	u16_t datalen =
	    RTE_MIN(rte_pktmbuf_pkt_len(p), (unsigned)DPIP_ICMP6_DATASIZE);

	/* ICMPv6 header + datalen (as much of the offending packet as possible) */
	q = pbuf_alloc(PBUF_IP, sizeof(struct icmp6_hdr) + datalen, PBUF_RAM);
	if (q == NULL) {
		DPIP_DEBUGF(ICMP_DEBUG,
			    ("icmp_time_exceeded: failed to allocate pbuf for ICMPv6 packet.\n"));
		ICMP6_STATS_INC(icmp6.memerr);
		return;
	}
	DPIP_ASSERT("check that first pbuf can hold icmp6 header",
		    (rte_pktmbuf_data_len(p) >= (sizeof(struct icmp6_hdr))));

	icmp6hdr = rte_pktmbuf_mtod(q, struct icmp6_hdr *);
	icmp6hdr->type = type;
	icmp6hdr->code = code;
	icmp6hdr->data = dpip_htonl(data);

	/* copy fields from original packet */
	pbuf_copy_partial_pbuf(q, p, datalen, sizeof(struct icmp6_hdr));

	/* calculate checksum */
	icmp6hdr->chksum = 0;
#if CHECKSUM_GEN_ICMP6
	IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_ICMP6) {
		icmp6hdr->chksum =
		    ip6_chksum_pseudo(q, IP6_NEXTH_ICMP6,
				      rte_pktmbuf_pkt_len(p), reply_src,
				      reply_dest);
	}
#endif /* CHECKSUM_GEN_ICMP6 */

	ICMP6_STATS_INC(icmp6.xmit);
	ip6_output_if(q, reply_src, reply_dest, DPIP_ICMP6_HL, 0,
		      IP6_NEXTH_ICMP6, netif);
	rte_pktmbuf_free(q);
}
