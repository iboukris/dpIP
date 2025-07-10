/**
 * @file
 * ICMP - Internet Control Message Protocol
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

/* Some ICMP messages should be passed to the transport protocols. This
   is not implemented. */

#include "dpip/opt.h"

#include "dpip/icmp.h"
#include "dpip/inet_chksum.h"
#include "dpip/ip.h"
#include "dpip/def.h"
#include "dpip/stats.h"

#include <string.h>

#ifdef DPIP_HOOK_FILENAME
#include DPIP_HOOK_FILENAME
#endif

/** Small optimization: set to 0 if incoming PBUF_POOL pbuf always can be
 * used to modify and send a response packet (and to 1 if this is not the case,
 * e.g. when link header is stripped off when receiving) */
#ifndef DPIP_ICMP_ECHO_CHECK_INPUT_PBUF_LEN
#define DPIP_ICMP_ECHO_CHECK_INPUT_PBUF_LEN 1
#endif /* DPIP_ICMP_ECHO_CHECK_INPUT_PBUF_LEN */

/* The maximum amount of data from the original packet to return in a dest-unreachable */
#define ICMP_DEST_UNREACH_DATASIZE 8

static void icmp_send_response(struct rte_mbuf *p, u8_t type, u8_t code);

/**
 * Processes ICMP input packets, called from ip_input().
 *
 * Currently only processes icmp echo requests and sends
 * out the echo response.
 *
 * @param p the icmp echo request packet, p->payload pointing to the icmp header
 * @param inp the netif on which this packet was received
 */
void
icmp_input(struct rte_mbuf *p, struct netif *inp, struct ip_data *ip_data_p)
{
	u8_t type;
#ifdef DPIP_DEBUG
	u8_t code;
#endif /* DPIP_DEBUG */
	struct icmp_echo_hdr *iecho;
	const struct ip_hdr *iphdr_in;
	u16_t hlen;
	const ip4_addr_t *src;

	ICMP_STATS_INC(icmp.recv);
	MIB2_STATS_INC(mib2.icmpinmsgs);

	iphdr_in = ip4_current_header(ip_data_p);
	hlen = IPH_HL_BYTES(iphdr_in);
	if (hlen < IP_HLEN) {
		DPIP_DEBUGF(ICMP_DEBUG,
			    ("icmp_input: short IP header (%" S16_F
			     " bytes) received\n", hlen));
		goto lenerr;
	}
	if (rte_pktmbuf_data_len(p) < sizeof(u16_t) * 2) {
		DPIP_DEBUGF(ICMP_DEBUG,
			    ("icmp_input: short ICMP (%" U16_F
			     " bytes) received\n", rte_pktmbuf_data_len(p)));
		goto lenerr;
	}

	type = *rte_pktmbuf_mtod(p, u8_t *);
#ifdef DPIP_DEBUG
	code = *(rte_pktmbuf_mtod(p, u8_t *) + 1);
	/* if debug is enabled but debug statement below is somehow disabled: */
	DPIP_UNUSED_ARG(code);
#endif /* DPIP_DEBUG */
	switch (type) {
	case ICMP_ER:
		/* This is OK, echo reply might have been parsed by a raw PCB
		   (as obviously, an echo request has been sent, too). */
		MIB2_STATS_INC(mib2.icmpinechoreps);
		break;
	case ICMP_ECHO:
		MIB2_STATS_INC(mib2.icmpinechos);
		src = ip4_current_dest_addr(ip_data_p);
		/* multicast destination address? */
		if (ip4_addr_ismulticast(ip4_current_dest_addr(ip_data_p))) {
#if DPIP_MULTICAST_PING
			/* For multicast, use address of receiving interface as source address */
			src = netif_ip4_addr(inp);
#else /* DPIP_MULTICAST_PING */
			DPIP_DEBUGF(ICMP_DEBUG,
				    ("icmp_input: Not echoing to multicast pings\n"));
			goto icmperr;
#endif /* DPIP_MULTICAST_PING */
		}
		/* broadcast destination address? */
		if (ip4_addr_isbroadcast(ip4_current_dest_addr(ip_data_p),
					 ip_current_netif(ip_data_p))) {
#if DPIP_BROADCAST_PING
			/* For broadcast, use address of receiving interface as source address */
			src = netif_ip4_addr(inp);
#else /* DPIP_BROADCAST_PING */
			DPIP_DEBUGF(ICMP_DEBUG,
				    ("icmp_input: Not echoing to broadcast pings\n"));
			goto icmperr;
#endif /* DPIP_BROADCAST_PING */
		}
		DPIP_DEBUGF(ICMP_DEBUG, ("icmp_input: ping\n"));
		if (rte_pktmbuf_pkt_len(p) < sizeof(struct icmp_echo_hdr)) {
			DPIP_DEBUGF(ICMP_DEBUG,
				    ("icmp_input: bad ICMP echo received\n"));
			goto lenerr;
		}
#if CHECKSUM_CHECK_ICMP
		IF__NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_CHECK_ICMP) {
			if (inet_chksum_pbuf(p) != 0) {
				DPIP_DEBUGF(ICMP_DEBUG,
					    ("icmp_input: checksum failed for received ICMP echo\n"));
				rte_pktmbuf_free(p);
				ICMP_STATS_INC(icmp.chkerr);
				MIB2_STATS_INC(mib2.icmpinerrors);
				return;
			}
		}
#endif
#if DPIP_ICMP_ECHO_CHECK_INPUT_PBUF_LEN
		if (rte_pktmbuf_prepend
		    (p,
		     hlen + PBUF_LINK_HLEN + PBUF_LINK_ENCAPSULATION_HLEN) ==
		    NULL) {
			/* p is not big enough to contain link headers
			 * allocate a new one and copy p into it
			 */
			struct rte_mbuf *r;
			u16_t alloc_len =
			    (u16_t) (rte_pktmbuf_pkt_len(p) + hlen);
			if (alloc_len < rte_pktmbuf_pkt_len(p)) {
				DPIP_DEBUGF(ICMP_DEBUG,
					    ("icmp_input: allocating new pbuf failed (tot_len overflow)\n"));
				goto icmperr;
			}
			/* allocate new packet buffer with space for link headers */
			r = pbuf_alloc(PBUF_LINK, alloc_len, PBUF_RAM);
			if (r == NULL) {
				DPIP_DEBUGF(ICMP_DEBUG,
					    ("icmp_input: allocating new pbuf failed\n"));
				goto icmperr;
			}
			if (rte_pktmbuf_data_len(r) <
			    hlen + sizeof(struct icmp_echo_hdr)) {
				DPIP_DEBUGF(ICMP_DEBUG | DPIP_DBG_LEVEL_SERIOUS,
					    ("first pbuf cannot hold the ICMP header\n"));
				rte_pktmbuf_free(r);
				goto icmperr;
			}
			/* copy the ip header */
			MEMCPY(rte_pktmbuf_mtod(r, char *), iphdr_in, hlen);
			/* switch r->payload back to icmp header (cannot fail) */
			if (rte_pktmbuf_adj(r, hlen) == NULL) {
				DPIP_ASSERT
				    ("icmp_input: moving r->payload to icmp header failed",
				     0);
				rte_pktmbuf_free(r);
				goto icmperr;
			}
			/* copy the rest of the packet without ip header */
			if (pbuf_copy(r, p) != ERR_OK) {
				DPIP_DEBUGF(ICMP_DEBUG | DPIP_DBG_LEVEL_SERIOUS,
					    ("icmp_input: copying to new pbuf failed\n"));
				rte_pktmbuf_free(r);
				goto icmperr;
			}
			/* free the original p */
			rte_pktmbuf_free(p);
			/* we now have an identical copy of p that has room for link headers */
			p = r;
		} else {
			/* restore p->payload to point to icmp header (cannot fail) */
			if (rte_pktmbuf_adj
			    (p,
			     hlen + PBUF_LINK_HLEN +
			     PBUF_LINK_ENCAPSULATION_HLEN) == NULL) {
				DPIP_ASSERT
				    ("icmp_input: restoring original p->payload failed",
				     0);
				goto icmperr;
			}
		}
#endif /* DPIP_ICMP_ECHO_CHECK_INPUT_PBUF_LEN */
		/* At this point, all checks are OK. */
		/* We generate an answer by switching the dest and src ip addresses,
		 * setting the icmp type to ECHO_RESPONSE and updating the checksum. */
		iecho = rte_pktmbuf_mtod(p, struct icmp_echo_hdr *);
		if (rte_pktmbuf_prepend(p, hlen) == NULL) {
			DPIP_DEBUGF(ICMP_DEBUG | DPIP_DBG_LEVEL_SERIOUS,
				    ("Can't move over header in packet\n"));
		} else {
			err_t ret;
			struct ip_hdr *iphdr =
			    rte_pktmbuf_mtod(p, struct ip_hdr *);
			ip4_addr_copy(iphdr->src, *src);
			ip4_addr_copy(iphdr->dest,
				      *ip4_current_src_addr(ip_data_p));
			ICMPH_TYPE_SET(iecho, ICMP_ER);
			p->port = NETIF_NO_INDEX;	/* we're reusing this pbuf, so reset its if_idx */
#if CHECKSUM_GEN_ICMP
			IF__NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_GEN_ICMP) {
				/* adjust the checksum */
				if (iecho->chksum >
				    PP_HTONS(0xffffU - (ICMP_ECHO << 8))) {
					iecho->chksum =
					    (u16_t) (iecho->chksum +
						     PP_HTONS((u16_t)
							      (ICMP_ECHO << 8))
						     + 1);
				} else {
					iecho->chksum =
					    (u16_t) (iecho->chksum +
						     PP_HTONS(ICMP_ECHO << 8));
				}
			}
#if DPIP_CHECKSUM_CTRL_PER_NETIF
			else {
				iecho->chksum = 0;
			}
#endif /* DPIP_CHECKSUM_CTRL_PER_NETIF */
#else /* CHECKSUM_GEN_ICMP */
			iecho->chksum = 0;
#endif /* CHECKSUM_GEN_ICMP */

			/* Set the correct TTL and recalculate the header checksum. */
			IPH_TTL_SET(iphdr, ICMP_TTL);
			IPH_CHKSUM_SET(iphdr, 0);
#if CHECKSUM_GEN_IP
			IF__NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_GEN_IP) {
				IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, hlen));
			}
#endif /* CHECKSUM_GEN_IP */

			ICMP_STATS_INC(icmp.xmit);
			/* increase number of messages attempted to send */
			MIB2_STATS_INC(mib2.icmpoutmsgs);
			/* increase number of echo replies attempted to send */
			MIB2_STATS_INC(mib2.icmpoutechoreps);

			/* send an ICMP packet */
			ret = ip4_output_if(p, src, DPIP_IP_HDRINCL,
					    ICMP_TTL, 0, IP_PROTO_ICMP, inp);
			if (ret != ERR_OK) {
				DPIP_DEBUGF(ICMP_DEBUG,
					    ("icmp_input: ip_output_if returned an error: %s\n",
					     dpip_strerr(ret)));
			}
		}
		break;
	default:
		if (type == ICMP_DUR) {
			MIB2_STATS_INC(mib2.icmpindestunreachs);
		} else if (type == ICMP_TE) {
			MIB2_STATS_INC(mib2.icmpintimeexcds);
		} else if (type == ICMP_PP) {
			MIB2_STATS_INC(mib2.icmpinparmprobs);
		} else if (type == ICMP_SQ) {
			MIB2_STATS_INC(mib2.icmpinsrcquenchs);
		} else if (type == ICMP_RD) {
			MIB2_STATS_INC(mib2.icmpinredirects);
		} else if (type == ICMP_TS) {
			MIB2_STATS_INC(mib2.icmpintimestamps);
		} else if (type == ICMP_TSR) {
			MIB2_STATS_INC(mib2.icmpintimestampreps);
		} else if (type == ICMP_AM) {
			MIB2_STATS_INC(mib2.icmpinaddrmasks);
		} else if (type == ICMP_AMR) {
			MIB2_STATS_INC(mib2.icmpinaddrmaskreps);
		}
		DPIP_DEBUGF(ICMP_DEBUG,
			    ("icmp_input: ICMP type %" S16_F " code %" S16_F
			     " not supported.\n", (s16_t) type, (s16_t) code));
		ICMP_STATS_INC(icmp.proterr);
		ICMP_STATS_INC(icmp.drop);
	}
	rte_pktmbuf_free(p);
	return;
 lenerr:
	rte_pktmbuf_free(p);
	ICMP_STATS_INC(icmp.lenerr);
	MIB2_STATS_INC(mib2.icmpinerrors);
	return;
#if DPIP_ICMP_ECHO_CHECK_INPUT_PBUF_LEN || !DPIP_MULTICAST_PING || !DPIP_BROADCAST_PING
 icmperr:
	rte_pktmbuf_free(p);
	ICMP_STATS_INC(icmp.err);
	MIB2_STATS_INC(mib2.icmpinerrors);
	return;
#endif /* DPIP_ICMP_ECHO_CHECK_INPUT_PBUF_LEN || !DPIP_MULTICAST_PING || !DPIP_BROADCAST_PING */
}

/**
 * Send an icmp 'destination unreachable' packet, called from ip_input() if
 * the transport layer protocol is unknown and from udp_input() if the local
 * port is not bound.
 *
 * @param p the input packet for which the 'unreachable' should be sent,
 *          p->payload pointing to the IP header
 * @param t type of the 'unreachable' packet
 */
void icmp_dest_unreach(struct rte_mbuf *p, enum icmp_dur_type t)
{
	MIB2_STATS_INC(mib2.icmpoutdestunreachs);
	icmp_send_response(p, ICMP_DUR, t);
}

#if IP_FORWARD || IP_REASSEMBLY
/**
 * Send a 'time exceeded' packet, called from ip_forward() if TTL is 0.
 *
 * @param p the input packet for which the 'time exceeded' should be sent,
 *          p->payload pointing to the IP header
 * @param t type of the 'time exceeded' packet
 */
void icmp_time_exceeded(struct rte_mbuf *p, enum icmp_te_type t)
{
	MIB2_STATS_INC(mib2.icmpouttimeexcds);
	icmp_send_response(p, ICMP_TE, t);
}

#endif /* IP_FORWARD || IP_REASSEMBLY */

/**
 * Send an icmp packet in response to an incoming packet.
 *
 * @param p the input packet for which the 'unreachable' should be sent,
 *          p->payload pointing to the IP header
 * @param type Type of the ICMP header
 * @param code Code of the ICMP header
 */
static void icmp_send_response(struct rte_mbuf *p, u8_t type, u8_t code)
{
	struct rte_mbuf *q;
	struct ip_hdr *iphdr;
	struct icmp_hdr *icmphdr;
	ip4_addr_t iphdr_src;
	struct netif *netif;
	u16_t response_pkt_len;

	/* increase number of messages attempted to send */
	MIB2_STATS_INC(mib2.icmpoutmsgs);

	/* Keep IP header + up to 8 bytes */
	response_pkt_len = IP_HLEN + ICMP_DEST_UNREACH_DATASIZE;
	if (rte_pktmbuf_pkt_len(p) < response_pkt_len) {
		response_pkt_len = rte_pktmbuf_pkt_len(p);
	}

	/* ICMP header + part of original packet */
	q = pbuf_alloc(PBUF_IP, sizeof(struct icmp_hdr) + response_pkt_len,
		       PBUF_RAM);
	if (q == NULL) {
		DPIP_DEBUGF(ICMP_DEBUG,
			    ("icmp_send_response: failed to allocate pbuf for ICMP packet.\n"));
		MIB2_STATS_INC(mib2.icmpouterrors);
		return;
	}
	DPIP_ASSERT("check that first pbuf can hold icmp message",
		    (rte_pktmbuf_data_len(q) >=
		     (sizeof(struct icmp_hdr) + response_pkt_len)));

	iphdr = rte_pktmbuf_mtod(p, struct ip_hdr *);
	DPIP_DEBUGF(ICMP_DEBUG,
		    ("icmp_send_response: Sending ICMP type %02X for packet from ",
		     type));
	ip4_addr_debug_print_val(ICMP_DEBUG, iphdr->src);
	DPIP_DEBUGF(ICMP_DEBUG, (" to "));
	ip4_addr_debug_print_val(ICMP_DEBUG, iphdr->dest);
	DPIP_DEBUGF(ICMP_DEBUG, ("\n"));

	icmphdr = rte_pktmbuf_mtod(q, struct icmp_hdr *);
	icmphdr->type = type;
	icmphdr->code = code;
	icmphdr->data = 0;

	/* copy fields from original packet */
	pbuf_copy_partial_pbuf(q, p, response_pkt_len, sizeof(struct icmp_hdr));

	ip4_addr_copy(iphdr_src, iphdr->src);
#ifdef DPIP_HOOK_IP4_ROUTE_SRC
	{
		ip4_addr_t iphdr_dst;
		ip4_addr_copy(iphdr_dst, iphdr->dest);
		netif = ip4_route_src(&iphdr_dst, &iphdr_src);
	}
#else
	netif = ip4_route(&iphdr_src);
#endif
	if (netif != NULL) {
		/* calculate checksum */
		icmphdr->chksum = 0;
#if CHECKSUM_GEN_ICMP
		IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_ICMP) {
			icmphdr->chksum =
			    inet_chksum(icmphdr, rte_pktmbuf_data_len(p));
		}
#endif
		ICMP_STATS_INC(icmp.xmit);
		ip4_output_if(q, NULL, &iphdr_src, ICMP_TTL, 0, IP_PROTO_ICMP,
			      netif);
	}
	rte_pktmbuf_free(q);
}
