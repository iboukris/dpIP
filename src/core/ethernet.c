/**
 * @file
 * Ethernet common functions
 *
 * @defgroup ethernet Ethernet
 * @ingroup callbackstyle_api
 */

/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * Copyright (c) 2003-2004 Leon Woestenberg <leon.woestenberg@axon.tv>
 * Copyright (c) 2003-2004 Axon Digital Design B.V., The Netherlands.
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
 */

#include "dpip/opt.h"

#if DPIP_ARP || DPIP_ETHERNET

#include "dpip/ethernet.h"
#include "dpip/def.h"
#include "dpip/stats.h"
#include "dpip/etharp.h"
#include "dpip/ip.h"
#include "dpip/snmp.h"

#include <string.h>

#ifdef DPIP_HOOK_FILENAME
#include DPIP_HOOK_FILENAME
#endif

const struct eth_addr ethbroadcast = { {0xff, 0xff, 0xff, 0xff, 0xff, 0xff} };
const struct eth_addr ethzero = { {0, 0, 0, 0, 0, 0} };

/**
 * @ingroup dpip_nosys
 * Process received ethernet frames. Using this function instead of directly
 * calling ip_input and passing ARP frames through etharp in ethernetif_input,
 * the ARP cache is protected from concurrent access.<br>
 * Don't call directly, pass to netif_add() and call netif->input().
 *
 * @param p the received packet, p->payload pointing to the ethernet header
 * @param netif the network interface on which the packet was received
 *
 * @see DPIP_HOOK_UNKNOWN_ETH_PROTOCOL
 * @see ETHARP_SUPPORT_VLAN
 * @see DPIP_HOOK_VLAN_CHECK
 */
err_t ethernet_input(struct rte_mbuf *p, struct netif *netif)
{
	struct eth_hdr *ethhdr;
	u16_t type;
	u16_t next_hdr_offset = SIZEOF_ETH_HDR;

	if (rte_pktmbuf_data_len(p) <= next_hdr_offset) {
		/* a packet with only an ethernet header (or less) is not valid for us */
		ETHARP_STATS_INC(etharp.proterr);
		ETHARP_STATS_INC(etharp.drop);
		MIB2_STATS_NETIF_INC(netif, ifinerrors);
		goto free_and_return;
	}

	/* points to packet payload, which starts with an Ethernet header */
	ethhdr = rte_pktmbuf_mtod(p, struct eth_hdr *);
	DPIP_DEBUGF(ETHARP_DEBUG | DPIP_DBG_TRACE,
		    ("ethernet_input: dest:%" X8_F ":%" X8_F ":%" X8_F ":%" X8_F
		     ":%" X8_F ":%" X8_F ", src:%" X8_F ":%" X8_F ":%" X8_F ":%"
		     X8_F ":%" X8_F ":%" X8_F ", type:%" X16_F "\n",
		     (unsigned char)ethhdr->dest.addr[0],
		     (unsigned char)ethhdr->dest.addr[1],
		     (unsigned char)ethhdr->dest.addr[2],
		     (unsigned char)ethhdr->dest.addr[3],
		     (unsigned char)ethhdr->dest.addr[4],
		     (unsigned char)ethhdr->dest.addr[5],
		     (unsigned char)ethhdr->src.addr[0],
		     (unsigned char)ethhdr->src.addr[1],
		     (unsigned char)ethhdr->src.addr[2],
		     (unsigned char)ethhdr->src.addr[3],
		     (unsigned char)ethhdr->src.addr[4],
		     (unsigned char)ethhdr->src.addr[5],
		     dpip_htons(ethhdr->type)));

	type = ethhdr->type;
#if ETHARP_SUPPORT_VLAN
	if (type == PP_HTONS(ETHTYPE_VLAN)) {
		struct eth_vlan_hdr *vlan =
		    (struct eth_vlan_hdr *)(((char *)ethhdr) + SIZEOF_ETH_HDR);
		next_hdr_offset = SIZEOF_ETH_HDR + SIZEOF_VLAN_HDR;
		if (rte_pktmbuf_data_len(p) <= next_hdr_offset) {
			/* a packet with only an ethernet/vlan header (or less) is not valid for us */
			ETHARP_STATS_INC(etharp.proterr);
			ETHARP_STATS_INC(etharp.drop);
			MIB2_STATS_NETIF_INC(netif, ifinerrors);
			goto free_and_return;
		}
		type = vlan->tpid;
	}
#endif /* ETHARP_SUPPORT_VLAN */

	if (p->port == NETIF_NO_INDEX) {
		p->port = netif_get_index(netif);
	}

	if (0 && p->port != netif_get_index(netif)) {
		DPIP_DEBUGF(ETHARP_DEBUG | DPIP_DBG_TRACE |
			    DPIP_DBG_LEVEL_SERIOUS,
			    ("ethernet_input: wrong p->port vs netif index.\n"));
		goto free_and_return;
	}

#if 0
	if (ethhdr->dest.addr[0] & 1) {
		/* this might be a multicast or broadcast packet */
		if (ethhdr->dest.addr[0] == LL_IP4_MULTICAST_ADDR_0) {
			if ((ethhdr->dest.addr[1] == LL_IP4_MULTICAST_ADDR_1) &&
			    (ethhdr->dest.addr[2] == LL_IP4_MULTICAST_ADDR_2)) {
				/* mark the pbuf as link-layer multicast */
				p->flags |= PBUF_FLAG_LLMCAST;
			}
		} else if ((ethhdr->dest.addr[0] == LL_IP6_MULTICAST_ADDR_0) &&
			   (ethhdr->dest.addr[1] == LL_IP6_MULTICAST_ADDR_1)) {
			/* mark the pbuf as link-layer multicast */
			p->flags |= PBUF_FLAG_LLMCAST;
		} else if (eth_addr_cmp(&ethhdr->dest, &ethbroadcast)) {
			/* mark the pbuf as link-layer broadcast */
			p->flags |= PBUF_FLAG_LLBCAST;
		}
	}
#endif

	switch (type) {
#if DPIP_ARP
		/* IP packet? */
	case PP_HTONS(ETHTYPE_IP):
		if (!(netif->flags & NETIF_FLAG_ETHARP)) {
			goto free_and_return;
		}
		/* skip Ethernet header (min. size checked above) */
		if (rte_pktmbuf_adj(p, next_hdr_offset) == NULL) {
			DPIP_DEBUGF(ETHARP_DEBUG | DPIP_DBG_TRACE |
				    DPIP_DBG_LEVEL_WARNING,
				    ("ethernet_input: IPv4 packet dropped, too short (%"
				     U16_F "/%" U16_F ")\n",
				     rte_pktmbuf_pkt_len(p), next_hdr_offset));
			DPIP_DEBUGF(ETHARP_DEBUG | DPIP_DBG_TRACE,
				    ("Can't move over header in packet\n"));
			goto free_and_return;
		} else {
			/* pass to IP layer */
			ip4_input(p, netif);
		}
		break;

	case PP_HTONS(ETHTYPE_ARP):
		if (!(netif->flags & NETIF_FLAG_ETHARP)) {
			goto free_and_return;
		}
		/* skip Ethernet header (min. size checked above) */
		if (rte_pktmbuf_adj(p, next_hdr_offset) == NULL) {
			DPIP_DEBUGF(ETHARP_DEBUG | DPIP_DBG_TRACE |
				    DPIP_DBG_LEVEL_WARNING,
				    ("ethernet_input: ARP response packet dropped, too short (%"
				     U16_F "/%" U16_F ")\n",
				     rte_pktmbuf_pkt_len(p), next_hdr_offset));
			DPIP_DEBUGF(ETHARP_DEBUG | DPIP_DBG_TRACE,
				    ("Can't move over header in packet\n"));
			ETHARP_STATS_INC(etharp.lenerr);
			ETHARP_STATS_INC(etharp.drop);
			goto free_and_return;
		} else {
			/* pass p to ARP module */
			etharp_input(p, netif);
		}
		break;
#endif /* DPIP_ARP */

	case PP_HTONS(ETHTYPE_IPV6):	/* IPv6 */
		/* skip Ethernet header */
		if (rte_pktmbuf_adj(p, next_hdr_offset) == NULL) {
			DPIP_DEBUGF(ETHARP_DEBUG | DPIP_DBG_TRACE |
				    DPIP_DBG_LEVEL_WARNING,
				    ("ethernet_input: IPv6 packet dropped, too short (%"
				     U16_F "/%" U16_F ")\n",
				     rte_pktmbuf_pkt_len(p), next_hdr_offset));
			goto free_and_return;
		} else {
			/* pass to IPv6 layer */
			ip6_input(p, netif);
		}
		break;

	default:
		ETHARP_STATS_INC(etharp.proterr);
		ETHARP_STATS_INC(etharp.drop);
		MIB2_STATS_NETIF_INC(netif, ifinunknownprotos);
		goto free_and_return;
	}

	/* This means the pbuf is freed or consumed,
	   so the caller doesn't have to free it again */
	return ERR_OK;

 free_and_return:
	rte_pktmbuf_free(p);
	return ERR_OK;
}

/**
 * @ingroup ethernet
 * Send an ethernet packet on the network using netif->linkoutput().
 * The ethernet header is filled in before sending.
 *
 * @param netif the dpIP network interface on which to send the packet
 * @param p the packet to send. pbuf layer must be @ref PBUF_LINK.
 * @param src the source MAC address to be copied into the ethernet header
 * @param dst the destination MAC address to be copied into the ethernet header
 * @param eth_type ethernet type (@ref dpip_ieee_eth_type)
 * @return ERR_OK if the packet was sent, any other err_t on failure
 */
err_t
ethernet_output(struct netif *netif, struct rte_mbuf *p,
		const struct eth_addr *src, const struct eth_addr *dst,
		u16_t eth_type)
{
	struct eth_hdr *ethhdr;
	u16_t eth_type_be = dpip_htons(eth_type);

#if DPIP_VLAN_PCP
	s32_t vlan_prio_vid;
	vlan_prio_vid = -1;
	if (netif->hints && (netif->hints->tci >= 0)) {
		vlan_prio_vid = (u16_t) netif->hints->tci;
	}
	if (vlan_prio_vid >= 0) {
		struct eth_vlan_hdr *vlanhdr;

		DPIP_ASSERT("prio_vid must be <= 0xFFFF",
			    vlan_prio_vid <= 0xFFFF);

		if (rte_pktmbuf_prepend(p, SIZEOF_ETH_HDR + SIZEOF_VLAN_HDR) ==
		    NULL) {
			goto pbuf_header_failed;
		}
		vlanhdr =
		    rte_pktmbuf_mtod_offset(p, struct eth_vlan_hdr *,
					    SIZEOF_ETH_HDR);
		vlanhdr->tpid = eth_type_be;
		vlanhdr->prio_vid = dpip_htons((u16_t) vlan_prio_vid);

		eth_type_be = PP_HTONS(ETHTYPE_VLAN);
	} else
#endif /* DPIP_VLAN_PCP */
	{
		if (rte_pktmbuf_prepend(p, SIZEOF_ETH_HDR) == NULL) {
			goto pbuf_header_failed;
		}
	}

	ethhdr = rte_pktmbuf_mtod(p, struct eth_hdr *);
	ethhdr->type = eth_type_be;
	SMEMCPY(&ethhdr->dest, dst, ETH_HWADDR_LEN);
	SMEMCPY(&ethhdr->src, src, ETH_HWADDR_LEN);

	DPIP_ASSERT("netif->hwaddr_len must be 6 for ethernet_output!",
		    (netif->hwaddr_len == ETH_HWADDR_LEN));
	DPIP_DEBUGF(ETHARP_DEBUG | DPIP_DBG_TRACE,
		    ("ethernet_output: sending packet %p\n", (void *)p));

	/* send the packet */
	return netif->linkoutput(netif, p);

 pbuf_header_failed:
	DPIP_DEBUGF(ETHARP_DEBUG | DPIP_DBG_TRACE | DPIP_DBG_LEVEL_SERIOUS,
		    ("ethernet_output: could not allocate room for header.\n"));
	LINK_STATS_INC(link.lenerr);
	return ERR_BUF;
}

#endif /* DPIP_ARP || DPIP_ETHERNET */
