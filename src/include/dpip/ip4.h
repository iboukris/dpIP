/**
 * @file
 * IPv4 API
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
#ifndef DPIP_HDR_IP4_H
#define DPIP_HDR_IP4_H

#include "dpip/opt.h"

#include "dpip/def.h"
#include "dpip/pbuf.h"
#include "dpip/ip4_addr.h"
#include "dpip/err.h"
#include "dpip/netif.h"
#include "dpip/prot/ip4.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef DPIP_HOOK_IP4_ROUTE_SRC
#define DPIP_IPV4_SRC_ROUTING   1
#else
#define DPIP_IPV4_SRC_ROUTING   0
#endif

#define ip_init()		/* Compatibility define, no init needed. */
struct netif *ip4_route(const ip4_addr_t * dest);
#if DPIP_IPV4_SRC_ROUTING
struct netif *ip4_route_src(const ip4_addr_t * src, const ip4_addr_t * dest);
#else				/* DPIP_IPV4_SRC_ROUTING */
#define ip4_route_src(src, dest) ip4_route(dest)
#endif				/* DPIP_IPV4_SRC_ROUTING */
err_t ip4_input(struct rte_mbuf *p, struct netif *inp);
err_t ip4_output(struct rte_mbuf *p, const ip4_addr_t * src,
		 const ip4_addr_t * dest, u8_t ttl, u8_t tos, u8_t proto);
err_t ip4_output_if(struct rte_mbuf *p, const ip4_addr_t * src,
		    const ip4_addr_t * dest, u8_t ttl, u8_t tos, u8_t proto,
		    struct netif *netif);
err_t ip4_output_if_src(struct rte_mbuf *p, const ip4_addr_t * src,
			const ip4_addr_t * dest, u8_t ttl, u8_t tos, u8_t proto,
			struct netif *netif);
#if DPIP_NETIF_USE_HINTS
err_t ip4_output_hinted(struct rte_mbuf *p, const ip4_addr_t * src,
			const ip4_addr_t * dest, u8_t ttl, u8_t tos, u8_t proto,
			struct netif_hint *netif_hint);
#endif				/* DPIP_NETIF_USE_HINTS */

#if DPIP_MULTICAST_TX_OPTIONS
void ip4_set_default_multicast_netif(struct netif *default_multicast_netif);
#endif				/* DPIP_MULTICAST_TX_OPTIONS */

#define ip4_netif_get_local_ip(netif) (((netif) != NULL) ? netif_ip_addr4(netif) : NULL)

#if IP_DEBUG
void ip4_debug_print(struct rte_mbuf *p);
#else
#define ip4_debug_print(p)
#endif				/* IP_DEBUG */

#ifdef __cplusplus
}
#endif
#endif				/* DPIP_HDR_IP_H */
