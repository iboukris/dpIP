/**
 * @file
 *
 * IPv6 layer.
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
#ifndef DPIP_HDR_IP6_H
#define DPIP_HDR_IP6_H

#include "dpip/opt.h"

#include "dpip/ip6_addr.h"
#include "dpip/prot/ip6.h"
#include "dpip/def.h"
#include "dpip/pbuf.h"
#include "dpip/netif.h"
#include "dpip/err.h"

#ifdef __cplusplus
extern "C" {
#endif

struct netif *ip6_route(const ip6_addr_t * src, const ip6_addr_t * dest);
const ip_addr_t *ip6_select_source_address(struct netif *netif,
					   const ip6_addr_t * dest);
err_t ip6_input(struct rte_mbuf *p, struct netif *inp);
err_t ip6_output(struct rte_mbuf *p, const ip6_addr_t * src,
		 const ip6_addr_t * dest, u8_t hl, u8_t tc, u8_t nexth);
err_t ip6_output_if(struct rte_mbuf *p, const ip6_addr_t * src,
		    const ip6_addr_t * dest, u8_t hl, u8_t tc, u8_t nexth,
		    struct netif *netif);
err_t ip6_output_if_src(struct rte_mbuf *p, const ip6_addr_t * src,
			const ip6_addr_t * dest, u8_t hl, u8_t tc, u8_t nexth,
			struct netif *netif);
#if DPIP_NETIF_USE_HINTS
err_t ip6_output_hinted(struct rte_mbuf *p, const ip6_addr_t * src,
			const ip6_addr_t * dest, u8_t hl, u8_t tc, u8_t nexth,
			struct netif_hint *netif_hint);
#endif				/* DPIP_NETIF_USE_HINTS */
err_t ip6_options_add_hbh_ra(struct rte_mbuf *p, u8_t nexth, u8_t value);

#define ip6_netif_get_local_ip(netif, dest) (((netif) != NULL) ? \
  ip6_select_source_address(netif, dest) : NULL)

#if IP6_DEBUG
void ip6_debug_print(struct rte_mbuf *p);
#else
#define ip6_debug_print(p)
#endif				/* IP6_DEBUG */

#ifdef __cplusplus
}
#endif
#endif				/* DPIP_HDR_IP6_H */
