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
#ifndef DPIP_HDR_ICMP6_H
#define DPIP_HDR_ICMP6_H

#include "dpip/opt.h"
#include "dpip/pbuf.h"
#include "dpip/ip6_addr.h"
#include "dpip/netif.h"
#include "dpip/ip.h"
#include "dpip/prot/icmp6.h"

#ifdef __cplusplus
extern "C" {
#endif

void icmp6_input(struct rte_mbuf *p, struct netif *inp,
		 struct ip_data *ip_data_p);
void icmp6_dest_unreach(struct rte_mbuf *p, struct ip_data *ip_data_p,
			enum icmp6_dur_code c);
void icmp6_packet_too_big(struct rte_mbuf *p, struct ip_data *ip_data_p,
			  u32_t mtu);
void icmp6_time_exceeded(struct rte_mbuf *p, struct ip_data *ip_data_p,
			 enum icmp6_te_code c);
void icmp6_time_exceeded_with_addrs(struct rte_mbuf *p, enum icmp6_te_code c,
				    const ip6_addr_t * src_addr,
				    const ip6_addr_t * dest_addr);
void icmp6_param_problem(struct rte_mbuf *p, struct ip_data *ip_data_p,
			 enum icmp6_pp_code c, const void *pointer);

#ifdef __cplusplus
}
#endif
#endif				/* DPIP_HDR_ICMP6_H */
