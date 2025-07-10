/**
 * @file
 * ICMP API
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
#ifndef DPIP_HDR_ICMP_H
#define DPIP_HDR_ICMP_H

#include "dpip/opt.h"
#include "dpip/pbuf.h"
#include "dpip/ip_addr.h"
#include "dpip/netif.h"
#include "dpip/prot/icmp.h"
#include "dpip/ip.h"
#include "dpip/icmp6.h"
#include "dpip/icmp6.h"

#ifdef __cplusplus
extern "C" {
#endif

/** ICMP destination unreachable codes */
enum icmp_dur_type {
  /** net unreachable */
	ICMP_DUR_NET = 0,
  /** host unreachable */
	ICMP_DUR_HOST = 1,
  /** protocol unreachable */
	ICMP_DUR_PROTO = 2,
  /** port unreachable */
	ICMP_DUR_PORT = 3,
  /** fragmentation needed and DF set */
	ICMP_DUR_FRAG = 4,
  /** source route failed */
	ICMP_DUR_SR = 5
};

/** ICMP time exceeded codes */
enum icmp_te_type {
  /** time to live exceeded in transit */
	ICMP_TE_TTL = 0,
  /** fragment reassembly time exceeded */
	ICMP_TE_FRAG = 1
};

void icmp_input(struct rte_mbuf *p, struct netif *inp,
		struct ip_data *ip_data_p);
void icmp_dest_unreach(struct rte_mbuf *p, enum icmp_dur_type t);
void icmp_time_exceeded(struct rte_mbuf *p, enum icmp_te_type t);

#define icmp_port_unreach(isipv6, pbuf) ((isipv6) ? \
                                         icmp6_dest_unreach(pbuf, ICMP6_DUR_PORT) : \
                                         icmp_dest_unreach(pbuf, ICMP_DUR_PORT))
#ifdef __cplusplus
}
#endif
#endif				/* DPIP_HDR_ICMP_H */
