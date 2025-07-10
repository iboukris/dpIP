/**
 * @file
 * IP checksum calculation functions
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
#ifndef DPIP_HDR_INET_CHKSUM_H
#define DPIP_HDR_INET_CHKSUM_H

#include "dpip/opt.h"

#include "dpip/pbuf.h"
#include "dpip/ip_addr.h"

/** Swap the bytes in an u16_t: much like dpip_htons() for little-endian */
#ifndef SWAP_BYTES_IN_WORD
#define SWAP_BYTES_IN_WORD(w) (((w) & 0xff) << 8) | (((w) & 0xff00) >> 8)
#endif /* SWAP_BYTES_IN_WORD */

/** Split an u32_t in two u16_ts and add them up */
#ifndef FOLD_U32T
#define FOLD_U32T(u)          ((u32_t)(((u) >> 16) + ((u) & 0x0000ffffUL)))
#endif

#ifdef __cplusplus
extern "C" {
#endif

u16_t inet_chksum(const void *dataptr, u16_t len);
u16_t inet_chksum_pbuf(struct rte_mbuf *p);

u16_t inet_chksum_pseudo(struct rte_mbuf *p, u8_t proto, u16_t proto_len,
			 const ip4_addr_t * src, const ip4_addr_t * dest);
u16_t inet_chksum_pseudo_partial(struct rte_mbuf *p, u8_t proto,
				 u16_t proto_len, u16_t chksum_len,
				 const ip4_addr_t * src,
				 const ip4_addr_t * dest);

u16_t ip6_chksum_pseudo(struct rte_mbuf *p, u8_t proto, u16_t proto_len,
			const ip6_addr_t * src, const ip6_addr_t * dest);
u16_t ip6_chksum_pseudo_partial(struct rte_mbuf *p, u8_t proto, u16_t proto_len,
				u16_t chksum_len, const ip6_addr_t * src,
				const ip6_addr_t * dest);

u16_t ip_chksum_pseudo(struct rte_mbuf *p, u8_t proto, u16_t proto_len,
		       const ip_addr_t * src, const ip_addr_t * dest);
u16_t ip_chksum_pseudo_partial(struct rte_mbuf *p, u8_t proto, u16_t proto_len,
			       u16_t chksum_len, const ip_addr_t * src,
			       const ip_addr_t * dest);

#ifdef __cplusplus
}
#endif
#endif				/* DPIP_HDR_INET_H */
