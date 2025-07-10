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

#include <rte_ip.h>

#include "dpip/opt.h"

#include "dpip/inet_chksum.h"
#include "dpip/def.h"
#include "dpip/ip_addr.h"

#include <string.h>

/** Parts of the pseudo checksum which are common to IPv4 and IPv6 */
static u16_t
inet_cksum_pseudo_base(struct rte_mbuf *p, u8_t proto, u16_t proto_len,
		       u32_t acc)
{
	struct rte_mbuf *q;
	int swapped = 0;

	/* iterate through all mbuf in chain */
	for (q = p; q != NULL; q = q->next) {
		DPIP_DEBUGF(INET_DEBUG,
			    ("inet_chksum_pseudo(): checksumming mbuf %p (has next %p) \n",
			     (void *)q, (void *)q->next));
		acc +=
		    rte_raw_cksum(rte_pktmbuf_mtod(q, const void *),
				  rte_pktmbuf_data_len(q));
		/*DPIP_DEBUGF(INET_DEBUG, ("inet_chksum_pseudo(): unwrapped dpip_chksum()=%"X32_F" \n", acc)); */
		/* just executing this next line is probably faster that the if statement needed
		   to check whether we really need to execute it, and does no harm */
		acc = FOLD_U32T(acc);
		if (rte_pktmbuf_data_len(q) % 2 != 0) {
			swapped = !swapped;
			acc = SWAP_BYTES_IN_WORD(acc);
		}
		/*DPIP_DEBUGF(INET_DEBUG, ("inet_chksum_pseudo(): wrapped dpip_chksum()=%"X32_F" \n", acc)); */
	}

	if (swapped) {
		acc = SWAP_BYTES_IN_WORD(acc);
	}

	acc += (u32_t) dpip_htons((u16_t) proto);
	acc += (u32_t) dpip_htons(proto_len);

	/* Fold 32-bit sum to 16 bits
	   calling this twice is probably faster than if statements... */
	acc = FOLD_U32T(acc);
	acc = FOLD_U32T(acc);
	DPIP_DEBUGF(INET_DEBUG,
		    ("inet_chksum_pseudo(): mbuf chain dpip_chksum()=%" X32_F
		     "\n", acc));
	return (u16_t) ~ (acc & 0xffffUL);
}

/* inet_chksum_pseudo:
 *
 * Calculates the IPv4 pseudo Internet checksum used by TCP and UDP for a mbuf chain.
 * IP addresses are expected to be in network byte order.
 *
 * @param p chain of mbufs over that a checksum should be calculated (ip data part)
 * @param src source ip address (used for checksum of pseudo header)
 * @param dst destination ip address (used for checksum of pseudo header)
 * @param proto ip protocol (used for checksum of pseudo header)
 * @param proto_len length of the ip data part (used for checksum of pseudo header)
 * @return checksum (as u16_t) to be saved directly in the protocol header
 */
u16_t
inet_chksum_pseudo(struct rte_mbuf *p, u8_t proto, u16_t proto_len,
		   const ip4_addr_t *src, const ip4_addr_t *dest)
{
	u32_t acc;
	u32_t addr;

	addr = ip4_addr_get_u32(src);
	acc = (addr & 0xffffUL);
	acc = (u32_t) (acc + ((addr >> 16) & 0xffffUL));
	addr = ip4_addr_get_u32(dest);
	acc = (u32_t) (acc + (addr & 0xffffUL));
	acc = (u32_t) (acc + ((addr >> 16) & 0xffffUL));
	/* fold down to 16 bits */
	acc = FOLD_U32T(acc);
	acc = FOLD_U32T(acc);

	return inet_cksum_pseudo_base(p, proto, proto_len, acc);
}

/**
 * Calculates the checksum with IPv6 pseudo header used by TCP and UDP for a mbuf chain.
 * IPv6 addresses are expected to be in network byte order.
 *
 * @param p chain of mbufs over that a checksum should be calculated (ip data part)
 * @param proto ipv6 protocol/next header (used for checksum of pseudo header)
 * @param proto_len length of the ipv6 payload (used for checksum of pseudo header)
 * @param src source ipv6 address (used for checksum of pseudo header)
 * @param dest destination ipv6 address (used for checksum of pseudo header)
 * @return checksum (as u16_t) to be saved directly in the protocol header
 */
u16_t
ip6_chksum_pseudo(struct rte_mbuf *p, u8_t proto, u16_t proto_len,
		  const ip6_addr_t *src, const ip6_addr_t *dest)
{
	u32_t acc = 0;
	u32_t addr;
	u8_t addr_part;

	for (addr_part = 0; addr_part < 4; addr_part++) {
		addr = src->addr[addr_part];
		acc = (u32_t) (acc + (addr & 0xffffUL));
		acc = (u32_t) (acc + ((addr >> 16) & 0xffffUL));
		addr = dest->addr[addr_part];
		acc = (u32_t) (acc + (addr & 0xffffUL));
		acc = (u32_t) (acc + ((addr >> 16) & 0xffffUL));
	}
	/* fold down to 16 bits */
	acc = FOLD_U32T(acc);
	acc = FOLD_U32T(acc);

	return inet_cksum_pseudo_base(p, proto, proto_len, acc);
}

/* ip_chksum_pseudo:
 *
 * Calculates the IPv4 or IPv6 pseudo Internet checksum used by TCP and UDP for a mbuf chain.
 * IP addresses are expected to be in network byte order.
 *
 * @param p chain of mbufs over that a checksum should be calculated (ip data part)
 * @param src source ip address (used for checksum of pseudo header)
 * @param dst destination ip address (used for checksum of pseudo header)
 * @param proto ip protocol (used for checksum of pseudo header)
 * @param proto_len length of the ip data part (used for checksum of pseudo header)
 * @return checksum (as u16_t) to be saved directly in the protocol header
 */
u16_t
ip_chksum_pseudo(struct rte_mbuf *p, u8_t proto, u16_t proto_len,
		 const ip_addr_t *src, const ip_addr_t *dest)
{
	if (IP_IS_V6(dest)) {
		return ip6_chksum_pseudo(p, proto, proto_len, ip_2_ip6(src),
					 ip_2_ip6(dest));
	} else {
		return inet_chksum_pseudo(p, proto, proto_len, ip_2_ip4(src),
					  ip_2_ip4(dest));
	}
}

/** Parts of the pseudo checksum which are common to IPv4 and IPv6 */
static u16_t
inet_cksum_pseudo_partial_base(struct rte_mbuf *p, u8_t proto, u16_t proto_len,
			       u16_t chksum_len, u32_t acc)
{
	struct rte_mbuf *q;
	int swapped = 0;
	u16_t chklen;

	/* iterate through all mbuf in chain */
	for (q = p; (q != NULL) && (chksum_len > 0); q = q->next) {
		DPIP_DEBUGF(INET_DEBUG,
			    ("inet_chksum_pseudo(): checksumming mbuf %p (has next %p) \n",
			     (void *)q, (void *)q->next));
		chklen = rte_pktmbuf_data_len(q);
		if (chklen > chksum_len) {
			chklen = chksum_len;
		}
		acc += rte_raw_cksum(rte_pktmbuf_mtod(q, const void *), chklen);
		chksum_len = (u16_t) (chksum_len - chklen);
		// XXX
		DPIP_ASSERT("delete me", chksum_len < 0x7fff);
		/*DPIP_DEBUGF(INET_DEBUG, ("inet_chksum_pseudo(): unwrapped dpip_chksum()=%"X32_F" \n", acc)); */
		/* fold the upper bit down */
		acc = FOLD_U32T(acc);
		if (rte_pktmbuf_data_len(q) % 2 != 0) {
			swapped = !swapped;
			acc = SWAP_BYTES_IN_WORD(acc);
		}
		/*DPIP_DEBUGF(INET_DEBUG, ("inet_chksum_pseudo(): wrapped dpip_chksum()=%"X32_F" \n", acc)); */
	}

	if (swapped) {
		acc = SWAP_BYTES_IN_WORD(acc);
	}

	acc += (u32_t) dpip_htons((u16_t) proto);
	acc += (u32_t) dpip_htons(proto_len);

	/* Fold 32-bit sum to 16 bits
	   calling this twice is probably faster than if statements... */
	acc = FOLD_U32T(acc);
	acc = FOLD_U32T(acc);
	DPIP_DEBUGF(INET_DEBUG,
		    ("inet_chksum_pseudo(): mbuf chain dpip_chksum()=%" X32_F
		     "\n", acc));
	return (u16_t) ~ (acc & 0xffffUL);
}

/* inet_chksum_pseudo_partial:
 *
 * Calculates the IPv4 pseudo Internet checksum used by TCP and UDP for a mbuf chain.
 * IP addresses are expected to be in network byte order.
 *
 * @param p chain of mbufs over that a checksum should be calculated (ip data part)
 * @param src source ip address (used for checksum of pseudo header)
 * @param dst destination ip address (used for checksum of pseudo header)
 * @param proto ip protocol (used for checksum of pseudo header)
 * @param proto_len length of the ip data part (used for checksum of pseudo header)
 * @return checksum (as u16_t) to be saved directly in the protocol header
 */
u16_t
inet_chksum_pseudo_partial(struct rte_mbuf *p, u8_t proto, u16_t proto_len,
			   u16_t chksum_len, const ip4_addr_t *src,
			   const ip4_addr_t *dest)
{
	u32_t acc;
	u32_t addr;

	addr = ip4_addr_get_u32(src);
	acc = (addr & 0xffffUL);
	acc = (u32_t) (acc + ((addr >> 16) & 0xffffUL));
	addr = ip4_addr_get_u32(dest);
	acc = (u32_t) (acc + (addr & 0xffffUL));
	acc = (u32_t) (acc + ((addr >> 16) & 0xffffUL));
	/* fold down to 16 bits */
	acc = FOLD_U32T(acc);
	acc = FOLD_U32T(acc);

	return inet_cksum_pseudo_partial_base(p, proto, proto_len, chksum_len,
					      acc);
}

/**
 * Calculates the checksum with IPv6 pseudo header used by TCP and UDP for a mbuf chain.
 * IPv6 addresses are expected to be in network byte order. Will only compute for a
 * portion of the payload.
 *
 * @param p chain of mbufs over that a checksum should be calculated (ip data part)
 * @param proto ipv6 protocol/next header (used for checksum of pseudo header)
 * @param proto_len length of the ipv6 payload (used for checksum of pseudo header)
 * @param chksum_len number of payload bytes used to compute chksum
 * @param src source ipv6 address (used for checksum of pseudo header)
 * @param dest destination ipv6 address (used for checksum of pseudo header)
 * @return checksum (as u16_t) to be saved directly in the protocol header
 */
u16_t
ip6_chksum_pseudo_partial(struct rte_mbuf *p, u8_t proto, u16_t proto_len,
			  u16_t chksum_len, const ip6_addr_t *src,
			  const ip6_addr_t *dest)
{
	u32_t acc = 0;
	u32_t addr;
	u8_t addr_part;

	for (addr_part = 0; addr_part < 4; addr_part++) {
		addr = src->addr[addr_part];
		acc = (u32_t) (acc + (addr & 0xffffUL));
		acc = (u32_t) (acc + ((addr >> 16) & 0xffffUL));
		addr = dest->addr[addr_part];
		acc = (u32_t) (acc + (addr & 0xffffUL));
		acc = (u32_t) (acc + ((addr >> 16) & 0xffffUL));
	}
	/* fold down to 16 bits */
	acc = FOLD_U32T(acc);
	acc = FOLD_U32T(acc);

	return inet_cksum_pseudo_partial_base(p, proto, proto_len, chksum_len,
					      acc);
}

/* ip_chksum_pseudo_partial:
 *
 * Calculates the IPv4 or IPv6 pseudo Internet checksum used by TCP and UDP for a mbuf chain.
 *
 * @param p chain of mbufs over that a checksum should be calculated (ip data part)
 * @param src source ip address (used for checksum of pseudo header)
 * @param dst destination ip address (used for checksum of pseudo header)
 * @param proto ip protocol (used for checksum of pseudo header)
 * @param proto_len length of the ip data part (used for checksum of pseudo header)
 * @return checksum (as u16_t) to be saved directly in the protocol header
 */
u16_t
ip_chksum_pseudo_partial(struct rte_mbuf *p, u8_t proto, u16_t proto_len,
			 u16_t chksum_len, const ip_addr_t *src,
			 const ip_addr_t *dest)
{
	if (IP_IS_V6(dest)) {
		return ip6_chksum_pseudo_partial(p, proto, proto_len,
						 chksum_len, ip_2_ip6(src),
						 ip_2_ip6(dest));
	} else {
		return inet_chksum_pseudo_partial(p, proto, proto_len,
						  chksum_len, ip_2_ip4(src),
						  ip_2_ip4(dest));
	}
}

/* inet_chksum:
 *
 * Calculates the Internet checksum over a portion of memory. Used primarily for IP
 * and ICMP.
 *
 * @param dataptr start of the buffer to calculate the checksum (no alignment needed)
 * @param len length of the buffer to calculate the checksum
 * @return checksum (as u16_t) to be saved directly in the protocol header
 */

u16_t inet_chksum(const void *dataptr, u16_t len)
{
	uint16_t cksum;

	cksum = rte_raw_cksum(dataptr, len);

	return (uint16_t) ~ cksum;
}

/**
 * Calculate a checksum over a chain of mbufs (without pseudo-header, much like
 * inet_chksum only mbufs are used).
 *
 * @param p mbuf chain over that the checksum should be calculated
 * @return checksum (as u16_t) to be saved directly in the protocol header
 */
u16_t inet_chksum_pbuf(struct rte_mbuf *p)
{
	u32_t acc;
	struct rte_mbuf *q;
	int swapped = 0;

	acc = 0;
	for (q = p; q != NULL; q = q->next) {
		acc +=
		    rte_raw_cksum(rte_pktmbuf_mtod(q, const void *),
				  rte_pktmbuf_data_len(q));
		acc = FOLD_U32T(acc);
		if (rte_pktmbuf_data_len(q) % 2 != 0) {
			swapped = !swapped;
			acc = SWAP_BYTES_IN_WORD(acc);
		}
	}

	if (swapped) {
		acc = SWAP_BYTES_IN_WORD(acc);
	}
	return (u16_t) ~ (acc & 0xffffUL);
}
