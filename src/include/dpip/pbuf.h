/**
 * @file
 * pbuf API
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

#ifndef DPIP_HDR_PBUF_H
#define DPIP_HDR_PBUF_H

#include "dpip/opt.h"
#include "dpip/err.h"

#include <rte_mempool.h>
#include <rte_mbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

/* @todo: We need a mechanism to prevent wasting memory in every pbuf
   (TCP vs. UDP, IPv4 vs. IPv6: UDP/IPv4 packets may waste up to 28 bytes) */

#define PBUF_TRANSPORT_HLEN 20
#if DPIP_IPV6
#define PBUF_IP_HLEN        40
#else
#define PBUF_IP_HLEN        20
#endif

/**
 * @ingroup pbuf
 * Enumeration of pbuf layers
 */
typedef enum {
  /** Includes spare room for transport layer header, e.g. UDP header.
   * Use this if you intend to pass the pbuf to functions like udp_send().
   */
	PBUF_TRANSPORT =
	    PBUF_LINK_ENCAPSULATION_HLEN + PBUF_LINK_HLEN + PBUF_IP_HLEN +
	    PBUF_TRANSPORT_HLEN,
  /** Includes spare room for IP header.
   * Use this if you intend to pass the pbuf to functions like raw_send().
   */
	PBUF_IP = PBUF_LINK_ENCAPSULATION_HLEN + PBUF_LINK_HLEN + PBUF_IP_HLEN,
  /** Includes spare room for link layer header (ethernet header).
   * Use this if you intend to pass the pbuf to functions like ethernet_output().
   * @see PBUF_LINK_HLEN
   */
	PBUF_LINK = PBUF_LINK_ENCAPSULATION_HLEN + PBUF_LINK_HLEN,
  /** Includes spare room for additional encapsulation header before ethernet
   * headers (e.g. 802.11).
   * Use this if you intend to pass the pbuf to functions like netif->linkoutput().
   * @see PBUF_LINK_ENCAPSULATION_HLEN
   */
	PBUF_RAW_TX = PBUF_LINK_ENCAPSULATION_HLEN,
  /** Use this for input packets in a netif driver when calling netif->input()
   * in the most common case - ethernet-layer netif driver. */
	PBUF_RAW = 0
} pbuf_layer;

/* Base flags for pbuf_type definitions: */

/** Indicates that the payload directly follows the struct rte_mbuf.
 *  This makes @ref pbuf_header work in both directions. */
#define PBUF_TYPE_FLAG_STRUCT_DATA_CONTIGUOUS       0x80
/** Indicates the data stored in this pbuf can change. If this pbuf needs
 * to be queued, it must be copied/duplicated. */
#define PBUF_TYPE_FLAG_DATA_VOLATILE                0x40
/** 4 bits are reserved for 16 allocation sources (e.g. heap, pool1, pool2, etc)
 * Internally, we use: 0=heap, 1=MEMP_PBUF, 2=MEMP_PBUF_POOL -> 13 types free*/
#define PBUF_TYPE_ALLOC_SRC_MASK                    0x0F
/** Indicates this pbuf is used for RX (if not set, indicates use for TX).
 * This information can be used to keep some spare RX buffers e.g. for
 * receiving TCP ACKs to unblock a connection) */
#define PBUF_ALLOC_FLAG_RX                          0x0100
/** Indicates the application needs the pbuf payload to be in one piece */
#define PBUF_ALLOC_FLAG_DATA_CONTIGUOUS             0x0200

#define PBUF_TYPE_ALLOC_SRC_MASK_STD_HEAP           0x00
#define PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF      0x01
#define PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF_POOL 0x02
/** First pbuf allocation type for applications */
#define PBUF_TYPE_ALLOC_SRC_MASK_APP_MIN            0x03
/** Last pbuf allocation type for applications */
#define PBUF_TYPE_ALLOC_SRC_MASK_APP_MAX            PBUF_TYPE_ALLOC_SRC_MASK

/**
 * @ingroup pbuf
 * Enumeration of pbuf types
 */
typedef enum {
  /** pbuf data is stored in RAM, used for TX mostly, struct rte_mbuf and its payload
      are allocated in one piece of contiguous memory (so the first payload byte
      can be calculated from struct rte_mbuf).
      pbuf_alloc() allocates PBUF_RAM pbufs as unchained pbufs (although that might
      change in future versions).
      This should be used for all OUTGOING packets (TX).*/
	PBUF_RAM =
	    (PBUF_ALLOC_FLAG_DATA_CONTIGUOUS |
	     PBUF_TYPE_FLAG_STRUCT_DATA_CONTIGUOUS |
	     PBUF_TYPE_ALLOC_SRC_MASK_STD_HEAP),
  /** pbuf data is stored in ROM, i.e. struct rte_mbuf and its payload are located in
      totally different memory areas. Since it points to ROM, payload does not
      have to be copied when queued for transmission. */
	PBUF_ROM = PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF,
  /** pbuf comes from the pbuf pool. Much like PBUF_ROM but payload might change
      so it has to be duplicated when queued before transmitting, depending on
      who has a 'ref' to it. */
	PBUF_REF =
	    (PBUF_TYPE_FLAG_DATA_VOLATILE |
	     PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF),
  /** pbuf payload refers to RAM. This one comes from a pool and should be used
      for RX. Payload can be chained (scatter-gather RX) but like PBUF_RAM, struct
      pbuf and its payload are allocated in one piece of contiguous memory (so
      the first payload byte can be calculated from struct rte_mbuf).
      Don't use this for TX, if the pool becomes empty e.g. because of TCP queuing,
      you are unable to receive TCP acks! */
	PBUF_POOL =
	    (PBUF_ALLOC_FLAG_RX | PBUF_TYPE_FLAG_STRUCT_DATA_CONTIGUOUS |
	     PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF_POOL)
} pbuf_type;

/** indicates this packet's data should be immediately passed to the application */
#define PBUF_FLAG_PUSH      0x01U
/** indicates this is a custom pbuf: pbuf_free calls pbuf_custom->custom_free_function()
    when the last reference is released (plus custom PBUF_RAM cannot be trimmed) */
#define PBUF_FLAG_IS_CUSTOM 0x02U
/** indicates this pbuf is UDP multicast to be looped back */
#define PBUF_FLAG_MCASTLOOP 0x04U
/** indicates this pbuf was received as link-level broadcast */
#define PBUF_FLAG_LLBCAST   0x08U
/** indicates this pbuf was received as link-level multicast */
#define PBUF_FLAG_LLMCAST   0x10U
/** indicates this pbuf includes a TCP FIN flag */
#define PBUF_FLAG_TCP_FIN   0x20U

/* Initializes the pbuf module. This call is empty for now, but may not be in future. */
#define pbuf_init()

struct rte_mbuf *pbuf_alloc(pbuf_layer l, u16_t length, pbuf_type type);
struct rte_mbuf *pbuf_alloc_reference(void *payload, u16_t length,
				      pbuf_type type);
void pbuf_realloc(struct rte_mbuf *p, u16_t new_len);
void pbuf_ref(struct rte_mbuf *p);
err_t pbuf_copy(struct rte_mbuf *p_to, const struct rte_mbuf *p_from);
err_t pbuf_copy_partial_pbuf(struct rte_mbuf *p_to,
			     const struct rte_mbuf *p_from, u16_t copy_len,
			     u16_t offset);
u16_t pbuf_copy_partial(const struct rte_mbuf *p, void *dataptr, u16_t len,
			u16_t offset);
struct rte_mbuf *pbuf_clone(pbuf_layer l, pbuf_type type, struct rte_mbuf *p);

#ifdef __cplusplus
}
#endif
#endif				/* DPIP_HDR_PBUF_H */
