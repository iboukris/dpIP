/**
 * @file
 * Modules initialization
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
 */

#include "dpip/opt.h"

#include "dpip/init.h"
#include "dpip/stats.h"
#include "dpip/sys.h"
#include "dpip/memp.h"
#include "dpip/pbuf.h"
#include "dpip/netif.h"
#include "dpip/ip.h"
#include "dpip/priv/tcp_priv.h"
#include "dpip/timeouts.h"
#include "dpip/etharp.h"
#include "dpip/ip6.h"
#include "dpip/nd6.h"

#ifndef DPIP_SKIP_PACKING_CHECK

#ifdef PACK_STRUCT_USE_INCLUDES
#include "arch/bpstruct.h"
#endif
PACK_STRUCT_BEGIN struct packed_struct_test {
	PACK_STRUCT_FLD_8(u8_t dummy1);
	PACK_STRUCT_FIELD(u32_t dummy2);
} PACK_STRUCT_STRUCT;
PACK_STRUCT_END
#ifdef PACK_STRUCT_USE_INCLUDES
#include "arch/epstruct.h"
#endif
#define PACKED_STRUCT_TEST_EXPECTED_SIZE 5
#endif
/* Compile-time sanity checks for configuration errors.
 * These can be done independently of DPIP_DEBUG, without penalty.
 */
#ifndef BYTE_ORDER
#error "BYTE_ORDER is not defined, you have to define it in your cc.h"
#endif
#if (!IP_SOF_BROADCAST && IP_SOF_BROADCAST_RECV)
#error "If you want to use broadcast filter per pcb on recv operations, you have to define IP_SOF_BROADCAST=1 in your opts.h"
#endif
#if (!DPIP_UDP && DPIP_UDPLITE)
#error "If you want to use UDP Lite, you have to define DPIP_UDP=1 in your opts.h"
#endif
#if (!DPIP_UDP && !DPIP_RAW && DPIP_MULTICAST_TX_OPTIONS)
#error "If you want to use DPIP_MULTICAST_TX_OPTIONS, you have to define DPIP_UDP=1 and/or DPIP_RAW=1 in your opts.h"
#endif
#if (!DPIP_UDP && DPIP_DNS)
#error "If you want to use DNS, you have to define DPIP_UDP=1 in your opts.h"
#endif
#if !MEMP_MEM_MALLOC		/* MEMP_NUM_* checks are disabled when not using the pool allocator */
#if (DPIP_ARP && ARP_QUEUEING && (MEMP_NUM_ARP_QUEUE<=0))
#error "If you want to use ARP Queueing, you have to define MEMP_NUM_ARP_QUEUE>=1 in your opts.h"
#endif
#if (DPIP_RAW && (MEMP_NUM_RAW_PCB<=0))
#error "If you want to use RAW, you have to define MEMP_NUM_RAW_PCB>=1 in your opts.h"
#endif
#if (DPIP_UDP && (MEMP_NUM_UDP_PCB<=0))
#error "If you want to use UDP, you have to define MEMP_NUM_UDP_PCB>=1 in your opts.h"
#endif
#if (DPIP_TCP && (MEMP_NUM_TCP_PCB<=0))
#error "If you want to use TCP, you have to define MEMP_NUM_TCP_PCB>=1 in your opts.h"
#endif
#if (IP_REASSEMBLY && (MEMP_NUM_REASSDATA > IP_REASS_MAX_PBUFS))
#error "MEMP_NUM_REASSDATA > IP_REASS_MAX_PBUFS doesn't make sense since each struct ip_reassdata must hold 2 pbufs at least!"
#endif
#endif /* !MEMP_MEM_MALLOC */
#if DPIP_WND_SCALE
#if (DPIP_TCP && (TCP_WND > 0xffffffff))
#error "If you want to use TCP, TCP_WND must fit in an u32_t, so, you have to reduce it in your opts.h"
#endif
#if (DPIP_TCP && (TCP_RCV_SCALE > 14))
#error "The maximum valid window scale value is 14!"
#endif
#if (DPIP_TCP && (TCP_WND > (0xFFFFU << TCP_RCV_SCALE)))
#error "TCP_WND is bigger than the configured DPIP_WND_SCALE allows!"
#endif
#if (DPIP_TCP && ((TCP_WND >> TCP_RCV_SCALE) == 0))
#error "TCP_WND is too small for the configured DPIP_WND_SCALE (results in zero window)!"
#endif
#else /* DPIP_WND_SCALE */
#if (DPIP_TCP && (TCP_WND > 0xffff))
#error "If you want to use TCP, TCP_WND must fit in an u16_t, so, you have to reduce it in your opts.h (or enable window scaling)"
#endif
#endif /* DPIP_WND_SCALE */
#if (DPIP_TCP && (TCP_SND_QUEUELEN > 0xffff))
#error "If you want to use TCP, TCP_SND_QUEUELEN must fit in an u16_t, so, you have to reduce it in your opts.h"
#endif
#if (DPIP_TCP && (TCP_SND_QUEUELEN < 2))
#error "TCP_SND_QUEUELEN must be at least 2 for no-copy TCP writes to work"
#endif
#if (DPIP_TCP && ((TCP_MAXRTX > 12) || (TCP_SYNMAXRTX > 12)))
#error "If you want to use TCP, TCP_MAXRTX and TCP_SYNMAXRTX must less or equal to 12 (due to tcp_backoff table), so, you have to reduce them in your opts.h"
#endif
#if (DPIP_TCP && DPIP_TCP_SACK_OUT && !TCP_QUEUE_OOSEQ)
#error "To use DPIP_TCP_SACK_OUT, TCP_QUEUE_OOSEQ needs to be enabled"
#endif
#if (DPIP_TCP && DPIP_TCP_SACK_OUT && (DPIP_TCP_MAX_SACK_NUM < 1))
#error "DPIP_TCP_MAX_SACK_NUM must be greater than 0"
#endif
#if (PBUF_POOL_BUFSIZE <= MEM_ALIGNMENT)
#error "PBUF_POOL_BUFSIZE must be greater than MEM_ALIGNMENT or the offset may take the full first pbuf"
#endif
#if !DPIP_ETHERNET && (DPIP_ARP || PPPOE_SUPPORT)
#error "DPIP_ETHERNET needs to be turned on for DPIP_ARP or PPPOE_SUPPORT"
#endif
/* Compile-time checks for deprecated options.
 */
#ifdef MEMP_NUM_TCPIP_MSG
#error "MEMP_NUM_TCPIP_MSG option is deprecated. Remove it from your opts.h."
#endif
#ifdef TCP_REXMIT_DEBUG
#error "TCP_REXMIT_DEBUG option is deprecated. Remove it from your opts.h."
#endif
#ifdef RAW_STATS
#error "RAW_STATS option is deprecated. Remove it from your opts.h."
#endif
#ifdef ETHARP_QUEUE_FIRST
#error "ETHARP_QUEUE_FIRST option is deprecated. Remove it from your opts.h."
#endif
#ifdef ETHARP_ALWAYS_INSERT
#error "ETHARP_ALWAYS_INSERT option is deprecated. Remove it from your opts.h."
#endif
struct rte_mempool *dpip_pktmbuf_pool;

/**
 * @ingroup dpip_nosys
 * Initialize all modules.
 */
void dpip_init(struct rte_mempool *pktmbuf_pool)
{

	DPIP_ASSERT("dpdk mbuf pool must be provided", pktmbuf_pool != NULL);
	dpip_pktmbuf_pool = pktmbuf_pool;

#ifndef DPIP_SKIP_CONST_CHECK
	int a = 0;
	DPIP_UNUSED_ARG(a);
	DPIP_ASSERT
	    ("DPIP_CONST_CAST not implemented correctly. Check your dpIP port.",
	     DPIP_CONST_CAST(void *, &a) == &a);
#endif
#ifndef DPIP_SKIP_PACKING_CHECK
	DPIP_ASSERT
	    ("Struct packing not implemented correctly. Check your dpIP port.",
	     sizeof(struct packed_struct_test) ==
	     PACKED_STRUCT_TEST_EXPECTED_SIZE);
#endif

	/* Modules initialization */
	stats_init();
	memp_init();
	pbuf_init();
	netif_init();
	ip_init();
#if DPIP_ARP
	etharp_init();
#endif /* DPIP_ARP */
#if DPIP_TCP
	tcp_init();
#endif /* DPIP_TCP */

#if DPIP_TIMERS
	sys_timeouts_init();
#endif /* DPIP_TIMERS */
}
