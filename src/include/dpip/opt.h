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

/*
 * NOTE: || defined __DOXYGEN__ is a workaround for doxygen bug -
 * without this, doxygen does not see the actual #define
 */

#if !defined DPIP_HDR_OPT_H
#define DPIP_HDR_OPT_H

#define DPIP_DEBUG	1
#include "dpip/debug.h"

/**
 * @defgroup dpip_opts_timers Timers
 * @ingroup dpip_opts_infrastructure
 * @{
 */
/**
 * DPIP_TIMERS==0: Drop support for sys_timeout and dpip-internal cyclic timers.
 * (the array of dpip-internal cyclic timers is still provided)
 */
#if !defined DPIP_TIMERS || defined __DOXYGEN__
#define DPIP_TIMERS                     1
#endif

/**
 * @defgroup dpip_opts_memcpy memcpy
 * @ingroup dpip_opts_infrastructure
 * @{
 */
/**
 * MEMCPY: override this if you have a faster implementation at hand than the
 * one included in your C library
 */
#if !defined MEMCPY || defined __DOXYGEN__
#define MEMCPY(dst,src,len)             memcpy(dst,src,len)
#endif

/**
 * SMEMCPY: override this with care! Some compilers (e.g. gcc) can inline a
 * call to memcpy() if the length is known at compile time and is small.
 */
#if !defined SMEMCPY || defined __DOXYGEN__
#define SMEMCPY(dst,src,len)            memcpy(dst,src,len)
#endif

/**
 * @}
 */

/*
   ------------------------------------
   ---------- Memory options ----------
   ------------------------------------
*/
/**
 * @defgroup dpip_opts_mem Heap and memory pools
 * @ingroup dpip_opts_infrastructure
 * @{
 */

/**
 * MEM_ALIGNMENT: should be set to the alignment of the CPU
 */
#if !defined MEM_ALIGNMENT || defined __DOXYGEN__
#define MEM_ALIGNMENT                   8U
#endif

/*
   ------------------------------------------------
   ---------- Internal Memory Pool Sizes ----------
   ------------------------------------------------
*/
/**
 * @defgroup dpip_opts_memp Internal memory pools
 * @ingroup dpip_opts_infrastructure
 * @{
 */
/**
 * MEMP_NUM_PBUF: the number of memp struct rte_mbufs (used for PBUF_ROM and PBUF_REF).
 * If the application sends a lot of data out of ROM (or other static memory),
 * this should be set high.
 */
#if !defined MEMP_NUM_PBUF || defined __DOXYGEN__
#define MEMP_NUM_PBUF                   (32768)
#endif

/**
 * MEMP_NUM_RAW_PCB: Number of raw connection PCBs
 * (requires the DPIP_RAW option)
 */
#if !defined MEMP_NUM_RAW_PCB || defined __DOXYGEN__
#define MEMP_NUM_RAW_PCB                128
#endif

/**
 * MEMP_NUM_UDP_PCB: the number of UDP protocol control blocks. One
 * per active UDP "connection".
 * (requires the DPIP_UDP option)
 */
#if !defined MEMP_NUM_UDP_PCB || defined __DOXYGEN__
#define MEMP_NUM_UDP_PCB                128
#endif

/**
 * MEMP_NUM_TCP_PCB: the number of simultaneously active TCP connections.
 * (requires the DPIP_TCP option)
 */
#if !defined MEMP_NUM_TCP_PCB || defined __DOXYGEN__
#define MEMP_NUM_TCP_PCB                256
#endif

/**
 * MEMP_NUM_TCP_SEG: the number of simultaneously queued TCP segments.
 * (requires the DPIP_TCP option)
 */
#if !defined MEMP_NUM_TCP_SEG || defined __DOXYGEN__
#define MEMP_NUM_TCP_SEG                32768
#endif

/**
 * MEMP_NUM_REASSDATA: the number of IP packets simultaneously queued for
 * reassembly (whole packets, not fragments!)
 */
#if !defined MEMP_NUM_REASSDATA || defined __DOXYGEN__
#define MEMP_NUM_REASSDATA              IP_REASS_MAX_PBUFS
#endif

/**
 * MEMP_NUM_FRAG_PBUF: the number of IP fragments simultaneously sent
 * (fragments, not whole packets!).
 * This is only used with DPIP_NETIF_TX_SINGLE_PBUF==0 and only has to be > 1
 * with DMA-enabled MACs where the packet is not yet sent when netif->output
 * returns.
 */
#if !defined MEMP_NUM_FRAG_PBUF || defined __DOXYGEN__
#define MEMP_NUM_FRAG_PBUF              15
#endif

/**
 * MEMP_NUM_ARP_QUEUE: the number of simultaneously queued outgoing
 * packets (pbufs) that are waiting for an ARP request (to resolve
 * their destination address) to finish.
 * (requires the ARP_QUEUEING option)
 */
#if !defined MEMP_NUM_ARP_QUEUE || defined __DOXYGEN__
#define MEMP_NUM_ARP_QUEUE              30
#endif

/**
 * PBUF_POOL_SIZE: the number of buffers in the pbuf pool.
 */
#if !defined PBUF_POOL_SIZE || defined __DOXYGEN__
#define PBUF_POOL_SIZE                  8192
#endif

/**
 * @}
 */

/*
   ---------------------------------
   ---------- ARP options ----------
   ---------------------------------
*/
/**
 * @defgroup dpip_opts_arp ARP
 * @ingroup dpip_opts_ipv4
 * @{
 */
/**
 * DPIP_ARP==1: Enable ARP functionality.
 */
#if !defined DPIP_ARP || defined __DOXYGEN__
#define DPIP_ARP                        1
#endif

/**
 * ARP_TABLE_SIZE: Number of active MAC-IP address pairs cached.
 */
#if !defined ARP_TABLE_SIZE || defined __DOXYGEN__
#define ARP_TABLE_SIZE                  10
#endif

/** the time an ARP entry stays valid after its last update,
 *  for ARP_TMR_INTERVAL = 1000, this is
 *  (60 * 5) seconds = 5 minutes.
 */
#if !defined ARP_MAXAGE || defined __DOXYGEN__
#define ARP_MAXAGE                      300
#endif

/**
 * ARP_QUEUEING==1: Multiple outgoing packets are queued during hardware address
 * resolution. By default, only the most recent packet is queued per IP address.
 * This is sufficient for most protocols and mainly reduces TCP connection
 * startup time. Set this to 1 if you know your application sends more than one
 * packet in a row to an IP address that is not in the ARP cache.
 */
#if !defined ARP_QUEUEING || defined __DOXYGEN__
#define ARP_QUEUEING                    1
#endif

/** The maximum number of packets which may be queued for each
 *  unresolved address by other network layers. Defaults to 3, 0 means disabled.
 *  Old packets are dropped, new packets are queued.
 */
#if !defined ARP_QUEUE_LEN || defined __DOXYGEN__
#define ARP_QUEUE_LEN                   3
#endif

/**
 * ETHARP_SUPPORT_VLAN==1: support receiving and sending ethernet packets with
 * VLAN header. See the description of DPIP_HOOK_VLAN_CHECK and
 * DPIP_HOOK_VLAN_SET hooks to check/set VLAN headers.
 * Additionally, you can define ETHARP_VLAN_CHECK to an u16_t VLAN ID to check.
 * If ETHARP_VLAN_CHECK is defined, only VLAN-traffic for this VLAN is accepted.
 * If ETHARP_VLAN_CHECK is not defined, all traffic is accepted.
 * Alternatively, define a function/define ETHARP_VLAN_CHECK_FN(eth_hdr, vlan)
 * that returns 1 to accept a packet or 0 to drop a packet.
 */
#if !defined ETHARP_SUPPORT_VLAN || defined __DOXYGEN__
#define ETHARP_SUPPORT_VLAN             0
#endif

/**
 * DPIP_VLAN_PCP==1: Enable outgoing VLAN tagging of frames on a per-PCB basis
 * for QoS purposes. With this feature enabled, each PCB has a new variable:
 * "netif_hints.tci" (Tag Control Identifier).
 * The TCI contains three fields: VID, CFI and PCP.
 * - VID is the VLAN ID, which should be set to zero.
 * - The "CFI" bit is used to enable or disable VLAN tags for the PCB.
 * - PCP (Priority Code Point) is a 3 bit field used for Ethernet level QoS.
 * See pcb_tci_*() functions to get/set/clear this.
 */
#ifndef DPIP_VLAN_PCP
#define DPIP_VLAN_PCP                   0
#endif

/** DPIP_ETHERNET==1: enable ethernet support even though ARP might be disabled
 */
#if !defined DPIP_ETHERNET || defined __DOXYGEN__
#define DPIP_ETHERNET                   DPIP_ARP
#endif

/** ETH_PAD_SIZE: number of bytes added before the ethernet header to ensure
 * alignment of payload after that header. Since the header is 14 bytes long,
 * without this padding e.g. addresses in the IP header will not be aligned
 * on a 32-bit boundary, so setting this to 2 can speed up 32-bit-platforms.
 */
#if !defined ETH_PAD_SIZE || defined __DOXYGEN__
#define ETH_PAD_SIZE                    0
#endif

/** ETHARP_SUPPORT_STATIC_ENTRIES==1: enable code to support static ARP table
 * entries (using etharp_add_static_entry/etharp_remove_static_entry).
 */
#if !defined ETHARP_SUPPORT_STATIC_ENTRIES || defined __DOXYGEN__
#define ETHARP_SUPPORT_STATIC_ENTRIES   0
#endif

/** ETHARP_TABLE_MATCH_NETIF==1: Match netif for ARP table entries.
 * If disabled, duplicate IP address on multiple netifs are not supported
 * (but this should only occur for AutoIP).
 */
#if !defined ETHARP_TABLE_MATCH_NETIF || defined __DOXYGEN__
#define ETHARP_TABLE_MATCH_NETIF        !DPIP_SINGLE_NETIF
#endif
/**
 * @}
 */

/*
   --------------------------------
   ---------- IP options ----------
   --------------------------------
*/
/**
 * IP_FORWARD==1: Enables the ability to forward IP packets across network
 * interfaces. If you are going to run dpIP on a device with only one network
 * interface, define this to 0.
 */
#if !defined IP_FORWARD || defined __DOXYGEN__
#define IP_FORWARD                      1
#endif

/**
 * IP_REASSEMBLY==1: Reassemble incoming fragmented IP packets. Note that
 * this option does not affect outgoing packet sizes, which can be controlled
 * via IP_FRAG.
 */
#if !defined IP_REASSEMBLY || defined __DOXYGEN__
#define IP_REASSEMBLY                   0
#endif

/**
 * IP_FRAG==1: Fragment outgoing IP packets if their size exceeds MTU. Note
 * that this option does not affect incoming packet sizes, which can be
 * controlled via IP_REASSEMBLY.
 */
#if !defined IP_FRAG || defined __DOXYGEN__
#define IP_FRAG                         0
#endif

/**
 * IP_OPTIONS_ALLOWED: Defines the behavior for IP options.
 *      IP_OPTIONS_ALLOWED==0: All packets with IP options are dropped.
 *      IP_OPTIONS_ALLOWED==1: IP options are allowed (but not parsed).
 */
#if !defined IP_OPTIONS_ALLOWED || defined __DOXYGEN__
#define IP_OPTIONS_ALLOWED              1
#endif

/**
 * IP_REASS_MAXAGE: Maximum time (in multiples of IP_TMR_INTERVAL - so seconds, normally)
 * a fragmented IP packet waits for all fragments to arrive. If not all fragments arrived
 * in this time, the whole packet is discarded.
 */
#if !defined IP_REASS_MAXAGE || defined __DOXYGEN__
#define IP_REASS_MAXAGE                 15
#endif

/**
 * IP_REASS_MAX_PBUFS: Total maximum amount of pbufs waiting to be reassembled.
 * Since the received pbufs are enqueued, be sure to configure
 * PBUF_POOL_SIZE > IP_REASS_MAX_PBUFS so that the stack is still able to receive
 * packets even if the maximum amount of fragments is enqueued for reassembly!
 * When IPv4 *and* IPv6 are enabled, this even changes to
 * (PBUF_POOL_SIZE > 2 * IP_REASS_MAX_PBUFS)!
 */
#if !defined IP_REASS_MAX_PBUFS || defined __DOXYGEN__
#define IP_REASS_MAX_PBUFS              (10 * ((1500 + PBUF_POOL_BUFSIZE - 1) / PBUF_POOL_BUFSIZE))
#endif

/**
 * IP_DEFAULT_TTL: Default value for Time-To-Live used by transport layers.
 */
#if !defined IP_DEFAULT_TTL || defined __DOXYGEN__
#define IP_DEFAULT_TTL                  255
#endif

/**
 * IP_SOF_BROADCAST=1: Use the SOF_BROADCAST field to enable broadcast
 * filter per pcb on udp and raw send operations. To enable broadcast filter
 * on recv operations, you also have to set IP_SOF_BROADCAST_RECV=1.
 */
#if !defined IP_SOF_BROADCAST || defined __DOXYGEN__
#define IP_SOF_BROADCAST                0
#endif

/**
 * IP_SOF_BROADCAST_RECV (requires IP_SOF_BROADCAST=1) enable the broadcast
 * filter on recv operations.
 */
#if !defined IP_SOF_BROADCAST_RECV || defined __DOXYGEN__
#define IP_SOF_BROADCAST_RECV           0
#endif

/**
 * IP_FORWARD_ALLOW_TX_ON_RX_NETIF==1: allow ip_forward() to send packets back
 * out on the netif where it was received. This should only be used for
 * wireless networks.
 * ATTENTION: When this is 1, make sure your netif driver correctly marks incoming
 * link-layer-broadcast/multicast packets as such using the corresponding pbuf flags!
 */
#if !defined IP_FORWARD_ALLOW_TX_ON_RX_NETIF || defined __DOXYGEN__
#define IP_FORWARD_ALLOW_TX_ON_RX_NETIF 0
#endif
/**
 * @}
 */

/*
   ----------------------------------
   ---------- ICMP options ----------
   ----------------------------------
*/
/**
 * ICMP_TTL: Default value for Time-To-Live used by ICMP packets.
 */
#if !defined ICMP_TTL || defined __DOXYGEN__
#define ICMP_TTL                        IP_DEFAULT_TTL
#endif

/**
 * DPIP_BROADCAST_PING==1: respond to broadcast pings (default is unicast only)
 */
#if !defined DPIP_BROADCAST_PING || defined __DOXYGEN__
#define DPIP_BROADCAST_PING             0
#endif

/**
 * DPIP_MULTICAST_PING==1: respond to multicast pings (default is unicast only)
 */
#if !defined DPIP_MULTICAST_PING || defined __DOXYGEN__
#define DPIP_MULTICAST_PING             0
#endif
/**
 * @}
 */

/*
   ---------------------------------
   ---------- RAW options ----------
   ---------------------------------
*/
/**
 * @defgroup dpip_opts_raw RAW
 * @ingroup dpip_opts_callback
 * @{
 */
/**
 * DPIP_RAW==1: Enable application layer to hook into the IP layer itself.
 */
#if !defined DPIP_RAW || defined __DOXYGEN__
#define DPIP_RAW                        0
#endif

/**
 * DPIP_RAW==1: Enable application layer to hook into the IP layer itself.
 */
#if !defined RAW_TTL || defined __DOXYGEN__
#define RAW_TTL                         IP_DEFAULT_TTL
#endif
/**
 * @}
 */

/*
   ----------------------------------
   ----- SNMP MIB2 support      -----
   ----------------------------------
*/
/**
 * @defgroup dpip_opts_mib2 SNMP MIB2 callbacks
 * @ingroup dpip_opts_infrastructure
 * @{
 */
/**
 * DPIP_MIB2_CALLBACKS==1: Turn on SNMP MIB2 callbacks.
 * Turn this on to get callbacks needed to implement MIB2.
 * Usually MIB2_STATS should be enabled, too.
 */
#if !defined DPIP_MIB2_CALLBACKS || defined __DOXYGEN__
#define DPIP_MIB2_CALLBACKS             0
#endif
/**
 * @}
 */

/*
   ---------------------------------
   ---------- UDP options ----------
   ---------------------------------
*/
/**
 * @defgroup dpip_opts_udp UDP
 * @ingroup dpip_opts_callback
 * @{
 */
/**
 * DPIP_UDP==1: Turn on UDP.
 */
#if !defined DPIP_UDP || defined __DOXYGEN__
#define DPIP_UDP                        0
#endif

/**
 * DPIP_UDPLITE==1: Turn on UDP-Lite. (Requires DPIP_UDP)
 */
#if !defined DPIP_UDPLITE || defined __DOXYGEN__
#define DPIP_UDPLITE                    0
#endif

/**
 * UDP_TTL: Default Time-To-Live value.
 */
#if !defined UDP_TTL || defined __DOXYGEN__
#define UDP_TTL                         IP_DEFAULT_TTL
#endif

/**
 * DPIP_NETBUF_RECVINFO==1: append destination addr and port to every netbuf.
 */
#if !defined DPIP_NETBUF_RECVINFO || defined __DOXYGEN__
#define DPIP_NETBUF_RECVINFO            0
#endif
/**
 * @}
 */

/*
   ---------------------------------
   ---------- TCP options ----------
   ---------------------------------
*/
/**
 * @defgroup dpip_opts_tcp TCP
 * @ingroup dpip_opts_callback
 * @{
 */
/**
 * DPIP_TCP==1: Turn on TCP.
 */
#if !defined DPIP_TCP || defined __DOXYGEN__
#define DPIP_TCP                        1
#endif

/**
 * TCP_TTL: Default Time-To-Live value.
 */
#if !defined TCP_TTL || defined __DOXYGEN__
#define TCP_TTL                         IP_DEFAULT_TTL
#endif

/**
 * TCP_WND: The size of a TCP window.  This must be at least
 * (2 * TCP_MSS) for things to work well.
 * ATTENTION: when using TCP_RCV_SCALE, TCP_WND is the total size
 * with scaling applied. Maximum window value in the TCP header
 * will be TCP_WND >> TCP_RCV_SCALE
 */
#if !defined TCP_WND || defined __DOXYGEN__
#define TCP_WND                         (20 * 1024)
#endif

/**
 * TCP_MAXRTX: Maximum number of retransmissions of data segments.
 */
#if !defined TCP_MAXRTX || defined __DOXYGEN__
#define TCP_MAXRTX                      12
#endif

/**
 * TCP_SYNMAXRTX: Maximum number of retransmissions of SYN segments.
 */
#if !defined TCP_SYNMAXRTX || defined __DOXYGEN__
#define TCP_SYNMAXRTX                   4
#endif

/**
 * TCP_QUEUE_OOSEQ==1: TCP will queue segments that arrive out of order.
 * Define to 0 if your device is low on memory.
 */
#if !defined TCP_QUEUE_OOSEQ || defined __DOXYGEN__
#define TCP_QUEUE_OOSEQ                 DPIP_TCP
#endif

/**
 * DPIP_TCP_SACK_OUT==1: TCP will support sending selective acknowledgements (SACKs).
 */
#if !defined DPIP_TCP_SACK_OUT || defined __DOXYGEN__
#define DPIP_TCP_SACK_OUT               0
#endif

/**
 * DPIP_TCP_MAX_SACK_NUM: The maximum number of SACK values to include in TCP segments.
 * Must be at least 1, but is only used if DPIP_TCP_SACK_OUT is enabled.
 * NOTE: Even though we never send more than 3 or 4 SACK ranges in a single segment
 * (depending on other options), setting this option to values greater than 4 is not pointless.
 * This is basically the max number of SACK ranges we want to keep track of.
 * As new data is delivered, some of the SACK ranges may be removed or merged.
 * In that case some of those older SACK ranges may be used again.
 * The amount of memory used to store SACK ranges is DPIP_TCP_MAX_SACK_NUM * 8 bytes for each TCP PCB.
 */
#if !defined DPIP_TCP_MAX_SACK_NUM || defined __DOXYGEN__
#define DPIP_TCP_MAX_SACK_NUM           4
#endif

/**
 * TCP_MSS: TCP Maximum segment size. (default is 536, a conservative default,
 * you might want to increase this.)
 * For the receive side, this MSS is advertised to the remote side
 * when opening a connection. For the transmit size, this MSS sets
 * an upper limit on the MSS advertised by the remote host.
 */
#if !defined TCP_MSS || defined __DOXYGEN__
#define TCP_MSS                         1460
#endif

/**
 * TCP_CALCULATE_EFF_SEND_MSS: "The maximum size of a segment that TCP really
 * sends, the 'effective send MSS,' MUST be the smaller of the send MSS (which
 * reflects the available reassembly buffer size at the remote host) and the
 * largest size permitted by the IP layer" (RFC 1122)
 * Setting this to 1 enables code that checks TCP_MSS against the MTU of the
 * netif used for a connection and limits the MSS if it would be too big otherwise.
 */
#if !defined TCP_CALCULATE_EFF_SEND_MSS || defined __DOXYGEN__
#define TCP_CALCULATE_EFF_SEND_MSS      1
#endif

/**
 * DPIP_TCP_RTO_TIME: Initial TCP retransmission timeout (ms).
 * This defaults to 3 seconds as traditionally defined in the TCP protocol.
 * For improving timely recovery on faster networks, this value could
 * be lowered down to 1 second (RFC 6298)
 */
#if !defined DPIP_TCP_RTO_TIME || defined __DOXYGEN__
#define DPIP_TCP_RTO_TIME               3000
#endif

/**
 * TCP_SND_BUF: TCP sender buffer space (bytes).
 * To achieve good performance, this should be at least 2 * TCP_MSS.
 */
#if !defined TCP_SND_BUF || defined __DOXYGEN__
#define TCP_SND_BUF                     (65535)
#endif

/**
 * TCP_SND_QUEUELEN: TCP sender buffer space (pbufs). This must be at least
 * as much as (2 * TCP_SND_BUF/TCP_MSS) for things to work.
 */
#if !defined TCP_SND_QUEUELEN || defined __DOXYGEN__
#define TCP_SND_QUEUELEN                (2 * TCP_SND_BUF/TCP_MSS)
#endif

/**
 * TCP_OOSEQ_MAX_BYTES: The default maximum number of bytes queued on ooseq per
 * pcb if TCP_OOSEQ_BYTES_LIMIT is not defined. Default is 0 (no limit).
 * Only valid for TCP_QUEUE_OOSEQ==1.
 */
#if !defined TCP_OOSEQ_MAX_BYTES || defined __DOXYGEN__
#define TCP_OOSEQ_MAX_BYTES             0
#endif

/**
 * TCP_OOSEQ_BYTES_LIMIT(pcb): Return the maximum number of bytes to be queued
 * on ooseq per pcb, given the pcb. Only valid for TCP_QUEUE_OOSEQ==1 &&
 * TCP_OOSEQ_MAX_BYTES==1.
 * Use this to override TCP_OOSEQ_MAX_BYTES to a dynamic value per pcb.
 */
#if !defined TCP_OOSEQ_BYTES_LIMIT
#if TCP_OOSEQ_MAX_BYTES
#define TCP_OOSEQ_BYTES_LIMIT(pcb)      TCP_OOSEQ_MAX_BYTES
#elif defined __DOXYGEN__
#define TCP_OOSEQ_BYTES_LIMIT(pcb)
#endif
#endif

/**
 * TCP_OOSEQ_MAX_PBUFS: The default maximum number of pbufs queued on ooseq per
 * pcb if TCP_OOSEQ_BYTES_LIMIT is not defined. Default is 0 (no limit).
 * Only valid for TCP_QUEUE_OOSEQ==1.
 */
#if !defined TCP_OOSEQ_MAX_PBUFS || defined __DOXYGEN__
#define TCP_OOSEQ_MAX_PBUFS             0
#endif

/**
 * TCP_OOSEQ_PBUFS_LIMIT(pcb): Return the maximum number of pbufs to be queued
 * on ooseq per pcb, given the pcb.  Only valid for TCP_QUEUE_OOSEQ==1 &&
 * TCP_OOSEQ_MAX_PBUFS==1.
 * Use this to override TCP_OOSEQ_MAX_PBUFS to a dynamic value per pcb.
 */
#if !defined TCP_OOSEQ_PBUFS_LIMIT
#if TCP_OOSEQ_MAX_PBUFS
#define TCP_OOSEQ_PBUFS_LIMIT(pcb)      TCP_OOSEQ_MAX_PBUFS
#elif defined __DOXYGEN__
#define TCP_OOSEQ_PBUFS_LIMIT(pcb)
#endif
#endif

/**
 * DPIP_TCP_TIMESTAMPS==1: support the TCP timestamp option.
 * The timestamp option is currently only used to help remote hosts, it is not
 * really used locally. Therefore, it is only enabled when a TS option is
 * received in the initial SYN packet from a remote host.
 */
#if !defined DPIP_TCP_TIMESTAMPS || defined __DOXYGEN__
#define DPIP_TCP_TIMESTAMPS             0
#endif

/**
 * TCP_WND_UPDATE_THRESHOLD: difference in window to trigger an
 * explicit window update
 */
#if !defined TCP_WND_UPDATE_THRESHOLD || defined __DOXYGEN__
#define TCP_WND_UPDATE_THRESHOLD        RTE_MIN((TCP_WND / 4), (TCP_MSS * 4))
#endif

/**
 * DPIP_WND_SCALE and TCP_RCV_SCALE:
 * Set DPIP_WND_SCALE to 1 to enable window scaling.
 * Set TCP_RCV_SCALE to the desired scaling factor (shift count in the
 * range of [0..14]).
 * When DPIP_WND_SCALE is enabled but TCP_RCV_SCALE is 0, we can use a large
 * send window while having a small receive window only.
 */
#if !defined DPIP_WND_SCALE || defined __DOXYGEN__
#define DPIP_WND_SCALE                  0
#define TCP_RCV_SCALE                   0
#endif

/*
   ----------------------------------
   ---------- Pbuf options ----------
   ----------------------------------
*/
/**
 * @defgroup dpip_opts_pbuf PBUF
 * @ingroup dpip_opts
 * @{
 */
/**
 * PBUF_LINK_HLEN: the number of bytes that should be allocated for a
 * link level header. The default is 14, the standard value for
 * Ethernet.
 */
#if !defined PBUF_LINK_HLEN || defined __DOXYGEN__
#if (defined DPIP_HOOK_VLAN_SET || DPIP_VLAN_PCP) && !defined __DOXYGEN__
#define PBUF_LINK_HLEN                  (18 + ETH_PAD_SIZE)
#else /* DPIP_HOOK_VLAN_SET || DPIP_VLAN_PCP */
#define PBUF_LINK_HLEN                  (14 + ETH_PAD_SIZE)
#endif /* DPIP_HOOK_VLAN_SET || DPIP_VLAN_PCP */
#endif

/**
 * PBUF_LINK_ENCAPSULATION_HLEN: the number of bytes that should be allocated
 * for an additional encapsulation header before ethernet headers (e.g. 802.11)
 */
#if !defined PBUF_LINK_ENCAPSULATION_HLEN || defined __DOXYGEN__
#define PBUF_LINK_ENCAPSULATION_HLEN    0
#endif

/**
 * PBUF_POOL_BUFSIZE: the size of each pbuf in the pbuf pool. The default is
 * designed to accommodate single full size TCP frame in one pbuf, including
 * TCP_MSS, IP header, and link header.
 */
#if !defined PBUF_POOL_BUFSIZE || defined __DOXYGEN__
#define PBUF_POOL_BUFSIZE               8192
#endif

/**
 * DPIP_PBUF_REF_T: Refcount type in pbuf.
 * Default width of u8_t can be increased if 255 refs are not enough for you.
 */
#if !defined DPIP_PBUF_REF_T || defined __DOXYGEN__
#define DPIP_PBUF_REF_T                 u8_t
#endif

/**
 * DPIP_PBUF_CUSTOM_DATA: Store private data on pbufs (e.g. timestamps)
 * This extends struct rte_mbuf so user can store custom data on every pbuf.
 * e.g.:
 *  \#define DPIP_PBUF_CUSTOM_DATA   u32_t myref;
 */
#if !defined DPIP_PBUF_CUSTOM_DATA || defined __DOXYGEN__
#define DPIP_PBUF_CUSTOM_DATA
#endif

/**
 * DPIP_PBUF_CUSTOM_DATA_INIT: Initialize private data on pbufs.
 * e.g. for the above example definition:
 *  \#define DPIP_PBUF_CUSTOM_DATA(p) (p)->myref = 0
 */
#if !defined DPIP_PBUF_CUSTOM_DATA_INIT || defined __DOXYGEN__
#define DPIP_PBUF_CUSTOM_DATA_INIT(p)
#endif

/**
 * @}
 */

/*
   ------------------------------------------------
   ---------- Network Interfaces options ----------
   ------------------------------------------------
*/
/**
 * @defgroup dpip_opts_netif NETIF
 * @ingroup dpip_opts
 * @{
 */
/**
 * DPIP_SINGLE_NETIF==1: use a single netif only. This is the common case for
 * small real-life targets. Some code like routing etc. can be left out.
 */
#if !defined DPIP_SINGLE_NETIF || defined __DOXYGEN__
#define DPIP_SINGLE_NETIF               0
#endif

/**
 * DPIP_NETIF_HOSTNAME==1: use DHCP_OPTION_HOSTNAME with netif's hostname
 * field.
 */
#if !defined DPIP_NETIF_HOSTNAME || defined __DOXYGEN__
#define DPIP_NETIF_HOSTNAME             0
#endif

/**
 * DPIP_NETIF_API==1: Support netif api (in netifapi.c)
 */
#if !defined DPIP_NETIF_API || defined __DOXYGEN__
#define DPIP_NETIF_API                  0
#endif

/**
 * DPIP_NETIF_STATUS_CALLBACK==1: Support a callback function whenever an interface
 * changes its up/down status (i.e., due to DHCP IP acquisition)
 */
#if !defined DPIP_NETIF_STATUS_CALLBACK || defined __DOXYGEN__
#define DPIP_NETIF_STATUS_CALLBACK      0
#endif

/**
 * DPIP_NETIF_EXT_STATUS_CALLBACK==1: Support an extended callback function
 * for several netif related event that supports multiple subscribers.
 * @see netif_ext_status_callback
 */
#if !defined DPIP_NETIF_EXT_STATUS_CALLBACK || defined __DOXYGEN__
#define DPIP_NETIF_EXT_STATUS_CALLBACK  0
#endif

/**
 * DPIP_NETIF_LINK_CALLBACK==1: Support a callback function from an interface
 * whenever the link changes (i.e., link down)
 */
#if !defined DPIP_NETIF_LINK_CALLBACK || defined __DOXYGEN__
#define DPIP_NETIF_LINK_CALLBACK        0
#endif

/**
 * DPIP_NETIF_REMOVE_CALLBACK==1: Support a callback function that is called
 * when a netif has been removed
 */
#if !defined DPIP_NETIF_REMOVE_CALLBACK || defined __DOXYGEN__
#define DPIP_NETIF_REMOVE_CALLBACK      0
#endif

/**
 * DPIP_NETIF_HWADDRHINT==1: Cache link-layer-address hints (e.g. table
 * indices) in struct netif. TCP and UDP can make use of this to prevent
 * scanning the ARP table for every sent packet. While this is faster for big
 * ARP tables or many concurrent connections, it might be counterproductive
 * if you have a tiny ARP table or if there never are concurrent connections.
 */
#if !defined DPIP_NETIF_HWADDRHINT || defined __DOXYGEN__
#define DPIP_NETIF_HWADDRHINT           0
#endif

/**
 * DPIP_NUM_NETIF_CLIENT_DATA: Number of clients that may store
 * data in client_data member array of struct netif (max. 256).
 */
#if !defined DPIP_NUM_NETIF_CLIENT_DATA || defined __DOXYGEN__
#define DPIP_NUM_NETIF_CLIENT_DATA      0
#endif
/**
 * @}
 */

/**
 * DPIP_TCP_KEEPALIVE==1: Enable TCP_KEEPIDLE, TCP_KEEPINTVL and TCP_KEEPCNT
 * options processing. Note that TCP_KEEPIDLE and TCP_KEEPINTVL have to be set
 * in seconds. (does not require sockets.c, and will affect tcp.c)
 */
#if !defined DPIP_TCP_KEEPALIVE || defined __DOXYGEN__
#define DPIP_TCP_KEEPALIVE              1
#endif

/*
   ----------------------------------------
   ---------- Statistics options ----------
   ----------------------------------------
*/
/**
 * @defgroup dpip_opts_stats Statistics
 * @ingroup dpip_opts_debug
 * @{
 */
/**
 * DPIP_STATS==1: Enable statistics collection in dpip_stats.
 */
#if !defined DPIP_STATS || defined __DOXYGEN__
#define DPIP_STATS                      1
#endif

#if DPIP_STATS

/**
 * DPIP_STATS_DISPLAY==1: Compile in the statistics output functions.
 */
#if !defined DPIP_STATS_DISPLAY || defined __DOXYGEN__
#define DPIP_STATS_DISPLAY              1
#endif

/**
 * LINK_STATS==1: Enable link stats.
 */
#if !defined LINK_STATS || defined __DOXYGEN__
#define LINK_STATS                      1
#endif

/**
 * ETHARP_STATS==1: Enable etharp stats.
 */
#if !defined ETHARP_STATS || defined __DOXYGEN__
#define ETHARP_STATS                    (DPIP_ARP)
#endif

/**
 * IP_STATS==1: Enable IP stats.
 */
#if !defined IP_STATS || defined __DOXYGEN__
#define IP_STATS                        1
#endif

/**
 * IPFRAG_STATS==1: Enable IP fragmentation stats. Default is
 * on if using either frag or reass.
 */
#if !defined IPFRAG_STATS || defined __DOXYGEN__
#define IPFRAG_STATS                    (IP_REASSEMBLY || IP_FRAG)
#endif

/**
 * ICMP_STATS==1: Enable ICMP stats.
 */
#if !defined ICMP_STATS || defined __DOXYGEN__
#define ICMP_STATS                      1
#endif

/**
 * UDP_STATS==1: Enable UDP stats. Default is on if
 * UDP enabled, otherwise off.
 */
#if !defined UDP_STATS || defined __DOXYGEN__
#define UDP_STATS                       (DPIP_UDP)
#endif

/**
 * TCP_STATS==1: Enable TCP stats. Default is on if TCP
 * enabled, otherwise off.
 */
#if !defined TCP_STATS || defined __DOXYGEN__
#define TCP_STATS                       (DPIP_TCP)
#endif

/**
 * IP6_STATS==1: Enable IPv6 stats.
 */
#if !defined IP6_STATS || defined __DOXYGEN__
#define IP6_STATS                       (1)
#endif

/**
 * ICMP6_STATS==1: Enable ICMP for IPv6 stats.
 */
#if !defined ICMP6_STATS || defined __DOXYGEN__
#define ICMP6_STATS                     1
#endif

/**
 * IP6_FRAG_STATS==1: Enable IPv6 fragmentation stats.
 */
#if !defined IP6_FRAG_STATS || defined __DOXYGEN__
#define IP6_FRAG_STATS                  (DPIP_IPV6_FRAG || DPIP_IPV6_REASS)
#endif

/**
 * ND6_STATS==1: Enable Neighbor discovery for IPv6 stats.
 */
#if !defined ND6_STATS || defined __DOXYGEN__
#define ND6_STATS                       (1)
#endif

/**
 * MIB2_STATS==1: Stats for SNMP MIB2.
 */
#if !defined MIB2_STATS || defined __DOXYGEN__
#define MIB2_STATS                      0
#endif

#else

#define LINK_STATS                      0
#define ETHARP_STATS                    0
#define IP_STATS                        0
#define IPFRAG_STATS                    0
#define ICMP_STATS                      0
#define UDP_STATS                       0
#define TCP_STATS                       0
#define DPIP_STATS_DISPLAY              0
#define IP6_STATS                       0
#define ICMP6_STATS                     0
#define IP6_FRAG_STATS                  0
#define ND6_STATS                       0
#define MIB2_STATS                      0

#endif /* DPIP_STATS */
/**
 * @}
 */

/*
   --------------------------------------
   ---------- Checksum options ----------
   --------------------------------------
*/
/**
 * @defgroup dpip_opts_checksum Checksum
 * @ingroup dpip_opts_infrastructure
 * @{
 */
/**
 * DPIP_CHECKSUM_CTRL_PER_NETIF==1: Checksum generation/check can be enabled/disabled
 * per netif.
 * ATTENTION: if enabled, the CHECKSUM_GEN_* and CHECKSUM_CHECK_* defines must be enabled!
 */
#if !defined DPIP_CHECKSUM_CTRL_PER_NETIF || defined __DOXYGEN__
#define DPIP_CHECKSUM_CTRL_PER_NETIF    0
#endif

/**
 * CHECKSUM_GEN_IP==1: Generate checksums in software for outgoing IP packets.
 */
#if !defined CHECKSUM_GEN_IP || defined __DOXYGEN__
#define CHECKSUM_GEN_IP                 1
#endif

/**
 * CHECKSUM_GEN_UDP==1: Generate checksums in software for outgoing UDP packets.
 */
#if !defined CHECKSUM_GEN_UDP || defined __DOXYGEN__
#define CHECKSUM_GEN_UDP                1
#endif

/**
 * CHECKSUM_GEN_TCP==1: Generate checksums in software for outgoing TCP packets.
 */
#if !defined CHECKSUM_GEN_TCP || defined __DOXYGEN__
#define CHECKSUM_GEN_TCP                1
#endif

/**
 * CHECKSUM_GEN_ICMP==1: Generate checksums in software for outgoing ICMP packets.
 */
#if !defined CHECKSUM_GEN_ICMP || defined __DOXYGEN__
#define CHECKSUM_GEN_ICMP               1
#endif

/**
 * CHECKSUM_GEN_ICMP6==1: Generate checksums in software for outgoing ICMP6 packets.
 */
#if !defined CHECKSUM_GEN_ICMP6 || defined __DOXYGEN__
#define CHECKSUM_GEN_ICMP6              1
#endif

/**
 * CHECKSUM_CHECK_IP==1: Check checksums in software for incoming IP packets.
 */
#if !defined CHECKSUM_CHECK_IP || defined __DOXYGEN__
#define CHECKSUM_CHECK_IP               1
#endif

/**
 * CHECKSUM_CHECK_UDP==1: Check checksums in software for incoming UDP packets.
 */
#if !defined CHECKSUM_CHECK_UDP || defined __DOXYGEN__
#define CHECKSUM_CHECK_UDP              1
#endif

/**
 * CHECKSUM_CHECK_TCP==1: Check checksums in software for incoming TCP packets.
 */
#if !defined CHECKSUM_CHECK_TCP || defined __DOXYGEN__
#define CHECKSUM_CHECK_TCP              1
#endif

/**
 * CHECKSUM_CHECK_ICMP==1: Check checksums in software for incoming ICMP packets.
 */
#if !defined CHECKSUM_CHECK_ICMP || defined __DOXYGEN__
#define CHECKSUM_CHECK_ICMP             1
#endif

/**
 * CHECKSUM_CHECK_ICMP6==1: Check checksums in software for incoming ICMPv6 packets
 */
#if !defined CHECKSUM_CHECK_ICMP6 || defined __DOXYGEN__
#define CHECKSUM_CHECK_ICMP6            1
#endif

/*
   ---------------------------------------
   ---------- IPv6 options ---------------
   ---------------------------------------
*/
/**
 * IPV6_REASS_MAXAGE: Maximum time (in multiples of IP6_REASS_TMR_INTERVAL - so seconds, normally)
 * a fragmented IP packet waits for all fragments to arrive. If not all fragments arrived
 * in this time, the whole packet is discarded.
 */
#if !defined IPV6_REASS_MAXAGE || defined __DOXYGEN__
#define IPV6_REASS_MAXAGE               60
#endif

/**
 * DPIP_IPV6_SCOPES==1: Enable support for IPv6 address scopes, ensuring that
 * e.g. link-local addresses are really treated as link-local. Disable this
 * setting only for single-interface configurations.
 * All addresses that have a scope according to the default policy (link-local
 * unicast addresses, interface-local and link-local multicast addresses) should
 * now have a zone set on them before being passed to the core API, although
 * dpIP will currently attempt to select a zone on the caller's behalf when
 * necessary. Applications that directly assign IPv6 addresses to interfaces
 * (which is NOT recommended) must now ensure that link-local addresses carry
 * the netif's zone. See the new ip6_zone.h header file for more information and
 * relevant macros. For now it is still possible to turn off scopes support
 * through the new DPIP_IPV6_SCOPES option. When upgrading an implementation that
 * uses the core API directly, it is highly recommended to enable
 * DPIP_IPV6_SCOPES_DEBUG at least for a while, to ensure e.g. proper address
 * initialization.
 */
#if !defined DPIP_IPV6_SCOPES || defined __DOXYGEN__
#define DPIP_IPV6_SCOPES                (!DPIP_SINGLE_NETIF)
#endif

/**
 * DPIP_IPV6_SCOPES_DEBUG==1: Perform run-time checks to verify that addresses
 * are properly zoned (see ip6_zone.h on what that means) where it matters.
 * Enabling this setting is highly recommended when upgrading from an existing
 * installation that is not yet scope-aware; otherwise it may be too expensive.
 */
#if !defined DPIP_IPV6_SCOPES_DEBUG || defined __DOXYGEN__
#define DPIP_IPV6_SCOPES_DEBUG          0
#endif

/**
 * DPIP_IPV6_NUM_ADDRESSES: Number of IPv6 addresses per netif.
 */
#if !defined DPIP_IPV6_NUM_ADDRESSES || defined __DOXYGEN__
#define DPIP_IPV6_NUM_ADDRESSES         3
#endif

/**
 * DPIP_IPV6_FORWARD==1: Forward IPv6 packets across netifs
 */
#if !defined DPIP_IPV6_FORWARD || defined __DOXYGEN__
#define DPIP_IPV6_FORWARD               0
#endif

/**
 * DPIP_IPV6_FRAG==1: Fragment outgoing IPv6 packets that are too big.
 */
#if !defined DPIP_IPV6_FRAG || defined __DOXYGEN__
#define DPIP_IPV6_FRAG                  0
#endif

/**
 * DPIP_IPV6_REASS==1: reassemble incoming IPv6 packets that fragmented
 */
#if !defined DPIP_IPV6_REASS || defined __DOXYGEN__
#define DPIP_IPV6_REASS                 0
#endif

/**
 * DPIP_IPV6_SEND_ROUTER_SOLICIT==1: Send router solicitation messages during
 * network startup.
 */
#if !defined DPIP_IPV6_SEND_ROUTER_SOLICIT || defined __DOXYGEN__
#define DPIP_IPV6_SEND_ROUTER_SOLICIT   1
#endif

/**
 * DPIP_IPV6_AUTOCONFIG==1: Enable stateless address autoconfiguration as per RFC 4862.
 */
#if !defined DPIP_IPV6_AUTOCONFIG || defined __DOXYGEN__
#define DPIP_IPV6_AUTOCONFIG            1
#endif

/**
 * DPIP_IPV6_ADDRESS_LIFETIMES==1: Keep valid and preferred lifetimes for each
 * IPv6 address. Required for DPIP_IPV6_AUTOCONFIG. May still be enabled
 * otherwise, in which case the application may assign address lifetimes with
 * the appropriate macros. Addresses with no lifetime are assumed to be static.
 * If this option is disabled, all addresses are assumed to be static.
 */
#if !defined DPIP_IPV6_ADDRESS_LIFETIMES || defined __DOXYGEN__
#define DPIP_IPV6_ADDRESS_LIFETIMES     DPIP_IPV6_AUTOCONFIG
#endif

/**
 * DPIP_IPV6_DUP_DETECT_ATTEMPTS=[0..7]: Number of duplicate address detection attempts.
 */
#if !defined DPIP_IPV6_DUP_DETECT_ATTEMPTS || defined __DOXYGEN__
#define DPIP_IPV6_DUP_DETECT_ATTEMPTS   1
#endif
/**
 * @}
 */

/**
 * DPIP_ICMP6_DATASIZE: bytes from original packet to send back in
 * ICMPv6 error messages (0 = default of IP6_MIN_MTU_LENGTH)
 * ATTENTION: RFC4443 section 2.4 says IP6_MIN_MTU_LENGTH is a MUST,
 * so override this only if you absolutely have to!
 */
#if !defined DPIP_ICMP6_DATASIZE || defined __DOXYGEN__
#define DPIP_ICMP6_DATASIZE             0
#endif

/**
 * DPIP_ICMP6_HL: default hop limit for ICMPv6 messages
 */
#if !defined DPIP_ICMP6_HL || defined __DOXYGEN__
#define DPIP_ICMP6_HL                   255
#endif
/**
 * @}
 */

/**
 * @defgroup dpip_opts_nd6 Neighbor discovery
 * @ingroup dpip_opts_ipv6
 * @{
 */
/**
 * DPIP_ND6_QUEUEING==1: queue outgoing IPv6 packets while MAC address
 * is being resolved.
 */
#if !defined DPIP_ND6_QUEUEING || defined __DOXYGEN__
#define DPIP_ND6_QUEUEING               1
#endif

/**
 * MEMP_NUM_ND6_QUEUE: Max number of IPv6 packets to queue during MAC resolution.
 */
#if !defined MEMP_NUM_ND6_QUEUE || defined __DOXYGEN__
#define MEMP_NUM_ND6_QUEUE              20
#endif

/**
 * DPIP_ND6_NUM_NEIGHBORS: Number of entries in IPv6 neighbor cache
 */
#if !defined DPIP_ND6_NUM_NEIGHBORS || defined __DOXYGEN__
#define DPIP_ND6_NUM_NEIGHBORS          10
#endif

/**
 * DPIP_ND6_NUM_DESTINATIONS: number of entries in IPv6 destination cache
 */
#if !defined DPIP_ND6_NUM_DESTINATIONS || defined __DOXYGEN__
#define DPIP_ND6_NUM_DESTINATIONS       10
#endif

/**
 * DPIP_ND6_NUM_PREFIXES: number of entries in IPv6 on-link prefixes cache
 */
#if !defined DPIP_ND6_NUM_PREFIXES || defined __DOXYGEN__
#define DPIP_ND6_NUM_PREFIXES           5
#endif

/**
 * DPIP_ND6_NUM_ROUTERS: number of entries in IPv6 default router cache
 */
#if !defined DPIP_ND6_NUM_ROUTERS || defined __DOXYGEN__
#define DPIP_ND6_NUM_ROUTERS            3
#endif

/**
 * DPIP_ND6_MAX_MULTICAST_SOLICIT: max number of multicast solicit messages to send
 * (neighbor solicit and router solicit)
 */
#if !defined DPIP_ND6_MAX_MULTICAST_SOLICIT || defined __DOXYGEN__
#define DPIP_ND6_MAX_MULTICAST_SOLICIT  3
#endif

/**
 * DPIP_ND6_MAX_UNICAST_SOLICIT: max number of unicast neighbor solicitation messages
 * to send during neighbor reachability detection.
 */
#if !defined DPIP_ND6_MAX_UNICAST_SOLICIT || defined __DOXYGEN__
#define DPIP_ND6_MAX_UNICAST_SOLICIT    3
#endif

/**
 * Unused: See ND RFC (time in milliseconds).
 */
#if !defined DPIP_ND6_MAX_ANYCAST_DELAY_TIME || defined __DOXYGEN__
#define DPIP_ND6_MAX_ANYCAST_DELAY_TIME 1000
#endif

/**
 * Unused: See ND RFC
 */
#if !defined DPIP_ND6_MAX_NEIGHBOR_ADVERTISEMENT || defined __DOXYGEN__
#define DPIP_ND6_MAX_NEIGHBOR_ADVERTISEMENT  3
#endif

/**
 * DPIP_ND6_REACHABLE_TIME: default neighbor reachable time (in milliseconds).
 * May be updated by router advertisement messages.
 */
#if !defined DPIP_ND6_REACHABLE_TIME || defined __DOXYGEN__
#define DPIP_ND6_REACHABLE_TIME         30000
#endif

/**
 * DPIP_ND6_RETRANS_TIMER: default retransmission timer for solicitation messages
 */
#if !defined DPIP_ND6_RETRANS_TIMER || defined __DOXYGEN__
#define DPIP_ND6_RETRANS_TIMER          1000
#endif

/**
 * DPIP_ND6_DELAY_FIRST_PROBE_TIME: Delay before first unicast neighbor solicitation
 * message is sent, during neighbor reachability detection.
 */
#if !defined DPIP_ND6_DELAY_FIRST_PROBE_TIME || defined __DOXYGEN__
#define DPIP_ND6_DELAY_FIRST_PROBE_TIME 5000
#endif

/**
 * DPIP_ND6_ALLOW_RA_UPDATES==1: Allow Router Advertisement messages to update
 * Reachable time and retransmission timers, and netif MTU.
 */
#if !defined DPIP_ND6_ALLOW_RA_UPDATES || defined __DOXYGEN__
#define DPIP_ND6_ALLOW_RA_UPDATES       1
#endif

/**
 * DPIP_ND6_TCP_REACHABILITY_HINTS==1: Allow TCP to provide Neighbor Discovery
 * with reachability hints for connected destinations. This helps avoid sending
 * unicast neighbor solicitation messages.
 */
#if !defined DPIP_ND6_TCP_REACHABILITY_HINTS || defined __DOXYGEN__
#define DPIP_ND6_TCP_REACHABILITY_HINTS 1
#endif

/**
 * DPIP_ND6_RDNSS_MAX_DNS_SERVERS > 0: Use IPv6 Router Advertisement Recursive
 * DNS Server Option (as per RFC 6106) to copy a defined maximum number of DNS
 * servers to the DNS module.
 */
#if !defined DPIP_ND6_RDNSS_MAX_DNS_SERVERS || defined __DOXYGEN__
#define DPIP_ND6_RDNSS_MAX_DNS_SERVERS  0
#endif
/**
 * @}
 */

/*
   ---------------------------------------
   ---------- Hook options ---------------
   ---------------------------------------
*/

/**
 * @defgroup dpip_opts_hooks Hooks
 * @ingroup dpip_opts_infrastructure
 * Hooks are undefined by default, define them to a function if you need them.
 * @{
 */

/**
 * DPIP_HOOK_FILENAME: Custom filename to \#include in files that provide hooks.
 * Declare your hook function prototypes in there, you may also \#include all headers
 * providing data types that are need in this file.
 */
#ifdef __DOXYGEN__
#define DPIP_HOOK_FILENAME "path/to/my/dpip_hooks.h"
#endif

/**
 * DPIP_HOOK_TCP_ISN:
 * Hook for generation of the Initial Sequence Number (ISN) for a new TCP
 * connection. The default dpIP ISN generation algorithm is very basic and may
 * allow for TCP spoofing attacks. This hook provides the means to implement
 * the standardized ISN generation algorithm from RFC 6528 (see contrib/adons/tcp_isn),
 * or any other desired algorithm as a replacement.
 * Called from tcp_connect() and tcp_listen_input() when an ISN is needed for
 * a new TCP connection, if TCP support (@ref DPIP_TCP) is enabled.<br>
 * Signature:\code{.c}
 * u32_t my_hook_tcp_isn(const ip_addr_t* local_ip, u16_t local_port, const ip_addr_t* remote_ip, u16_t remote_port);
 * \endcode
 * - it may be necessary to use "struct ip_addr" (ip4_addr, ip6_addr) instead of "ip_addr_t" in function declarations<br>
 * Arguments:
 * - local_ip: pointer to the local IP address of the connection
 * - local_port: local port number of the connection (host-byte order)
 * - remote_ip: pointer to the remote IP address of the connection
 * - remote_port: remote port number of the connection (host-byte order)<br>
 * Return value:
 * - the 32-bit Initial Sequence Number to use for the new TCP connection.
 */
#ifdef __DOXYGEN__
#define DPIP_HOOK_TCP_ISN(local_ip, local_port, remote_ip, remote_port)
#endif

/**
 * DPIP_HOOK_TCP_INPACKET_PCB:
 * Hook for intercepting incoming packets before they are passed to a pcb. This
 * allows updating some state or even dropping a packet.
 * Signature:\code{.c}
 * err_t my_hook_tcp_inpkt(struct tcp_pcb *pcb, struct tcp_hdr *hdr, u16_t optlen, u16_t opt1len, u8_t *opt2, struct rte_mbuf *p);
 * \endcode
 * Arguments:
 * - pcb: tcp_pcb selected for input of this packet (ATTENTION: this may be
 *        struct tcp_pcb_listen if pcb->state == LISTEN)
 * - hdr: pointer to tcp header (ATTENTION: tcp options may not be in one piece!)
 * - optlen: tcp option length
 * - opt1len: tcp option length 1st part
 * - opt2: if this is != NULL, tcp options are split among 2 pbufs. In that case,
 *         options start at right after the tcp header ('(u8_t*)(hdr + 1)') for
 *         the first 'opt1len' bytes and the rest starts at 'opt2'. opt2len can
 *         be simply calculated: 'opt2len = optlen - opt1len;'
 * - p: input packet, p->payload points to application data (that's why tcp hdr
 *      and options are passed in separately)
 * Return value:
 * - ERR_OK: continue input of this packet as normal
 * - != ERR_OK: drop this packet for input (don't continue input processing)
 *
 * ATTENTION: don't call any tcp api functions that might change tcp state (pcb
 * state or any pcb lists) from this callback!
 */
#ifdef __DOXYGEN__
#define DPIP_HOOK_TCP_INPACKET_PCB(pcb, hdr, optlen, opt1len, opt2, p)
#endif

/**
 * DPIP_HOOK_TCP_OUT_TCPOPT_LENGTH:
 * Hook for increasing the size of the options allocated with a tcp header.
 * Together with DPIP_HOOK_TCP_OUT_ADD_TCPOPTS, this can be used to add custom
 * options to outgoing tcp segments.
 * Signature:\code{.c}
 * u8_t my_hook_tcp_out_tcpopt_length(const struct tcp_pcb *pcb, u8_t internal_option_length);
 * \endcode
 * Arguments:
 * - pcb: tcp_pcb that transmits (ATTENTION: this may be NULL or
 *        struct tcp_pcb_listen if pcb->state == LISTEN)
 * - internal_option_length: tcp option length used by the stack internally
 * Return value:
 * - a number of bytes to allocate for tcp options (internal_option_length <= ret <= 40)
 *
 * ATTENTION: don't call any tcp api functions that might change tcp state (pcb
 * state or any pcb lists) from this callback!
 */
#ifdef __DOXYGEN__
#define DPIP_HOOK_TCP_OUT_TCPOPT_LENGTH(pcb, internal_len)
#endif

/**
 * DPIP_HOOK_TCP_OUT_ADD_TCPOPTS:
 * Hook for adding custom options to outgoing tcp segments.
 * Space for these custom options has to be reserved via DPIP_HOOK_TCP_OUT_TCPOPT_LENGTH.
 * Signature:\code{.c}
 * u32_t *my_hook_tcp_out_add_tcpopts(struct rte_mbuf *p, struct tcp_hdr *hdr, const struct tcp_pcb *pcb, u32_t *opts);
 * \endcode
 * Arguments:
 * - p: output packet, p->payload pointing to tcp header, data follows
 * - hdr: tcp header
 * - pcb: tcp_pcb that transmits (ATTENTION: this may be NULL or
 *        struct tcp_pcb_listen if pcb->state == LISTEN)
 * - opts: pointer where to add the custom options (there may already be options
 *         between the header and these)
 * Return value:
 * - pointer pointing directly after the inserted options
 *
 * ATTENTION: don't call any tcp api functions that might change tcp state (pcb
 * state or any pcb lists) from this callback!
 */
#ifdef __DOXYGEN__
#define DPIP_HOOK_TCP_OUT_ADD_TCPOPTS(p, hdr, pcb, opts)
#endif

/**
 * DPIP_HOOK_IP4_INPUT(pbuf, input_netif):
 * Called from ip_input() (IPv4)
 * Signature:\code{.c}
 *   int my_hook(struct rte_mbuf *pbuf, struct netif *input_netif);
 * \endcode
 * Arguments:
 * - pbuf: received struct rte_mbuf passed to ip_input()
 * - input_netif: struct netif on which the packet has been received
 * Return values:
 * - 0: Hook has not consumed the packet, packet is processed as normal
 * - != 0: Hook has consumed the packet.
 * If the hook consumed the packet, 'pbuf' is in the responsibility of the hook
 * (i.e. free it when done).
 */
#ifdef __DOXYGEN__
#define DPIP_HOOK_IP4_INPUT(pbuf, input_netif)
#endif

/**
 * DPIP_HOOK_IP4_ROUTE(dest):
 * Called from ip_route() (IPv4)
 * Signature:\code{.c}
 *   struct netif *my_hook(const ip4_addr_t *dest);
 * \endcode
 * Arguments:
 * - dest: destination IPv4 address
 * Returns values:
 * - the destination netif
 * - NULL if no destination netif is found. In that case, ip_route() continues as normal.
 */
#ifdef __DOXYGEN__
#define DPIP_HOOK_IP4_ROUTE()
#endif

/**
 * DPIP_HOOK_IP4_ROUTE_SRC(src, dest):
 * Source-based routing for IPv4 - called from ip_route() (IPv4)
 * Signature:\code{.c}
 *   struct netif *my_hook(const ip4_addr_t *src, const ip4_addr_t *dest);
 * \endcode
 * Arguments:
 * - src: local/source IPv4 address
 * - dest: destination IPv4 address
 * Returns values:
 * - the destination netif
 * - NULL if no destination netif is found. In that case, ip_route() continues as normal.
 */
#ifdef __DOXYGEN__
#define DPIP_HOOK_IP4_ROUTE_SRC(src, dest)
#endif

/**
 * DPIP_HOOK_IP4_CANFORWARD(src, dest):
 * Check if an IPv4 can be forwarded - called from:
 * ip4_input() -> ip4_forward() -> ip4_canforward() (IPv4)
 * - source address is available via ip4_current_src_addr()
 * - calling an output function in this context (e.g. multicast router) is allowed
 * Signature:\code{.c}
 *   int my_hook(struct rte_mbuf *p, u32_t dest_addr_hostorder);
 * \endcode
 * Arguments:
 * - p: packet to forward
 * - dest: destination IPv4 address
 * Returns values:
 * - 1: forward
 * - 0: don't forward
 * - -1: no decision. In that case, ip4_canforward() continues as normal.
 */
#ifdef __DOXYGEN__
#define DPIP_HOOK_IP4_CANFORWARD(src, dest)
#endif

/**
 * DPIP_HOOK_ETHARP_GET_GW(netif, dest):
 * Called from etharp_output() (IPv4)
 * Signature:\code{.c}
 *   const ip4_addr_t *my_hook(struct netif *netif, const ip4_addr_t *dest);
 * \endcode
 * Arguments:
 * - netif: the netif used for sending
 * - dest: the destination IPv4 address
 * Return values:
 * - the IPv4 address of the gateway to handle the specified destination IPv4 address
 * - NULL, in which case the netif's default gateway is used
 *
 * The returned address MUST be directly reachable on the specified netif!
 * This function is meant to implement advanced IPv4 routing together with
 * DPIP_HOOK_IP4_ROUTE(). The actual routing/gateway table implementation is
 * not part of dpIP but can e.g. be hidden in the netif's state argument.
*/
#ifdef __DOXYGEN__
#define DPIP_HOOK_ETHARP_GET_GW(netif, dest)
#endif

/**
 * DPIP_HOOK_IP6_INPUT(pbuf, input_netif):
 * Called from ip6_input() (IPv6)
 * Signature:\code{.c}
 *   int my_hook(struct rte_mbuf *pbuf, struct netif *input_netif);
 * \endcode
 * Arguments:
 * - pbuf: received struct rte_mbuf passed to ip6_input()
 * - input_netif: struct netif on which the packet has been received
 * Return values:
 * - 0: Hook has not consumed the packet, packet is processed as normal
 * - != 0: Hook has consumed the packet.
 * If the hook consumed the packet, 'pbuf' is in the responsibility of the hook
 * (i.e. free it when done).
 */
#ifdef __DOXYGEN__
#define DPIP_HOOK_IP6_INPUT(pbuf, input_netif)
#endif

/**
 * DPIP_HOOK_IP6_ROUTE(src, dest):
 * Called from ip_route() (IPv6)
 * Signature:\code{.c}
 *   struct netif *my_hook(const ip6_addr_t *dest, const ip6_addr_t *src);
 * \endcode
 * Arguments:
 * - src: source IPv6 address
 * - dest: destination IPv6 address
 * Return values:
 * - the destination netif
 * - NULL if no destination netif is found. In that case, ip6_route() continues as normal.
 */
#ifdef __DOXYGEN__
#define DPIP_HOOK_IP6_ROUTE(src, dest)
#endif

/**
 * DPIP_HOOK_ND6_GET_GW(netif, dest):
 * Called from nd6_get_next_hop_entry() (IPv6)
 * Signature:\code{.c}
 *   const ip6_addr_t *my_hook(struct netif *netif, const ip6_addr_t *dest);
 * \endcode
 * Arguments:
 * - netif: the netif used for sending
 * - dest: the destination IPv6 address
 * Return values:
 * - the IPv6 address of the next hop to handle the specified destination IPv6 address
 * - NULL, in which case a NDP-discovered router is used instead
 *
 * The returned address MUST be directly reachable on the specified netif!
 * This function is meant to implement advanced IPv6 routing together with
 * DPIP_HOOK_IP6_ROUTE(). The actual routing/gateway table implementation is
 * not part of dpIP but can e.g. be hidden in the netif's state argument.
*/
#ifdef __DOXYGEN__
#define DPIP_HOOK_ND6_GET_GW(netif, dest)
#endif

/**
 * DPIP_HOOK_VLAN_CHECK(netif, eth_hdr, vlan_hdr):
 * Called from ethernet_input() if VLAN support is enabled
 * Signature:\code{.c}
 *   int my_hook(struct netif *netif, struct eth_hdr *eth_hdr, struct eth_vlan_hdr *vlan_hdr);
 * \endcode
 * Arguments:
 * - netif: struct netif on which the packet has been received
 * - eth_hdr: struct eth_hdr of the packet
 * - vlan_hdr: struct eth_vlan_hdr of the packet
 * Return values:
 * - 0: Packet must be dropped.
 * - != 0: Packet must be accepted.
 */
#ifdef __DOXYGEN__
#define DPIP_HOOK_VLAN_CHECK(netif, eth_hdr, vlan_hdr)
#endif

/**
 * DPIP_HOOK_VLAN_SET:
 * Hook can be used to set prio_vid field of vlan_hdr. If you need to store data
 * on per-netif basis to implement this callback, see @ref netif_cd.
 * Called from ethernet_output() if VLAN support (@ref ETHARP_SUPPORT_VLAN) is enabled.<br>
 * Signature:\code{.c}
 *   s32_t my_hook_vlan_set(struct netif* netif, struct rte_mbuf* pbuf, const struct eth_addr* src, const struct eth_addr* dst, u16_t eth_type);
 * \endcode
 * Arguments:
 * - netif: struct netif that the packet will be sent through
 * - p: struct rte_mbuf packet to be sent
 * - src: source eth address
 * - dst: destination eth address
 * - eth_type: ethernet type to packet to be sent<br>
 *
 *
 * Return values:
 * - &lt;0: Packet shall not contain VLAN header.
 * - 0 &lt;= return value &lt;= 0xFFFF: Packet shall contain VLAN header. Return value is prio_vid in host byte order.
 */
#ifdef __DOXYGEN__
#define DPIP_HOOK_VLAN_SET(netif, p, src, dst, eth_type)
#endif

/**
 * DPIP_HOOK_MEMP_AVAILABLE(memp_t_type):
 * Called from memp_free() when a memp pool was empty and an item is now available
 * Signature:\code{.c}
 *   void my_hook(memp_t type);
 * \endcode
 */
#ifdef __DOXYGEN__
#define DPIP_HOOK_MEMP_AVAILABLE(memp_t_type)
#endif

/**
 * DPIP_HOOK_UNKNOWN_ETH_PROTOCOL(pbuf, netif):
 * Called from ethernet_input() when an unknown eth type is encountered.
 * Signature:\code{.c}
 *   err_t my_hook(struct rte_mbuf* pbuf, struct netif* netif);
 * \endcode
 * Arguments:
 * - p: rx packet with unknown eth type
 * - netif: netif on which the packet has been received
 * Return values:
 * - ERR_OK if packet is accepted (hook function now owns the pbuf)
 * - any error code otherwise (pbuf is freed)
 *
 * Payload points to ethernet header!
 */
#ifdef __DOXYGEN__
#define DPIP_HOOK_UNKNOWN_ETH_PROTOCOL(pbuf, netif)
#endif

/*
   ---------------------------------------
   ---------- Debugging options ----------
   ---------------------------------------
*/
/**
 * @defgroup dpip_opts_debugmsg Debug messages
 * @ingroup dpip_opts_debug
 * @{
 */
/**
 * DPIP_DBG_MIN_LEVEL: After masking, the value of the debug is
 * compared against this value. If it is smaller, then debugging
 * messages are written.
 * @see debugging_levels
 */
#if !defined DPIP_DBG_MIN_LEVEL || defined __DOXYGEN__
#define DPIP_DBG_MIN_LEVEL              DPIP_DBG_LEVEL_ALL
#endif

/**
 * DPIP_DBG_TYPES_ON: A mask that can be used to globally enable/disable
 * debug messages of certain types.
 * @see debugging_levels
 */
#if !defined DPIP_DBG_TYPES_ON || defined __DOXYGEN__
#define DPIP_DBG_TYPES_ON         (DPIP_DBG_ON|DPIP_DBG_TRACE|DPIP_DBG_STATE|DPIP_DBG_FRESH|DPIP_DBG_HALT)
#endif

/**
 * ETHARP_DEBUG: Enable debugging in etharp.c.
 */
#if !defined ETHARP_DEBUG || defined __DOXYGEN__
#define ETHARP_DEBUG                    DPIP_DBG_OFF
#endif

/**
 * NETIF_DEBUG: Enable debugging in netif.c.
 */
#if !defined NETIF_DEBUG || defined __DOXYGEN__
#define NETIF_DEBUG                     DPIP_DBG_ON
#endif

/**
 * PBUF_DEBUG: Enable debugging in pbuf.c.
 */
#if !defined PBUF_DEBUG || defined __DOXYGEN__
#define PBUF_DEBUG                      DPIP_DBG_ON
#endif

/**
 * API_LIB_DEBUG: Enable debugging in api_lib.c.
 */
#if !defined API_LIB_DEBUG || defined __DOXYGEN__
#define API_LIB_DEBUG                   DPIP_DBG_ON
#endif

/**
 * API_MSG_DEBUG: Enable debugging in api_msg.c.
 */
#if !defined API_MSG_DEBUG || defined __DOXYGEN__
#define API_MSG_DEBUG                   DPIP_DBG_ON
#endif

/**
 * SOCKETS_DEBUG: Enable debugging in sockets.c.
 */
#if !defined SOCKETS_DEBUG || defined __DOXYGEN__
#define SOCKETS_DEBUG                   DPIP_DBG_ON
#endif

/**
 * ICMP_DEBUG: Enable debugging in icmp.c.
 */
#if !defined ICMP_DEBUG || defined __DOXYGEN__
#define ICMP_DEBUG                      DPIP_DBG_ON
#endif

/**
 * IGMP_DEBUG: Enable debugging in igmp.c.
 */
#if !defined IGMP_DEBUG || defined __DOXYGEN__
#define IGMP_DEBUG                      DPIP_DBG_ON
#endif

/**
 * INET_DEBUG: Enable debugging in inet.c.
 */
#if !defined INET_DEBUG || defined __DOXYGEN__
#define INET_DEBUG                      DPIP_DBG_OFF
#endif

/**
 * IP_DEBUG: Enable debugging for IP.
 */
#if !defined IP_DEBUG || defined __DOXYGEN__
#define IP_DEBUG                        DPIP_DBG_ON
#endif

/**
 * IP_REASS_DEBUG: Enable debugging in ip_frag.c for both frag & reass.
 */
#if !defined IP_REASS_DEBUG || defined __DOXYGEN__
#define IP_REASS_DEBUG                  DPIP_DBG_OFF
#endif

/**
 * RAW_DEBUG: Enable debugging in raw.c.
 */
#if !defined RAW_DEBUG || defined __DOXYGEN__
#define RAW_DEBUG                       DPIP_DBG_OFF
#endif

/**
 * MEM_DEBUG: Enable debugging in mem.c.
 */
#if !defined MEM_DEBUG || defined __DOXYGEN__
#define MEM_DEBUG                       DPIP_DBG_ON
#endif

/**
 * MEMP_DEBUG: Enable debugging in memp.c.
 */
#if !defined MEMP_DEBUG || defined __DOXYGEN__
#define MEMP_DEBUG                      DPIP_DBG_ON
#endif

/**
 * SYS_DEBUG: Enable debugging in sys.c.
 */
#if !defined SYS_DEBUG || defined __DOXYGEN__
#define SYS_DEBUG                       DPIP_DBG_ON
#endif

/**
 * TIMERS_DEBUG: Enable debugging in timers.c.
 */
#if !defined TIMERS_DEBUG || defined __DOXYGEN__
#define TIMERS_DEBUG                    DPIP_DBG_ON
#endif

/**
 * TCP_DEBUG: Enable debugging for TCP.
 */
#if !defined TCP_DEBUG || defined __DOXYGEN__
#define TCP_DEBUG                       DPIP_DBG_ON
#endif

/**
 * TCP_INPUT_DEBUG: Enable debugging in tcp_in.c for incoming debug.
 */
#if !defined TCP_INPUT_DEBUG || defined __DOXYGEN__
#define TCP_INPUT_DEBUG                 DPIP_DBG_ON
#endif

/**
 * TCP_FR_DEBUG: Enable debugging in tcp_in.c for fast retransmit.
 */
#if !defined TCP_FR_DEBUG || defined __DOXYGEN__
#define TCP_FR_DEBUG                    DPIP_DBG_ON
#endif

/**
 * TCP_RTO_DEBUG: Enable debugging in TCP for retransmit
 * timeout.
 */
#if !defined TCP_RTO_DEBUG || defined __DOXYGEN__
#define TCP_RTO_DEBUG                   DPIP_DBG_ON
#endif

/**
 * TCP_CWND_DEBUG: Enable debugging for TCP congestion window.
 */
#if !defined TCP_CWND_DEBUG || defined __DOXYGEN__
#define TCP_CWND_DEBUG                  DPIP_DBG_ON
#endif

/**
 * TCP_WND_DEBUG: Enable debugging in tcp_in.c for window updating.
 */
#if !defined TCP_WND_DEBUG || defined __DOXYGEN__
#define TCP_WND_DEBUG                   DPIP_DBG_ON
#endif

/**
 * TCP_OUTPUT_DEBUG: Enable debugging in tcp_out.c output functions.
 */
#if !defined TCP_OUTPUT_DEBUG || defined __DOXYGEN__
#define TCP_OUTPUT_DEBUG                DPIP_DBG_ON
#endif

/**
 * TCP_RST_DEBUG: Enable debugging for TCP with the RST message.
 */
#if !defined TCP_RST_DEBUG || defined __DOXYGEN__
#define TCP_RST_DEBUG                   DPIP_DBG_ON
#endif

/**
 * TCP_QLEN_DEBUG: Enable debugging for TCP queue lengths.
 */
#if !defined TCP_QLEN_DEBUG || defined __DOXYGEN__
#define TCP_QLEN_DEBUG                  DPIP_DBG_ON
#endif

/**
 * UDP_DEBUG: Enable debugging in UDP.
 */
#if !defined UDP_DEBUG || defined __DOXYGEN__
#define UDP_DEBUG                       DPIP_DBG_ON
#endif

/**
 * TCPIP_DEBUG: Enable debugging in tcpip.c.
 */
#if !defined TCPIP_DEBUG || defined __DOXYGEN__
#define TCPIP_DEBUG                     DPIP_DBG_ON
#endif

/**
 * SLIP_DEBUG: Enable debugging in slipif.c.
 */
#if !defined SLIP_DEBUG || defined __DOXYGEN__
#define SLIP_DEBUG                      DPIP_DBG_OFF
#endif

/**
 * DHCP_DEBUG: Enable debugging in dhcp.c.
 */
#if !defined DHCP_DEBUG || defined __DOXYGEN__
#define DHCP_DEBUG                      DPIP_DBG_ON
#endif

/**
 * AUTOIP_DEBUG: Enable debugging in autoip.c.
 */
#if !defined AUTOIP_DEBUG || defined __DOXYGEN__
#define AUTOIP_DEBUG                    DPIP_DBG_ON
#endif

/**
 * ACD_DEBUG: Enable debugging in acd.c.
 */
#if !defined ACD_DEBUG || defined __DOXYGEN__
#define ACD_DEBUG                       DPIP_DBG_OFF
#endif

/**
 * DNS_DEBUG: Enable debugging for DNS.
 */
#if !defined DNS_DEBUG || defined __DOXYGEN__
#define DNS_DEBUG                       DPIP_DBG_ON
#endif

/**
 * IP6_DEBUG: Enable debugging for IPv6.
 */
#if !defined IP6_DEBUG || defined __DOXYGEN__
#define IP6_DEBUG                       DPIP_DBG_OFF
#endif

/**
 * DHCP6_DEBUG: Enable debugging in dhcp6.c.
 */
#if !defined DHCP6_DEBUG || defined __DOXYGEN__
#define DHCP6_DEBUG                     DPIP_DBG_OFF
#endif
/**
 * @}
 */

/* added for the benchmark app  */
#define DPIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1

#endif /* DPIP_HDR_OPT_H */
