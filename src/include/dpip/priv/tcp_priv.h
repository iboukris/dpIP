/**
 * @file
 * TCP internal implementations (do not use in application code)
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
#ifndef DPIP_HDR_TCP_PRIV_H
#define DPIP_HDR_TCP_PRIV_H

#include <sys/queue.h>

#include "dpip/opt.h"

#if DPIP_TCP			/* don't build if not configured for use in opts.h */

#include "dpip/tcp.h"
#include "dpip/pbuf.h"
#include "dpip/ip.h"
#include "dpip/icmp.h"
#include "dpip/err.h"
#include "dpip/ip6.h"
#include "dpip/ip6_addr.h"
#include "dpip/prot/tcp.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Functions for interfacing with TCP: */

/* Lower layer interface to TCP: */
void tcp_init(void);		/* Initialize this module. */
void tcp_tmr(void);		/* Must be called every
				   TCP_TMR_INTERVAL
				   ms. (Typically 250 ms). */
/* It is also possible to call these two functions at the right
   intervals (instead of calling tcp_tmr()). */
void tcp_slowtmr(void);
void tcp_fasttmr(void);

/* Call this from a netif driver (watch out for threading issues!) that has
   returned a memory error on transmit and now has free buffers to send more.
   This iterates all active pcbs that had an error and tries to call
   tcp_output, so use this with care as it might slow down the system. */
void tcp_txnow(void);

/* Only used by IP to pass a TCP segment to TCP: */
void tcp_input(struct rte_mbuf *p, struct netif *inp,
	       struct ip_data *ip_data_p);
/* Used within the TCP code only: */
struct tcp_pcb *tcp_alloc(u8_t prio);
void tcp_free(struct tcp_pcb *pcb);
void tcp_abandon(struct tcp_pcb *pcb, int reset);
err_t tcp_send_empty_ack(struct tcp_pcb *pcb);
err_t tcp_rexmit(struct tcp_pcb *pcb);
err_t tcp_rexmit_rto_prepare(struct tcp_pcb *pcb);
void tcp_rexmit_rto_commit(struct tcp_pcb *pcb);
void tcp_rexmit_rto(struct tcp_pcb *pcb);
void tcp_rexmit_fast(struct tcp_pcb *pcb);
u32_t tcp_update_rcv_ann_wnd(struct tcp_pcb *pcb);

/**
 * This is the Nagle algorithm: try to combine user data to send as few TCP
 * segments as possible. Only send if
 * - no previously transmitted data on the connection remains unacknowledged or
 * - the TF_NODELAY flag is set (nagle algorithm turned off for this pcb) or
 * - the only unsent segment is at least pcb->mss bytes long (or there is more
 *   than one unsent segment - with dpIP, this can happen although unsent->len < mss)
 * - or if we are in fast-retransmit (TF_INFR)
 */
#define tcp_do_output_nagle(tpcb) ((((tpcb)->unacked == NULL) || \
                            ((tpcb)->flags & (TF_NODELAY | TF_INFR)) || \
                            (((tpcb)->unsent != NULL) && (((tpcb)->unsent->next != NULL) || \
                              ((tpcb)->unsent->len >= (tpcb)->mss))) || \
                            ((tcp_sndbuf(tpcb) == 0) || (tcp_sndqueuelen(tpcb) >= TCP_SND_QUEUELEN)) \
                            ) ? 1 : 0)
#define tcp_output_nagle(tpcb) (tcp_do_output_nagle(tpcb) ? tcp_output(tpcb) : ERR_OK)

#define TCP_SEQ_LT(a,b)     (((u32_t)((u32_t)(a) - (u32_t)(b)) & 0x80000000u) != 0)
#define TCP_SEQ_LEQ(a,b)    (!(TCP_SEQ_LT(b,a)))
#define TCP_SEQ_GT(a,b)     TCP_SEQ_LT(b,a)
#define TCP_SEQ_GEQ(a,b)    TCP_SEQ_LEQ(b,a)
/* is b<=a<=c? */
#define TCP_SEQ_BETWEEN(a,b,c) (TCP_SEQ_GEQ(a,b) && TCP_SEQ_LEQ(a,c))

#ifndef TCP_TMR_INTERVAL
#define TCP_TMR_INTERVAL       250	/* The TCP timer interval in milliseconds. */
#endif				/* TCP_TMR_INTERVAL */

#ifndef TCP_FAST_INTERVAL
#define TCP_FAST_INTERVAL      TCP_TMR_INTERVAL	/* the fine grained timeout in milliseconds */
#endif				/* TCP_FAST_INTERVAL */

#ifndef TCP_SLOW_INTERVAL
#define TCP_SLOW_INTERVAL      (2*TCP_TMR_INTERVAL)	/* the coarse grained timeout in milliseconds */
#endif				/* TCP_SLOW_INTERVAL */

#define TCP_FIN_WAIT_TIMEOUT 20000	/* milliseconds */
#define TCP_SYN_RCVD_TIMEOUT 20000	/* milliseconds */

#define TCP_OOSEQ_TIMEOUT        6U	/* x RTO */

#ifndef TCP_MSL
#define TCP_MSL 60000UL		/* The maximum segment lifetime in milliseconds */
#endif

/* Keepalive values, compliant with RFC 1122. Don't change this unless you know what you're doing */
#ifndef  TCP_KEEPIDLE_DEFAULT
#define  TCP_KEEPIDLE_DEFAULT     7200000UL	/* Default KEEPALIVE timer in milliseconds */
#endif

#ifndef  TCP_KEEPINTVL_DEFAULT
#define  TCP_KEEPINTVL_DEFAULT    75000UL	/* Default Time between KEEPALIVE probes in milliseconds */
#endif

#ifndef  TCP_KEEPCNT_DEFAULT
#define  TCP_KEEPCNT_DEFAULT      9U	/* Default Counter for KEEPALIVE probes */
#endif

#define  TCP_MAXIDLE              TCP_KEEPCNT_DEFAULT * TCP_KEEPINTVL_DEFAULT	/* Maximum KEEPALIVE probe time */

#define TCP_TCPLEN(seg) ((seg)->len + (((TCPH_FLAGS((seg)->tcphdr) & (TCP_FIN | TCP_SYN)) != 0) ? 1U : 0U))

/** Flags used on input processing, not on pcb->flags
*/
#define TF_INPUT     (u8_t)0x04U	/* Connection in input processing. */
#define TF_RESET     (u8_t)0x08U	/* Connection was reset. */
#define TF_CLOSED    (u8_t)0x10U	/* Connection was successfully closed. */
#define TF_GOT_FIN   (u8_t)0x20U	/* Connection was closed by the remote end. */

#define TCP_EVENT_ACCEPT(pcb,err,ret)                 \
  do {                                                         \
    if((pcb)->accept != NULL)                                 \
      (ret) = (pcb)->accept((pcb)->callback_arg,(pcb),(err));               \
    else (ret) = ERR_ARG;                                      \
  } while (0)

#define TCP_EVENT_SENT(pcb,space,ret)                          \
  do {                                                         \
    if((pcb)->sent != NULL)                                    \
      (ret) = (pcb)->sent((pcb)->callback_arg,(pcb),(space));  \
    else (ret) = ERR_OK;                                       \
  } while (0)

#define TCP_EVENT_RECV(pcb,p,err,ret)                          \
  do {                                                         \
    if((pcb)->recv != NULL) {                                  \
      (ret) = (pcb)->recv((pcb)->callback_arg,(pcb),(p),(err));\
    } else {                                                   \
      (ret) = tcp_recv_null(NULL, (pcb), (p), (err));          \
    }                                                          \
  } while (0)

#define TCP_EVENT_CLOSED(pcb,ret)                                \
  do {                                                           \
    if(((pcb)->recv != NULL)) {                                  \
      (ret) = (pcb)->recv((pcb)->callback_arg,(pcb),NULL,ERR_OK);\
    } else {                                                     \
      (ret) = ERR_OK;                                            \
    }                                                            \
  } while (0)

#define TCP_EVENT_CONNECTED(pcb,err,ret)                         \
  do {                                                           \
    if((pcb)->connected != NULL)                                 \
      (ret) = (pcb)->connected((pcb)->callback_arg,(pcb),(err)); \
    else (ret) = ERR_OK;                                         \
  } while (0)

#define TCP_EVENT_POLL(pcb,ret)                                \
  do {                                                         \
    if((pcb)->poll != NULL)                                    \
      (ret) = (pcb)->poll((pcb)->callback_arg,(pcb));          \
    else (ret) = ERR_OK;                                       \
  } while (0)

#define TCP_EVENT_ERR(last_state,errf,arg,err)                 \
  do {                                                         \
    DPIP_UNUSED_ARG(last_state);                               \
    if((errf) != NULL)                                         \
      (errf)((arg),(err));                                     \
  } while (0)

/** Don't generate checksum on copy if CHECKSUM_GEN_TCP is disabled */
#define TCP_CHECKSUM_ON_COPY  (0 && CHECKSUM_GEN_TCP)

/* This structure represents a TCP segment on the unsent, unacked and ooseq queues */
struct tcp_seg {
	struct tcp_seg *next;	/* used when putting segments on a queue */
	struct rte_mbuf *p;	/* buffer containing data + TCP header */
	u16_t len;		/* the TCP length of this segment */
	u8_t flags;
#define TF_SEG_OPTS_MSS         (u8_t)0x01U	/* Include MSS option (only used in SYN segments) */
#define TF_SEG_OPTS_TS          (u8_t)0x02U	/* Include timestamp option. */
#define TF_SEG_OPTS_WND_SCALE   (u8_t)0x08U	/* Include WND SCALE option (only used in SYN segments) */
#define TF_SEG_OPTS_SACK_PERM   (u8_t)0x10U	/* Include SACK Permitted option (only used in SYN segments) */
	struct tcp_hdr *tcphdr;	/* the TCP header */
};

#define DPIP_TCP_OPT_EOL        0
#define DPIP_TCP_OPT_NOP        1
#define DPIP_TCP_OPT_MSS        2
#define DPIP_TCP_OPT_WS         3
#define DPIP_TCP_OPT_SACK_PERM  4
#define DPIP_TCP_OPT_TS         8

#define DPIP_TCP_OPT_LEN_MSS    4
#if DPIP_TCP_TIMESTAMPS
#define DPIP_TCP_OPT_LEN_TS     10
#define DPIP_TCP_OPT_LEN_TS_OUT 12	/* aligned for output (includes NOP padding) */
#else
#define DPIP_TCP_OPT_LEN_TS_OUT 0
#endif
#if DPIP_WND_SCALE
#define DPIP_TCP_OPT_LEN_WS     3
#define DPIP_TCP_OPT_LEN_WS_OUT 4	/* aligned for output (includes NOP padding) */
#else
#define DPIP_TCP_OPT_LEN_WS_OUT 0
#endif

#if DPIP_TCP_SACK_OUT
#define DPIP_TCP_OPT_LEN_SACK_PERM     2
#define DPIP_TCP_OPT_LEN_SACK_PERM_OUT 4	/* aligned for output (includes NOP padding) */
#else
#define DPIP_TCP_OPT_LEN_SACK_PERM_OUT 0
#endif

#define DPIP_TCP_OPT_LENGTH(flags) \
  ((flags) & TF_SEG_OPTS_MSS       ? DPIP_TCP_OPT_LEN_MSS           : 0) + \
  ((flags) & TF_SEG_OPTS_TS        ? DPIP_TCP_OPT_LEN_TS_OUT        : 0) + \
  ((flags) & TF_SEG_OPTS_WND_SCALE ? DPIP_TCP_OPT_LEN_WS_OUT        : 0) + \
  ((flags) & TF_SEG_OPTS_SACK_PERM ? DPIP_TCP_OPT_LEN_SACK_PERM_OUT : 0)

/** This returns a TCP header option for MSS in an u32_t */
#define TCP_BUILD_MSS_OPTION(mss) dpip_htonl(0x02040000 | ((mss) & 0xFFFF))

#if DPIP_WND_SCALE
#define TCPWNDSIZE_F       U32_F
#define TCPWND_MAX         0xFFFFFFFFU
#define TCPWND_CHECK16(x)  DPIP_ASSERT("window size > 0xFFFF", (x) <= 0xFFFF)
#define TCPWND_MIN16(x)    ((u16_t)RTE_MIN((x), 0xFFFF))
#else				/* DPIP_WND_SCALE */
#define TCPWNDSIZE_F       U16_F
#define TCPWND_MAX         0xFFFFU
#define TCPWND_CHECK16(x)
#define TCPWND_MIN16(x)    x
#endif				/* DPIP_WND_SCALE */

/* Global variables: */
extern u32_t tcp_ticks;
extern u8_t tcp_active_pcbs_changed;

/* The TCP PCB lists. */
 TAILQ_HEAD(tcp_pcb_list, tcp_pcb);
typedef struct tcp_pcb_list *tcp_pcb_list_t;

extern struct tcp_pcb_list tcp_listen_pcbs;
extern struct tcp_pcb_list tcp_active_pcbs;
extern struct tcp_pcb_list tcp_tw_pcbs;

enum pcb_list_type {
/** List of all TCP PCBs in LISTEN state */
	PCB_LIST_LISTEN,
/** List of all TCP PCBs bound but not yet (connected || listening) */
	PCB_LIST_BOUND,
/** List of all TCP PCBs that are in a state in which they accept or send data. */
	PCB_LIST_ACTIVE,
/** List of all TCP PCBs in TIME-WAIT state */
	PCB_LIST_TW,
/** Sum of all TCP PCBs lists */
	PCB_LIST_SUM
};

#define NUM_TCP_PCB_LISTS_NO_TIME_WAIT  3

/* Axioms about the above lists:
   1) Every TCP PCB that is not CLOSED is in one of the lists.
   2) A PCB is only in one of the lists.
   3) All PCBs in the tcp_listen_pcbs list is in LISTEN state.
   4) All PCBs in the tcp_tw_pcbs list is in TIME-WAIT state.
*/
/* Define two macros, TCP_REG and TCP_RMV that registers a TCP PCB
   with a PCB list or removes a PCB from a list, respectively. */

#define TCP_REG(pcbs, npcb) TAILQ_INSERT_TAIL(pcbs, npcb, next)

#define TCP_RMV(pcbs, npcb) TAILQ_REMOVE(pcbs, npcb, next)

#define TCP_REG_ACTIVE(npcb)                       \
  do {                                             \
    TCP_REG(&tcp_active_pcbs, npcb);               \
    tcp_active_pcbs_changed = 1;                   \
  } while (0)

#define TCP_RMV_ACTIVE(npcb)                       \
  do {                                             \
    TCP_RMV(&tcp_active_pcbs, npcb);               \
    tcp_active_pcbs_changed = 1;                   \
  } while (0)

#define TCP_PCB_REMOVE_ACTIVE(pcb)                 \
  do {                                             \
    tcp_pcb_remove(&tcp_active_pcbs, pcb);         \
    tcp_active_pcbs_changed = 1;                   \
  } while (0)

/* Internal functions: */
struct tcp_pcb *tcp_pcb_copy(struct tcp_pcb *pcb);
void tcp_pcb_purge(struct tcp_pcb *pcb);
void tcp_pcb_remove(tcp_pcb_list_t pcblist, struct tcp_pcb *pcb);

void tcp_segs_free(struct tcp_seg *seg);
void tcp_seg_free(struct tcp_seg *seg);
struct tcp_seg *tcp_seg_copy(struct tcp_seg *seg);

#define tcp_ack(pcb)                               \
  do {                                             \
    if((pcb)->flags & TF_ACK_DELAY) {              \
      tcp_clear_flags(pcb, TF_ACK_DELAY);          \
      tcp_ack_now(pcb);                            \
    }                                              \
    else {                                         \
      tcp_set_flags(pcb, TF_ACK_DELAY);            \
    }                                              \
  } while (0)

#define tcp_ack_now(pcb)                           \
  tcp_set_flags(pcb, TF_ACK_NOW)

err_t tcp_send_fin(struct tcp_pcb *pcb);
err_t tcp_enqueue_flags(struct tcp_pcb *pcb, u8_t flags);

void tcp_rexmit_seg(struct tcp_pcb *pcb, struct tcp_seg *seg);

void tcp_rst(const struct tcp_pcb *pcb, u32_t seqno, u32_t ackno,
	     const ip_addr_t * local_ip, const ip_addr_t * remote_ip,
	     u16_t local_port, u16_t remote_port);
void tcp_rst_netif(struct netif *netif, u32_t seqno, u32_t ackno,
		   const ip_addr_t * local_ip, const ip_addr_t * remote_ip,
		   u16_t local_port, u16_t remote_port);

u32_t tcp_next_iss(struct tcp_pcb *pcb);

err_t tcp_keepalive(struct tcp_pcb *pcb);
err_t tcp_split_unsent_seg(struct tcp_pcb *pcb, u16_t split);
err_t tcp_zero_window_probe(struct tcp_pcb *pcb);
void tcp_trigger_input_pcb_close(struct tcp_pcb *pcb);

#if TCP_CALCULATE_EFF_SEND_MSS
u16_t tcp_eff_send_mss_netif(u16_t sendmss, struct netif *outif,
			     const ip_addr_t * dest);
#define tcp_eff_send_mss(sendmss, src, dest) \
    tcp_eff_send_mss_netif(sendmss, ip_route(src, dest), dest)
#endif				/* TCP_CALCULATE_EFF_SEND_MSS */

err_t tcp_recv_null(void *arg, struct tcp_pcb *pcb, struct rte_mbuf *p,
		    err_t err);

#if TCP_DEBUG || TCP_INPUT_DEBUG || TCP_OUTPUT_DEBUG
void tcp_debug_print(struct tcp_hdr *tcphdr);
void tcp_debug_print_flags(u8_t flags);
void tcp_debug_print_state(enum tcp_state s);
void tcp_debug_print_pcbs(void);
s16_t tcp_pcbs_sane(void);
#else
#define tcp_debug_print(tcphdr)
#define tcp_debug_print_flags(flags)
#define tcp_debug_print_state(s)
#define tcp_debug_print_pcbs()
#define tcp_pcbs_sane() 1
#endif				/* TCP_DEBUG */

void tcp_netif_ip_addr_changed(const ip_addr_t * old_addr,
			       const ip_addr_t * new_addr);

#if TCP_QUEUE_OOSEQ
void tcp_free_ooseq(struct tcp_pcb *pcb);
#endif

#ifdef __cplusplus
}
#endif
#endif				/* DPIP_TCP */
#endif				/* DPIP_HDR_TCP_PRIV_H */
