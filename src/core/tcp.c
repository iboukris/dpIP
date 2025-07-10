/**
 * @file
 * Transmission Control Protocol for IP
 * See also @ref tcp_raw
 *
 * @defgroup tcp_raw TCP
 * @ingroup callbackstyle_api
 * Transmission Control Protocol for IP<br>
 * @see @ref api
 *
 * Common functions for the TCP implementation, such as functions
 * for manipulating the data structures and the TCP timer functions. TCP functions
 * related to input and output is found in tcp_in.c and tcp_out.c respectively.<br>
 *
 * TCP connection setup
 * --------------------
 * The functions used for setting up connections is similar to that of
 * the sequential API and of the BSD socket API. A new TCP connection
 * identifier (i.e., a protocol control block - PCB) is created with the
 * tcp_new() function. This PCB can then be either set to listen for new
 * incoming connections or be explicitly connected to another host.
 * - tcp_new()
 * - tcp_bind()
 * - tcp_listen()
 * - tcp_accept()
 * - tcp_connect()
 *
 * Sending TCP data
 * ----------------
 * TCP data is sent by enqueueing the data with a call to tcp_write() and
 * triggering to send by calling tcp_output(). When the data is successfully
 * transmitted to the remote host, the application will be notified with a
 * call to a specified callback function.
 * - tcp_write()
 * - tcp_output()
 * - tcp_sent()
 *
 * Receiving TCP data
 * ------------------
 * TCP data reception is callback based - an application specified
 * callback function is called when new data arrives. When the
 * application has taken the data, it has to call the tcp_recved()
 * function to indicate that TCP can advertise increase the receive
 * window.
 * - tcp_recv()
 * - tcp_recved()
 *
 * Application polling
 * -------------------
 * When a connection is idle (i.e., no data is either transmitted or
 * received), dpIP will repeatedly poll the application by calling a
 * specified callback function. This can be used either as a watchdog
 * timer for killing connections that have stayed idle for too long, or
 * as a method of waiting for memory to become available. For instance,
 * if a call to tcp_write() has failed because memory wasn't available,
 * the application may use the polling functionality to call tcp_write()
 * again when the connection has been idle for a while.
 * - tcp_poll()
 *
 * Closing and aborting connections
 * --------------------------------
 * - tcp_close()
 * - tcp_abort()
 * - tcp_err()
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
 *
 */

#include "dpip/opt.h"

#if DPIP_TCP			/* don't build if not configured for use in opts.h */

#include "dpip/def.h"
#include "dpip/memp.h"
#include "dpip/tcp.h"
#include "dpip/priv/tcp_priv.h"
#include "dpip/debug.h"
#include "dpip/stats.h"
#include "dpip/ip6.h"
#include "dpip/ip6_addr.h"
#include "dpip/nd6.h"

#include <string.h>

#ifndef TCP_LOCAL_PORT_RANGE_START
/* From http://www.iana.org/assignments/port-numbers:
   "The Dynamic and/or Private Ports are those from 49152 through 65535" */
#define TCP_LOCAL_PORT_RANGE_START        0xc000
#define TCP_LOCAL_PORT_RANGE_END          0xffff
#define TCP_ENSURE_LOCAL_PORT_RANGE(port) ((u16_t)(((port) & (u16_t)~TCP_LOCAL_PORT_RANGE_START) + TCP_LOCAL_PORT_RANGE_START))
#endif

#if DPIP_TCP_KEEPALIVE
#define TCP_KEEP_DUR(pcb)   ((pcb)->keep_cnt * (pcb)->keep_intvl)
#define TCP_KEEP_INTVL(pcb) ((pcb)->keep_intvl)
#else /* DPIP_TCP_KEEPALIVE */
#define TCP_KEEP_DUR(pcb)   TCP_MAXIDLE
#define TCP_KEEP_INTVL(pcb) TCP_KEEPINTVL_DEFAULT
#endif /* DPIP_TCP_KEEPALIVE */

/* As initial send MSS, we use TCP_MSS but limit it to 536. */
#if TCP_MSS > 536
#define INITIAL_MSS 536
#else
#define INITIAL_MSS TCP_MSS
#endif

static const char *const tcp_state_str[] = {
	"CLOSED",
	"LISTEN",
	"SYN_SENT",
	"SYN_RCVD",
	"ESTABLISHED",
	"FIN_WAIT_1",
	"FIN_WAIT_2",
	"CLOSE_WAIT",
	"CLOSING",
	"LAST_ACK",
	"TIME_WAIT"
};

/* last local TCP port */
static u16_t tcp_port = TCP_LOCAL_PORT_RANGE_START;

/* Incremented every coarse grained timer shot (typically every 500 ms). */
u32_t tcp_ticks;
static const u8_t tcp_backoff[13] = { 1, 2, 3, 4, 5, 6, 7, 7, 7, 7, 7, 7, 7 };

/* Times per slowtmr hits */
static const u8_t tcp_persist_backoff[7] = { 3, 6, 12, 24, 48, 96, 120 };

/** List of all TCP PCBs bound but not yet (connected || listening) */
static struct tcp_pcb_list tcp_bound_pcbs;
/** List of all TCP PCBs in LISTEN state */
struct tcp_pcb_list tcp_listen_pcbs;
/** List of all TCP PCBs that are in a state in which they accept or send data. */
struct tcp_pcb_list tcp_active_pcbs;
/** List of all TCP PCBs in TIME-WAIT state */
struct tcp_pcb_list tcp_tw_pcbs;

/** An array with all (non-temporary) PCB lists */
static tcp_pcb_list_t tcp_pcb_lists[PCB_LIST_SUM] = {
	&tcp_listen_pcbs,
	&tcp_bound_pcbs,
	&tcp_active_pcbs,
	&tcp_tw_pcbs
};

u8_t tcp_active_pcbs_changed;

/** Timer counter to handle calling slow-timer from tcp_tmr() */
static u8_t tcp_timer;
static u8_t tcp_timer_ctr;
static u16_t tcp_new_port(void);

static err_t tcp_close_shutdown_fin(struct tcp_pcb *pcb);

/**
 * Initialize this module.
 */
void tcp_init(void)
{
	TAILQ_INIT(&tcp_bound_pcbs);
	TAILQ_INIT(&tcp_listen_pcbs);
	TAILQ_INIT(&tcp_active_pcbs);
	TAILQ_INIT(&tcp_tw_pcbs);
#ifdef DPIP_RAND
	tcp_port = TCP_ENSURE_LOCAL_PORT_RANGE(DPIP_RAND());
#endif /* DPIP_RAND */
}

/** Free a tcp pcb */
void tcp_free(struct tcp_pcb *pcb)
{
	DPIP_ASSERT("tcp_free: LISTEN", pcb->state != LISTEN);
	memp_free(MEMP_TCP_PCB, pcb);
}

/**
 * Called periodically to dispatch TCP timers.
 */
void tcp_tmr(void)
{
	/* Call tcp_fasttmr() every 250 ms */
	tcp_fasttmr();

	if (++tcp_timer & 1) {
		/* Call tcp_slowtmr() every 500 ms, i.e., every other timer
		   tcp_tmr() is called. */
		tcp_slowtmr();
	}
}

/** Called when a listen pcb is closed. **/
static void tcp_listen_closed(struct tcp_pcb *pcb)
{
	DPIP_UNUSED_ARG(pcb);
}

/**
 * Closes the TX side of a connection held by the PCB.
 * For tcp_close(), a RST is sent if the application didn't receive all data
 * (tcp_recved() not called for all data passed to recv callback).
 *
 * Listening pcbs are freed and may not be referenced any more.
 * Connection pcbs are freed if not yet connected and may not be referenced
 * any more. If a connection is established (at least SYN received or in
 * a closing state), the connection is closed, and put in a closing state.
 * The pcb is then automatically freed in tcp_slowtmr(). It is therefore
 * unsafe to reference it.
 *
 * @param pcb the tcp_pcb to close
 * @return ERR_OK if connection has been closed
 *         another err_t if closing failed and pcb is not freed
 */
static err_t tcp_close_shutdown(struct tcp_pcb *pcb, u8_t rst_on_unacked_data)
{
	DPIP_ASSERT("tcp_close_shutdown: invalid pcb", pcb != NULL);

	if (rst_on_unacked_data
	    && ((pcb->state == ESTABLISHED) || (pcb->state == CLOSE_WAIT))) {
		if (pcb->rcv_wnd != TCP_WND_MAX(pcb)) {
			/* Not all data received by application, send RST to tell the remote
			   side about this. */
			DPIP_ASSERT("pcb->flags & TF_RXCLOSED",
				    pcb->flags & TF_RXCLOSED);

			/* don't call tcp_abort here: we must not deallocate the pcb since
			   that might not be expected when calling tcp_close */
			tcp_rst(pcb, pcb->snd_nxt, pcb->rcv_nxt, &pcb->local_ip,
				&pcb->remote_ip, pcb->local_port,
				pcb->remote_port);

			tcp_pcb_purge(pcb);
			TCP_RMV_ACTIVE(pcb);
			/* Deallocate the pcb since we already sent a RST for it */
			if (pcb->recv_flags & TF_INPUT) {
				/* prevent using a deallocated pcb: free it from tcp_input later */
				tcp_trigger_input_pcb_close(pcb);
			} else {
				tcp_free(pcb);
			}
			return ERR_OK;
		}
	}

	/* - states which free the pcb are handled here,
	   - states which send FIN and change state are handled in tcp_close_shutdown_fin() */
	switch (pcb->state) {
	case CLOSED:
		/* Closing a pcb in the CLOSED state might seem erroneous,
		 * however, it is in this state once allocated and as yet unused
		 * and the user needs some way to free it should the need arise.
		 * Calling tcp_close() with a pcb that has already been closed, (i.e. twice)
		 * or for a pcb that has been used and then entered the CLOSED state
		 * is erroneous, but this should never happen as the pcb has in those cases
		 * been freed, and so any remaining handles are bogus. */
		if (pcb->local_port != 0) {
			TCP_RMV(&tcp_bound_pcbs, pcb);
		}
		tcp_free(pcb);
		break;
	case LISTEN:
		tcp_listen_closed(pcb);
		tcp_pcb_remove(&tcp_listen_pcbs, pcb);
		tcp_free(pcb);
		break;
	case SYN_SENT:
		TCP_PCB_REMOVE_ACTIVE(pcb);
		tcp_free(pcb);
		MIB2_STATS_INC(mib2.tcpattemptfails);
		break;
	default:
		return tcp_close_shutdown_fin(pcb);
	}
	return ERR_OK;
}

static err_t tcp_close_shutdown_fin(struct tcp_pcb *pcb)
{
	err_t err;
	DPIP_ASSERT("pcb != NULL", pcb != NULL);

	switch (pcb->state) {
	case SYN_RCVD:
		err = tcp_send_fin(pcb);
		if (err == ERR_OK) {
			MIB2_STATS_INC(mib2.tcpattemptfails);
			pcb->state = FIN_WAIT_1;
		}
		break;
	case ESTABLISHED:
		err = tcp_send_fin(pcb);
		if (err == ERR_OK) {
			MIB2_STATS_INC(mib2.tcpestabresets);
			pcb->state = FIN_WAIT_1;
		}
		break;
	case CLOSE_WAIT:
		err = tcp_send_fin(pcb);
		if (err == ERR_OK) {
			MIB2_STATS_INC(mib2.tcpestabresets);
			pcb->state = LAST_ACK;
		}
		break;
	default:
		/* Has already been closed, do nothing. */
		return ERR_OK;
	}

	if (err == ERR_OK) {
		/* To ensure all data has been sent when tcp_close returns, we have
		   to make sure tcp_output doesn't fail.
		   Since we don't really have to ensure all data has been sent when tcp_close
		   returns (unsent data is sent from tcp timer functions, also), we don't care
		   for the return value of tcp_output for now. */
		tcp_output(pcb);
	} else if (err == ERR_MEM) {
		/* Mark this pcb for closing. Closing is retried from tcp_tmr. */
		tcp_set_flags(pcb, TF_CLOSEPEND);
		/* We have to return ERR_OK from here to indicate to the callers that this
		   pcb should not be used any more as it will be freed soon via tcp_tmr.
		   This is OK here since sending FIN does not guarantee a time frime for
		   actually freeing the pcb, either (it is left in closure states for
		   remote ACK or timeout) */
		return ERR_OK;
	}
	return err;
}

/**
 * @ingroup tcp_raw
 * Closes the connection held by the PCB.
 *
 * Listening pcbs are freed and may not be referenced any more.
 * Connection pcbs are freed if not yet connected and may not be referenced
 * any more. If a connection is established (at least SYN received or in
 * a closing state), the connection is closed, and put in a closing state.
 * The pcb is then automatically freed in tcp_slowtmr(). It is therefore
 * unsafe to reference it (unless an error is returned).
 *
 * The function may return ERR_MEM if no memory
 * was available for closing the connection. If so, the application
 * should wait and try again either by using the acknowledgment
 * callback or the polling functionality. If the close succeeds, the
 * function returns ERR_OK.
 *
 * @param pcb the tcp_pcb to close
 * @return ERR_OK if connection has been closed
 *         another err_t if closing failed and pcb is not freed
 */
err_t tcp_close(struct tcp_pcb *pcb)
{

	DPIP_ERROR("tcp_close: invalid pcb", pcb != NULL, return ERR_ARG);
	DPIP_DEBUGF(TCP_DEBUG, ("tcp_close: closing in "));

	tcp_debug_print_state(pcb->state);

	if (pcb->state != LISTEN) {
		/* Set a flag not to receive any more data... */
		tcp_set_flags(pcb, TF_RXCLOSED);
	}
	/* ... and close */
	return tcp_close_shutdown(pcb, 1);
}

/**
 * @ingroup tcp_raw
 * Causes all or part of a full-duplex connection of this PCB to be shut down.
 * This doesn't deallocate the PCB unless shutting down both sides!
 * Shutting down both sides is the same as calling tcp_close, so if it succeeds
 * (i.e. returns ER_OK), the PCB must not be referenced any more!
 *
 * @param pcb PCB to shutdown
 * @param shut_rx shut down receive side if this is != 0
 * @param shut_tx shut down send side if this is != 0
 * @return ERR_OK if shutdown succeeded (or the PCB has already been shut down)
 *         another err_t on error.
 */
err_t tcp_shutdown(struct tcp_pcb *pcb, int shut_rx, int shut_tx)
{

	DPIP_ERROR("tcp_shutdown: invalid pcb", pcb != NULL, return ERR_ARG);

	if (pcb->state == LISTEN) {
		return ERR_CONN;
	}
	if (shut_rx) {
		/* shut down the receive side: set a flag not to receive any more data... */
		tcp_set_flags(pcb, TF_RXCLOSED);
		if (shut_tx) {
			/* shutting down the tx AND rx side is the same as closing for the raw API */
			return tcp_close_shutdown(pcb, 1);
		}
	}
	if (shut_tx) {
		/* This can't happen twice since if it succeeds, the pcb's state is changed.
		   Only close in these states as the others directly deallocate the PCB */
		switch (pcb->state) {
		case SYN_RCVD:
		case ESTABLISHED:
		case CLOSE_WAIT:
			return tcp_close_shutdown(pcb, (u8_t) shut_rx);
		default:
			/* Not (yet?) connected, cannot shutdown the TX side as that would bring us
			   into CLOSED state, where the PCB is deallocated. */
			return ERR_CONN;
		}
	}
	return ERR_OK;
}

/**
 * Abandons a connection and optionally sends a RST to the remote
 * host.  Deletes the local protocol control block. This is done when
 * a connection is killed because of shortage of memory.
 *
 * @param pcb the tcp_pcb to abort
 * @param reset boolean to indicate whether a reset should be sent
 */
void tcp_abandon(struct tcp_pcb *pcb, int reset)
{
	u32_t seqno, ackno;
	tcp_err_fn errf;
	void *errf_arg;

	DPIP_ERROR("tcp_abandon: invalid pcb", pcb != NULL, return);

	/* pcb->state LISTEN not allowed here */
	DPIP_ASSERT("don't call tcp_abort/tcp_abandon for listen-pcbs",
		    pcb->state != LISTEN);
	/* Figure out on which TCP PCB list we are, and remove us. If we
	   are in an active state, call the receive function associated with
	   the PCB with a NULL argument, and send an RST to the remote end. */
	if (pcb->state == TIME_WAIT) {
		tcp_pcb_remove(&tcp_tw_pcbs, pcb);
		tcp_free(pcb);
	} else {
		int send_rst = 0;
		u16_t local_port = 0;
		enum tcp_state last_state;
		seqno = pcb->snd_nxt;
		ackno = pcb->rcv_nxt;
		errf = pcb->errf;
		errf_arg = pcb->callback_arg;
		if (pcb->state == CLOSED) {
			if (pcb->local_port != 0) {
				/* bound, not yet opened */
				TCP_RMV(&tcp_bound_pcbs, pcb);
			}
		} else {
			send_rst = reset;
			local_port = pcb->local_port;
			TCP_PCB_REMOVE_ACTIVE(pcb);
		}
		if (pcb->unacked != NULL) {
			tcp_segs_free(pcb->unacked);
		}
		if (pcb->unsent != NULL) {
			tcp_segs_free(pcb->unsent);
		}
#if TCP_QUEUE_OOSEQ
		if (pcb->ooseq != NULL) {
			tcp_segs_free(pcb->ooseq);
		}
#endif /* TCP_QUEUE_OOSEQ */
		if (send_rst) {
			DPIP_DEBUGF(TCP_RST_DEBUG,
				    ("tcp_abandon: sending RST\n"));
			tcp_rst(pcb, seqno, ackno, &pcb->local_ip,
				&pcb->remote_ip, local_port, pcb->remote_port);
		}
		last_state = pcb->state;
		tcp_free(pcb);
		TCP_EVENT_ERR(last_state, errf, errf_arg, ERR_ABRT);
	}
}

/**
 * @ingroup tcp_raw
 * Aborts the connection by sending a RST (reset) segment to the remote
 * host. The pcb is deallocated. This function never fails.
 *
 * ATTENTION: When calling this from one of the TCP callbacks, make
 * sure you always return ERR_ABRT (and never return ERR_ABRT otherwise
 * or you will risk accessing deallocated memory or memory leaks!
 *
 * @param pcb the tcp pcb to abort
 */
void tcp_abort(struct tcp_pcb *pcb)
{
	tcp_abandon(pcb, 1);
}

/**
 * @ingroup tcp_raw
 * Binds the connection to a local port number and IP address. If the
 * IP address is not given (i.e., ipaddr == IP_ANY_TYPE), the connection is
 * bound to all local IP addresses.
 * If another connection is bound to the same port, the function will
 * return ERR_USE, otherwise ERR_OK is returned.
 *
 * @param pcb the tcp_pcb to bind (no check is done whether this pcb is
 *        already bound!)
 * @param ipaddr the local ip address to bind to (use IPx_ADDR_ANY to bind
 *        to any local address
 * @param port the local port to bind to
 * @return ERR_USE if the port is already in use
 *         ERR_VAL if bind failed because the PCB is not in a valid state
 *         ERR_OK if bound
 */
err_t tcp_bind(struct tcp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port)
{
	int i;
	int max_pcb_list = PCB_LIST_SUM;
	struct tcp_pcb *cpcb;
#if DPIP_IPV6_SCOPES
	ip_addr_t zoned_ipaddr;
#endif /* DPIP_IPV6_SCOPES */

	/* Don't propagate NULL pointer (IPv4 ANY) to subsequent functions */
	if (ipaddr == NULL) {
		ipaddr = IP4_ADDR_ANY;
	}

	DPIP_ERROR("tcp_bind: invalid pcb", pcb != NULL, return ERR_ARG);

	DPIP_ERROR("tcp_bind: can only bind in state CLOSED",
		   pcb->state == CLOSED, return ERR_VAL);

	/* Unless the REUSEADDR flag is set,
	   we have to check the pcbs in TIME-WAIT state, also.
	   We do not dump TIME_WAIT pcb's; they can still be matched by incoming
	   packets using both local and remote IP addresses and ports to distinguish.
	 */
	if (ip_get_option(pcb, SOF_REUSEADDR)) {
		max_pcb_list = NUM_TCP_PCB_LISTS_NO_TIME_WAIT;
	}

#if DPIP_IPV6_SCOPES
	/* If the given IP address should have a zone but doesn't, assign one now.
	 * This is legacy support: scope-aware callers should always provide properly
	 * zoned source addresses. Do the zone selection before the address-in-use
	 * check below; as such we have to make a temporary copy of the address. */
	if (IP_IS_V6(ipaddr)
	    && ip6_addr_lacks_zone(ip_2_ip6(ipaddr), IP6_UNICAST)) {
		ip_addr_copy(zoned_ipaddr, *ipaddr);
		ip6_addr_select_zone(ip_2_ip6(&zoned_ipaddr),
				     ip_2_ip6(&zoned_ipaddr));
		ipaddr = &zoned_ipaddr;
	}
#endif /* DPIP_IPV6_SCOPES */

	if (port == 0) {
		port = tcp_new_port();
		if (port == 0) {
			return ERR_BUF;
		}
	} else {
		/* Check if the address already is in use (on all lists) */
		for (i = 0; i < max_pcb_list; i++) {
			TAILQ_FOREACH(cpcb, tcp_pcb_lists[i], next) {
				if (cpcb->local_port == port) {
					/* Omit checking for the same port if both pcbs have REUSEADDR set.
					   For SO_REUSEADDR, the duplicate-check for a 5-tuple is done in
					   tcp_connect. */
					if (ip_get_option(pcb, SOF_REUSEADDR) &&
					    ip_get_option(cpcb,
							  SOF_REUSEADDR)) {
						continue;
					}

					/* @todo: check accept_any_ip_version */
					if ((IP_IS_V6(ipaddr) ==
					     IP_IS_V6_VAL(cpcb->local_ip))
					    && (ip_addr_isany(&cpcb->local_ip)
						|| ip_addr_isany(ipaddr)
						|| ip_addr_eq(&cpcb->local_ip,
							      ipaddr))) {
						return ERR_USE;
					}
				}
			}
		}
	}

	if (!ip_addr_isany(ipaddr)
	    || (IP_GET_TYPE(ipaddr) != IP_GET_TYPE(&pcb->local_ip))
	    ) {
		ip_addr_set(&pcb->local_ip, ipaddr);
	}
	pcb->local_port = port;
	TCP_REG(&tcp_bound_pcbs, pcb);
	DPIP_DEBUGF(TCP_DEBUG, ("tcp_bind: bind to port %" U16_F "\n", port));
	return ERR_OK;
}

/**
 * @ingroup tcp_raw
 * Binds the connection to a netif and IP address.
 * After calling this function, all packets received via this PCB
 * are guaranteed to have come in via the specified netif, and all
 * outgoing packets will go out via the specified netif.
 *
 * @param pcb the tcp_pcb to bind.
 * @param netif the netif to bind to. Can be NULL.
 */
void tcp_bind_netif(struct tcp_pcb *pcb, const struct netif *netif)
{
	if (netif != NULL) {
		pcb->netif_idx = netif_get_index(netif);
	} else {
		pcb->netif_idx = NETIF_NO_INDEX;
	}
}

/**
 * Default accept callback if no accept callback is specified by the user.
 */
static err_t tcp_accept_null(void *arg, struct tcp_pcb *pcb, err_t err)
{
	DPIP_UNUSED_ARG(arg);
	DPIP_UNUSED_ARG(err);

	DPIP_ASSERT("tcp_accept_null: invalid pcb", pcb != NULL);

	tcp_abort(pcb);

	return ERR_ABRT;
}

/**
 * @ingroup tcp_raw
 * Set the state of the connection to be LISTEN, which means that it
 * is able to accept incoming connections. The protocol control block
 * is reallocated in order to consume less memory. Setting the
 * connection to LISTEN is an irreversible process.
 * When an incoming connection is accepted, the function specified with
 * the tcp_accept() function will be called. The pcb has to be bound
 * to a local port with the tcp_bind() function.
 *
 * @param pcb to listen on
 * @return the error reason
 *
 */
err_t tcp_listen(struct tcp_pcb *pcb)
{

	DPIP_ERROR("tcp_listen: invalid pcb", pcb != NULL, return ERR_ARG);
	DPIP_ERROR("tcp_listen: pcb already connected", pcb->state == CLOSED,
		   return ERR_CLSD);

	/* already listening? */
	if (pcb->state == LISTEN) {
		return ERR_ALREADY;
	}

	if (ip_get_option(pcb, SOF_REUSEADDR)) {
		struct tcp_pcb *lpcb;
		/* Since SOF_REUSEADDR allows reusing a local address before the pcb's usage
		   is declared (listen-/connection-pcb), we have to make sure now that
		   this port is only used once for every local IP. */
		TAILQ_FOREACH(lpcb, &tcp_listen_pcbs, next) {
			if ((lpcb->local_port == pcb->local_port) &&
			    ip_addr_eq(&lpcb->local_ip, &pcb->local_ip)) {
				/* this address/port is already used */
				return ERR_USE;
			}
		}
	}

	pcb->state = LISTEN;
	if (pcb->local_port != 0) {
		TCP_RMV(&tcp_bound_pcbs, pcb);
	}
	pcb->accept = tcp_accept_null;
	TCP_REG(&tcp_listen_pcbs, pcb);

	return ERR_OK;
}

/**
 * Update the state that tracks the available window space to advertise.
 *
 * Returns how much extra window would be advertised if we sent an
 * update now.
 */
u32_t tcp_update_rcv_ann_wnd(struct tcp_pcb *pcb)
{
	u32_t new_right_edge;

	DPIP_ASSERT("tcp_update_rcv_ann_wnd: invalid pcb", pcb != NULL);
	new_right_edge = pcb->rcv_nxt + pcb->rcv_wnd;

	if (TCP_SEQ_GEQ
	    (new_right_edge,
	     pcb->rcv_ann_right_edge + RTE_MIN((TCP_WND / 2), pcb->mss))) {
		/* we can advertise more window */
		pcb->rcv_ann_wnd = pcb->rcv_wnd;
		return new_right_edge - pcb->rcv_ann_right_edge;
	} else {
		if (TCP_SEQ_GT(pcb->rcv_nxt, pcb->rcv_ann_right_edge)) {
			/* Can happen due to other end sending out of advertised window,
			 * but within actual available (but not yet advertised) window */
			pcb->rcv_ann_wnd = 0;
		} else {
			/* keep the right edge of window constant */
			u32_t new_rcv_ann_wnd =
			    pcb->rcv_ann_right_edge - pcb->rcv_nxt;
#if !DPIP_WND_SCALE
			DPIP_ASSERT("new_rcv_ann_wnd <= 0xffff",
				    new_rcv_ann_wnd <= 0xffff);
#endif
			pcb->rcv_ann_wnd = (tcpwnd_size_t) new_rcv_ann_wnd;
		}
		return 0;
	}
}

/**
 * @ingroup tcp_raw
 * This function should be called by the application when it has
 * processed the data. The purpose is to advertise a larger window
 * when the data has been processed.
 *
 * @param pcb the tcp_pcb for which data is read
 * @param len the amount of bytes that have been read by the application
 */
void tcp_recved(struct tcp_pcb *pcb, u16_t len)
{
	u32_t wnd_inflation;
	tcpwnd_size_t rcv_wnd;

	DPIP_ERROR("tcp_recved: invalid pcb", pcb != NULL, return);

	/* pcb->state LISTEN not allowed here */
	DPIP_ASSERT("don't call tcp_recved for listen-pcbs",
		    pcb->state != LISTEN);

	rcv_wnd = (tcpwnd_size_t) (pcb->rcv_wnd + len);
	if ((rcv_wnd > TCP_WND_MAX(pcb)) || (rcv_wnd < pcb->rcv_wnd)) {
		/* window got too big or tcpwnd_size_t overflow */
		DPIP_DEBUGF(TCP_DEBUG,
			    ("tcp_recved: window got too big or tcpwnd_size_t overflow\n"));
		pcb->rcv_wnd = TCP_WND_MAX(pcb);
	} else {
		pcb->rcv_wnd = rcv_wnd;
	}

	wnd_inflation = tcp_update_rcv_ann_wnd(pcb);

	/* If the change in the right edge of window is significant (default
	 * watermark is TCP_WND/4), then send an explicit update now.
	 * Otherwise wait for a packet to be sent in the normal course of
	 * events (or more window to be available later) */
	if (wnd_inflation >= (unsigned)TCP_WND_UPDATE_THRESHOLD) {
		tcp_ack_now(pcb);
		tcp_output(pcb);
	}

	DPIP_DEBUGF(TCP_DEBUG,
		    ("tcp_recved: received %" U16_F " bytes, wnd %" TCPWNDSIZE_F
		     " (%" TCPWNDSIZE_F ").\n", len, pcb->rcv_wnd,
		     (u16_t) (TCP_WND_MAX(pcb) - pcb->rcv_wnd)));
}

/**
 * Allocate a new local TCP port.
 *
 * @return a new (free) local TCP port number
 */
static u16_t tcp_new_port(void)
{
	u8_t i;
	u16_t n = 0;
	struct tcp_pcb *pcb;

 again:
	tcp_port++;
	if (tcp_port == TCP_LOCAL_PORT_RANGE_END) {
		tcp_port = TCP_LOCAL_PORT_RANGE_START;
	}
	/* Check all PCB lists. */
	for (i = 0; i < PCB_LIST_SUM; i++) {
		TAILQ_FOREACH(pcb, tcp_pcb_lists[i], next) {
			if (pcb->local_port == tcp_port) {
				n++;
				if (n >
				    (TCP_LOCAL_PORT_RANGE_END -
				     TCP_LOCAL_PORT_RANGE_START)) {
					return 0;
				}
				goto again;
			}
		}
	}
	return tcp_port;
}

/**
 * @ingroup tcp_raw
 * Connects to another host. The function given as the "connected"
 * argument will be called when the connection has been established.
 *  Sets up the pcb to connect to the remote host and sends the
 * initial SYN segment which opens the connection.
 *
 * The tcp_connect() function returns immediately; it does not wait for
 * the connection to be properly setup. Instead, it will call the
 * function specified as the fourth argument (the "connected" argument)
 * when the connection is established. If the connection could not be
 * properly established, either because the other host refused the
 * connection or because the other host didn't answer, the "err"
 * callback function of this pcb (registered with tcp_err, see below)
 * will be called.
 *
 * The tcp_connect() function can return ERR_MEM if no memory is
 * available for enqueueing the SYN segment. If the SYN indeed was
 * enqueued successfully, the tcp_connect() function returns ERR_OK.
 *
 * @param pcb the tcp_pcb used to establish the connection
 * @param ipaddr the remote ip address to connect to
 * @param port the remote tcp port to connect to
 * @param connected callback function to call when connected (on error,
                    the err callback will be called)
 * @return ERR_VAL if invalid arguments are given
 *         ERR_OK if connect request has been sent
 *         other err_t values if connect request couldn't be sent
 */
err_t
tcp_connect(struct tcp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port,
	    tcp_connected_fn connected)
{
	struct netif *netif = NULL;
	err_t ret;
	u32_t iss;
	u16_t old_local_port;

	DPIP_ERROR("tcp_connect: invalid pcb", pcb != NULL, return ERR_ARG);
	DPIP_ERROR("tcp_connect: invalid ipaddr", ipaddr != NULL,
		   return ERR_ARG);

	DPIP_ERROR("tcp_connect: can only connect from state CLOSED",
		   pcb->state == CLOSED, return ERR_ISCONN);

	DPIP_DEBUGF(TCP_DEBUG, ("tcp_connect to port %" U16_F "\n", port));
	ip_addr_set(&pcb->remote_ip, ipaddr);
	pcb->remote_port = port;

	if (pcb->netif_idx != NETIF_NO_INDEX) {
		netif = netif_get_by_index(pcb->netif_idx);
	} else {
		/* check if we have a route to the remote host */
		netif = ip_route(&pcb->local_ip, &pcb->remote_ip);
	}
	if (netif == NULL) {
		/* Don't even try to send a SYN packet if we have no route since that will fail. */
		return ERR_RTE;
	}

	/* check if local IP has been assigned to pcb, if not, get one */
	if (ip_addr_isany(&pcb->local_ip)) {
		const ip_addr_t *local_ip =
		    ip_netif_get_local_ip(netif, ipaddr);
		if (local_ip == NULL) {
			return ERR_RTE;
		}
		ip_addr_copy(pcb->local_ip, *local_ip);
	}

#if DPIP_IPV6_SCOPES
	/* If the given IP address should have a zone but doesn't, assign one now.
	 * Given that we already have the target netif, this is easy and cheap. */
	if (IP_IS_V6(&pcb->remote_ip) &&
	    ip6_addr_lacks_zone(ip_2_ip6(&pcb->remote_ip), IP6_UNICAST)) {
		ip6_addr_assign_zone(ip_2_ip6(&pcb->remote_ip), IP6_UNICAST,
				     netif);
	}
#endif /* DPIP_IPV6_SCOPES */

	old_local_port = pcb->local_port;
	if (pcb->local_port == 0) {
		pcb->local_port = tcp_new_port();
		if (pcb->local_port == 0) {
			return ERR_BUF;
		}
	} else if (ip_get_option(pcb, SOF_REUSEADDR)) {
		/* Since SOF_REUSEADDR allows reusing a local address, we have to make sure
		   now that the 5-tuple is unique. */
		struct tcp_pcb *cpcb;
		int i;
		/* Don't check listen- and bound-PCBs, check active- and TIME-WAIT PCBs. */
		for (i = 2; i < PCB_LIST_SUM; i++) {
			TAILQ_FOREACH(cpcb, tcp_pcb_lists[i], next) {
				if ((cpcb->local_port == pcb->local_port) &&
				    (cpcb->remote_port == port) &&
				    ip_addr_eq(&cpcb->local_ip, &pcb->local_ip)
				    && ip_addr_eq(&cpcb->remote_ip, ipaddr)) {
					/* linux returns EISCONN here, but ERR_USE should be OK for us */
					return ERR_USE;
				}
			}
		}
	}

	iss = tcp_next_iss(pcb);
	pcb->rcv_nxt = 0;
	pcb->snd_nxt = iss;
	pcb->lastack = iss - 1;
	pcb->snd_wl2 = iss - 1;
	pcb->snd_lbb = iss - 1;
	/* Start with a window that does not need scaling. When window scaling is
	   enabled and used, the window is enlarged when both sides agree on scaling. */
	pcb->rcv_wnd = pcb->rcv_ann_wnd = TCPWND_MIN16(TCP_WND);
	pcb->rcv_ann_right_edge = pcb->rcv_nxt;
	pcb->snd_wnd = TCP_WND;
	/* As initial send MSS, we use TCP_MSS but limit it to 536.
	   The send MSS is updated when an MSS option is received. */
	pcb->mss = INITIAL_MSS;
#if TCP_CALCULATE_EFF_SEND_MSS
	pcb->mss = tcp_eff_send_mss_netif(pcb->mss, netif, &pcb->remote_ip);
#endif /* TCP_CALCULATE_EFF_SEND_MSS */
	pcb->cwnd = 1;
	pcb->connected = connected;

	/* Send a SYN together with the MSS option. */
	ret = tcp_enqueue_flags(pcb, TCP_SYN);
	if (ret == ERR_OK) {
		/* SYN segment was enqueued, changed the pcbs state now */
		pcb->state = SYN_SENT;
		if (old_local_port != 0) {
			TCP_RMV(&tcp_bound_pcbs, pcb);
		}
		TCP_REG_ACTIVE(pcb);
		MIB2_STATS_INC(mib2.tcpactiveopens);

		tcp_output(pcb);
	}
	return ret;
}

/**
 * Called every 500 ms and implements the retransmission timer and the timer that
 * removes PCBs that have been in TIME-WAIT for enough time. It also increments
 * various timers such as the inactivity timer in each PCB.
 *
 * Automatically called from tcp_tmr().
 */
void tcp_slowtmr(void)
{
	struct tcp_pcb *pcb, *next;
	tcpwnd_size_t eff_wnd;
	u8_t pcb_remove;	/* flag if a PCB should be removed */
	u8_t pcb_reset;		/* flag if a RST should be sent when removing */
	err_t err;

	err = ERR_OK;

	++tcp_ticks;
	++tcp_timer_ctr;

 tcp_slowtmr_start:
	/* Steps through all of the active PCBs. */
	pcb = TAILQ_FIRST(&tcp_active_pcbs);
	if (pcb == NULL) {
		DPIP_DEBUGF(TCP_DEBUG, ("tcp_slowtmr: no active pcbs\n"));
	}
	while (pcb != NULL) {
		next = TAILQ_NEXT(pcb, next);

		DPIP_DEBUGF(TCP_DEBUG,
			    ("tcp_slowtmr: processing active pcb\n"));
		DPIP_ASSERT("tcp_slowtmr: active pcb->state != CLOSED",
			    pcb->state != CLOSED);
		DPIP_ASSERT("tcp_slowtmr: active pcb->state != LISTEN",
			    pcb->state != LISTEN);
		DPIP_ASSERT("tcp_slowtmr: active pcb->state != TIME-WAIT",
			    pcb->state != TIME_WAIT);
		if (pcb->last_timer == tcp_timer_ctr) {
			/* skip this pcb, we have already processed it */
			pcb = next;
			continue;
		}
		pcb->last_timer = tcp_timer_ctr;

		pcb_remove = 0;
		pcb_reset = 0;

		if (pcb->state == SYN_SENT && pcb->nrtx >= TCP_SYNMAXRTX) {
			++pcb_remove;
			DPIP_DEBUGF(TCP_DEBUG,
				    ("tcp_slowtmr: max SYN retries reached\n"));
		} else if (pcb->nrtx >= TCP_MAXRTX) {
			++pcb_remove;
			DPIP_DEBUGF(TCP_DEBUG,
				    ("tcp_slowtmr: max DATA retries reached\n"));
		} else {
			if (pcb->persist_backoff > 0) {
				DPIP_ASSERT
				    ("tcp_slowtimr: persist ticking with in-flight data",
				     pcb->unacked == NULL);
				DPIP_ASSERT
				    ("tcp_slowtimr: persist ticking with empty send buffer",
				     pcb->unsent != NULL);
				if (pcb->persist_probe >= TCP_MAXRTX) {
					++pcb_remove;	/* max probes reached */
				} else {
					u8_t backoff_cnt =
					    tcp_persist_backoff[pcb->
								persist_backoff
								- 1];
					if (pcb->persist_cnt < backoff_cnt) {
						pcb->persist_cnt++;
					}
					if (pcb->persist_cnt >= backoff_cnt) {
						int next_slot = 1;	/* increment timer to next slot */
						/* If snd_wnd is zero, send 1 byte probes */
						if (pcb->snd_wnd == 0) {
							if (tcp_zero_window_probe(pcb) != ERR_OK) {
								next_slot = 0;	/* try probe again with current slot */
							}
							/* snd_wnd not fully closed, split unsent head and fill window */
						} else {
							if (tcp_split_unsent_seg
							    (pcb,
							     (u16_t) pcb->
							     snd_wnd) ==
							    ERR_OK) {
								if (tcp_output
								    (pcb) ==
								    ERR_OK) {
									/* sending will cancel persist timer, else retry with current slot */
									next_slot
									    = 0;
								}
							}
						}
						if (next_slot) {
							pcb->persist_cnt = 0;
							if (pcb->
							    persist_backoff <
							    sizeof
							    (tcp_persist_backoff))
							{
								pcb->
								    persist_backoff++;
							}
						}
					}
				}
			} else {
				/* Increase the retransmission timer if it is running */
				if ((pcb->rtime >= 0) && (pcb->rtime < 0x7FFF)) {
					++pcb->rtime;
				}

				if (pcb->rtime >= pcb->rto) {
					/* Time for a retransmission. */
					DPIP_DEBUGF(TCP_RTO_DEBUG,
						    ("tcp_slowtmr: rtime %"
						     S16_F " pcb->rto %" S16_F
						     "\n", pcb->rtime,
						     pcb->rto));
					/* If prepare phase fails but we have unsent data but no unacked data,
					   still execute the backoff calculations below, as this means we somehow
					   failed to send segment. */
					if ((tcp_rexmit_rto_prepare(pcb) ==
					     ERR_OK) || ((pcb->unacked == NULL)
							 && (pcb->unsent !=
							     NULL))) {
						/* Double retransmission time-out unless we are trying to
						 * connect to somebody (i.e., we are in SYN_SENT). */
						if (pcb->state != SYN_SENT) {
							u8_t backoff_idx =
							    RTE_MIN(pcb->nrtx,
								    sizeof
								    (tcp_backoff)
								    - 1);
							int calc_rto =
							    ((pcb->sa >> 3) +
							     pcb->
							     sv) <<
							    tcp_backoff
							    [backoff_idx];
							pcb->rto =
							    (s16_t)
							    RTE_MIN(calc_rto,
								    0x7FFF);
						}

						/* Reset the retransmission timer. */
						pcb->rtime = 0;

						/* Reduce congestion window and ssthresh. */
						eff_wnd =
						    RTE_MIN(pcb->cwnd,
							    pcb->snd_wnd);
						pcb->ssthresh = eff_wnd >> 1;
						if (pcb->ssthresh <
						    (tcpwnd_size_t) (pcb->
								     mss << 1))
						{
							pcb->ssthresh =
							    (tcpwnd_size_t)
							    (pcb->mss << 1);
						}
						pcb->cwnd = pcb->mss;
						DPIP_DEBUGF(TCP_CWND_DEBUG,
							    ("tcp_slowtmr: cwnd %"
							     TCPWNDSIZE_F
							     " ssthresh %"
							     TCPWNDSIZE_F "\n",
							     pcb->cwnd,
							     pcb->ssthresh));
						pcb->bytes_acked = 0;

						/* The following needs to be called AFTER cwnd is set to one
						   mss - STJ */
						tcp_rexmit_rto_commit(pcb);
					}
				}
			}
		}
		/* Check if this PCB has stayed too long in FIN-WAIT-2 */
		if (pcb->state == FIN_WAIT_2) {
			/* If this PCB is in FIN_WAIT_2 because of SHUT_WR don't let it time out. */
			if (pcb->flags & TF_RXCLOSED) {
				/* PCB was fully closed (either through close() or SHUT_RDWR):
				   normal FIN-WAIT timeout handling. */
				if ((u32_t) (tcp_ticks - pcb->tmr) >
				    TCP_FIN_WAIT_TIMEOUT / TCP_SLOW_INTERVAL) {
					++pcb_remove;
					DPIP_DEBUGF(TCP_DEBUG,
						    ("tcp_slowtmr: removing pcb stuck in FIN-WAIT-2\n"));
				}
			}
		}

		/* Check if KEEPALIVE should be sent */
		if (ip_get_option(pcb, SOF_KEEPALIVE) &&
		    ((pcb->state == ESTABLISHED) ||
		     (pcb->state == CLOSE_WAIT))) {
			if ((u32_t) (tcp_ticks - pcb->tmr) >
			    (pcb->keep_idle +
			     TCP_KEEP_DUR(pcb)) / TCP_SLOW_INTERVAL) {
				DPIP_DEBUGF(TCP_DEBUG,
					    ("tcp_slowtmr: KEEPALIVE timeout. Aborting connection to "));
				ip_addr_debug_print_val(TCP_DEBUG,
							pcb->remote_ip);
				DPIP_DEBUGF(TCP_DEBUG, ("\n"));

				++pcb_remove;
				++pcb_reset;
			} else if ((u32_t) (tcp_ticks - pcb->tmr) >
				   (pcb->keep_idle +
				    pcb->keep_cnt_sent * TCP_KEEP_INTVL(pcb))
				   / TCP_SLOW_INTERVAL) {
				err = tcp_keepalive(pcb);
				if (err == ERR_OK) {
					pcb->keep_cnt_sent++;
				}
			}
		}

		/* If this PCB has queued out of sequence data, but has been
		   inactive for too long, will drop the data (it will eventually
		   be retransmitted). */
#if TCP_QUEUE_OOSEQ
		if (pcb->ooseq != NULL &&
		    (tcp_ticks - pcb->tmr >=
		     (u32_t) pcb->rto * TCP_OOSEQ_TIMEOUT)) {
			DPIP_DEBUGF(TCP_CWND_DEBUG,
				    ("tcp_slowtmr: dropping OOSEQ queued data\n"));
			tcp_free_ooseq(pcb);
		}
#endif /* TCP_QUEUE_OOSEQ */

		/* Check if this PCB has stayed too long in SYN-RCVD */
		if (pcb->state == SYN_RCVD) {
			if ((u32_t) (tcp_ticks - pcb->tmr) >
			    TCP_SYN_RCVD_TIMEOUT / TCP_SLOW_INTERVAL) {
				++pcb_remove;
				DPIP_DEBUGF(TCP_DEBUG,
					    ("tcp_slowtmr: removing pcb stuck in SYN-RCVD\n"));
			}
		}

		/* Check if this PCB has stayed too long in LAST-ACK */
		if (pcb->state == LAST_ACK) {
			if ((u32_t) (tcp_ticks - pcb->tmr) >
			    2 * TCP_MSL / TCP_SLOW_INTERVAL) {
				++pcb_remove;
				DPIP_DEBUGF(TCP_DEBUG,
					    ("tcp_slowtmr: removing pcb stuck in LAST-ACK\n"));
			}
		}

		/* If the PCB should be removed, do it. */
		if (pcb_remove) {
			tcp_err_fn err_fn = pcb->errf;
			void *err_arg;
			enum tcp_state last_state;
			tcp_pcb_purge(pcb);
			/* Remove PCB from tcp_active_pcbs list. */
			TCP_RMV(&tcp_active_pcbs, pcb);

			if (pcb_reset) {
				tcp_rst(pcb, pcb->snd_nxt, pcb->rcv_nxt,
					&pcb->local_ip, &pcb->remote_ip,
					pcb->local_port, pcb->remote_port);
			}

			err_arg = pcb->callback_arg;
			last_state = pcb->state;
			tcp_free(pcb);

			tcp_active_pcbs_changed = 0;
			TCP_EVENT_ERR(last_state, err_fn, err_arg, ERR_ABRT);
			if (tcp_active_pcbs_changed) {
				goto tcp_slowtmr_start;
			}
		} else {

			/* We check if we should poll the connection. */
			++pcb->polltmr;
			if (pcb->polltmr >= pcb->pollinterval) {
				pcb->polltmr = 0;
				DPIP_DEBUGF(TCP_DEBUG,
					    ("tcp_slowtmr: polling application\n"));
				tcp_active_pcbs_changed = 0;
				TCP_EVENT_POLL(pcb, err);
				if (tcp_active_pcbs_changed) {
					goto tcp_slowtmr_start;
				}
				/* if err == ERR_ABRT, pcb is already deallocated */
				if (err == ERR_OK) {
					tcp_output(pcb);
				}
			}
		}

		pcb = next;
	}

	/* Steps through all of the TIME-WAIT PCBs. */
	pcb = TAILQ_FIRST(&tcp_tw_pcbs);
	while (pcb != NULL) {
		next = TAILQ_NEXT(pcb, next);

		DPIP_ASSERT("tcp_slowtmr: TIME-WAIT pcb->state == TIME-WAIT",
			    pcb->state == TIME_WAIT);

		/* Check if this PCB has stayed long enough in TIME-WAIT */
		if ((u32_t) (tcp_ticks - pcb->tmr) >
		    2 * TCP_MSL / TCP_SLOW_INTERVAL) {
			tcp_pcb_purge(pcb);
			/* Remove PCB from tcp_tw_pcbs list. */
			TCP_RMV(&tcp_tw_pcbs, pcb);
			tcp_free(pcb);
		}

		pcb = next;
	}
}

/**
 * Is called every TCP_FAST_INTERVAL (250 ms) and sends delayed ACKs or pending FINs.
 *
 * Automatically called from tcp_tmr().
 */
void tcp_fasttmr(void)
{
	struct tcp_pcb *pcb;

	++tcp_timer_ctr;

	TAILQ_FOREACH(pcb, &tcp_active_pcbs, next) {
		if (pcb->last_timer != tcp_timer_ctr) {
			pcb->last_timer = tcp_timer_ctr;
			/* send delayed ACKs */
			if (pcb->flags & TF_ACK_DELAY) {
				DPIP_DEBUGF(TCP_DEBUG,
					    ("tcp_fasttmr: delayed ACK\n"));
				tcp_ack_now(pcb);
				tcp_output(pcb);
				tcp_clear_flags(pcb, TF_ACK_DELAY | TF_ACK_NOW);
			}
			/* send pending FIN */
			if (pcb->flags & TF_CLOSEPEND) {
				DPIP_DEBUGF(TCP_DEBUG,
					    ("tcp_fasttmr: pending FIN\n"));
				tcp_clear_flags(pcb, TF_CLOSEPEND);
				tcp_close_shutdown_fin(pcb);
			}
		}
	}
}

/** Call tcp_output for all active pcbs that have TF_NAGLEMEMERR set */
void tcp_txnow(void)
{
	struct tcp_pcb *pcb;

	TAILQ_FOREACH(pcb, &tcp_active_pcbs, next) {
		if (pcb->flags & TF_NAGLEMEMERR) {
			tcp_output(pcb);
		}
	}
}

/**
 * Deallocates a list of TCP segments (tcp_seg structures).
 *
 * @param seg tcp_seg list of TCP segments to free
 */
void tcp_segs_free(struct tcp_seg *seg)
{
	while (seg != NULL) {
		struct tcp_seg *next = seg->next;
		tcp_seg_free(seg);
		seg = next;
	}
}

/**
 * Frees a TCP segment (tcp_seg structure).
 *
 * @param seg single tcp_seg to free
 */
void tcp_seg_free(struct tcp_seg *seg)
{
	if (seg != NULL) {
		if (seg->p != NULL) {
			rte_pktmbuf_free(seg->p);
#if TCP_DEBUG
			seg->p = NULL;
#endif /* TCP_DEBUG */
		}
		memp_free(MEMP_TCP_SEG, seg);
	}
}

/**
 * @ingroup tcp
 * Sets the priority of a connection.
 *
 * @param pcb the tcp_pcb to manipulate
 * @param prio new priority
 */
void tcp_setprio(struct tcp_pcb *pcb, u8_t prio)
{

	DPIP_ERROR("tcp_setprio: invalid pcb", pcb != NULL, return);

	pcb->prio = prio;
}

#if TCP_QUEUE_OOSEQ
/**
 * Returns a copy of the given TCP segment.
 * The mbuf and data are not copied, only the pointers
 *
 * @param seg the old tcp_seg
 * @return a copy of seg
 */
struct tcp_seg *tcp_seg_copy(struct tcp_seg *seg)
{
	struct tcp_seg *cseg;

	DPIP_ASSERT("tcp_seg_copy: invalid seg", seg != NULL);

	cseg = (struct tcp_seg *)memp_malloc(MEMP_TCP_SEG);
	if (cseg == NULL) {
		return NULL;
	}
	SMEMCPY((u8_t *) cseg, (const u8_t *)seg, sizeof(struct tcp_seg));
	rte_mbuf_refcnt_update(cseg->p, 1);
	return cseg;
}
#endif /* TCP_QUEUE_OOSEQ */

/**
 * Default receive callback that is called if the user didn't register
 * a recv callback for the pcb.
 */
err_t
tcp_recv_null(void *arg, struct tcp_pcb *pcb, struct rte_mbuf *p, err_t err)
{
	DPIP_UNUSED_ARG(arg);

	DPIP_ERROR("tcp_recv_null: invalid pcb", pcb != NULL, return ERR_ARG);

	if (p != NULL) {
		tcp_recved(pcb, rte_pktmbuf_pkt_len(p));
		rte_pktmbuf_free(p);
	} else if (err == ERR_OK) {
		return tcp_close(pcb);
	}
	return ERR_OK;
}

/**
 * Kills the oldest active connection that has a lower priority than 'prio'.
 *
 * @param prio minimum priority
 */
static void tcp_kill_prio(u8_t prio)
{
	struct tcp_pcb *pcb, *inactive;
	u32_t inactivity;
	u8_t mprio;

	mprio = RTE_MIN(TCP_PRIO_MAX, prio);

	/* We want to kill connections with a lower prio, so bail out if
	 * supplied prio is 0 - there can never be a lower prio
	 */
	if (mprio == 0) {
		return;
	}

	/* We only want kill connections with a lower prio, so decrement prio by one
	 * and start searching for oldest connection with same or lower priority than mprio.
	 * We want to find the connections with the lowest possible prio, and among
	 * these the one with the longest inactivity time.
	 */
	mprio--;

	inactivity = 0;
	inactive = NULL;
	TAILQ_FOREACH(pcb, &tcp_active_pcbs, next) {
		/* lower prio is always a kill candidate */
		if ((pcb->prio < mprio) ||
		    /* longer inactivity is also a kill candidate */
		    ((pcb->prio == mprio)
		     && ((u32_t) (tcp_ticks - pcb->tmr) >= inactivity))) {
			inactivity = tcp_ticks - pcb->tmr;
			inactive = pcb;
			mprio = pcb->prio;
		}
	}
	if (inactive != NULL) {
		DPIP_DEBUGF(TCP_DEBUG,
			    ("tcp_kill_prio: killing oldest PCB %p (%" S32_F
			     ")\n", (void *)inactive, inactivity));
		tcp_abort(inactive);
	}
}

/**
 * Kills the oldest connection that is in specific state.
 * Called from tcp_alloc() for LAST_ACK and CLOSING if no more connections are available.
 */
static void tcp_kill_state(enum tcp_state state)
{
	struct tcp_pcb *pcb, *inactive;
	u32_t inactivity;

	DPIP_ASSERT("invalid state", (state == CLOSING) || (state == LAST_ACK));

	inactivity = 0;
	inactive = NULL;
	/* Go through the list of active pcbs and get the oldest pcb that is in state
	   CLOSING/LAST_ACK. */
	TAILQ_FOREACH(pcb, &tcp_active_pcbs, next) {
		if (pcb->state == state) {
			if ((u32_t) (tcp_ticks - pcb->tmr) >= inactivity) {
				inactivity = tcp_ticks - pcb->tmr;
				inactive = pcb;
			}
		}
	}
	if (inactive != NULL) {
		DPIP_DEBUGF(TCP_DEBUG,
			    ("tcp_kill_closing: killing oldest %s PCB %p (%"
			     S32_F ")\n", tcp_state_str[state],
			     (void *)inactive, inactivity));
		/* Don't send a RST, since no data is lost. */
		tcp_abandon(inactive, 0);
	}
}

/**
 * Kills the oldest connection that is in TIME_WAIT state.
 * Called from tcp_alloc() if no more connections are available.
 */
static void tcp_kill_timewait(void)
{
	struct tcp_pcb *pcb, *inactive;
	u32_t inactivity;

	inactivity = 0;
	inactive = NULL;
	/* Go through the list of TIME_WAIT pcbs and get the oldest pcb. */
	TAILQ_FOREACH(pcb, &tcp_tw_pcbs, next) {
		if ((u32_t) (tcp_ticks - pcb->tmr) >= inactivity) {
			inactivity = tcp_ticks - pcb->tmr;
			inactive = pcb;
		}
	}
	if (inactive != NULL) {
		DPIP_DEBUGF(TCP_DEBUG,
			    ("tcp_kill_timewait: killing oldest TIME-WAIT PCB %p (%"
			     S32_F ")\n", (void *)inactive, inactivity));
		tcp_abort(inactive);
	}
}

/* Called when allocating a pcb fails.
 * In this case, we want to handle all pcbs that want to close first: if we can
 * now send the FIN (which failed before), the pcb might be in a state that is
 * OK for us to now free it.
 */
static void tcp_handle_closepend(void)
{
	struct tcp_pcb *pcb;

	TAILQ_FOREACH(pcb, &tcp_active_pcbs, next) {
		/* send pending FIN */
		if (pcb->flags & TF_CLOSEPEND) {
			DPIP_DEBUGF(TCP_DEBUG,
				    ("tcp_handle_closepend: pending FIN\n"));
			tcp_clear_flags(pcb, TF_CLOSEPEND);
			tcp_close_shutdown_fin(pcb);
		}
	}
}

/**
 * Allocate a new tcp_pcb structure.
 *
 * @param prio priority for the new pcb
 * @return a new tcp_pcb that initially is in state CLOSED
 */
struct tcp_pcb *tcp_alloc(u8_t prio)
{
	struct tcp_pcb *pcb;

	pcb = (struct tcp_pcb *)memp_malloc(MEMP_TCP_PCB);
	if (pcb == NULL) {
		/* Try to send FIN for all pcbs stuck in TF_CLOSEPEND first */
		tcp_handle_closepend();

		/* Try killing oldest connection in TIME-WAIT. */
		DPIP_DEBUGF(TCP_DEBUG,
			    ("tcp_alloc: killing off oldest TIME-WAIT connection\n"));
		tcp_kill_timewait();
		/* Try to allocate a tcp_pcb again. */
		pcb = (struct tcp_pcb *)memp_malloc(MEMP_TCP_PCB);
		if (pcb == NULL) {
			/* Try killing oldest connection in LAST-ACK (these wouldn't go to TIME-WAIT). */
			DPIP_DEBUGF(TCP_DEBUG,
				    ("tcp_alloc: killing off oldest LAST-ACK connection\n"));
			tcp_kill_state(LAST_ACK);
			/* Try to allocate a tcp_pcb again. */
			pcb = (struct tcp_pcb *)memp_malloc(MEMP_TCP_PCB);
			if (pcb == NULL) {
				/* Try killing oldest connection in CLOSING. */
				DPIP_DEBUGF(TCP_DEBUG,
					    ("tcp_alloc: killing off oldest CLOSING connection\n"));
				tcp_kill_state(CLOSING);
				/* Try to allocate a tcp_pcb again. */
				pcb =
				    (struct tcp_pcb *)memp_malloc(MEMP_TCP_PCB);
				if (pcb == NULL) {
					/* Try killing oldest active connection with lower priority than the new one. */
					DPIP_DEBUGF(TCP_DEBUG,
						    ("tcp_alloc: killing oldest connection with prio lower than %d\n",
						     prio));
					tcp_kill_prio(prio);
					/* Try to allocate a tcp_pcb again. */
					pcb =
					    (struct tcp_pcb *)
					    memp_malloc(MEMP_TCP_PCB);
				}
			}
		}
	}
	if (pcb != NULL) {
		/* zero out the whole pcb, so there is no need to initialize members to zero */
		memset(pcb, 0, sizeof(struct tcp_pcb));
		pcb->prio = prio;
		pcb->snd_buf = TCP_SND_BUF;
		/* Start with a window that does not need scaling. When window scaling is
		   enabled and used, the window is enlarged when both sides agree on scaling. */
		pcb->rcv_wnd = pcb->rcv_ann_wnd = TCPWND_MIN16(TCP_WND);
		pcb->ttl = TCP_TTL;
		/* As initial send MSS, we use TCP_MSS but limit it to 536.
		   The send MSS is updated when an MSS option is received. */
		pcb->mss = INITIAL_MSS;
		/* Set initial TCP's retransmission timeout to 3000 ms by default.
		   This value could be configured in opts.h */
		pcb->rto = DPIP_TCP_RTO_TIME / TCP_SLOW_INTERVAL;
		pcb->sv = DPIP_TCP_RTO_TIME / TCP_SLOW_INTERVAL;
		pcb->rtime = -1;
		pcb->cwnd = 1;
		pcb->tmr = tcp_ticks;
		pcb->last_timer = tcp_timer_ctr;

		/* RFC 5681 recommends setting ssthresh arbitrarily high and gives an example
		   of using the largest advertised receive window.  We've seen complications with
		   receiving TCPs that use window scaling and/or window auto-tuning where the
		   initial advertised window is very small and then grows rapidly once the
		   connection is established. To avoid these complications, we set ssthresh to the
		   largest effective cwnd (amount of in-flight data) that the sender can have. */
		pcb->ssthresh = TCP_SND_BUF;

		pcb->recv = tcp_recv_null;

		/* Init KEEPALIVE timer */
		pcb->keep_idle = TCP_KEEPIDLE_DEFAULT;

#if DPIP_TCP_KEEPALIVE
		pcb->keep_intvl = TCP_KEEPINTVL_DEFAULT;
		pcb->keep_cnt = TCP_KEEPCNT_DEFAULT;
#endif /* DPIP_TCP_KEEPALIVE */
		pcb_tci_init(pcb);
	}
	return pcb;
}

/**
 * @ingroup tcp_raw
 * Creates a new TCP protocol control block but doesn't place it on
 * any of the TCP PCB lists.
 * The pcb is not put on any list until binding using tcp_bind().
 * If memory is not available for creating the new pcb, NULL is returned.
 *
 * @internal: Maybe there should be a idle TCP PCB list where these
 * PCBs are put on. Port reservation using tcp_bind() is implemented but
 * allocated pcbs that are not bound can't be killed automatically if wanting
 * to allocate a pcb with higher prio (@see tcp_kill_prio())
 *
 * @return a new tcp_pcb that initially is in state CLOSED
 */
struct tcp_pcb *tcp_new(void)
{
	return tcp_alloc(TCP_PRIO_NORMAL);
}

/**
 * @ingroup tcp_raw
 * Creates a new TCP protocol control block but doesn't
 * place it on any of the TCP PCB lists.
 * The pcb is not put on any list until binding using tcp_bind().
 *
 * @param type IP address type, see @ref dpip_ip_addr_type definitions.
 * If you want to listen to IPv4 and IPv6 (dual-stack) connections,
 * supply @ref IPADDR_TYPE_ANY as argument and bind to @ref IP_ANY_TYPE.
 * @return a new tcp_pcb that initially is in state CLOSED
 */
struct tcp_pcb *tcp_new_ip_type(u8_t type)
{
	struct tcp_pcb *pcb;
	pcb = tcp_alloc(TCP_PRIO_NORMAL);

	if (pcb != NULL) {
		IP_SET_TYPE_VAL(pcb->local_ip, type);
		IP_SET_TYPE_VAL(pcb->remote_ip, type);
	}

	return pcb;
}

/**
 * @ingroup tcp_raw
 * Specifies the program specific state that should be passed to all
 * other callback functions. The "pcb" argument is the current TCP
 * connection control block, and the "arg" argument is the argument
 * that will be passed to the callbacks.
 *
 * @param pcb tcp_pcb to set the callback argument
 * @param arg void pointer argument to pass to callback functions
 */
void tcp_arg(struct tcp_pcb *pcb, void *arg)
{
	/* This function is allowed to be called for both listen pcbs and
	   connection pcbs. */
	if (pcb != NULL) {
		pcb->callback_arg = arg;
	}
}

/**
 * @ingroup tcp_raw
 * Sets the callback function that will be called when new data
 * arrives. The callback function will be passed a NULL mbuf to
 * indicate that the remote host has closed the connection. If the
 * callback function returns ERR_OK or ERR_ABRT it must have
 * freed the mbuf, otherwise it must not have freed it.
 *
 * @param pcb tcp_pcb to set the recv callback
 * @param recv callback function to call for this pcb when data is received
 */
void tcp_recv(struct tcp_pcb *pcb, tcp_recv_fn recv)
{
	if (pcb != NULL) {
		DPIP_ASSERT("invalid socket state for recv callback",
			    pcb->state != LISTEN);
		pcb->recv = recv;
	}
}

/**
 * @ingroup tcp_raw
 * Specifies the callback function that should be called when data has
 * successfully been received (i.e., acknowledged) by the remote
 * host. The len argument passed to the callback function gives the
 * amount bytes that was acknowledged by the last acknowledgment.
 *
 * @param pcb tcp_pcb to set the sent callback
 * @param sent callback function to call for this pcb when data is successfully sent
 */
void tcp_sent(struct tcp_pcb *pcb, tcp_sent_fn sent)
{
	if (pcb != NULL) {
		DPIP_ASSERT("invalid socket state for sent callback",
			    pcb->state != LISTEN);
		pcb->sent = sent;
	}
}

/**
 * @ingroup tcp_raw
 * Used to specify the function that should be called when a fatal error
 * has occurred on the connection.
 *
 * If a connection is aborted because of an error, the application is
 * alerted of this event by the err callback. Errors that might abort a
 * connection are when there is a shortage of memory. The callback
 * function to be called is set using the tcp_err() function.
 *
 * @note The corresponding pcb is already freed when this callback is called!
 *
 * @param pcb tcp_pcb to set the err callback
 * @param err callback function to call for this pcb when a fatal error
 *        has occurred on the connection
 */
void tcp_err(struct tcp_pcb *pcb, tcp_err_fn err)
{
	if (pcb != NULL) {
		DPIP_ASSERT("invalid socket state for err callback",
			    pcb->state != LISTEN);
		pcb->errf = err;
	}
}

/**
 * @ingroup tcp_raw
 * Used for specifying the function that should be called when a
 * LISTENing connection has been connected to another host.
 *
 * @param pcb tcp_pcb to set the accept callback
 * @param accept callback function to call for this pcb when LISTENing
 *        connection has been connected to another host
 */
void tcp_accept(struct tcp_pcb *pcb, tcp_accept_fn accept)
{
	if ((pcb != NULL) && (pcb->state == LISTEN)) {
		pcb->accept = accept;
	}
}

/**
 * @ingroup tcp_raw
 * Specifies the polling interval and the callback function that should
 * be called to poll the application. The interval is specified in
 * number of TCP coarse grained timer shots, which typically occurs
 * twice a second. An interval of 10 means that the application would
 * be polled every 5 seconds.
 *
 * When a connection is idle (i.e., no data is either transmitted or
 * received), dpIP will repeatedly poll the application by calling a
 * specified callback function. This can be used either as a watchdog
 * timer for killing connections that have stayed idle for too long, or
 * as a method of waiting for memory to become available. For instance,
 * if a call to tcp_write() has failed because memory wasn't available,
 * the application may use the polling functionality to call tcp_write()
 * again when the connection has been idle for a while.
 */
void tcp_poll(struct tcp_pcb *pcb, tcp_poll_fn poll, u8_t interval)
{

	DPIP_ERROR("tcp_poll: invalid pcb", pcb != NULL, return);
	DPIP_ASSERT("invalid socket state for poll", pcb->state != LISTEN);

	pcb->poll = poll;
	pcb->pollinterval = interval;
}

/**
 * Purges a TCP PCB. Removes any buffered data and frees the buffer memory
 * (pcb->ooseq, pcb->unsent and pcb->unacked are freed).
 *
 * @param pcb tcp_pcb to purge. The pcb itself is not deallocated!
 */
void tcp_pcb_purge(struct tcp_pcb *pcb)
{
	DPIP_ERROR("tcp_pcb_purge: invalid pcb", pcb != NULL, return);

	if (pcb->state != CLOSED &&
	    pcb->state != TIME_WAIT && pcb->state != LISTEN) {

		DPIP_DEBUGF(TCP_DEBUG, ("tcp_pcb_purge\n"));

		if (pcb->unsent != NULL) {
			DPIP_DEBUGF(TCP_DEBUG,
				    ("tcp_pcb_purge: not all data sent\n"));
		}
		if (pcb->unacked != NULL) {
			DPIP_DEBUGF(TCP_DEBUG,
				    ("tcp_pcb_purge: data left on ->unacked\n"));
		}
#if TCP_QUEUE_OOSEQ
		if (pcb->ooseq != NULL) {
			DPIP_DEBUGF(TCP_DEBUG,
				    ("tcp_pcb_purge: data left on ->ooseq\n"));
			tcp_free_ooseq(pcb);
		}
#endif /* TCP_QUEUE_OOSEQ */

		/* Stop the retransmission timer as it will expect data on unacked
		   queue if it fires */
		pcb->rtime = -1;

		tcp_segs_free(pcb->unsent);
		tcp_segs_free(pcb->unacked);
		pcb->unacked = pcb->unsent = NULL;
	}
}

/**
 * Purges the PCB and removes it from a PCB list. Any delayed ACKs are sent first.
 *
 * @param pcblist PCB list to purge.
 * @param pcb tcp_pcb to purge. The pcb itself is NOT deallocated!
 */
void tcp_pcb_remove(tcp_pcb_list_t pcblist, struct tcp_pcb *pcb)
{
	DPIP_ASSERT("tcp_pcb_remove: invalid pcb", pcb != NULL);
	DPIP_ASSERT("tcp_pcb_remove: invalid pcblist", pcblist != NULL);

	TCP_RMV(pcblist, pcb);

	tcp_pcb_purge(pcb);

	/* if there is an outstanding delayed ACKs, send it */
	if ((pcb->state != TIME_WAIT) &&
	    (pcb->state != LISTEN) && (pcb->flags & TF_ACK_DELAY)) {
		tcp_ack_now(pcb);
		tcp_output(pcb);
	}

	if (pcb->state != LISTEN) {
		DPIP_ASSERT("unsent segments leaking", pcb->unsent == NULL);
		DPIP_ASSERT("unacked segments leaking", pcb->unacked == NULL);
#if TCP_QUEUE_OOSEQ
		DPIP_ASSERT("ooseq segments leaking", pcb->ooseq == NULL);
#endif /* TCP_QUEUE_OOSEQ */
	}

	pcb->state = CLOSED;
	/* reset the local port to prevent the pcb from being 'bound' */
	pcb->local_port = 0;

	DPIP_ASSERT("tcp_pcb_remove: tcp_pcbs_sane()", tcp_pcbs_sane());
}

/**
 * Calculates a new initial sequence number for new connections.
 *
 * @return u32_t pseudo random sequence number
 */
u32_t tcp_next_iss(struct tcp_pcb *pcb)
{
#ifdef DPIP_HOOK_TCP_ISN
	DPIP_ASSERT("tcp_next_iss: invalid pcb", pcb != NULL);
	return DPIP_HOOK_TCP_ISN(&pcb->local_ip, pcb->local_port,
				 &pcb->remote_ip, pcb->remote_port);
#else /* DPIP_HOOK_TCP_ISN */
	static u32_t iss = 6510;

	DPIP_ASSERT("tcp_next_iss: invalid pcb", pcb != NULL);
	DPIP_UNUSED_ARG(pcb);

	iss += tcp_ticks;	/* XXX */
	return iss;
#endif /* DPIP_HOOK_TCP_ISN */
}

#if TCP_CALCULATE_EFF_SEND_MSS
/**
 * Calculates the effective send mss that can be used for a specific IP address
 * by calculating the minimum of TCP_MSS and the mtu (if set) of the target
 * netif (if not NULL).
 */
u16_t
tcp_eff_send_mss_netif(u16_t sendmss, struct netif *outif,
		       const ip_addr_t *dest)
{
	u16_t mss_s;
	u16_t mtu;

	DPIP_UNUSED_ARG(dest);	/* in case IPv6 is disabled */

	DPIP_ASSERT("tcp_eff_send_mss_netif: invalid dst_ip", dest != NULL);

	if (IP_IS_V6(dest)) {
		/* First look in destination cache, to see if there is a Path MTU. */
		mtu = nd6_get_destination_mtu(ip_2_ip6(dest), outif);
	} else {
		if (outif == NULL) {
			return sendmss;
		}
		mtu = outif->mtu;
	}

	if (mtu != 0) {
		u16_t offset;

		if (IP_IS_V6(dest)) {
			offset = IP6_HLEN + TCP_HLEN;
		} else {
			offset = IP_HLEN + TCP_HLEN;
		}

		mss_s = (mtu > offset) ? (u16_t) (mtu - offset) : 0;
		/* RFC 1122, chap 4.2.2.6:
		 * Eff.snd.MSS = min(SendMSS+20, MMS_S) - TCPhdrsize - IPoptionsize
		 * We correct for TCP options in tcp_write(), and don't support IP options.
		 */
		sendmss = RTE_MIN(sendmss, mss_s);
	}
	return sendmss;
}
#endif /* TCP_CALCULATE_EFF_SEND_MSS */

/** Helper function for tcp_netif_ip_addr_changed() that iterates a pcb list */
static void
tcp_netif_ip_addr_changed_pcblist(const ip_addr_t *old_addr,
				  tcp_pcb_list_t pcb_list)
{
	struct tcp_pcb *pcb, *next;
	pcb = TAILQ_FIRST(pcb_list);

	DPIP_ASSERT("tcp_netif_ip_addr_changed_pcblist: invalid old_addr",
		    old_addr != NULL);

	while (pcb != NULL) {
		next = TAILQ_NEXT(pcb, next);
		/* PCB bound to current local interface address? */
		if (ip_addr_eq(&pcb->local_ip, old_addr)) {
			/* this connection must be aborted */
			DPIP_DEBUGF(NETIF_DEBUG | DPIP_DBG_STATE,
				    ("netif_set_ipaddr: aborting TCP pcb %p\n",
				     (void *)pcb));
			tcp_abort(pcb);
		}
		pcb = next;
	}
}

/** This function is called from netif.c when address is changed or netif is removed
 *
 * @param old_addr IP address of the netif before change
 * @param new_addr IP address of the netif after change or NULL if netif has been removed
 */
void
tcp_netif_ip_addr_changed(const ip_addr_t *old_addr, const ip_addr_t *new_addr)
{
	struct tcp_pcb *lpcb;

	if (!ip_addr_isany(old_addr)) {
		tcp_netif_ip_addr_changed_pcblist(old_addr, &tcp_active_pcbs);
		tcp_netif_ip_addr_changed_pcblist(old_addr, &tcp_bound_pcbs);

		if (!ip_addr_isany(new_addr)) {
			/* PCB bound to current local interface address? */
			TAILQ_FOREACH(lpcb, &tcp_listen_pcbs, next) {
				/* PCB bound to current local interface address? */
				if (ip_addr_eq(&lpcb->local_ip, old_addr)) {
					/* The PCB is listening to the old ipaddr and
					 * is set to listen to the new one instead */
					ip_addr_copy(lpcb->local_ip, *new_addr);
				}
			}
		}
	}
}

const char *tcp_debug_state_str(enum tcp_state s)
{
	return tcp_state_str[s];
}

err_t
tcp_tcp_get_tcp_addrinfo(struct tcp_pcb *pcb, int local, ip_addr_t *addr,
			 u16_t *port)
{
	if (pcb) {
		if (local) {
			if (addr) {
				*addr = pcb->local_ip;
			}
			if (port) {
				*port = pcb->local_port;
			}
		} else {
			if (addr) {
				*addr = pcb->remote_ip;
			}
			if (port) {
				*port = pcb->remote_port;
			}
		}
		return ERR_OK;
	}
	return ERR_VAL;
}

#if TCP_QUEUE_OOSEQ
/* Free all ooseq mbufs (and possibly reset SACK state) */
void tcp_free_ooseq(struct tcp_pcb *pcb)
{
	if (pcb->ooseq) {
		tcp_segs_free(pcb->ooseq);
		pcb->ooseq = NULL;
#if DPIP_TCP_SACK_OUT
		memset(pcb->rcv_sacks, 0, sizeof(pcb->rcv_sacks));
#endif /* DPIP_TCP_SACK_OUT */
	}
}
#endif /* TCP_QUEUE_OOSEQ */

#if TCP_DEBUG || TCP_INPUT_DEBUG || TCP_OUTPUT_DEBUG
/**
 * Print a tcp header for debugging purposes.
 *
 * @param tcphdr pointer to a struct tcp_hdr
 */
void tcp_debug_print(struct tcp_hdr *tcphdr)
{
	DPIP_DEBUGF(TCP_DEBUG, ("TCP header:\n"));
	DPIP_DEBUGF(TCP_DEBUG, ("+-------------------------------+\n"));
	DPIP_DEBUGF(TCP_DEBUG,
		    ("|    %5" U16_F "      |    %5" U16_F
		     "      | (src port, dest port)\n", dpip_ntohs(tcphdr->src),
		     dpip_ntohs(tcphdr->dest)));
	DPIP_DEBUGF(TCP_DEBUG, ("+-------------------------------+\n"));
	DPIP_DEBUGF(TCP_DEBUG,
		    ("|           %010" U32_F "          | (seq no)\n",
		     dpip_ntohl(tcphdr->seqno)));
	DPIP_DEBUGF(TCP_DEBUG, ("+-------------------------------+\n"));
	DPIP_DEBUGF(TCP_DEBUG,
		    ("|           %010" U32_F "          | (ack no)\n",
		     dpip_ntohl(tcphdr->ackno)));
	DPIP_DEBUGF(TCP_DEBUG, ("+-------------------------------+\n"));
	DPIP_DEBUGF(TCP_DEBUG,
		    ("| %2" U16_F " |   |%" U16_F "%" U16_F "%" U16_F "%" U16_F
		     "%" U16_F "%" U16_F "|     %5" U16_F
		     "     | (hdrlen, flags (", TCPH_HDRLEN(tcphdr),
		     (u16_t) (TCPH_FLAGS(tcphdr) >> 5 & 1),
		     (u16_t) (TCPH_FLAGS(tcphdr) >> 4 & 1),
		     (u16_t) (TCPH_FLAGS(tcphdr) >> 3 & 1),
		     (u16_t) (TCPH_FLAGS(tcphdr) >> 2 & 1),
		     (u16_t) (TCPH_FLAGS(tcphdr) >> 1 & 1),
		     (u16_t) (TCPH_FLAGS(tcphdr) & 1),
		     dpip_ntohs(tcphdr->wnd)));
	tcp_debug_print_flags(TCPH_FLAGS(tcphdr));
	DPIP_DEBUGF(TCP_DEBUG, ("), win)\n"));
	DPIP_DEBUGF(TCP_DEBUG, ("+-------------------------------+\n"));
	DPIP_DEBUGF(TCP_DEBUG,
		    ("|    0x%04" X16_F "     |     %5" U16_F
		     "     | (chksum, urgp)\n", dpip_ntohs(tcphdr->chksum),
		     dpip_ntohs(tcphdr->urgp)));
	DPIP_DEBUGF(TCP_DEBUG, ("+-------------------------------+\n"));
}

/**
 * Print a tcp state for debugging purposes.
 *
 * @param s enum tcp_state to print
 */
void tcp_debug_print_state(enum tcp_state s)
{
	DPIP_DEBUGF(TCP_DEBUG, ("State: %s\n", tcp_state_str[s]));
}

/**
 * Print tcp flags for debugging purposes.
 *
 * @param flags tcp flags, all active flags are printed
 */
void tcp_debug_print_flags(u8_t flags)
{
	if (flags & TCP_FIN) {
		DPIP_DEBUGF(TCP_DEBUG, ("FIN "));
	}
	if (flags & TCP_SYN) {
		DPIP_DEBUGF(TCP_DEBUG, ("SYN "));
	}
	if (flags & TCP_RST) {
		DPIP_DEBUGF(TCP_DEBUG, ("RST "));
	}
	if (flags & TCP_PSH) {
		DPIP_DEBUGF(TCP_DEBUG, ("PSH "));
	}
	if (flags & TCP_ACK) {
		DPIP_DEBUGF(TCP_DEBUG, ("ACK "));
	}
	if (flags & TCP_URG) {
		DPIP_DEBUGF(TCP_DEBUG, ("URG "));
	}
	if (flags & TCP_ECE) {
		DPIP_DEBUGF(TCP_DEBUG, ("ECE "));
	}
	if (flags & TCP_CWR) {
		DPIP_DEBUGF(TCP_DEBUG, ("CWR "));
	}
	DPIP_DEBUGF(TCP_DEBUG, ("\n"));
}

/**
 * Print all tcp_pcbs in every list for debugging purposes.
 */
void tcp_debug_print_pcbs(void)
{
	struct tcp_pcb *pcb;

	DPIP_DEBUGF(TCP_DEBUG, ("Active PCB states:\n"));
	TAILQ_FOREACH(pcb, &tcp_active_pcbs, next) {
		DPIP_DEBUGF(TCP_DEBUG,
			    ("Local port %" U16_F ", foreign port %" U16_F
			     " snd_nxt %" U32_F " rcv_nxt %" U32_F " ",
			     pcb->local_port, pcb->remote_port, pcb->snd_nxt,
			     pcb->rcv_nxt));
		tcp_debug_print_state(pcb->state);
	}

	DPIP_DEBUGF(TCP_DEBUG, ("Listen PCB states:\n"));
	TAILQ_FOREACH(pcb, &tcp_listen_pcbs, next) {
		DPIP_DEBUGF(TCP_DEBUG,
			    ("Local port %" U16_F " ", pcb->local_port));
		tcp_debug_print_state(pcb->state);
	}

	DPIP_DEBUGF(TCP_DEBUG, ("TIME-WAIT PCB states:\n"));
	TAILQ_FOREACH(pcb, &tcp_tw_pcbs, next) {
		DPIP_DEBUGF(TCP_DEBUG,
			    ("Local port %" U16_F ", foreign port %" U16_F
			     " snd_nxt %" U32_F " rcv_nxt %" U32_F " ",
			     pcb->local_port, pcb->remote_port, pcb->snd_nxt,
			     pcb->rcv_nxt));
		tcp_debug_print_state(pcb->state);
	}
}

/**
 * Check state consistency of the tcp_pcb lists.
 */
s16_t tcp_pcbs_sane(void)
{
	struct tcp_pcb *pcb;
	TAILQ_FOREACH(pcb, &tcp_active_pcbs, next) {
		DPIP_ASSERT("tcp_pcbs_sane: active pcb->state != CLOSED",
			    pcb->state != CLOSED);
		DPIP_ASSERT("tcp_pcbs_sane: active pcb->state != LISTEN",
			    pcb->state != LISTEN);
		DPIP_ASSERT("tcp_pcbs_sane: active pcb->state != TIME-WAIT",
			    pcb->state != TIME_WAIT);
	}
	TAILQ_FOREACH(pcb, &tcp_tw_pcbs, next) {
		DPIP_ASSERT("tcp_pcbs_sane: tw pcb->state == TIME-WAIT",
			    pcb->state == TIME_WAIT);
	}
	return 1;
}
#endif /* TCP_DEBUG */

#endif /* DPIP_TCP */
