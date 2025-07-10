/**
 * @file
 * Transmission Control Protocol, outgoing traffic
 *
 * The output functions of TCP.
 *
 * There are two distinct ways for TCP segments to get sent:
 * - queued data: these are segments transferring data or segments containing
 *   SYN or FIN (which both count as one sequence number). They are created as
 *   struct @ref pbuf together with a struct tcp_seg and enqueue to the
 *   unsent list of the pcb. They are sent by tcp_output:
 *   - @ref tcp_write : creates data segments
 *   - @ref tcp_split_unsent_seg : splits a data segment
 *   - @ref tcp_enqueue_flags : creates SYN-only or FIN-only segments
 *   - @ref tcp_output / tcp_output_segment : finalize the tcp header
 *      (e.g. sequence numbers, options, checksum) and output to IP
 *   - the various tcp_rexmit functions shuffle around segments between the
 *     unsent an unacked lists to retransmit them
 *   - tcp_create_segment and tcp_pbuf_prealloc allocate pbuf and
 *     segment for these functions
 * - direct send: these segments don't contain data but control the connection
 *   behaviour. They are created as pbuf only and sent directly without
 *   enqueueing them:
 *   - @ref tcp_send_empty_ack sends an ACK-only segment
 *   - @ref tcp_rst sends a RST segment
 *   - @ref tcp_keepalive sends a keepalive segment
 *   - @ref tcp_zero_window_probe sends a window probe segment
 *   - tcp_output_alloc_header allocates a header-only pbuf for these functions
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

#include "dpip/priv/tcp_priv.h"
#include "dpip/def.h"
#include "dpip/memp.h"
#include "dpip/ip_addr.h"
#include "dpip/netif.h"
#include "dpip/inet_chksum.h"
#include "dpip/stats.h"
#include "dpip/ip6.h"
#include "dpip/ip6_addr.h"
#if DPIP_TCP_TIMESTAMPS
#include "dpip/sys.h"
#endif

#include <string.h>

/* Allow to add custom TCP header options by defining this hook */
#ifdef DPIP_HOOK_TCP_OUT_TCPOPT_LENGTH
#define DPIP_TCP_OPT_LENGTH_SEGMENT(flags, pcb) DPIP_HOOK_TCP_OUT_TCPOPT_LENGTH(pcb, DPIP_TCP_OPT_LENGTH(flags))
#else
#define DPIP_TCP_OPT_LENGTH_SEGMENT(flags, pcb) DPIP_TCP_OPT_LENGTH(flags)
#endif

#define TCP_DATA_COPY(dst, src, len, seg)                     MEMCPY(dst, src, len)
#define TCP_DATA_COPY2(dst, src, len, chksum, chksum_swapped) MEMCPY(dst, src, len)

/* Forward declarations.*/
static err_t tcp_output_segment(struct tcp_seg *seg, struct tcp_pcb *pcb,
				struct netif *netif);
static err_t tcp_output_control_segment_netif(const struct tcp_pcb *pcb,
					      struct rte_mbuf *p,
					      const ip_addr_t * src,
					      const ip_addr_t * dst,
					      struct netif *netif);

/* tcp_route: common code that returns a fixed bound netif or calls ip_route */
static struct netif *tcp_route(const struct tcp_pcb *pcb, const ip_addr_t *src,
			       const ip_addr_t *dst)
{
	DPIP_UNUSED_ARG(src);	/* in case IPv4-only and source-based routing is disabled */

	if ((pcb != NULL) && (pcb->netif_idx != NETIF_NO_INDEX)) {
		return netif_get_by_index(pcb->netif_idx);
	} else {
		return ip_route(src, dst);
	}
}

/**
 * Create a TCP segment with prefilled header.
 *
 * Called by @ref tcp_write, @ref tcp_enqueue_flags and @ref tcp_split_unsent_seg
 *
 * @param pcb Protocol control block for the TCP connection.
 * @param p pbuf that is used to hold the TCP header.
 * @param hdrflags TCP flags for header.
 * @param seqno TCP sequence number of this packet
 * @param optflags options to include in TCP header
 * @return a new tcp_seg pointing to p, or NULL.
 * The TCP header is filled in except ackno and wnd.
 * p is freed on failure.
 */
static struct tcp_seg *tcp_create_segment(const struct tcp_pcb *pcb,
					  struct rte_mbuf *p, u8_t hdrflags,
					  u32_t seqno, u8_t optflags)
{
	struct tcp_seg *seg;
	u8_t optlen;

	DPIP_ASSERT("tcp_create_segment: invalid pcb", pcb != NULL);
	DPIP_ASSERT("tcp_create_segment: invalid pbuf", p != NULL);

	optlen = DPIP_TCP_OPT_LENGTH_SEGMENT(optflags, pcb);

	if ((seg = (struct tcp_seg *)memp_malloc(MEMP_TCP_SEG)) == NULL) {
		DPIP_DEBUGF(TCP_OUTPUT_DEBUG | DPIP_DBG_LEVEL_SERIOUS,
			    ("tcp_create_segment: no memory.\n"));
		rte_pktmbuf_free(p);
		return NULL;
	}
	seg->flags = optflags;
	seg->next = NULL;
	seg->p = p;
	DPIP_ASSERT("p->tot_len >= optlen", rte_pktmbuf_pkt_len(p) >= optlen);
	seg->len = rte_pktmbuf_pkt_len(p) - optlen;

	/* build TCP header */
	if (rte_pktmbuf_prepend(p, TCP_HLEN) == NULL) {
		DPIP_DEBUGF(TCP_OUTPUT_DEBUG | DPIP_DBG_LEVEL_SERIOUS,
			    ("tcp_create_segment: no room for TCP header in pbuf.\n"));
		TCP_STATS_INC(tcp.err);
		tcp_seg_free(seg);
		return NULL;
	}
	seg->tcphdr = rte_pktmbuf_mtod(seg->p, struct tcp_hdr *);
	seg->tcphdr->src = dpip_htons(pcb->local_port);
	seg->tcphdr->dest = dpip_htons(pcb->remote_port);
	seg->tcphdr->seqno = dpip_htonl(seqno);
	/* ackno is set in tcp_output */
	TCPH_HDRLEN_FLAGS_SET(seg->tcphdr, (5 + optlen / 4), hdrflags);
	/* wnd and chksum are set in tcp_output */
	seg->tcphdr->urgp = 0;
	return seg;
}

/**
 * Allocate a PBUF_RAM pbuf, perhaps with extra space at the end.
 *
 * This function is like pbuf_alloc(layer, length, PBUF_RAM) except
 * there may be extra bytes available at the end.
 *
 * Called by @ref tcp_write
 *
 * @param layer flag to define header size.
 * @param length size of the pbuf's payload.
 * @param max_length maximum usable size of payload+oversize.
 * @param oversize pointer to a u16_t that will receive the number of usable tail bytes.
 * @param pcb The TCP connection that will enqueue the pbuf.
 * @param apiflags API flags given to tcp_write.
 * @param first_seg true when this pbuf will be used in the first enqueued segment.
 */

#define tcp_pbuf_prealloc(layer, length, mx, os, pcb, api, fst) pbuf_alloc((layer), (length), PBUF_RAM)

/** Checks if tcp_write is allowed or not (checks state, snd_buf and snd_queuelen).
 *
 * @param pcb the tcp pcb to check for
 * @param len length of data to send (checked against snd_buf)
 * @return ERR_OK if tcp_write is allowed to proceed, another err_t otherwise
 */
static err_t tcp_write_checks(struct tcp_pcb *pcb, u16_t len)
{
	DPIP_ASSERT("tcp_write_checks: invalid pcb", pcb != NULL);

	/* connection is in invalid state for data transmission? */
	if ((pcb->state != ESTABLISHED) &&
	    (pcb->state != CLOSE_WAIT) &&
	    (pcb->state != SYN_SENT) && (pcb->state != SYN_RCVD)) {
		DPIP_DEBUGF(TCP_OUTPUT_DEBUG | DPIP_DBG_STATE |
			    DPIP_DBG_LEVEL_SEVERE,
			    ("tcp_write() called in invalid state\n"));
		return ERR_CONN;
	} else if (len == 0) {
		return ERR_OK;
	}

	/* fail on too much data */
	if (len > pcb->snd_buf) {
		DPIP_DEBUGF(TCP_OUTPUT_DEBUG | DPIP_DBG_LEVEL_SEVERE,
			    ("tcp_write: too much data (len=%" U16_F
			     " > snd_buf=%" TCPWNDSIZE_F ")\n", len,
			     pcb->snd_buf));
		tcp_set_flags(pcb, TF_NAGLEMEMERR);
		return ERR_MEM;
	}

	DPIP_DEBUGF(TCP_QLEN_DEBUG,
		    ("tcp_write: queuelen: %" TCPWNDSIZE_F "\n",
		     (tcpwnd_size_t) pcb->snd_queuelen));

	/* If total number of pbufs on the unsent/unacked queues exceeds the
	 * configured maximum, return an error */
	/* check for configured max queuelen and possible overflow */
	if (pcb->snd_queuelen >=
	    RTE_MIN((unsigned)TCP_SND_QUEUELEN,
		    (TCP_SNDQUEUELEN_OVERFLOW + 1))) {
		DPIP_DEBUGF(TCP_OUTPUT_DEBUG | DPIP_DBG_LEVEL_SEVERE,
			    ("tcp_write: too long queue %" U16_F " (max %" U16_F
			     ")\n", pcb->snd_queuelen,
			     (u16_t) TCP_SND_QUEUELEN));
		TCP_STATS_INC(tcp.memerr);
		tcp_set_flags(pcb, TF_NAGLEMEMERR);
		return ERR_MEM;
	}
	if (pcb->snd_queuelen != 0) {
		DPIP_ASSERT
		    ("tcp_write: pbufs on queue => at least one queue non-empty",
		     pcb->unacked != NULL || pcb->unsent != NULL);
	} else {
		DPIP_ASSERT("tcp_write: no pbufs on queue => both queues empty",
			    pcb->unacked == NULL && pcb->unsent == NULL);
	}
	return ERR_OK;
}

/**
 * @ingroup tcp_raw
 * Write data for sending (but does not send it immediately).
 *
 * It waits in the expectation of more data being sent soon (as
 * it can send them more efficiently by combining them together).
 * To prompt the system to send data now, call tcp_output() after
 * calling tcp_write().
 *
 * This function enqueues the data pointed to by the argument dataptr. The length of
 * the data is passed as the len parameter. The apiflags can be one or more of:
 * - TCP_WRITE_FLAG_COPY: indicates whether the new memory should be allocated
 *   for the data to be copied into. If this flag is not given, no new memory
 *   should be allocated and the data should only be referenced by pointer. This
 *   also means that the memory behind dataptr must not change until the data is
 *   ACKed by the remote host
 * - TCP_WRITE_FLAG_MORE: indicates that more data follows. If this is omitted,
 *   the PSH flag is set in the last segment created by this call to tcp_write.
 *   If this flag is given, the PSH flag is not set.
 *
 * The tcp_write() function will fail and return ERR_MEM if the length
 * of the data exceeds the current send buffer size or if the length of
 * the queue of outgoing segment is larger than the upper limit defined
 * in opts.h. The number of bytes available in the output queue can
 * be retrieved with the tcp_sndbuf() function.
 *
 * The proper way to use this function is to call the function with at
 * most tcp_sndbuf() bytes of data. If the function returns ERR_MEM,
 * the application should wait until some of the currently enqueued
 * data has been successfully received by the other host and try again.
 *
 * @param pcb Protocol control block for the TCP connection to enqueue data for.
 * @param arg Pointer to the data to be enqueued for sending.
 * @param len Data length in bytes
 * @param apiflags combination of following flags :
 * - TCP_WRITE_FLAG_COPY (0x01) data will be copied into memory belonging to the stack
 * - TCP_WRITE_FLAG_MORE (0x02) for TCP connection, PSH flag will not be set on last segment sent,
 * @return ERR_OK if enqueued, another err_t on error
 */
err_t tcp_write(struct tcp_pcb *pcb, const void *arg, u16_t len, u8_t apiflags)
{
	struct rte_mbuf *concat_p = NULL;
	struct tcp_seg *last_unsent = NULL, *seg = NULL, *prev_seg =
	    NULL, *queue = NULL;
	u16_t pos = 0;		/* position in 'arg' data */
	u16_t queuelen;
	u8_t optlen;
	u8_t optflags = 0;
	u16_t extendlen = 0;
	err_t err;
	u16_t mss_local;

	DPIP_ERROR("tcp_write: invalid pcb", pcb != NULL, return ERR_ARG);

	/* don't allocate segments bigger than half the maximum window we ever received */
	mss_local = RTE_MIN(pcb->mss, TCPWND_MIN16(pcb->snd_wnd_max / 2));
	mss_local = mss_local ? mss_local : pcb->mss;

	DPIP_DEBUGF(TCP_OUTPUT_DEBUG,
		    ("tcp_write(pcb=%p, data=%p, len=%" U16_F ", apiflags=%"
		     U16_F ")\n", (void *)pcb, arg, len, (u16_t) apiflags));
	DPIP_ERROR("tcp_write: arg == NULL (programmer violates API)",
		   arg != NULL, return ERR_ARG;
	    );

	err = tcp_write_checks(pcb, len);
	if (err != ERR_OK) {
		return err;
	}
	queuelen = pcb->snd_queuelen;

#if DPIP_TCP_TIMESTAMPS
	if ((pcb->flags & TF_TIMESTAMP)) {
		/* Make sure the timestamp option is only included in data segments if we
		   agreed about it with the remote host. */
		optflags = TF_SEG_OPTS_TS;
		optlen = DPIP_TCP_OPT_LENGTH_SEGMENT(TF_SEG_OPTS_TS, pcb);
		/* ensure that segments can hold at least one data byte... */
		mss_local = RTE_MAX(mss_local, DPIP_TCP_OPT_LEN_TS + 1);
	} else
#endif /* DPIP_TCP_TIMESTAMPS */
	{
		optlen = DPIP_TCP_OPT_LENGTH_SEGMENT(0, pcb);
	}

	/*
	 * TCP segmentation is done in three phases with increasing complexity:
	 *
	 * 1. Copy data directly into an oversized pbuf.
	 * 2. Chain a new pbuf to the end of pcb->unsent.
	 * 3. Create new segments.
	 *
	 * We may run out of memory at any point. In that case we must
	 * return ERR_MEM and not change anything in pcb. Therefore, all
	 * changes are recorded in local variables and committed at the end
	 * of the function. Some pcb fields are maintained in local copies:
	 *
	 * queuelen = pcb->snd_queuelen
	 * oversize = pcb->unsent_oversize
	 *
	 * These variables are set consistently by the phases:
	 *
	 * seg points to the last segment tampered with.
	 *
	 * pos records progress as data is segmented.
	 */

	/* Find the tail of the unsent queue. */
	if (pcb->unsent != NULL) {
		u16_t space;
		u16_t unsent_optlen;

		/* @todo: this could be sped up by keeping last_unsent in the pcb */
		for (last_unsent = pcb->unsent; last_unsent->next != NULL;
		     last_unsent = last_unsent->next) ;

		/* Usable space at the end of the last unsent segment */
		unsent_optlen =
		    DPIP_TCP_OPT_LENGTH_SEGMENT(last_unsent->flags, pcb);
		DPIP_ASSERT("mss_local is too small",
			    mss_local >= last_unsent->len + unsent_optlen);
		space = mss_local - (last_unsent->len + unsent_optlen);

		/*
		 * Phase 1: Copy data directly into an oversized pbuf.
		 *
		 * The number of bytes copied is recorded in the oversize_used
		 * variable. The actual copying is done at the bottom of the
		 * function.
		 */

		/*
		 * Phase 2: Chain a new pbuf to the end of pcb->unsent.
		 *
		 * As an exception when NOT copying the data, if the given data buffer
		 * directly follows the last unsent data buffer in memory, extend the last
		 * ROM pbuf reference to the buffer, thus saving a ROM pbuf allocation.
		 *
		 * We don't extend segments containing SYN/FIN flags or options
		 * (len==0). The new pbuf is kept in concat_p and pbuf_cat'ed at
		 * the end.
		 */
		if ((pos < len) && (space > 0) && (last_unsent->len > 0)) {
			u16_t seglen = RTE_MIN(space, len - pos);
			seg = last_unsent;

			/* Create a pbuf with a copy or reference to seglen bytes. We
			 * can use PBUF_RAW here since the data appears in the middle of
			 * a segment. A header will never be prepended. */
			if (apiflags & TCP_WRITE_FLAG_COPY) {
				/* Data is copied */
				if ((concat_p =
				     tcp_pbuf_prealloc(PBUF_RAW, seglen, space,
						       &oversize, pcb, apiflags,
						       1)) == NULL) {
					DPIP_DEBUGF(TCP_OUTPUT_DEBUG |
						    DPIP_DBG_LEVEL_SERIOUS,
						    ("tcp_write : could not allocate memory for pbuf copy size %"
						     U16_F "\n", seglen));
					goto memerr;
				}
				TCP_DATA_COPY2(rte_pktmbuf_mtod
					       (concat_p, u8_t *),
					       (const u8_t *)arg + pos, seglen,
					       &concat_chksum,
					       &concat_chksum_swapped);
				queuelen += concat_p->nb_segs;
			} else {

				abort();
#if 0
				/* Data is not copied */
				/* If the last unsent pbuf is of type PBUF_ROM, try to extend it. */
				struct rte_mbuf *p;
				for (p = last_unsent->p; p->next != NULL;
				     p = p->next) ;
				if (((p->
				      type_internal &
				      (PBUF_TYPE_FLAG_STRUCT_DATA_CONTIGUOUS |
				       PBUF_TYPE_FLAG_DATA_VOLATILE)) == 0)
				    && (const u8_t *)p->payload + p->len ==
				    (const u8_t *)arg) {
					DPIP_ASSERT
					    ("tcp_write: ROM pbufs cannot be oversized",
					     pos == 0);
					extendlen = seglen;
				} else {
					if ((concat_p =
					     pbuf_alloc(PBUF_RAW, seglen,
							PBUF_ROM)) == NULL) {
						DPIP_DEBUGF(TCP_OUTPUT_DEBUG |
							    DPIP_DBG_LEVEL_SERIOUS,
							    ("tcp_write: could not allocate memory for zero-copy pbuf\n"));
						goto memerr;
					}
					/* reference the non-volatile payload data */
					concat_p->payload = (u8_t *) arg + pos;
					queuelen += pbuf_clen(concat_p);
				}
#endif
			}

			pos += seglen;
		}
	}

	/*
	 * Phase 3: Create new segments.
	 *
	 * The new segments are chained together in the local 'queue'
	 * variable, ready to be appended to pcb->unsent.
	 */
	while (pos < len) {
		struct rte_mbuf *p;
		u16_t left = len - pos;
		u16_t max_len = mss_local - optlen;
		u16_t seglen = RTE_MIN(left, max_len);

		if (apiflags & TCP_WRITE_FLAG_COPY) {
			/* If copy is set, memory should be allocated and data copied
			 * into pbuf */
			if ((p =
			     tcp_pbuf_prealloc(PBUF_TRANSPORT, seglen + optlen,
					       mss_local, &oversize, pcb,
					       apiflags,
					       queue == NULL)) == NULL) {
				DPIP_DEBUGF(TCP_OUTPUT_DEBUG |
					    DPIP_DBG_LEVEL_SERIOUS,
					    ("tcp_write : could not allocate memory for pbuf copy size %"
					     U16_F "\n", seglen));
				goto memerr;
			}
			DPIP_ASSERT
			    ("tcp_write: check that first pbuf can hold the complete seglen",
			     (rte_pktmbuf_data_len(p) >= seglen));
			TCP_DATA_COPY2(rte_pktmbuf_mtod(p, char *) + optlen,
				       (const u8_t *)arg + pos, seglen, &chksum,
				       &chksum_swapped);
		} else {

			abort();
#if 0
			/* Copy is not set: First allocate a pbuf for holding the data.
			 * Since the referenced data is available at least until it is
			 * sent out on the link (as it has to be ACKed by the remote
			 * party) we can safely use PBUF_ROM instead of PBUF_REF here.
			 */
			struct rte_mbuf *p2;
			if ((p2 =
			     pbuf_alloc(PBUF_TRANSPORT, seglen,
					PBUF_ROM)) == NULL) {
				DPIP_DEBUGF(TCP_OUTPUT_DEBUG |
					    DPIP_DBG_LEVEL_SERIOUS,
					    ("tcp_write: could not allocate memory for zero-copy pbuf\n"));
				goto memerr;
			}
			/* reference the non-volatile payload data */
			p2->payload = (u8_t *) arg + pos;

			/* Second, allocate a pbuf for the headers. */
			if ((p =
			     pbuf_alloc(PBUF_TRANSPORT, optlen,
					PBUF_RAM)) == NULL) {
				/* If allocation fails, we have to deallocate the data pbuf as
				 * well. */
				rte_pktmbuf_free(p2);
				DPIP_DEBUGF(TCP_OUTPUT_DEBUG |
					    DPIP_DBG_LEVEL_SERIOUS,
					    ("tcp_write: could not allocate memory for header pbuf\n"));
				goto memerr;
			}
			/* Concatenate the headers and data pbufs together. */
			pbuf_cat(p /*header */ , p2 /*data */ );
#endif
		}

		queuelen += p->nb_segs;

		/* Now that there are more segments queued, we check again if the
		 * length of the queue exceeds the configured maximum or
		 * overflows. */
		if (queuelen >
		    RTE_MIN((unsigned)TCP_SND_QUEUELEN,
			    TCP_SNDQUEUELEN_OVERFLOW)) {
			DPIP_DEBUGF(TCP_OUTPUT_DEBUG | DPIP_DBG_LEVEL_SERIOUS,
				    ("tcp_write: queue too long %" U16_F
				     " (%d)\n", queuelen,
				     (int)TCP_SND_QUEUELEN));
			rte_pktmbuf_free(p);
			goto memerr;
		}

		if ((seg =
		     tcp_create_segment(pcb, p, 0, pcb->snd_lbb + pos,
					optflags)) == NULL) {
			goto memerr;
		}

		/* first segment of to-be-queued data? */
		if (queue == NULL) {
			queue = seg;
		} else {
			/* Attach the segment to the end of the queued segments */
			DPIP_ASSERT("prev_seg != NULL", prev_seg != NULL);
			prev_seg->next = seg;
		}
		/* remember last segment of to-be-queued data for next iteration */
		prev_seg = seg;

		DPIP_DEBUGF(TCP_OUTPUT_DEBUG | DPIP_DBG_TRACE,
			    ("tcp_write: queueing %" U32_F ":%" U32_F "\n",
			     dpip_ntohl(seg->tcphdr->seqno),
			     dpip_ntohl(seg->tcphdr->seqno) + TCP_TCPLEN(seg)));

		pos += seglen;
	}

	/*
	 * All three segmentation phases were successful. We can commit the
	 * transaction.
	 */

	/*
	 * Phase 1: If data has been added to the preallocated tail of
	 * last_unsent, we update the length fields of the pbuf chain.
	 */

	/*
	 * Phase 2: concat_p can be concatenated onto last_unsent->p, unless we
	 * determined that the last ROM pbuf can be extended to include the new data.
	 */
	if (concat_p != NULL) {
		DPIP_ASSERT
		    ("tcp_write: cannot concatenate when pcb->unsent is empty",
		     (last_unsent != NULL));
		// TODO: check ret
		rte_pktmbuf_chain(last_unsent->p, concat_p);
		last_unsent->len += rte_pktmbuf_pkt_len(concat_p);
	} else if (extendlen > 0) {
		struct rte_mbuf *p;
		DPIP_ASSERT
		    ("tcp_write: extension of reference requires reference",
		     last_unsent != NULL && last_unsent->p != NULL);
		for (p = last_unsent->p; p->next != NULL; p = p->next) {
			rte_pktmbuf_pkt_len(p) += extendlen;
		}
		rte_pktmbuf_pkt_len(p) += extendlen;
		rte_pktmbuf_data_len(p) += extendlen;
		last_unsent->len += extendlen;
	}

	/*
	 * Phase 3: Append queue to pcb->unsent. Queue may be NULL, but that
	 * is harmless
	 */
	if (last_unsent == NULL) {
		pcb->unsent = queue;
	} else {
		last_unsent->next = queue;
	}

	/*
	 * Finally update the pcb state.
	 */
	pcb->snd_lbb += len;
	pcb->snd_buf -= len;
	pcb->snd_queuelen = queuelen;

	DPIP_DEBUGF(TCP_QLEN_DEBUG, ("tcp_write: %" S16_F " (after enqueued)\n",
				     pcb->snd_queuelen));
	if (pcb->snd_queuelen != 0) {
		DPIP_ASSERT("tcp_write: valid queue length",
			    pcb->unacked != NULL || pcb->unsent != NULL);
	}

	/* Set the PSH flag in the last segment that we enqueued. */
	if (seg != NULL && seg->tcphdr != NULL
	    && ((apiflags & TCP_WRITE_FLAG_MORE) == 0)) {
		TCPH_SET_FLAG(seg->tcphdr, TCP_PSH);
	}

	return ERR_OK;
 memerr:
	tcp_set_flags(pcb, TF_NAGLEMEMERR);
	TCP_STATS_INC(tcp.memerr);

	if (concat_p != NULL) {
		rte_pktmbuf_free(concat_p);
	}
	if (queue != NULL) {
		tcp_segs_free(queue);
	}
	if (pcb->snd_queuelen != 0) {
		DPIP_ASSERT("tcp_write: valid queue length",
			    pcb->unacked != NULL || pcb->unsent != NULL);
	}
	DPIP_DEBUGF(TCP_QLEN_DEBUG | DPIP_DBG_STATE,
		    ("tcp_write: %" S16_F " (with mem err)\n",
		     pcb->snd_queuelen));
	return ERR_MEM;
}

/**
 * Split segment on the head of the unsent queue.  If return is not
 * ERR_OK, existing head remains intact
 *
 * The split is accomplished by creating a new TCP segment and pbuf
 * which holds the remainder payload after the split.  The original
 * pbuf is trimmed to new length.  This allows splitting of read-only
 * pbufs
 *
 * @param pcb the tcp_pcb for which to split the unsent head
 * @param split the amount of payload to remain in the head
 */
err_t tcp_split_unsent_seg(struct tcp_pcb *pcb, u16_t split)
{
	struct tcp_seg *seg = NULL, *useg = NULL;
	struct rte_mbuf *p = NULL;
	u8_t optlen;
	u8_t optflags;
	u8_t split_flags;
	u8_t remainder_flags;
	u16_t remainder;
	u16_t offset;

	DPIP_ASSERT("tcp_split_unsent_seg: invalid pcb", pcb != NULL);

	useg = pcb->unsent;
	if (useg == NULL) {
		return ERR_MEM;
	}

	if (split == 0) {
		DPIP_ASSERT("Can't split segment into length 0", 0);
		return ERR_VAL;
	}

	if (useg->len <= split) {
		return ERR_OK;
	}

	DPIP_ASSERT("split <= mss", split <= pcb->mss);
	DPIP_ASSERT("useg->len > 0", useg->len > 0);

	/* We should check that we don't exceed TCP_SND_QUEUELEN but we need
	 * to split this packet so we may actually exceed the max value by
	 * one!
	 */
	DPIP_DEBUGF(TCP_QLEN_DEBUG,
		    ("tcp_enqueue: split_unsent_seg: %u\n",
		     (unsigned int)pcb->snd_queuelen));

	optflags = useg->flags;
	optlen = DPIP_TCP_OPT_LENGTH(optflags);
	remainder = useg->len - split;

	/* Create new pbuf for the remainder of the split */
	p = pbuf_alloc(PBUF_TRANSPORT, remainder + optlen, PBUF_RAM);
	if (p == NULL) {
		DPIP_DEBUGF(TCP_OUTPUT_DEBUG | DPIP_DBG_LEVEL_SERIOUS,
			    ("tcp_split_unsent_seg: could not allocate memory for pbuf remainder %u\n",
			     remainder));
		goto memerr;
	}

	/* Offset into the original pbuf is past TCP/IP headers, options, and split amount */
	offset = rte_pktmbuf_pkt_len(useg->p) - useg->len + split;
	/* Copy remainder into new pbuf, headers and options will not be filled out */
	if (pbuf_copy_partial
	    (useg->p, rte_pktmbuf_mtod(p, u8_t *) + optlen, remainder,
	     offset) != remainder) {
		DPIP_DEBUGF(TCP_OUTPUT_DEBUG | DPIP_DBG_LEVEL_SERIOUS,
			    ("tcp_split_unsent_seg: could not copy pbuf remainder %u\n",
			     remainder));
		goto memerr;
	}

	/* Options are created when calling tcp_output() */

	/* Migrate flags from original segment */
	split_flags = TCPH_FLAGS(useg->tcphdr);
	remainder_flags = 0;	/* ACK added in tcp_output() */

	if (split_flags & TCP_PSH) {
		split_flags &= ~TCP_PSH;
		remainder_flags |= TCP_PSH;
	}
	if (split_flags & TCP_FIN) {
		split_flags &= ~TCP_FIN;
		remainder_flags |= TCP_FIN;
	}
	/* SYN should be left on split, RST should not be present with data */

	seg =
	    tcp_create_segment(pcb, p, remainder_flags,
			       dpip_ntohl(useg->tcphdr->seqno) + split,
			       optflags);
	if (seg == NULL) {
		p = NULL;	/* Freed by tcp_create_segment */
		DPIP_DEBUGF(TCP_OUTPUT_DEBUG | DPIP_DBG_LEVEL_SERIOUS,
			    ("tcp_split_unsent_seg: could not create new TCP segment\n"));
		goto memerr;
	}

	/* Remove this segment from the queue since trimming it may free pbufs */
	pcb->snd_queuelen -= useg->p->nb_segs;

	/* Trim the original pbuf into our split size.  At this point our remainder segment must be setup
	   successfully because we are modifying the original segment */
	pbuf_realloc(useg->p, rte_pktmbuf_pkt_len(useg->p) - remainder);

	useg->len -= remainder;
	TCPH_SET_FLAG(useg->tcphdr, split_flags);

	/* Add back to the queue with new trimmed pbuf */
	pcb->snd_queuelen += useg->p->nb_segs;

	/* Update number of segments on the queues. Note that length now may
	 * exceed TCP_SND_QUEUELEN! We don't have to touch pcb->snd_buf
	 * because the total amount of data is constant when packet is split */
	pcb->snd_queuelen += seg->p->nb_segs;

	/* Finally insert remainder into queue after split (which stays head) */
	seg->next = useg->next;
	useg->next = seg;

	return ERR_OK;
 memerr:
	TCP_STATS_INC(tcp.memerr);

	DPIP_ASSERT("seg == NULL", seg == NULL);
	if (p != NULL) {
		rte_pktmbuf_free(p);
	}

	return ERR_MEM;
}

/**
 * Called by tcp_close() to send a segment including FIN flag but not data.
 * This FIN may be added to an existing segment or a new, otherwise empty
 * segment is enqueued.
 *
 * @param pcb the tcp_pcb over which to send a segment
 * @return ERR_OK if sent, another err_t otherwise
 */
err_t tcp_send_fin(struct tcp_pcb *pcb)
{
	DPIP_ASSERT("tcp_send_fin: invalid pcb", pcb != NULL);

	/* first, try to add the fin to the last unsent segment */
	if (pcb->unsent != NULL) {
		struct tcp_seg *last_unsent;
		for (last_unsent = pcb->unsent; last_unsent->next != NULL;
		     last_unsent = last_unsent->next) ;

		if ((TCPH_FLAGS(last_unsent->tcphdr) &
		     (TCP_SYN | TCP_FIN | TCP_RST)) == 0) {
			/* no SYN/FIN/RST flag in the header, we can add the FIN flag */
			TCPH_SET_FLAG(last_unsent->tcphdr, TCP_FIN);
			tcp_set_flags(pcb, TF_FIN);
			return ERR_OK;
		}
	}
	/* no data, no length, flags, copy=1, no optdata */
	return tcp_enqueue_flags(pcb, TCP_FIN);
}

/**
 * Enqueue SYN or FIN for transmission.
 *
 * Called by @ref tcp_connect, tcp_listen_input, and @ref tcp_close
 * (via @ref tcp_send_fin)
 *
 * @param pcb Protocol control block for the TCP connection.
 * @param flags TCP header flags to set in the outgoing segment.
 */
err_t tcp_enqueue_flags(struct tcp_pcb *pcb, u8_t flags)
{
	struct rte_mbuf *p;
	struct tcp_seg *seg;
	u8_t optflags = 0;
	u8_t optlen = 0;

	DPIP_ASSERT
	    ("tcp_enqueue_flags: need either TCP_SYN or TCP_FIN in flags (programmer violates API)",
	     (flags & (TCP_SYN | TCP_FIN)) != 0);
	DPIP_ASSERT("tcp_enqueue_flags: invalid pcb", pcb != NULL);

	DPIP_DEBUGF(TCP_QLEN_DEBUG,
		    ("tcp_enqueue_flags: queuelen: %" U16_F "\n",
		     (u16_t) pcb->snd_queuelen));

	/* No need to check pcb->snd_queuelen if only SYN or FIN are allowed! */

	/* Get options for this segment. This is a special case since this is the
	   only place where a SYN can be sent. */
	if (flags & TCP_SYN) {
		optflags = TF_SEG_OPTS_MSS;
#if DPIP_WND_SCALE
		if ((pcb->state != SYN_RCVD) || (pcb->flags & TF_WND_SCALE)) {
			/* In a <SYN,ACK> (sent in state SYN_RCVD), the window scale option may only
			   be sent if we received a window scale option from the remote host. */
			optflags |= TF_SEG_OPTS_WND_SCALE;
		}
#endif /* DPIP_WND_SCALE */
#if DPIP_TCP_SACK_OUT
		if ((pcb->state != SYN_RCVD) || (pcb->flags & TF_SACK)) {
			/* In a <SYN,ACK> (sent in state SYN_RCVD), the SACK_PERM option may only
			   be sent if we received a SACK_PERM option from the remote host. */
			optflags |= TF_SEG_OPTS_SACK_PERM;
		}
#endif /* DPIP_TCP_SACK_OUT */
	}
#if DPIP_TCP_TIMESTAMPS
	if ((pcb->flags & TF_TIMESTAMP)
	    || ((flags & TCP_SYN) && (pcb->state != SYN_RCVD))) {
		/* Make sure the timestamp option is only included in data segments if we
		   agreed about it with the remote host (and in active open SYN segments). */
		optflags |= TF_SEG_OPTS_TS;
	}
#endif /* DPIP_TCP_TIMESTAMPS */
	optlen = DPIP_TCP_OPT_LENGTH_SEGMENT(optflags, pcb);

	/* Allocate pbuf with room for TCP header + options */
	if ((p = pbuf_alloc(PBUF_TRANSPORT, optlen, PBUF_RAM)) == NULL) {
		tcp_set_flags(pcb, TF_NAGLEMEMERR);
		TCP_STATS_INC(tcp.memerr);
		return ERR_MEM;
	}
	DPIP_ASSERT("tcp_enqueue_flags: check that first pbuf can hold optlen",
		    (rte_pktmbuf_data_len(p) >= optlen));

	/* Allocate memory for tcp_seg, and fill in fields. */
	if ((seg =
	     tcp_create_segment(pcb, p, flags, pcb->snd_lbb,
				optflags)) == NULL) {
		tcp_set_flags(pcb, TF_NAGLEMEMERR);
		TCP_STATS_INC(tcp.memerr);
		return ERR_MEM;
	}
	DPIP_ASSERT("seg->tcphdr not aligned",
		    ((mem_ptr_t) seg->tcphdr % RTE_MIN(MEM_ALIGNMENT, 4U)) ==
		    0);
	DPIP_ASSERT("tcp_enqueue_flags: invalid segment length", seg->len == 0);

	DPIP_DEBUGF(TCP_OUTPUT_DEBUG | DPIP_DBG_TRACE,
		    ("tcp_enqueue_flags: queueing %" U32_F ":%" U32_F " (0x%"
		     X16_F ")\n", dpip_ntohl(seg->tcphdr->seqno),
		     dpip_ntohl(seg->tcphdr->seqno) + TCP_TCPLEN(seg),
		     (u16_t) flags));

	/* Now append seg to pcb->unsent queue */
	if (pcb->unsent == NULL) {
		pcb->unsent = seg;
	} else {
		struct tcp_seg *useg;
		for (useg = pcb->unsent; useg->next != NULL;
		     useg = useg->next) ;
		useg->next = seg;
	}

	/* SYN and FIN bump the sequence number */
	if ((flags & TCP_SYN) || (flags & TCP_FIN)) {
		pcb->snd_lbb++;
		/* optlen does not influence snd_buf */
	}
	if (flags & TCP_FIN) {
		tcp_set_flags(pcb, TF_FIN);
	}

	/* update number of segments on the queues */
	pcb->snd_queuelen += seg->p->nb_segs;
	DPIP_DEBUGF(TCP_QLEN_DEBUG,
		    ("tcp_enqueue_flags: %" S16_F " (after enqueued)\n",
		     pcb->snd_queuelen));
	if (pcb->snd_queuelen != 0) {
		DPIP_ASSERT("tcp_enqueue_flags: invalid queue length",
			    pcb->unacked != NULL || pcb->unsent != NULL);
	}

	return ERR_OK;
}

#if DPIP_TCP_TIMESTAMPS
/* Build a timestamp option (12 bytes long) at the specified options pointer)
 *
 * @param pcb tcp_pcb
 * @param opts option pointer where to store the timestamp option
 */
static void tcp_build_timestamp_option(const struct tcp_pcb *pcb, u32_t *opts)
{
	DPIP_ASSERT("tcp_build_timestamp_option: invalid pcb", pcb != NULL);

	/* Pad with two NOP options to make everything nicely aligned */
	opts[0] = PP_HTONL(0x0101080A);
	opts[1] = dpip_htonl(sys_now());
	opts[2] = dpip_htonl(pcb->ts_recent);
}
#endif

#if DPIP_TCP_SACK_OUT
/**
 * Calculates the number of SACK entries that should be generated.
 * It takes into account whether TF_SACK flag is set,
 * the number of SACK entries in tcp_pcb that are valid,
 * as well as the available options size.
 *
 * @param pcb tcp_pcb
 * @param optlen the length of other TCP options (in bytes)
 * @return the number of SACK ranges that can be used
 */
static u8_t tcp_get_num_sacks(const struct tcp_pcb *pcb, u8_t optlen)
{
	u8_t num_sacks = 0;

	DPIP_ASSERT("tcp_get_num_sacks: invalid pcb", pcb != NULL);

	if (pcb->flags & TF_SACK) {
		u8_t i;

		/* The first SACK takes up 12 bytes (it includes SACK header and two NOP options),
		   each additional one - 8 bytes. */
		optlen += 12;

		/* Max options size = 40, number of SACK array entries = DPIP_TCP_MAX_SACK_NUM */
		for (i = 0;
		     (i < DPIP_TCP_MAX_SACK_NUM)
		     && (optlen <= TCP_MAX_OPTION_BYTES)
		     && DPIP_TCP_SACK_VALID(pcb, i); ++i) {
			++num_sacks;
			optlen += 8;
		}
	}

	return num_sacks;
}

/** Build a SACK option (12 or more bytes long) at the specified options pointer)
 *
 * @param pcb tcp_pcb
 * @param opts option pointer where to store the SACK option
 * @param num_sacks the number of SACKs to store
 */
static void
tcp_build_sack_option(const struct tcp_pcb *pcb, u32_t *opts, u8_t num_sacks)
{
	u8_t i;

	DPIP_ASSERT("tcp_build_sack_option: invalid pcb", pcb != NULL);
	DPIP_ASSERT("tcp_build_sack_option: invalid opts", opts != NULL);

	/* Pad with two NOP options to make everything nicely aligned.
	   We add the length (of just the SACK option, not the NOPs in front of it),
	   which is 2B of header, plus 8B for each SACK. */
	*(opts++) = PP_HTONL(0x01010500 + 2 + num_sacks * 8);

	for (i = 0; i < num_sacks; ++i) {
		*(opts++) = dpip_htonl(pcb->rcv_sacks[i].left);
		*(opts++) = dpip_htonl(pcb->rcv_sacks[i].right);
	}
}

#endif

#if DPIP_WND_SCALE
/** Build a window scale option (3 bytes long) at the specified options pointer)
 *
 * @param opts option pointer where to store the window scale option
 */
static void tcp_build_wnd_scale_option(u32_t *opts)
{
	DPIP_ASSERT("tcp_build_wnd_scale_option: invalid opts", opts != NULL);

	/* Pad with one NOP option to make everything nicely aligned */
	opts[0] = PP_HTONL(0x01030300 | TCP_RCV_SCALE);
}
#endif

/**
 * @ingroup tcp_raw
 * Find out what we can send and send it
 *
 * @param pcb Protocol control block for the TCP connection to send data
 * @return ERR_OK if data has been sent or nothing to send
 *         another err_t on error
 */
err_t tcp_output(struct tcp_pcb *pcb)
{
	struct tcp_seg *seg, *useg;
	u32_t wnd;		//, snd_nxt;
	err_t err;
	struct netif *netif;
#if TCP_CWND_DEBUG
	s16_t i = 0;
#endif /* TCP_CWND_DEBUG */

	DPIP_ASSERT("tcp_output: invalid pcb", pcb != NULL);
	/* pcb->state LISTEN not allowed here */
	DPIP_ASSERT("don't call tcp_output for listen-pcbs",
		    pcb->state != LISTEN);

	/* First, check if we are invoked by the TCP input processing
	   code. If so, we do not output anything. Instead, we rely on the
	   input processing code to call us when input processing is done
	   with. */
	if (false && /*XXX*/ NULL == pcb) {
		return ERR_OK;
	}

	wnd = RTE_MIN(pcb->snd_wnd, pcb->cwnd);

	seg = pcb->unsent;

	if (seg == NULL) {
		DPIP_DEBUGF(TCP_OUTPUT_DEBUG,
			    ("tcp_output: nothing to send pcb=%p, unsent(%p)\n",
			     pcb, (void *)pcb->unsent));
		DPIP_DEBUGF(TCP_CWND_DEBUG,
			    ("tcp_output: snd_wnd %" TCPWNDSIZE_F ", cwnd %"
			     TCPWNDSIZE_F ", wnd %" U32_F ", seg == NULL, ack %"
			     U32_F "\n", pcb->snd_wnd, pcb->cwnd, wnd,
			     pcb->lastack));

		/* If the TF_ACK_NOW flag is set and the ->unsent queue is empty, construct
		 * an empty ACK segment and send it. */
		if (pcb->flags & TF_ACK_NOW) {
			return tcp_send_empty_ack(pcb);
		}
		/* nothing to send: shortcut out of here */
		goto output_done;
	} else {
		DPIP_DEBUGF(TCP_CWND_DEBUG,
			    ("tcp_output: snd_wnd %" TCPWNDSIZE_F ", cwnd %"
			     TCPWNDSIZE_F ", wnd %" U32_F ", effwnd %" U32_F
			     ", seq %" U32_F ", ack %" U32_F "\n", pcb->snd_wnd,
			     pcb->cwnd, wnd,
			     dpip_ntohl(seg->tcphdr->seqno) - pcb->lastack +
			     seg->len, dpip_ntohl(seg->tcphdr->seqno),
			     pcb->lastack));
	}

	netif = tcp_route(pcb, &pcb->local_ip, &pcb->remote_ip);
	if (netif == NULL) {
		return ERR_RTE;
	}

	/* If we don't have a local IP address, we get one from netif */
	if (ip_addr_isany(&pcb->local_ip)) {
		const ip_addr_t *local_ip =
		    ip_netif_get_local_ip(netif, &pcb->remote_ip);
		if (local_ip == NULL) {
			return ERR_RTE;
		}
		ip_addr_copy(pcb->local_ip, *local_ip);
	}

	/* Handle the current segment not fitting within the window */
	if (dpip_ntohl(seg->tcphdr->seqno) - pcb->lastack + seg->len > wnd) {
		/* We need to start the persistent timer when the next unsent segment does not fit
		 * within the remaining (could be 0) send window and RTO timer is not running (we
		 * have no in-flight data). If window is still too small after persist timer fires,
		 * then we split the segment. We don't consider the congestion window since a cwnd
		 * smaller than 1 SMSS implies in-flight data
		 */
		if (wnd == pcb->snd_wnd && pcb->unacked == NULL
		    && pcb->persist_backoff == 0) {
			pcb->persist_cnt = 0;
			pcb->persist_backoff = 1;
			pcb->persist_probe = 0;
		}
		/* We need an ACK, but can't send data now, so send an empty ACK */
		if (pcb->flags & TF_ACK_NOW) {
			return tcp_send_empty_ack(pcb);
		}
		goto output_done;
	}
	/* Stop persist timer, above conditions are not active */
	pcb->persist_backoff = 0;

	/* useg should point to last segment on unacked queue */
	useg = pcb->unacked;
	if (useg != NULL) {
		for (; useg->next != NULL; useg = useg->next) ;
	}
	/* data available and window allows it to be sent? */
	while (seg != NULL &&
	       dpip_ntohl(seg->tcphdr->seqno) - pcb->lastack + seg->len <=
	       wnd) {
		DPIP_ASSERT("RST not expected here!",
			    (TCPH_FLAGS(seg->tcphdr) & TCP_RST) == 0);
		/* Stop sending if the nagle algorithm would prevent it
		 * Don't stop:
		 * - if tcp_write had a memory error before (prevent delayed ACK timeout) or
		 * - if FIN was already enqueued for this PCB (SYN is always alone in a segment -
		 *   either seg->next != NULL or pcb->unacked == NULL;
		 *   RST is no sent using tcp_write/tcp_output.
		 */
		if ((tcp_do_output_nagle(pcb) == 0) &&
		    ((pcb->flags & (TF_NAGLEMEMERR | TF_FIN)) == 0)) {
			break;
		}
#if TCP_CWND_DEBUG
		DPIP_DEBUGF(TCP_CWND_DEBUG,
			    ("tcp_output: snd_wnd %" TCPWNDSIZE_F ", cwnd %"
			     TCPWNDSIZE_F ", wnd %" U32_F ", effwnd %" U32_F
			     ", seq %" U32_F ", ack %" U32_F ", i %" S16_F "\n",
			     pcb->snd_wnd, pcb->cwnd, wnd,
			     dpip_ntohl(seg->tcphdr->seqno) + seg->len -
			     pcb->lastack, dpip_ntohl(seg->tcphdr->seqno),
			     pcb->lastack, i));
		++i;
#endif /* TCP_CWND_DEBUG */

		if (pcb->state != SYN_SENT) {
			TCPH_SET_FLAG(seg->tcphdr, TCP_ACK);
		}

		printf("tcp_out: pcb=%p, before out_seg\n", pcb);
		err = tcp_output_segment(seg, pcb, netif);
		if (err != ERR_OK) {
			printf("tcp_out: pcb=%p, error in out_seg\n", pcb);
			/* segment could not be sent, for whatever reason */
			tcp_set_flags(pcb, TF_NAGLEMEMERR);
			return err;
		}
		printf("tcp_out: pcb=%p, after out_seg\n", pcb);
		pcb->unsent = seg->next;
		if (pcb->state != SYN_SENT) {
			tcp_clear_flags(pcb, TF_ACK_DELAY | TF_ACK_NOW);
		}
		//snd_nxt = dpip_ntohl(seg->tcphdr->seqno) + TCP_TCPLEN(seg);
		//printf("tcp_out: pcb=%p, snd_nxt=%u, pcb->snd_nxt=%u\n", pcb, snd_nxt, pcb->snd_nxt);
		//if (TCP_SEQ_LT(pcb->snd_nxt, snd_nxt)) {
		//  pcb->snd_nxt = snd_nxt;
		//}
		/* put segment on unacknowledged list if length > 0 */
		if (TCP_TCPLEN(seg) > 0) {
			seg->next = NULL;
			/* unacked list is empty? */
			if (pcb->unacked == NULL) {
				pcb->unacked = seg;
				useg = seg;
				/* unacked list is not empty? */
			} else {
				/* In the case of fast retransmit, the packet should not go to the tail
				 * of the unacked queue, but rather somewhere before it. We need to check for
				 * this case. -STJ Jul 27, 2004 */
				if (TCP_SEQ_LT
				    (dpip_ntohl(seg->tcphdr->seqno),
				     dpip_ntohl(useg->tcphdr->seqno))) {
					/* add segment to before tail of unacked list, keeping the list sorted */
					struct tcp_seg **cur_seg =
					    &(pcb->unacked);
					while (*cur_seg
					       &&
					       TCP_SEQ_LT(dpip_ntohl
							  ((*cur_seg)->tcphdr->
							   seqno),
							  dpip_ntohl(seg->
								     tcphdr->
								     seqno))) {
						cur_seg = &((*cur_seg)->next);
					}
					seg->next = (*cur_seg);
					(*cur_seg) = seg;
				} else {
					/* add segment to tail of unacked list */
					useg->next = seg;
					useg = useg->next;
				}
			}
			/* do not queue empty segments on the unacked list */
		} else {
			tcp_seg_free(seg);
		}
		seg = pcb->unsent;
	}

 output_done:
	tcp_clear_flags(pcb, TF_NAGLEMEMERR);
	return ERR_OK;
}

/** Check if a segment's pbufs are used by someone else than TCP.
 * This can happen on retransmission if the pbuf of this segment is still
 * referenced by the netif driver due to deferred transmission.
 * This is the case (only!) if someone down the TX call path called
 * pbuf_ref() on one of the pbufs!
 *
 * @arg seg the tcp segment to check
 * @return 1 if ref != 1, 0 if ref == 1
 */
static int tcp_output_segment_busy(const struct tcp_seg *seg)
{
	DPIP_ASSERT("tcp_output_segment_busy: invalid seg", seg != NULL);

	/* We only need to check the first pbuf here:
	   If a pbuf is queued for transmission, a driver calls pbuf_ref(),
	   which only changes the ref count of the first pbuf */
	if (rte_mbuf_refcnt_read(seg->p) != 1) {
		/* other reference found */
		return 1;
	}
	/* no other references found */
	return 0;
}

/**
 * Called by tcp_output() to actually send a TCP segment over IP.
 *
 * @param seg the tcp_seg to send
 * @param pcb the tcp_pcb for the TCP connection used to send the segment
 * @param netif the netif used to send the segment
 */
static err_t
tcp_output_segment(struct tcp_seg *seg, struct tcp_pcb *pcb,
		   struct netif *netif)
{
	err_t err;
	u16_t len;
	u32_t *opts;
	u32_t snd_prv, snd_nxt;

	DPIP_ASSERT("tcp_output_segment: invalid seg", seg != NULL);
	DPIP_ASSERT("tcp_output_segment: invalid pcb", pcb != NULL);
	DPIP_ASSERT("tcp_output_segment: invalid netif", netif != NULL);

	if (tcp_output_segment_busy(seg)) {
		/* This should not happen: rexmit functions should have checked this.
		   However, since this function modifies p->len, we must not continue in this case. */
		DPIP_DEBUGF(TCP_RTO_DEBUG | DPIP_DBG_LEVEL_SERIOUS,
			    ("tcp_output_segment: segment busy\n"));
		return ERR_OK;
	}

	/* The TCP header has already been constructed, but the ackno and
	   wnd fields remain. */
	seg->tcphdr->ackno = dpip_htonl(pcb->rcv_nxt);

	/* advertise our receive window size in this TCP segment */
#if DPIP_WND_SCALE
	if (seg->flags & TF_SEG_OPTS_WND_SCALE) {
		/* The Window field in a SYN segment itself (the only type where we send
		   the window scale option) is never scaled. */
		seg->tcphdr->wnd = dpip_htons(TCPWND_MIN16(pcb->rcv_ann_wnd));
	} else
#endif /* DPIP_WND_SCALE */
	{
		seg->tcphdr->wnd =
		    dpip_htons(TCPWND_MIN16
			       (RCV_WND_SCALE(pcb, pcb->rcv_ann_wnd)));
	}

	pcb->rcv_ann_right_edge = pcb->rcv_nxt + pcb->rcv_ann_wnd;

	/* Add any requested options.  NB MSS option is only set on SYN
	   packets, so ignore it here */
	/* cast through void* to get rid of alignment warnings */
	opts = (u32_t *) (void *)(seg->tcphdr + 1);
	if (seg->flags & TF_SEG_OPTS_MSS) {
		u16_t mss;
#if TCP_CALCULATE_EFF_SEND_MSS
		mss = tcp_eff_send_mss_netif(TCP_MSS, netif, &pcb->remote_ip);
#else /* TCP_CALCULATE_EFF_SEND_MSS */
		mss = TCP_MSS;
#endif /* TCP_CALCULATE_EFF_SEND_MSS */
		*opts = TCP_BUILD_MSS_OPTION(mss);
		opts += 1;
	}
#if DPIP_TCP_TIMESTAMPS
	pcb->ts_lastacksent = pcb->rcv_nxt;

	if (seg->flags & TF_SEG_OPTS_TS) {
		tcp_build_timestamp_option(pcb, opts);
		opts += 3;
	}
#endif
#if DPIP_WND_SCALE
	if (seg->flags & TF_SEG_OPTS_WND_SCALE) {
		tcp_build_wnd_scale_option(opts);
		opts += 1;
	}
#endif
#if DPIP_TCP_SACK_OUT
	if (seg->flags & TF_SEG_OPTS_SACK_PERM) {
		/* Pad with two NOP options to make everything nicely aligned
		 * NOTE: When we send both timestamp and SACK_PERM options,
		 * we could use the first two NOPs before the timestamp to store SACK_PERM option,
		 * but that would complicate the code.
		 */
		*(opts++) = PP_HTONL(0x01010402);
	}
#endif

	/* Set retransmission timer running if it is not currently enabled
	   This must be set before checking the route. */
	if (pcb->rtime < 0) {
		pcb->rtime = 0;
	}

	if (pcb->rttest == 0) {
		pcb->rttest = tcp_ticks;
		pcb->rtseq = dpip_ntohl(seg->tcphdr->seqno);

		DPIP_DEBUGF(TCP_RTO_DEBUG,
			    ("tcp_output_segment: rtseq %" U32_F "\n",
			     pcb->rtseq));
	}
	DPIP_DEBUGF(TCP_OUTPUT_DEBUG,
		    ("tcp_output_segment: %" U32_F ":%" U32_F "\n",
		     dpip_htonl(seg->tcphdr->seqno),
		     dpip_htonl(seg->tcphdr->seqno) + seg->len));

	len = (u16_t) ((u8_t *) seg->tcphdr - rte_pktmbuf_mtod(seg->p, u8_t *));
	if (len == 0) {
    /** Exclude retransmitted segments from this count. */
		MIB2_STATS_INC(mib2.tcpoutsegs);
	}

	rte_pktmbuf_adj(seg->p, len);

	/*seg->p->len -= len;
	   seg->p->tot_len -= len;

	   seg->p->payload = seg->tcphdr; */

	seg->tcphdr->chksum = 0;

#ifdef DPIP_HOOK_TCP_OUT_ADD_TCPOPTS
	opts = DPIP_HOOK_TCP_OUT_ADD_TCPOPTS(seg->p, seg->tcphdr, pcb, opts);
#endif
	DPIP_ASSERT("options not filled",
		    (u8_t *) opts ==
		    ((u8_t *) (seg->tcphdr + 1)) +
		    DPIP_TCP_OPT_LENGTH_SEGMENT(seg->flags, pcb));

#if CHECKSUM_GEN_TCP
	IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_TCP) {
		seg->tcphdr->chksum = ip_chksum_pseudo(seg->p, IP_PROTO_TCP,
						       rte_pktmbuf_pkt_len(seg->
									   p),
						       &pcb->local_ip,
						       &pcb->remote_ip);
	}
#endif /* CHECKSUM_GEN_TCP */

	TCP_STATS_INC(tcp.xmit);

	snd_prv = pcb->snd_nxt;
	snd_nxt = dpip_ntohl(seg->tcphdr->seqno) + TCP_TCPLEN(seg);
	printf("tcp_out_seg: pcb=%p, snd_nxt=%u, pcb->snd_nxt=%u\n", pcb,
	       snd_nxt, pcb->snd_nxt);
	if (TCP_SEQ_LT(pcb->snd_nxt, snd_nxt)) {
		pcb->snd_nxt = snd_nxt;
	}

	NETIF_SET_HINTS(netif, &(pcb->netif_hints));
	err = ip_output_if(seg->p, &pcb->local_ip, &pcb->remote_ip, pcb->ttl,
			   pcb->tos, IP_PROTO_TCP, netif);
	NETIF_RESET_HINTS(netif);

	if (err != ERR_OK) {
		pcb->snd_nxt = snd_prv;
	}

	return err;
}

/**
 * Requeue all unacked segments for retransmission
 *
 * Called by tcp_slowtmr() for slow retransmission.
 *
 * @param pcb the tcp_pcb for which to re-enqueue all unacked segments
 */
err_t tcp_rexmit_rto_prepare(struct tcp_pcb *pcb)
{
	struct tcp_seg *seg;

	DPIP_ASSERT("tcp_rexmit_rto_prepare: invalid pcb", pcb != NULL);

	if (pcb->unacked == NULL) {
		return ERR_VAL;
	}

	/* Move all unacked segments to the head of the unsent queue.
	   However, give up if any of the unsent pbufs are still referenced by the
	   netif driver due to deferred transmission. No point loading the link further
	   if it is struggling to flush its buffered writes. */
	for (seg = pcb->unacked; seg->next != NULL; seg = seg->next) {
		if (tcp_output_segment_busy(seg)) {
			DPIP_DEBUGF(TCP_RTO_DEBUG,
				    ("tcp_rexmit_rto: segment busy\n"));
			return ERR_VAL;
		}
	}
	if (tcp_output_segment_busy(seg)) {
		DPIP_DEBUGF(TCP_RTO_DEBUG, ("tcp_rexmit_rto: segment busy\n"));
		return ERR_VAL;
	}
	/* concatenate unsent queue after unacked queue */
	seg->next = pcb->unsent;
	/* unsent queue is the concatenated queue (of unacked, unsent) */
	pcb->unsent = pcb->unacked;
	/* unacked queue is now empty */
	pcb->unacked = NULL;

	/* Mark RTO in-progress */
	tcp_set_flags(pcb, TF_RTO);
	/* Record the next byte following retransmit */
	pcb->rto_end = dpip_ntohl(seg->tcphdr->seqno) + TCP_TCPLEN(seg);
	/* Don't take any RTT measurements after retransmitting. */
	pcb->rttest = 0;

	return ERR_OK;
}

/**
 * Requeue all unacked segments for retransmission
 *
 * Called by tcp_slowtmr() for slow retransmission.
 *
 * @param pcb the tcp_pcb for which to re-enqueue all unacked segments
 */
void tcp_rexmit_rto_commit(struct tcp_pcb *pcb)
{
	DPIP_ASSERT("tcp_rexmit_rto_commit: invalid pcb", pcb != NULL);

	/* increment number of retransmissions */
	if (pcb->nrtx < 0xFF) {
		++pcb->nrtx;
	}
	/* Do the actual retransmission */
	tcp_output(pcb);
}

/**
 * Requeue all unacked segments for retransmission
 *
 * Called by tcp_process() only, tcp_slowtmr() needs to do some things between
 * "prepare" and "commit".
 *
 * @param pcb the tcp_pcb for which to re-enqueue all unacked segments
 */
void tcp_rexmit_rto(struct tcp_pcb *pcb)
{
	DPIP_ASSERT("tcp_rexmit_rto: invalid pcb", pcb != NULL);

	if (tcp_rexmit_rto_prepare(pcb) == ERR_OK) {
		tcp_rexmit_rto_commit(pcb);
	}
}

/**
 * Requeue the first unacked segment for retransmission
 *
 * Called by tcp_receive() for fast retransmit.
 *
 * @param pcb the tcp_pcb for which to retransmit the first unacked segment
 */
err_t tcp_rexmit(struct tcp_pcb *pcb)
{
	struct tcp_seg *seg;
	struct tcp_seg **cur_seg;

	DPIP_ASSERT("tcp_rexmit: invalid pcb", pcb != NULL);

	if (pcb->unacked == NULL) {
		return ERR_VAL;
	}

	seg = pcb->unacked;

	/* Give up if the segment is still referenced by the netif driver
	   due to deferred transmission. */
	if (tcp_output_segment_busy(seg)) {
		DPIP_DEBUGF(TCP_RTO_DEBUG, ("tcp_rexmit busy\n"));
		return ERR_VAL;
	}

	/* Move the first unacked segment to the unsent queue */
	/* Keep the unsent queue sorted. */
	pcb->unacked = seg->next;

	cur_seg = &(pcb->unsent);
	while (*cur_seg &&
	       TCP_SEQ_LT(dpip_ntohl((*cur_seg)->tcphdr->seqno),
			  dpip_ntohl(seg->tcphdr->seqno))) {
		cur_seg = &((*cur_seg)->next);
	}
	seg->next = *cur_seg;
	*cur_seg = seg;

	if (pcb->nrtx < 0xFF) {
		++pcb->nrtx;
	}

	/* Don't take any rtt measurements after retransmitting. */
	pcb->rttest = 0;

	/* Do the actual retransmission. */
	MIB2_STATS_INC(mib2.tcpretranssegs);
	/* No need to call tcp_output: we are always called from tcp_input()
	   and thus tcp_output directly returns. */
	return ERR_OK;
}

/**
 * Handle retransmission after three dupacks received
 *
 * @param pcb the tcp_pcb for which to retransmit the first unacked segment
 */
void tcp_rexmit_fast(struct tcp_pcb *pcb)
{
	DPIP_ASSERT("tcp_rexmit_fast: invalid pcb", pcb != NULL);

	if (pcb->unacked != NULL && !(pcb->flags & TF_INFR)) {
		/* This is fast retransmit. Retransmit the first unacked segment. */
		DPIP_DEBUGF(TCP_FR_DEBUG,
			    ("tcp_receive: dupacks %" U16_F " (%" U32_F
			     "), fast retransmit %" U32_F "\n",
			     (u16_t) pcb->dupacks, pcb->lastack,
			     dpip_ntohl(pcb->unacked->tcphdr->seqno)));
		if (tcp_rexmit(pcb) == ERR_OK) {
			/* Set ssthresh to half of the minimum of the current
			 * cwnd and the advertised window */
			pcb->ssthresh = RTE_MIN(pcb->cwnd, pcb->snd_wnd) / 2;

			/* The minimum value for ssthresh should be 2 MSS */
			if (pcb->ssthresh < (2U * pcb->mss)) {
				DPIP_DEBUGF(TCP_FR_DEBUG,
					    ("tcp_receive: The minimum value for ssthresh %"
					     TCPWNDSIZE_F
					     " should be min 2 mss %" U16_F
					     "...\n", pcb->ssthresh,
					     (u16_t) (2 * pcb->mss)));
				pcb->ssthresh = 2 * pcb->mss;
			}

			pcb->cwnd = pcb->ssthresh + 3 * pcb->mss;
			tcp_set_flags(pcb, TF_INFR);

			/* Reset the retransmission timer to prevent immediate rto retransmissions */
			pcb->rtime = 0;
		}
	}
}

static struct rte_mbuf *tcp_output_alloc_header_common(u32_t ackno,
						       u16_t optlen,
						       u16_t datalen,
						       u32_t seqno_be
						       /* already in network byte order */
						       ,
						       u16_t src_port,
						       u16_t dst_port,
						       u8_t flags, u16_t wnd)
{
	struct tcp_hdr *tcphdr;
	struct rte_mbuf *p;

	p = pbuf_alloc(PBUF_IP, TCP_HLEN + optlen + datalen, PBUF_RAM);
	if (p != NULL) {
		DPIP_ASSERT("check that first pbuf can hold struct tcp_hdr",
			    (rte_pktmbuf_data_len(p) >= TCP_HLEN + optlen));
		tcphdr = rte_pktmbuf_mtod(p, struct tcp_hdr *);
		tcphdr->src = dpip_htons(src_port);
		tcphdr->dest = dpip_htons(dst_port);
		tcphdr->seqno = seqno_be;
		tcphdr->ackno = dpip_htonl(ackno);
		TCPH_HDRLEN_FLAGS_SET(tcphdr, (5 + optlen / 4), flags);
		tcphdr->wnd = dpip_htons(wnd);
		tcphdr->chksum = 0;
		tcphdr->urgp = 0;
	}
	return p;
}

/** Allocate a pbuf and create a tcphdr at p->payload, used for output
 * functions other than the default tcp_output -> tcp_output_segment
 * (e.g. tcp_send_empty_ack, etc.)
 *
 * @param pcb tcp pcb for which to send a packet (used to initialize tcp_hdr)
 * @param optlen length of header-options
 * @param datalen length of tcp data to reserve in pbuf
 * @param seqno_be seqno in network byte order (big-endian)
 * @return pbuf with p->payload being the tcp_hdr
 */
static struct rte_mbuf *tcp_output_alloc_header(struct tcp_pcb *pcb,
						u16_t optlen, u16_t datalen,
						u32_t seqno_be
						/* already in network byte order */
						)
{
	struct rte_mbuf *p;

	DPIP_ASSERT("tcp_output_alloc_header: invalid pcb", pcb != NULL);

	p = tcp_output_alloc_header_common(pcb->rcv_nxt, optlen, datalen,
					   seqno_be, pcb->local_port,
					   pcb->remote_port, TCP_ACK,
					   TCPWND_MIN16(RCV_WND_SCALE
							(pcb,
							 pcb->rcv_ann_wnd)));
	if (p != NULL) {
		/* If we're sending a packet, update the announced right window edge */
		pcb->rcv_ann_right_edge = pcb->rcv_nxt + pcb->rcv_ann_wnd;
	}
	return p;
}

/* Fill in options for control segments */
static void
tcp_output_fill_options(const struct tcp_pcb *pcb, struct rte_mbuf *p,
			u8_t optflags, u8_t num_sacks)
{
	struct tcp_hdr *tcphdr;
	u32_t *opts;
	u16_t sacks_len = 0;

	DPIP_ASSERT("tcp_output_fill_options: invalid pbuf", p != NULL);

	tcphdr = rte_pktmbuf_mtod(p, struct tcp_hdr *);
	opts = (u32_t *) (void *)(tcphdr + 1);

	/* NB. MSS and window scale options are only sent on SYNs, so ignore them here */

#if DPIP_TCP_TIMESTAMPS
	if (optflags & TF_SEG_OPTS_TS) {
		tcp_build_timestamp_option(pcb, opts);
		opts += 3;
	}
#endif

#if DPIP_TCP_SACK_OUT
	if (pcb && (num_sacks > 0)) {
		tcp_build_sack_option(pcb, opts, num_sacks);
		/* 1 word for SACKs header (including 2xNOP), and 2 words for each SACK */
		sacks_len = 1 + num_sacks * 2;
		opts += sacks_len;
	}
#else
	DPIP_UNUSED_ARG(num_sacks);
#endif

#ifdef DPIP_HOOK_TCP_OUT_ADD_TCPOPTS
	opts = DPIP_HOOK_TCP_OUT_ADD_TCPOPTS(p, tcphdr, pcb, opts);
#endif

	DPIP_UNUSED_ARG(pcb);
	DPIP_UNUSED_ARG(sacks_len);
	DPIP_ASSERT("options not filled",
		    (u8_t *) opts ==
		    ((u8_t *) (tcphdr + 1)) + sacks_len * 4 +
		    DPIP_TCP_OPT_LENGTH_SEGMENT(optflags, pcb));
	DPIP_UNUSED_ARG(optflags);	/* for DPIP_NOASSERT */
	DPIP_UNUSED_ARG(opts);	/* for DPIP_NOASSERT */
}

/** Output a control segment pbuf to IP.
 *
 * Called from tcp_rst, tcp_send_empty_ack, tcp_keepalive and tcp_zero_window_probe,
 * this function combines selecting a netif for transmission, generating the tcp
 * header checksum and calling ip_output_if while handling netif hints and stats.
 */
static err_t
tcp_output_control_segment(const struct tcp_pcb *pcb, struct rte_mbuf *p,
			   const ip_addr_t *src, const ip_addr_t *dst)
{
	struct netif *netif;

	DPIP_ASSERT("tcp_output_control_segment: invalid pbuf", p != NULL);

	netif = tcp_route(pcb, src, dst);
	if (netif == NULL) {
		rte_pktmbuf_free(p);
		return ERR_RTE;
	}
	return tcp_output_control_segment_netif(pcb, p, src, dst, netif);
}

/** Output a control segment pbuf to IP.
 *
 * Called instead of tcp_output_control_segment when we don't have a pcb but we
 * do know the interface to send to.
 */
static err_t
tcp_output_control_segment_netif(const struct tcp_pcb *pcb, struct rte_mbuf *p,
				 const ip_addr_t *src, const ip_addr_t *dst,
				 struct netif *netif)
{
	err_t err;
	u8_t ttl, tos;

	DPIP_ASSERT("tcp_output_control_segment_netif: no netif given",
		    netif != NULL);

#if CHECKSUM_GEN_TCP
	IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_TCP) {
		struct tcp_hdr *tcphdr = rte_pktmbuf_mtod(p, struct tcp_hdr *);
		tcphdr->chksum =
		    ip_chksum_pseudo(p, IP_PROTO_TCP, rte_pktmbuf_pkt_len(p),
				     src, dst);
	}
#endif
	if (pcb != NULL) {
		NETIF_SET_HINTS(netif,
				DPIP_CONST_CAST(struct netif_hint *,
						&(pcb->netif_hints)));
		ttl = pcb->ttl;
		tos = pcb->tos;
	} else {
		/* Send output with hardcoded TTL/HL since we have no access to the pcb */
		ttl = TCP_TTL;
		tos = 0;
	}
	TCP_STATS_INC(tcp.xmit);
	err = ip_output_if(p, src, dst, ttl, tos, IP_PROTO_TCP, netif);
	NETIF_RESET_HINTS(netif);

	rte_pktmbuf_free(p);
	return err;
}

static struct rte_mbuf *tcp_rst_common(const struct tcp_pcb *pcb, u32_t seqno,
				       u32_t ackno, const ip_addr_t *local_ip,
				       const ip_addr_t *remote_ip,
				       u16_t local_port, u16_t remote_port)
{
	struct rte_mbuf *p;
	u16_t wnd;
	u8_t optlen;

	DPIP_ASSERT("tcp_rst: invalid local_ip", local_ip != NULL);
	DPIP_ASSERT("tcp_rst: invalid remote_ip", remote_ip != NULL);
	/* these two are passed only for checks, disable warnings without asserts */
	DPIP_UNUSED_ARG(local_ip);
	DPIP_UNUSED_ARG(remote_ip);

	optlen = DPIP_TCP_OPT_LENGTH_SEGMENT(0, pcb);

#if DPIP_WND_SCALE
	wnd = PP_HTONS(((TCP_WND >> TCP_RCV_SCALE) & 0xFFFF));
#else
	wnd = PP_HTONS(TCP_WND);
#endif

	p = tcp_output_alloc_header_common(ackno, optlen, 0, dpip_htonl(seqno),
					   local_port, remote_port,
					   TCP_RST | TCP_ACK, wnd);
	if (p == NULL) {
		DPIP_DEBUGF(TCP_DEBUG,
			    ("tcp_rst: could not allocate memory for pbuf\n"));
		return NULL;
	}
	tcp_output_fill_options(pcb, p, 0, 0);

	MIB2_STATS_INC(mib2.tcpoutrsts);

	DPIP_DEBUGF(TCP_RST_DEBUG,
		    ("tcp_rst: seqno %" U32_F " ackno %" U32_F ".\n", seqno,
		     ackno));
	abort();
	return p;
}

/**
 * Send a TCP RESET packet (empty segment with RST flag set) to abort a
 * connection.
 *
 * Called by tcp_abort() (to abort a local connection), tcp_closen() (if not
 * all data has been received by the application), tcp_timewait_input() (if a
 * SYN is received) and tcp_process() (received segment in the wrong state).
 *
 * Since a RST segment is in most cases not sent for an active connection,
 * tcp_rst() has a number of arguments that are taken from a tcp_pcb for
 * most other segment output functions.
 *
 * @param pcb TCP pcb (may be NULL if no pcb is available)
 * @param seqno the sequence number to use for the outgoing segment
 * @param ackno the acknowledge number to use for the outgoing segment
 * @param local_ip the local IP address to send the segment from
 * @param remote_ip the remote IP address to send the segment to
 * @param local_port the local TCP port to send the segment from
 * @param remote_port the remote TCP port to send the segment to
 */
void
tcp_rst(const struct tcp_pcb *pcb, u32_t seqno, u32_t ackno,
	const ip_addr_t *local_ip, const ip_addr_t *remote_ip,
	u16_t local_port, u16_t remote_port)
{
	struct rte_mbuf *p;

	p = tcp_rst_common(pcb, seqno, ackno, local_ip, remote_ip, local_port,
			   remote_port);
	if (p != NULL) {
		tcp_output_control_segment(pcb, p, local_ip, remote_ip);
	}
}

/**
 * Send a TCP RESET packet (empty segment with RST flag set) to show that there
 * is no matching local connection for a received segment.
 *
 * Called by tcp_input() (if no matching local pcb was found) and
 * tcp_listen_input() (if incoming segment has ACK flag set).
 *
 * Since a RST segment is in most cases not sent for an active connection,
 * tcp_rst() has a number of arguments that are taken from a tcp_pcb for
 * most other segment output functions.
 *
 * @param netif the netif on which to send the RST (since we have no pcb)
 * @param seqno the sequence number to use for the outgoing segment
 * @param ackno the acknowledge number to use for the outgoing segment
 * @param local_ip the local IP address to send the segment from
 * @param remote_ip the remote IP address to send the segment to
 * @param local_port the local TCP port to send the segment from
 * @param remote_port the remote TCP port to send the segment to
 */
void
tcp_rst_netif(struct netif *netif, u32_t seqno, u32_t ackno,
	      const ip_addr_t *local_ip, const ip_addr_t *remote_ip,
	      u16_t local_port, u16_t remote_port)
{
	if (netif) {
		struct rte_mbuf *p =
		    tcp_rst_common(NULL, seqno, ackno, local_ip, remote_ip,
				   local_port, remote_port);
		if (p != NULL) {
			tcp_output_control_segment_netif(NULL, p, local_ip,
							 remote_ip, netif);
		}
	} else {
		DPIP_DEBUGF(TCP_OUTPUT_DEBUG,
			    ("tcp_rst_netif: no netif given\n"));
	}
}

/**
 * Send an ACK without data.
 *
 * @param pcb Protocol control block for the TCP connection to send the ACK
 */
err_t tcp_send_empty_ack(struct tcp_pcb *pcb)
{
	err_t err;
	struct rte_mbuf *p;
	u8_t optlen, optflags = 0;
	u8_t num_sacks = 0;

	DPIP_ASSERT("tcp_send_empty_ack: invalid pcb", pcb != NULL);

#if DPIP_TCP_TIMESTAMPS
	if (pcb->flags & TF_TIMESTAMP) {
		optflags = TF_SEG_OPTS_TS;
	}
#endif
	optlen = DPIP_TCP_OPT_LENGTH_SEGMENT(optflags, pcb);

#if DPIP_TCP_SACK_OUT
	/* For now, SACKs are only sent with empty ACKs */
	if ((num_sacks = tcp_get_num_sacks(pcb, optlen)) > 0) {
		optlen += 4 + num_sacks * 8;	/* 4 bytes for header (including 2*NOP), plus 8B for each SACK */
	}
#endif

	p = tcp_output_alloc_header(pcb, optlen, 0, dpip_htonl(pcb->snd_nxt));
	if (p == NULL) {
		/* let tcp_fasttmr retry sending this ACK */
		tcp_set_flags(pcb, TF_ACK_DELAY | TF_ACK_NOW);
		DPIP_DEBUGF(TCP_OUTPUT_DEBUG,
			    ("tcp_output: (ACK) could not allocate pbuf\n"));
		return ERR_BUF;
	}
	tcp_output_fill_options(pcb, p, optflags, num_sacks);

#if DPIP_TCP_TIMESTAMPS
	pcb->ts_lastacksent = pcb->rcv_nxt;
#endif

	DPIP_DEBUGF(TCP_OUTPUT_DEBUG,
		    ("tcp_output: sending ACK for %" U32_F "\n", pcb->rcv_nxt));
	err =
	    tcp_output_control_segment(pcb, p, &pcb->local_ip, &pcb->remote_ip);
	if (err != ERR_OK) {
		/* let tcp_fasttmr retry sending this ACK */
		tcp_set_flags(pcb, TF_ACK_DELAY | TF_ACK_NOW);
	} else {
		/* remove ACK flags from the PCB, as we sent an empty ACK now */
		tcp_clear_flags(pcb, TF_ACK_DELAY | TF_ACK_NOW);
	}

	return err;
}

/**
 * Send keepalive packets to keep a connection active although
 * no data is sent over it.
 *
 * Called by tcp_slowtmr()
 *
 * @param pcb the tcp_pcb for which to send a keepalive packet
 */
err_t tcp_keepalive(struct tcp_pcb *pcb)
{
	err_t err;
	struct rte_mbuf *p;
	u8_t optlen = DPIP_TCP_OPT_LENGTH_SEGMENT(0, pcb);

	DPIP_ASSERT("tcp_keepalive: invalid pcb", pcb != NULL);

	DPIP_DEBUGF(TCP_DEBUG, ("tcp_keepalive: sending KEEPALIVE probe to "));
	ip_addr_debug_print_val(TCP_DEBUG, pcb->remote_ip);
	DPIP_DEBUGF(TCP_DEBUG, ("\n"));

	DPIP_DEBUGF(TCP_DEBUG,
		    ("tcp_keepalive: tcp_ticks %" U32_F "   pcb->tmr %" U32_F
		     " pcb->keep_cnt_sent %" U16_F "\n", tcp_ticks, pcb->tmr,
		     (u16_t) pcb->keep_cnt_sent));

	p = tcp_output_alloc_header(pcb, optlen, 0,
				    dpip_htonl(pcb->snd_nxt - 1));
	if (p == NULL) {
		DPIP_DEBUGF(TCP_DEBUG,
			    ("tcp_keepalive: could not allocate memory for pbuf\n"));
		return ERR_MEM;
	}
	tcp_output_fill_options(pcb, p, 0, 0);
	err =
	    tcp_output_control_segment(pcb, p, &pcb->local_ip, &pcb->remote_ip);

	DPIP_DEBUGF(TCP_DEBUG,
		    ("tcp_keepalive: seqno %" U32_F " ackno %" U32_F
		     " err %d.\n", pcb->snd_nxt - 1, pcb->rcv_nxt, (int)err));
	return err;
}

/**
 * Send persist timer zero-window probes to keep a connection active
 * when a window update is lost.
 *
 * Called by tcp_slowtmr()
 *
 * @param pcb the tcp_pcb for which to send a zero-window probe packet
 */
err_t tcp_zero_window_probe(struct tcp_pcb *pcb)
{
	err_t err;
	struct rte_mbuf *p;
	struct tcp_hdr *tcphdr;
	struct tcp_seg *seg;
	u16_t len;
	u8_t is_fin;
	u32_t snd_nxt;
	u8_t optlen = DPIP_TCP_OPT_LENGTH_SEGMENT(0, pcb);

	DPIP_ASSERT("tcp_zero_window_probe: invalid pcb", pcb != NULL);

	DPIP_DEBUGF(TCP_DEBUG,
		    ("tcp_zero_window_probe: sending ZERO WINDOW probe to "));
	ip_addr_debug_print_val(TCP_DEBUG, pcb->remote_ip);
	DPIP_DEBUGF(TCP_DEBUG, ("\n"));

	DPIP_DEBUGF(TCP_DEBUG,
		    ("tcp_zero_window_probe: tcp_ticks %" U32_F
		     "   pcb->tmr %" U32_F " pcb->keep_cnt_sent %" U16_F "\n",
		     tcp_ticks, pcb->tmr, (u16_t) pcb->keep_cnt_sent));

	/* Only consider unsent, persist timer should be off when there is data in-flight */
	seg = pcb->unsent;
	if (seg == NULL) {
		/* Not expected, persist timer should be off when the send buffer is empty */
		return ERR_OK;
	}

	/* increment probe count. NOTE: we record probe even if it fails
	   to actually transmit due to an error. This ensures memory exhaustion/
	   routing problem doesn't leave a zero-window pcb as an indefinite zombie.
	   RTO mechanism has similar behavior, see pcb->nrtx */
	if (pcb->persist_probe < 0xFF) {
		++pcb->persist_probe;
	}

	is_fin = ((TCPH_FLAGS(seg->tcphdr) & TCP_FIN) != 0) && (seg->len == 0);
	/* we want to send one seqno: either FIN or data (no options) */
	len = is_fin ? 0 : 1;

	p = tcp_output_alloc_header(pcb, optlen, len, seg->tcphdr->seqno);
	if (p == NULL) {
		DPIP_DEBUGF(TCP_DEBUG,
			    ("tcp_zero_window_probe: no memory for pbuf\n"));
		return ERR_MEM;
	}
	tcphdr = rte_pktmbuf_mtod(p, struct tcp_hdr *);

	if (is_fin) {
		/* FIN segment, no data */
		TCPH_FLAGS_SET(tcphdr, TCP_ACK | TCP_FIN);
	} else {
		/* Data segment, copy in one byte from the head of the unacked queue */
		char *d = (rte_pktmbuf_mtod(p, char *) + TCP_HLEN);
		/* Depending on whether the segment has already been sent (unacked) or not
		   (unsent), seg->p->payload points to the IP header or TCP header.
		   Ensure we copy the first TCP data byte: */
		pbuf_copy_partial(seg->p, d, 1,
				  rte_pktmbuf_pkt_len(seg->p) - seg->len);
	}

	/* The byte may be acknowledged without the window being opened. */
	snd_nxt = dpip_ntohl(seg->tcphdr->seqno) + 1;
	if (TCP_SEQ_LT(pcb->snd_nxt, snd_nxt)) {
		pcb->snd_nxt = snd_nxt;
	}
	tcp_output_fill_options(pcb, p, 0, 0);

	err =
	    tcp_output_control_segment(pcb, p, &pcb->local_ip, &pcb->remote_ip);

	DPIP_DEBUGF(TCP_DEBUG, ("tcp_zero_window_probe: seqno %" U32_F
				" ackno %" U32_F " err %d.\n",
				pcb->snd_nxt - 1, pcb->rcv_nxt, (int)err));
	return err;
}
#endif /* DPIP_TCP */
