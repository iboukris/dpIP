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

#include "dpip/pbuf.h"
#include "dpip/stats.h"
#include "dpip/def.h"
#include "dpip/memp.h"
#include "dpip/sys.h"
#include "dpip/netif.h"
#if DPIP_TCP && TCP_QUEUE_OOSEQ
#include "dpip/priv/tcp_priv.h"
#endif

#include <string.h>

extern struct rte_mempool *dpip_pktmbuf_pool;

/**
 * @ingroup pbuf
 * Allocates a pbuf of the given type (possibly a chain for PBUF_POOL type).
 *
 * The actual memory allocated for the pbuf is determined by the
 * layer at which the pbuf is allocated and the requested size
 * (from the size parameter).
 *
 * @param layer header size
 * @param length size of the pbuf's payload
 * @param type this parameter decides how and where the pbuf
 * should be allocated as follows:
 *
 * - PBUF_RAM: buffer memory for pbuf is allocated as one large
 *             chunk. This includes protocol headers as well.
 * - PBUF_ROM: no buffer memory is allocated for the pbuf, even for
 *             protocol headers. Additional headers must be prepended
 *             by allocating another pbuf and chain in to the front of
 *             the ROM pbuf. It is assumed that the memory used is really
 *             similar to ROM in that it is immutable and will not be
 *             changed. Memory which is dynamic should generally not
 *             be attached to PBUF_ROM pbufs. Use PBUF_REF instead.
 * - PBUF_REF: no buffer memory is allocated for the pbuf, even for
 *             protocol headers. It is assumed that the pbuf is only
 *             being used in a single thread. If the pbuf gets queued,
 *             then pbuf_take should be called to copy the buffer.
 * - PBUF_POOL: the pbuf is allocated as a pbuf chain, with pbufs from
 *              the pbuf pool that is allocated during pbuf_init().
 *
 * @return the allocated pbuf. If multiple pbufs where allocated, this
 * is the first pbuf of a pbuf chain.
 */
struct rte_mbuf *pbuf_alloc(pbuf_layer layer, u16_t length, pbuf_type type)
{
	struct rte_mbuf *p;
	u16_t offset = (u16_t) layer;
	DPIP_DEBUGF(PBUF_DEBUG,
		    ("pbuf_alloc(length=%" U16_F ",offset=%" U16_F ")\n",
		     length, offset));

	switch (type) {
	case PBUF_REF:		/* fall through */
	case PBUF_ROM:
		p = pbuf_alloc_reference(NULL, length, type);
		break;
	case PBUF_RAM:		/* fall through */
	case PBUF_POOL:{
			{
				size_t payload_len =
				    DPIP_MEM_ALIGN_SIZE(offset) + length;
				//size_t payload_len = offset + length;

				p = rte_pktmbuf_alloc(dpip_pktmbuf_pool);
				if (p == NULL) {
					DPIP_DEBUGF(PBUF_DEBUG,
						    ("mbuf alloc failed, requested=%lu\n",
						     payload_len));
					/* bail out unsuccessfully */
					return NULL;
				}
				if (rte_pktmbuf_tailroom(p) < payload_len) {
					DPIP_DEBUGF(PBUF_DEBUG,
						    ("mbuf too small, size=%d, requested=%lu\n",
						     rte_pktmbuf_tailroom(p),
						     payload_len));
					rte_pktmbuf_free(p);
					return NULL;
				}
				DPIP_ASSERT
				    ("pbuf_alloc: pbuf p->payload properly aligned",
				     ((rte_pktmbuf_mtod(p, mem_ptr_t)) %
				      MEM_ALIGNMENT) == 0);
				DPIP_ASSERT
				    ("PBUF_POOL_BUFSIZE must be bigger than MEM_ALIGNMENT",
				     (rte_pktmbuf_tailroom(p) -
				      DPIP_MEM_ALIGN_SIZE(offset)) > 0);

				if (rte_pktmbuf_append(p, payload_len) == NULL) {
					rte_pktmbuf_free(p);
					return NULL;
				}

				DPIP_DEBUGF(PBUF_DEBUG,
					    ("pbuf_alloc(rte_pktmbuf_data_len=%"
					     U16_F ") == %p\n",
					     rte_pktmbuf_data_len(p),
					     (void *)p));

				if (rte_pktmbuf_adj
				    (p, DPIP_MEM_ALIGN_SIZE(offset)) == NULL) {
					rte_pktmbuf_free(p);
					return NULL;
				}

				DPIP_ASSERT
				    ("pbuf_alloc: pbuf p->payload properly aligned",
				     ((rte_pktmbuf_mtod(p, mem_ptr_t)) %
				      MEM_ALIGNMENT) == 0);

				DPIP_DEBUGF(PBUF_DEBUG,
					    ("pbuf_alloc(rte_pktmbuf_data_len=%"
					     U16_F ") == %p\n",
					     rte_pktmbuf_data_len(p),
					     (void *)p));
			}
			break;
		}
	default:
		DPIP_ASSERT("pbuf_alloc: erroneous type", 0);
		return NULL;
	}

	return p;
}

/**
 * @ingroup pbuf
 * Allocates a pbuf for referenced data.
 * Referenced data can be volatile (PBUF_REF) or long-lived (PBUF_ROM).
 *
 * The actual memory allocated for the pbuf is determined by the
 * layer at which the pbuf is allocated and the requested size
 * (from the size parameter).
 *
 * @param payload referenced payload
 * @param length size of the pbuf's payload
 * @param type this parameter decides how and where the pbuf
 * should be allocated as follows:
 *
 * - PBUF_ROM: It is assumed that the memory used is really
 *             similar to ROM in that it is immutable and will not be
 *             changed. Memory which is dynamic should generally not
 *             be attached to PBUF_ROM pbufs. Use PBUF_REF instead.
 * - PBUF_REF: It is assumed that the pbuf is only
 *             being used in a single thread. If the pbuf gets queued,
 *             then pbuf_take should be called to copy the buffer.
 *
 * @return the allocated pbuf.
 */
struct rte_mbuf *pbuf_alloc_reference(void *payload, u16_t length,
				      pbuf_type type)
{
	struct rte_mbuf *p;
	DPIP_ASSERT("invalid pbuf_type", (type == PBUF_REF)
		    || (type == PBUF_ROM));
	DPIP_UNUSED_ARG(payload);
	DPIP_UNUSED_ARG(length);
	DPIP_UNUSED_ARG(type);
	abort();
#if 0
	/* only allocate memory for the pbuf structure */
	p = (struct rte_mbuf *)memp_malloc(MEMP_PBUF);
	if (p == NULL) {
		DPIP_DEBUGF(PBUF_DEBUG | DPIP_DBG_LEVEL_SERIOUS,
			    ("pbuf_alloc_reference: Could not allocate MEMP_PBUF for PBUF_%s.\n",
			     (type == PBUF_ROM) ? "ROM" : "REF"));
		return NULL;
	}
	pbuf_init_alloced_pbuf(p, payload, length, length, type, 0);
#endif
	return p;
}

static u16_t chop_tail(struct rte_mbuf *p)
{
	struct rte_mbuf *new_tail = p;
	while (new_tail->next != NULL) {
		if (new_tail->next->next == NULL) {
			u16_t tail_len = rte_pktmbuf_data_len(new_tail->next);
			rte_pktmbuf_free_seg(new_tail->next);
			new_tail->next = NULL;
			rte_pktmbuf_pkt_len(p) -= tail_len;
			p->nb_segs -= 1;
			return tail_len;
		}
		new_tail = new_tail->next;
	}
	return 0;
}

/**
 * @ingroup pbuf
 * Shrink a pbuf chain to a desired length.
 *
 * @param p pbuf to shrink.
 * @param new_len desired new length of pbuf chain
 *
 * Depending on the desired length, the first few pbufs in a chain might
 * be skipped and left unchanged. The new last pbuf in the chain will be
 * resized, and any remaining pbufs will be freed.
 *
 * @note If the pbuf is ROM/REF, only the ->tot_len and ->len fields are adjusted.
 * @note May not be called on a packet queue.
 *
 * @note Despite its name, pbuf_realloc cannot grow the size of a pbuf (chain).
 */
void pbuf_realloc(struct rte_mbuf *p, u16_t new_len)
{
	u16_t shrink;

	DPIP_ASSERT("pbuf_realloc: p != NULL", p != NULL);

	/* desired length larger than current length? */
	if (new_len >= rte_pktmbuf_pkt_len(p)) {
		/* enlarging not yet supported */
		return;
	}

	/* the pbuf chain grows by (new_len - p->tot_len) bytes
	 * (which may be negative in case of shrinking) */
	shrink = (u16_t) (rte_pktmbuf_pkt_len(p) - new_len);

	while (rte_pktmbuf_trim(p, shrink) < 0) {
		shrink -= chop_tail(p);
	}

	if (rte_pktmbuf_data_len(rte_pktmbuf_lastseg(p)) == 0) {
		chop_tail(p);
	}
}

/**
 * @ingroup pbuf
 * Copy the contents of one packet buffer into another.
 *
 * @note Only one packet is copied, no packet queue!
 *
 * @param p_to pbuf destination of the copy
 * @param p_from pbuf source of the copy
 *
 * @return ERR_OK if pbuf was copied
 *         ERR_ARG if one of the pbufs is NULL or p_to is not big
 *                 enough to hold p_from
 *         ERR_VAL if any of the pbufs are part of a queue
 */
err_t pbuf_copy(struct rte_mbuf *p_to, const struct rte_mbuf *p_from)
{
	DPIP_DEBUGF(PBUF_DEBUG | DPIP_DBG_TRACE, ("pbuf_copy(%p, %p)\n",
						  (const void *)p_to,
						  (const void *)p_from));

	DPIP_ERROR("pbuf_copy: invalid source", p_from != NULL, return ERR_ARG;
	    );
	return pbuf_copy_partial_pbuf(p_to, p_from, rte_pktmbuf_pkt_len(p_from),
				      0);
}

/**
 * @ingroup pbuf
 * Copy part or all of one packet buffer into another, to a specified offset.
 *
 * @note Only data in one packet is copied, no packet queue!
 * @note Argument order is shared with pbuf_copy, but different than pbuf_copy_partial.
 *
 * @param p_to pbuf destination of the copy
 * @param p_from pbuf source of the copy
 * @param copy_len number of bytes to copy
 * @param offset offset in destination pbuf where to copy to
 *
 * @return ERR_OK if copy_len bytes were copied
 *         ERR_ARG if one of the pbufs is NULL or p_from is shorter than copy_len
 *                 or p_to is not big enough to hold copy_len at offset
 *         ERR_VAL if any of the pbufs are part of a queue
 */
err_t
pbuf_copy_partial_pbuf(struct rte_mbuf *p_to, const struct rte_mbuf *p_from,
		       u16_t copy_len, u16_t offset)
{
	size_t offset_to = offset, offset_from = 0, len;

	DPIP_DEBUGF(PBUF_DEBUG | DPIP_DBG_TRACE,
		    ("pbuf_copy_partial_pbuf(%p, %p, %" U16_F ", %" U16_F ")\n",
		     (const void *)p_to, (const void *)p_from, copy_len,
		     offset));

	/* is the copy_len in range? */
	DPIP_ERROR("pbuf_copy_partial_pbuf: copy_len bigger than source",
		   ((p_from != NULL)
		    && (rte_pktmbuf_pkt_len(p_from) >= copy_len)),
		   return ERR_ARG;
	    );
	/* is the target big enough to hold the source? */
	DPIP_ERROR("pbuf_copy_partial_pbuf: target not big enough",
		   ((p_to != NULL)
		    && (rte_pktmbuf_pkt_len(p_to) >= (offset + copy_len))),
		   return ERR_ARG;
	    );

	/* iterate through pbuf chain */

	// TODO: change loop to nb_segs

	do {
		/* copy one part of the original chain */
		if ((rte_pktmbuf_data_len(p_to) - offset_to) >=
		    (rte_pktmbuf_data_len(p_from) - offset_from)) {
			/* complete current p_from fits into current p_to */
			len = rte_pktmbuf_data_len(p_from) - offset_from;
		} else {
			/* current p_from does not fit into current p_to */
			len = rte_pktmbuf_data_len(p_to) - offset_to;
		}
		len = RTE_MIN(copy_len, len);
		MEMCPY(rte_pktmbuf_mtod(p_to, u8_t *) + offset_to,
		       rte_pktmbuf_mtod(p_from, u8_t *) + offset_from, len);
		offset_to += len;
		offset_from += len;
		copy_len = (u16_t) (copy_len - len);
		DPIP_ASSERT("offset_to <= p_to->len",
			    offset_to <= rte_pktmbuf_data_len(p_to));
		DPIP_ASSERT("offset_from <= p_from->len",
			    offset_from <= rte_pktmbuf_data_len(p_from));
		if (offset_from >= rte_pktmbuf_data_len(p_from)) {
			/* on to next p_from (if any) */
			offset_from = 0;
			p_from = p_from->next;
			DPIP_ERROR("p_from != NULL", (p_from != NULL)
				   || (copy_len == 0), return ERR_ARG;
			    );
		}
		if (offset_to == rte_pktmbuf_data_len(p_to)) {
			/* on to next p_to (if any) */
			offset_to = 0;
			p_to = p_to->next;
			DPIP_ERROR("p_to != NULL", (p_to != NULL)
				   || (copy_len == 0), return ERR_ARG;
			    );
		}

	} while (copy_len);
	DPIP_DEBUGF(PBUF_DEBUG | DPIP_DBG_TRACE,
		    ("pbuf_copy_partial_pbuf: copy complete.\n"));
	return ERR_OK;
}

/**
 * @ingroup pbuf
 * Copy (part of) the contents of a packet buffer
 * to an application supplied buffer.
 *
 * @param buf the pbuf from which to copy data
 * @param dataptr the application supplied buffer
 * @param len length of data to copy (dataptr must be big enough). No more
 * than buf->tot_len will be copied, irrespective of len
 * @param offset offset into the packet buffer from where to begin copying len bytes
 * @return the number of bytes copied, or 0 on failure
 */
u16_t
pbuf_copy_partial(const struct rte_mbuf *buf, void *dataptr, u16_t len,
		  u16_t offset)
{
	const struct rte_mbuf *p;
	u16_t left = 0;
	u16_t buf_copy_len;
	u16_t copied_total = 0;

	DPIP_ERROR("pbuf_copy_partial: invalid buf", (buf != NULL), return 0;
	    );
	DPIP_ERROR("pbuf_copy_partial: invalid dataptr", (dataptr != NULL),
		   return 0;
	    );

	/* Note some systems use byte copy if dataptr or one of the pbuf payload pointers are unaligned. */
	for (p = buf; len != 0 && p != NULL; p = p->next) {

		// TODO: change loop to nb_segs

		if ((offset != 0) && (offset >= rte_pktmbuf_data_len(p))) {
			/* don't copy from this buffer -> on to the next */
			offset = (u16_t) (offset - rte_pktmbuf_data_len(p));
		} else {
			/* copy from this buffer. maybe only partially. */
			buf_copy_len =
			    (u16_t) (rte_pktmbuf_data_len(p) - offset);
			if (buf_copy_len > len) {
				buf_copy_len = len;
			}
			/* copy the necessary parts of the buffer */
			MEMCPY(&((char *)dataptr)[left],
			       &(rte_pktmbuf_mtod(p, char *))[offset],
			       buf_copy_len);
			copied_total = (u16_t) (copied_total + buf_copy_len);
			left = (u16_t) (left + buf_copy_len);
			len = (u16_t) (len - buf_copy_len);
			offset = 0;
		}
	}
	return copied_total;
}

/**
 * @ingroup pbuf
 * Allocates a new pbuf of same length (via pbuf_alloc()) and copies the source
 * pbuf into this new pbuf (using pbuf_copy()).
 *
 * @param layer pbuf_layer of the new pbuf
 * @param type this parameter decides how and where the pbuf should be allocated
 *             (@see pbuf_alloc())
 * @param p the source pbuf
 *
 * @return a new pbuf or NULL if allocation fails
 */
struct rte_mbuf *pbuf_clone(pbuf_layer layer, pbuf_type type,
			    struct rte_mbuf *p)
{
	// TODO: use rte_pktmbuf_copy()
	struct rte_mbuf *q;
	err_t err;
	q = pbuf_alloc(layer, rte_pktmbuf_pkt_len(p), type);
	if (q == NULL) {
		return NULL;
	}
	err = pbuf_copy(q, p);
	DPIP_UNUSED_ARG(err);	/* in case of DPIP_NOASSERT */
	DPIP_ASSERT("pbuf_copy failed", err == ERR_OK);
	return q;
}
