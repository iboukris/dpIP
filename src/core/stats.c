/**
 * @file
 * Statistics module
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

#if DPIP_STATS			/* don't build if not configured for use in opts.h */

#include "dpip/def.h"
#include "dpip/stats.h"
#include "dpip/debug.h"

#include <string.h>

struct stats_ dpip_stats;

void stats_init(void)
{
}

#if DPIP_STATS_DISPLAY
void stats_display_proto(struct stats_proto *proto, const char *name)
{
	DPIP_PLATFORM_DIAG(("\n%s\n\t", name));
	DPIP_PLATFORM_DIAG(("xmit: %" STAT_COUNTER_F "\n\t", proto->xmit));
	DPIP_PLATFORM_DIAG(("recv: %" STAT_COUNTER_F "\n\t", proto->recv));
	DPIP_PLATFORM_DIAG(("fw: %" STAT_COUNTER_F "\n\t", proto->fw));
	DPIP_PLATFORM_DIAG(("drop: %" STAT_COUNTER_F "\n\t", proto->drop));
	DPIP_PLATFORM_DIAG(("chkerr: %" STAT_COUNTER_F "\n\t", proto->chkerr));
	DPIP_PLATFORM_DIAG(("lenerr: %" STAT_COUNTER_F "\n\t", proto->lenerr));
	DPIP_PLATFORM_DIAG(("memerr: %" STAT_COUNTER_F "\n\t", proto->memerr));
	DPIP_PLATFORM_DIAG(("rterr: %" STAT_COUNTER_F "\n\t", proto->rterr));
	DPIP_PLATFORM_DIAG(("proterr: %" STAT_COUNTER_F "\n\t",
			    proto->proterr));
	DPIP_PLATFORM_DIAG(("opterr: %" STAT_COUNTER_F "\n\t", proto->opterr));
	DPIP_PLATFORM_DIAG(("err: %" STAT_COUNTER_F "\n\t", proto->err));
	DPIP_PLATFORM_DIAG(("cachehit: %" STAT_COUNTER_F "\n",
			    proto->cachehit));
}

void stats_display(void)
{
	LINK_STATS_DISPLAY();
	ETHARP_STATS_DISPLAY();
	IPFRAG_STATS_DISPLAY();
	IP6_FRAG_STATS_DISPLAY();
	IP_STATS_DISPLAY();
	ND6_STATS_DISPLAY();
	IP6_STATS_DISPLAY();
	ICMP_STATS_DISPLAY();
	ICMP6_STATS_DISPLAY();
	UDP_STATS_DISPLAY();
	TCP_STATS_DISPLAY();
}
#endif /* DPIP_STATS_DISPLAY */

#endif /* DPIP_STATS */
