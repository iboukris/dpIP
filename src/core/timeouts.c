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
 *         Simon Goldschmidt
 *
 */

#include "dpip/opt.h"

#include "dpip/timeouts.h"
#include "dpip/priv/tcp_priv.h"

#include "dpip/def.h"
#include "dpip/memp.h"

#include "dpip/etharp.h"
#include "dpip/nd6.h"
#include "dpip/sys.h"
#include "dpip/pbuf.h"

#include <rte_timer.h>
#include <rte_lcore.h>

static RTE_DEFINE_PER_LCORE(uint32_t, timer_data_id);

#define HANDLER(x) x

/** This array contains all stack-internal cyclic timers. To get the number of
 * timers, use RTE_DIM() */
struct dpip_cyclic_timer dpip_cyclic_timers[] = {
#if DPIP_TCP
	/* The TCP timer is a special case: it does not have to run always and
	   is triggered to start from TCP using tcp_timer_needed() */
	{TCP_TMR_INTERVAL, HANDLER(tcp_tmr), {0}},
#endif /* DPIP_TCP */
#if IP_REASSEMBLY
	{IP_TMR_INTERVAL, HANDLER(ip_reass_tmr), {0}},
#endif /* IP_REASSEMBLY */
#if DPIP_ARP
	{ARP_TMR_INTERVAL, HANDLER(etharp_tmr), {0}},
#endif /* DPIP_ARP */
	{ND6_TMR_INTERVAL, HANDLER(nd6_tmr), {0}},
#if DPIP_IPV6_REASS
	{IP6_REASS_TMR_INTERVAL, HANDLER(ip6_reass_tmr), {0}},
#endif /* DPIP_IPV6_REASS */
};

const int dpip_num_cyclic_timers = RTE_DIM(dpip_cyclic_timers);

#if DPIP_TIMERS

/**
 * Timer callback function that calls cyclic->handler() and reschedules itself.
 *
 * @param arg unused argument
 */
static void dpip_cyclic_timer(struct rte_timer *tim)
{
	const struct dpip_cyclic_timer *cyclic =
	    (const struct dpip_cyclic_timer *)tim->arg;

	cyclic->handler();
}

/** Initialize this module */
void sys_timeouts_init(void)
{
	int err;
	size_t i;

	err = rte_timer_subsystem_init();
	if (err != 0) {
		DPIP_DEBUGF(TIMERS_DEBUG,
			    ("warn: rte_timer_subsystem_init() returned %d\n",
			     err));
	}

	err = rte_timer_data_alloc(&RTE_PER_LCORE(timer_data_id));
	if (err != 0) {
		DPIP_DEBUGF(TIMERS_DEBUG,
			    ("warn: rte_timer_data_alloc() returned %d\n",
			     err));
		//TODO return err..
	}

	/* tcp_tmr() at index 0 is started on demand */
	for (i = 0; i < RTE_DIM(dpip_cyclic_timers); i++) {
		/* we have to cast via size_t to get rid of const warning
		   (this is OK as cyclic_timer() casts back to const* */
		uint64_t interval_cyc;

		interval_cyc =
		    dpip_cyclic_timers[i].interval_ms * rte_get_timer_hz() /
		    MS_PER_S;

		rte_timer_init(&dpip_cyclic_timers[i].timer);

		err =
		    rte_timer_alt_reset(RTE_PER_LCORE(timer_data_id),
					&dpip_cyclic_timers[i].timer,
					interval_cyc, PERIODICAL,
					rte_lcore_id(), NULL,
					&dpip_cyclic_timers[i]);
		if (err != 0) {
			DPIP_DEBUGF(TIMERS_DEBUG,
				    ("warn: rte_timer_alt_reset() returned %d\n",
				     err));
		}
	}
}

/**
 * @ingroup dpip_nosys
 * Handle timeouts. Uses sys_now() to call timeout
 * handler functions when timeouts expire.
 *
 * Must be called periodically from your main loop.
 */
void sys_check_timeouts(void)
{
	int err;
	err =
	    rte_timer_alt_manage(RTE_PER_LCORE(timer_data_id), NULL, 0,
				 dpip_cyclic_timer);
	if (err != 0) {
		DPIP_DEBUGF(TIMERS_DEBUG,
			    ("warn: rte_timer_alt_manage() returned %d\n",
			     err));
	}
}

#endif /* DPIP_TIMERS */
