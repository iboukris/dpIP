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
#ifndef DPIP_HDR_TIMEOUTS_H
#define DPIP_HDR_TIMEOUTS_H

#include "dpip/opt.h"
#include "dpip/err.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef DPIP_DEBUG_TIMERNAMES
#ifdef DPIP_DEBUG
#define DPIP_DEBUG_TIMERNAMES SYS_DEBUG
#else				/* DPIP_DEBUG */
#define DPIP_DEBUG_TIMERNAMES 0
#endif				/* DPIP_DEBUG */
#endif

/** Returned by sys_timeouts_sleeptime() to indicate there is no timer, so we
 * can sleep forever.
 */
#define SYS_TIMEOUTS_SLEEPTIME_INFINITE 0xFFFFFFFF

/** Function prototype for a stack-internal timer function that has to be
 * called at a defined interval */
typedef void (*dpip_cyclic_timer_handler)(void);

/** This struct contains information about a stack-internal timer function
 that has to be called at a defined interval */
#include <rte_timer.h>
struct dpip_cyclic_timer {
	u32_t interval_ms;
	dpip_cyclic_timer_handler handler;
	struct rte_timer timer;
};

#if DPIP_TIMERS

/** Function prototype for a timeout callback function. Register such a function
 * using sys_timeout().
 *
 * @param arg Additional argument to pass to the function - set up by sys_timeout()
 */
typedef void (*sys_timeout_handler)(void *arg);

struct sys_timeo {
	struct sys_timeo *next;
	u32_t time;
	sys_timeout_handler h;
	void *arg;
#if DPIP_DEBUG_TIMERNAMES
	const char *handler_name;
#endif				/* DPIP_DEBUG_TIMERNAMES */
};

void sys_timeouts_init(void);

void sys_timeout(u32_t msecs, sys_timeout_handler handler, void *arg);

void sys_check_timeouts(void);

#endif				/* DPIP_TIMERS */

#ifdef __cplusplus
}
#endif
#endif				/* DPIP_HDR_TIMEOUTS_H */
