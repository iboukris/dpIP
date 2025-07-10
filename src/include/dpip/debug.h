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
#ifndef DPIP_HDR_DEBUG_H
#define DPIP_HDR_DEBUG_H

#include "dpip/arch.h"
#include "dpip/opt.h"

/**
 * @defgroup debugging_levels DPIP_DBG_MIN_LEVEL and DPIP_DBG_TYPES_ON values
 * @ingroup dpip_opts_debugmsg
 * @{
 */

/** @name Debug level (DPIP_DBG_MIN_LEVEL)
 * @{
 */
/** Debug level: ALL messages*/
#define DPIP_DBG_LEVEL_ALL     0x00
/** Debug level: Warnings. bad checksums, dropped packets, ... */
#define DPIP_DBG_LEVEL_WARNING 0x01
/** Debug level: Serious. memory allocation failures, ... */
#define DPIP_DBG_LEVEL_SERIOUS 0x02
/** Debug level: Severe */
#define DPIP_DBG_LEVEL_SEVERE  0x03
/**
 * @}
 */

#define DPIP_DBG_MASK_LEVEL    0x03
/* compatibility define only */
#define DPIP_DBG_LEVEL_OFF     DPIP_DBG_LEVEL_ALL

/** @name Enable/disable debug messages completely (DPIP_DBG_TYPES_ON)
 * @{
 */
/** flag for DPIP_DEBUGF to enable that debug message */
#define DPIP_DBG_ON            0x80U
/** flag for DPIP_DEBUGF to disable that debug message */
#define DPIP_DBG_OFF           0x00U
/**
 * @}
 */

/** @name Debug message types (DPIP_DBG_TYPES_ON)
 * @{
 */
/** flag for DPIP_DEBUGF indicating a tracing message (to follow program flow) */
#define DPIP_DBG_TRACE         0x40U
/** flag for DPIP_DEBUGF indicating a state debug message (to follow module states) */
#define DPIP_DBG_STATE         0x20U
/** flag for DPIP_DEBUGF indicating newly added code, not thoroughly tested yet */
#define DPIP_DBG_FRESH         0x10U
/** flag for DPIP_DEBUGF to halt after printing this debug message */
#define DPIP_DBG_HALT          0x08U
/**
 * @}
 */

/**
 * @}
 */

/**
 * @defgroup dpip_assertions Assertion handling
 * @ingroup dpip_opts_debug
 * @{
 */
/**
 * DPIP_NOASSERT: Disable DPIP_ASSERT checks:
 * To disable assertions define DPIP_NOASSERT in arch/cc.h.
 */
#ifdef __DOXYGEN__
#define DPIP_NOASSERT
#undef DPIP_NOASSERT
#endif
/**
 * @}
 */

#ifndef DPIP_NOASSERT
#define DPIP_ASSERT(message, assertion) do { if (!(assertion)) { \
  DPIP_PLATFORM_ASSERT(message); }} while(0)
#else /* DPIP_NOASSERT */
#define DPIP_ASSERT(message, assertion)
#endif /* DPIP_NOASSERT */

#ifndef DPIP_ERROR
#ifdef DPIP_DEBUG
#define DPIP_PLATFORM_ERROR(message) DPIP_PLATFORM_DIAG((message))
#else
#define DPIP_PLATFORM_ERROR(message)
#endif

/* if "expression" isn't true, then print "message" and execute "handler" expression */
#define DPIP_ERROR(message, expression, handler) do { if (!(expression)) { \
  DPIP_PLATFORM_ERROR(message); handler;}} while(0)
#endif /* DPIP_ERROR */

/** Enable debug message printing, but only if debug message type is enabled
 *  AND is of correct type AND is at least DPIP_DBG_LEVEL.
 */
#ifdef __DOXYGEN__
#define DPIP_DEBUG
#undef DPIP_DEBUG
#endif

#ifdef DPIP_DEBUG
#define DPIP_DEBUG_ENABLED(debug) (((debug) & DPIP_DBG_ON) && \
                                   ((debug) & DPIP_DBG_TYPES_ON) && \
                                   ((s16_t)((debug) & DPIP_DBG_MASK_LEVEL) >= DPIP_DBG_MIN_LEVEL))

#define DPIP_DEBUGF(debug, message) do { \
                               if (DPIP_DEBUG_ENABLED(debug)) { \
                                 DPIP_PLATFORM_DIAG(message); \
                                 if ((debug) & DPIP_DBG_HALT) { \
                                   while(1); \
                                 } \
                               } \
                             } while(0)

#else /* DPIP_DEBUG */
#define DPIP_DEBUG_ENABLED(debug) 0
#define DPIP_DEBUGF(debug, message)
#endif /* DPIP_DEBUG */

#endif /* DPIP_HDR_DEBUG_H */
