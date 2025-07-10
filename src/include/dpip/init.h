/**
 * @file
 * dpIP initialization API
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
#ifndef DPIP_HDR_INIT_H
#define DPIP_HDR_INIT_H

#include "dpip/opt.h"

#include <rte_mempool.h>
#include <rte_mbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup dpip_version Version
 * @ingroup dpip
 * @{
 */

/** X.x.x: Major version of the stack */
#define DPIP_VERSION_MAJOR      2
/** x.X.x: Minor version of the stack */
#define DPIP_VERSION_MINOR      2
/** x.x.X: Revision of the stack */
#define DPIP_VERSION_REVISION   2
/** For release candidates, this is set to 1..254
  * For official releases, this is set to 255 (DPIP_RC_RELEASE)
  * For development versions (Git), this is set to 0 (DPIP_RC_DEVELOPMENT) */
#define DPIP_VERSION_RC         DPIP_RC_DEVELOPMENT

/** DPIP_VERSION_RC is set to DPIP_RC_RELEASE for official releases */
#define DPIP_RC_RELEASE         255
/** DPIP_VERSION_RC is set to DPIP_RC_DEVELOPMENT for Git versions */
#define DPIP_RC_DEVELOPMENT     0

#define DPIP_VERSION_IS_RELEASE     (DPIP_VERSION_RC == DPIP_RC_RELEASE)
#define DPIP_VERSION_IS_DEVELOPMENT (DPIP_VERSION_RC == DPIP_RC_DEVELOPMENT)
#define DPIP_VERSION_IS_RC          ((DPIP_VERSION_RC != DPIP_RC_RELEASE) && (DPIP_VERSION_RC != DPIP_RC_DEVELOPMENT))

/* Some helper defines to get a version string */
#define DPIP_VERSTR2(x) #x
#define DPIP_VERSTR(x) DPIP_VERSTR2(x)
#if DPIP_VERSION_IS_RELEASE
#define DPIP_VERSION_STRING_SUFFIX ""
#elif DPIP_VERSION_IS_DEVELOPMENT
#define DPIP_VERSION_STRING_SUFFIX "d"
#else
#define DPIP_VERSION_STRING_SUFFIX "rc" DPIP_VERSTR(DPIP_VERSION_RC)
#endif

/** Provides the version of the stack */
#define DPIP_VERSION   ((DPIP_VERSION_MAJOR) << 24   | (DPIP_VERSION_MINOR) << 16 | \
                        (DPIP_VERSION_REVISION) << 8 | (DPIP_VERSION_RC))
/** Provides the version of the stack as string */
#define DPIP_VERSION_STRING     DPIP_VERSTR(DPIP_VERSION_MAJOR) "." DPIP_VERSTR(DPIP_VERSION_MINOR) "." DPIP_VERSTR(DPIP_VERSION_REVISION) DPIP_VERSION_STRING_SUFFIX

/**
 * @}
 */

/* Modules initialization */
void dpip_init(struct rte_mempool *pktmbuf_pool);

#ifdef __cplusplus
}
#endif
#endif				/* DPIP_HDR_INIT_H */
