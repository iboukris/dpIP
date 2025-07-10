/**
 * @file
 * various utility macros
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

#ifndef DPIP_HDR_DEF_H
#define DPIP_HDR_DEF_H

/* arch.h might define NULL already */
#include "dpip/arch.h"
#include "dpip/opt.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Create u32_t value from bytes */
#define DPIP_MAKEU32(a,b,c,d) (((u32_t)((a) & 0xff) << 24) | \
                               ((u32_t)((b) & 0xff) << 16) | \
                               ((u32_t)((c) & 0xff) << 8)  | \
                                (u32_t)((d) & 0xff))

#if BYTE_ORDER == BIG_ENDIAN
#define dpip_htons(x) ((u16_t)(x))
#define dpip_ntohs(x) ((u16_t)(x))
#define dpip_htonl(x) ((u32_t)(x))
#define dpip_ntohl(x) ((u32_t)(x))
#define PP_HTONS(x)   ((u16_t)(x))
#define PP_NTOHS(x)   ((u16_t)(x))
#define PP_HTONL(x)   ((u32_t)(x))
#define PP_NTOHL(x)   ((u32_t)(x))
#else				/* BYTE_ORDER != BIG_ENDIAN */
#ifndef dpip_htons
u16_t dpip_htons(u16_t x);
#endif
#define dpip_ntohs(x) dpip_htons(x)

#ifndef dpip_htonl
u32_t dpip_htonl(u32_t x);
#endif
#define dpip_ntohl(x) dpip_htonl(x)

/* These macros should be calculated by the preprocessor and are used
   with compile-time constants only (so that there is no little-endian
   overhead at runtime). */
#define PP_HTONS(x) ((u16_t)((((x) & (u16_t)0x00ffU) << 8) | (((x) & (u16_t)0xff00U) >> 8)))
#define PP_NTOHS(x) PP_HTONS(x)
#define PP_HTONL(x) ((((x) & (u32_t)0x000000ffUL) << 24) | \
                     (((x) & (u32_t)0x0000ff00UL) <<  8) | \
                     (((x) & (u32_t)0x00ff0000UL) >>  8) | \
                     (((x) & (u32_t)0xff000000UL) >> 24))
#define PP_NTOHL(x) PP_HTONL(x)
#endif				/* BYTE_ORDER == BIG_ENDIAN */

/* Provide usual function names as macros for users, but this can be turned off */
#ifndef DPIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS
#define htons(x) dpip_htons(x)
#define ntohs(x) dpip_ntohs(x)
#define htonl(x) dpip_htonl(x)
#define ntohl(x) dpip_ntohl(x)
#endif

/* Functions that are not available as standard implementations.
 * In cc.h, you can #define these to implementations available on
 * your platform to save some code bytes if you use these functions
 * in your application, too.
 */

#ifndef dpip_itoa
/* This can be #defined to itoa() or snprintf(result, bufsize, "%d", number) depending on your platform */
void dpip_itoa(char *result, size_t bufsize, int number);
#endif
#ifndef dpip_strnicmp
/* This can be #defined to strnicmp() or strncasecmp() depending on your platform */
int dpip_strnicmp(const char *str1, const char *str2, size_t len);
#endif
#ifndef dpip_stricmp
/* This can be #defined to stricmp() or strcasecmp() depending on your platform */
int dpip_stricmp(const char *str1, const char *str2);
#endif
#ifndef dpip_strnstr
/* This can be #defined to strnstr() depending on your platform */
char *dpip_strnstr(const char *buffer, const char *token, size_t n);
#endif
#ifndef dpip_strnistr
/* This can be #defined to strnistr() depending on your platform */
char *dpip_strnistr(const char *buffer, const char *token, size_t n);
#endif
#ifndef dpip_memcmp_consttime
/* This could be #defined to something existing on your platform
 * The goal of this function is to compare memory with constant runtime in order to prevent
 * timing attacks to various parts in the stack.
 * To do that, in contrast to memcmp(), it only returns:
 * 0: equal
 * != 0: not equal
 */
int dpip_memcmp_consttime(const void *s1, const void *s2, size_t len);
#endif

#ifdef __cplusplus
}
#endif
#endif				/* DPIP_HDR_DEF_H */
