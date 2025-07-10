/**
 * @file
 * Support for different processor and compiler architectures
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
#ifndef DPIP_HDR_ARCH_H
#define DPIP_HDR_ARCH_H

#include <rte_log.h>

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 1234
#endif

#ifndef BIG_ENDIAN
#define BIG_ENDIAN 4321
#endif

/**
 * @defgroup compiler_abstraction Compiler/platform abstraction
 * @ingroup sys_layer
 * All defines related to this section must not be placed in opts.h,
 * but in arch/cc.h!
 * If the compiler does not provide memset() this file must include a
 * definition of it, or include a file which defines it.
 * These options cannot be \#defined in opts.h since they are not options
 * of dpIP itself, but options of the dpIP port to your system.
 * @{
 */

/** Define the byte order of the system.
 * Needed for conversion of network data to host byte order.
 * Allowed values: LITTLE_ENDIAN and BIG_ENDIAN
 */
#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif

/** Define random number generator function of your system */
#ifdef __DOXYGEN__
#define DPIP_RAND() ((u32_t)rand())
#endif

/** Platform specific diagnostic output.<br>
 * Note the default implementation pulls in printf, which may
 * in turn pull in a lot of standard library code. In resource-constrained
 * systems, this should be defined to something less resource-consuming.
 */
#ifndef DPIP_PLATFORM_DIAG
#define _Args(...) __VA_ARGS__
#define STRIP_PARENS(X) X
#define PASS_PARAMETERS(X) STRIP_PARENS( _Args X )
#define DPIP_PLATFORM_DIAG(x) do {rte_log(0, RTE_LOGTYPE_USER1, PASS_PARAMETERS(x));} while(0)
#endif

/** Platform specific assertion handling.<br>
 * Note the default implementation pulls in printf, fflush and abort, which may
 * in turn pull in a lot of standard library code. In resource-constrained
 * systems, this should be defined to something less resource-consuming.
 */
#ifndef DPIP_PLATFORM_ASSERT
#define DPIP_PLATFORM_ASSERT(x) do {printf("Assertion \"%s\" failed at line %d in %s\n", \
                                     x, __LINE__, __FILE__); fflush(NULL); abort();} while(0)
#include <stdio.h>
#include <stdlib.h>
#endif

/** Define this to 1 in arch/cc.h of your port if you do not want to
 * include stddef.h header to get size_t. You need to typedef size_t
 * by yourself in this case.
 */
#ifndef DPIP_NO_STDDEF_H
#define DPIP_NO_STDDEF_H 0
#endif

#if !DPIP_NO_STDDEF_H
#include <stddef.h>		/* for size_t */
#endif

/** Define this to 1 in arch/cc.h of your port if your compiler does not provide
 * the stdint.h header. You need to typedef the generic types listed in
 * dpip/arch.h yourself in this case (u8_t, u16_t...).
 */
#ifndef DPIP_NO_STDINT_H
#define DPIP_NO_STDINT_H 0
#endif

/* Define generic types used in dpIP */
#if !DPIP_NO_STDINT_H
#include <stdint.h>
/* stdint.h is C99 which should also provide support for 64-bit integers */
#if !defined(DPIP_HAVE_INT64) && defined(UINT64_MAX)
#define DPIP_HAVE_INT64 1
#endif
typedef uint8_t u8_t;
typedef int8_t s8_t;
typedef uint16_t u16_t;
typedef int16_t s16_t;
typedef uint32_t u32_t;
typedef int32_t s32_t;
#if DPIP_HAVE_INT64
typedef uint64_t u64_t;
typedef int64_t s64_t;
#endif
typedef uintptr_t mem_ptr_t;
#endif

/** Define this to 1 in arch/cc.h of your port if your compiler does not provide
 * the inttypes.h header. You need to define the format strings listed in
 * dpip/arch.h yourself in this case (X8_F, U16_F...).
 */
#ifndef DPIP_NO_INTTYPES_H
#define DPIP_NO_INTTYPES_H 0
#endif

/* Define (sn)printf formatters for these dpIP types */
#if !DPIP_NO_INTTYPES_H
#include <inttypes.h>
#ifndef X8_F
#define X8_F  "02" PRIx8
#endif
#ifndef U16_F
#define U16_F PRIu16
#endif
#ifndef S16_F
#define S16_F PRId16
#endif
#ifndef X16_F
#define X16_F PRIx16
#endif
#ifndef U32_F
#define U32_F PRIu32
#endif
#ifndef S32_F
#define S32_F PRId32
#endif
#ifndef X32_F
#define X32_F PRIx32
#endif
#ifndef SZT_F
#define SZT_F PRIuPTR
#endif
#endif

/** Define this to 1 in arch/cc.h of your port if your compiler does not provide
 * the limits.h header. You need to define the type limits yourself in this case
 * (e.g. INT_MAX, SSIZE_MAX).
 */
#ifndef DPIP_NO_LIMITS_H
#define DPIP_NO_LIMITS_H 0
#endif

/* Include limits.h? */
#if !DPIP_NO_LIMITS_H
#include <limits.h>
#endif

/* Do we need to define ssize_t? This is a compatibility hack:
 * Unfortunately, this type seems to be unavailable on some systems (even if
 * sys/types or unistd.h are available).
 * Being like that, we define it to 'int' if SSIZE_MAX is not defined.
 */
#ifdef SSIZE_MAX
/* If SSIZE_MAX is defined, unistd.h should provide the type as well */
#ifndef DPIP_NO_UNISTD_H
#define DPIP_NO_UNISTD_H 0
#endif
#if !DPIP_NO_UNISTD_H
#include <unistd.h>
#endif
#else /* SSIZE_MAX */
typedef int ssize_t;
#define SSIZE_MAX INT_MAX
#endif /* SSIZE_MAX */

/* some maximum values needed in dpip code */
#define DPIP_UINT32_MAX 0xffffffff

/** Define this to 1 in arch/cc.h of your port if your compiler does not provide
 * the ctype.h header. If ctype.h is available, a few character functions
 * are mapped to the appropriate functions (dpip_islower, dpip_isdigit...), if
 * not, a private implementation is provided.
 */
#ifndef DPIP_NO_CTYPE_H
#define DPIP_NO_CTYPE_H 0
#endif

#if DPIP_NO_CTYPE_H
#define dpip_in_range(c, lo, up)  ((u8_t)(c) >= (lo) && (u8_t)(c) <= (up))
#define dpip_isdigit(c)           dpip_in_range((c), '0', '9')
#define dpip_isxdigit(c)          (dpip_isdigit(c) || dpip_in_range((c), 'a', 'f') || dpip_in_range((c), 'A', 'F'))
#define dpip_islower(c)           dpip_in_range((c), 'a', 'z')
#define dpip_isspace(c)           ((c) == ' ' || (c) == '\f' || (c) == '\n' || (c) == '\r' || (c) == '\t' || (c) == '\v')
#define dpip_isupper(c)           dpip_in_range((c), 'A', 'Z')
#define dpip_tolower(c)           (dpip_isupper(c) ? (c) - 'A' + 'a' : c)
#define dpip_toupper(c)           (dpip_islower(c) ? (c) - 'a' + 'A' : c)
#else
#include <ctype.h>
#define dpip_isdigit(c)           isdigit((unsigned char)(c))
#define dpip_isxdigit(c)          isxdigit((unsigned char)(c))
#define dpip_islower(c)           islower((unsigned char)(c))
#define dpip_isspace(c)           isspace((unsigned char)(c))
#define dpip_isupper(c)           isupper((unsigned char)(c))
#define dpip_tolower(c)           tolower((unsigned char)(c))
#define dpip_toupper(c)           toupper((unsigned char)(c))
#endif

/** C++ const_cast<target_type>(val) equivalent to remove constness from a value (GCC -Wcast-qual) */
#ifndef DPIP_CONST_CAST
#define DPIP_CONST_CAST(target_type, val) ((target_type)((ptrdiff_t)val))
#endif

/** Get rid of alignment cast warnings (GCC -Wcast-align) */
#ifndef DPIP_ALIGNMENT_CAST
#define DPIP_ALIGNMENT_CAST(target_type, val) DPIP_CONST_CAST(target_type, val)
#endif

/** Get rid of warnings related to pointer-to-numeric and vice-versa casts,
 * e.g. "conversion from 'u8_t' to 'void *' of greater size"
 */
#ifndef DPIP_PTR_NUMERIC_CAST
#define DPIP_PTR_NUMERIC_CAST(target_type, val) DPIP_CONST_CAST(target_type, val)
#endif

/** Avoid warnings/errors related to implicitly casting away packed attributes by doing a explicit cast */
#ifndef DPIP_PACKED_CAST
#define DPIP_PACKED_CAST(target_type, val) DPIP_CONST_CAST(target_type, val)
#endif

/** Allocates a memory buffer of specified size that is of sufficient size to align
 * its start address using DPIP_MEM_ALIGN.
 * You can declare your own version here e.g. to enforce alignment without adding
 * trailing padding bytes (see DPIP_MEM_ALIGN_BUFFER) or your own section placement
 * requirements.<br>
 * e.g. if you use gcc and need 32 bit alignment:<br>
 * \#define DPIP_DECLARE_MEMORY_ALIGNED(variable_name, size) u8_t variable_name[size] \_\_attribute\_\_((aligned(4)))<br>
 * or more portable:<br>
 * \#define DPIP_DECLARE_MEMORY_ALIGNED(variable_name, size) u32_t variable_name[(size + sizeof(u32_t) - 1) / sizeof(u32_t)]
 */
#ifndef DPIP_DECLARE_MEMORY_ALIGNED
#define DPIP_DECLARE_MEMORY_ALIGNED(variable_name, size) u8_t variable_name[DPIP_MEM_ALIGN_BUFFER(size)]
#endif

/** Calculate memory size for an aligned buffer - returns the next highest
 * multiple of MEM_ALIGNMENT (e.g. DPIP_MEM_ALIGN_SIZE(3) and
 * DPIP_MEM_ALIGN_SIZE(4) will both yield 4 for MEM_ALIGNMENT == 4).
 */
#ifndef DPIP_MEM_ALIGN_SIZE
#define DPIP_MEM_ALIGN_SIZE(size) (((size) + MEM_ALIGNMENT - 1U) & ~(MEM_ALIGNMENT-1U))
#endif

/** Calculate safe memory size for an aligned buffer when using an unaligned
 * type as storage. This includes a safety-margin on (MEM_ALIGNMENT - 1) at the
 * start (e.g. if buffer is u8_t[] and actual data will be u32_t*)
 */
#ifndef DPIP_MEM_ALIGN_BUFFER
#define DPIP_MEM_ALIGN_BUFFER(size) (((size) + MEM_ALIGNMENT - 1U))
#endif

/** Align a memory pointer to the alignment defined by MEM_ALIGNMENT
 * so that ADDR % MEM_ALIGNMENT == 0
 */
#ifndef DPIP_MEM_ALIGN
#define DPIP_MEM_ALIGN(addr) ((void *)(((mem_ptr_t)(addr) + MEM_ALIGNMENT - 1) & ~(mem_ptr_t)(MEM_ALIGNMENT-1)))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** Packed structs support.
  * Placed BEFORE declaration of a packed struct.<br>
  * For examples of packed struct declarations, see include/dpip/prot/ subfolder.<br>
  * A port to GCC/clang is included in dpIP, if you use these compilers there is nothing to do here.
  */
#ifndef PACK_STRUCT_BEGIN
#define PACK_STRUCT_BEGIN
#endif				/* PACK_STRUCT_BEGIN */

/** Packed structs support.
  * Placed AFTER declaration of a packed struct.<br>
  * For examples of packed struct declarations, see include/dpip/prot/ subfolder.<br>
  * A port to GCC/clang is included in dpIP, if you use these compilers there is nothing to do here.
  */
#ifndef PACK_STRUCT_END
#define PACK_STRUCT_END
#endif				/* PACK_STRUCT_END */

/** Packed structs support.
  * Placed between end of declaration of a packed struct and trailing semicolon.<br>
  * For examples of packed struct declarations, see include/dpip/prot/ subfolder.<br>
  * A port to GCC/clang is included in dpIP, if you use these compilers there is nothing to do here.
  */
#ifndef PACK_STRUCT_STRUCT
#if defined(__GNUC__) || defined(__clang__)
#define PACK_STRUCT_STRUCT __attribute__((packed))
#else
#define PACK_STRUCT_STRUCT
#endif
#endif				/* PACK_STRUCT_STRUCT */

/** Packed structs support.
  * Wraps u32_t and u16_t members.<br>
  * For examples of packed struct declarations, see include/dpip/prot/ subfolder.<br>
  * A port to GCC/clang is included in dpIP, if you use these compilers there is nothing to do here.
  */
#ifndef PACK_STRUCT_FIELD
#define PACK_STRUCT_FIELD(x) x
#endif				/* PACK_STRUCT_FIELD */

/** Packed structs support.
  * Wraps u8_t members, where some compilers warn that packing is not necessary.<br>
  * For examples of packed struct declarations, see include/dpip/prot/ subfolder.<br>
  * A port to GCC/clang is included in dpIP, if you use these compilers there is nothing to do here.
  */
#ifndef PACK_STRUCT_FLD_8
#define PACK_STRUCT_FLD_8(x) PACK_STRUCT_FIELD(x)
#endif				/* PACK_STRUCT_FLD_8 */

/** Packed structs support.
  * Wraps members that are packed structs themselves, where some compilers warn that packing is not necessary.<br>
  * For examples of packed struct declarations, see include/dpip/prot/ subfolder.<br>
  * A port to GCC/clang is included in dpIP, if you use these compilers there is nothing to do here.
  */
#ifndef PACK_STRUCT_FLD_S
#define PACK_STRUCT_FLD_S(x) PACK_STRUCT_FIELD(x)
#endif				/* PACK_STRUCT_FLD_S */

/** Eliminates compiler warning about unused arguments (GCC -Wextra -Wunused). */
#ifndef DPIP_UNUSED_ARG
#define DPIP_UNUSED_ARG(x) (void)x
#endif				/* DPIP_UNUSED_ARG */

/** DPIP_PROVIDE_ERRNO==1: Let dpIP provide ERRNO values and the 'errno' variable.
 * If this is disabled, cc.h must either define 'errno', include <errno.h>,
 * define DPIP_ERRNO_STDINCLUDE to get <errno.h> included or
 * define DPIP_ERRNO_INCLUDE to <errno.h> or equivalent.
 */
#if defined __DOXYGEN__
#define DPIP_PROVIDE_ERRNO
#endif

/* Use a special, reproducible version of rand() for fuzz tests? */
#ifdef DPIP_RAND_FOR_FUZZ
#ifdef DPIP_RAND
#undef DPIP_RAND
#endif
u32_t dpip_fuzz_rand(void);
#define DPIP_RAND() dpip_fuzz_rand()
#endif

/**
 * @}
 */

#ifdef __cplusplus
}
#endif
#endif				/* DPIP_HDR_ARCH_H */
