/**
 * @file
 * Internal helpers shared by the agent sources.
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
 * This file replaces lwIP's opt.h, def.h, err.h, arch.h, and arch/cc.h. What
 * survived of them is the handful of macros the agent sources actually use,
 * plus the ERR_* codes, which are the agent's own error vocabulary.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SNMP_PRIV_H
#define SNMP_PRIV_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/logging/log.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/sys/__assert.h>
#include <zephyr/sys/util.h>

#include <snmp/snmp_opts.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @name Result codes
 *
 * Internal to the agent. The public functions in snmp_agent.h return 0 or a
 * negative errno instead.
 * @{
 */
#define ERR_OK   0   /**< No error. */
#define ERR_MEM  -1  /**< Out of memory. */
#define ERR_BUF  -2  /**< Buffer full. */
#define ERR_VAL  -6  /**< Illegal value. */
#define ERR_ARG  -16 /**< Illegal argument. */
#define ERR_CONN -11 /**< Not connected. */
#define ERR_RTE  -4  /**< Routing problem. */
/** @} */

#define LWIP_MIN(x, y)     MIN(x, y)
#define LWIP_MAX(x, y)     MAX(x, y)
#define LWIP_ARRAYSIZE(x)  ARRAY_SIZE(x)
#define LWIP_UNUSED_ARG(x) ARG_UNUSED(x)

#define MEMCPY(dst, src, len) memcpy(dst, src, len)

/** Byte-swap a compile-time constant, so the swap costs nothing at runtime. */
#define PP_HTONS(x)                                                                                \
	((uint16_t)((((x) & (uint16_t)0x00ffU) << 8) | (((x) & (uint16_t)0xff00U) >> 8)))
#define PP_NTOHS(x) PP_HTONS(x)

/** The agent encodes Counter64, so 64-bit integers are required. */
#define LWIP_HAVE_INT64 1

/** Guards a caller contract; every use marks a programming error rather than a
 *  condition a peer can provoke. Compiles out unless CONFIG_ASSERT is set.
 */
#define LWIP_ASSERT(phrase, expression) __ASSERT(expression, "%s", (phrase))

/** If @p expression is false, run @p handler. @p message is for the reader. */
#define LWIP_ERROR(message, expression, handler)                                                   \
	do {                                                                                       \
		if (!(expression)) {                                                               \
			handler;                                                                   \
		}                                                                                  \
	} while (0)

/** Milliseconds since boot. */
uint32_t sys_now(void);

/** sysUpTime is in hundredths of a second; sys_now() is in milliseconds.
 *  This wraps after about 49 days, as the MIB-2 type does.
 */
#define MIB2_COPY_SYSUPTIME_TO(ptrToVal) (*(ptrToVal) = (sys_now() / 10))

/** Longest OID rendered as text: SNMP_MAX_OBJ_ID_LEN sub-identifiers, each at
 *  most 10 digits plus a separator, and the terminator.
 */
#define SNMP_OID_STR_LEN (SNMP_MAX_OBJ_ID_LEN * 11U + 1U)

/**
 * @brief Render an OID as dotted decimal into @p buf.
 *
 * @return @p buf, always NUL-terminated.
 */
const char *snmp_oid_to_str(char *buf, size_t buf_size, size_t oid_len, const uint32_t *oid_words);

/** Dispatch an OID to the callbacks installed with install_snmp_handler(). */
size_t snmp_private_call_handler(const char *prefix, void *value);

#ifdef __cplusplus
}
#endif

#endif /* SNMP_PRIV_H */
