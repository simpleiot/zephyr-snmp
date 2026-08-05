/**
 * @file
 * SNMP server options list
 */

/*
 * Copyright (c) 2015 Dirk Ziegelmeier
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
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Dirk Ziegelmeier
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef ZEPHYR_INCLUDE_SNMP_OPTS_H_
#define ZEPHYR_INCLUDE_SNMP_OPTS_H_

#include <stddef.h>
#include <stdint.h>

#include <zephyr/sys/util.h>

/**
 * @defgroup snmp_opts Options
 * @ingroup snmp
 * @{
 */

/**
 * LWIP_SNMP==1: This enables the lwIP SNMP agent. UDP must be available
 * for SNMP transport.
 * If you want to use your own SNMP agent, leave this disabled.
 * To integrate MIB2 of an external agent, you need to enable
 * LWIP_MIB2_CALLBACKS and MIB2_STATS. This will give you the callbacks
 * and statistics counters you need to get MIB2 working.
 */
#define LWIP_SNMP 1

/**
 * SNMP_TRAP_DESTINATIONS: Number of trap destinations. At least one trap
 * destination is required
 */
#define SNMP_TRAP_DESTINATIONS CONFIG_SNMP_AGENT_TRAP_DESTINATIONS

/**
 * Only allow SNMP write actions that are 'safe' (e.g. disabling netifs is not
 * a safe action and disabled when SNMP_SAFE_REQUESTS = 1).
 * Unsafe requests are disabled by default!
 */
#if !defined SNMP_SAFE_REQUESTS || defined __DOXYGEN__
#define SNMP_SAFE_REQUESTS 1
#endif

/**
 * The maximum length of strings used.
 */
#if !defined SNMP_MAX_OCTET_STRING_LEN || defined __DOXYGEN__
#define SNMP_MAX_OCTET_STRING_LEN 127
#endif

/**
 * The maximum number of Sub ID's inside an object identifier.
 * Indirectly this also limits the maximum depth of SNMP tree.
 */
#if !defined SNMP_MAX_OBJ_ID_LEN || defined __DOXYGEN__
#define SNMP_MAX_OBJ_ID_LEN 50
#endif

#if !defined SNMP_MAX_VALUE_SIZE || defined __DOXYGEN__
/**
 * The minimum size of a value.
 */
#define SNMP_MIN_VALUE_SIZE                                                                        \
	(2 *                                                                                       \
	 sizeof(uint32_t *)) /* size required to store the basic types (8 bytes for counter64) */
/**
 * The maximum size of a value.
 */
#define SNMP_MAX_VALUE_SIZE                                                                        \
	MAX(MAX((SNMP_MAX_OCTET_STRING_LEN), sizeof(uint32_t) * (SNMP_MAX_OBJ_ID_LEN)),            \
	    SNMP_MIN_VALUE_SIZE)
#endif

/**
 * The snmp read-access community. Used for write-access and traps, too
 * unless SNMP_COMMUNITY_WRITE or SNMP_COMMUNITY_TRAP are enabled, respectively.
 */
#if !defined SNMP_COMMUNITY || defined __DOXYGEN__
#define SNMP_COMMUNITY "public"
#endif

/**
 * The snmp write-access community.
 * Set this community to "" in order to disallow any write access.
 */
#if !defined SNMP_COMMUNITY_WRITE || defined __DOXYGEN__
#define SNMP_COMMUNITY_WRITE "private"
#endif

/**
 * The snmp community used for sending traps.
 */
#if !defined SNMP_COMMUNITY_TRAP || defined __DOXYGEN__
#define SNMP_COMMUNITY_TRAP "public"
#endif

/**
 * The maximum length of community string.
 * If community names shall be adjusted at runtime via snmp_set_community() calls,
 * enter here the possible maximum length (+1 for terminating null character).
 */
#if !defined SNMP_MAX_COMMUNITY_STR_LEN || defined __DOXYGEN__
#define SNMP_MAX_COMMUNITY_STR_LEN                                                                 \
	MAX(MAX(sizeof(SNMP_COMMUNITY), sizeof(SNMP_COMMUNITY_WRITE)), sizeof(SNMP_COMMUNITY_TRAP))
#endif

/**
 * The OID identifiying the device. This may be the enterprise OID itself or any OID located below
 * it in tree.
 */
#if !defined SNMP_DEVICE_ENTERPRISE_OID || defined __DOXYGEN__
#define SNMP_LWIP_ENTERPRISE_OID       62530
/**
 * IANA assigned enterprise ID for lwIP is 62530
 * @see http://www.iana.org/assignments/enterprise-numbers
 *
 * @note this enterprise ID is assigned to the lwIP project,
 * all object identifiers living under this ID are assigned
 * by the lwIP maintainers!
 * @note don't change this define, use snmp_set_device_enterprise_oid()
 *
 * If you need to create your own private MIB you'll need
 * to apply for your own enterprise ID with IANA:
 * http://www.iana.org/numbers.html
 */
#define SNMP_DEVICE_ENTERPRISE_OID     {1, 3, 6, 1, 4, 1, SNMP_LWIP_ENTERPRISE_OID}
/**
 * Length of SNMP_DEVICE_ENTERPRISE_OID
 */
#define SNMP_DEVICE_ENTERPRISE_OID_LEN 7
#endif

/**
 * SNMP_DEBUG: Enable debugging for SNMP messages.
 */
#if !defined SNMP_DEBUG || defined __DOXYGEN__
#define SNMP_DEBUG 0
#endif

/**
 * SNMP_MIB_DEBUG: Enable debugging for SNMP MIBs.
 */
#if !defined SNMP_MIB_DEBUG || defined __DOXYGEN__
#define SNMP_MIB_DEBUG 0
#endif

/**
 * Indicates if the MIB2 implementation of LWIP SNMP stack is used.
 */
#if !defined SNMP_LWIP_MIB2 || defined __DOXYGEN__
#define SNMP_LWIP_MIB2 1
#endif

/**
 * Value return for sysDesc field of MIB2.
 */
#if !defined SNMP_LWIP_MIB2_SYSDESC || defined __DOXYGEN__
#define SNMP_LWIP_MIB2_SYSDESC "sysDesc"
#endif

/**
 * Value return for sysName field of MIB2.
 * To make sysName field settable, call snmp_mib2_set_sysname() to provide the necessary buffers.
 */
#if !defined SNMP_LWIP_MIB2_SYSNAME || defined __DOXYGEN__
#define SNMP_LWIP_MIB2_SYSNAME "sysName"
#endif

/**
 * Value return for sysContact field of MIB2.
 * To make sysContact field settable, call snmp_mib2_set_syscontact() to provide the necessary
 * buffers.
 */
#if !defined SNMP_LWIP_MIB2_SYSCONTACT || defined __DOXYGEN__
#define SNMP_LWIP_MIB2_SYSCONTACT "sysContact"
#endif

/**
 * Value return for sysLocation field of MIB2.
 * To make sysLocation field settable, call snmp_mib2_set_syslocation() to provide the necessary
 * buffers.
 */
#if !defined SNMP_LWIP_MIB2_SYSLOCATION || defined __DOXYGEN__
#define SNMP_LWIP_MIB2_SYSLOCATION "sysLocation"
#endif

/**
 * This value is used to limit the repetitions processed in GetBulk requests (value == 0 means no
 * limitation). This may be useful to limit the load for a single request. According to SNMP RFC
 * 1905 it is allowed to not return all requested variables from a GetBulk request if system load
 * would be too high. so the effect is that the client will do more requests to gather all data. For
 * the stack this could be useful in case that SNMP processing is done in TCP/IP thread. In this
 * situation a request with many repetitions could block the thread for a longer time. Setting limit
 * here will keep the stack more responsive.
 */
#if !defined SNMP_LWIP_GETBULK_MAX_REPETITIONS || defined __DOXYGEN__
#define SNMP_LWIP_GETBULK_MAX_REPETITIONS 0
#endif

/**
 * @}
 */

#endif /* ZEPHYR_INCLUDE_SNMP_OPTS_H_ */
