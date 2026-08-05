/**
 * @file
 * MIB tree access/construction functions.
 */

/*
 * Copyright (c) 2006 Axon Digital Design B.V., The Netherlands.
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
 * Author: Christiaan Simons <christiaan.simons@axon.tv>
 *         Martin Hentschel <info@cl-soft.de>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @defgroup snmp SNMPv2c/v3 agent
 * @ingroup apps
 * SNMPv2c and SNMPv3 compatible agent<br>
 * There is also a MIB compiler and a MIB viewer in lwIP/contrib subdir
 * (lwip/contrib/apps/LwipMibCompiler).<br>
 * The agent implements the most important MIB2 MIBs including IPv6 support
 * (interfaces, UDP, TCP, SNMP, ICMP, SYSTEM). IP MIB is an older version
 * without IPv6 statistics (TODO).<br>
 * Rewritten by Martin Hentschel <info@cl-soft.de> and
 * Dirk Ziegelmeier <dziegel@gmx.de>
 *
 * 0 Agent Capabilities
 * ====================
 *
 * Features:
 * ---------
 * - SNMPv2c support.
 * - SNMPv3 support (a port to ARM mbedtls is provided, LWIP_SNMP_V3_MBEDTLS option).
 * - Low RAM usage - no memory pools, stack only.
 * - MIB2 implementation is separated from SNMP stack.
 * - Support for multiple MIBs (snmp_set_mibs() call) - e.g. for private MIB.
 * - Simple and generic API for MIB implementation.
 * - Comfortable node types and helper functions for scalar arrays and tables.
 * - Counter64, bit and truthvalue datatype support.
 * - Callbacks for SNMP writes e.g. to implement persistency.
 * - Runs on two APIs: RAW and netconn.
 * - Async API is gone - the stack now supports netconn API instead,
 *   so blocking operations can be done in MIB calls.
 *   SNMP runs in a worker thread when netconn API is used.
 * - Simplified thread sync support for MIBs - useful when MIBs
 *   need to access variables shared with other threads where no locking is
 *   possible. Used in MIB2 to access lwIP stats from lwIP thread.
 *
 * MIB compiler (code generator):
 * ------------------------------
 * - Provided in contrib dir.
 * - Written in C#. MIB viewer using Windows Forms.
 * - Developed on Windows with Visual Studio 2010.
 * - Can be compiled and used on all platforms with http://www.monodevelop.com/.
 * - Based on a heavily modified version of of SharpSnmpLib (a4bd05c6afb4)
 *   (https://sharpsnmplib.codeplex.com/SourceControl/network/forks/Nemo157/MIBParserUpdate).
 *   This has been the last known revision of that code before being converted to
 *   closed source. The new code on github has completely changed, so we can not
 *   just update :-(
 * - MIB parser, C file generation framework and LWIP code generation are cleanly
 *   separated, which means the code may be useful as a base for code generation
 *   of other SNMP agents.
 *
 * Notes:
 * ------
 * - Stack and MIB compiler were used to implement a Profinet device.
 *   Compiled/implemented MIBs: LLDP-MIB, LLDP-EXT-DOT3-MIB, LLDP-EXT-PNO-MIB.
 *
 * SNMPv1 per RFC1157 and SNMPv2c per RFC 3416
 * -------------------------------------------
 *   Note the S in SNMP stands for "Simple". Note that "Simple" is
 *   relative. SNMP is simple compared to the complex ISO network
 *   management protocols CMIP (Common Management Information Protocol)
 *   and CMOT (CMip Over Tcp).
 *
 * SNMPv3
 * ------
 * When SNMPv3 is used, several functions from snmpv3.h must be implemented
 * by the user. This is mainly user management and persistence handling.
 * The sample provided in lwip-contrib is insecure, don't use it in production
 * systems, especially the missing persistence for engine boots variable
 * simplifies replay attacks.
 *
 * MIB II
 * ------
 *   The standard lwIP stack management information base.
 *   This is a required MIB, so this is always enabled.
 *   The groups EGP, CMOT and transmission are disabled by default.
 *
 *   Most mib-2 objects are not writable except:
 *   sysName, sysLocation, sysContact, snmpEnableAuthenTraps.
 *   Writing to or changing the ARP and IP address and route
 *   tables is not possible.
 *
 *   Note lwIP has a very limited notion of IP routing. It currently
 *   doesn't have a route table and doesn't have a notion of the U,G,H flags.
 *   Instead lwIP uses the interface list with only one default interface
 *   acting as a single gateway interface (G) for the default route.
 *
 *   The agent returns a "virtual table" with the default route 0.0.0.0
 *   for the default interface and network routes (no H) for each
 *   network interface in the netif_list.
 *   All routes are considered to be up (U).
 *
 * Loading additional MIBs
 * -----------------------
 *   MIBs can only be added in compile-time, not in run-time.
 *
 *
 * 1 Building the Agent
 * ====================
 * First of all you'll need to add the following define
 * to your local lwipopts.h:
 * \#define LWIP_SNMP               1
 *
 * and add the source files your makefile.
 *
 * Note you'll might need to adapt you network driver to update
 * the mib2 variables for your interface.
 *
 * 2 Running the Agent
 * ===================
 * The following function calls must be made in your program to
 * actually get the SNMP agent running.
 *
 * Before starting the agent you should supply pointers
 * for sysContact, sysLocation, and snmpEnableAuthenTraps.
 * You can do this by calling
 *
 * - snmp_mib2_set_syscontact()
 * - snmp_mib2_set_syslocation()
 * - snmp_set_auth_traps_enabled()
 *
 * You can register a callback which is called on successful write access:
 * snmp_set_write_callback().
 *
 * Additionally you may want to set
 *
 * - snmp_mib2_set_sysdescr()
 * - snmp_set_device_enterprise_oid()
 * - snmp_mib2_set_sysname()
 *
 * Also before starting the agent you need to setup
 * one or more trap destinations using these calls:
 *
 * - snmp_trap_dst_enable()
 * - snmp_trap_dst_ip_set()
 *
 * If you need more than MIB2, set the MIBs you want to use
 * by snmp_set_mibs().
 *
 * Finally, enable the agent by calling snmp_init()
 *
 * @defgroup snmp_core Core
 * @ingroup snmp
 *
 * @defgroup snmp_traps Traps
 * @ingroup snmp
 */

#include <stdio.h>

#include <snmp/snmp_opts.h>
#include "snmp_priv.h"
#include "snmp_lock.h"

LOG_MODULE_DECLARE(net_snmp_agent, CONFIG_SNMP_AGENT_LOG_LEVEL);

#if LWIP_SNMP /* don't build if not configured for use in lwipopts.h */

#include <snmp/snmp.h>
#include <snmp/snmp_core.h>
#include <snmp/snmp_scalar.h>
#include "snmp_core_priv.h"
#include <string.h>

#if (LWIP_SNMP && (SNMP_TRAP_DESTINATIONS <= 0))
#error "CONFIG_SNMP_AGENT_TRAP_DESTINATIONS must be at least 1"
#endif
#if SNMP_MAX_OBJ_ID_LEN > 255
#error "SNMP_MAX_OBJ_ID_LEN must fit into an uint8_t"
#endif

struct snmp_statistics snmp_stats;
static const struct snmp_obj_id snmp_device_enterprise_oid_default = {
	SNMP_DEVICE_ENTERPRISE_OID_LEN, SNMP_DEVICE_ENTERPRISE_OID};
static const struct snmp_obj_id *snmp_device_enterprise_oid = &snmp_device_enterprise_oid_default;

const uint32_t snmp_zero_dot_zero_values[] = {0, 0};
const struct snmp_obj_id_const_ref snmp_zero_dot_zero = {LWIP_ARRAYSIZE(snmp_zero_dot_zero_values),
							 snmp_zero_dot_zero_values};

#if SNMP_LWIP_MIB2
#include <snmp/snmp_mib2.h>
static const struct snmp_mib *const default_mibs[] = {&mib2};
static uint8_t snmp_num_mibs = LWIP_ARRAYSIZE(default_mibs);
#else
static const struct snmp_mib *const default_mibs[] = {NULL};
static uint8_t snmp_num_mibs;
#endif

/* List of known mibs */
static struct snmp_mib const *const *snmp_mibs = default_mibs;

/**
 * @ingroup snmp_core
 * Sets the MIBs to use.
 * Example: call snmp_set_mibs() as follows:
 * static const struct snmp_mib *my_snmp_mibs[] = {
 *   &mib2,
 *   &private_mib
 * };
 * snmp_set_mibs(my_snmp_mibs, LWIP_ARRAYSIZE(my_snmp_mibs));
 */
void snmp_set_mibs(const struct snmp_mib **mibs, uint8_t num_mibs)
{
	LWIP_ASSERT("mibs pointer must be != NULL", (mibs != NULL));
	LWIP_ASSERT("num_mibs pointer must be != 0", (num_mibs != 0));
	snmp_agent_lock();
	snmp_mibs = mibs;
	snmp_num_mibs = num_mibs;
	snmp_agent_unlock();
}

/**
 * @ingroup snmp_core
 * 'device enterprise oid' is used for 'device OID' field in trap PDU's (for identification of
 * generating device) as well as for value returned by MIB-2 'sysObjectID' field (if internal MIB2
 * implementation is used). The 'device enterprise oid' shall point to an OID located under
 * 'private-enterprises' branch (1.3.6.1.4.1.XXX). If a vendor wants to provide a custom object
 * there, he has to get its own enterprise oid from IANA (http://www.iana.org). It is not allowed to
 * use LWIP enterprise ID! In order to identify a specific device it is recommended to create a
 * dedicated OID for each device type under its own enterprise oid. e.g. device a
 * > 1.3.6.1.4.1.XXX(ent-oid).1(devices).1(device a) device b
 * > 1.3.6.1.4.1.XXX(ent-oid).1(devices).2(device b) for more details see description of
 * 'sysObjectID' field in RFC1213-MIB
 */
void snmp_set_device_enterprise_oid(const struct snmp_obj_id *device_enterprise_oid)
{
	snmp_agent_lock();
	if (device_enterprise_oid == NULL) {
		snmp_device_enterprise_oid = &snmp_device_enterprise_oid_default;
	} else {
		snmp_device_enterprise_oid = device_enterprise_oid;
	}
	snmp_agent_unlock();
}

/**
 * @ingroup snmp_core
 * Get 'device enterprise oid'
 */
const struct snmp_obj_id *snmp_get_device_enterprise_oid(void)
{
	const struct snmp_obj_id *oid;

	snmp_agent_lock();
	oid = snmp_device_enterprise_oid;
	snmp_agent_unlock();

	return oid;
}

/**
 * Conversion from InetAddressIPv4 oid to an IPv4 address
 * @param oid points to uint32_t ident[4] input
 * @param ip points to output struct
 */
uint8_t snmp_oid_to_ip4(const uint32_t *oid, struct net_in_addr *ip)
{
	if ((oid[0] > 0xFF) || (oid[1] > 0xFF) || (oid[2] > 0xFF) || (oid[3] > 0xFF)) {
		ip->s_addr = 0;
		return 0;
	}

	/* InetAddressIPv4 is most significant octet first, which is also how the
	   address is held on the wire. */
	ip->s_addr = net_htonl(((uint32_t)oid[0] << 24) | ((uint32_t)oid[1] << 16) |
			       ((uint32_t)oid[2] << 8) | (uint32_t)oid[3]);
	return 1;
}

/**
 * Convert an IPv4 address to InetAddressIPv4 (no InetAddressType)
 * @param ip points to input struct
 * @param oid points to uint32_t ident[4] output
 */
void snmp_ip4_to_oid(const struct net_in_addr *ip, uint32_t *oid)
{
	uint32_t addr = net_ntohl(ip->s_addr);

	oid[0] = (addr >> 24) & 0xFF;
	oid[1] = (addr >> 16) & 0xFF;
	oid[2] = (addr >> 8) & 0xFF;
	oid[3] = addr & 0xFF;
}

/**
 * Convert to InetAddressType+InetAddress+InetPortNumber
 * @param ip IP address
 * @param port Port
 * @param oid OID
 * @return OID length
 */
uint8_t snmp_ip_port_to_oid(const struct net_in_addr *ip, uint16_t port, uint32_t *oid)
{
	uint8_t idx;

	idx = snmp_ip_to_oid(ip, oid);
	oid[idx] = port;
	idx++;

	return idx;
}

/**
 * Convert to InetAddressType+InetAddress
 * @param ip IP address
 * @param oid OID
 * @return OID length
 */
uint8_t snmp_ip_to_oid(const struct net_in_addr *ip, uint32_t *oid)
{
	if (ip->s_addr == 0) {
		oid[0] = 0; /* any */
		oid[1] = 0; /* no IP OIDs follow */
		return 2;
	}

	oid[0] = 1; /* ipv4 */
	oid[1] = 4; /* 4 InetAddressIPv4 OIDs follow */
	snmp_ip4_to_oid(ip, &oid[2]);

	return 6;
}

/**
 * Convert from InetAddressType+InetAddress to an IPv4 address
 * @param oid OID
 * @param oid_len OID length
 * @param ip IP address
 * @return Parsed OID length
 */
uint8_t snmp_oid_to_ip(const uint32_t *oid, uint8_t oid_len, struct net_in_addr *ip)
{
	/* InetAddressType */
	if (oid_len < 1) {
		return 0;
	}

	if (oid[0] == 0) { /* any */
		/* 1x InetAddressType, 1x OID len */
		if ((oid_len < 2) || (oid[1] != 0)) {
			return 0;
		}

		ip->s_addr = 0;

		return 2;
	} else if (oid[0] == 1) { /* ipv4 */
		/* 1x InetAddressType, 1x OID len, 4x InetAddressIPv4 */
		if ((oid_len < 6) || (oid[1] != 4)) {
			return 0;
		}

		if (!snmp_oid_to_ip4(&oid[2], ip)) {
			return 0;
		}

		return 6;
	}

	/* unsupported InetAddressType; this port is IPv4 only */
	return 0;
}

/**
 * Convert from InetAddressType+InetAddress+InetPortNumber to an address and port
 * @param oid OID
 * @param oid_len OID length
 * @param ip IP address
 * @param port Port
 * @return Parsed OID length
 */
uint8_t snmp_oid_to_ip_port(const uint32_t *oid, uint8_t oid_len, struct net_in_addr *ip,
			    uint16_t *port)
{
	uint8_t idx;

	/* InetAddressType + InetAddress */
	idx = snmp_oid_to_ip(&oid[0], oid_len, ip);
	if (idx == 0) {
		return 0;
	}

	/* InetPortNumber */
	if (oid_len < (idx + 1)) {
		return 0;
	}
	if (oid[idx] > 0xffff) {
		return 0;
	}
	*port = (uint16_t)oid[idx];
	idx++;

	return idx;
}

/**
 * Assign an OID to struct snmp_obj_id
 * @param target Assignment target
 * @param oid OID
 * @param oid_len OID length
 */
void snmp_oid_assign(struct snmp_obj_id *target, const uint32_t *oid, uint8_t oid_len)
{
	LWIP_ASSERT("oid_len <= SNMP_MAX_OBJ_ID_LEN", oid_len <= SNMP_MAX_OBJ_ID_LEN);

	target->len = oid_len;

	if (oid_len > 0) {
		MEMCPY(target->id, oid, oid_len * sizeof(uint32_t));
	}
}

/**
 * Prefix an OID to OID in struct snmp_obj_id
 * @param target Assignment target to prefix
 * @param oid OID
 * @param oid_len OID length
 */
void snmp_oid_prefix(struct snmp_obj_id *target, const uint32_t *oid, uint8_t oid_len)
{
	LWIP_ASSERT("target->len + oid_len <= SNMP_MAX_OBJ_ID_LEN",
		    (target->len + oid_len) <= SNMP_MAX_OBJ_ID_LEN);

	if (oid_len > 0) {
		/* move existing OID to make room at the beginning for OID to insert */
		int i;
		for (i = target->len - 1; i >= 0; i--) {
			target->id[i + oid_len] = target->id[i];
		}

		/* paste oid at the beginning */
		MEMCPY(target->id, oid, oid_len * sizeof(uint32_t));
	}
}

/**
 * Combine two OIDs into struct snmp_obj_id
 * @param target Assignment target
 * @param oid1 OID 1
 * @param oid1_len OID 1 length
 * @param oid2 OID 2
 * @param oid2_len OID 2 length
 */
void snmp_oid_combine(struct snmp_obj_id *target, const uint32_t *oid1, uint8_t oid1_len,
		      const uint32_t *oid2, uint8_t oid2_len)
{
	snmp_oid_assign(target, oid1, oid1_len);
	snmp_oid_append(target, oid2, oid2_len);
}

/**
 * Append OIDs to struct snmp_obj_id
 * @param target Assignment target to append to
 * @param oid OID
 * @param oid_len OID length
 */
void snmp_oid_append(struct snmp_obj_id *target, const uint32_t *oid, uint8_t oid_len)
{
	LWIP_ASSERT("offset + oid_len <= SNMP_MAX_OBJ_ID_LEN",
		    (target->len + oid_len) <= SNMP_MAX_OBJ_ID_LEN);

	if (oid_len > 0) {
		MEMCPY(&target->id[target->len], oid, oid_len * sizeof(uint32_t));
		target->len = (uint8_t)(target->len + oid_len);
	}
}

/**
 * Compare two OIDs
 * @param oid1 OID 1
 * @param oid1_len OID 1 length
 * @param oid2 OID 2
 * @param oid2_len OID 2 length
 * @return -1: OID1&lt;OID2  1: OID1 &gt;OID2 0: equal
 */
int8_t snmp_oid_compare(const uint32_t *oid1, uint8_t oid1_len, const uint32_t *oid2,
			uint8_t oid2_len)
{
	uint8_t level = 0;
	LWIP_ASSERT("'oid1' param must not be NULL or 'oid1_len' param be 0!",
		    (oid1 != NULL) || (oid1_len == 0));
	LWIP_ASSERT("'oid2' param must not be NULL or 'oid2_len' param be 0!",
		    (oid2 != NULL) || (oid2_len == 0));

	while ((level < oid1_len) && (level < oid2_len)) {
		if (*oid1 < *oid2) {
			return -1;
		}
		if (*oid1 > *oid2) {
			return 1;
		}

		level++;
		oid1++;
		oid2++;
	}

	/* common part of both OID's is equal, compare length */
	if (oid1_len < oid2_len) {
		return -1;
	}
	if (oid1_len > oid2_len) {
		return 1;
	}

	/* they are equal */
	return 0;
}

/**
 * Check of two OIDs are equal
 * @param oid1 OID 1
 * @param oid1_len OID 1 length
 * @param oid2 OID 2
 * @param oid2_len OID 2 length
 * @return 1: equal 0: non-equal
 */
uint8_t snmp_oid_equal(const uint32_t *oid1, uint8_t oid1_len, const uint32_t *oid2,
		       uint8_t oid2_len)
{
	return (snmp_oid_compare(oid1, oid1_len, oid2, oid2_len) == 0) ? 1 : 0;
}

static const struct snmp_mib *snmp_get_mib_from_oid(const uint32_t *oid, uint8_t oid_len)
{
	const uint32_t *list_oid;
	const uint32_t *searched_oid;
	uint8_t i, l;

	uint8_t max_match_len = 0;
	const struct snmp_mib *matched_mib = NULL;

	LWIP_ASSERT("'oid' param must not be NULL!", (oid != NULL));

	if (oid_len == 0) {
		return NULL;
	}

	for (i = 0; i < snmp_num_mibs; i++) {
		LWIP_ASSERT("MIB array not initialized correctly", (snmp_mibs[i] != NULL));
		LWIP_ASSERT("MIB array not initialized correctly - base OID is NULL",
			    (snmp_mibs[i]->base_oid != NULL));

		if (oid_len >= snmp_mibs[i]->base_oid_len) {
			l = snmp_mibs[i]->base_oid_len;
			list_oid = snmp_mibs[i]->base_oid;
			searched_oid = oid;

			while (l > 0) {
				if (*list_oid != *searched_oid) {
					break;
				}

				l--;
				list_oid++;
				searched_oid++;
			}

			if ((l == 0) && (snmp_mibs[i]->base_oid_len > max_match_len)) {
				max_match_len = snmp_mibs[i]->base_oid_len;
				matched_mib = snmp_mibs[i];
			}
		}
	}

	return matched_mib;
}

static const struct snmp_mib *snmp_get_next_mib(const uint32_t *oid, uint8_t oid_len)
{
	uint8_t i;
	const struct snmp_mib *next_mib = NULL;

	LWIP_ASSERT("'oid' param must not be NULL!", (oid != NULL));

	if (oid_len == 0) {
		return NULL;
	}

	for (i = 0; i < snmp_num_mibs; i++) {
		if (snmp_mibs[i]->base_oid != NULL) {
			/* check if mib is located behind starting point */
			if (snmp_oid_compare(snmp_mibs[i]->base_oid, snmp_mibs[i]->base_oid_len,
					     oid, oid_len) > 0) {
				if ((next_mib == NULL) ||
				    (snmp_oid_compare(
					     snmp_mibs[i]->base_oid, snmp_mibs[i]->base_oid_len,
					     next_mib->base_oid, next_mib->base_oid_len) < 0)) {
					next_mib = snmp_mibs[i];
				}
			}
		}
	}

	return next_mib;
}

static const struct snmp_mib *snmp_get_mib_between(const uint32_t *oid1, uint8_t oid1_len,
						   const uint32_t *oid2, uint8_t oid2_len)
{
	const struct snmp_mib *next_mib = snmp_get_next_mib(oid1, oid1_len);

	LWIP_ASSERT("'oid2' param must not be NULL!", (oid2 != NULL));
	LWIP_ASSERT("'oid2_len' param must be greater than 0!", (oid2_len > 0));

	if (next_mib != NULL) {
		if (snmp_oid_compare(next_mib->base_oid, next_mib->base_oid_len, oid2, oid2_len) <
		    0) {
			return next_mib;
		}
	}

	return NULL;
}

uint8_t snmp_get_node_instance_from_oid(const uint32_t *oid, uint8_t oid_len,
					struct snmp_node_instance *node_instance)
{
	uint8_t result = SNMP_ERR_NOSUCHOBJECT;
	const struct snmp_mib *mib;
	const struct snmp_node *mn = NULL;

	mib = snmp_get_mib_from_oid(oid, oid_len);
	if (mib != NULL) {
		uint8_t oid_instance_len;

		mn = snmp_mib_tree_resolve_exact(mib, oid, oid_len, &oid_instance_len);
		if ((mn != NULL) && (mn->node_type != SNMP_NODE_TREE)) {
			/* get instance */
			const struct snmp_leaf_node *leaf_node =
				(const struct snmp_leaf_node *)(const void *)mn;

			node_instance->node = mn;
			snmp_oid_assign(&node_instance->instance_oid,
					oid + (oid_len - oid_instance_len), oid_instance_len);

			result = leaf_node->get_instance(oid, oid_len - oid_instance_len,
							 node_instance);

#ifdef LWIP_DEBUG
			if (result == SNMP_ERR_NOERROR) {
				if (((node_instance->access & SNMP_NODE_INSTANCE_ACCESS_READ) !=
				     0) &&
				    (node_instance->get_value == NULL)) {
					LOG_DBG("SNMP inconsistent access: node is readable but no "
						"get_value function is specified\n");
				}
				if (((node_instance->access & SNMP_NODE_INSTANCE_ACCESS_WRITE) !=
				     0) &&
				    (node_instance->set_value == NULL)) {
					LOG_DBG("SNMP inconsistent access: node is writable but no "
						"set_value and/or set_test function is "
						"specified\n");
				}
			}
#endif
		}
	} else {
		/** No mib was found describing the given OID.
		 */
	}

	return result;
}

uint8_t snmp_get_next_node_instance_from_oid(
	const uint32_t *oid, uint8_t oid_len,
	snmp_validate_node_instance_method validate_node_instance_method,
	void *validate_node_instance_arg, struct snmp_obj_id *node_oid,
	struct snmp_node_instance *node_instance)
{
	const struct snmp_mib *mib;
	const struct snmp_node *mn = NULL;
	const uint32_t *start_oid = NULL;
	uint8_t start_oid_len = 0;

	/* resolve target MIB from passed OID */
	mib = snmp_get_mib_from_oid(oid, oid_len);
	if (mib == NULL) {
		/* passed OID does not reference any known MIB, start at the next closest MIB */
		mib = snmp_get_next_mib(oid, oid_len);

		if (mib != NULL) {
			start_oid = mib->base_oid;
			start_oid_len = mib->base_oid_len;
		}
	} else {
		start_oid = oid;
		start_oid_len = oid_len;
	}

	/* resolve target node from MIB, skip to next MIB if no suitable node is found in current
	 * MIB */
	while ((mib != NULL) && (mn == NULL)) {
		uint8_t oid_instance_len;

		/* check if OID directly references a node inside current MIB, in this case we have
		 * to ask this node for the next instance */
		mn = snmp_mib_tree_resolve_exact(mib, start_oid, start_oid_len, &oid_instance_len);
		if (mn != NULL) {
			snmp_oid_assign(node_oid, start_oid,
					start_oid_len - oid_instance_len); /* set oid to node */
			snmp_oid_assign(&node_instance->instance_oid,
					start_oid + (start_oid_len - oid_instance_len),
					oid_instance_len); /* set (relative) instance oid */
		} else {
			/* OID does not reference a node, search for the next closest node inside
			 * MIB; set instance_oid.len to zero because we want the first instance of
			 * this node */
			mn = snmp_mib_tree_resolve_next(mib, start_oid, start_oid_len, node_oid);
			node_instance->instance_oid.len = 0;
		}

		/* validate the node; if the node has no further instance or the returned instance
		 * is invalid, search for the next in MIB and validate again */
		node_instance->node = mn;
		while (mn != NULL) {
			uint8_t result;

			/* clear fields which may have values from previous loops */
			node_instance->asn1_type = 0;
			node_instance->access = SNMP_NODE_INSTANCE_NOT_ACCESSIBLE;
			node_instance->get_value = NULL;
			node_instance->set_test = NULL;
			node_instance->set_value = NULL;
			node_instance->release_instance = NULL;
			node_instance->reference.ptr = NULL;
			node_instance->reference_len = 0;

			result = ((const struct snmp_leaf_node *)(const void *)mn)
					 ->get_next_instance(node_oid->id, node_oid->len,
							     node_instance);

			if (result == SNMP_ERR_NOERROR) {
#ifdef LWIP_DEBUG
				if (((node_instance->access & SNMP_NODE_INSTANCE_ACCESS_READ) !=
				     0) &&
				    (node_instance->get_value == NULL)) {
					LOG_DBG("SNMP inconsistent access: node is readable but no "
						"get_value function is specified\n");
				}
				if (((node_instance->access & SNMP_NODE_INSTANCE_ACCESS_WRITE) !=
				     0) &&
				    (node_instance->set_value == NULL)) {
					LOG_DBG("SNMP inconsistent access: node is writable but no "
						"set_value function is specified\n");
				}
#endif

				/* validate node because the node may be not accessible for example
				 * (but let the caller decide what is valid */
				if ((validate_node_instance_method == NULL) ||
				    (validate_node_instance_method(node_instance,
								   validate_node_instance_arg) ==
				     SNMP_ERR_NOERROR)) {
					/* node_oid "returns" the full result OID (including the
					 * instance part) */
					snmp_oid_append(node_oid, node_instance->instance_oid.id,
							node_instance->instance_oid.len);
					break;
				}

				if (node_instance->release_instance != NULL) {
					node_instance->release_instance(node_instance);
				}
				/*
				the instance itself is not valid, ask for next instance from same
				node. we don't have to change any variables because
				node_instance->instance_oid is used as input (starting point) as
				well as output (resulting next OID), so we have to simply call
				get_next_instance method again
				*/
			} else {
				if (node_instance->release_instance != NULL) {
					node_instance->release_instance(node_instance);
				}

				/* the node has no further instance, skip to next node */
				mn = snmp_mib_tree_resolve_next(
					mib, node_oid->id, node_oid->len,
					&node_instance->instance_oid); /* misuse
									  node_instance->instance_oid
									  as tmp buffer */
				if (mn != NULL) {
					/* prepare for next loop */
					snmp_oid_assign(node_oid, node_instance->instance_oid.id,
							node_instance->instance_oid.len);
					node_instance->instance_oid.len = 0;
					node_instance->node = mn;
				}
			}
		}

		if (mn != NULL) {
			/*
			we found a suitable next node,
			now we have to check if a inner MIB is located between the searched OID and
			the resulting OID. this is possible because MIB's may be located anywhere in
			the global tree, that means also in the subtree of another MIB (e.g. if
			searched OID is .2 and resulting OID is .4, then another MIB having .3 as
			root node may exist)
			*/
			const struct snmp_mib *intermediate_mib;
			intermediate_mib = snmp_get_mib_between(start_oid, start_oid_len,
								node_oid->id, node_oid->len);

			if (intermediate_mib != NULL) {
				/* search for first node inside intermediate mib in next loop */
				if (node_instance->release_instance != NULL) {
					node_instance->release_instance(node_instance);
				}

				mn = NULL;
				mib = intermediate_mib;
				start_oid = mib->base_oid;
				start_oid_len = mib->base_oid_len;
			}
			/* else { we found out target node } */
		} else {
			/*
			there is no further (suitable) node inside this MIB, search for the next MIB
			with following priority
			1. search for inner MIB's (whose root is located inside tree of current MIB)
			2. search for surrounding MIB's (where the current MIB is the inner MIB) and
			continue there if any
			3. take the next closest MIB (not being related to the current MIB)
			*/
			const struct snmp_mib *next_mib;
			next_mib = snmp_get_next_mib(
				start_oid,
				start_oid_len); /* returns MIB's related to point 1 and 3 */

			/* is the found MIB an inner MIB? (point 1) */
			if ((next_mib != NULL) && (next_mib->base_oid_len > mib->base_oid_len) &&
			    (snmp_oid_compare(next_mib->base_oid, mib->base_oid_len, mib->base_oid,
					      mib->base_oid_len) == 0)) {
				/* yes it is -> continue at inner MIB */
				mib = next_mib;
				start_oid = mib->base_oid;
				start_oid_len = mib->base_oid_len;
			} else {
				/* check if there is a surrounding mib where to continue (point 2)
				 * (only possible if OID length > 1) */
				if (mib->base_oid_len > 1) {
					mib = snmp_get_mib_from_oid(mib->base_oid,
								    mib->base_oid_len - 1);

					if (mib == NULL) {
						/* no surrounding mib, use next mib encountered
						 * above (point 3) */
						mib = next_mib;

						if (mib != NULL) {
							start_oid = mib->base_oid;
							start_oid_len = mib->base_oid_len;
						}
					}
					/* else { start_oid stays the same because we want to
					 * continue from current offset in surrounding mib (point 2)
					 * } */
				}
			}
		}
	}

	if (mib == NULL) {
		/* loop is only left when mib == null (error) or mib_node != NULL (success) */
		return SNMP_ERR_ENDOFMIBVIEW;
	}

	return SNMP_ERR_NOERROR;
}

/**
 * Searches tree for the supplied object identifier.
 *
 */
const struct snmp_node *snmp_mib_tree_resolve_exact(const struct snmp_mib *mib, const uint32_t *oid,
						    uint8_t oid_len, uint8_t *oid_instance_len)
{
	const struct snmp_node *const *node = &mib->root_node;
	uint8_t oid_offset = mib->base_oid_len;

	while ((oid_offset < oid_len) && ((*node)->node_type == SNMP_NODE_TREE)) {
		/* search for matching sub node */
		uint32_t subnode_oid = *(oid + oid_offset);

		uint32_t i = (*(const struct snmp_tree_node *const *)node)->subnode_count;
		node = (*(const struct snmp_tree_node *const *)node)->subnodes;
		while ((i > 0) && ((*node)->oid != subnode_oid)) {
			node++;
			i--;
		}

		if (i == 0) {
			/* no matching subnode found */
			return NULL;
		}

		oid_offset++;
	}

	if ((*node)->node_type != SNMP_NODE_TREE) {
		/* we found a leaf node */
		*oid_instance_len = oid_len - oid_offset;
		return *node;
	}

	return NULL;
}

const struct snmp_node *snmp_mib_tree_resolve_next(const struct snmp_mib *mib, const uint32_t *oid,
						   uint8_t oid_len, struct snmp_obj_id *oidret)
{
	uint8_t oid_offset = mib->base_oid_len;
	const struct snmp_node *const *node;
	const struct snmp_tree_node *node_stack[SNMP_MAX_OBJ_ID_LEN];
	int32_t nsi = 0; /* NodeStackIndex */
	uint32_t subnode_oid;

	if (mib->root_node->node_type != SNMP_NODE_TREE) {
		/* a next operation on a mib with only a leaf node will always return NULL because
		 * there is no other node */
		return NULL;
	}

	/* first build node stack related to passed oid (as far as possible), then go backwards to
	 * determine the next node */
	node_stack[nsi] = (const struct snmp_tree_node *)(const void *)mib->root_node;
	while (oid_offset < oid_len) {
		/* search for matching sub node */
		uint32_t i = node_stack[nsi]->subnode_count;
		node = node_stack[nsi]->subnodes;

		subnode_oid = *(oid + oid_offset);

		while ((i > 0) && ((*node)->oid != subnode_oid)) {
			node++;
			i--;
		}

		if ((i == 0) || ((*node)->node_type != SNMP_NODE_TREE)) {
			/* no (matching) tree-subnode found */
			break;
		}
		nsi++;
		node_stack[nsi] = (const struct snmp_tree_node *)(const void *)(*node);

		oid_offset++;
	}

	if (oid_offset >= oid_len) {
		/* passed oid references a tree node -> return first usable sub node of it */
		subnode_oid = 0;
	} else {
		subnode_oid = *(oid + oid_offset) + 1;
	}

	while (nsi >= 0) {
		const struct snmp_node *subnode = NULL;

		/* find next node on current level */
		int32_t i = node_stack[nsi]->subnode_count;
		node = node_stack[nsi]->subnodes;
		while (i > 0) {
			if ((*node)->oid == subnode_oid) {
				subnode = *node;
				break;
			} else if (((*node)->oid > subnode_oid) &&
				   ((subnode == NULL) || ((*node)->oid < subnode->oid))) {
				subnode = *node;
			}

			node++;
			i--;
		}

		if (subnode == NULL) {
			/* no further node found on this level, go one level up and start searching
			 * with index of current node*/
			subnode_oid = node_stack[nsi]->node.oid + 1;
			nsi--;
		} else {
			if (subnode->node_type == SNMP_NODE_TREE) {
				/* next is a tree node, go into it and start searching */
				nsi++;
				node_stack[nsi] =
					(const struct snmp_tree_node *)(const void *)subnode;
				subnode_oid = 0;
			} else {
				/* we found a leaf node -> fill oidret and return it */
				snmp_oid_assign(oidret, mib->base_oid, mib->base_oid_len);
				i = 1;
				while (i <= nsi) {
					oidret->id[oidret->len] = node_stack[i]->node.oid;
					oidret->len++;
					i++;
				}

				oidret->id[oidret->len] = subnode->oid;
				oidret->len++;

				return subnode;
			}
		}
	}

	return NULL;
}

/** initialize struct next_oid_state using this function before passing it to next_oid_check */
void snmp_next_oid_init(struct snmp_next_oid_state *state, const uint32_t *start_oid,
			uint8_t start_oid_len, uint32_t *next_oid_buf, uint8_t next_oid_max_len)
{
	state->start_oid = start_oid;
	state->start_oid_len = start_oid_len;
	state->next_oid = next_oid_buf;
	state->next_oid_len = 0;
	state->next_oid_max_len = next_oid_max_len;
	state->status = SNMP_NEXT_OID_STATUS_NO_MATCH;
}

/** checks if the passed incomplete OID may be a possible candidate for snmp_next_oid_check();
this method is intended if the complete OID is not yet known but it is very expensive to build it
up, so it is possible to test the starting part before building up the complete oid and pass it to
snmp_next_oid_check()*/
uint8_t snmp_next_oid_precheck(struct snmp_next_oid_state *state, const uint32_t *oid,
			       uint8_t oid_len)
{
	if (state->status != SNMP_NEXT_OID_STATUS_BUF_TO_SMALL) {
		uint8_t start_oid_len =
			(oid_len < state->start_oid_len) ? oid_len : state->start_oid_len;

		/* check passed OID is located behind start offset */
		if (snmp_oid_compare(oid, oid_len, state->start_oid, start_oid_len) >= 0) {
			/* check if new oid is located closer to start oid than current closest oid
			 */
			if ((state->status == SNMP_NEXT_OID_STATUS_NO_MATCH) ||
			    (snmp_oid_compare(oid, oid_len, state->next_oid, state->next_oid_len) <
			     0)) {
				return 1;
			}
		}
	}

	return 0;
}

/** checks the passed OID if it is a candidate to be the next one (get_next); returns !=0 if passed
 * oid is currently closest, otherwise 0 */
uint8_t snmp_next_oid_check(struct snmp_next_oid_state *state, const uint32_t *oid, uint8_t oid_len,
			    void *reference)
{
	/* do not overwrite a fail result */
	if (state->status != SNMP_NEXT_OID_STATUS_BUF_TO_SMALL) {
		/* check passed OID is located behind start offset */
		if (snmp_oid_compare(oid, oid_len, state->start_oid, state->start_oid_len) > 0) {
			/* check if new oid is located closer to start oid than current closest oid
			 */
			if ((state->status == SNMP_NEXT_OID_STATUS_NO_MATCH) ||
			    (snmp_oid_compare(oid, oid_len, state->next_oid, state->next_oid_len) <
			     0)) {
				if (oid_len <= state->next_oid_max_len) {
					MEMCPY(state->next_oid, oid, oid_len * sizeof(uint32_t));
					state->next_oid_len = oid_len;
					state->status = SNMP_NEXT_OID_STATUS_SUCCESS;
					state->reference = reference;
					return 1;
				} else {
					state->status = SNMP_NEXT_OID_STATUS_BUF_TO_SMALL;
				}
			}
		}
	}

	return 0;
}

uint8_t snmp_oid_in_range(const uint32_t *oid_in, uint8_t oid_len,
			  const struct snmp_oid_range *oid_ranges, uint8_t oid_ranges_len)
{
	uint8_t i;

	if (oid_len != oid_ranges_len) {
		return 0;
	}

	for (i = 0; i < oid_ranges_len; i++) {
		if ((oid_in[i] < oid_ranges[i].min) || (oid_in[i] > oid_ranges[i].max)) {
			return 0;
		}
	}

	return 1;
}

snmp_err_t snmp_set_test_ok(struct snmp_node_instance *instance, uint16_t value_len, void *value)
{
	LWIP_UNUSED_ARG(instance);
	LWIP_UNUSED_ARG(value_len);
	LWIP_UNUSED_ARG(value);

	return SNMP_ERR_NOERROR;
}

/**
 * Decodes BITS pseudotype value from ASN.1 OctetString.
 *
 * @note Because BITS pseudo type is encoded as OCTET STRING, it cannot directly
 * be encoded/decoded by the agent. Instead call this function as required from
 * get/test/set methods.
 *
 * @param buf points to a buffer holding the ASN1 octet string
 * @param buf_len length of octet string
 * @param bit_value decoded Bit value with Bit0 == LSB
 * @return ERR_OK if successful, ERR_ARG if bit value contains more than 32 bit
 */
int snmp_decode_bits(const uint8_t *buf, uint32_t buf_len, uint32_t *bit_value)
{
	uint8_t b;
	uint8_t bits_processed = 0;
	*bit_value = 0;

	while (buf_len > 0) {
		/* any bit set in this byte? */
		if (*buf != 0x00) {
			if (bits_processed >= 32) {
				/* accept more than 4 bytes, but only when no bits are set */
				return ERR_VAL;
			}

			b = *buf;
			do {
				if (b & 0x80) {
					*bit_value |= (1 << bits_processed);
				}
				bits_processed++;
				b <<= 1;
			} while ((bits_processed & 0x07) != 0); /* &0x07 -> % 8 */
		} else {
			bits_processed += 8;
		}

		buf_len--;
		buf++;
	}

	return ERR_OK;
}

int snmp_decode_truthvalue(const int32_t *asn1_value, uint8_t *bool_value)
{
	/* defined by RFC1443:
	 TruthValue ::= TEXTUAL-CONVENTION
	  STATUS       current
	  DESCRIPTION
	   "Represents a boolean value."
	  SYNTAX       INTEGER { true(1), false(2) }
	*/

	if ((asn1_value == NULL) || (bool_value == NULL)) {
		return ERR_ARG;
	}

	if (*asn1_value == 1) {
		*bool_value = 1;
	} else if (*asn1_value == 2) {
		*bool_value = 0;
	} else {
		return ERR_VAL;
	}

	return ERR_OK;
}

/**
 * Encodes BITS pseudotype value into ASN.1 OctetString.
 *
 * @note Because BITS pseudo type is encoded as OCTET STRING, it cannot directly
 * be encoded/decoded by the agent. Instead call this function as required from
 * get/test/set methods.
 *
 * @param buf points to a buffer where the resulting ASN1 octet string is stored to
 * @param buf_len max length of the buffer
 * @param bit_value Bit value to encode with Bit0 == LSB
 * @param bit_count Number of possible bits for the bit value (according to rfc we have to send all
 * bits independent from their truth value)
 * @return number of bytes used from buffer to store the resulting OctetString
 */
uint8_t snmp_encode_bits(uint8_t *buf, uint32_t buf_len, uint32_t bit_value, uint8_t bit_count)
{
	uint8_t len = 0;
	uint8_t min_bytes = (bit_count + 7) >> 3; /* >>3 -> / 8 */

	while ((buf_len > 0) && (bit_value != 0x00)) {
		int8_t i = 7;
		*buf = 0x00;
		while (i >= 0) {
			if (bit_value & 0x01) {
				*buf |= 0x01;
			}

			if (i > 0) {
				*buf <<= 1;
			}

			bit_value >>= 1;
			i--;
		}

		buf++;
		buf_len--;
		len++;
	}

	if (len < min_bytes) {
		buf += len;
		buf_len -= len;

		while ((len < min_bytes) && (buf_len > 0)) {
			*buf = 0x00;
			buf++;
			buf_len--;
			len++;
		}
	}

	return len;
}

uint8_t snmp_encode_truthvalue(int32_t *asn1_value, uint32_t bool_value)
{
	/* defined by RFC1443:
	 TruthValue ::= TEXTUAL-CONVENTION
	  STATUS       current
	  DESCRIPTION
	   "Represents a boolean value."
	  SYNTAX       INTEGER { true(1), false(2) }
	*/

	if (asn1_value == NULL) {
		return 0;
	}

	if (bool_value) {
		*asn1_value = 1; /* defined by RFC1443 */
	} else {
		*asn1_value = 2; /* defined by RFC1443 */
	}

	return sizeof(int32_t);
}

#endif /* LWIP_SNMP */
