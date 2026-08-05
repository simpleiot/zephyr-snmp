/**
 * @file
 * Management Information Base II (RFC1213) INTERFACES objects and functions.
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
 * Author: Dirk Ziegelmeier <dziegel@gmx.de>
 *         Christiaan Simons <christiaan.simons@axon.tv>
 *
 * The data sources are Zephyr's, not lwIP's: net_if_foreach() and the
 * interface accessors replace netif_list, and net_stats replaces
 * netif->mib2_counters.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "lwip/def.h"
#include "lwip/apps/snmp.h"
#include "lwip/apps/snmp_core.h"
#include "lwip/apps/snmp_mib2.h"
#include "lwip/apps/snmp_table.h"
#include "lwip/apps/snmp_scalar.h"

#include <stdio.h>
#include <string.h>

#include <zephyr/net/net_if.h>
#include <zephyr/net/net_stats.h>

LOG_MODULE_DECLARE(net_snmp_agent, CONFIG_SNMP_AGENT_LOG_LEVEL);

#if LWIP_SNMP && SNMP_LWIP_MIB2 && defined(CONFIG_SNMP_AGENT_MIB2_INTERFACES)

/* --- interfaces .1.3.6.1.2.1.2 ----------------------------------------------------- */

/** ifOperStatus and ifAdminStatus values from RFC 1213. */
#define IFSTATUS_UP              1
#define IFSTATUS_DOWN            2
#define IFSTATUS_LOWERLAYERDOWN  7

/** ifType values from the IANAifType registry. */
#define IFTYPE_OTHER              1
#define IFTYPE_ETHERNETCSMACD     6
#define IFTYPE_SOFTWARELOOPBACK  24
#define IFTYPE_IEEE802154       259
#define IFTYPE_BLUETOOTH        272

static void interfaces_count_cb(struct net_if *iface, void *user_data)
{
	s32_t *count = user_data;

	ARG_UNUSED(iface);
	(*count)++;
}

static s16_t interfaces_get_value(struct snmp_node_instance *instance, void *value)
{
	if (instance->node->oid == 1) {
		s32_t *sint_ptr = (s32_t *)value;
		s32_t count = 0;

		net_if_foreach(interfaces_count_cb, &count);
		*sint_ptr = count;

		return sizeof(*sint_ptr);
	}

	return 0;
}

/* list of allowed value ranges for incoming OID */
static const struct snmp_oid_range interfaces_Table_oid_ranges[] = {
	{ 1, 0xff } /* interface indices are small and 1-based */
};

static snmp_err_t interfaces_Table_get_cell_instance(const u32_t *column, const u32_t *row_oid,
						     u8_t row_oid_len,
						     struct snmp_node_instance *cell_instance)
{
	struct net_if *iface;

	LWIP_UNUSED_ARG(column);

	/* check if incoming OID length and if values are in plausible range */
	if (!snmp_oid_in_range(row_oid, row_oid_len, interfaces_Table_oid_ranges,
			       LWIP_ARRAYSIZE(interfaces_Table_oid_ranges))) {
		return SNMP_ERR_NOSUCHINSTANCE;
	}

	iface = net_if_get_by_index((int)row_oid[0]);
	if (iface == NULL) {
		return SNMP_ERR_NOSUCHINSTANCE;
	}

	/* store the interface for subsequent operations (get/test/set) */
	cell_instance->reference.ptr = iface;

	return SNMP_ERR_NOERROR;
}

struct interfaces_next_ctx {
	struct snmp_next_oid_state *state;
};

static void interfaces_next_cb(struct net_if *iface, void *user_data)
{
	struct interfaces_next_ctx *ctx = user_data;
	u32_t test_oid[LWIP_ARRAYSIZE(interfaces_Table_oid_ranges)];

	test_oid[0] = (u32_t)net_if_get_by_iface(iface);

	snmp_next_oid_check(ctx->state, test_oid, LWIP_ARRAYSIZE(interfaces_Table_oid_ranges), iface);
}

static snmp_err_t interfaces_Table_get_next_cell_instance(const u32_t *column,
							  struct snmp_obj_id *row_oid,
							  struct snmp_node_instance *cell_instance)
{
	struct snmp_next_oid_state state;
	struct interfaces_next_ctx ctx = { .state = &state };
	u32_t result_temp[LWIP_ARRAYSIZE(interfaces_Table_oid_ranges)];

	LWIP_UNUSED_ARG(column);

	snmp_next_oid_init(&state, row_oid->id, row_oid->len, result_temp,
			   LWIP_ARRAYSIZE(interfaces_Table_oid_ranges));

	net_if_foreach(interfaces_next_cb, &ctx);

	if (state.status == SNMP_NEXT_OID_STATUS_SUCCESS) {
		snmp_oid_assign(row_oid, state.next_oid, state.next_oid_len);
		cell_instance->reference.ptr = state.reference;
		return SNMP_ERR_NOERROR;
	}

	return SNMP_ERR_NOSUCHINSTANCE;
}

/** Map the link layer onto the IANAifType the manager expects. */
static s32_t interfaces_iftype(struct net_if *iface)
{
	struct net_linkaddr *linkaddr = net_if_get_link_addr(iface);

	if (linkaddr == NULL) {
		return IFTYPE_OTHER;
	}

	switch (linkaddr->type) {
	case NET_LINK_ETHERNET:
		return IFTYPE_ETHERNETCSMACD;
	case NET_LINK_DUMMY:
		return IFTYPE_SOFTWARELOOPBACK;
	case NET_LINK_IEEE802154:
		return IFTYPE_IEEE802154;
	case NET_LINK_BLUETOOTH:
		return IFTYPE_BLUETOOTH;
	default:
		return IFTYPE_OTHER;
	}
}

/**
 * @brief Read one per-interface counter.
 *
 * Zephyr keeps these only when CONFIG_NET_STATISTICS_PER_INTERFACE is on;
 * without it every counter reads zero, which is what an agent should report
 * for a counter it does not maintain.
 */
static u32_t interfaces_counter(struct net_if *iface, u8_t column)
{
#if defined(CONFIG_NET_STATISTICS_PER_INTERFACE)
	const struct net_stats *stats = &iface->stats;

	switch (column) {
	case 10: /* ifInOctets */
		return (u32_t)stats->bytes.received;
	case 11: /* ifInUcastPkts */
		return IS_ENABLED(CONFIG_NET_STATISTICS_IPV4) ? stats->ipv4.recv : 0;
	case 13: /* ifInDiscards */
		return IS_ENABLED(CONFIG_NET_STATISTICS_IPV4) ? stats->ipv4.drop : 0;
	case 14: /* ifInErrors */
		return stats->processing_error;
	case 15: /* ifInUnknownProtos */
		return stats->ip_errors.protoerr;
	case 16: /* ifOutOctets */
		return (u32_t)stats->bytes.sent;
	case 17: /* ifOutUcastPkts */
		return IS_ENABLED(CONFIG_NET_STATISTICS_IPV4) ? stats->ipv4.sent : 0;
	default:
		return 0;
	}
#else
	ARG_UNUSED(iface);
	ARG_UNUSED(column);

	return 0;
#endif /* CONFIG_NET_STATISTICS_PER_INTERFACE */
}

static s16_t interfaces_Table_get_value(struct snmp_node_instance *instance, void *value)
{
	struct net_if *iface = (struct net_if *)instance->reference.ptr;
	u32_t *value_u32 = (u32_t *)value;
	s32_t *value_s32 = (s32_t *)value;
	u8_t column = SNMP_TABLE_GET_COLUMN_FROM_OID(instance->instance_oid.id);
	u16_t value_len;

	switch (column) {
	case 1: /* ifIndex */
		*value_s32 = net_if_get_by_iface(iface);
		value_len = sizeof(*value_s32);
		break;
	case 2: { /* ifDescr */
		char name[CONFIG_NET_INTERFACE_NAME_LEN + 1];
		int ret = net_if_get_name(iface, name, sizeof(name));

		if (ret < 0) {
			/* No name configured; report the index instead of an
			 * empty string, which managers display poorly. */
			value_len = (u16_t)snprintf(name, sizeof(name), "if%d",
						    net_if_get_by_iface(iface));
		} else {
			value_len = (u16_t)strlen(name);
		}
		MEMCPY(value, name, value_len);
		break;
	}
	case 3: /* ifType */
		*value_s32 = interfaces_iftype(iface);
		value_len = sizeof(*value_s32);
		break;
	case 4: /* ifMtu */
		*value_s32 = net_if_get_mtu(iface);
		value_len = sizeof(*value_s32);
		break;
	case 5: /* ifSpeed */
		/* Zephyr exposes no portable link speed; 0 means unknown. */
		*value_u32 = 0;
		value_len = sizeof(*value_u32);
		break;
	case 6: { /* ifPhysAddress */
		struct net_linkaddr *linkaddr = net_if_get_link_addr(iface);

		value_len = (linkaddr != NULL) ? linkaddr->len : 0;
		if (value_len > 0) {
			MEMCPY(value, linkaddr->addr, value_len);
		}
		break;
	}
	case 7: /* ifAdminStatus */
		*value_s32 = net_if_is_admin_up(iface) ? IFSTATUS_UP : IFSTATUS_DOWN;
		value_len = sizeof(*value_s32);
		break;
	case 8: /* ifOperStatus */
		if (!net_if_is_admin_up(iface)) {
			*value_s32 = IFSTATUS_DOWN;
		} else if (net_if_is_carrier_ok(iface)) {
			*value_s32 = IFSTATUS_UP;
		} else {
			*value_s32 = IFSTATUS_LOWERLAYERDOWN;
		}
		value_len = sizeof(*value_s32);
		break;
	case 9: /* ifLastChange */
		/* Zephyr does not record when the interface last changed
		 * state, so report 0, meaning "before the agent started". */
		*value_u32 = 0;
		value_len = sizeof(*value_u32);
		break;
	case 21: /* ifOutQLen */
		*value_u32 = 0;
		value_len = sizeof(*value_u32);
		break;
	/** @note returning zeroDotZero (0.0) no media specific MIB support */
	case 22: /* ifSpecific */
		value_len = snmp_zero_dot_zero.len * sizeof(u32_t);
		MEMCPY(value, snmp_zero_dot_zero.id, value_len);
		break;
	case 10: /* ifInOctets */
	case 11: /* ifInUcastPkts */
	case 12: /* ifInNUcastPkts */
	case 13: /* ifInDiscards */
	case 14: /* ifInErrors */
	case 15: /* ifInUnknownProtos */
	case 16: /* ifOutOctets */
	case 17: /* ifOutUcastPkts */
	case 18: /* ifOutNUcastPkts */
	case 19: /* ifOutDiscards */
	case 20: /* ifOutErrors */
		*value_u32 = interfaces_counter(iface, column);
		value_len = sizeof(*value_u32);
		break;
	default:
		return 0;
	}

	return value_len;
}

static const struct snmp_scalar_node interfaces_Number =
	SNMP_SCALAR_CREATE_NODE_READONLY(1, SNMP_ASN1_TYPE_INTEGER, interfaces_get_value);

static const struct snmp_table_col_def interfaces_Table_columns[] = {
	{  1, SNMP_ASN1_TYPE_INTEGER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifIndex */
	{  2, SNMP_ASN1_TYPE_OCTET_STRING, SNMP_NODE_INSTANCE_READ_ONLY }, /* ifDescr */
	{  3, SNMP_ASN1_TYPE_INTEGER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifType */
	{  4, SNMP_ASN1_TYPE_INTEGER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifMtu */
	{  5, SNMP_ASN1_TYPE_GAUGE,        SNMP_NODE_INSTANCE_READ_ONLY }, /* ifSpeed */
	{  6, SNMP_ASN1_TYPE_OCTET_STRING, SNMP_NODE_INSTANCE_READ_ONLY }, /* ifPhysAddress */
	{  7, SNMP_ASN1_TYPE_INTEGER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifAdminStatus */
	{  8, SNMP_ASN1_TYPE_INTEGER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifOperStatus */
	{  9, SNMP_ASN1_TYPE_TIMETICKS,    SNMP_NODE_INSTANCE_READ_ONLY }, /* ifLastChange */
	{ 10, SNMP_ASN1_TYPE_COUNTER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifInOctets */
	{ 11, SNMP_ASN1_TYPE_COUNTER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifInUcastPkts */
	{ 12, SNMP_ASN1_TYPE_COUNTER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifInNUcastPkts */
	{ 13, SNMP_ASN1_TYPE_COUNTER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifInDiscards */
	{ 14, SNMP_ASN1_TYPE_COUNTER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifInErrors */
	{ 15, SNMP_ASN1_TYPE_COUNTER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifInUnknownProtos */
	{ 16, SNMP_ASN1_TYPE_COUNTER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifOutOctets */
	{ 17, SNMP_ASN1_TYPE_COUNTER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifOutUcastPkts */
	{ 18, SNMP_ASN1_TYPE_COUNTER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifOutNUcastPkts */
	{ 19, SNMP_ASN1_TYPE_COUNTER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifOutDiscards */
	{ 20, SNMP_ASN1_TYPE_COUNTER,      SNMP_NODE_INSTANCE_READ_ONLY }, /* ifOutErrors */
	{ 21, SNMP_ASN1_TYPE_GAUGE,        SNMP_NODE_INSTANCE_READ_ONLY }, /* ifOutQLen */
	{ 22, SNMP_ASN1_TYPE_OBJECT_ID,    SNMP_NODE_INSTANCE_READ_ONLY }  /* ifSpecific */
};

/* Every column is read-only: bringing an interface down over SNMP would cut
 * the path the request arrived on. */
static const struct snmp_table_node interfaces_Table = SNMP_TABLE_CREATE(
	2, interfaces_Table_columns,
	interfaces_Table_get_cell_instance, interfaces_Table_get_next_cell_instance,
	interfaces_Table_get_value, NULL, NULL);

static const struct snmp_node *const interface_nodes[] = {
	&interfaces_Number.node.node,
	&interfaces_Table.node.node
};

const struct snmp_tree_node snmp_mib2_interface_root = SNMP_CREATE_TREE_NODE(2, interface_nodes);

#endif /* LWIP_SNMP && SNMP_LWIP_MIB2 && CONFIG_SNMP_AGENT_MIB2_INTERFACES */
