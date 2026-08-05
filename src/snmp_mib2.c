/**
 * @file
 * Management Information Base II (RFC1213) objects and functions.
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
 */

/**
 * @defgroup snmp_mib2 MIB2
 * @ingroup snmp
 */

#include <snmp/snmp_opts.h>
#include "snmp_priv.h"

#if LWIP_SNMP && SNMP_LWIP_MIB2 /* don't build if not configured for use in lwipopts.h */

#include <snmp/snmp.h>
#include <snmp/snmp_core.h>
#include <snmp/snmp_mib2.h>
#include <snmp/snmp_scalar.h>

/* The groups this port publishes are the ones it can answer from Zephyr:
 * system, interfaces, and snmp. The ip and udp groups were dropped because
 * every scalar in them read an lwIP global that this port never populates,
 * so they reported zeros and empty tables; reporting nothing is more honest
 * than reporting zero. They can return backed by net_stats and
 * net_context_foreach(). The at, icmp, and tcp groups were never compiled.
 */

/* --- mib-2 .1.3.6.1.2.1 ----------------------------------------------------- */
extern const struct snmp_scalar_array_node snmp_mib2_system_node;
extern const struct snmp_tree_node snmp_mib2_interface_root;
extern const struct snmp_scalar_array_node snmp_mib2_snmp_root;

static const struct snmp_node *const mib2_nodes[] = {
#ifdef CONFIG_SNMP_AGENT_MIB2_SYSTEM
	&snmp_mib2_system_node.node.node,
#endif
#ifdef CONFIG_SNMP_AGENT_MIB2_INTERFACES
	&snmp_mib2_interface_root.node,
#endif
#ifdef CONFIG_SNMP_AGENT_MIB2_SNMP
	&snmp_mib2_snmp_root.node.node,
#endif
};

static const struct snmp_tree_node mib2_root = SNMP_CREATE_TREE_NODE(1, mib2_nodes);

static const uint32_t mib2_base_oid_arr[] = {1, 3, 6, 1, 2, 1};
const struct snmp_mib mib2 = SNMP_MIB_CREATE(mib2_base_oid_arr, &mib2_root.node);

#endif /* LWIP_SNMP && SNMP_LWIP_MIB2 */
