/**
 * @file
 * Zephyr frontend for the SNMP agent.
 */

/*
 * Copyright (c) 2025 lwIP contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __SNMP_ZEPHYR_H
#define __SNMP_ZEPHYR_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Start the SNMP agent.
 *
 * Creates the UDP socket the agent listens on and registers it with Zephyr's
 * socket service, which delivers requests on its own thread. The socket binds
 * to any address, so the agent may be started before an IPv4 address has been
 * assigned; it answers as soon as one is.
 *
 * Calling this on an already running agent succeeds and changes nothing.
 *
 * @return 0 on success, or a negative errno value.
 */
int net_snmp_agent_start(void);

/**
 * @brief Stop the SNMP agent.
 *
 * Unregisters the socket service and closes the socket. Calling this on an
 * agent that is not running succeeds and changes nothing.
 *
 * @return 0 on success, or a negative errno value.
 */
int net_snmp_agent_stop(void);

/**
 * @brief Direct traps at a manager, for bring-up.
 *
 * Selects SNMPv2c and points trap destination 0 at @p ip_address, which is a
 * convenience wrapper over snmp_set_default_trap_version(),
 * snmp_trap_dst_enable(), and snmp_trap_dst_ip_set(). Use those directly to
 * configure more than one destination.
 *
 * @param[in] ip_address Manager address in dotted-quad form.
 *
 * @return 0 on success, or -EINVAL if @p ip_address does not parse.
 */
int net_snmp_agent_trap_dst_set(const char *ip_address);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __SNMP_ZEPHYR_H */
