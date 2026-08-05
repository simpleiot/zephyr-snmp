/**
 * @file
 * Serialization of agent state between the socket service and applications.
 */

/*
 * Copyright (c) 2025 lwIP contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef LWIP_HDR_SNMP_LOCK_H
#define LWIP_HDR_SNMP_LOCK_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The agent core keeps state in file-scope variables and has no locking of
 * its own. Requests are processed on Zephyr's socket service thread while
 * applications configure the agent and send traps from their own threads, so
 * both sides take this lock.
 *
 * The lock is recursive: an application entry point may hold it while the
 * agent core calls back into another entry point.
 */
void snmp_agent_lock(void);
void snmp_agent_unlock(void);

/**
 * @brief Whether the calling thread holds the agent lock.
 *
 * For assertions only.
 */
bool snmp_agent_lock_held(void);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_HDR_SNMP_LOCK_H */
