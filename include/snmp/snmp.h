/**
 * @file
 * SNMP server main API - start and basic configuration
 */

/*
 * Copyright (c) 2001, 2002 Leon Woestenberg <leon.woestenberg@axon.tv>
 * Copyright (c) 2001, 2002 Axon Digital Design B.V., The Netherlands.
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
 * Author: Leon Woestenberg <leon.woestenberg@axon.tv>
 *         Martin Hentschel <info@cl-soft.de>
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef ZEPHYR_INCLUDE_SNMP_H_
#define ZEPHYR_INCLUDE_SNMP_H_

#include <snmp/snmp_opts.h>

#include <zephyr/net/net_ip.h>

#ifdef __cplusplus
extern "C" {
#endif

#if LWIP_SNMP /* don't build if not configured for use in lwipopts.h */

#include <snmp/snmp_core.h>

/** SNMP variable binding descriptor (publicly needed for traps) */
struct snmp_varbind {
	/** pointer to next varbind, NULL for last in list */
	struct snmp_varbind *next;
	/** Pointer to previous varbind, NULL for first in list.
	 *
	 * Retained for source compatibility. The agent walks varbind lists
	 * forward only and never reads this field, so leaving it NULL is fine.
	 */
	struct snmp_varbind *prev;

	/** object identifier */
	struct snmp_obj_id oid;

	/** value ASN1 type */
	uint8_t type;
	/** object value length */
	uint16_t value_len;
	/** object value */
	void *object_value;
};

/**
 * @ingroup snmp_core
 * Agent setup, start listening to port 161.
 */
int snmp_init(void);
void snmp_set_mibs(const struct snmp_mib **mibs, uint8_t num_mibs);

void snmp_set_device_enterprise_oid(const struct snmp_obj_id *device_enterprise_oid);
const struct snmp_obj_id *snmp_get_device_enterprise_oid(void);

void snmp_trap_dst_enable(uint8_t dst_idx, uint8_t enable);
void snmp_trap_dst_ip_set(uint8_t dst_idx, const struct net_in_addr *dst);

/** Generic trap: cold start */
#define SNMP_GENTRAP_COLDSTART           0
/** Generic trap: warm start */
#define SNMP_GENTRAP_WARMSTART           1
/** Generic trap: link down */
#define SNMP_GENTRAP_LINKDOWN            2
/** Generic trap: link up */
#define SNMP_GENTRAP_LINKUP              3
/** Generic trap: authentication failure */
#define SNMP_GENTRAP_AUTH_FAILURE        4
/** Generic trap: EGP neighbor lost */
#define SNMP_GENTRAP_EGP_NEIGHBOR_LOSS   5
/** Generic trap: enterprise specific */
#define SNMP_GENTRAP_ENTERPRISE_SPECIFIC 6

int snmp_send_trap_generic(int32_t generic_trap);
int snmp_send_trap_specific(int32_t specific_trap, struct snmp_varbind *varbinds);
int snmp_send_trap(const struct snmp_obj_id *oid, int32_t generic_trap, int32_t specific_trap,
		   struct snmp_varbind *varbinds);

int snmp_send_inform_generic(int32_t generic_trap, struct snmp_varbind *varbinds,
			     int32_t *ptr_request_id);
int snmp_send_inform_specific(int32_t specific_trap, struct snmp_varbind *varbinds,
			      int32_t *ptr_request_id);
int snmp_send_inform(const struct snmp_obj_id *oid, int32_t generic_trap, int32_t specific_trap,
		     struct snmp_varbind *varbinds, int32_t *ptr_request_id);
struct snmp_request;
typedef void (*snmp_inform_callback_fct)(struct snmp_request *request, void *callback_arg);
void snmp_set_inform_callback(snmp_inform_callback_fct inform_callback, void *callback_arg);

void snmp_set_default_trap_version(uint8_t snmp_version);
uint8_t snmp_get_default_trap_version(void);

#define SNMP_AUTH_TRAPS_DISABLED 0
#define SNMP_AUTH_TRAPS_ENABLED  1
void snmp_set_auth_traps_enabled(uint8_t enable);
uint8_t snmp_get_auth_traps_enabled(void);

uint8_t snmp_v1_enabled(void);
uint8_t snmp_v2c_enabled(void);
uint8_t snmp_v3_enabled(void);
void snmp_v1_enable(uint8_t enable);
void snmp_v2c_enable(uint8_t enable);
void snmp_v3_enable(uint8_t enable);

const char *snmp_get_community(void);
const char *snmp_get_community_write(void);
const char *snmp_get_community_trap(void);
void snmp_set_community(const char *const community);
void snmp_set_community_write(const char *const community);
void snmp_set_community_trap(const char *const community);

void snmp_coldstart_trap(void);
void snmp_authfail_trap(void);

typedef void (*snmp_write_callback_fct)(const uint32_t *oid, uint8_t oid_len, void *callback_arg);
void snmp_set_write_callback(snmp_write_callback_fct write_callback, void *callback_arg);

#endif /* LWIP_SNMP */

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_SNMP_H_ */
