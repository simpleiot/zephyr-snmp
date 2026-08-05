/**
 * @file
 * SNMP server MIB API to implement table nodes
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
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Martin Hentschel <info@cl-soft.de>
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ZEPHYR_INCLUDE_SNMP_TABLE_H_
#define ZEPHYR_INCLUDE_SNMP_TABLE_H_

#include <snmp/snmp_opts.h>
#include <snmp/snmp_core.h>

#ifdef __cplusplus
extern "C" {
#endif

#if LWIP_SNMP /* don't build if not configured for use in lwipopts.h */

/** default (customizable) read/write table */
struct snmp_table_col_def {
	uint32_t index;
	uint8_t asn1_type;
	snmp_access_t access;
};

/** table node */
struct snmp_table_node {
	/** inherited "base class" members */
	struct snmp_leaf_node node;
	uint16_t column_count;
	const struct snmp_table_col_def *columns;
	snmp_err_t (*get_cell_instance)(const uint32_t *column, const uint32_t *row_oid,
					uint8_t row_oid_len,
					struct snmp_node_instance *cell_instance);
	snmp_err_t (*get_next_cell_instance)(const uint32_t *column, struct snmp_obj_id *row_oid,
					     struct snmp_node_instance *cell_instance);
	/** returns object value for the given object identifier */
	node_instance_get_value_method get_value;
	/** tests length and/or range BEFORE setting */
	node_instance_set_test_method set_test;
	/** sets object value, only called when set_test() was successful */
	node_instance_set_value_method set_value;
};

snmp_err_t snmp_table_get_instance(const uint32_t *root_oid, uint8_t root_oid_len,
				   struct snmp_node_instance *instance);
snmp_err_t snmp_table_get_next_instance(const uint32_t *root_oid, uint8_t root_oid_len,
					struct snmp_node_instance *instance);

#define SNMP_TABLE_CREATE(oid, columns, get_cell_instance_method, get_next_cell_instance_method,   \
			  get_value_method, set_test_method, set_value_method)                     \
	{{{SNMP_NODE_TABLE, (oid)}, snmp_table_get_instance, snmp_table_get_next_instance},        \
	 (uint16_t)LWIP_ARRAYSIZE(columns),                                                        \
	 (columns),                                                                                \
	 (get_cell_instance_method),                                                               \
	 (get_next_cell_instance_method),                                                          \
	 (get_value_method),                                                                       \
	 (set_test_method),                                                                        \
	 (set_value_method)}

/* The first array value is the (fixed) row entry, the second is the column,
 * followed by the instance.
 */
#define SNMP_TABLE_GET_COLUMN_FROM_OID(oid) ((oid)[1])

/** simple read-only table */
typedef enum {
	SNMP_VARIANT_VALUE_TYPE_U32,
	SNMP_VARIANT_VALUE_TYPE_S32,
	SNMP_VARIANT_VALUE_TYPE_PTR,
	SNMP_VARIANT_VALUE_TYPE_CONST_PTR
} snmp_table_column_data_type_t;

struct snmp_table_simple_col_def {
	uint32_t index;
	uint8_t asn1_type;
	/* selects the union member used to store the value */
	snmp_table_column_data_type_t data_type;
};

/** simple read-only table node */
struct snmp_table_simple_node {
	/* inherited "base class" members */
	struct snmp_leaf_node node;
	uint16_t column_count;
	const struct snmp_table_simple_col_def *columns;
	snmp_err_t (*get_cell_value)(const uint32_t *column, const uint32_t *row_oid,
				     uint8_t row_oid_len, union snmp_variant_value *value,
				     uint32_t *value_len);
	snmp_err_t (*get_next_cell_instance_and_value)(const uint32_t *column,
						       struct snmp_obj_id *row_oid,
						       union snmp_variant_value *value,
						       uint32_t *value_len);
};

snmp_err_t snmp_table_simple_get_instance(const uint32_t *root_oid, uint8_t root_oid_len,
					  struct snmp_node_instance *instance);
snmp_err_t snmp_table_simple_get_next_instance(const uint32_t *root_oid, uint8_t root_oid_len,
					       struct snmp_node_instance *instance);

#define SNMP_TABLE_CREATE_SIMPLE(oid, columns, get_cell_value_method,                              \
				 get_next_cell_instance_and_value_method)                          \
	{{{SNMP_NODE_TABLE, (oid)},                                                                \
	  snmp_table_simple_get_instance,                                                          \
	  snmp_table_simple_get_next_instance},                                                    \
	 (uint16_t)LWIP_ARRAYSIZE(columns),                                                        \
	 (columns),                                                                                \
	 (get_cell_value_method),                                                                  \
	 (get_next_cell_instance_and_value_method)}

int16_t snmp_table_extract_value_from_s32ref(struct snmp_node_instance *instance, void *value);
int16_t snmp_table_extract_value_from_u32ref(struct snmp_node_instance *instance, void *value);
int16_t snmp_table_extract_value_from_refconstptr(struct snmp_node_instance *instance, void *value);

#endif /* LWIP_SNMP */

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_SNMP_TABLE_H_ */
