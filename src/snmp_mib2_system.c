/**
 * @file
 * Management Information Base II (RFC1213) SYSTEM objects and functions.
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
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <snmp/snmp.h>
#include <snmp/snmp_core.h>
#include <snmp/snmp_mib2.h>
#include <snmp/snmp_table.h>
#include <snmp/snmp_scalar.h>
#include "snmp_priv.h"

#include <string.h>
#include "snmp_lock.h"

LOG_MODULE_DECLARE(net_snmp_agent, CONFIG_SNMP_AGENT_LOG_LEVEL);

#if LWIP_SNMP && SNMP_LWIP_MIB2 && defined(CONFIG_SNMP_AGENT_MIB2_SYSTEM)

#define SYNC_NODE_NAME(node_name) node_name
#define CREATE_LWIP_SYNC_NODE(oid, node_name)

/* --- system .1.3.6.1.2.1.1 ----------------------------------------------------- */

/** mib-2.system.sysDescr */
static const uint8_t sysdescr_default[] = SNMP_LWIP_MIB2_SYSDESC;
static const uint8_t *sysdescr = sysdescr_default;
static const uint16_t *sysdescr_len; /* use strlen for determining len */

/** mib-2.system.sysContact */
static const uint8_t syscontact_default[] = SNMP_LWIP_MIB2_SYSCONTACT;
static const uint8_t *syscontact = syscontact_default;
static const uint16_t *syscontact_len; /* use strlen for determining len */
/* The writable aliases point at the same buffers as the const pointers above;
 * the duplication is what keeps the read-only views correctly const.
 */
static uint8_t *syscontact_wr;
static uint16_t *syscontact_wr_len;
static uint16_t syscontact_bufsize; /* 0=not writable */

/** mib-2.system.sysName */
static const uint8_t sysname_default[] = SNMP_LWIP_MIB2_SYSNAME;
static const uint8_t *sysname = sysname_default;
static const uint16_t *sysname_len; /* use strlen for determining len */
static uint8_t *sysname_wr;
static uint16_t *sysname_wr_len;
static uint16_t sysname_bufsize; /* 0=not writable */

/** mib-2.system.sysLocation */
static const uint8_t syslocation_default[] = SNMP_LWIP_MIB2_SYSLOCATION;
static const uint8_t *syslocation = syslocation_default;
static const uint16_t *syslocation_len; /* use strlen for determining len */
static uint8_t *syslocation_wr;
static uint16_t *syslocation_wr_len;
static uint16_t syslocation_bufsize; /* 0=not writable */

/**
 * @ingroup snmp_mib2
 * Initializes sysDescr pointers.
 *
 * @param str if non-NULL then copy str pointer
 * @param len points to string length, excluding zero terminator
 */
void snmp_mib2_set_sysdescr(const uint8_t *str, const uint16_t *len)
{
	snmp_agent_lock();
	if (str != NULL) {
		sysdescr = str;
		sysdescr_len = len;
	}
	snmp_agent_unlock();
}

/**
 * @ingroup snmp_mib2
 * Initializes sysContact pointers
 *
 * @param ocstr if non-NULL then copy str pointer
 * @param ocstrlen points to string length, excluding zero terminator.
 *        if set to NULL it is assumed that ocstr is NULL-terminated.
 * @param bufsize size of the buffer in bytes.
 *        (this is required because the buffer can be overwritten by snmp-set)
 *        if ocstrlen is NULL buffer needs space for terminating 0 byte.
 *        otherwise complete buffer is used for string.
 *        if bufsize is set to 0, the value is regarded as read-only.
 */
void snmp_mib2_set_syscontact(uint8_t *ocstr, uint16_t *ocstrlen, uint16_t bufsize)
{
	snmp_agent_lock();
	if (ocstr != NULL) {
		syscontact = ocstr;
		syscontact_wr = ocstr;
		syscontact_len = ocstrlen;
		syscontact_wr_len = ocstrlen;
		syscontact_bufsize = bufsize;
	}
	snmp_agent_unlock();
}

/**
 * @ingroup snmp_mib2
 * see \ref snmp_mib2_set_syscontact but set pointer to readonly memory
 */
void snmp_mib2_set_syscontact_readonly(const uint8_t *ocstr, const uint16_t *ocstrlen)
{
	snmp_agent_lock();
	if (ocstr != NULL) {
		syscontact = ocstr;
		syscontact_len = ocstrlen;
		syscontact_wr = NULL;
		syscontact_wr_len = NULL;
		syscontact_bufsize = 0;
	}
	snmp_agent_unlock();
}

/**
 * @ingroup snmp_mib2
 * Initializes sysName pointers
 *
 * @param ocstr if non-NULL then copy str pointer
 * @param ocstrlen points to string length, excluding zero terminator.
 *        if set to NULL it is assumed that ocstr is NULL-terminated.
 * @param bufsize size of the buffer in bytes.
 *        (this is required because the buffer can be overwritten by snmp-set)
 *        if ocstrlen is NULL buffer needs space for terminating 0 byte.
 *        otherwise complete buffer is used for string.
 *        if bufsize is set to 0, the value is regarded as read-only.
 */
void snmp_mib2_set_sysname(uint8_t *ocstr, uint16_t *ocstrlen, uint16_t bufsize)
{
	snmp_agent_lock();
	if (ocstr != NULL) {
		sysname = ocstr;
		sysname_wr = ocstr;
		sysname_len = ocstrlen;
		sysname_wr_len = ocstrlen;
		sysname_bufsize = bufsize;
	}
	snmp_agent_unlock();
}

/**
 * @ingroup snmp_mib2
 * see \ref snmp_mib2_set_sysname but set pointer to readonly memory
 */
void snmp_mib2_set_sysname_readonly(const uint8_t *ocstr, const uint16_t *ocstrlen)
{
	snmp_agent_lock();
	if (ocstr != NULL) {
		sysname = ocstr;
		sysname_len = ocstrlen;
		sysname_wr = NULL;
		sysname_wr_len = NULL;
		sysname_bufsize = 0;
	}
	snmp_agent_unlock();
}

/**
 * @ingroup snmp_mib2
 * Initializes sysLocation pointers
 *
 * @param ocstr if non-NULL then copy str pointer
 * @param ocstrlen points to string length, excluding zero terminator.
 *        if set to NULL it is assumed that ocstr is NULL-terminated.
 * @param bufsize size of the buffer in bytes.
 *        (this is required because the buffer can be overwritten by snmp-set)
 *        if ocstrlen is NULL buffer needs space for terminating 0 byte.
 *        otherwise complete buffer is used for string.
 *        if bufsize is set to 0, the value is regarded as read-only.
 */
void snmp_mib2_set_syslocation(uint8_t *ocstr, uint16_t *ocstrlen, uint16_t bufsize)
{
	snmp_agent_lock();
	if (ocstr != NULL) {
		syslocation = ocstr;
		syslocation_wr = ocstr;
		syslocation_len = ocstrlen;
		syslocation_wr_len = ocstrlen;
		syslocation_bufsize = bufsize;
	}
	snmp_agent_unlock();
}

/**
 * @ingroup snmp_mib2
 * see \ref snmp_mib2_set_syslocation but set pointer to readonly memory
 */
void snmp_mib2_set_syslocation_readonly(const uint8_t *ocstr, const uint16_t *ocstrlen)
{
	snmp_agent_lock();
	if (ocstr != NULL) {
		syslocation = ocstr;
		syslocation_len = ocstrlen;
		syslocation_wr = NULL;
		syslocation_wr_len = NULL;
		syslocation_bufsize = 0;
	}
	snmp_agent_unlock();
}

static const char *const oid_names[] = {
	"oidNull",    "sysDescr", "sysObjectID", "sysUpTime",
	"sysContact", "sysName",  "sysLocation", "sysServices",
};

static const char *oid_name(int index)
{
	if (index >= 0 && index < (int)ARRAY_SIZE(oid_names)) {
		return oid_names[index];
	}
	return "oidUnknown";
}

static int16_t system_get_value(const struct snmp_scalar_array_node_def *node, void *value)
{
	const uint8_t *var = NULL;
	const int16_t *var_len;
	uint16_t result;

	LOG_DBG("get id %d (%s)", (int)node->oid, oid_name(node->oid));

	switch (node->oid) {
	case 1: /* sysDescr */
		var = sysdescr;
		var_len = (const int16_t *)sysdescr_len;
		break;
	case 2: { /* sysObjectID */
		const struct snmp_obj_id *dev_enterprise_oid = snmp_get_device_enterprise_oid();

		MEMCPY(value, dev_enterprise_oid->id, dev_enterprise_oid->len * sizeof(uint32_t));
		return dev_enterprise_oid->len * sizeof(uint32_t);
	}
	case 3: /* sysUpTime */
		MIB2_COPY_SYSUPTIME_TO((uint32_t *)value);
		return sizeof(uint32_t);
	case 4: /* sysContact */
		var = syscontact;
		var_len = (const int16_t *)syscontact_len;
		break;
	case 5: /* sysName */
		var = sysname;
		var_len = (const int16_t *)sysname_len;
		break;
	case 6: /* sysLocation */
		var = syslocation;
		var_len = (const int16_t *)syslocation_len;
		break;
	case 7: /* sysServices */
		*(int32_t *)value = SNMP_SYSSERVICES;
		return sizeof(int32_t);
	default:
		LOG_DBG("get: unknown id %d", node->oid);
		return 0;
	}

	/* handle string values (OID 1,4,5 and 6) */
	LWIP_ASSERT("", (value != NULL));
	if (var_len == NULL) {
		result = (int16_t)strlen((const char *)var);
	} else {
		result = *var_len;
	}
	MEMCPY(value, var, result);
	return result;
}

static snmp_err_t system_set_test(const struct snmp_scalar_array_node_def *node, uint16_t len,
				  void *value)
{
	snmp_err_t ret = SNMP_ERR_WRONGVALUE;
	const uint16_t *var_bufsize = NULL;
	const uint16_t *var_wr_len;

	LWIP_UNUSED_ARG(value);

	switch (node->oid) {
	case 4: /* sysContact */
		var_bufsize = &syscontact_bufsize;
		var_wr_len = syscontact_wr_len;
		break;
	case 5: /* sysName */
		var_bufsize = &sysname_bufsize;
		var_wr_len = sysname_wr_len;
		break;
	case 6: /* sysLocation */
		var_bufsize = &syslocation_bufsize;
		var_wr_len = syslocation_wr_len;
		break;
	default:
		LOG_DBG("set test: unknown id %d", node->oid);
		return ret;
	}

	/* check if value is writable at all */
	if (*var_bufsize > 0) {
		if (var_wr_len == NULL) {
			/* we have to take the terminating 0 into account */
			if (len < *var_bufsize) {
				ret = SNMP_ERR_NOERROR;
			}
		} else {
			if (len <= *var_bufsize) {
				ret = SNMP_ERR_NOERROR;
			}
		}
	} else {
		ret = SNMP_ERR_NOTWRITABLE;
	}

	return ret;
}

static snmp_err_t system_set_value(const struct snmp_scalar_array_node_def *node, uint16_t len,
				   void *value)
{
	uint8_t *var_wr = NULL;
	uint16_t *var_wr_len;

	switch (node->oid) {
	case 4: /* sysContact */
		var_wr = syscontact_wr;
		var_wr_len = syscontact_wr_len;
		break;
	case 5: /* sysName */
		var_wr = sysname_wr;
		var_wr_len = sysname_wr_len;
		break;
	case 6: /* sysLocation */
		var_wr = syslocation_wr;
		var_wr_len = syslocation_wr_len;
		break;
	default:
		LOG_DBG("set: unknown id %d", node->oid);
		return SNMP_ERR_GENERROR;
	}

	/* no need to check size of target buffer, this was already done in set_test method */
	LWIP_ASSERT("", var_wr != NULL);
	MEMCPY(var_wr, value, len);

	if (var_wr_len == NULL) {
		/* add terminating 0 */
		var_wr[len] = 0;
	} else {
		*var_wr_len = len;
	}

	return SNMP_ERR_NOERROR;
}

static const struct snmp_scalar_array_node_def system_nodes[] = {
	{1, SNMP_ASN1_TYPE_OCTET_STRING, SNMP_NODE_INSTANCE_READ_ONLY},  /* sysDescr */
	{2, SNMP_ASN1_TYPE_OBJECT_ID, SNMP_NODE_INSTANCE_READ_ONLY},     /* sysObjectID */
	{3, SNMP_ASN1_TYPE_TIMETICKS, SNMP_NODE_INSTANCE_READ_ONLY},     /* sysUpTime */
	{4, SNMP_ASN1_TYPE_OCTET_STRING, SNMP_NODE_INSTANCE_READ_WRITE}, /* sysContact */
	{5, SNMP_ASN1_TYPE_OCTET_STRING, SNMP_NODE_INSTANCE_READ_WRITE}, /* sysName */
	{6, SNMP_ASN1_TYPE_OCTET_STRING, SNMP_NODE_INSTANCE_READ_WRITE}, /* sysLocation */
	{7, SNMP_ASN1_TYPE_INTEGER, SNMP_NODE_INSTANCE_READ_ONLY}        /* sysServices */
};

const struct snmp_scalar_array_node snmp_mib2_system_node = SNMP_SCALAR_CREATE_ARRAY_NODE(
	1, system_nodes, system_get_value, system_set_test, system_set_value);

#endif /* LWIP_SNMP && SNMP_LWIP_MIB2 && CONFIG_SNMP_AGENT_MIB2_SYSTEM */
