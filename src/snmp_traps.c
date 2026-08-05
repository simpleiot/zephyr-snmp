/**
 * @file
 * SNMPv1 and SNMPv2 traps implementation.
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
 * Author: Martin Hentschel
 *         Christiaan Simons <christiaan.simons@axon.tv>
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <snmp/snmp_opts.h>
#include "snmp_priv.h"
#include "snmp_lock.h"

LOG_MODULE_DECLARE(net_snmp_agent, CONFIG_SNMP_AGENT_LOG_LEVEL);

#if LWIP_SNMP /* don't build if not configured for use in lwipopts.h */

#include <string.h>

#include <snmp/snmp.h>
#include <snmp/snmp_core.h>
#include "snmp_msg.h"
#include "snmp_asn1.h"
#include "snmp_core_priv.h"

#define SNMP_IS_INFORM 1
#define SNMP_IS_TRAP   0

struct snmp_msg_trap {
	/* source enterprise ID (sysObjectID) */
	const struct snmp_obj_id *enterprise;
	/* source IP address, raw network order format */
	struct net_in_addr sip;
	/* generic trap code */
	uint32_t gen_trap;
	/* specific trap code */
	uint32_t spc_trap;
	/* timestamp */
	uint32_t ts;
	/* snmp_version */
	uint32_t snmp_version;

	/* output trap lengths used in ASN encoding */
	/* encoding pdu length */
	uint16_t pdulen;
	/* encoding community length */
	uint16_t comlen;
	/* encoding sequence length */
	uint16_t seqlen;
	/* encoding varbinds sequence length */
	uint16_t vbseqlen;

	/* error status */
	int32_t error_status;
	/* error index */
	int32_t error_index;
	/* trap or inform? */
	uint8_t trap_or_inform;
};

static uint16_t snmp_trap_varbind_sum(struct snmp_msg_trap *trap, struct snmp_varbind *varbinds);
static uint16_t snmp_trap_header_sum(struct snmp_msg_trap *trap, uint16_t vb_len);
static int snmp_trap_header_enc(struct snmp_msg_trap *trap, struct snmp_pbuf_stream *pbuf_stream);
static int snmp_trap_varbind_enc(struct snmp_msg_trap *trap, struct snmp_pbuf_stream *pbuf_stream,
				 struct snmp_varbind *varbinds);
static uint16_t snmp_trap_header_sum_v1_specific(struct snmp_msg_trap *trap);
static uint16_t snmp_trap_header_sum_v2c_specific(struct snmp_msg_trap *trap);
static int snmp_trap_header_enc_v1_specific(struct snmp_msg_trap *trap,
					    struct snmp_pbuf_stream *pbuf_stream);
static int snmp_trap_header_enc_v2c_specific(struct snmp_msg_trap *trap,
					     struct snmp_pbuf_stream *pbuf_stream);
static int snmp_prepare_trap_oid(struct snmp_obj_id *dest_snmp_trap_oid,
				 const struct snmp_obj_id *eoid, int32_t generic_trap,
				 int32_t specific_trap);
static void snmp_prepare_necessary_msg_fields(struct snmp_msg_trap *trap_msg,
					      const struct snmp_obj_id *eoid, int32_t generic_trap,
					      int32_t specific_trap, struct snmp_varbind *varbinds);
static int snmp_send_msg(struct snmp_msg_trap *trap_msg, struct snmp_varbind *varbinds,
			 uint16_t tot_len, struct net_in_addr *dip);

#define BUILD_EXEC(code)                                                                           \
	if ((code) != ERR_OK) {                                                                    \
		LOG_DBG("SNMP error during creation of outbound trap frame!\n");                   \
		return ERR_ARG;                                                                    \
	}

/** Agent community string for sending traps */
extern const char *snmp_community_trap;

void *snmp_traps_handle;

/**
 * @ingroup snmp_traps
 * @struct snmp_trap_dst
 */
struct snmp_trap_dst {
	/* destination IP address in network order */
	struct net_in_addr dip;
	/* set to 0 when disabled, >0 when enabled */
	uint8_t enable;
};
static struct snmp_trap_dst trap_dst[SNMP_TRAP_DESTINATIONS];

/** Where traps are encoded. Separate from the response buffer so that a trap
 *  raised while a request is being answered cannot overwrite the reply. */
static uint8_t snmp_trap_buf[CONFIG_SNMP_AGENT_MAX_MSG_SIZE];

static uint8_t snmp_auth_traps_enabled;

/* This is used in functions like snmp_coldstart_trap where user didn't specify which version of
 * trap to use */
static uint8_t snmp_default_trap_version = SNMP_VERSION_1;

/* This is used in trap messages v2c */
static int32_t req_id = 1;

/**
 * @ingroup snmp_traps
 * Sets enable switch for this trap destination.
 * @param dst_idx index in 0 .. SNMP_TRAP_DESTINATIONS-1
 * @param enable switch if 0 destination is disabled >0 enabled.
 *
 * @retval void
 */
void snmp_trap_dst_enable(uint8_t dst_idx, uint8_t enable)
{
	snmp_agent_lock();
	if (dst_idx < SNMP_TRAP_DESTINATIONS) {
		trap_dst[dst_idx].enable = enable;
	}
	snmp_agent_unlock();
}

/**
 * @ingroup snmp_traps
 * Sets IPv4 address for this trap destination.
 * @param dst_idx index in 0 .. SNMP_TRAP_DESTINATIONS-1
 * @param dst IPv4 address in host order.
 *
 * @retval void
 */
void snmp_trap_dst_ip_set(uint8_t dst_idx, const struct net_in_addr *dst)
{
	snmp_agent_lock();
	if (dst_idx < SNMP_TRAP_DESTINATIONS) {
		trap_dst[dst_idx].dip = *dst;
	}
	snmp_agent_unlock();
}

/**
 * @ingroup snmp_traps
 * Enable/disable authentication traps
 *
 * @param enable enable SNMP traps
 *
 * @retval void
 */
void snmp_set_auth_traps_enabled(uint8_t enable)
{
	snmp_agent_lock();
	snmp_auth_traps_enabled = enable;
	snmp_agent_unlock();
}

/**
 * @ingroup snmp_traps
 * Get authentication traps enabled state
 *
 * @return TRUE if traps are enabled, FALSE if they aren't
 */
uint8_t snmp_get_auth_traps_enabled(void)
{
	uint8_t enabled;

	snmp_agent_lock();
	enabled = snmp_auth_traps_enabled;
	snmp_agent_unlock();

	return enabled;
}

/**
 * @ingroup snmp_traps
 * Choose default SNMP version for sending traps (if not specified, default version is
 * SNMP_VERSION_1) SNMP_VERSION_1  0 SNMP_VERSION_2c 1 SNMP_VERSION_3  3
 *
 * @param snmp_version version that will be used for sending traps
 *
 * @retval void
 */
void snmp_set_default_trap_version(uint8_t snmp_version)
{
	snmp_agent_lock();
	snmp_default_trap_version = snmp_version;
	snmp_agent_unlock();
}

/**
 * @ingroup snmp_traps
 * Get default SNMP version for sending traps
 *
 * @return selected default version:
 * 0 - SNMP_VERSION_1
 * 1 - SNMP_VERSION_2c
 * 3 - SNMP_VERSION_3
 */
uint8_t snmp_get_default_trap_version(void)
{
	uint8_t version;

	snmp_agent_lock();
	version = snmp_default_trap_version;
	snmp_agent_unlock();

	return version;
}

/**
 * @ingroup snmp_traps
 * Prepares snmpTrapOID for SNMP v2c
 * @param dest_snmp_trap_oid pointer to destination snmpTrapOID
 * @param eoid enterprise oid (can be NULL)
 * @param generic_trap SNMP v1 generic trap
 * @param specific_trap SNMP v1 specific trap
 * @return ERR_OK if completed successfully;
 *         ERR_MEM if there wasn't enough memory allocated for destination;
 *         ERR_VAL if value for generic trap was incorrect;
 */
static int snmp_prepare_trap_oid(struct snmp_obj_id *dest_snmp_trap_oid,
				 const struct snmp_obj_id *eoid, int32_t generic_trap,
				 int32_t specific_trap)
{
	int err = ERR_OK;
	const uint32_t snmpTrapOID[] = {1, 3, 6, 1, 6, 3, 1, 1, 5}; /* please see rfc3584 */

	if (generic_trap == SNMP_GENTRAP_ENTERPRISE_SPECIFIC) {
		if (eoid == NULL) {
			MEMCPY(dest_snmp_trap_oid, snmp_get_device_enterprise_oid(),
			       sizeof(*dest_snmp_trap_oid));
		} else {
			MEMCPY(dest_snmp_trap_oid, eoid, sizeof(*dest_snmp_trap_oid));
		}
		if (dest_snmp_trap_oid->len + 2 < SNMP_MAX_OBJ_ID_LEN) {
			dest_snmp_trap_oid->id[dest_snmp_trap_oid->len++] = specific_trap;
		} else {
			err = ERR_MEM;
		}
	} else if ((generic_trap >= SNMP_GENTRAP_COLDSTART) &&
		   (generic_trap < SNMP_GENTRAP_ENTERPRISE_SPECIFIC)) {
		if (sizeof(dest_snmp_trap_oid->id) >= sizeof(snmpTrapOID)) {
			MEMCPY(&dest_snmp_trap_oid->id, snmpTrapOID, sizeof(snmpTrapOID));
			dest_snmp_trap_oid->len = LWIP_ARRAYSIZE(snmpTrapOID);
			dest_snmp_trap_oid->id[dest_snmp_trap_oid->len++] = generic_trap + 1;
		} else {
			err = ERR_MEM;
		}
	} else {
		err = ERR_VAL;
	}

	return err;
}

/**
 * @ingroup snmp_traps
 * Prepare the rest of the necessary fields for trap/notification/inform message.
 * @param trap_msg message that should be set
 * @param eoid enterprise oid (can be NULL)
 * @param generic_trap SNMP v1 generic trap
 * @param specific_trap SNMP v1 specific trap
 * @param varbinds list of varbinds
 * @retval void
 */
static void snmp_prepare_necessary_msg_fields(struct snmp_msg_trap *trap_msg,
					      const struct snmp_obj_id *eoid, int32_t generic_trap,
					      int32_t specific_trap, struct snmp_varbind *varbinds)
{
	if (trap_msg->snmp_version == SNMP_VERSION_1) {
		trap_msg->enterprise = (eoid == NULL) ? snmp_get_device_enterprise_oid() : eoid;
		trap_msg->gen_trap = generic_trap;
		trap_msg->spc_trap =
			(generic_trap == SNMP_GENTRAP_ENTERPRISE_SPECIFIC) ? specific_trap : 0;
		MIB2_COPY_SYSUPTIME_TO(&trap_msg->ts);
	} else if (trap_msg->snmp_version == SNMP_VERSION_2c) {
		/* Copy sysUpTime into the first varbind */
		MIB2_COPY_SYSUPTIME_TO((uint32_t *)varbinds[0].object_value);
	}
}

/**
 * @ingroup snmp_traps
 * Copy trap message structure to pbuf and sends it
 * @param trap_msg contains the data that should be sent
 * @param varbinds list of varbinds
 * @param tot_len total length of encoded data
 * @param dip destination IP address
 * @return ERR_OK if sending was successful
 */
static int snmp_send_msg(struct snmp_msg_trap *trap_msg, struct snmp_varbind *varbinds,
			 uint16_t tot_len, struct net_in_addr *dip)
{
	int err = ERR_OK;
	struct snmp_pbuf_stream pbuf_stream;
	/* snmp_sendto() wants a network-endian port number. */
	uint16_t port = net_htons(CONFIG_SNMP_AGENT_TRAP_PORT);

	if (tot_len > sizeof(snmp_trap_buf)) {
		LOG_ERR("trap needs %u bytes, CONFIG_SNMP_AGENT_MAX_MSG_SIZE is %u",
			(unsigned)tot_len, (unsigned)sizeof(snmp_trap_buf));
		return ERR_MEM;
	}

	snmp_pbuf_stream_init(&pbuf_stream, snmp_trap_buf, 0, tot_len);

	BUILD_EXEC(snmp_trap_header_enc(trap_msg, &pbuf_stream));
	BUILD_EXEC(snmp_trap_varbind_enc(trap_msg, &pbuf_stream, varbinds));

	snmp_stats.outtraps++;
	snmp_stats.outpkts++;

	err = snmp_sendto(snmp_traps_handle, snmp_trap_buf, tot_len, dip, port);

	return err;
}

/**
 * @ingroup snmp_traps
 * Prepare and sends a generic or enterprise specific trap message, notification or inform.
 *
 * @param trap_msg defines msg type
 * @param eoid points to enterprise object identifier
 * @param generic_trap is the trap code
 * @param specific_trap used for enterprise traps when generic_trap == 6
 * @param varbinds linked list of varbinds to be sent
 * @return ERR_OK when success, ERR_MEM if we're out of memory
 *
 * @note the use of the enterprise identifier field
 * is per RFC1215.
 * Use .iso.org.dod.internet.mgmt.mib-2.snmp for generic traps
 * and .iso.org.dod.internet.private.enterprises.yourenterprise
 * (sysObjectID) for specific traps.
 */
static int snmp_send_trap_or_notification_or_inform_generic(struct snmp_msg_trap *trap_msg,
							    const struct snmp_obj_id *eoid,
							    int32_t generic_trap,
							    int32_t specific_trap,
							    struct snmp_varbind *varbinds)
{
	struct snmp_trap_dst *td = NULL;
	uint16_t i = 0;
	uint16_t tot_len = 0;
	int err = ERR_OK;
	uint32_t timestamp = 0;
	struct snmp_varbind *original_varbinds = varbinds;
	struct snmp_varbind *original_prev = NULL;
	bool prev_replaced = false;
	/* Converts the SNMPv1 generic/specific trap parameters to an SNMPv2
	 * snmpTrapOID. This must outlive the block that fills it in: the
	 * varbind below points at snmp_trap_oid.id, and the encoding happens
	 * further down, in the loop over trap destinations.
	 */
	struct snmp_obj_id snmp_trap_oid = {0};
	struct snmp_varbind snmp_v2_special_varbinds[] = {
		/* First varbind is used to store sysUpTime */
		{
			NULL, /* *next */
			NULL, /* *prev */
			{
				/* oid */
				9, /* oid len */
				{1, 3, 6, 1, 2, 1, 1, 3, 0}
				/* oid for sysUpTime (1.3.6.1.2.1.1.3) */
			},
			SNMP_ASN1_TYPE_TIMETICKS, /* type */
			sizeof(uint32_t),         /* value_len */
			NULL                      /* value */
		},
		/* 1.3.6.1.6.3.1.1.4.1.0
		 * Second varbind is used to store snmpTrapOID
		 * "The authoritative identification of the notification
		 * currently being sent. This variable occurs as
		 * the second varbind in every SNMPv2-Trap-PDU and
		 * InformRequest-PDU."
		 */
		{
			NULL, /* *next */
			NULL, /* *prev */
			{
				/* oid */
				11, /* oid len */
				{1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0}
				/* oid for snmpTrapOID (1.3.6.1.6.3.1.1.4.1.0) */
			},
			SNMP_ASN1_TYPE_OBJECT_ID, /* type */
			0,                        /* value_len */
			NULL                      /* value */
		}};

	LWIP_ASSERT_SNMP_LOCKED();

	snmp_v2_special_varbinds[0].next = &snmp_v2_special_varbinds[1];
	snmp_v2_special_varbinds[1].prev = &snmp_v2_special_varbinds[0];

	snmp_v2_special_varbinds[0].object_value = &timestamp;

	snmp_v2_special_varbinds[1].next = varbinds;

	/* see rfc3584 */
	if (trap_msg->snmp_version == SNMP_VERSION_2c) {
		err = snmp_prepare_trap_oid(&snmp_trap_oid, eoid, generic_trap, specific_trap);
		if (err == ERR_OK) {
			snmp_v2_special_varbinds[1].value_len =
				snmp_trap_oid.len * sizeof(snmp_trap_oid.id[0]);
			snmp_v2_special_varbinds[1].object_value = snmp_trap_oid.id;
			if (varbinds != NULL) {
				original_prev = varbinds->prev;
				varbinds->prev = &snmp_v2_special_varbinds[1];
				prev_replaced = true;
			}
			varbinds = snmp_v2_special_varbinds; /* After inserting two varbinds at the
								beginning of the list, make sure
								that pointer is pointing to the
								first element  */
		}
	}

	for (i = 0, td = &trap_dst[0]; (i < SNMP_TRAP_DESTINATIONS) && (err == ERR_OK); i++, td++) {
		if ((td->enable != 0) && (td->dip.s_addr != 0)) {
			/* lookup current source address for this dst */
			if (snmp_get_local_ip_for_dst(snmp_traps_handle, &td->dip,
						      &trap_msg->sip)) {
				snmp_prepare_necessary_msg_fields(trap_msg, eoid, generic_trap,
								  specific_trap, varbinds);

				/* pass 0, calculate length fields */
				tot_len = snmp_trap_varbind_sum(trap_msg, varbinds);
				tot_len = snmp_trap_header_sum(trap_msg, tot_len);

				/* encode and send */
				err = snmp_send_msg(trap_msg, varbinds, tot_len, &td->dip);
			} else {
				/* routing error */
				err = ERR_RTE;
			}
		}
	}
	/* The two special varbinds live on this stack frame, so the caller's
	 * list must not keep pointing at them. Restore only what was replaced;
	 * an unconditional restore cleared the caller's prev pointer when the
	 * snmpTrapOID could not be prepared.
	 */
	if (prev_replaced) {
		original_varbinds->prev = original_prev;
	}
	req_id++;
	return err;
}

/**
 * @ingroup snmp_traps
 * This function is a wrapper function for preparing and sending generic or specific traps.
 *
 * @param oid points to enterprise object identifier
 * @param generic_trap is the trap code
 * @param specific_trap used for enterprise traps when generic_trap == 6
 * @param varbinds linked list of varbinds to be sent
 * @return ERR_OK when success, ERR_MEM if we're out of memory
 *
 * @note the use of the enterprise identifier field
 * is per RFC1215.
 * Use .iso.org.dod.internet.mgmt.mib-2.snmp for generic traps
 * and .iso.org.dod.internet.private.enterprises.yourenterprise
 * (sysObjectID) for specific traps.
 */
int snmp_send_trap(const struct snmp_obj_id *oid, int32_t generic_trap, int32_t specific_trap,
		   struct snmp_varbind *varbinds)
{
	struct snmp_msg_trap trap_msg = {0};
	int err;

	snmp_agent_lock();
	trap_msg.snmp_version = snmp_default_trap_version;
	trap_msg.trap_or_inform = SNMP_IS_TRAP;
	err = snmp_send_trap_or_notification_or_inform_generic(&trap_msg, oid, generic_trap,
							       specific_trap, varbinds);
	snmp_agent_unlock();

	return err;
}

/**
 * @ingroup snmp_traps
 * Send generic SNMP trap
 * @param generic_trap is the trap code
 * return ERR_OK when success
 */
int snmp_send_trap_generic(int32_t generic_trap)
{
	int err = ERR_OK;
	struct snmp_msg_trap trap_msg = {0};

	snmp_agent_lock();
	trap_msg.snmp_version = snmp_default_trap_version;
	trap_msg.trap_or_inform = SNMP_IS_TRAP;

	if (snmp_default_trap_version == SNMP_VERSION_1) {
		static const struct snmp_obj_id oid = {7, {1, 3, 6, 1, 2, 1, 11}};
		err = snmp_send_trap_or_notification_or_inform_generic(&trap_msg, &oid,
								       generic_trap, 0, NULL);
	} else if (snmp_default_trap_version == SNMP_VERSION_2c) {
		err = snmp_send_trap_or_notification_or_inform_generic(&trap_msg, NULL,
								       generic_trap, 0, NULL);
	} else {
		err = ERR_VAL;
	}
	snmp_agent_unlock();

	return err;
}

/**
 * @ingroup snmp_traps
 * Send specific SNMP trap with variable bindings
 * @param specific_trap used for enterprise traps (generic_trap = 6)
 * @param varbinds linked list of varbinds to be sent
 * @return ERR_OK when success
 */
int snmp_send_trap_specific(int32_t specific_trap, struct snmp_varbind *varbinds)
{
	struct snmp_msg_trap trap_msg = {0};
	int err;

	snmp_agent_lock();
	trap_msg.snmp_version = snmp_default_trap_version;
	trap_msg.trap_or_inform = SNMP_IS_TRAP;
	err = snmp_send_trap_or_notification_or_inform_generic(
		&trap_msg, NULL, SNMP_GENTRAP_ENTERPRISE_SPECIFIC, specific_trap, varbinds);
	snmp_agent_unlock();

	return err;
}

/**
 * @ingroup snmp_traps
 * Send coldstart trap
 * @retval void
 */
void snmp_coldstart_trap(void)
{
	snmp_send_trap_generic(SNMP_GENTRAP_COLDSTART);
}

/**
 * @ingroup snmp_traps
 * Send authentication failure trap (used internally by agent)
 * @retval void
 */
void snmp_authfail_trap(void)
{
	snmp_agent_lock();
	if (snmp_auth_traps_enabled != 0) {
		snmp_send_trap_generic(SNMP_GENTRAP_AUTH_FAILURE);
	}
	snmp_agent_unlock();
}

/**
 * @ingroup snmp_traps
 * Sums trap varbinds
 *
 * @param trap Trap message
 * @param varbinds linked list of varbinds
 * @return the required length for encoding of this part of the trap header
 */
static uint16_t snmp_trap_varbind_sum(struct snmp_msg_trap *trap, struct snmp_varbind *varbinds)
{
	struct snmp_varbind *varbind;
	uint16_t tot_len;
	uint8_t tot_len_len;

	tot_len = 0;
	varbind = varbinds;
	while (varbind != NULL) {
		struct snmp_varbind_len len;

		if (snmp_varbind_length(varbind, &len) == ERR_OK) {
			tot_len += 1 + len.vb_len_len + len.vb_value_len;
		}

		varbind = varbind->next;
	}

	trap->vbseqlen = tot_len;
	snmp_asn1_enc_length_cnt(trap->vbseqlen, &tot_len_len);
	tot_len += 1 + tot_len_len;

	return tot_len;
}

/**
 * @ingroup snmp_traps
 * Sums trap header fields that are specific for SNMP v1
 *
 * @param trap Trap message
 * @return the required length for encoding of this part of the trap header
 */
static uint16_t snmp_trap_header_sum_v1_specific(struct snmp_msg_trap *trap)
{
	uint16_t tot_len = 0;
	uint16_t len = 0;
	uint8_t lenlen = 0;

	snmp_asn1_enc_u32t_cnt(trap->ts, &len);
	snmp_asn1_enc_length_cnt(len, &lenlen);
	tot_len += 1 + len + lenlen;

	snmp_asn1_enc_s32t_cnt(trap->spc_trap, &len);
	snmp_asn1_enc_length_cnt(len, &lenlen);
	tot_len += 1 + len + lenlen;

	snmp_asn1_enc_s32t_cnt(trap->gen_trap, &len);
	snmp_asn1_enc_length_cnt(len, &lenlen);
	tot_len += 1 + len + lenlen;

	len = sizeof(trap->sip.s_addr);
	snmp_asn1_enc_length_cnt(len, &lenlen);
	tot_len += 1 + len + lenlen;

	snmp_asn1_enc_oid_cnt(trap->enterprise->id, trap->enterprise->len, &len);
	snmp_asn1_enc_length_cnt(len, &lenlen);
	tot_len += 1 + len + lenlen;

	return tot_len;
}

/**
 * @ingroup snmp_traps
 * Sums trap header fields that are specific for SNMP v2c
 *
 * @param trap Trap message
 * @return the required length for encoding of this part of the trap header
 */
static uint16_t snmp_trap_header_sum_v2c_specific(struct snmp_msg_trap *trap)
{
	uint16_t tot_len = 0;
	uint16_t len = 0;
	uint8_t lenlen = 0;

	snmp_asn1_enc_u32t_cnt(req_id, &len);
	snmp_asn1_enc_length_cnt(len, &lenlen);
	tot_len += 1 + len + lenlen;
	snmp_asn1_enc_u32t_cnt(trap->error_status, &len);
	snmp_asn1_enc_length_cnt(len, &lenlen);
	tot_len += 1 + len + lenlen;
	snmp_asn1_enc_u32t_cnt(trap->error_index, &len);
	snmp_asn1_enc_length_cnt(len, &lenlen);
	tot_len += 1 + len + lenlen;

	return tot_len;
}

/**
 * @ingroup snmp_traps
 * Sums trap header field lengths from tail to head and
 * returns trap_header_lengths for second encoding pass.
 *
 * @param trap Trap message
 * @param vb_len varbind-list length
 * @return the required length for encoding the trap header
 */
static uint16_t snmp_trap_header_sum(struct snmp_msg_trap *trap, uint16_t vb_len)
{
	uint16_t tot_len = vb_len;
	uint16_t len = 0;
	uint8_t lenlen = 0;

	if (trap->snmp_version == SNMP_VERSION_1) {
		tot_len += snmp_trap_header_sum_v1_specific(trap);
	} else if (trap->snmp_version == SNMP_VERSION_2c) {
		tot_len += snmp_trap_header_sum_v2c_specific(trap);
	}
	trap->pdulen = tot_len;
	snmp_asn1_enc_length_cnt(trap->pdulen, &lenlen);
	tot_len += 1 + lenlen;

	trap->comlen = (uint16_t)LWIP_MIN(strlen(snmp_community_trap), 0xFFFF);
	snmp_asn1_enc_length_cnt(trap->comlen, &lenlen);
	tot_len += 1 + lenlen + trap->comlen;

	snmp_asn1_enc_s32t_cnt(trap->snmp_version, &len);
	snmp_asn1_enc_length_cnt(len, &lenlen);
	tot_len += 1 + len + lenlen;

	trap->seqlen = tot_len;
	snmp_asn1_enc_length_cnt(trap->seqlen, &lenlen);
	tot_len += 1 + lenlen;

	return tot_len;
}

/**
 * @ingroup snmp_traps
 * Encodes varbinds.
 * @param trap Trap message
 * @param pbuf_stream stream used for storing data inside pbuf
 * @param varbinds linked list of varbinds
 * @retval int ERR_OK if successful, ERR_ARG otherwise
 */
static int snmp_trap_varbind_enc(struct snmp_msg_trap *trap, struct snmp_pbuf_stream *pbuf_stream,
				 struct snmp_varbind *varbinds)
{
	struct snmp_asn1_tlv tlv;
	struct snmp_varbind *varbind;

	varbind = varbinds;

	SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_SEQUENCE, 0, trap->vbseqlen);
	BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));

	while (varbind != NULL) {
		BUILD_EXEC(snmp_append_outbound_varbind(pbuf_stream, varbind));

		varbind = varbind->next;
	}

	return ERR_OK;
}

/**
 * @ingroup snmp_traps
 * Encodes trap header PDU part.
 * @param trap Trap message
 * @param pbuf_stream stream used for storing data inside pbuf
 * @retval int ERR_OK if successful, ERR_ARG otherwise
 */
static int snmp_trap_header_enc_pdu(struct snmp_msg_trap *trap,
				    struct snmp_pbuf_stream *pbuf_stream)
{
	struct snmp_asn1_tlv tlv;
	/* 'PDU' sequence */
	if (trap->snmp_version == SNMP_VERSION_1) {
		/* TRAP V1 */
		SNMP_ASN1_SET_TLV_PARAMS(tlv,
					 (SNMP_ASN1_CLASS_CONTEXT |
					  SNMP_ASN1_CONTENTTYPE_CONSTRUCTED |
					  SNMP_ASN1_CONTEXT_PDU_TRAP),
					 0, trap->pdulen);
		BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
	} else if ((trap->snmp_version == SNMP_VERSION_2c) &&
		   (trap->trap_or_inform == SNMP_IS_INFORM)) {
		/* TRAP v2 - INFORM */
		SNMP_ASN1_SET_TLV_PARAMS(tlv,
					 (SNMP_ASN1_CLASS_CONTEXT |
					  SNMP_ASN1_CONTENTTYPE_CONSTRUCTED |
					  SNMP_ASN1_CONTEXT_PDU_INFORM_REQ),
					 0, trap->pdulen);
		BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
	} else if (trap->snmp_version == SNMP_VERSION_2c) {
		/* TRAP v2 - NOTIFICATION*/
		SNMP_ASN1_SET_TLV_PARAMS(tlv,
					 (SNMP_ASN1_CLASS_CONTEXT |
					  SNMP_ASN1_CONTENTTYPE_CONSTRUCTED |
					  SNMP_ASN1_CONTEXT_PDU_V2_TRAP),
					 0, trap->pdulen);
		BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
	}

	return ERR_OK;
}

/**
 * @ingroup snmp_traps
 * Encodes trap header part that is SNMP v1 header specific.
 * @param trap Trap message
 * @param pbuf_stream stream used for storing data inside pbuf
 * @retval void
 */
static int snmp_trap_header_enc_v1_specific(struct snmp_msg_trap *trap,
					    struct snmp_pbuf_stream *pbuf_stream)
{
	struct snmp_asn1_tlv tlv;
	/* object ID */
	SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OBJECT_ID, 0, 0);
	snmp_asn1_enc_oid_cnt(trap->enterprise->id, trap->enterprise->len, &tlv.value_len);
	BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
	BUILD_EXEC(snmp_asn1_enc_oid(pbuf_stream, trap->enterprise->id, trap->enterprise->len));

	/* IP addr */
	SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_IPADDR, 0, sizeof(trap->sip.s_addr));
	BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
	BUILD_EXEC(snmp_asn1_enc_raw(pbuf_stream, (const uint8_t *)&trap->sip.s_addr,
				     sizeof(trap->sip.s_addr)));

	/* generic trap */
	SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
	snmp_asn1_enc_s32t_cnt(trap->gen_trap, &tlv.value_len);
	BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
	BUILD_EXEC(snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, trap->gen_trap));

	/* specific trap */
	SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
	snmp_asn1_enc_s32t_cnt(trap->spc_trap, &tlv.value_len);
	BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
	BUILD_EXEC(snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, trap->spc_trap));

	/* timestamp */
	SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_TIMETICKS, 0, 0);
	snmp_asn1_enc_s32t_cnt(trap->ts, &tlv.value_len);
	BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
	BUILD_EXEC(snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, trap->ts));

	return ERR_OK;
}

/**
 * @ingroup snmp_traps
 * Encodes trap header part that is SNMP v2c header specific.
 *
 * @param trap Trap message
 * @param pbuf_stream stream used for storing data inside pbuf
 * @retval void
 */
static int snmp_trap_header_enc_v2c_specific(struct snmp_msg_trap *trap,
					     struct snmp_pbuf_stream *pbuf_stream)
{
	struct snmp_asn1_tlv tlv;
	/* request id */
	SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
	snmp_asn1_enc_s32t_cnt(req_id, &tlv.value_len);
	BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
	BUILD_EXEC(snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, req_id));

	/* error status */
	SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
	snmp_asn1_enc_s32t_cnt(trap->error_status, &tlv.value_len);
	BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
	BUILD_EXEC(snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, trap->error_status));

	/* error index */
	SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
	snmp_asn1_enc_s32t_cnt(trap->error_index, &tlv.value_len);
	BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
	BUILD_EXEC(snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, trap->error_index));

	return ERR_OK;
}

/**
 * @ingroup snmp_traps
 * Encodes trap header from head to tail.
 *
 * @param trap Trap message
 * @param pbuf_stream stream used for storing data inside pbuf
 * @retval void
 */
static int snmp_trap_header_enc(struct snmp_msg_trap *trap, struct snmp_pbuf_stream *pbuf_stream)
{
	struct snmp_asn1_tlv tlv;

	/* 'Message' sequence */
	SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_SEQUENCE, 0, trap->seqlen);
	BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));

	/* version */
	SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_INTEGER, 0, 0);
	snmp_asn1_enc_s32t_cnt(trap->snmp_version, &tlv.value_len);
	BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
	BUILD_EXEC(snmp_asn1_enc_s32t(pbuf_stream, tlv.value_len, trap->snmp_version));

	/* community */
	SNMP_ASN1_SET_TLV_PARAMS(tlv, SNMP_ASN1_TYPE_OCTET_STRING, 0, trap->comlen);
	BUILD_EXEC(snmp_ans1_enc_tlv(pbuf_stream, &tlv));
	BUILD_EXEC(
		snmp_asn1_enc_raw(pbuf_stream, (const uint8_t *)snmp_community_trap, trap->comlen));

	/* PDU */
	BUILD_EXEC(snmp_trap_header_enc_pdu(trap, pbuf_stream));
	if (trap->snmp_version == SNMP_VERSION_1) {
		/* object ID, IP addr, generic trap, specific trap, timestamp */
		BUILD_EXEC(snmp_trap_header_enc_v1_specific(trap, pbuf_stream));
	} else if (SNMP_VERSION_2c == trap->snmp_version) {
		/* request id, error status, error index */
		BUILD_EXEC(snmp_trap_header_enc_v2c_specific(trap, pbuf_stream));
	}

	return ERR_OK;
}

/**
 * @ingroup snmp_traps
 * Wrapper function for sending informs
 * @param specific_trap will be appended to enterprise oid [see RFC 3584]
 * @param varbinds linked list of varbinds (at the beginning of this list function will insert 2
 * special purpose varbinds [see RFC 3584])
 * @param ptr_request_id [out] variable in which to store request_id needed to verify
 * acknowledgement
 * @return ERR_OK if successful
 */
int snmp_send_inform_specific(int32_t specific_trap, struct snmp_varbind *varbinds,
			      int32_t *ptr_request_id)
{
	return snmp_send_inform(NULL, SNMP_GENTRAP_ENTERPRISE_SPECIFIC, specific_trap, varbinds,
				ptr_request_id);
}

/**
 * @ingroup snmp_traps
 * Wrapper function for sending informs
 * @param generic_trap is the trap code
 * @param varbinds linked list of varbinds (at the beginning of this list function will insert 2
 * special purpose varbinds [see RFC 3584])
 * @param ptr_request_id [out] variable in which to store request_id needed to verify
 * acknowledgement
 * @return ERR_OK if successful
 */
int snmp_send_inform_generic(int32_t generic_trap, struct snmp_varbind *varbinds,
			     int32_t *ptr_request_id)
{
	return snmp_send_inform(NULL, generic_trap, 0, varbinds, ptr_request_id);
}

/**
 * @ingroup snmp_traps
 * Generic function for sending informs
 * @param oid points to object identifier
 * @param generic_trap is the trap code
 * @param specific_trap used for enterprise traps when generic_trap == 6
 * @param varbinds linked list of varbinds (at the beginning of this list function will insert 2
 * special purpose varbinds [see RFC 3584])
 * @param ptr_request_id [out] variable in which to store request_id needed to verify
 * acknowledgement
 * @return ERR_OK if successful
 */
int snmp_send_inform(const struct snmp_obj_id *oid, int32_t generic_trap, int32_t specific_trap,
		     struct snmp_varbind *varbinds, int32_t *ptr_request_id)
{
	struct snmp_msg_trap trap_msg = {0};
	int err;

	snmp_agent_lock();
	trap_msg.snmp_version = SNMP_VERSION_2c;
	trap_msg.trap_or_inform = SNMP_IS_INFORM;
	*ptr_request_id = req_id;
	err = snmp_send_trap_or_notification_or_inform_generic(&trap_msg, oid, generic_trap,
							       specific_trap, varbinds);
	snmp_agent_unlock();

	return err;
}

#endif /* LWIP_SNMP */
