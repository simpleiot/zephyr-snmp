/**
 * @file
 * SNMP Agent message handling structures (internal API, do not use in client code).
 */

/*
 * Copyright (c) 2006 Axon Digital Design B.V., The Netherlands.
 * Copyright (c) 2016 Elias Oenal.
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
 *         Elias Oenal <lwip@eliasoenal.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef LWIP_HDR_APPS_SNMP_MSG_H
#define LWIP_HDR_APPS_SNMP_MSG_H

#include <snmp/snmp_opts.h>
#include "snmp_priv.h"

#if LWIP_SNMP

#include <snmp/snmp.h>
#include <snmp/snmp_core.h>
#include "snmp_pbuf_stream.h"

#ifdef __cplusplus
extern "C" {
#endif

/* version defines used in PDU */
#define SNMP_VERSION_1  0
#define SNMP_VERSION_2c 1
#define SNMP_VERSION_3  3

struct snmp_varbind_enumerator {
	struct snmp_pbuf_stream pbuf_stream;
	uint16_t varbind_count;
};

typedef enum {
	SNMP_VB_ENUMERATOR_ERR_OK = 0,
	SNMP_VB_ENUMERATOR_ERR_EOVB = 1,
	SNMP_VB_ENUMERATOR_ERR_ASN1ERROR = 2,
	SNMP_VB_ENUMERATOR_ERR_INVALIDLENGTH = 3
} snmp_vb_enumerator_err_t;

void snmp_vb_enumerator_init(struct snmp_varbind_enumerator *enumerator, uint8_t *data,
			     uint16_t offset, uint16_t length);
snmp_vb_enumerator_err_t snmp_vb_enumerator_get_next(struct snmp_varbind_enumerator *enumerator,
						     struct snmp_varbind *varbind);

#define SNMP_MAX_COMMUNITY_SIZE 12U

struct snmp_request {
	/* Communication handle */
	void *handle;
	/* source IP address */
	const struct net_in_addr *source_ip;
	/* source UDP port */
	uint16_t source_port;
	/* incoming snmp version */
	uint8_t version;
	/* community name (zero terminated) */
	uint8_t community[SNMP_MAX_COMMUNITY_SIZE + 1];
	/* community string length (exclusive zero term) */
	uint16_t community_strlen;
	/* request type */
	uint8_t request_type;
	/* request ID */
	int32_t request_id;
	/* error status */
	int32_t error_status;
	/* error index */
	int32_t error_index;
	/* non-repeaters (getBulkRequest (SNMPv2c)) */
	int32_t non_repeaters;
	/* max-repetitions (getBulkRequest (SNMPv2c)) */
	int32_t max_repetitions;

	/* Usually response-pdu (2). When snmpv3 errors are detected report-pdu(8) */
	uint8_t request_out_type;

	uint8_t *inbound_buf;
	uint16_t inbound_len;
	struct snmp_varbind_enumerator inbound_varbind_enumerator;
	uint16_t inbound_varbind_offset;
	uint16_t inbound_varbind_len;
	uint16_t inbound_padding_len;

	uint8_t *outbound_buf;
	uint16_t outbound_buf_size;
	/** Set once the frame is complete; the number of bytes to send. */
	uint16_t outbound_len;
	struct snmp_pbuf_stream outbound_pbuf_stream;
	uint16_t outbound_pdu_offset;
	uint16_t outbound_error_status_offset;
	uint16_t outbound_error_index_offset;
	uint16_t outbound_varbind_offset;

// uint8_t value_buffer[SNMP_MAX_VALUE_SIZE];
#define SNMP_VALUE_BUFFER_SIZE 64

	uint8_t value_buffer[SNMP_VALUE_BUFFER_SIZE];
};

/** A helper struct keeping length information about varbinds */
struct snmp_varbind_len {
	uint8_t vb_len_len;
	uint16_t vb_value_len;
	uint8_t oid_len_len;
	uint16_t oid_value_len;
	uint8_t value_len_len;
	uint16_t value_value_len;
};

/** Agent community string */
extern const char *snmp_community;
/** Agent community string for write access */
extern const char *snmp_community_write;
/** handle for sending traps */
extern void *snmp_traps_handle;

void snmp_receive(void *handle, uint8_t *data, uint16_t len, const struct net_in_addr *source_ip,
		  uint16_t port);
int snmp_sendto(void *handle, const uint8_t *data, uint16_t len, const struct net_in_addr *dst,
		uint16_t port);
uint8_t snmp_get_local_ip_for_dst(void *handle, const struct net_in_addr *dst,
				  struct net_in_addr *result);
int snmp_varbind_length(struct snmp_varbind *varbind, struct snmp_varbind_len *len);
int snmp_append_outbound_varbind(struct snmp_pbuf_stream *pbuf_stream,
				 struct snmp_varbind *varbind);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_SNMP */

#endif /* LWIP_HDR_APPS_SNMP_MSG_H */
