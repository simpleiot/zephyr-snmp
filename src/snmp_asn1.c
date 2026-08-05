/**
 * @file
 * Abstract Syntax Notation One (ISO 8824, 8825) encoding
 *
 * @todo not optimised (yet), favor correctness over speed, favor speed over size
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
 */

#include <snmp/snmp_opts.h>
#include "snmp_priv.h"

#if LWIP_SNMP /* don't build if not configured for use in lwipopts.h */

#include "snmp_asn1.h"

#define PBUF_OP_EXEC(code)                                                                         \
	if ((code) != ERR_OK) {                                                                    \
		return ERR_BUF;                                                                    \
	}

/**
 * Encodes a TLV into a pbuf stream.
 *
 * @param pbuf_stream points to a pbuf stream
 * @param tlv TLV to encode
 * @return ERR_OK if successful, ERR_ARG if we can't (or won't) encode
 */
int snmp_ans1_enc_tlv(struct snmp_pbuf_stream *pbuf_stream, struct snmp_asn1_tlv *tlv)
{
	uint8_t data;
	uint8_t length_bytes_required;

	/* write type */
	if ((tlv->type & SNMP_ASN1_DATATYPE_MASK) == SNMP_ASN1_DATATYPE_EXTENDED) {
		/* extended format is not used by SNMP so we do not accept those values */
		return ERR_ARG;
	}
	if (tlv->type_len != 0) {
		/* any other value as auto is not accepted for type (we always use one byte because
		 * extended syntax is prohibited) */
		return ERR_ARG;
	}

	PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream, tlv->type));
	tlv->type_len = 1;

	/* write length */
	if (tlv->value_len <= 127) {
		length_bytes_required = 1;
	} else if (tlv->value_len <= 255) {
		length_bytes_required = 2;
	} else {
		length_bytes_required = 3;
	}

	/* check for forced min length */
	if (tlv->length_len > 0) {
		if (tlv->length_len < length_bytes_required) {
			/* unable to code requested length in requested number of bytes */
			return ERR_ARG;
		}

		length_bytes_required = tlv->length_len;
	} else {
		tlv->length_len = length_bytes_required;
	}

	if (length_bytes_required > 1) {
		/* multi byte representation required */
		length_bytes_required--;
		data = 0x80 | length_bytes_required; /* extended length definition, 1 length byte
							follows */

		PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream, data));

		while (length_bytes_required > 1) {
			if (length_bytes_required == 2) {
				/* append high byte */
				data = (uint8_t)(tlv->value_len >> 8);
			} else {
				/* append leading 0x00 */
				data = 0x00;
			}

			PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream, data));
			length_bytes_required--;
		}
	}

	/* append low byte */
	data = (uint8_t)(tlv->value_len & 0xFF);
	PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream, data));

	return ERR_OK;
}

/**
 * Encodes raw data (octet string, opaque) into a pbuf chained ASN1 msg.
 *
 * @param pbuf_stream points to a pbuf stream
 * @param raw_len raw data length
 * @param raw points raw data
 * @return ERR_OK if successful, ERR_ARG if we can't (or won't) encode
 */
int snmp_asn1_enc_raw(struct snmp_pbuf_stream *pbuf_stream, const uint8_t *raw, uint16_t raw_len)
{
	PBUF_OP_EXEC(snmp_pbuf_stream_writebuf(pbuf_stream, raw, raw_len));

	return ERR_OK;
}

/**
 * Encodes uint32_t (counter, gauge, timeticks) into a pbuf chained ASN1 msg.
 *
 * @param pbuf_stream points to a pbuf stream
 * @param octets_needed encoding length (from snmp_asn1_enc_u32t_cnt())
 * @param value is the host order uint32_t value to be encoded
 * @return ERR_OK if successful, ERR_ARG if we can't (or won't) encode
 *
 * @see snmp_asn1_enc_u32t_cnt()
 */
int snmp_asn1_enc_u32t(struct snmp_pbuf_stream *pbuf_stream, uint16_t octets_needed, uint32_t value)
{
	if (octets_needed > 5) {
		return ERR_ARG;
	}
	if (octets_needed == 5) {
		/* not enough bits in 'value' add leading 0x00 */
		PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream, 0x00));
		octets_needed--;
	}

	while (octets_needed > 1) {
		octets_needed--;
		PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream,
						    (uint8_t)(value >> (octets_needed << 3))));
	}

	/* (only) one least significant octet */
	PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream, (uint8_t)value));

	return ERR_OK;
}
/**
 * Encodes int32_t integer into a pbuf chained ASN1 msg.
 *
 * @param pbuf_stream points to a pbuf stream
 * @param octets_needed encoding length (from snmp_asn1_enc_s32t_cnt())
 * @param value is the host order int32_t value to be encoded
 * @return ERR_OK if successful, ERR_ARG if we can't (or won't) encode
 *
 * @see snmp_asn1_enc_s32t_cnt()
 */
int snmp_asn1_enc_s32t(struct snmp_pbuf_stream *pbuf_stream, uint16_t octets_needed, int32_t value)
{
	while (octets_needed > 1) {
		octets_needed--;

		PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream,
						    (uint8_t)(value >> (octets_needed << 3))));
	}

	/* (only) one least significant octet */
	PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream, (uint8_t)value));

	return ERR_OK;
}

/**
 * Encodes object identifier into a pbuf chained ASN1 msg.
 *
 * @param pbuf_stream points to a pbuf stream
 * @param oid points to object identifier array
 * @param oid_len object identifier array length
 * @return ERR_OK if successful, ERR_ARG if we can't (or won't) encode
 */
int snmp_asn1_enc_oid(struct snmp_pbuf_stream *pbuf_stream, const uint32_t *oid, uint16_t oid_len)
{
	if (oid_len > 1) {
		/* write compressed first two sub id's */
		uint32_t compressed_byte = ((oid[0] * 40) + oid[1]);
		PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream, (uint8_t)compressed_byte));
		oid_len -= 2;
		oid += 2;
	} else {
		/* @bug:  allow empty varbinds for symmetry (we must decode them for getnext), allow
		 * partial compression?? */
		/* ident_len <= 1, at least we need zeroDotZero (0.0) (ident_len == 2) */
		return ERR_ARG;
	}

	while (oid_len > 0) {
		uint32_t sub_id;
		uint8_t shift, tail;

		oid_len--;
		sub_id = *oid;
		tail = 0;
		shift = 28;
		while (shift > 0) {
			uint8_t code;

			code = (uint8_t)(sub_id >> shift);
			if ((code != 0) || (tail != 0)) {
				tail = 1;
				PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream, code | 0x80));
			}
			shift -= 7;
		}
		PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream, (uint8_t)sub_id & 0x7F));

		/* proceed to next sub-identifier */
		oid++;
	}
	return ERR_OK;
}

/**
 * Returns octet count for length.
 *
 * @param length parameter length
 * @param octets_needed points to the return value
 */
void snmp_asn1_enc_length_cnt(uint16_t length, uint8_t *octets_needed)
{
	if (length < 0x80U) {
		*octets_needed = 1;
	} else if (length < 0x100U) {
		*octets_needed = 2;
	} else {
		*octets_needed = 3;
	}
}

/**
 * Returns octet count for an uint32_t.
 *
 * @param value value to be encoded
 * @param octets_needed points to the return value
 *
 * @note ASN coded integers are _always_ signed. E.g. +0xFFFF is coded
 * as 0x00,0xFF,0xFF. Note the leading sign octet. A positive value
 * of 0xFFFFFFFF is preceded with 0x00 and the length is 5 octets!!
 */
void snmp_asn1_enc_u32t_cnt(uint32_t value, uint16_t *octets_needed)
{
	if (value < 0x80UL) {
		*octets_needed = 1;
	} else if (value < 0x8000UL) {
		*octets_needed = 2;
	} else if (value < 0x800000UL) {
		*octets_needed = 3;
	} else if (value < 0x80000000UL) {
		*octets_needed = 4;
	} else {
		*octets_needed = 5;
	}
}

/**
 * Returns octet count for an int32_t.
 *
 * @param value value to be encoded
 * @param octets_needed points to the return value
 *
 * @note ASN coded integers are _always_ signed.
 */
void snmp_asn1_enc_s32t_cnt(int32_t value, uint16_t *octets_needed)
{
	if (value < 0) {
		value = ~value;
	}
	if (value < 0x80L) {
		*octets_needed = 1;
	} else if (value < 0x8000L) {
		*octets_needed = 2;
	} else if (value < 0x800000L) {
		*octets_needed = 3;
	} else {
		*octets_needed = 4;
	}
}

/**
 * Returns octet count for an object identifier.
 *
 * @param oid points to object identifier array
 * @param oid_len object identifier array length
 * @param octets_needed points to the return value
 */
void snmp_asn1_enc_oid_cnt(const uint32_t *oid, uint16_t oid_len, uint16_t *octets_needed)
{
	uint32_t sub_id;

	*octets_needed = 0;
	if (oid_len > 1) {
		/* compressed prefix in one octet */
		(*octets_needed)++;
		oid_len -= 2;
		oid += 2;
	}
	while (oid_len > 0) {
		oid_len--;
		sub_id = *oid;

		sub_id >>= 7;
		(*octets_needed)++;
		while (sub_id > 0) {
			sub_id >>= 7;
			(*octets_needed)++;
		}
		oid++;
	}
}

/**
 * Decodes a TLV from a pbuf stream.
 *
 * @param pbuf_stream points to a pbuf stream
 * @param tlv returns decoded TLV
 * @return ERR_OK if successful, ERR_VAL if we can't decode
 */
int snmp_asn1_dec_tlv(struct snmp_pbuf_stream *pbuf_stream, struct snmp_asn1_tlv *tlv)
{
	uint8_t data;

	/* decode type first */
	PBUF_OP_EXEC(snmp_pbuf_stream_read(pbuf_stream, &data));
	tlv->type = data;

	if ((tlv->type & SNMP_ASN1_DATATYPE_MASK) == SNMP_ASN1_DATATYPE_EXTENDED) {
		/* extended format is not used by SNMP so we do not accept those values */
		return ERR_VAL;
	}
	tlv->type_len = 1;

	/* now, decode length */
	PBUF_OP_EXEC(snmp_pbuf_stream_read(pbuf_stream, &data));

	if (data < 0x80) { /* short form */
		tlv->length_len = 1;
		tlv->value_len = data;
	} else if (data > 0x80) { /* long form */
		uint8_t length_bytes = data - 0x80;
		if (length_bytes > pbuf_stream->length) {
			return ERR_VAL;
		}
		tlv->length_len =
			length_bytes + 1; /* this byte + defined number of length bytes following */
		tlv->value_len = 0;

		while (length_bytes > 0) {
			/* we only support up to u16.maxvalue-1 (2 bytes) but have to accept leading
			 * zero bytes */
			if (tlv->value_len > 0xFF) {
				return ERR_VAL;
			}
			PBUF_OP_EXEC(snmp_pbuf_stream_read(pbuf_stream, &data));
			tlv->value_len <<= 8;
			tlv->value_len |= data;

			/* take care for special value used for indefinite length */
			if (tlv->value_len == 0xFFFF) {
				return ERR_VAL;
			}

			length_bytes--;
		}
	} else { /* data == 0x80 indefinite length form */
		/* (not allowed for SNMP; RFC 1157, 3.2.2) */
		return ERR_VAL;
	}

	return ERR_OK;
}

/**
 * Decodes positive integer (counter, gauge, timeticks) into uint32_t.
 *
 * @param pbuf_stream points to a pbuf stream
 * @param len length of the coded integer field
 * @param value return host order integer
 * @return ERR_OK if successful, ERR_ARG if we can't (or won't) decode
 *
 * @note ASN coded integers are _always_ signed. E.g. +0xFFFF is coded
 * as 0x00,0xFF,0xFF. Note the leading sign octet. A positive value
 * of 0xFFFFFFFF is preceded with 0x00 and the length is 5 octets!!
 */
int snmp_asn1_dec_u32t(struct snmp_pbuf_stream *pbuf_stream, uint16_t len, uint32_t *value)
{
	uint8_t data;

	if ((len > 0) && (len <= 5)) {
		PBUF_OP_EXEC(snmp_pbuf_stream_read(pbuf_stream, &data));

		/* expecting sign bit to be zero, only unsigned please! */
		if (((len == 5) && (data == 0x00)) || ((len < 5) && ((data & 0x80) == 0))) {
			*value = data;
			len--;

			while (len > 0) {
				PBUF_OP_EXEC(snmp_pbuf_stream_read(pbuf_stream, &data));
				len--;

				*value <<= 8;
				*value |= data;
			}

			return ERR_OK;
		}
	}

	return ERR_VAL;
}

/**
 * Decodes integer into int32_t.
 *
 * @param pbuf_stream points to a pbuf stream
 * @param len length of the coded integer field
 * @param value return host order integer
 * @return ERR_OK if successful, ERR_ARG if we can't (or won't) decode
 *
 * @note ASN coded integers are _always_ signed!
 */
int snmp_asn1_dec_s32t(struct snmp_pbuf_stream *pbuf_stream, uint16_t len, int32_t *value)
{
	uint8_t data;

	if ((len > 0) && (len < 5)) {
		PBUF_OP_EXEC(snmp_pbuf_stream_read(pbuf_stream, &data));

		if (data & 0x80) {
			/* negative, start from -1 */
			*value = -1;
			*value = (*value << 8) | data;
		} else {
			/* positive, start from 0 */
			*value = data;
		}
		len--;
		/* shift in the remaining value */
		while (len > 0) {
			PBUF_OP_EXEC(snmp_pbuf_stream_read(pbuf_stream, &data));
			*value = (*value << 8) | data;
			len--;
		}
		return ERR_OK;
	}

	return ERR_VAL;
}

/**
 * Decodes object identifier from incoming message into array of uint32_t.
 *
 * @param pbuf_stream points to a pbuf stream
 * @param len length of the coded object identifier
 * @param oid return decoded object identifier
 * @param oid_len return decoded object identifier length
 * @param oid_max_len size of oid buffer
 * @return ERR_OK if successful, ERR_ARG if we can't (or won't) decode
 */
int snmp_asn1_dec_oid(struct snmp_pbuf_stream *pbuf_stream, uint16_t len, uint32_t *oid,
		      uint8_t *oid_len, uint8_t oid_max_len)
{
	uint32_t *oid_ptr;
	uint8_t data;

	*oid_len = 0;
	oid_ptr = oid;
	if (len > 0) {
		if (oid_max_len < 2) {
			return ERR_MEM;
		}

		PBUF_OP_EXEC(snmp_pbuf_stream_read(pbuf_stream, &data));
		len--;

		/* first compressed octet */
		if (data == 0x2B) {
			/* (most) common case 1.3 (iso.org) */
			*oid_ptr = 1;
			oid_ptr++;
			*oid_ptr = 3;
			oid_ptr++;
		} else if (data < 40) {
			*oid_ptr = 0;
			oid_ptr++;
			*oid_ptr = data;
			oid_ptr++;
		} else if (data < 80) {
			*oid_ptr = 1;
			oid_ptr++;
			*oid_ptr = data - 40;
			oid_ptr++;
		} else {
			*oid_ptr = 2;
			oid_ptr++;
			*oid_ptr = data - 80;
			oid_ptr++;
		}
		*oid_len = 2;
	} else {
		/* accepting zero length identifiers e.g. for getnext operation. uncommon but valid
		 */
		return ERR_OK;
	}

	while ((len > 0) && (*oid_len < oid_max_len)) {
		PBUF_OP_EXEC(snmp_pbuf_stream_read(pbuf_stream, &data));
		len--;

		if ((data & 0x80) == 0x00) {
			/* sub-identifier uses single octet */
			*oid_ptr = data;
		} else {
			/* sub-identifier uses multiple octets */
			uint32_t sub_id = (data & ~0x80);
			while ((len > 0) && ((data & 0x80) != 0)) {
				PBUF_OP_EXEC(snmp_pbuf_stream_read(pbuf_stream, &data));
				len--;

				sub_id = (sub_id << 7) + (data & ~0x80);
			}

			if ((data & 0x80) != 0) {
				/* "more bytes following" bit still set at end of len */
				return ERR_VAL;
			}
			*oid_ptr = sub_id;
		}
		oid_ptr++;
		(*oid_len)++;
	}

	if (len > 0) {
		/* OID to long to fit in our buffer */
		return ERR_MEM;
	}

	return ERR_OK;
}

/**
 * Decodes (copies) raw data (ip-addresses, octet strings, opaque encoding)
 * from incoming message into array.
 *
 * @param pbuf_stream points to a pbuf stream
 * @param len length of the coded raw data (zero is valid, e.g. empty string!)
 * @param buf return raw bytes
 * @param buf_len returns length of the raw return value
 * @param buf_max_len buffer size
 * @return ERR_OK if successful, ERR_ARG if we can't (or won't) decode
 */
int snmp_asn1_dec_raw(struct snmp_pbuf_stream *pbuf_stream, uint16_t len, uint8_t *buf,
		      uint16_t *buf_len, uint16_t buf_max_len)
{
	if (len > buf_max_len) {
		/* not enough dst space */
		return ERR_MEM;
	}
	*buf_len = len;

	while (len > 0) {
		PBUF_OP_EXEC(snmp_pbuf_stream_read(pbuf_stream, buf));
		buf++;
		len--;
	}

	return ERR_OK;
}

#if LWIP_HAVE_INT64
/**
 * Returns octet count for an uint64_t.
 *
 * @param value value to be encoded
 * @param octets_needed points to the return value
 *
 * @note ASN coded integers are _always_ signed. E.g. +0xFFFF is coded
 * as 0x00,0xFF,0xFF. Note the leading sign octet. A positive value
 * of 0xFFFFFFFFFFFFFFFF is preceded with 0x00 and the length is 9 octets!!
 */
void snmp_asn1_enc_u64t_cnt(uint64_t value, uint16_t *octets_needed)
{
	/* check if high u32 is 0 */
	if ((value >> 32) == 0) {
		/* only low u32 is important */
		snmp_asn1_enc_u32t_cnt((uint32_t)value, octets_needed);
	} else {
		/* low u32 does not matter for length determination */
		snmp_asn1_enc_u32t_cnt((uint32_t)(value >> 32), octets_needed);
		*octets_needed = *octets_needed + 4; /* add the 4 bytes of low u32 */
	}
}

/**
 * Decodes large positive integer (counter64) into 2x uint32_t.
 *
 * @param pbuf_stream points to a pbuf stream
 * @param len length of the coded integer field
 * @param value return 64 bit integer
 * @return ERR_OK if successful, ERR_ARG if we can't (or won't) decode
 *
 * @note ASN coded integers are _always_ signed. E.g. +0xFFFF is coded
 * as 0x00,0xFF,0xFF. Note the leading sign octet. A positive value
 * of 0xFFFFFFFFFFFFFFFF is preceded with 0x00 and the length is 9 octets!!
 */
int snmp_asn1_dec_u64t(struct snmp_pbuf_stream *pbuf_stream, uint16_t len, uint64_t *value)
{
	uint8_t data;

	if ((len > 0) && (len <= 9)) {
		PBUF_OP_EXEC(snmp_pbuf_stream_read(pbuf_stream, &data));

		/* expecting sign bit to be zero, only unsigned please! */
		if (((len == 9) && (data == 0x00)) || ((len < 9) && ((data & 0x80) == 0))) {
			*value = data;
			len--;

			while (len > 0) {
				PBUF_OP_EXEC(snmp_pbuf_stream_read(pbuf_stream, &data));
				*value <<= 8;
				*value |= data;
				len--;
			}

			return ERR_OK;
		}
	}

	return ERR_VAL;
}

/**
 * Encodes uint64_t (counter64) into a pbuf chained ASN1 msg.
 *
 * @param pbuf_stream points to a pbuf stream
 * @param octets_needed encoding length (from snmp_asn1_enc_u32t_cnt())
 * @param value is the value to be encoded
 * @return ERR_OK if successful, ERR_ARG if we can't (or won't) encode
 *
 * @see snmp_asn1_enc_u64t_cnt()
 */
int snmp_asn1_enc_u64t(struct snmp_pbuf_stream *pbuf_stream, uint16_t octets_needed, uint64_t value)
{
	if (octets_needed > 9) {
		return ERR_ARG;
	}
	if (octets_needed == 9) {
		/* not enough bits in 'value' add leading 0x00 */
		PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream, 0x00));
		octets_needed--;
	}

	while (octets_needed > 1) {
		octets_needed--;
		PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream,
						    (uint8_t)(value >> (octets_needed << 3))));
	}

	/* always write at least one octet (also in case of value == 0) */
	PBUF_OP_EXEC(snmp_pbuf_stream_write(pbuf_stream, (uint8_t)(value)));

	return ERR_OK;
}
#endif

#endif /* LWIP_SNMP */
