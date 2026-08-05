/**
 * @file
 * SNMP pbuf stream wrapper implementation (internal API, do not use in client code).
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

#include <snmp/snmp_opts.h>
#include "snmp_priv.h"

#if LWIP_SNMP /* don't build if not configured for use in lwipopts.h */

#include "snmp_pbuf_stream.h"
#include <string.h>

int snmp_pbuf_stream_init(struct snmp_pbuf_stream *pbuf_stream, uint8_t *data, uint16_t offset,
			  uint16_t length)
{
	pbuf_stream->offset = offset;
	pbuf_stream->length = length;
	pbuf_stream->data = data;

	return ERR_OK;
}

int snmp_pbuf_stream_read(struct snmp_pbuf_stream *pbuf_stream, uint8_t *data)
{
	if (pbuf_stream->length == 0) {
		return ERR_BUF;
	}

	*data = pbuf_stream->data[pbuf_stream->offset];

	pbuf_stream->offset++;
	pbuf_stream->length--;

	return ERR_OK;
}

int snmp_pbuf_stream_write(struct snmp_pbuf_stream *pbuf_stream, uint8_t data)
{
	return snmp_pbuf_stream_writebuf(pbuf_stream, &data, 1);
}

int snmp_pbuf_stream_writebuf(struct snmp_pbuf_stream *pbuf_stream, const void *buf,
			      uint16_t buf_len)
{
	if (pbuf_stream->length < buf_len) {
		return ERR_BUF;
	}

	memcpy(&pbuf_stream->data[pbuf_stream->offset], buf, buf_len);

	pbuf_stream->offset += buf_len;
	pbuf_stream->length -= buf_len;

	return ERR_OK;
}

int snmp_pbuf_stream_writeto(struct snmp_pbuf_stream *pbuf_stream,
			     struct snmp_pbuf_stream *target_pbuf_stream, uint16_t len)
{
	if ((pbuf_stream == NULL) || (target_pbuf_stream == NULL)) {
		return ERR_ARG;
	}
	if ((len > pbuf_stream->length) || (len > target_pbuf_stream->length)) {
		return ERR_ARG;
	}

	if (len == 0) {
		len = LWIP_MIN(pbuf_stream->length, target_pbuf_stream->length);
	}

	{
		int err = snmp_pbuf_stream_writebuf(target_pbuf_stream,
						    &pbuf_stream->data[pbuf_stream->offset], len);
		if (err != ERR_OK) {
			return err;
		}
	}

	pbuf_stream->offset += len;
	pbuf_stream->length -= len;

	return ERR_OK;
}

int snmp_pbuf_stream_seek(struct snmp_pbuf_stream *pbuf_stream, int32_t offset)
{
	if (((pbuf_stream->offset + offset) < 0) || (offset > pbuf_stream->length)) {
		/* we cannot seek backwards or forward behind stream end */
		return ERR_ARG;
	}

	pbuf_stream->offset += (uint16_t)offset;
	pbuf_stream->length -= (uint16_t)offset;

	return ERR_OK;
}

int snmp_pbuf_stream_seek_abs(struct snmp_pbuf_stream *pbuf_stream, uint32_t offset)
{
	int32_t rel_offset = offset - pbuf_stream->offset;
	return snmp_pbuf_stream_seek(pbuf_stream, rel_offset);
}

#endif /* LWIP_SNMP */
