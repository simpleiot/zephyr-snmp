/**
 * @file
 * Zephyr frontend for the SNMP agent.
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
 * Author: Dirk Ziegelmeier <dziegel@gmx.de>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/socket_service.h>

#include <lwip/apps/snmp_opts.h>
#include <lwip/apps/snmp_zephyr.h>

#include "lwip/ip.h"
#include "lwip/sys.h"
#include "lwip/udp.h"
#include "snmp_lock.h"
#include "snmp_msg.h"

LOG_MODULE_REGISTER(net_snmp_agent, CONFIG_SNMP_AGENT_LOG_LEVEL);

/* The agent core keeps its state in file-scope variables and does no locking
 * of its own. Requests arrive on the socket service thread while applications
 * configure the agent and send traps from their own threads, so every path
 * into that state takes this mutex. Zephyr mutexes are recursive, which
 * matters because an entry point may hold it while the core calls back into
 * another one.
 */
static K_MUTEX_DEFINE(agent_lock);

/** The socket requests arrive on, and traps are sent from. */
static int agent_sock = -1;

/** Guarded by agent_lock, so one buffer serves every request. */
static uint8_t recv_buf[CONFIG_SNMP_AGENT_MAX_MSG_SIZE];

static struct zsock_pollfd agent_fds[1] = { { .fd = -1 } };

void snmp_agent_lock(void)
{
	k_mutex_lock(&agent_lock, K_FOREVER);
}

void snmp_agent_unlock(void)
{
	k_mutex_unlock(&agent_lock);
}

bool snmp_agent_lock_held(void)
{
	return agent_lock.owner == k_current_get();
}

/**
 * @brief Socket service callback, run on Zephyr's shared service thread.
 *
 * Requests are parsed and answered here rather than being queued for an
 * application thread. Handling is short and bounded, and doing it in place
 * removes the buffer hand-off that used to sit between the two.
 */
static void snmp_service_cb(struct net_socket_service_event *evt)
{
	struct net_sockaddr_in from;
	socklen_t fromlen = sizeof(from);
	int ret;

	if (evt->event.revents & ZSOCK_POLLERR) {
		LOG_ERR("socket poll error, stopping the agent");
		(void)net_snmp_agent_stop();
		return;
	}

	if (!(evt->event.revents & ZSOCK_POLLIN)) {
		return;
	}

	snmp_agent_lock();

	if (evt->event.fd != agent_sock) {
		/* The agent stopped between the poll and this callback. */
		goto unlock;
	}

	ret = zsock_recvfrom(evt->event.fd, recv_buf, sizeof(recv_buf),
			     ZSOCK_MSG_DONTWAIT,
			     (struct net_sockaddr *)&from, &fromlen);
	if (ret < 0) {
		if (errno != EAGAIN) {
			LOG_ERR("recvfrom failed, errno %d", errno);
		}
		goto unlock;
	}

	if (ret == 0) {
		goto unlock;
	}

	if (IS_ENABLED(CONFIG_NET_LOG)) {
		char addr[NET_INET_ADDRSTRLEN];

		LOG_DBG("%d bytes from %s:%u", ret,
			net_addr_ntop(NET_AF_INET, &from.sin_addr, addr, sizeof(addr)),
			net_ntohs(from.sin_port));
	}

	{
		ip_addr_t from_address;

		from_address.addr = from.sin_addr.s_addr;

		/* The socket is passed as an opaque handle because that is
		 * what the agent core hands back to snmp_sendto() when it
		 * wants to reply. */
		snmp_receive((void *)(intptr_t)evt->event.fd, recv_buf, (u16_t)ret,
			     &from_address, from.sin_port);
	}

unlock:
	snmp_agent_unlock();
}

NET_SOCKET_SERVICE_SYNC_DEFINE_STATIC(snmp_service, snmp_service_cb,
				      ARRAY_SIZE(agent_fds));

int net_snmp_agent_start(void)
{
	struct net_sockaddr_in bind_addr = {
		.sin_family = NET_AF_INET,
		.sin_addr = NET_INADDR_ANY_INIT,
		.sin_port = net_htons(CONFIG_SNMP_AGENT_PORT),
	};
	int sock;
	int ret;

	snmp_agent_lock();

	if (agent_sock >= 0) {
		ret = 0;
		goto unlock;
	}

	sock = zsock_socket(NET_AF_INET, NET_SOCK_DGRAM, NET_IPPROTO_UDP);
	if (sock < 0) {
		ret = -errno;
		LOG_ERR("cannot create the agent socket, %d", ret);
		goto unlock;
	}

	ret = zsock_bind(sock, (struct net_sockaddr *)&bind_addr, sizeof(bind_addr));
	if (ret < 0) {
		ret = -errno;
		LOG_ERR("cannot bind to port %d, %d", CONFIG_SNMP_AGENT_PORT, ret);
		(void)zsock_close(sock);
		goto unlock;
	}

	agent_fds[0].fd = sock;
	agent_fds[0].events = ZSOCK_POLLIN;

	ret = net_socket_service_register(&snmp_service, agent_fds,
					  ARRAY_SIZE(agent_fds), NULL);
	if (ret < 0) {
		LOG_ERR("cannot register the socket service, %d", ret);
		agent_fds[0].fd = -1;
		(void)zsock_close(sock);
		goto unlock;
	}

	agent_sock = sock;

	/* Traps leave from the same socket. Their destination is still the
	 * manager's port 162; only the source port is shared. */
	snmp_traps_handle = (void *)(intptr_t)sock;

	LOG_INF("SNMP agent listening on UDP port %d", CONFIG_SNMP_AGENT_PORT);
	ret = 0;

unlock:
	snmp_agent_unlock();

	return ret;
}

int net_snmp_agent_stop(void)
{
	int ret = 0;

	snmp_agent_lock();

	if (agent_sock < 0) {
		goto unlock;
	}

	/* Unregister before closing, so the service thread cannot poll a
	 * descriptor that has already been handed back. */
	ret = net_socket_service_unregister(&snmp_service);
	if (ret < 0) {
		LOG_ERR("cannot unregister the socket service, %d", ret);
		goto unlock;
	}

	(void)zsock_close(agent_sock);

	agent_sock = -1;
	agent_fds[0].fd = -1;
	snmp_traps_handle = (void *)(intptr_t)-1;

	LOG_INF("SNMP agent stopped");

unlock:
	snmp_agent_unlock();

	return ret;
}

int net_snmp_agent_trap_dst_set(const char *ip_address)
{
	struct net_in_addr addr;
	ip_addr_t dst;
	int ret;

	if (ip_address == NULL) {
		return -EINVAL;
	}

	ret = net_addr_pton(NET_AF_INET, ip_address, &addr);
	if (ret < 0) {
		LOG_ERR("cannot parse trap destination \"%s\"", ip_address);
		return -EINVAL;
	}

	dst.addr = addr.s_addr;

	snmp_agent_lock();
	snmp_set_default_trap_version(SNMP_VERSION_2c);
	snmp_trap_dst_enable(0, true);
	snmp_trap_dst_ip_set(0, &dst);
	snmp_agent_unlock();

	return 0;
}

/**
 * @brief Send one encoded message, called by the agent core.
 *
 * @param handle The socket the request arrived on, as an opaque value.
 * @param data   The encoded message.
 * @param len    Its length in bytes.
 * @param dst    Destination address.
 * @param port   Destination port, in network byte order.
 */
err_t snmp_sendto(void *handle, const u8_t *data, u16_t len, const ip_addr_t *dst,
		  u16_t port)
{
	struct net_sockaddr_in to = {
		.sin_family = NET_AF_INET,
		.sin_port = port,
	};
	int sock = (int)(intptr_t)handle;
	int ret;

	to.sin_addr.s_addr = dst->addr;

	ret = zsock_sendto(sock, data, len, 0,
			   (struct net_sockaddr *)&to, sizeof(to));
	if (ret < 0) {
		LOG_ERR("sendto failed, errno %d", errno);
		return ERR_CONN;
	}

	return ERR_OK;
}

u8_t snmp_get_local_ip_for_dst(void *handle, const ip_addr_t *dst, ip_addr_t *result)
{
	(void)handle;

	ip_addr_copy(*result, *dst);

	return 1;
}

u32_t sys_now(void)
{
	return k_uptime_get();
}

const char *snmp_oid_to_str(char *buf, size_t buf_size, size_t oid_len,
			    const u32_t *oid_words)
{
	size_t count = (oid_len <= SNMP_MAX_OBJ_ID_LEN) ? oid_len : SNMP_MAX_OBJ_ID_LEN;
	size_t length = 0;
	size_t index;

	if (buf_size == 0) {
		return buf;
	}

	buf[0] = '\0';

	for (index = 0; index < count && length < buf_size - 1; index++) {
		int written = snprintf(buf + length, buf_size - length,
				       (index == 0) ? "%u" : ".%u",
				       (unsigned)oid_words[index]);

		if (written < 0) {
			break;
		}
		/* snprintf() reports what it would have written, so stop at
		 * the point where the buffer ran out rather than past it. */
		if ((size_t)written >= buf_size - length) {
			length = buf_size - 1;
			break;
		}
		length += (size_t)written;
	}

	return buf;
}

/* Link stubs for lwIP globals the MIB-2 groups still reference. They are
 * never populated in this port; the groups that read them are rewritten
 * against Zephyr's own interfaces in a later phase. */

const ip_addr_t ip_addr_any;

/** udp_pcbs export for external reference (e.g. SNMP agent) */
struct udp_pcb *udp_pcbs;

/** Global variable containing lwIP internal statistics. */
struct stats_ lwip_stats;

/** Global variable containing the list of network interfaces. */
struct netif *netif_list;

/** The default network interface. */
struct netif *netif_default;
