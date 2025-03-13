/**
 * @file
 * SNMP netconn frontend.
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#ifndef __ZEPHYR__

	#include <netinet/in.h>
	#include <sys/socket.h>
	#include <unistd.h>

#else

	#include <zephyr/net/socket.h>
	#include <zephyr/kernel.h>

#endif

#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <fcntl.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h>
#include <app_version.h>

#include "lwip/apps/snmp_opts.h"

#if LWIP_SNMP && SNMP_USE_ZEPHYR

	#include <string.h>
/*#include "lwip/api.h" */
	#include "lwip/ip.h"
	#include "lwip/udp.h"
	#include "snmp_msg.h"
	#include "lwip/sys.h"
	#include "lwip/prot/iana.h"

	LOG_MODULE_REGISTER( snmp_log, LOG_LEVEL_DBG );

	typedef struct
	{
		int socket_161;  /* SNMP/serv socket */
		int socket_162;  /* SNMP/trap socket */
		struct timeval timeout; /* Maximum time to wait for an event. */
		int select_max;  /* The max parameter for select. */
	} socket_set_t;

	const ip_addr_t ip_addr_any;

/** udp_pcbs export for external reference (e.g. SNMP agent) */
/** Yes, a global variable. */
	struct udp_pcb * udp_pcbs;

/** Global variable containing lwIP internal statistics. Add this to your debugger's watchlist. */
	struct stats_ lwip_stats;

/** Global variable containing the list of network interfaces. */
	struct netif * netif_list;

/** The default network interface. */
	struct netif * netif_default;

	static void go_sleep();

/** Wake up the thread 'z_snmp_client' in order to send a trap. */
	void snmp_send_zbus(void);

	static socket_set_t socket_set;

	#define CHAR_BUF_LEN  512 /* declared on the heap at first time use. */
	char char_buffer[CHAR_BUF_LEN];

	static int create_socket(unsigned port)
	{
		int socket_fd = -1;
		int opt;
		int ret;
		socklen_t optlen = sizeof( int );

		struct sockaddr_in6 bind_addr =
		{
			.sin6_family = AF_INET,
			.sin6_addr   = IN6ADDR_ANY_INIT,
			.sin6_port   = htons( port ),
		};

		socket_fd = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP );

		if( socket_fd < 0 )
		{
			zephyr_log( "create_socket: error: socket: %d errno: %d\n", socket_fd, errno );
			go_sleep( 1 );
		}
		else
		{
			zephyr_log( "create_socket: socket: %d %s (OK)\n",
				socket_fd,
				(port == LWIP_IANA_PORT_SNMP_TRAP) ? "traps" : "server");

			ret = getsockopt( socket_fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, &optlen );

			if (ret == 0 && opt != 0)
			{
				zephyr_log( "create_socket: IPV6_V6ONLY option is on, turning it off.\n" );

				opt = 0;
				ret = setsockopt( socket_fd, IPPROTO_IPV6, IPV6_V6ONLY,
								  &opt, optlen );

				if( ret < 0 )
				{
					zephyr_log( "create_socket: Cannot turn off IPV6_V6ONLY option\n" );
				}
			}

			struct timeval tv;
			tv.tv_sec = 0;
			tv.tv_usec = 10000;
			int rc = setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
			zephyr_log( "process_udp: setsockopt %d\n", rc);

			if( bind( socket_fd, ( struct sockaddr * ) &bind_addr, sizeof( bind_addr ) ) < 0 )
			{
				zephyr_log( "create_socket: bind: %d\n", errno );
				go_sleep( 1 );
			}
		}
		return socket_fd;
	}

	void snmp_prepare_trap_test(const char * ip_address)
	{
		/** Initiate a trap for testing. */
		/// Setting version to use for testing.
		snmp_set_default_trap_version(SNMP_VERSION_2c);

		ip_addr_t dst;
		struct in_addr in_addr;
		dst.addr = inet_addr(ip_address);
		
		in_addr.s_addr = dst.addr;
		
		snmp_trap_dst_enable(0, true);
		snmp_trap_dst_ip_set(0, &dst);
	}

	static int max_int(int left, int right)
	{
		int rc = left;
		if (right > rc)
		{
			rc = right;
		}
		return rc;
	}

	void snmp_loop()
	{
		int rc_select;
		fd_set read_set; /* A set of file descriptors. */
		FD_ZERO(&read_set);
		FD_SET(socket_set.socket_161, &read_set);
		FD_SET(socket_set.socket_162, &read_set);
		socket_set.select_max = max_int(socket_set.socket_161, socket_set.socket_162) + 1;

		rc_select = select(socket_set.select_max, &read_set, NULL, NULL, &(socket_set.timeout));
		if (rc_select > 0) for (int index = 0; index < 2; index++)
		{
			int udp_socket = (index == 0) ? socket_set.socket_161 : socket_set.socket_162;
			if (FD_ISSET(udp_socket, &read_set))
			{
				struct sockaddr client_addr;
				struct sockaddr_in * sin = (struct sockaddr_in *) &client_addr;
				socklen_t client_addr_len = sizeof client_addr;
				int len;
				len = recvfrom( udp_socket,
								char_buffer,
								sizeof char_buffer,
								0, // flags
								&client_addr,
								&client_addr_len );
				if (len > 0) {
					int port = (index == 0) ? 161 : 162;
					zephyr_log( "recv[%u]: %d bytes from %s:%u\n",
						 port,
						 len,
						 inet_ntoa(sin->sin_addr),
						 ntohs(sin->sin_port));
				}
				if (len > 0) //  && index == 0)
				{
					struct pbuf * pbuf = pbuf_alloc( PBUF_TRANSPORT, len, PBUF_RAM );

					if( pbuf != NULL )
					{
						pbuf->next = NULL;
						memcpy( pbuf->payload, char_buffer, len );
						pbuf->tot_len = len;
						pbuf->len = len;
						pbuf->ref = 1;

						ip_addr_t from_address;
						from_address.addr = sin->sin_addr.s_addr;
						snmp_receive( (void*) udp_socket, pbuf, &from_address, sin->sin_port);
						pbuf_free (pbuf);
					}
				} /* if (len > 0 && index == 0) */
			} /* FD_ISSET */
		} /* for (int index = 0 */
	}

/**
 * Starts SNMP Agent.
 */
	void snmp_init(void)
	{
		static int has_created = false;
		if (has_created == false) {
			has_created = true;

			/* Create the sockets. */
			socket_set.socket_161 = create_socket(LWIP_IANA_PORT_SNMP);
			socket_set.socket_162 = create_socket(LWIP_IANA_PORT_SNMP_TRAP);

			/* The lwIP SNMP driver owns a socket for traps 'snmp_traps_handle'. */
			snmp_traps_handle = ( void * ) socket_set.socket_162;

			socket_set.timeout.tv_sec = 0;
			socket_set.timeout.tv_usec = 10000U;
		}
	}

	/* send a UDP packet to the LAN using a network-endian
	 * port number and IP-address. */
	err_t snmp_sendto( void * handle,
					   struct pbuf * p,
					   const ip_addr_t * dst,
					   u16_t port )
	{
		int rc; /* Store the result of sendto(). */
		struct sockaddr client_addr;
		struct sockaddr_in * client_addr_in = (struct sockaddr_in *) &client_addr;
		socklen_t client_addr_len = sizeof(client_addr);

		client_addr_in->sin_addr.s_addr = dst->addr;
		client_addr_in->sin_port = port;
		client_addr_in->sin_family = AF_INET;
		// snmp_sendto: hnd = 8 port = 162, IP=C0A80213, len = 65

		rc = sendto ((int) handle, p->payload, p->len, 0, &client_addr, client_addr_len);
		zephyr_log("snmp_sendto: hnd = %d port = %u, IP=%s, len = %d, rc %d\n",
			(int) handle, ntohs (port), inet_ntoa(client_addr_in->sin_addr), p->len, rc);

		return rc;
	}

	u8_t snmp_get_local_ip_for_dst( void * handle,
									const ip_addr_t * dst,
									ip_addr_t * result )
	{
		const ip_addr_t * dst_ip = dst;
		struct in_addr in_addr;

		in_addr.s_addr = dst->addr;
//      zephyr_log ("snmp_get_local_ip_for_dst: dst->addr = %s\n", inet_ntoa(in_addr));
		ip_addr_copy( *result, *dst_ip );

		return 1;
	}

	static void go_sleep()
	{
		/* Some fatal error occurred, sleep for ever. */
		for( ; ; )
		{
			k_sleep( Z_TIMEOUT_MS( 5000 ) );
		}
	}

	void * mem_malloc( mem_size_t size )
	{
		return k_malloc( size );
	}

	void mem_free( void * rmem )
	{
		k_free( rmem );
	}

	void * mem_trim( void * rmem,
					 mem_size_t newsize )
	{
		( void ) rmem;
		( void ) newsize;
		return rmem;
	}

	void * memp_malloc( memp_t type )
	{
		__ASSERT( false, "memp_malloc() should not be called" );
		return NULL;
	}

	void memp_free( memp_t type,
					void * mem )
	{
		( void ) type;
		( void ) type;
		( void ) mem;
		__ASSERT( false, "memp_free() should not be called" );
	}

	u32_t sys_now( void )
	{
		return k_uptime_get();
	}

#endif /* LWIP_SNMP && SNMP_USE_ZEPHYR */

size_t zephyr_log( const char * format,
				 ... )
{
	va_list args;
	static char toprint[ 201 ];

	va_start( args, format );
	size_t rc = vsnprintf(toprint, sizeof toprint, format, args);
	va_end( args );
	if (rc > 2) {
		if (rc > sizeof toprint - 1) {
			rc = sizeof toprint - 1; /* buffer was too short */
		}
		while (rc > 0) {
			if (toprint[rc-1] != 10 && toprint[rc-1] != 13)	{
				break;
			}
			/* Remove the CR or LF */
			toprint[--rc] = 0;
		}
	}

	if (rc >= 1) {
		LOG_INF ("%s", toprint);
	}
	return rc;
}

const char * print_oid (size_t oid_len, const u32_t *oid_words)
{
	int length = 0;
	size_t index;
	size_t count = (oid_len <= SNMP_MAX_OBJ_ID_LEN) ? oid_len : SNMP_MAX_OBJ_ID_LEN;
	#define buf_size   128U
	static char buf[buf_size];

	buf[0] = 0;
	if (count > 0) {
		length += snprintf (buf+length, sizeof buf-length, "%u", oid_words[0]);
	}
	for (index = 1; index < count; index++) {
		length += snprintf (buf + length, buf_size - length, ".%u", oid_words[index]);
	}
	return buf;
}

/* Use this function while stepping through the lwIP code. */
const char *leafNodeName (unsigned aType)
{
	switch (aType) {
	case SNMP_NODE_TREE:         return "Tree";         // 0x00
/* predefined leaf node types */
	case SNMP_NODE_SCALAR:       return "Scalar";       // 0x01
	case SNMP_NODE_SCALAR_ARRAY: return "Scalar-array"; // 0x02
	case SNMP_NODE_TABLE:        return "Table";        // 0x03
	case SNMP_NODE_THREADSYNC:   return "Threadsync";   // 0x04
	}
	return "Unknown";
}
