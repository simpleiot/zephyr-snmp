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
		fd_set read_set; /* A set of file descriptors. */
		struct timeval timeout; /* Maximum time to wait for an exvent. */
		int select_max;  /* The max parameter for select. */
	} socket_set_t;

	static k_tid_t snmp_thread;
	static struct k_thread snmp_thread_data;
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

	void net_if_callback( struct net_if * iface,
						  void * user_data )
	{
		/* Just for test. */
		zephyr_log( "net_if_callback: called\n" );
	}

	static void wait_for_ethernet()
	{
		k_sleep( Z_TIMEOUT_MS( 1000 ) );

		struct net_if * iface = net_if_get_default();

		if( iface != NULL )
		{
			for( ; ; )
			{
				int is_up = net_if_is_up( iface );
				zephyr_log( "\nprocess_udp: Name \"%s\" UP: %s\n",
							iface->if_dev->dev->name,
							is_up ? "true" : "false" );

				if( is_up )
				{
					break;
				}

				k_sleep( Z_TIMEOUT_MS( 1000 ) );
			}
		}
	}

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
			zephyr_log( "process_udp: error: socket: %d errno: %d\n", socket_fd, errno );
		}
		else
		{
			zephyr_log( "process_udp: socket: %d %s (OK)\n",
				socket_fd,
				port == LWIP_IANA_PORT_SNMP_TRAP ? "traps" : "server");

			ret = getsockopt( socket_fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, &optlen );

			if( ret == 0 )
			{
				if( opt )
				{
					zephyr_log( "process_udp: IPV6_V6ONLY option is on, turning it off.\n" );

					opt = 0;
					ret = setsockopt( socket_fd, IPPROTO_IPV6, IPV6_V6ONLY,
									  &opt, optlen );

					if( ret < 0 )
					{
						zephyr_log( "process_udp: Cannot turn off IPV6_V6ONLY option\n" );
					}
				}
			}

			struct timeval tv;
			tv.tv_sec = 0;
			tv.tv_usec = 10000;
			int rc = setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
			zephyr_log( "process_udp: setsockopt %d\n", rc);

			if( bind( socket_fd, ( struct sockaddr * ) &bind_addr, sizeof( bind_addr ) ) < 0 )
			{
				zephyr_log( "error: bind: %d\n", errno );
				go_sleep( 1 );
			}
		}
		return socket_fd;
	}

	static void snmp_send_trap_test()
	{
		/** Initiate a trap for testing. */
		/// Setting version to use for testing.
		snmp_set_default_trap_version(SNMP_VERSION_2c);

		ip_addr_t dst;
		struct in_addr in_addr;
		dst.addr = inet_addr("192.168.2.11");
		dst.addr = inet_addr("192.168.2.17");
		
		in_addr.s_addr = dst.addr;
		
		snmp_trap_dst_enable(0, true);
		snmp_trap_dst_ip_set(0, &dst);

		zephyr_log ("Sending a cold-start trap to %s:%u\n",
			inet_ntoa(in_addr), LWIP_IANA_PORT_SNMP_TRAP);
		snmp_coldstart_trap();
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

	static void loop_for_ever(socket_set_t * socket_set)
	{
		#define CHAR_BUF_LEN  512
		char * char_buffer = k_malloc(CHAR_BUF_LEN);

		socket_set->timeout.tv_sec = 0;
		socket_set->timeout.tv_usec = 10000U;
		do
		{
			struct sockaddr client_addr;
			struct sockaddr_in * sin = ( struct sockaddr_in * ) &client_addr;
			socklen_t client_addr_len = sizeof( client_addr );
			select(socket_set->select_max, &socket_set->read_set, NULL, NULL, &(socket_set->timeout));

			for (int index = 0; index < 2; index++)
			{
				int udp_socket = (index == 0) ? socket_set->socket_161 : socket_set->socket_162;
				int len = recvfrom( udp_socket,
									char_buffer,
									CHAR_BUF_LEN, 0,
									&client_addr,
									&client_addr_len );

				if (len > 0 && index == 0)
				{
					LOG_INF( "process_udp: Recv %d bytes from %s:%u",
							 len, inet_ntoa( sin->sin_addr ), ntohs( sin->sin_port ) );
					struct pbuf * pbuf = pbuf_alloc( PBUF_TRANSPORT, len, PBUF_RAM );
					LOG_INF( "pbuf_alloc returns %p", pbuf );

					if( pbuf != NULL )
					{
						pbuf->next = NULL;
						memcpy( pbuf->payload, char_buffer, len );
						pbuf->tot_len = len;
						pbuf->len = len;
						pbuf->ref = 1;

						ip_addr_t from_address;
						from_address.addr = sin->sin_addr.s_addr;
						snmp_receive( ( void * ) udp_socket, pbuf, &from_address, sin->sin_port );
						pbuf_free (pbuf);
					}
					//snmp_send_trap_test();
					{
						extern void snmp_send_zbus ();
						snmp_send_zbus();
					}
				}
			}
		} while( 1 );
	}

/** SNMP netconn API worker thread */
	static void snmp_zephyr_thread( void * arg1,
									void * arg2,
									void * arg3 )
	{
		LWIP_UNUSED_ARG( arg1 );
		LWIP_UNUSED_ARG( arg2 );
		LWIP_UNUSED_ARG( arg3 );
		socket_set_t socket_set;

		wait_for_ethernet();

		/* Initialise a socket set to select 2 sockets. */
		memset (&socket_set, 0, sizeof socket_set);

		/* Create the sockets. */
		socket_set.socket_161 = create_socket(LWIP_IANA_PORT_SNMP);
		socket_set.socket_162 = create_socket(LWIP_IANA_PORT_SNMP_TRAP);

		FD_ZERO(&socket_set.read_set);
		FD_SET(socket_set.socket_161, &socket_set.read_set);
		FD_SET(socket_set.socket_162, &socket_set.read_set);
		socket_set.select_max = max_int(socket_set.socket_161, socket_set.socket_162) + 1;

//		socket_set.timeout.tv_sec = 5;

		/* The lwIP SNMP driver owns a socket for traps 'snmp_traps_handle'. */
		snmp_traps_handle = ( void * ) socket_set.socket_162;

		loop_for_ever(&socket_set);
	}

	err_t snmp_sendto( void * handle,
					   struct pbuf * p,
					   const ip_addr_t * dst,
					   u16_t port )
	{
		err_t result;
		struct sockaddr client_addr;
		struct sockaddr_in * client_addr_in = ( struct sockaddr_in * ) &client_addr;
		socklen_t client_addr_len = sizeof( client_addr );

		client_addr_in->sin_addr.s_addr = dst->addr;
		client_addr_in->sin_port = port; // ntohs (port);
		client_addr_in->sin_family = AF_INET;
		// snmp_sendto: hnd = 8 port = 162, IP=C0A80213, len = 65
		zephyr_log("snmp_sendto: hnd = %d port = %u, IP=%08X, len = %d\n",
			(int) handle, port, client_addr_in->sin_addr.s_addr, p->len);

		result = sendto( ( int ) handle, p->payload, p->len, 0, &client_addr, client_addr_len );

		return result;
	}

	u8_t snmp_get_local_ip_for_dst( void * handle,
									const ip_addr_t * dst,
									ip_addr_t * result )
	{
//		struct netif * dst_if;
		const ip_addr_t * dst_ip = dst;
		struct in_addr in_addr;

		in_addr.s_addr = dst->addr;
        zephyr_log ("snmp_get_local_ip_for_dst: dst->addr = %s\n",
			inet_ntoa(in_addr));
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

/**
 * Starts SNMP Agent.
 */
	static K_KERNEL_STACK_DEFINE( snmp_stack, SNMP_STACK_SIZE );
	void snmp_init( void )
	{
//		snmp_thread = k_thread_create(
//			&snmp_thread_data,      /* struct k_thread * new_thread, */
//			snmp_stack,             /* k_thread_stack_t * stack, */
//			SNMP_STACK_SIZE,        /* size_t 	stack_size, */
//			snmp_zephyr_thread,     /* k_thread_entry_t entry, */
//			NULL,                   /* void * p1, */
//			NULL,                   /* void * p2, */
//			NULL,                   /* void * p3, */
//			SNMP_THREAD_PRIO,       /* int prio, */
//			0U,                     /* uint32_t options, */
//			Z_TIMEOUT_MS( 100U ) ); /* k_timeout_t delay */
	}
K_THREAD_DEFINE(snmp_zephyr, SNMP_STACK_SIZE, snmp_zephyr_thread, NULL, NULL, NULL, SNMP_THREAD_PRIO, K_ESSENTIAL, 0);
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

/*
 * 0000   30 26 02 01 00 04 06 70 75 62 6c 69 63 a0 19 02   0&.....public...
 *     hh hh hh hh vv        p  u  b  l  i  c
 * 0010   01 26 02 01 00 02 01 00 30 0e 30 0c 06 08 2b 06   .&......0.0...+.
 *        RI
 * 0020   01 02 01 01 02 00 05 00                           ........
 *
 *
 */
size_t zephyr_log( const char * format,
				 ... )
{
	va_list args;
	char toprint[ 201 ];

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

const char * print_oid (char *buf, size_t buf_size, size_t oid_len, u32_t *oid_words)
{
	int length = 0;
	int index;
	buf[0] = 0;

	length += snprintf (buf+length, sizeof buf-length, "%u", oid_words[0]);
	for (index = 1; index < oid_len; index++) {
		length += snprintf (buf + length, buf_size - length, ".%u", oid_words[index]);
	}
	return buf;
}
