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
	#include <arpa/inet.h>
	#include <unistd.h>

#else

	#include <zephyr/net/socket.h>
	#include <zephyr/kernel.h>

#endif

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

	static k_tid_t snmp_thread;
	static struct k_thread snmp_thread_data;
	static K_KERNEL_STACK_DEFINE( snmp_stack, SNMP_STACK_SIZE );
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

	extern char * inet_ntoa( struct in_addr in );

	void net_if_callback( struct net_if * iface,
						  void * user_data )
	{
		/* Just for test. */
		zephyr_log( "net_if_callback: called" );
	}

/** SNMP netconn API worker thread */
	static void snmp_zephyr_thread( void * arg1,
									void * arg2,
									void * arg3 )
	{
		int udp_socket;

		LWIP_UNUSED_ARG( arg1 );
		LWIP_UNUSED_ARG( arg2 );
		LWIP_UNUSED_ARG( arg3 );

		#if 0
			/* Bind to SNMP port with default IP address */
			#if LWIP_IPV6
				conn = netconn_new( NETCONN_UDP_IPV6 );
				netconn_bind( conn, IP6_ADDR_ANY, LWIP_IANA_PORT_SNMP );
			#else /* LWIP_IPV6 */
				conn = netconn_new( NETCONN_UDP );
				netconn_bind( conn, IP4_ADDR_ANY, LWIP_IANA_PORT_SNMP );
			#endif /* LWIP_IPV6 */
			LWIP_ERROR( "snmp_netconn: invalid conn", ( conn != NULL ), return;

						);
		#endif /* 0 */

		int opt;
		socklen_t optlen = sizeof( int );
		int ret;
		struct sockaddr_in6 bind_addr =
		{
			.sin6_family = AF_INET,
			.sin6_addr   = IN6ADDR_ANY_INIT,
			.sin6_port   = htons( LWIP_IANA_PORT_SNMP ),
		};

		k_sleep( Z_TIMEOUT_MS( 1000 ) );
		zephyr_log( "process_udp: started" );

		struct net_if * iface = net_if_get_default();

		if( iface != NULL )
		{
			for( ; ; )
			{
				int is_up = net_if_is_up( iface );
				zephyr_log( "process_udp: Name \"%s\" UP: %s",
							iface->if_dev->dev->name,
							is_up ? "true" : "false" );

				if( is_up )
				{
					break;
				}

				k_sleep( Z_TIMEOUT_MS( 1000 ) );
			}
		}

		udp_socket = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP );

		if( udp_socket < 0 )
		{
			zephyr_log( "process_udp: error: socket: %d errno: %d", udp_socket, errno );
			go_sleep( 1 );
		}

		zephyr_log( "process_udp: socket: %d (OK)", udp_socket );

		ret = getsockopt( udp_socket, IPPROTO_IPV6, IPV6_V6ONLY, &opt, &optlen );

		if( ret == 0 )
		{
			if( opt )
			{
				zephyr_log( "process_udp: IPV6_V6ONLY option is on, turning it off." );

				opt = 0;
				ret = setsockopt( udp_socket, IPPROTO_IPV6, IPV6_V6ONLY,
								  &opt, optlen );

				if( ret < 0 )
				{
					zephyr_log( "process_udp: Cannot turn off IPV6_V6ONLY option" );
				}
				else
				{
					zephyr_log( "Sharing same socket between IPv6 and IPv4" );
				}
			}
		}

		if( bind( udp_socket, ( struct sockaddr * ) &bind_addr, sizeof( bind_addr ) ) < 0 )
		{
			zephyr_log( "error: bind: %d", errno );
			go_sleep( 1 );
		}

		LOG_INF( "Wait for a packet on port %d.", LWIP_IANA_PORT_SNMP );

		snmp_traps_handle = ( void * ) udp_socket;

/*  net_if_foreach(net_if_callback, NULL); */

		do
		{
			struct sockaddr client_addr;
			struct sockaddr_in * sin = ( struct sockaddr_in * ) &client_addr;
			#define CHAR_BUF_LEN  512
			char * char_buffer;
			if (char_buffer == NULL) {
				char_buffer = k_malloc(CHAR_BUF_LEN);
			}
			socklen_t client_addr_len = sizeof( client_addr );
			int len = recvfrom( udp_socket,
								char_buffer,
								CHAR_BUF_LEN, 0,
								&client_addr,
								&client_addr_len );

			if( len > 0 )
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
			}
		} while( 1 );
	}

	err_t snmp_sendto( void * handle,
					   struct pbuf * p,
					   const ip_addr_t * dst,
					   u16_t port )
	{
		err_t result;
		struct sockaddr client_addr;
		struct sockaddr_in * in_addr = ( struct sockaddr_in * ) &client_addr;
		socklen_t client_addr_len = sizeof( client_addr );

		memcpy( &in_addr->sin_addr, &dst->addr, sizeof dst->addr );
		in_addr->sin_port = port;

		result = sendto( ( int ) handle, p->payload, p->len, 0, &client_addr, client_addr_len );

/*result = sendto((int)handle, &buf, dst, port); */

		return result;
	}

	u8_t snmp_get_local_ip_for_dst( void * handle,
									const ip_addr_t * dst,
									ip_addr_t * result )
	{
		struct netconn * conn = ( struct netconn * ) handle;
		struct netif * dst_if;
		const ip_addr_t * dst_ip;
		struct in_addr in_addr;

		in_addr.s_addr = dst->addr;
        zephyr_log ("snmp_get_local_ip_for_dst: dst->addr = %s",
			inet_ntoa(in_addr));

		LWIP_UNUSED_ARG( conn ); /* unused in case of IPV4 only configuration */
		return false;

/*  ip_route_get_local_ip(&conn->pcb.udp->local_ip, dst, dst_if, dst_ip); */
		LOG_INF( "Skipped call to ip_route_get_local_ip()" );

		if( ( dst_if != NULL ) && ( dst_ip != NULL ) )
		{
			ip_addr_copy( *result, *dst_ip );
			return 1;
		}
		else
		{
			return 0;
		}
	}

	static void go_sleep()
	{
		for( ; ; )
		{
			k_sleep( Z_TIMEOUT_MS( 5000 ) );
		}
	}

/**
 * Starts SNMP Agent.
 */
	void snmp_init( void )
	{
/*sys_thread_new("snmp_netconn", snmp_zephyr_thread, NULL, SNMP_STACK_SIZE, SNMP_THREAD_PRIO); */
		snmp_thread = k_thread_create(
			&snmp_thread_data,      /* struct k_thread * new_thread, */
			snmp_stack,             /* k_thread_stack_t * stack, */
			SNMP_STACK_SIZE,        /* size_t 	stack_size, */
			snmp_zephyr_thread,     /* k_thread_entry_t entry, */
			NULL,                   /* void * p1, */
			NULL,                   /* void * p2, */
			NULL,                   /* void * p3, */
			SNMP_THREAD_PRIO,       /* int prio, */
			0U,                     /* uint32_t options, */
			Z_TIMEOUT_MS( 100U ) ); /* k_timeout_t delay */
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

/*
 * 0000   30 26 02 01 00 04 06 70 75 62 6c 69 63 a0 19 02   0&.....public...
 *     hh hh hh hh vv        p  u  b  l  i  c
 * 0010   01 26 02 01 00 02 01 00 30 0e 30 0c 06 08 2b 06   .&......0.0...+.
 *        RI
 * 0020   01 02 01 01 02 00 05 00                           ........
 *
 *
 */
void zephyr_log( const char * format,
				 ... )
{
	va_list args;
	char toprint[ 129 ];

	va_start( args, format );
	int rc = vsnprintf(toprint, sizeof toprint, format, args);
	va_end( args );

	LOG_INF( "%s", toprint );
}
