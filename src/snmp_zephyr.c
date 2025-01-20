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


	/* Wait for the negotiation of the DHCP client.
	 * It will sleep for 500 ms and poll 'dhcpv4.state'.
	 * It will wait at most 12 seconds. */
	static void wait_for_ethernet()
	{
		k_sleep( Z_TIMEOUT_MS( 1000 ) );

		struct net_if * iface = net_if_get_default();

		if( iface != NULL )
		{
			int counter;
			enum net_dhcpv4_state last_state = NET_DHCPV4_DISABLED;
			for(counter = 0; counter< 24 ; counter++)
			{
				int is_up = net_if_is_up( iface );
				if (last_state != iface->config.dhcpv4.state) {
					last_state = iface->config.dhcpv4.state;
					zephyr_log( "DHCP: Name \"%s\" UP: %s DHCP %s\n",
								iface->if_dev->dev->name,
								is_up ? "true" : "false",
								net_dhcpv4_state_name(iface->config.dhcpv4.state));
				}
				if (iface->config.dhcpv4.state >= NET_DHCPV4_REBINDING) {
					break;
				}
				k_sleep( Z_TIMEOUT_MS( 500 ) );
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

	void snmp_prepare_trap_test()
	{
		/** Initiate a trap for testing. */
		/// Setting version to use for testing.
		snmp_set_default_trap_version(SNMP_VERSION_2c);

		ip_addr_t dst;
		struct in_addr in_addr;
		dst.addr = inet_addr("192.168.2.11");
//		dst.addr = inet_addr("192.168.2.17");
		
		in_addr.s_addr = dst.addr;
		
		snmp_trap_dst_enable(0, true);
		snmp_trap_dst_ip_set(0, &dst);
	}

	/* Define the OID for the enterprise object
	   struct snmp_obj_id
	   {
	  	  u8_t len;
	  	  u32_t id[SNMP_MAX_OBJ_ID_LEN];
	   };
	*/
	#define ENTERPRISE_OID {7, {1,3,6,1,4,1,12345} } // Example OID, replace with actual

	// Function to send SNMP trap
	void send_snmp_trap(void)
	{
		snmp_prepare_trap_test();

  		struct snmp_varbind *varbinds = NULL;
		struct snmp_obj_id eoid = ENTERPRISE_OID; // Set enterprise OID
		s32_t generic_trap = 6; // Generic trap code (e.g., 6 for enterprise specific)
		s32_t specific_trap = 1; // Specific trap code (customize as needed)

		// Allocate memory for varbinds, about 220 bytes
		// It will allocate SNMP_MAX_OBJ_ID_LEN (50) uint32's.
		varbinds = (struct snmp_varbind *)mem_malloc(sizeof(struct snmp_varbind));
		
		if (varbinds != NULL) {

			// Set up varbinds
			varbinds->oid.len   = 5; // Length of OID
			varbinds->oid.id[0] = 1; // Example OID value (customize as needed)
			varbinds->oid.id[1] = 2; // "1.2.3.4.5"
			varbinds->oid.id[2] = 3;
			varbinds->oid.id[3] = 4;
			varbinds->oid.id[4] = 5;

			varbinds->type = SNMP_ASN1_TYPE_UNSIGNED32; // Type of the variable
			u32_t value = 100; // Example value to send
			varbinds->value = (void *)&value; // Pointer to value
			varbinds->value_len = sizeof(value); // Length of value

			// Send the SNMP trap
			err_t err = snmp_send_trap(&eoid, generic_trap, specific_trap, varbinds);
			
			if (err == ERR_OK) {
				zephyr_log("SNMP trap sent successfully.\n");
			} else {
				zephyr_log("Failed to send SNMP trap: %d\n", err);
			}

			// Free allocated memory for varbinds
			mem_free(varbinds);
		} else {
			zephyr_log("Memory allocation failed for varbinds.\n");
		}
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

				if (len > 0 && index == 0)
				{
					zephyr_log( "recv: %d bytes %s:%u sel=%d",
							 len,
							 inet_ntoa(sin->sin_addr),
							 ntohs(sin->sin_port),
							 rc_select);
	
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
		wait_for_ethernet();

		/* Create the sockets. */
		socket_set.socket_161 = create_socket(LWIP_IANA_PORT_SNMP);
		socket_set.socket_162 = create_socket(LWIP_IANA_PORT_SNMP_TRAP);

		/* The lwIP SNMP driver owns a socket for traps 'snmp_traps_handle'. */
		snmp_traps_handle = ( void * ) socket_set.socket_162;

		socket_set.timeout.tv_sec = 0;
		socket_set.timeout.tv_usec = 10000U;
	}

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
		client_addr_in->sin_port = port; // ntohs (port);
		client_addr_in->sin_family = AF_INET;
		// snmp_sendto: hnd = 8 port = 162, IP=C0A80213, len = 65
		zephyr_log("snmp_sendto: hnd = %d port = %u, IP=%08X, len = %d\n",
			(int) handle, port, client_addr_in->sin_addr.s_addr, p->len);

		rc = sendto ((int) handle, p->payload, p->len, 0, &client_addr, client_addr_len);

		return rc;
	}

	u8_t snmp_get_local_ip_for_dst( void * handle,
									const ip_addr_t * dst,
									ip_addr_t * result )
	{
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
