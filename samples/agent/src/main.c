/*
 * Copyright (c) 2025 lwIP contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * Minimal SNMP agent sample. The agent runs on Zephyr's socket service
 * thread, so the application only starts it and describes the device.
 */

#include <zephyr/kernel.h>

#include <snmp/snmp_opts.h>
#include <snmp/snmp.h>
#include <snmp/snmp_mib2.h>
#include <snmp/snmp_agent.h>

/*
 * Where to point a manager depends on how the sample was built. With
 * offloaded sockets the agent listens on the host's own stack; otherwise it
 * listens on the Zephyr interface configured in prj.conf.
 */
#if defined(CONFIG_NET_NATIVE_OFFLOADED_SOCKETS)
#define SAMPLE_QUERY_ADDR "localhost"
#elif defined(CONFIG_NET_CONFIG_MY_IPV4_ADDR)
#define SAMPLE_QUERY_ADDR CONFIG_NET_CONFIG_MY_IPV4_ADDR
#else
/* The address arrives at runtime, from DHCP or the application. */
#define SAMPLE_QUERY_ADDR "<this device>"
#endif

/* MIB-2 system group: describe this device. */
static const uint8_t sys_descr[] = "zephyr-snmp sample agent";
static const uint16_t sys_descr_len = sizeof(sys_descr) - 1;

static uint8_t sys_name[32] = "snmp-sample";
static uint16_t sys_name_len = 11;

static uint8_t sys_location[64] = "native_sim";
static uint16_t sys_location_len = 10;

static uint8_t sys_contact[64] = "user@example.com";
static uint16_t sys_contact_len = 16;

static void snmp_describe_device(void)
{
	snmp_mib2_set_sysdescr(sys_descr, &sys_descr_len);
	snmp_mib2_set_sysname(sys_name, &sys_name_len, sizeof(sys_name));
	snmp_mib2_set_syslocation(sys_location, &sys_location_len, sizeof(sys_location));
	snmp_mib2_set_syscontact(sys_contact, &sys_contact_len, sizeof(sys_contact));
}

int main(void)
{
	int ret;

	snmp_describe_device();

	/* The socket binds to any address, so there is no need to wait for
	 * an IPv4 address to be assigned first. */
	ret = net_snmp_agent_start();
	if (ret < 0) {
		printk("SNMP: cannot start the agent: %d\n", ret);
		return ret;
	}

	printk("zephyr-snmp sample: query me with "
	       "'snmpwalk -v2c -c public " SAMPLE_QUERY_ADDR ":%d 1'\n",
	       CONFIG_SNMP_AGENT_PORT);

	return 0;
}
