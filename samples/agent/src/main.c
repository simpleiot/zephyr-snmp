/*
 * Copyright (c) 2025 lwIP contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * Minimal SNMP agent sample. The agent runs on Zephyr's socket service
 * thread, so the application only starts it and describes the device. It also
 * sends traps, which the agent transmits on whichever thread calls in.
 */

#include <string.h>

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

/*
 * The object this sample reports in its enterprise-specific trap: seconds
 * since boot, under the enterprise the agent publishes as sysObjectID. A real
 * device uses the enterprise number IANA assigned to it, and defines the
 * object in its own MIB so a manager can name it.
 */
static const uint32_t sample_uptime_oid[] = {1, 3, 6, 1, 4, 1, SNMP_LWIP_ENTERPRISE_OID, 1, 1, 0};

static void snmp_send_sample_trap(struct k_work *work)
{
	struct snmp_varbind varbind;
	int32_t seconds = (int32_t)(k_uptime_get() / MSEC_PER_SEC);
	int ret;

	/*
	 * The value and the varbind only have to stay in scope until the call
	 * returns: the agent encodes the message before it sends it.
	 */
	memset(&varbind, 0, sizeof(varbind));
	snmp_oid_assign(&varbind.oid, sample_uptime_oid, ARRAY_SIZE(sample_uptime_oid));
	varbind.type = SNMP_ASN1_TYPE_INTEGER;
	varbind.value_len = sizeof(seconds);
	varbind.object_value = &seconds;

	/* Specific trap 1 of this device, as its own MIB would define it. */
	ret = snmp_send_trap_specific(1, &varbind);
	if (ret < 0) {
		printk("SNMP: cannot send the trap: %d\n", ret);
	}

	k_work_reschedule(k_work_delayable_from_work(work),
			  K_SECONDS(CONFIG_SAMPLE_TRAP_PERIOD_SECONDS));
}

static K_WORK_DELAYABLE_DEFINE(sample_trap_work, snmp_send_sample_trap);

static void snmp_start_traps(void)
{
	int ret;

	/*
	 * Selects SNMPv2c and points destination 0 at the manager. Configuring
	 * more than one destination means calling snmp_set_default_trap_version(),
	 * snmp_trap_dst_ip_set(), and snmp_trap_dst_enable() directly.
	 */
	ret = net_snmp_agent_trap_dst_set(CONFIG_SAMPLE_TRAP_MANAGER);
	if (ret < 0) {
		printk("SNMP: cannot set the trap destination '%s': %d\n",
		       CONFIG_SAMPLE_TRAP_MANAGER, ret);
		return;
	}

	/* Announce that the agent has just come up. */
	snmp_send_trap_generic(SNMP_GENTRAP_COLDSTART);

	printk("zephyr-snmp sample: sending traps to " CONFIG_SAMPLE_TRAP_MANAGER ":%d, "
	       "watch them with 'snmptrapd -f -Lo -c /dev/null %d'\n",
	       CONFIG_SNMP_AGENT_TRAP_PORT, CONFIG_SNMP_AGENT_TRAP_PORT);

	if (CONFIG_SAMPLE_TRAP_PERIOD_SECONDS > 0) {
		k_work_reschedule(&sample_trap_work, K_SECONDS(CONFIG_SAMPLE_TRAP_PERIOD_SECONDS));
	}
}

int main(void)
{
	int ret;

	snmp_describe_device();

	/* The socket binds to any address, so there is no need to wait for
	 * an IPv4 address to be assigned first.
	 */
	ret = net_snmp_agent_start();
	if (ret < 0) {
		printk("SNMP: cannot start the agent: %d\n", ret);
		return ret;
	}

	printk("zephyr-snmp sample: query me with "
	       "'snmpwalk -v2c -c public " SAMPLE_QUERY_ADDR ":%d 1'\n",
	       CONFIG_SNMP_AGENT_PORT);

	snmp_start_traps();

	return 0;
}
