/*
 * Minimal SNMP agent sample, following the usage documented in the
 * project README: a socket-service callback forwards packet ids to a
 * single application thread that owns every call into the library.
 */

#include <zephyr/kernel.h>
#include <zephyr/net/net_if.h>

#include <lwip/apps/snmp_opts.h>
#include <lwip/apps/snmp.h>
#include <lwip/apps/snmp_mib2.h>
#include <lwip/apps/snmp_zephyr.h>

#define SNMP_THREAD_STACK_SIZE 4096
#define SNMP_THREAD_PRIORITY   7

/* Packet ids travel from the socket service thread to the SNMP thread. */
K_MSGQ_DEFINE(snmp_queue, sizeof(int), 4, 4);

/* Called on the socket service thread. Keep it short. */
static void snmp_packet_received(int packet_id)
{
	(void)k_msgq_put(&snmp_queue, &packet_id, K_NO_WAIT);
}

static void wait_for_ipv4(void)
{
	struct net_if *iface = net_if_get_default();

	while (net_if_ipv4_get_global_addr(iface, NET_ADDR_PREFERRED) == NULL) {
		k_sleep(K_MSEC(250));
	}
}

/* MIB-2 system group: describe this device. */
static const u8_t sys_descr[] = "zephyr-snmp sample agent";
static const u16_t sys_descr_len = sizeof(sys_descr) - 1;

static u8_t sys_name[32] = "snmp-sample";
static u16_t sys_name_len = 11;

static u8_t sys_location[64] = "native_sim";
static u16_t sys_location_len = 10;

static u8_t sys_contact[64] = "user@example.com";
static u16_t sys_contact_len = 16;

static void snmp_describe_device(void)
{
	snmp_mib2_set_sysdescr(sys_descr, &sys_descr_len);
	snmp_mib2_set_sysname(sys_name, &sys_name_len, sizeof(sys_name));
	snmp_mib2_set_syslocation(sys_location, &sys_location_len,
				  sizeof(sys_location));
	snmp_mib2_set_syscontact(sys_contact, &sys_contact_len,
				 sizeof(sys_contact));
}

static void snmp_thread(void *p1, void *p2, void *p3)
{
	int packet_id;

	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	wait_for_ipv4();

	if (snmp_zephyr_init(snmp_packet_received) == 0) {
		printk("SNMP: unable to create the agent sockets\n");
		return;
	}

	snmp_describe_device();

	printk("SNMP: agent listening on port 161\n");

	while (true) {
		if (k_msgq_get(&snmp_queue, &packet_id, K_FOREVER) == 0) {
			snmp_recv_packet(packet_id);
		}
	}
}

K_THREAD_DEFINE(snmp_tid, SNMP_THREAD_STACK_SIZE, snmp_thread,
		NULL, NULL, NULL, SNMP_THREAD_PRIORITY, 0, 0);

int main(void)
{
	printk("zephyr-snmp sample: query me with "
	       "'snmpwalk -v2c -c public 192.0.2.1 1'\n");
	return 0;
}
