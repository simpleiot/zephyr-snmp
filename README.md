# Zephyr SNMP Module

This module provides SNMP support for Zephyr.

It is a port of the lwIP SNMP agent to the native Zephyr network stack, so
lwIP itself is not required. The agent listens on UDP port 161, answers `get`,
`getnext`, `getbulk` and `set` requests for the standard MIB-2 tree, and can
send traps from UDP port 162. Applications extend the tree either by
registering callbacks for individual OIDs or by adding a private MIB.

SNMP v1 and v2c are supported, over IPv4.

## Adding to your project

### As a west module

Add the repository to the `projects` list of your workspace manifest
(`west.yml`):

```yaml
manifest:
  remotes:
    - name: simpleiot
      url-base: https://github.com/simpleiot

  projects:
    - name: zephyr-snmp
      remote: simpleiot
      revision: v0.0.6
      path: modules/lib/zephyr-snmp
```

Then run `west update`. Zephyr discovers the module through
`zephyr/module.yml` and builds it whenever `CONFIG_SNMP_AGENT` is set.

### Without west

Point Zephyr at the checkout from your application `CMakeLists.txt`, before
`find_package(Zephyr ...)`:

```cmake
list(APPEND ZEPHYR_EXTRA_MODULES /path/to/zephyr-snmp)
```

### Configuration

A minimal `prj.conf` for an application using the agent:

```
CONFIG_SNMP_AGENT=y

# Networking: IPv4 UDP, which the agent selects sockets and the socket
# service on top of
CONFIG_NETWORKING=y
CONFIG_NET_IPV4=y
CONFIG_NET_UDP=y

# inet_addr() and inet_ntoa() come from the POSIX networking layer
CONFIG_POSIX_API=y

# The agent allocates packet buffers with k_malloc()
CONFIG_HEAP_MEM_POOL_SIZE=4096

CONFIG_LOG=y
```

`CONFIG_SNMP_AGENT_LOG_LEVEL` sets the log level for the agent, which logs
through the `net_snmp_agent` module. `CONFIG_SNMP_AGENT_MAX_MSG_SIZE` sizes
the receive and transmit buffers, and so caps how large a request the agent
accepts and how large a response it produces.
`CONFIG_SNMP_AGENT_TRAP_DESTINATIONS` sets how many managers the agent can
send traps to.

Request handling runs on Zephyr's shared socket service thread, so
`CONFIG_NET_SOCKETS_SERVICE_STACK_SIZE` may need raising.

The library includes `<app_version.h>`, and Zephyr generates that header only
when the application directory contains a `VERSION` file. Add one if your
application does not have it yet:

```
VERSION_MAJOR = 0
VERSION_MINOR = 1
PATCHLEVEL = 0
VERSION_TWEAK = 0
EXTRAVERSION =
```

## API

| Header                                             | Contents                                                                                              |
| -------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `lwip/apps/snmp_zephyr.h`                          | `snmp_zephyr_init()`, `snmp_recv_packet()`, `snmp_prepare_trap_test()`, `print_oid()`, `zephyr_log()` |
| `lwip/apps/snmp.h`                                 | Agent configuration, community strings, trap destinations, trap sending                               |
| `lwip/apps/snmp_callback.h`                        | `install_snmp_handler()` for per-OID callbacks                                                        |
| `lwip/apps/snmp_mib2.h`                            | Setters for the MIB-2 system group                                                                    |
| `lwip/apps/snmp_core.h`, `lwip/apps/snmp_scalar.h` | Node and MIB definition macros for private MIBs                                                       |

The agent does not create a thread of its own. A Zephyr socket service reads
incoming datagrams and calls the handler passed to `snmp_zephyr_init()`. That
handler runs on the socket service thread and should do nothing more than
forward the packet id to the application thread that owns the agent. That
thread then calls `snmp_recv_packet()`, which parses the request and sends the
reply. Keeping every call into the library on one thread removes the need for
locking.

## Examples

### Running the agent

The application below waits for an IPv4 address, starts the agent, and then
serves requests from a single thread. The library holds two receive buffers,
so the application thread should stay responsive.

```c
#include <zephyr/kernel.h>
#include <zephyr/net/net_if.h>

#include <lwip/apps/snmp_opts.h>
#include <lwip/apps/snmp.h>
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

	printk("SNMP: agent listening on port 161\n");

	while (true) {
		if (k_msgq_get(&snmp_queue, &packet_id, K_FOREVER) == 0) {
			snmp_recv_packet(packet_id);
		}
	}
}

K_THREAD_DEFINE(snmp_tid, SNMP_THREAD_STACK_SIZE, snmp_thread,
		NULL, NULL, NULL, SNMP_THREAD_PRIORITY, 0, 0);
```

### Describing the device

The MIB-2 system group returns compile time defaults until the application
provides its own storage. A writable field needs a buffer, a length variable
and the buffer size. A read-only field needs only the string and its length.

```c
#include <lwip/apps/snmp_mib2.h>

static const u8_t sys_descr[] = "Example gateway";
static const u16_t sys_descr_len = sizeof(sys_descr) - 1;

static u8_t sys_name[32] = "gateway-01";
static u16_t sys_name_len = 10;

static u8_t sys_location[64] = "building 2, rack 4";
static u16_t sys_location_len = 18;

static u8_t sys_contact[64] = "ops@example.com";
static u16_t sys_contact_len = 15;

static void snmp_describe_device(void)
{
	snmp_mib2_set_sysdescr(sys_descr, &sys_descr_len);
	snmp_mib2_set_sysname(sys_name, &sys_name_len, sizeof(sys_name));
	snmp_mib2_set_syslocation(sys_location, &sys_location_len,
				  sizeof(sys_location));
	snmp_mib2_set_syscontact(sys_contact, &sys_contact_len,
				 sizeof(sys_contact));
}
```

Call this from the SNMP thread, right after `snmp_zephyr_init()`. Use
`snmp_mib2_set_sysname_readonly()` and its companions when a manager should
not be able to change the value.

### Community strings

The defaults are `public` for reads, `private` for writes and `public` for
traps. The strings have to remain valid for as long as the agent runs, so use
string literals or static buffers.

```c
#include <lwip/apps/snmp.h>

snmp_set_community("plant-floor");
snmp_set_community_write("plant-floor-rw");
snmp_set_community_trap("plant-floor");
```

### Serving a value with a callback

Callbacks are the lightest way to attach live data to an OID. Each entry
matches a prefix and returns an integer, which the agent encodes using the
type of the matching MIB node. A prefix matches either literally or up to a
trailing `*`, so both `1.3.6.1.4.1.12345.1.2.` and `1.3.6.1.4.1.12345.1.2.*`
match every OID below that point. The entry is linked into a list inside the
library, so it needs static lifetime.

```c
#include <stdlib.h>
#include <string.h>

#include <lwip/apps/snmp_callback.h>

static int handle_uptime(const char *oid, struct snmp_handler_entry *entry)
{
	ARG_UNUSED(oid);
	ARG_UNUSED(entry);

	return (int)(k_uptime_get() / 1000);
}

static int handle_sensor(const char *oid, struct snmp_handler_entry *entry)
{
	/* The full OID arrives as text, including the instance suffix, for
	 * example "1.3.6.1.4.1.12345.1.2.3.0". Skipping the literal part of
	 * the prefix leaves the sensor index.
	 */
	const char *suffix = oid + strlen(entry->prefix) - 1;
	int index = (int)strtoul(suffix, NULL, 10);

	return sensor_read_milli_celsius(index);
}

static struct snmp_handler_entry uptime_entry = {
	.handler = handle_uptime,
	.prefix = "1.3.6.1.4.1.12345.1.1.0",
};

static struct snmp_handler_entry sensor_entry = {
	.handler = handle_sensor,
	.prefix = "1.3.6.1.4.1.12345.1.2.*",
};

static void snmp_install_callbacks(void)
{
	install_snmp_handler(&uptime_entry);
	install_snmp_handler(&sensor_entry);
}
```

Callbacks run after the agent has located the OID in a registered MIB, so the
OID has to exist in the tree. Use them to serve values for MIB-2 nodes, or for
nodes of a private MIB such as the one below. Entries are searched in
installation order and the first match wins, so install the most specific
prefixes first.

### Adding a private MIB

For OIDs outside MIB-2, describe the tree with the node macros and register it
with `snmp_set_mibs()`. The example places two read-only scalars under the
enterprise OID `1.3.6.1.4.1.12345`. Replace that number with the enterprise
number assigned to your organization.

```c
#include <lwip/apps/snmp.h>
#include <lwip/apps/snmp_core.h>
#include <lwip/apps/snmp_mib2.h>
#include <lwip/apps/snmp_scalar.h>

static s16_t get_uptime(struct snmp_node_instance *instance, void *value)
{
	u32_t *result = (u32_t *)value;

	ARG_UNUSED(instance);
	*result = (u32_t)(k_uptime_get() / 1000);

	return sizeof(*result);
}

static s16_t get_temperature(struct snmp_node_instance *instance, void *value)
{
	s32_t *result = (s32_t *)value;

	ARG_UNUSED(instance);
	*result = sensor_read_milli_celsius(0);

	return sizeof(*result);
}

/* .1.3.6.1.4.1.12345.1.1.0 and .1.3.6.1.4.1.12345.1.2.0 */
static const struct snmp_scalar_node uptime_node =
	SNMP_SCALAR_CREATE_NODE_READONLY(1, SNMP_ASN1_TYPE_GAUGE, get_uptime);
static const struct snmp_scalar_node temperature_node =
	SNMP_SCALAR_CREATE_NODE_READONLY(2, SNMP_ASN1_TYPE_INTEGER,
					 get_temperature);

static const struct snmp_node *const device_group_nodes[] = {
	&uptime_node.node.node,
	&temperature_node.node.node,
};

/* The device group, .1 below the enterprise OID. */
static const struct snmp_tree_node device_group =
	SNMP_CREATE_TREE_NODE(1, device_group_nodes);

static const struct snmp_node *const private_mib_nodes[] = {
	&device_group.node,
};

/* Matching starts at the base OID, so the identifier of the root node itself
 * is not used. MIB-2 follows the same pattern.
 */
static const struct snmp_tree_node private_mib_root =
	SNMP_CREATE_TREE_NODE(1, private_mib_nodes);

static const u32_t private_mib_base_oid[] = { 1, 3, 6, 1, 4, 1, 12345 };
static const struct snmp_mib private_mib =
	SNMP_MIB_CREATE(private_mib_base_oid, &private_mib_root.node);

/* Keep mib2 in the list so the standard tree stays available. */
static const struct snmp_mib *device_mibs[] = { &mib2, &private_mib };

static void snmp_register_private_mib(void)
{
	snmp_set_mibs(device_mibs, LWIP_ARRAYSIZE(device_mibs));
}
```

### Sending traps

Configure the destination once, then send traps from the SNMP thread so that
requests and traps never overlap.

```c
#include <arpa/inet.h>

#include <lwip/apps/snmp.h>

static void snmp_configure_traps(const char *manager_ip)
{
	ip_addr_t dst;

	dst.addr = inet_addr(manager_ip);   /* network byte order */

	snmp_set_default_trap_version(SNMP_VERSION_2c);
	snmp_trap_dst_ip_set(0, &dst);
	snmp_trap_dst_enable(0, true);
}

static void snmp_report_link_up(void)
{
	snmp_send_trap_generic(SNMP_GENTRAP_LINKUP);
}
```

`snmp_prepare_trap_test("192.168.2.11")` from `snmp_zephyr.h` performs the
same three configuration calls, which is convenient while bringing a board up.

An enterprise specific trap carries its own variable bindings. The value and
the varbind stay in scope until the call returns.

```c
#include <string.h>

static void snmp_report_over_temperature(s32_t milli_celsius)
{
	static const u32_t temperature_oid[] = {
		1, 3, 6, 1, 4, 1, 12345, 1, 2, 0
	};
	struct snmp_varbind varbind;
	s32_t value = milli_celsius;

	memset(&varbind, 0, sizeof(varbind));
	snmp_oid_assign(&varbind.oid, temperature_oid,
			LWIP_ARRAYSIZE(temperature_oid));
	varbind.type = SNMP_ASN1_TYPE_INTEGER;
	varbind.value_len = sizeof(value);
	varbind.object_value = &value;

	/* Specific trap 1 of this device, as defined by your own MIB. */
	snmp_send_trap_specific(1, &varbind);
}
```

`SNMP_TRAP_DESTINATIONS` in `snmp_opts.h` sets how many managers can be
configured, and defaults to one.

### Testing from a host

With `net-snmp` installed on a machine on the same network:

```sh
# Read the system description of a board at 192.168.2.17
snmpget -v2c -c public 192.168.2.17 1.3.6.1.2.1.1.1.0

# Read a value served by the private MIB
snmpget -v2c -c public 192.168.2.17 1.3.6.1.4.1.12345.1.1.0

# Walk the whole tree, which exercises every node the agent publishes
snmpwalk -v2c -c public 192.168.2.17 1

# Watch for incoming traps
sudo snmptrapd -f -Lo -c /dev/null
```

## Notes and current limitations

- Callbacks return an `int`, so they serve integer valued types such as
  `INTEGER`, `Gauge32`, `Counter32` and `TimeTicks`. Use a private MIB node
  with a `get_value` method for strings and other types.
- Requests are received into a 96 byte buffer, which suits the get, getnext
  and small getbulk requests that managers normally send.
- The agent binds IPv4 sockets on ports 161 and 162.
- SNMPv3 sources are included but the feature is disabled in this port
  (`LWIP_SNMP_V3` is 0).
- Call the library from a single thread. `snmp_recv_packet()`, the trap calls
  and the configuration setters all share the same internal state.

## License

BSD-3-Clause, inherited from lwIP. See [LICENSE](LICENSE).
