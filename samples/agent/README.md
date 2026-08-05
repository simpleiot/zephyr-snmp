# SNMP agent sample

A minimal application that starts the SNMP agent, sets the MIB-2 system
group fields, and serves requests on UDP port 161. The agent runs on
Zephyr's shared socket service thread, so the application only has to start
it and describe the device. It also sends traps, so a manager has something
to receive.

## Running on native_sim

`overlay-host.conf` builds the sample against the host's own network stack,
so it needs neither root nor a TAP interface. This is the quickest way to
exercise the agent, and the recommended one:

```sh
west build -b native_sim path/to/zephyr-snmp/samples/agent \
	-- -DEXTRA_CONF_FILE=overlay-host.conf
./build/zephyr/zephyr.exe &
```

The sample prints the address to query on startup. Ports 161 and 162 are
privileged, so this configuration moves the agent to 1161 and 1162:

```sh
# System description
snmpget -v2c -c public localhost:1161 1.3.6.1.2.1.1.1.0

# Walk everything the agent publishes
snmpwalk -v2c -c public localhost:1161 1
```

The overlay works by offloading sockets: the application's socket calls go
straight to the host rather than through Zephyr's IP stack. Two things
follow from that. The interfaces table describes the offloaded pseudo
interface rather than a real Ethernet one, so `ifNumber` is 1 and the
per-interface counters stay at zero. And because the host does the
addressing, `CONFIG_NET_CONFIG_*` has no effect here.

To exercise the interfaces group against Zephyr's own stack, use the TAP
interface described below.

## Setting values

`sysName`, `sysLocation` and `sysContact` are writable, because
`snmp_describe_device()` registers each of them with the size of its buffer.
`sysDescr` passes no buffer size and stays read-only.

Writes are checked against the write community, which is a different string
from the one reads use and defaults to `private`:

```sh
snmpset -v2c -c private localhost:1161 1.3.6.1.2.1.1.6.0 s "rack 4"
snmpget -v2c -c public  localhost:1161 1.3.6.1.2.1.1.6.0
```

A request carrying the wrong community is discarded without a reply, which
is what RFC 1157 asks for, so `snmpset -c public` reports a timeout rather
than an error. The agent counts the attempt in `snmpInBadCommunityNames`:

```sh
snmpget -v2c -c public localhost:1161 1.3.6.1.2.1.11.4.0
```

It also sends an authentication failure trap, though only once those are
enabled. They are off until the application calls
`snmp_set_auth_traps_enabled(SNMP_AUTH_TRAPS_ENABLED)` or a manager writes
`snmpEnableAuthenTraps`. `snmp_set_community_write()` changes the write
community, and setting it to `""` makes every object read-only.

The sample installs a write callback, so it prints each value a manager
changes:

```
SNMP: sysLocation is now 'rack 4'
```

The agent copies the new value into the application's buffer before calling
back, which is where a real device would persist it. The callback receives
the OID rather than the value, so the application looks at whichever
variable that OID stands for. It runs once per variable binding, on the
socket service thread that handled the request.

Objects the agent implements itself are writable too. The callback still
runs for them, so an application that only tracks its own variables needs a
final branch for the rest:

```sh
snmpset -v2c -c private localhost:1161 1.3.6.1.2.1.11.30.0 i 2   # disable authen traps
```

Writing a read-only object returns `notWritable` and changes nothing. When
one variable binding in a request fails, none of them are applied: the agent
tests every binding before committing any.

## Receiving traps

The sample sends a cold start trap once the agent is running, then an
enterprise-specific trap every `CONFIG_SAMPLE_TRAP_PERIOD_SECONDS`. Start a
manager before the sample to catch the first one. `snmptrapd` needs no root
on the unprivileged port this configuration uses:

```sh
snmptrapd -f -Lo -c /dev/null 1162
```

```
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (0) 0:00:00.00
	SNMPv2-MIB::snmpTrapOID.0 = OID: SNMPv2-MIB::coldStart
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (501) 0:00:05.01
	SNMPv2-MIB::snmpTrapOID.0 = OID: SNMPv2-SMI::enterprises.62530.1
	SNMPv2-SMI::enterprises.62530.1.1.0 = INTEGER: 5
```

The second trap carries a variable binding, which is the part worth copying
into a real application: `snmp_send_trap_specific()` takes a list of them,
and the values only have to stay in scope until the call returns. Its
subidentifiers come from the enterprise the agent publishes as `sysObjectID`
and the specific-trap number, so a device defines both in its own MIB for a
manager to resolve the names.

Two sample options control this:

| Option                              | Default       | Meaning                              |
| ----------------------------------- | ------------- | ------------------------------------ |
| `CONFIG_SAMPLE_TRAP_MANAGER`        | `"127.0.0.1"` | Where to send traps                  |
| `CONFIG_SAMPLE_TRAP_PERIOD_SECONDS` | `10`          | Interval; 0 sends only the cold start |

Point the sample at another machine by setting the first, and give
`snmptrapd` the matching `CONFIG_SNMP_AGENT_TRAP_PORT`:

```sh
west build -b native_sim path/to/zephyr-snmp/samples/agent \
	-- -DEXTRA_CONF_FILE=overlay-host.conf \
	   -DCONFIG_SAMPLE_TRAP_MANAGER=\"192.168.2.11\"
```

Traps are sent from the calling thread rather than a thread of the agent's
own. The agent's mutex serializes them against requests arriving on the
socket service thread, so an application can send one from wherever the
event it reports is detected.

## Running on native_sim through zeth

The simulator can instead reach the network through the `zeth` TAP
interface from Zephyr's
[net-tools](https://github.com/zephyrproject-rtos/net-tools), which needs
root to create:

```sh
git clone https://github.com/zephyrproject-rtos/net-tools
sudo net-tools/net-setup.sh start
```

Build without the overlay, then run the sample and query it from the host
at the address in `prj.conf`:

```sh
west build -b native_sim path/to/zephyr-snmp/samples/agent
./build/zephyr/zephyr.exe &
snmpwalk -v2c -c public 192.0.2.1 1
```

`net-setup.sh` both creates the TAP device and gives the host its end of
the link (192.0.2.2). Creating `zeth` by hand is not enough on its own: the
driver configures only Zephyr's side, so without an address and `ip link
set zeth up` on the host, requests to 192.0.2.1 are routed out the default
interface and never arrive.

When finished, `sudo net-tools/net-setup.sh stop` removes the interface.

## Building for a real board

The sample adds its parent repository to `ZEPHYR_EXTRA_MODULES` itself, so
it builds from any Zephyr workspace without a manifest entry:

```sh
west build -b <your-board> path/to/zephyr-snmp/samples/agent
```

Any board with an Ethernet interface works; adjust the static address
configuration in `prj.conf` (or replace it with `CONFIG_NET_DHCPV4=y`) to
match your network.
