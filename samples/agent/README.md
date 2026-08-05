# SNMP agent sample

A minimal application that starts the SNMP agent, sets the MIB-2 system
group fields, and serves requests on UDP port 161. The agent runs on
Zephyr's shared socket service thread, so the application only has to start
it and describe the device.

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
