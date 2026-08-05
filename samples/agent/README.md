# SNMP agent sample

A minimal application that starts the SNMP agent, sets the MIB-2 system
group fields, and serves requests on UDP port 161. The agent runs on
Zephyr's shared socket service thread, so the application only has to start
it and describe the device.

## Building

The sample adds its parent repository to `ZEPHYR_EXTRA_MODULES` itself, so
it builds from any Zephyr workspace without a manifest entry:

```sh
west build -b native_sim path/to/zephyr-snmp/samples/agent
```

It also builds for real boards with an Ethernet interface; adjust the
static address configuration in `prj.conf` (or replace it with DHCP) to
match your network.

## Running on native_sim

The simulator connects to the host through the `zeth` TAP interface from
Zephyr's [net-tools](https://github.com/zephyrproject-rtos/net-tools),
which needs root to create:

```sh
git clone https://github.com/zephyrproject-rtos/net-tools
sudo net-tools/net-setup.sh start
```

Then run the sample and query it from the host:

```sh
./build/zephyr/zephyr.exe
```

```sh
# System description
snmpget -v2c -c public 192.0.2.1 1.3.6.1.2.1.1.1.0

# Walk everything the agent publishes
snmpwalk -v2c -c public 192.0.2.1 1
```

When finished, `sudo net-tools/net-setup.sh stop` removes the interface.
