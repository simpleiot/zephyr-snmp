# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [unreleased]

- make the host network stack the documented default for running the sample on
  native_sim, since it needs neither root nor a TAP interface, and describe the
  zeth route as the alternative for exercising the interfaces group against
  Zephyr's own stack
- print the address the sample is actually reachable at on startup. It always
  named 192.0.2.1 on port 161, which was wrong whenever the agent was built
  with `overlay-host.conf` or a non-default port
- stop creating the zeth TAP interface in `overlay-host.conf` builds. Nothing
  reaches the network through it once sockets are offloaded, so it only logged
  a failure to create it at boot; `ifNumber` in that configuration is now 1
- fix the SNMPv2c trap OID, which named the wrong notification: for a generic
  trap the last sub-identifier was built from the specific-trap parameter,
  which `snmp_send_trap_generic()` always passes as 0, so every generic trap
  reached the manager as `coldStart`
- fix a use-after-scope in the trap path: the `snmpTrapOID` value was built in
  a block-scoped variable whose address was still referenced by the varbind
  list when the message was encoded, further down the same function
- stop rewriting the caller's varbind list when sending a trap. The agent
  prepended its two special varbinds by pointing the caller's `prev` at a
  local array and then putting the old value back, which published the
  address of a stack frame into memory the application owns and cleared that
  pointer outright when the trap OID could not be prepared. Varbind lists are
  only ever walked forward, so `struct snmp_varbind` loses its `prev` field
  entirely. Applications that fill a varbind field by field need no change;
  those using positional initializers drop the second element
- add SPDX identifiers throughout, keeping the lwIP copyright blocks that the
  BSD-3-Clause license requires, and give the public headers Zephyr-style
  include guards

- document the module in README.md: adding it to a project, configuration, and
  usage examples for the agent thread, MIB-2 system group, OID callbacks,
  private MIBs, and traps
- add samples/agent, a runnable agent application for native_sim and real
  boards, discoverable by twister through zephyr/module.yml
- fix the build against Zephyr 4.4 by using the namespaced socket types
  (struct zsock_pollfd, ZSOCK_POLLIN) in snmp_zephyr.c
- adopt Zephyr's .clang-format, .checkpatch.conf, and .editorconfig
- remove code that was never reachable in this port: the SNMPv3 and USM
  sources, the lwIP netconn and raw transports, thread synchronization, the
  MIB-2 icmp and tcp groups, and the conditional regions that selected them
- rename `CONFIG_LIB_SNMP` to `CONFIG_SNMP_AGENT`, which now depends on
  `NET_IPV4` and `NET_UDP` and selects the socket options the agent needs
- replace `CONFIG_SNMP_LOG_LEVEL`, which nothing read, with the standard
  networking log template: `CONFIG_SNMP_AGENT_LOG_LEVEL` filters the
  `net_snmp_agent` module
- add `CONFIG_SNMP_AGENT_MAX_MSG_SIZE`, `CONFIG_SNMP_AGENT_TRAP_DESTINATIONS`,
  `CONFIG_SNMP_AGENT_PORT`, and `CONFIG_SNMP_AGENT_TRAP_PORT` in place of the
  buffer sizes and port numbers that were compiled in
- log through `LOG_ERR`, `LOG_WRN`, `LOG_INF`, and `LOG_DBG` at levels that
  suit each message, replacing the `zephyr_log()` wrapper that shared one
  static buffer and reported everything at info level
- give `print_oid()` a caller-supplied buffer, as `snmp_oid_to_str()`; the
  shared static buffer it used before returned the same storage when a single
  log statement rendered two OIDs
- process requests in the socket service callback instead of handing packet
  ids to an application thread. `snmp_zephyr_init()`, `snmp_recv_packet()`,
  and the `recv_packet_handler` contract are replaced by
  `net_snmp_agent_start()` and `net_snmp_agent_stop()`, which return 0 or a
  negative errno. Applications no longer supply a thread, a message queue, or
  a callback
- fix a race in the receive path: two static slots were filled by the socket
  service thread with no synchronization, so a burst of datagrams could
  overwrite a slot the application thread was still reading
- serialize agent state with a mutex taken by the socket service callback and
  by every public entry point, which removes the "call everything from one
  thread" rule
- rename `snmp_prepare_trap_test()` to `net_snmp_agent_trap_dst_set()`, which
  now parses the address and reports a failure to
- bind a single IPv4 socket on port 161 and send traps from it. The port 162
  socket is gone; an agent needs 162 only to receive, which is the manager's
  role
- fix the socket setup, which created an `AF_INET` socket but filled in a
  `struct sockaddr_in6`, bound with the IPv6 length, and queried
  `IPV6_V6ONLY` on it
- fix `lwip_htons()` and friends, which expanded to identity macros: the
  `#if BYTE_ORDER == BIG_ENDIAN` test compared two undefined names, so it was
  always true. They now use Zephyr's `net_htons()` family
- drop the dependency on `CONFIG_POSIX_API` by using the namespaced
  networking API throughout, and the `VERSION` file requirement by dropping
  an `<app_version.h>` include that nothing used
- back the MIB-2 `interfaces` group with Zephyr's own data: `net_if_foreach()`
  and the interface accessors supply ifNumber and ifTable, including names,
  link type, MTU, hardware address, and admin and operational status, with the
  counters coming from `net_stats` when `CONFIG_NET_STATISTICS_PER_INTERFACE`
  is enabled. It previously walked lwIP's `netif_list`, which this port never
  populated, so ifNumber was always 0 and ifTable always empty
- drop the MIB-2 `ip` and `udp` groups, whose every scalar read an lwIP global
  that this port never populated and so reported zero. Reporting nothing is
  more accurate than reporting a wrong zero; they can return backed by
  `net_stats` and `net_context_foreach()`
- replace lwIP's short types with the fixed-width names Zephyr uses
  (`u8_t` becomes `uint8_t` and so on); they had been typedef'd in three
  places at once. `err_t` becomes plain `int`, keeping the `ERR_*` codes
- turn `LWIP_ASSERT` into `__ASSERT` and `LWIP_DEBUGF` into `LOG_DBG`. Every
  assertion guards a caller contract rather than anything a peer can provoke
- move the public headers from `lwip/apps/` to `snmp/`, since an out-of-tree
  module should not claim another project's include namespace, and rename
  `snmp_zephyr.h` to `snmp_agent.h`. `opt.h`, `def.h`, `err.h`, `arch.h`, and
  `arch/cc.h` collapse into a private `src/snmp_priv.h`
- fix `snmp_private_call_handler()` reading `prefix[mlength - 1]` when
  `mlength` was 0, which ran off the front of the string whenever the first
  character already differed
- make `oid_names[]` static; it was a global with a name likely to collide
- apply Zephyr's `.clang-format` and clear checkpatch's errors
- gate the published groups with `CONFIG_SNMP_AGENT_MIB2_SYSTEM`,
  `CONFIG_SNMP_AGENT_MIB2_INTERFACES`, and `CONFIG_SNMP_AGENT_MIB2_SNMP`
- back `snmp_pbuf_stream` with a flat buffer cursor and delete `src/pbuf.c`,
  `lwip/pbuf.h`, and the `mem`/`memp` headers and stubs. Messages are encoded
  into static buffers of `CONFIG_SNMP_AGENT_MAX_MSG_SIZE` bytes, one for
  responses and one for traps, so nothing is allocated per packet and
  `CONFIG_HEAP_MEM_POOL_SIZE` is no longer required
- use `struct net_in_addr` in place of lwIP's `ip_addr_t` and `ip4_addr_t`,
  including in the public `snmp_trap_dst_ip_set()` and the OID conversion
  helpers, and delete `lwip/ip_addr.h`, `ip4_addr.h`, `ip6_addr.h`, `ip.h`,
  `netif.h`, `udp.h`, `stats.h`, `sys.h`, `snmp.h`, and `arch/sys_arch.h`
  along with the never-populated `netif_list`, `udp_pcbs`, and `lwip_stats`
  globals that stood in for them

## [v0.0.6] - 2025-05-08

- remove circular reference

## [v0.0.5] - 2025-05-01

- fix compile issues

## [v0.0.4] - 2025-04-30

- mib2 entries

## [v0.0.3] - 2025-04-23

- remove app compiler flags as this was leaking into the main application compile

## [v0.0.2] 2025-04-23

- move to a callback for SNMP get requests

## [v0.0.1] 2025-04-27

- Tested the MIB's and library by running an SNMP walk. This command iterates through all entries, starting at a certain point, eg. '1':
  Command: `snmpwalk -v2c -c public 192.168.2.17 1`
  It provides an interesting extra test.

## 2025-04-24

- #10 from remove_compiler_warning_changes
- Remove the compiler warning from CMakeList.txt

## 2025-04-22

- #9 from Start_using_socket_service
- The SNMP port started using the Zephyr socket services
- This makes it possible to have the SNMP thread sleep in a central place and with the `K_FOREVER` parameter.
- The socket services will pass UDP data to the SNMP thread, which will execute the commands and give a reply. The sending of traps happens in the same thread, thus avoiding things like: race conditions, data races, deadlocks and synchronisation errors.
- And also in this big PR: a call-back system was developed.

## 2025-03-13

- #8 from Worked_on_snmp_zephyr
- Removed the check about the network, added snmp_zephyr.h

## 2025-03-13

- #7 from assume_network_ready_while_init
- Assume that the zephyr network is up-and-running at start-up. Until now this seems to work OK.

## 2025-02-25

- #6 from pass_address_network_endian
- Pass the SNMP trap port number and IP-address in network-endian format

## 2025-01-29

- #5 from More_logging_more_tested
- Tested sending traps, also tested the new functions in snmp_zephyr.c

## 2025-01-15

- #3 from Better_logging_snmp_zephyr
- Made logging better by showing request OID (Object ID) of requests.

## 2025-01-06

- PR #1 from added_header_files
- Added the necessary header files from the latest lwIP release, also started to port the software for Zypher, using it native IP-stack.
- Adapted opt.h to make things compiling and running.
- TODO: porting code should appear in lwipopts.h
