# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [unreleased]

## [v0.1.0] - 2026-08-05

The agent now runs on Zephyr's own primitives throughout: Zephyr sockets, the
socket service, `net_if`, and `net_stats`, with no lwIP code or compatibility
headers left underneath. The public API, the header paths, and the Kconfig
names all changed along the way, so applications built against 0.0.x need
updating. Zephyr 4.4 or newer is required.

### Added

- `net_snmp_agent_start()` and `net_snmp_agent_stop()`, which return 0 or a
  negative errno and process requests in the socket service callback.
  Applications no longer supply a thread, a message queue, or a callback;
  `snmp_zephyr_init()`, `snmp_recv_packet()`, and the `recv_packet_handler`
  contract are gone.
- A mutex taken by the socket service callback and by every public entry point,
  which removes the "call everything from one thread" rule.
- `samples/agent`, a runnable application for native_sim and real boards,
  discoverable by twister. It sends a cold start trap and then a periodic
  enterprise-specific trap to `CONFIG_SAMPLE_TRAP_MANAGER`, installs a write
  callback that prints each value a manager changes, prints the address it is
  reachable at and an `snmpset` command to try, and ships an
  `overlay-host.conf` that runs it against the host network stack without root
  or a TAP interface.
- `README.md`, covering how to add the module to a project, configuration, the
  MIB-2 system group, OID callbacks, private MIBs, traps, reacting to writes
  with `snmp_set_write_callback()`, the community strings, and which Zephyr
  release each version of the module supports.
- Kconfig for what used to be compiled in: `CONFIG_SNMP_AGENT_MAX_MSG_SIZE`,
  `CONFIG_SNMP_AGENT_TRAP_DESTINATIONS`, `CONFIG_SNMP_AGENT_PORT`,
  `CONFIG_SNMP_AGENT_TRAP_PORT`, and `CONFIG_SNMP_AGENT_MIB2_SYSTEM`,
  `_INTERFACES`, and `_SNMP` to gate the published groups.
- A GitHub release published when a `v*` tag is pushed, with the body taken
  from this file by `scripts/extract-changelog.sh`. Nothing is built, since the
  module compiles only as part of an application; move the `[unreleased]`
  heading to `[vX.Y.Z] - <date>` before tagging so the notes have a section to
  come from.
- Continuous integration that builds both sample configurations through
  twister and gates on checkpatch, plus a `west.yml` so a workspace can be
  built around a checkout of the module.
- SPDX identifiers throughout, keeping the lwIP copyright blocks that the
  BSD-3-Clause license requires, and Zephyr-style include guards on the public
  headers.

### Changed

- Public headers move from `lwip/apps/` to `snmp/`, since an out-of-tree module
  should not claim another project's include namespace, and `snmp_zephyr.h`
  becomes `snmp_agent.h`. `opt.h`, `def.h`, `err.h`, `arch.h`, and `arch/cc.h`
  collapse into a private `src/snmp_priv.h`.
- `snmp_prepare_trap_test()` becomes `net_snmp_agent_trap_dst_set()`, which now
  parses the address and reports a failure to do so.
- `CONFIG_LIB_SNMP` becomes `CONFIG_SNMP_AGENT`, which depends on `NET_IPV4`
  and `NET_UDP` and selects the socket options the agent needs.
  `CONFIG_SNMP_LOG_LEVEL`, which nothing read, becomes
  `CONFIG_SNMP_AGENT_LOG_LEVEL`, filtering the `net_snmp_agent` module.
- lwIP's short types give way to the fixed-width names Zephyr uses (`u8_t`
  becomes `uint8_t` and so on); they had been typedef'd in three places at
  once. `err_t` becomes plain `int`, keeping the `ERR_*` codes; `ip_addr_t` and
  `ip4_addr_t` become `struct net_in_addr`, including in the public
  `snmp_trap_dst_ip_set()`; `LWIP_ASSERT` becomes `__ASSERT` and `LWIP_DEBUGF`
  becomes `LOG_DBG`.
- The MIB-2 `interfaces` group is backed by Zephyr's own data: `net_if_foreach()`
  and the interface accessors supply ifNumber and ifTable, including names, link
  type, MTU, hardware address, and admin and operational status, with counters
  from `net_stats` when `CONFIG_NET_STATISTICS_PER_INTERFACE` is enabled. It
  previously walked lwIP's `netif_list`, which this port never populated, so
  ifNumber was always 0 and ifTable always empty.
- `snmp_pbuf_stream` is backed by a flat buffer cursor. Messages are encoded
  into static buffers of `CONFIG_SNMP_AGENT_MAX_MSG_SIZE` bytes, one for
  responses and one for traps, so nothing is allocated per packet and
  `CONFIG_HEAP_MEM_POOL_SIZE` is no longer required.
- A single IPv4 socket on port 161 both answers requests and sends traps. The
  port 162 socket is gone; an agent needs 162 only to receive, which is the
  manager's role.
- Logging goes through `LOG_ERR`, `LOG_WRN`, `LOG_INF`, and `LOG_DBG` at levels
  that suit each message, replacing the `zephyr_log()` wrapper that shared one
  static buffer and reported everything at info level. `print_oid()` becomes
  `snmp_oid_to_str()` with a caller-supplied buffer, since the shared static it
  used before returned the same storage when one log statement rendered two
  OIDs. `oid_names[]` is now static rather than a global with a name likely to
  collide.
- `CMakeLists.txt` checks for Zephyr 4.4 and fails with a message naming the
  requirement, rather than a wall of compile errors: the module builds on the
  namespaced networking API that arrived in that release, and
  `zephyr/module.yml` has no field for a kernel version.
- The sample documents the host network stack as the default way to run on
  native_sim, since it needs neither root nor a TAP interface, with the zeth
  route as the alternative for exercising the interfaces group against Zephyr's
  own stack.
- Zephyr's `.clang-format`, `.checkpatch.conf`, and `.editorconfig` are adopted
  and the sources are clean under both tools. The style-only changes cover
  block comments, blank lines after declarations, `//` comment removals,
  `sizeof` parentheses, and guard-clause rewrites replacing `else` after a
  `return` or `break`; a full walk plus get, get-next, get-bulk, set, and
  error-path probes return byte-identical results before and after. The ASN.1
  codec keeps its error-propagation macros, with `MACRO_WITH_FLOW_CONTROL`
  recorded in `.checkpatch.conf` as a deliberate exception rather than
  reworking roughly 150 call sites.

### Removed

- Code that was never reachable in this port: the SNMPv3 and USM sources, the
  lwIP netconn and raw transports, thread synchronization, the MIB-2 icmp and
  tcp groups, and the conditional regions that selected them.
- The MIB-2 `ip` and `udp` groups, whose every scalar read an lwIP global that
  this port never populated and so reported zero. Reporting nothing is more
  accurate than reporting a wrong zero; they can return backed by `net_stats`
  and `net_context_foreach()`.
- `src/pbuf.c`, `lwip/pbuf.h`, the `mem` and `memp` headers and stubs, and
  `lwip/ip_addr.h`, `ip4_addr.h`, `ip6_addr.h`, `ip.h`, `netif.h`, `udp.h`,
  `stats.h`, `sys.h`, `snmp.h`, and `arch/sys_arch.h`, along with the
  never-populated `netif_list`, `udp_pcbs`, and `lwip_stats` globals that stood
  in for real data.
- The dependency on `CONFIG_POSIX_API`, by using the namespaced networking API
  throughout, and the `VERSION` file requirement, by dropping an
  `<app_version.h>` include that nothing used.
- The zeth TAP interface in `overlay-host.conf` builds. Nothing reaches the
  network through it once sockets are offloaded, so it only logged a failure to
  create it at boot; `ifNumber` in that configuration is now 1.
- The migration notes for the 0.0.x series.

### Fixed

- Sending a trap no longer rewrites the caller's varbind list. The agent
  prepended its two special varbinds by pointing the caller's `prev` at a local
  array and then putting the old value back, which published the address of a
  stack frame into memory the application owns and cleared that pointer
  outright when the trap OID could not be prepared. Varbind lists are only ever
  walked forward, so `struct snmp_varbind` loses its `prev` field entirely.
  Applications that fill a varbind field by field need no change; those using
  positional initializers drop the second element.
- A use-after-scope in the trap path, where the `snmpTrapOID` value was built
  in a block-scoped variable whose address was still referenced by the varbind
  list when the message was encoded, further down the same function.
- The SNMPv2c trap OID, which named the wrong notification: for a generic trap
  the last sub-identifier was built from the specific-trap parameter, which
  `snmp_send_trap_generic()` always passes as 0, so every generic trap reached
  the manager as `coldStart`.
- A race in the receive path, where two static slots were filled by the socket
  service thread with no synchronization, so a burst of datagrams could
  overwrite a slot the application thread was still reading.
- The socket setup, which created an `AF_INET` socket but filled in a
  `struct sockaddr_in6`, bound with the IPv6 length, and queried `IPV6_V6ONLY`
  on it. The build against Zephyr 4.4 is fixed alongside it, by using the
  namespaced socket types (`struct zsock_pollfd`, `ZSOCK_POLLIN`).
- `lwip_htons()` and friends, which expanded to identity macros because the
  `#if BYTE_ORDER == BIG_ENDIAN` test compared two undefined names and was
  always true. They now use Zephyr's `net_htons()` family.
- `snmp_private_call_handler()` reading `prefix[mlength - 1]` when `mlength` was
  0, which ran off the front of the string whenever the first character already
  differed.
- The sample's startup message, which always named 192.0.2.1 on port 161. That
  was wrong whenever the agent was built with `overlay-host.conf` or a
  non-default port.

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
