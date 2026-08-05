# Cleanup and Modernization Plan

Goal: turn this port of the lwIP SNMP agent into a clean, self-contained
Zephyr module that follows upstream Zephyr networking conventions — no lwIP
compatibility shims, no dead code, and an integration with the network stack
that matches how in-tree libraries work (reference: Zephyr 4.4 tree at
`/scratch/simpleiot/zephyr-siot/zephyr`).

Current size is ~19,000 lines. Roughly 5,500 of those compile to nothing or
are unreachable, and another ~2,000 are lwIP shim machinery that a flat-buffer
design removes. The end state should be roughly half the current size.

## 1. Architecture review

### What is right today

- **Using the socket service is the correct choice.** It is the recommended
  pattern for small UDP servers in-tree (`dhcpv4_server.c`, `llmnr_responder.c`,
  `mdns_responder.c`, zperf receivers all use it), precisely so a library does
  not need its own thread.
- The single-threaded agent core (no internal locking) is workable; it just
  needs a defined owner thread rather than pushing that job onto the
  application.

### What needs to change

1. **The receive hand-off is more complex than the problem requires, and it
   races.** Today: the socket service callback reads the datagram into one of
   two static 96-byte slots, calls an application callback with a slot index,
   the application forwards that index through its own thread and message
   queue, and `snmp_recv_packet()` later copies the slot into a heap-allocated
   pbuf for parsing. There is no synchronization on the slot array, so a
   burst of three datagrams overwrites a slot the application thread is still
   reading. The in-tree model (`dhcpv4_server_cb()` in
   `subsys/net/lib/dhcpv4/dhcpv4_server.c`) parses and replies **inline in
   the service callback** — no slots, no second thread, no copies, no
   application involvement. SNMP request handling is short and bounded, so it
   fits this model. Trap and configuration calls from application threads then
   need a mutex around agent state (see Phase 3).

2. **The library must not depend on `CONFIG_POSIX_API`.** Zephyr 4.4
   namespaced the entire networking API (`zsock_*`, `NET_AF_INET`,
   `struct net_sockaddr`, `net_htons`, `ZSOCK_POLLIN`, …) and net headers no
   longer include POSIX headers. In-tree libraries use the namespaced forms
   exclusively; only applications may opt into POSIX names. The
   `inet_addr()`/`inet_ntoa()` calls become `net_addr_pton()`/
   `net_addr_ntop()`.

3. **The pbuf layer should be replaced with a flat buffer cursor.** In-tree
   protocol libraries parse and build messages in plain byte arrays
   (`dhcpv4_server.c` uses a stack buffer; CoAP uses
   `struct coap_packet { uint8_t *data; uint16_t offset; uint16_t max_len; }`
   over a static Kconfig-sized buffer). Heap allocation per packet is not the
   house style, and this agent's needs are simple: one receive buffer, one
   transmit buffer, both bounded. `snmp_pbuf_stream.c` already isolates the
   agent core from pbuf details, so it becomes the seam: keep its API, back
   it with `{ uint8_t *data; size_t max_len; size_t offset; }`.

4. **The library should never block waiting for the network.** Binding UDP
   sockets to `INADDR_ANY` works before an address is assigned, so the
   wait-for-IPv4 loop in the README example is unnecessary for serving
   requests. In-tree libraries register `net_mgmt` event callbacks
   (`NET_EVENT_IPV4_ADDR_ADD`, `NET_EVENT_L4_CONNECTED`) when they need to
   react to readiness; applications that gate startup use conn_mgr. The
   library provides `start()`/`stop()` and leaves timing to the caller.

5. **MIB-2 is mostly hollow and must either be wired to Zephyr or trimmed.**
   Only the `system` and `snmp` groups return real data. The `interfaces`,
   `ip`, and `udp` groups iterate lwIP globals (`netif_list`, `lwip_stats`,
   `udp_pcbs`) that exist in this port only as never-populated link stubs, so
   they return zeros and empty tables. The `icmp` and `tcp` groups are not
   compiled at all. Zephyr has real sources for all of this: `net_if_foreach()`
   and interface properties for `interfaces`, `net_stats` /
   `CONFIG_NET_STATISTICS` for the counters, `net_context_foreach()` for the
   UDP endpoint table.

### Target architecture

```
application
    │  net_snmp_* API: start/stop, communities, trap dests,
    │  MIB registration, callback handlers, trap sends
    ▼
snmp agent core (single lock)          Zephyr's shared socket service
    ▲                                  thread (not owned by this module)
    │  parse → dispatch → encode → send     │  zsock_recvfrom into
    └───────────────────────────────────────┘  static buffer, handle inline
```

The agent contributes no thread of its own: request handling runs as a
callback on the socket service dispatcher that Zephyr already runs for all
registered services, and trap sends execute directly on the calling
application thread.

- One `NET_SOCKET_SERVICE_SYNC_DEFINE_STATIC` service owning the port 161
  socket (and 162 only if trap _reception_ is ever wanted — sending traps
  does not require a bound socket of its own; see Phase 3).
- A single mutex serializes the service callback against application-thread
  calls (traps, setters). The application no longer supplies a thread, a
  message queue, or a callback for received packets — `snmp_zephyr_init()`,
  `snmp_recv_packet()`, and the packet-id contract all disappear.
- Public API renamed to Zephyr style: `net_snmp_agent_start()` /
  `net_snmp_agent_stop()`, returning 0 or negative errno.

## 2. Phased plan

Each phase leaves the tree building and the agent answering an `snmpwalk`,
so phases can land as individual PRs.

### Phase 0 — Make the work verifiable

- Add `samples/agent/` — a minimal application (the README example, reduced)
  buildable with `west build -b native_sim` so every later phase can be
  smoke-tested on the host against `snmpget`/`snmpwalk`/`snmptrapd` via the
  net-tools TAP setup, plus any real board already in use.
- Add `samples:` (and later `tests:`) to `zephyr/module.yml` so twister can
  discover them.
- Copy `.clang-format`, `.checkpatch.conf`, and `.editorconfig` from the
  Zephyr tree. Do not reformat yet — that lands with the type sweep in
  Phase 5 to keep diffs reviewable.

### Phase 1 — Delete dead code (no behavior change)

Delete files that compile to empty translation units or are unreachable:

- V3/USM: `src/snmpv3.c`, `src/snmpv3_mbedtls.c`, `src/snmpv3_priv.h`,
  `src/snmp_snmpv2_framework.c`, `src/snmp_snmpv2_usm.c`, and headers
  `include/lwip/apps/snmpv3.h`, `snmp_snmpv2_framework.h`,
  `snmp_snmpv2_usm.h`. (SNMPv3 was never enabled; if it is ever wanted, the
  lwIP upstream remains the better starting point than carrying this dead
  weight.)
- Alternative lwIP transports: `src/snmp_netconn.c`, `src/snmp_raw.c`,
  `src/snmp_threadsync.c`, `include/lwip/apps/snmp_threadsync.h`. Note
  `snmp_threadsync.c` currently _does_ compile and calls `sys_mutex_*`
  functions that are declared but implemented nowhere — a latent link error.
- MIB-2 groups that are compiled out: `src/snmp_mib2_icmp.c`,
  `src/snmp_mib2_tcp.c`, `include/lwip/icmp.h`, `include/lwip/tcp.h`,
  `include/lwip/priv/tcp_priv.h`.
- `include/cmsis.h` (an empty shell) together with the `arch/cc.h` lines that
  include it.
- Dead declarations and helpers: `snmp_install_handlers()` (declared, never
  defined), `leafNodeName()`, the `lwip_htons`/`lwip_htonl` and
  `err_to_errno()` declarations, `mem_init`/`mem_calloc` prototypes.

Then strip conditional blocks inside surviving files: every
`#if LWIP_SNMP_V3`, `SNMP_USE_NETCONN`, `SNMP_USE_RAW`, and
`LWIP_SNMP_CONFIGURE_VERSIONS` region in `snmp_msg.c` (~620 lines),
`snmp_msg.h`, `snmp_core.c`, `snmp_mib2.c`, `snmp_opts.h`, and the matching
prototypes in `include/lwip/apps/snmp.h`. Remove the deleted files from
`CMakeLists.txt` and drop the `.h` entries listed there as sources.

Verify: build the Phase 0 sample, run `snmpwalk`, confirm identical output
before/after.

### Phase 2 — Kconfig, CMake, and logging conformance

- Kconfig: rename `LIB_SNMP` to `SNMP_AGENT` following in-tree naming
  (`config SNMP_AGENT`, `if SNMP_AGENT` … `endif # SNMP_AGENT`), with
  `depends on NET_IPV4 && NET_UDP` and
  `select NET_SOCKETS` / `select NET_SOCKETS_SERVICE`.
- Replace the hand-rolled `SNMP_LOG_LEVEL` int (currently defined in Kconfig
  but referenced nowhere — the code hardcodes `LOG_LEVEL_DBG`) with the
  standard template:

  ```kconfig
  module = SNMP_AGENT
  module-dep = NET_LOG
  module-str = Log level for SNMP agent
  source "subsys/net/Kconfig.template.log_config.net"
  ```

  and `LOG_MODULE_REGISTER(net_snmp_agent, CONFIG_SNMP_AGENT_LOG_LEVEL)`.

- Add Kconfig ints for the sizes that are magic numbers today:
  `SNMP_AGENT_MAX_MSG_SIZE` (receive/transmit buffer, replacing the 96-byte
  `MAX_BUF_LEN` and the hardcoded 1472-byte transmit allocation) and trap
  destination count. Document that `NET_SOCKETS_SERVICE_STACK_SIZE` may need
  raising, as in-tree users do.
- Remove the `zephyr_log()` wrapper (static buffer, not thread-safe, single
  hardcoded level) and route everything through `LOG_ERR`/`LOG_WRN`/
  `LOG_INF`/`LOG_DBG` at appropriate levels. `LWIP_DEBUGF` currently discards
  its category argument and logs everything at INFO; per-message levels
  restore the filtering the logging subsystem is designed for. Make
  `print_oid()` take a caller-supplied buffer (the shared static buffer
  aliases when used twice in one log statement).
- CMake: `zephyr_library_named(snmp)` and one source per line, gated on the
  new symbol.

### Phase 3 — Rework the port layer (`snmp_zephyr.c`)

- Process datagrams inline in the socket service callback, modeled directly
  on `dhcpv4_server_cb()`: fd-to-context lookup, `ZSOCK_POLLERR` check,
  `zsock_recvfrom(..., ZSOCK_MSG_DONTWAIT, ...)`, treat `EAGAIN` as normal,
  parse and reply in place. Delete the two-slot packet buffer, the packet-id
  contract, `snmp_recv_packet()`, and the `recv_packet_handler` type.
- Add `struct k_mutex` around agent state; take it in the service callback
  and in every public entry point that touches agent state (trap sends,
  community and trap-destination setters, MIB registration). This removes
  the "call everything from one thread" rule from the application contract.
- New public API in Zephyr style, 0/negative-errno returns:
  `net_snmp_agent_start()`, `net_snmp_agent_stop()` (unregister the service
  before closing sockets, matching in-tree ordering). Keep
  `snmp_prepare_trap_test()` only if still useful for bring-up, renamed and
  documented as a test helper.
- Fix the socket setup: today it creates an `AF_INET` socket, initializes a
  `struct sockaddr_in6` with `.sin6_family = AF_INET`, binds with the IPv6
  size, and queries `IPV6_V6ONLY` on it — remnants of a dual-stack attempt.
  Use `struct net_sockaddr_in` cleanly. Remove the 1 ms `SO_RCVTIMEO`
  (pointless once reads are `ZSOCK_MSG_DONTWAIT`).
- Reconsider the port 162 socket: an agent only needs it to _receive_ on
  162, which agents do not do (162 is the manager side). Traps can be sent
  from the 161 socket or an ephemeral one. Dropping it halves the socket
  footprint; keep it only if there is a known deployment reason.
- Fix the broken include guard in `snmp_zephyr.h` (`#ifndef` with no
  `#define`) and the `_GNUC_` → `__GNUC__` typo, or rather retire that
  header entirely in favor of the new public header (Phase 6).

### Phase 4 — Remove the pbuf and lwIP runtime shims

- Back `snmp_pbuf_stream` with a flat `{ data, max_len, offset }` cursor
  (the CoAP `coap_packet` pattern). Its call sites in the core barely
  change; the receive path parses the service callback's buffer in place,
  and the transmit path encodes into a static Kconfig-sized buffer.
- Delete `src/pbuf.c` (1,823 lines; only 6 of its 35 functions were ever
  called), `include/lwip/pbuf.h`, the `mem_malloc`/`mem_free`/`mem_trim`/
  `memp_*` stubs, and `include/lwip/mem.h`, `memp.h`, `priv/memp_priv.h`,
  `priv/memp_std.h`, `priv/mem_priv.h`. The `k_malloc` dependency
  (`CONFIG_HEAP_MEM_POOL_SIZE`) disappears from the application
  requirements.
- Delete the link-stub globals in `snmp_zephyr.c` (`udp_pcbs`, `lwip_stats`,
  `netif_list`, `netif_default`) together with their headers
  (`include/lwip/netif.h`, `stats.h`, `udp.h`, `sys.h`, `arch/sys_arch.h`,
  `etharp.h`, `ip.h`) once Phase 5's MIB-2 decision removes the readers.
  `sys_now()` survives as a direct `k_uptime_get()` use at its two call
  sites.
- Replace `include/lwip/ip_addr.h` / `ip4_addr.h` / `ip6_addr.h` usage with
  `struct net_in_addr` / `struct net_sockaddr_in` from `net_ip.h`.
- Collapse `opt.h`, `arch.h`, `arch/cc.h`, `def.h`, `err.h` into one small
  private `snmp_priv.h`: the handful of macros actually used
  (`LWIP_ARRAYSIZE` → `ARRAY_SIZE`, min/max → Zephyr's, byte order →
  `<zephyr/sys/byteorder.h>`), with `err_t` migrated to plain `int` +
  negative errno at the API boundary and the existing `snmp_err_t` wire
  codes kept (those are protocol constants, not lwIP vestiges).

### Phase 5 — Type and idiom sweep through the agent core

Mechanical pass over `snmp_msg.c`, `snmp_core.c`, `snmp_asn1.c`,
`snmp_traps.c`, `snmp_scalar.c`, `snmp_table.c`, `snmp_callback.c`, and the
`snmp_mib2_*.c` survivors:

- `u8_t`/`u16_t`/`u32_t`/`s16_t`/`s32_t` → `uint8_t`/… (these lwIP typedefs
  are currently defined in three places in this repo; Zephyr removed its own
  short types back in the 2.x era).
- `LWIP_ASSERT` (which today only logs and continues) → `__ASSERT` where the
  condition is a programming error, error returns where it is reachable.
- `LWIP_DEBUGF` → `LOG_DBG`.
- Apply `.clang-format` (Linux style, tabs, 100 columns, braces on all
  bodies, `/* */` comments) and run `checkpatch.pl` across the tree in this
  same phase, so the noisy diff happens once.
- Fix the small defects found in review while passing through:
  `snmp_callback.c` reads `prefix[mlength-1]` without guarding
  `mlength == 0`; `oid_names[]` in `snmp_mib2_system.c` is a non-static
  global; `snmp_sendto()` ignores pbuf chains (moot once flat buffers land);
  duplicate `(void) type;` in `memp_free` (deleted in Phase 4 anyway);
  leftover `_HT_` investigation comments and commented-out log calls.
- Rename the include tree: `include/lwip/apps/*.h` → `include/snmp/*.h`
  (an out-of-tree module should not claim the `zephyr/` include namespace),
  with `snmp_opts.h` reduced to protocol constants that Kconfig does not
  cover.

### Phase 6 — MIB-2: wire to Zephyr or trim

Decision point (see §3), with a recommended shape:

- **Keep and wire `interfaces`** using `net_if_foreach()`, interface names,
  link address, MTU, admin/oper state, and `net_stats` per-interface
  counters when `CONFIG_NET_STATISTICS` / `_PER_INTERFACE` are enabled.
  This is the group managers actually use.
- **Keep `system` and `snmp`** (already real).
- **Drop `ip` and `udp` for now** — every scalar returns zero and every
  table is empty today, so nothing is lost; misreporting zeros to a manager
  is worse than absence. They can return later backed by
  `net_stats`/`net_context_foreach()` behind their own Kconfig options.
- Gate each group with `CONFIG_SNMP_AGENT_MIB2_*` options so applications
  can trade footprint for coverage.

### Phase 7 — Public API, documentation, release

- One public header (e.g. `include/snmp/snmp.h` plus the MIB-definition
  headers), each with the standard Zephyr shape: `@file` brief, SPDX (see
  §4), `ZEPHYR_INCLUDE_..._H_` guard style, `extern "C"` block, doxygen
  `@defgroup` with `@since`/`@version`, `@cond INTERNAL_HIDDEN` around
  internals, imperative `@brief` lines.
- Rewrite the README for the new API and configuration; update the sample;
  update `CHANGELOG.md`; tag a release with a clear migration note (the
  application-visible changes: no more agent thread/queue/callback, new
  function names, new Kconfig symbols, `CONFIG_POSIX_API` and
  `CONFIG_HEAP_MEM_POOL_SIZE` no longer required).
- Update `CLAUDE.md`, which currently instructs keeping diffs against lwIP
  upstream minimal — after this plan, that guidance inverts.

## 3. Decisions to confirm before starting

1. **MIB-2 scope** — the recommendation above is wire `interfaces`, keep
   `system`/`snmp`, drop `ip`/`udp` until backed by real data. Confirm, or
   choose to wire everything in one pass (adds meaningful work: the tables
   need `net_context` iteration and index ordering).
2. **Port 162** — drop the trap-receive socket unless a deployment depends
   on it.
3. **API naming** — `net_snmp_agent_*` (in-tree style) vs. `snmp_zephyr_*`
   (continuity). The plan assumes the former; existing lwIP-named MIB
   authoring APIs (`snmp_set_mibs`, `SNMP_SCALAR_CREATE_NODE_*`, …) keep
   their names since they are the agent's own vocabulary, not lwIP plumbing.
4. **IPv6** — the plan cleans to IPv4-only (matching current behavior).
   Dual-stack support would slot into Phase 3 cleanly if wanted now.
5. **Threading model** — the plan replaces the "application owns the one
   thread" contract with inline processing plus a mutex. If lock-free
   operation matters more than API simplicity, the alternative is a
   library-owned thread with a control eventfd (the CoAP server pattern);
   the mutex approach is simpler and recommended.

## 4. Licensing boundary

"Remove all vestiges of lwIP" has one hard limit: the agent core remains a
derived work of BSD-3-Clause lwIP code, and that license requires retaining
the copyright notices in the source files. Renaming types and restructuring
files does not change their origin. So: keep the lwIP copyright blocks on
every file that descends from lwIP sources (`snmp_msg.c`, `snmp_core.c`,
`snmp_asn1.c`, the MIB-2 files, …), add SPDX identifiers
(`SPDX-License-Identifier: BSD-3-Clause`) alongside them, and use
Apache-2.0 only for files written from scratch for this module. The
top-level `LICENSE` stays BSD-3-Clause.

## 5. Verification, per phase

- Build the `native_sim` sample and any target board.
- `snmpwalk -v2c -c public <addr> 1` — full-tree walk, output diffed against
  the previous phase (Phases 1–5 must produce identical output; Phase 6
  changes it deliberately).
- `snmpget`/`snmpset` on the system group, a callback OID, and a private-MIB
  OID; trap delivery into `snmptrapd`.
- `checkpatch.pl` and twister once Phase 0 lands them.
- A load nudge for Phase 3: burst several requests at once (the old two-slot
  design drops or corrupts here; the inline design must not).
