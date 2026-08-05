# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Zephyr module that provides an SNMP v1/v2c agent by porting the lwIP SNMP
application to the native Zephyr network stack — lwIP itself is not used. The
agent serves get/getnext/getbulk/set on UDP port 161 and sends traps from port
162, over IPv4. BSD-3-Clause, inherited from lwIP.

## Building

There is no standalone build in this repo. It compiles only as part of a
Zephyr application that includes it as a module (via a west manifest entry or
`ZEPHYR_EXTRA_MODULES`) and sets `CONFIG_LIB_SNMP=y`. Module discovery goes
through `zephyr/module.yml`; the source list is in the top-level
`CMakeLists.txt`, gated on `CONFIG_LIB_SNMP`. Kconfig adds only
`SNMP_LOG_LEVEL`.

To validate a change, build a consuming Zephyr application (sibling checkouts
of `zephyr` live in `/scratch/zephyr`). The README documents the `prj.conf`
options an application needs (`CONFIG_NET_SOCKETS_SERVICE`,
`CONFIG_POSIX_API`, `CONFIG_HEAP_MEM_POOL_SIZE`, and a `VERSION` file so
`<app_version.h>` exists).

Functional testing is done from a host with net-snmp against a running board:
`snmpwalk -v2c -c public <board-ip> 1` exercises every published node;
`snmptrapd -f -Lo -c /dev/null` watches traps.

## Architecture

Two layers, kept deliberately distinct:

- **Upstream lwIP SNMP agent** (`src/snmp_*.c` except `snmp_zephyr.c`, plus
  `include/lwip/apps/`): ASN.1 codec, message processing (`snmp_msg.c`),
  MIB-2 implementation (`snmp_mib2_*.c`), scalar/table node helpers, traps.
  This code retains lwIP style (`u8_t`, `err_t`, lwIP copyright headers).
  Keep diffs against upstream minimal to ease future syncs.

- **Zephyr port layer**:
  - `src/snmp_zephyr.c` — the frontend. Creates the 161/162 sockets,
    registers them with Zephyr's socket service, buffers received datagrams,
    and provides `snmp_zephyr_init()`, `snmp_recv_packet()`, and trap test
    helpers (public API in `include/lwip/apps/snmp_zephyr.h`).
  - `src/pbuf.c` and the compatibility headers in `include/lwip/` (and
    `include/arch/`) — a minimal reimplementation of the lwIP types the agent
    depends on (pbuf, ip_addr_t, err_t, sys/mem shims) on top of Zephyr
    primitives (`k_malloc`, sockets). `include/lwip/apps/snmp_opts.h` and
    `include/lwip/opt.h` carry the port's feature configuration.
  - `src/snmp_callback.c` / `include/lwip/apps/snmp_callback.h` — a
    Zephyr-port addition (not upstream lwIP): per-OID integer callbacks
    matched by string prefix, installed with `install_snmp_handler()`.

### Threading model

The library creates no thread and has no internal locking. Zephyr's socket
service thread receives datagrams and invokes the application callback passed
to `snmp_zephyr_init()`, which must only hand the packet id off (e.g. via a
message queue) to the single application thread that owns the agent. That
thread calls `snmp_recv_packet()`, the configuration setters, and the trap
functions. Any change that touches shared state must preserve this
single-thread contract.

### Notable constraints

- Receive buffer is 96 bytes (`MAX_BUF_LEN` in `snmp_zephyr.c`), sized for
  typical get/getnext requests.
- SNMPv3 sources are present but disabled (`LWIP_SNMP_V3` is 0).
- Callbacks return `int`, so they only serve integer-valued ASN.1 types; use
  a private MIB node's `get_value` for strings.
- Logging goes through the `snmp_log` module registered in `snmp_zephyr.c`.

## Conventions

- Update `CHANGELOG.md` (Keep a Changelog format, semver tags) under
  `[unreleased]` for user-visible changes.
- The README is the reference for the public API and usage patterns; keep it
  in sync when the API surface changes.
