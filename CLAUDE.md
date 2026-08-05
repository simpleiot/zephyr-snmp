# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Zephyr module that provides an SNMP v1/v2c agent. It began as a port of the
lwIP SNMP application and keeps that agent core, but it now runs on Zephyr's
own primitives throughout: Zephyr sockets, the socket service, `net_if`, and
`net_stats`. lwIP itself is not used, and neither are its compatibility
headers. The agent serves get/getnext/getbulk/set on UDP port 161 and sends
traps to port 162, over IPv4.

BSD-3-Clause for the agent core and everything derived from it; Apache-2.0 for
files written for this module.

## Building

There is no standalone build in this repo. It compiles only as part of a
Zephyr application that includes it as a module (via a west manifest entry or
`ZEPHYR_EXTRA_MODULES`) and sets `CONFIG_SNMP_AGENT=y`. Module discovery goes
through `zephyr/module.yml`; the source list is in the top-level
`CMakeLists.txt`.

`samples/agent` is the fastest way to validate a change:

```sh
west build -b native_sim samples/agent
```

Sibling checkouts of `zephyr` live in `/scratch/zephyr` and
`/scratch/simpleiot/zephyr-siot`. The module targets Zephyr 4.4, whose
networking API is namespaced (`zsock_*`, `NET_AF_INET`,
`struct net_sockaddr_in`, `net_htons`); use those forms, never the POSIX
names. The library must not require `CONFIG_POSIX_API`.

### Functional testing

`samples/agent/overlay-host.conf` builds the sample against the host's network
stack, so no TAP interface and no root are needed:

```sh
west build -b native_sim samples/agent -- -DEXTRA_CONF_FILE=overlay-host.conf
./build/zephyr/zephyr.exe &
snmpwalk -v2c -c public localhost:1161 1
```

Diff a full walk before and after any change that is not meant to alter what
the agent publishes. Against a real board, use `snmpwalk -v2c -c public
<board-ip> 1` and `snmptrapd -f -Lo -c /dev/null`.

## Architecture

Two layers, kept deliberately distinct:

- **Agent core** (`src/snmp_*.c` except `snmp_zephyr.c`, plus
  `include/snmp/`): ASN.1 codec, message processing (`snmp_msg.c`), MIB-2
  groups (`snmp_mib2_*.c`), scalar and table node helpers, traps. This code
  descends from lwIP and keeps its copyright headers, but it no longer tracks
  upstream: types, headers, and idioms have been converted to Zephyr's.

- **Port layer**:
  - `src/snmp_zephyr.c` — the frontend. Creates the port 161 socket,
    registers it with Zephyr's socket service, parses and answers requests in
    the service callback, and provides `net_snmp_agent_start()`,
    `net_snmp_agent_stop()`, and `net_snmp_agent_trap_dst_set()` (public API
    in `include/snmp/snmp_agent.h`). It also holds the agent mutex,
    `snmp_sendto()`, and `sys_now()`.
  - `src/snmp_priv.h` — the private header the core builds on. It replaced
    lwIP's `opt.h`, `def.h`, `err.h`, `arch.h`, and `arch/cc.h` with the few
    macros still in use, mapped onto Zephyr equivalents.
  - `src/snmp_callback.c` / `include/snmp/snmp_callback.h` — not from
    upstream lwIP: per-OID integer callbacks matched by string prefix,
    installed with `install_snmp_handler()`.

### Threading model

The library creates no thread. Zephyr's shared socket service thread delivers
each datagram and the agent parses and replies on that thread. Applications
call in from their own threads to configure the agent and send traps.

A single recursive mutex in `src/snmp_zephyr.c` serializes the two;
`snmp_agent_lock()` and `snmp_agent_unlock()` are declared in
`src/snmp_lock.h`. Every public entry point that touches agent state takes it,
and `LWIP_ASSERT_SNMP_LOCKED()` checks that it is held. Any new public
function that reads or writes agent state must take it too.

### Notable constraints

- Message buffers are `CONFIG_SNMP_AGENT_MAX_MSG_SIZE` bytes: one for
  receive, one for responses, one for traps, all static.
- Callbacks return `int`, so they only serve integer-valued ASN.1 types; use
  a private MIB node's `get_value` for strings.
- Only the `system`, `interfaces`, and `snmp` MIB-2 groups are published, each
  behind `CONFIG_SNMP_AGENT_MIB2_*`. Adding `ip` or `udp` back means backing
  them with `net_stats` and `net_context_foreach()` rather than restoring the
  versions that returned zeros.
- IPv4 only; SNMP v1 and v2c only.
- Logging goes through the `net_snmp_agent` module, filtered by
  `CONFIG_SNMP_AGENT_LOG_LEVEL`. Sources other than `snmp_zephyr.c` need
  `LOG_MODULE_DECLARE`.

## Conventions

- Follow the `.clang-format` in the repo (Zephyr's) and keep `checkpatch.pl`
  free of errors.
- Keep the lwIP copyright block on any file that descends from lwIP; the
  license requires it. Add `SPDX-License-Identifier` alongside.
- Update `CHANGELOG.md` (Keep a Changelog format, semver tags) under
  `[unreleased]` for user-visible changes. To cut a release, rename that
  heading to `[vX.Y.Z] - <date>` and push the matching tag;
  `.github/workflows/release.yml` publishes a GitHub release whose body comes
  from that section by way of `scripts/extract-changelog.sh`.
- The README is the reference for the public API and usage patterns; keep it
  in sync when the API surface changes.
