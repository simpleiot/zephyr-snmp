# Copyright (c) 2025 lwIP contributors
# SPDX-License-Identifier: BSD-3-Clause

if(CONFIG_SNMP_AGENT)

# The agent builds on Zephyr's namespaced networking API, which arrived in
# 4.4. Say so here: zephyr/module.yml has no field for a kernel version, and
# without this the mismatch surfaces as a wall of implicit-declaration errors.
set(SNMP_MIN_ZEPHYR_VERSION 4.4)

if("${KERNEL_VERSION_MAJOR}.${KERNEL_VERSION_MINOR}.${KERNEL_PATCHLEVEL}"
   VERSION_LESS ${SNMP_MIN_ZEPHYR_VERSION})
  message(FATAL_ERROR
    "zephyr-snmp requires Zephyr ${SNMP_MIN_ZEPHYR_VERSION} or later, but "
    "this workspace is ${KERNEL_VERSION_STRING}. The agent uses the "
    "namespaced networking API (zsock_*, NET_AF_INET, struct "
    "net_sockaddr_in), which earlier releases do not provide. See the "
    "compatibility table in the module README for a version that matches.")
endif()

zephyr_library_named(snmp)

zephyr_include_directories(include)

zephyr_library_sources(src/snmp_asn1.c)
zephyr_library_sources(src/snmp_callback.c)
zephyr_library_sources(src/snmp_core.c)
zephyr_library_sources(src/snmp_mib2.c)
zephyr_library_sources_ifdef(CONFIG_SNMP_AGENT_MIB2_INTERFACES src/snmp_mib2_interfaces.c)
zephyr_library_sources_ifdef(CONFIG_SNMP_AGENT_MIB2_SNMP src/snmp_mib2_snmp.c)
zephyr_library_sources_ifdef(CONFIG_SNMP_AGENT_MIB2_SYSTEM src/snmp_mib2_system.c)
zephyr_library_sources(src/snmp_msg.c)
zephyr_library_sources(src/snmp_pbuf_stream.c)
zephyr_library_sources(src/snmp_scalar.c)
zephyr_library_sources(src/snmp_table.c)
zephyr_library_sources(src/snmp_traps.c)
zephyr_library_sources(src/snmp_zephyr.c)

endif()
