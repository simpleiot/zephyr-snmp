# Copyright (c) 2025 lwIP contributors
# SPDX-License-Identifier: BSD-3-Clause

if(CONFIG_SNMP_AGENT)

zephyr_library_named(snmp)

zephyr_include_directories(include)

zephyr_library_sources(src/pbuf.c)
zephyr_library_sources(src/snmp_asn1.c)
zephyr_library_sources(src/snmp_callback.c)
zephyr_library_sources(src/snmp_core.c)
zephyr_library_sources(src/snmp_mib2.c)
zephyr_library_sources(src/snmp_mib2_interfaces.c)
zephyr_library_sources(src/snmp_mib2_ip.c)
zephyr_library_sources(src/snmp_mib2_snmp.c)
zephyr_library_sources(src/snmp_mib2_system.c)
zephyr_library_sources(src/snmp_mib2_udp.c)
zephyr_library_sources(src/snmp_msg.c)
zephyr_library_sources(src/snmp_pbuf_stream.c)
zephyr_library_sources(src/snmp_scalar.c)
zephyr_library_sources(src/snmp_table.c)
zephyr_library_sources(src/snmp_traps.c)
zephyr_library_sources(src/snmp_zephyr.c)

endif()
