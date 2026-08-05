if (CONFIG_LIB_SNMP)
zephyr_library()
zephyr_include_directories(include)
zephyr_library_sources(
  src/pbuf.c
  src/snmp_asn1.c
  src/snmp_callback.c
  src/snmp_core.c
  src/snmp_mib2.c
  src/snmp_mib2_interfaces.c
  src/snmp_mib2_ip.c
  src/snmp_mib2_snmp.c
  src/snmp_mib2_system.c
  src/snmp_mib2_udp.c
  src/snmp_msg.c
  src/snmp_pbuf_stream.c
  src/snmp_scalar.c
  src/snmp_table.c
  src/snmp_traps.c
  src/snmp_zephyr.c
)

endif (CONFIG_LIB_SNMP)
