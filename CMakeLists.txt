if (CONFIG_LIB_SNMP)
zephyr_library()
zephyr_include_directories(include)
zephyr_library_sources(
  src/pbuf.c
  src/snmp_asn1.c
  src/snmp_asn1.h
  src/snmp_core.c
  src/snmp_core_priv.h
  src/snmp_mib2.c
  src/snmp_mib2_icmp.c
  src/snmp_mib2_interfaces.c
  src/snmp_mib2_ip.c
  src/snmp_mib2_snmp.c
  src/snmp_mib2_system.c
  src/snmp_mib2_tcp.c
  src/snmp_mib2_udp.c
  src/snmp_msg.c
  src/snmp_msg.h
  src/snmp_netconn.c
  src/snmp_pbuf_stream.c
  src/snmp_pbuf_stream.h
  src/snmp_raw.c
  src/snmp_scalar.c
  src/snmp_snmpv2_framework.c
  src/snmp_snmpv2_usm.c
  src/snmp_table.c
  src/snmp_threadsync.c
  src/snmp_traps.c
  src/snmp_zephyr.c
  src/snmpv3.c
  src/snmpv3_mbedtls.c
  src/snmpv3_priv.h
)

endif (CONFIG_LIB_SNMP)
