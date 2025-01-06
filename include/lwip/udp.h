/*
 * A stub for the udp.h header file.
 */

#ifndef LWIP_UDP_H

#define LWIP_UDP_H

#include "lwip/ip_addr.h"

struct udp_pcb {
  struct udp_pcb *next;

  u8_t flags;
  /** ports are in host byte order */
  u16_t local_port, remote_port;
  ip_addr_t local_ip;
  ip_addr_t remote_ip;
};

/* udp_pcbs export for external reference (e.g. SNMP agent) */
extern struct udp_pcb *udp_pcbs;

#endif /* LWIP_UDP_H */

