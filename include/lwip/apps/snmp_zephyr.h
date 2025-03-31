#ifndef __SNMP_ZEPHYR_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Starts SNMP Agent.
 */
extern void snmp_init(void);

/**
 * handle incomming requests.
 * A call-back will be generated when necessary.
 */
extern void snmp_loop(void);

/**
 * Sets the IP-address for the next trap.
 */
extern void snmp_prepare_trap_test(const char * ip_address);

/**
 * Takes an array of integeres as an input, and returns a
 * human readble string like eg. "1.3.6.1.4.1.62530.2.10.15".
 */
const char * print_oid (size_t oid_len, const u32_t *oid_words);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif

