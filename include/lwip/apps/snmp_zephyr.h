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


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif

