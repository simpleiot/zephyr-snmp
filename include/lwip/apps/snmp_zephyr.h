/**
 * @file
 * SNMP zephyr frontend.
 */

#ifndef __SNMP_ZEPHYR_H

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief handle incomming requests.
 *        A call-back will be executed when necessary.
 */
typedef void ( * recv_packet_handler )(int packet_id);

/**
 * @brief Starts SNMP Agent. It assumes that the network is up and
 *        running. The UDP sockets will be created.
 *
 * @param[in] The address of a function that forwards incoming packets.
 */
extern int snmp_zephyr_init(recv_packet_handler handler);

/**
 * @brief handle incomming requests.
 *        A call-back will be executed when necessary.
 */
extern void snmp_recv_packet(int packet_id);

/**
 * @brief Sets the IP-address for the next trap.
 *
 * @param[in] ip_address A string representation of the IP-address.
 */
extern void snmp_prepare_trap_test(const char *ip_address);

void snmp_install_handlers(void);

/**
 * @brief Converts an array of integeres to a human-readable
 *        character string, representing the OID.
 *
 * @param[in] oid_len The number of integeres in the parameter oid_words
 * @param[in] oid_words The array of integer values
 */
const char *print_oid(size_t oid_len, const u32_t *oid_words);

size_t zephyr_log( const char * format, ... )
#ifdef _GNUC_
	__attribute__ ((format (printf, 1, 2)))
#endif
;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
