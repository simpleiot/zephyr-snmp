/**
 * @file
 * SNMP zephyr frontend.
 */

#ifndef __SNMP_ZEPHYR_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Definition of a callback function.
 *
 * @param[in] oid The current OID that is requested.
 * @param[in] entry A struct with information about this call-back.
 *
 * @return The return value of the handler will be sent to the requester.
 */
struct snmp_handler_entry;
typedef int (*snmp_handler)(const char *oid, struct snmp_handler_entry * entry);

/**
 * @brief Definition of a callback entry.
 *
 */
struct snmp_handler_entry {
  snmp_handler handler;            /**< The function that will be called. */
  const char *prefix;              /**< The IOD for which it will be called. */
  struct snmp_handler_entry *next; /**< The next handler in an array. */
};

/**
 * @brief Try to match an OID with the installed handlers.
 *        When a match is found, call the handler function.
 *        This function is private and should only be called from
 *        the SNMP library.
 */
size_t snmp_private_call_handler(const char *prefix, void *value);

/**
 * @brief Install a new SNMP callback function.
 *
 * @param[in] entry A description of the new callback.
 */
void install_snmp_handler(struct snmp_handler_entry * entry);

/**
 * @brief Starts SNMP Agent. It assumes that the network is up and
 *        running. The UDP sockets will be created.
 */
extern int snmp_init(void);

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

void snmp_recv_complete(int packet_id);
#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
