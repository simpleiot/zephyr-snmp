#ifndef LWIP_HDR_APPS_SNMP_CALLBACK_H
#define LWIP_HDR_APPS_SNMP_CALLBACK_H

#include "lwip/apps/snmp_opts.h"

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

#ifdef __cplusplus
} /* extern "C"  */
#endif

#endif /* LWIP_HDR_APPS_SNMP_CALLBACK_H */
