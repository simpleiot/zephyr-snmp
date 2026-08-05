/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <stdio.h>

#include <snmp/snmp_opts.h>
#include "snmp_priv.h"

#include <snmp/snmp.h>
#include <snmp/snmp_scalar.h>
#include <snmp/snmp_core.h>
#include <snmp/snmp_callback.h>
#include "snmp_lock.h"

LOG_MODULE_DECLARE(net_snmp_agent, CONFIG_SNMP_AGENT_LOG_LEVEL);

/** The first entry in a liinked list of handler entries. */
static struct snmp_handler_entry *first_handler;

static int match_length(const char *complete, const char *partial)
{
	int index;

	for (index = 0;; index++) {
		char ch0 = complete[index];
		char ch1 = partial[index];
		if (!ch0 || !ch1) {
			break;
		}
		if (ch1 == '*') {
			index++;
			break;
		}
		if (ch0 != ch1) {
			break;
		}
	}
	return index;
}

void install_snmp_handler(struct snmp_handler_entry *new_entry)
{
	snmp_agent_lock();
	new_entry->next = NULL;
	if (first_handler == NULL) {
		first_handler = new_entry;
	} else {
		struct snmp_handler_entry *current = first_handler;
		for (;;) {
			/* assert that 'current != NULL ' */
			if (current->next == NULL) {
				current->next = new_entry;
				break;
			}
			current = current->next;
		}
	}
	snmp_agent_unlock();
}

size_t snmp_private_call_handler(const char *prefix, void *value_p)
{
	int value_length = 0;
	struct snmp_handler_entry *entry = first_handler;
	size_t plength = strlen(prefix);

	/* value is actually an array of SNMP_VALUE_BUFFER_SIZE bytes. */
	LOG_DBG("looking for %s", prefix);
	while (entry != NULL) {
		if (entry->handler) {
			size_t mlength = match_length(prefix, entry->prefix);
			/* The last character matched, or '\0' when nothing did.
			 * Reading prefix[mlength - 1] without this check ran off
			 * the front of the string whenever the first character
			 * already differed.
			 */
			char special = (mlength > 0) ? entry->prefix[mlength - 1] : '\0';
			bool does_match =
				(mlength >= plength) || (mlength == strlen(entry->prefix));

			LOG_DBG("match %s \"%s\" %zu/%zu special = %c",
				does_match ? "true" : "false", entry->prefix, mlength, plength,
				special);
			if (does_match) {
				int value = entry->handler(prefix, entry);

				value_length = sizeof(value);
				memcpy(value_p, &value, value_length);
				break;
			}
		}
		entry = entry->next;
	}
	LOG_DBG("snmp_private_call_handler (%s): %sfound", prefix, value_length ? "" : "not ");
	return value_length;
}
