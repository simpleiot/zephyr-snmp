#include <string.h>
#include <stdio.h>

#include "lwip/apps/snmp_opts.h"

#include "lwip/apps/snmp.h"
#include "lwip/apps/snmp_scalar.h"
#include "lwip/apps/snmp_core.h"
#include "lwip/apps/snmp_callback.h"

/** The first entry in a liinked list of handler entries. */
static struct snmp_handler_entry * first_handler = NULL;

static int match_length(const char *complete, const char *partial)
{
	int index;
	for (index = 0; ; index++) {
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

void install_snmp_handler(struct snmp_handler_entry * new_entry)
{
	new_entry->next = NULL;
	if (first_handler == NULL) {
		first_handler = new_entry;
	} else {
		struct snmp_handler_entry * current = first_handler;
		for (;;) {
			/* assert that 'current != NULL ' */
			if (current->next == NULL) {
				current->next = new_entry;
				break;
			}
			current = current->next;
		}
	}
}


size_t snmp_private_call_handler(const char *prefix, void *value_p)
{
	int value_length = 0;
	struct snmp_handler_entry *entry = first_handler;
	size_t plength = strlen (prefix);

            
	/* value is actually an array of SNMP_VALUE_BUFFER_SIZE bytes. */
	zephyr_log("snmp_private_call_handler: Looking for %s\n", prefix);
		while (entry != NULL) {
			if (entry->handler) {
			size_t mlength = match_length(prefix, entry->prefix);
			char special = entry->prefix[mlength-1];
			zephyr_log("Match \"%s\" %d/%d special = %c\n", entry->prefix, mlength, plength, special);
			if ((mlength >= plength) || (mlength == strlen (entry->prefix))) {
					int value = entry->handler(prefix, entry);
					value_length = sizeof value;
					memcpy (value_p, &value, value_length);
					break;
				}
			}
			entry = entry->next;
		}
	zephyr_log ("snmp_private_call_handler (%s): %sfound\n", prefix, value_length ? "" : "not ");
	return value_length;
}

