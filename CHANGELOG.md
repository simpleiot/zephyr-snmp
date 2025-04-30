# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [unreleased]

## [v0.0.4] - 2025-04-30

- mib2 entries

## [v0.0.3] - 2025-04-23

- remove app compiler flags as this was leaking into the main application compile

## [v0.0.2] - 2025-04-23

- move to a callback for SNMP get requests

## [v0.0.1] - 2025-04-27

- Tested the MIB's and library by running an SNMP walk. This command iterates through all entries, starting at a certain point, eg. '1':
  Command: `snmpwalk -v2c -c public 192.168.2.17 1`
  It provides an interesting extra test.

## [v0.0.1] - 2025-04-24

- #10 from remove_compiler_warning_changes
- Remove the compiler warning from CMakeList.txt

## [v0.0.1] - 2025-04-22

- #9 from Start_using_socket_service
- The SNMP port started using the Zephyr socket services
- This makes it possible to have the SNMP thread sleep in a central place and with the `K_FOREVER` parameter.
- The socket services will pass UDP data to the SNMP thread, which will execute the commands and give a reply. The sending of traps happens in the same thread, thus avoiding things like: race conditions, data races, deadlocks and synchronisation errors.
- And also in this big PR: a call-back system was developed.

## [v0.0.1] - 2025-03-13

- #8 from Worked_on_snmp_zephyr
- Removed the check about the network, added snmp_zephyr.h

## [v0.0.1] - 2025-03-13

- #7 from assume_network_ready_while_init
- Assume that the zephyr network is up-and-running at start-up. Until now this seems to work OK.

## [v0.0.1] - 2025-02-25

- #6 from pass_address_network_endian
- Pass the SNMP trap port number and IP-address in network-endian format

## [v0.0.1] - 2025-01-29

- #5 from More_logging_more_tested
- Tested sending traps, also tested the new functions in snmp_zephyr.c

## [v0.0.1] - 2025-01-15

- #3 from Better_logging_snmp_zephyr
- Made logging better by showing request OID (Object ID) of requests.

## [v0.0.1] - 2025-01-06

- PR #1 from added_header_files
- Added the necessary header files from the latest lwIP release, also started to port the software for Zypher, using it native IP-stack.
- Adapted opt.h to make things compiling and running.
- TODO: porting code should appear in lwipopts.h
