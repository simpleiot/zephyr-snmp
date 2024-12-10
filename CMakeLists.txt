cmake_minimum_required(VERSION 3.20)
project(snmp)

add_library(snmp)
target_compile_options(snmp PRIVATE -Wall -Wextra)
set_target_properties(snmp PROPERTIES C_STANDARD 11)

target_include_directories(snmp PUBLIC include)
add_subdirectory(src)

file(CONFIGURE OUTPUT .gitignore
  NEWLINE_STYLE UNIX
  CONTENT "*")
