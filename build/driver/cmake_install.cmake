# Install script for directory: /Users/dev/deepsys/driver

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Debug")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set path to fallback-tool for dependency-resolution.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "agent" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/src/-" TYPE FILE RENAME "Makefile" FILES "/Users/dev/deepsys/build/driver/Makefile.dkms")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "agent" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/src/-" TYPE FILE FILES
    "/Users/dev/deepsys/build/driver/dkms.conf"
    "/Users/dev/deepsys/driver/dynamic_params_table.c"
    "/Users/dev/deepsys/driver/driver_config.h"
    "/Users/dev/deepsys/driver/event_table.c"
    "/Users/dev/deepsys/driver/flags_table.c"
    "/Users/dev/deepsys/driver/main.c"
    "/Users/dev/deepsys/driver/ppm.h"
    "/Users/dev/deepsys/driver/ppm_events.c"
    "/Users/dev/deepsys/driver/ppm_events.h"
    "/Users/dev/deepsys/driver/ppm_events_public.h"
    "/Users/dev/deepsys/driver/ppm_fillers.c"
    "/Users/dev/deepsys/driver/ppm_ringbuffer.h"
    "/Users/dev/deepsys/driver/ppm_syscall.h"
    "/Users/dev/deepsys/driver/syscall_table.c"
    "/Users/dev/deepsys/driver/ppm_cputime.c"
    "/Users/dev/deepsys/driver/ppm_compat_unistd_32.h"
    )
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
if(CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "/Users/dev/deepsys/build/driver/install_local_manifest.txt"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
