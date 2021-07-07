# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

project(
    "ConfidentialPackageManager"
    VERSION 0.1
    LANGUAGES C CXX)


# default locacion for the Open Enclave SDK directory
if (NOT OE_PACKAGE_PREFIX) 
  # optee directory (used for linker file)
  set(OE_PACKAGE_PREFIX ${CMAKE_SOURCE_DIR}/../ms-iot.msiot-vscode-openenclave/sdk/optee/)

  # Generic platform for Open Enclave TA's as we want to be plaform agnostic
  set(OpenEnclave_DIR ${OE_PACKAGE_PREFIX}/armv8a-cps/lib/openenclave/cmake)
endif()

# Default location for the Confidential Package Specification
if (NOT CPS_DIR) 
  set(CPS_DIR ${CMAKE_SOURCE_DIR}/../ConfidentialPackageSpecification/)
endif()

# Check build type, and default to release build
if (NOT CMAKE_BUILD_TYPE) 
    message(STATUS "---------------------------------------------------------")
    message(STATUS " Build type not specified, defaulting to Release build")
    message(STATUS "---------------------------------------------------------")
    set(CMAKE_BUILD_TYPE Release)
    set(OE_DEBUG OFF)
else() 
  set(CMAKE_BUILD_TYPE Debug)
  set(OE_DEBUG ON)
endif()

find_package(OpenEnclave CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 11)


include(cmake/add-enclave.cmake)

add_custom_command(
    OUTPUT
        ConfidentialPackageSpecification_t.h
        ConfidentialPackageSpecification_t.c
        ConfidentialPackageSpecification_args.h
    DEPENDS ${CPS_DIR}/ConfidentialPackageSpecification.edl
    COMMAND openenclave::oeedger8r --trusted ${CPS_DIR}/ConfidentialPackageSpecification.edl)

add_enclave(
    TARGET ConfidentialPackageManager
    DEPENDS CPS_target
    SOURCES
        source/main.c
        ${CMAKE_CURRENT_BINARY_DIR}/ConfidentialPackageSpecification_t.c)
