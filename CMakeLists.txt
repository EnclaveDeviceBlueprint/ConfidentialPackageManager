# Copyright (c) Confidential Packaging contributors.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

project(
  "ConfidentialPackageSpecification"
  VERSION 1.0
  LANGUAGES C CXX)

set(OE_OPTEE ON)
set(OE_PACKAGE_OPTEE_PLATFORM trustsom)

set(OpenEnclave_DIR  ${OE_PACKAGE_PREFIX}/${OE_PACKAGE_OPTEE_PLATFORM}/lib/openenclave/cmake)

string(TOUPPER ${CMAKE_BUILD_TYPE} OE_BUILD_TYPE)
if ("${OE_BUILD_TYPE}" STREQUAL "DEBUG")
  set(OE_DEBUG ON)
else ()
  set(OE_DEBUG OFF)
endif ()

find_package(OpenEnclave CONFIG REQUIRED)

list(APPEND CMAKE_MODULE_PATH "cmake")

set(CMAKE_CXX_STANDARD 11)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/lib)

add_subdirectory(ta)
add_subdirectory(test)
