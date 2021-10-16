# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include(../cmake/add-enclave.cmake)

add_custom_command(
  OUTPUT
    ConfidentialPackageSpecification_t.h
    ConfidentialPackageSpecification_t.c
    ConfidentialPackageSpecification_args.h
  DEPENDS ${CPS_DIR}/ConfidentialPackageSpecification.edl
  COMMAND openenclave::oeedger8r --trusted ${CPS_DIR}/ConfidentialPackageSpecification.edl)

add_enclave(
  TARGET ConfidentialPackageManager
  UUID 5d286b7e-ff68-4b4b-b7b8-05f55dbfd0c7
    SOURCES
    main.c
    ${CMAKE_CURRENT_BINARY_DIR}/ConfidentialPackageSpecification_t.c)

target_link_libraries(ConfidentialPackageManager openenclave::oeenclave openenclave::oecryptombedtls)
