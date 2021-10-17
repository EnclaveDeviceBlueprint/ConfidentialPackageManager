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
  UUID d3c5bbbc-adad-11eb-bd25-4362002e2749
    SOURCES
    cpm_crypto.c
    main.c
    ${CMAKE_CURRENT_BINARY_DIR}/ConfidentialPackageSpecification_t.c)

target_link_libraries(ConfidentialPackageManager openenclave::oeenclave openenclave::oecryptombedtls)
