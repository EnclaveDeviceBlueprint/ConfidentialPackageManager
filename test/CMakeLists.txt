# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT
    ConfidentialPackageSpecification_u.h
    ConfidentialPackageSpecification_u.c
    ConfidentialPackageSpecification_args.h
  DEPENDS ${CPS_DIR}/ConfidentialPackageSpecification.edl
  COMMAND openenclave::oeedger8r --untrusted ${CPS_DIR}/ConfidentialPackageSpecification.edl)
  
add_executable(cpm-test
    host.c
    main.c
    ${CMAKE_CURRENT_BINARY_DIR}/ConfidentialPackageSpecification_u.c)

target_include_directories(cpm-test PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(cpm-test openenclave::oehost)
