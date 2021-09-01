# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

macro (add_enclave)

  set(options CXX)
  set(oneValueArgs TARGET KEY)
  set(multiValueArgs SOURCES)
  cmake_parse_arguments(ENCLAVE "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
  
  # Set up the linker flags exactly as we need them such that the resulting
  # binary be compatible with OP-TEE's loader.
  set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS)
  set(CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS)
  set(CMAKE_EXE_EXPORTS_C_FLAG)

  string(REPLACE "gcc" "ld" LINKER ${CMAKE_C_COMPILER})
  set(CMAKE_C_LINK_EXECUTABLE
    "${LINKER} <CMAKE_CXX_LINK_FLAGS> <LINK_FLAGS> --start-group <OBJECTS> <LINK_LIBRARIES> --end-group -o <TARGET>"
  )
  set(CMAKE_CXX_LINK_EXECUTABLE
    "${LINKER} <CMAKE_CXX_LINK_FLAGS> <LINK_FLAGS> --start-group <OBJECTS> <LINK_LIBRARIES> --end-group -o <TARGET>"
  )

  # Generate linker script from template.
  string(REPLACE "gcc" "cpp" C_PREPROCESSOR ${CMAKE_C_COMPILER})
  set(TA_LINKER_SCRIPT ${CMAKE_CURRENT_BINARY_DIR}/ta.ld)
  add_custom_target(
    ${ENCLAVE_TARGET}.ld
    COMMAND ${C_PREPROCESSOR} -Wp,-P -DASM=1 -DARM64 -nostdinc
            ${OE_PACKAGE_PREFIX}/ta.ld.S > ${TA_LINKER_SCRIPT}
    SOURCES ${OE_PACKAGE_PREFIX}/ta.ld.S
    DEPENDS ${OE_PACKAGE_PREFIX}/ta.ld.S
    BYPRODUCTS ${TA_LINKER_SCRIPT})

  # Ask GCC where is libgcc.
  execute_process(
    COMMAND ${CMAKE_C_COMPILER} -print-libgcc-file-name
    OUTPUT_VARIABLE LIBGCC_PATH
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  get_filename_component(LIBGCC_PATH ${LIBGCC_PATH} DIRECTORY)

  # Set up the target.
  add_executable(${ENCLAVE_TARGET} ${ENCLAVE_SOURCES})
  set_property(TARGET ${ENCLAVE_TARGET} PROPERTY C_STANDARD 99)
  set_target_properties(${ENCLAVE_TARGET} PROPERTIES OUTPUT_NAME
                                                     ${ENCLAVE_TARGET})
  set_target_properties(${ENCLAVE_TARGET} PROPERTIES SUFFIX ".elf")
  add_dependencies(${ENCLAVE_TARGET} ${ENCLAVE_TARGET}.ld)
  target_include_directories(${ENCLAVE_TARGET} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
  target_link_libraries(${ENCLAVE_TARGET} openenclave::oeenclave)
  if (ENCLAVE_CXX)
    target_link_libraries(${ENCLAVE_TARGET} openenclave::oelibcxx)
  endif ()

  find_library(LIBGCC NAMES libgcc.a)
  target_link_libraries(${ENCLAVE_TARGET} ${LIBGCC})

  # Strip binary for release builds
  if (CMAKE_BUILD_TYPE STREQUAL Release)
    add_custom_command(TARGET ${ENCLAVE_TARGET} POST_BUILD
      COMMAND ${CMAKE_STRIP} ${ENCLAVE_TARGET}.elf)
  endif ()

  
  # Set linker options.
  # NOTE: This has to be at the end, apparently:
  #       https://gitlab.kitware.com/cmake/cmake/issues/17210
  set(CMAKE_EXE_LINKER_FLAGS
      "-T ${TA_LINKER_SCRIPT} -L${LIBGCC_PATH} --entry=_start")
  if (ENCLAVE_CXX)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --eh-frame-hdr")
  endif ()
                        

endmacro ()
