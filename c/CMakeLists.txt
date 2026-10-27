cmake_minimum_required(VERSION 3.13)
project(openpaykernel VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
  add_compile_options(-Wall -Wextra -Wno-unused-parameter)
endif()

add_library(openpaykernel
  src/opk_tlv.c
  src/opk_crypto.c
  src/opk_oda.c
  src/opk_emvproc.c
  src/opk_entry_point.c
  src/opk_visa.c
  src/opk_mastercard.c
  src/opk_contact.c
  src/opk_kernel_common.c
  src/opk_discover.c
  src/opk_amex.c
  src/opk_jcb.c)
target_include_directories(openpaykernel PUBLIC include)

enable_testing()
add_executable(test_core tests/test_core.c)
target_link_libraries(test_core openpaykernel)
add_test(NAME core COMMAND test_core)

file(GLOB VECTORS ${CMAKE_CURRENT_SOURCE_DIR}/../conformance/vectors/*.txt)
add_executable(test_vectors tests/test_vectors.c)
target_link_libraries(test_vectors openpaykernel)
add_test(NAME vectors COMMAND test_vectors ${VECTORS})

# ---------------------------------------------------------------- examples
add_executable(opk_reader_template examples/reader_template.c)
target_link_libraries(opk_reader_template openpaykernel)

option(OPK_BUILD_PCSC_EXAMPLE "Build the PC/SC terminal example (needs PC/SC: macOS framework, pcsc-lite, or winscard)" OFF)
if(OPK_BUILD_PCSC_EXAMPLE)
  add_executable(opk_pcsc_terminal examples/pcsc_terminal.c)
  target_link_libraries(opk_pcsc_terminal openpaykernel)
  if(APPLE)
    find_library(PCSC_FRAMEWORK PCSC REQUIRED)
    target_link_libraries(opk_pcsc_terminal ${PCSC_FRAMEWORK})
  elseif(WIN32)
    target_link_libraries(opk_pcsc_terminal winscard)
  else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(PCSC REQUIRED libpcsclite)
    target_include_directories(opk_pcsc_terminal PRIVATE ${PCSC_INCLUDE_DIRS})
    target_link_libraries(opk_pcsc_terminal ${PCSC_LIBRARIES})
  endif()
endif()
