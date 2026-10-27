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
  src/opk_contact.c)
target_include_directories(openpaykernel PUBLIC include)

enable_testing()
add_executable(test_core tests/test_core.c)
target_link_libraries(test_core openpaykernel)
add_test(NAME core COMMAND test_core)

file(GLOB VECTORS ${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors/*.txt)
add_executable(test_vectors tests/test_vectors.c)
target_link_libraries(test_vectors openpaykernel)
add_test(NAME vectors COMMAND test_vectors ${VECTORS})
