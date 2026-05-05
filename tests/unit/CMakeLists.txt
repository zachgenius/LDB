# Unit tests — Catch2 v3 amalgamated.
#
# Build sources from src/ are included directly (we don't ship a static lib
# yet; this is fine for M1 scale and avoids a CMake refactor for one test
# binary).

set(LDB_UNIT_SOURCES
  unit_main.cpp
  test_protocol_jsonrpc.cpp
)

set(LDB_LIB_SOURCES
  ${CMAKE_SOURCE_DIR}/src/protocol/jsonrpc.cpp
  ${CMAKE_SOURCE_DIR}/src/util/log.cpp
)

# Catch2 amalgamated lives in third_party/.
add_library(ldb_catch2 STATIC
  ${CMAKE_SOURCE_DIR}/third_party/catch2/catch_amalgamated.cpp
)
target_include_directories(ldb_catch2 SYSTEM PUBLIC
  ${CMAKE_SOURCE_DIR}/third_party/catch2
)
# Catch2 has its own internal warnings we don't care about.
target_compile_options(ldb_catch2 PRIVATE -w)

add_executable(ldb_unit_tests
  ${LDB_UNIT_SOURCES}
  ${LDB_LIB_SOURCES}
)
target_include_directories(ldb_unit_tests PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src
)
target_link_libraries(ldb_unit_tests PRIVATE
  ldb_catch2
  ldb_json
  ldb_warnings
)

add_test(
  NAME unit_tests
  COMMAND ldb_unit_tests --reporter console::out=- --reporter junit::out=${CMAKE_BINARY_DIR}/unit-tests.xml
)
set_tests_properties(unit_tests PROPERTIES
  TIMEOUT 30
)
