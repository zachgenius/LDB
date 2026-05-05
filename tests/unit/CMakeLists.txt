# Unit tests — Catch2 v3 amalgamated.
#
# Build sources from src/ are included directly (we don't ship a static lib
# yet; this is fine for M1 scale and avoids a CMake refactor for one test
# binary).

set(LDB_UNIT_SOURCES
  unit_main.cpp
  test_protocol_jsonrpc.cpp
  test_backend_type_layout.cpp
  test_backend_symbol_find.cpp
  test_backend_string_list.cpp
  test_backend_disasm.cpp
  test_backend_xref.cpp
)

set(LDB_LIB_SOURCES
  ${CMAKE_SOURCE_DIR}/src/protocol/jsonrpc.cpp
  ${CMAKE_SOURCE_DIR}/src/util/log.cpp
  ${CMAKE_SOURCE_DIR}/src/backend/lldb_backend.cpp
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
  ldb_lldb
  ldb_warnings
)

# The fixture binary is consumed by tests at runtime. The path is baked
# into the test binary via a compile-time definition; keeping it as
# $<TARGET_FILE:...> ensures the build-system knows we depend on it.
add_dependencies(ldb_unit_tests ldb_fix_structs)
target_compile_definitions(ldb_unit_tests PRIVATE
  LDB_FIXTURE_STRUCTS_PATH="$<TARGET_FILE:ldb_fix_structs>"
)

add_test(
  NAME unit_tests
  COMMAND ldb_unit_tests --reporter console::out=- --reporter junit::out=${CMAKE_BINARY_DIR}/unit-tests.xml
)
set_tests_properties(unit_tests PROPERTIES
  TIMEOUT 30
)
