# Fixture binaries (real ELF/Mach-O with known DWARF, used by endpoint
# tests). Build them before any target that depends on them.
add_subdirectory(fixtures)

# Smoke tests — end-to-end against the built ldbd binary.
add_test(
  NAME smoke_hello
  COMMAND "${CMAKE_SOURCE_DIR}/tests/smoke/run.sh" "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_hello PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_type_layout
  COMMAND "${CMAKE_SOURCE_DIR}/tests/smoke/test_type_layout.sh"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_type_layout PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_symbol_find
  COMMAND "${CMAKE_SOURCE_DIR}/tests/smoke/test_symbol_find.sh"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_symbol_find PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_string_list
  COMMAND "${CMAKE_SOURCE_DIR}/tests/smoke/test_string_list.sh"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_string_list PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_disasm
  COMMAND "${CMAKE_SOURCE_DIR}/tests/smoke/test_disasm.sh"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_disasm PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_xref_addr
  COMMAND "${CMAKE_SOURCE_DIR}/tests/smoke/test_xref_addr.sh"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_xref_addr PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_string_xref
  COMMAND "${CMAKE_SOURCE_DIR}/tests/smoke/test_string_xref.sh"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_string_xref PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_view_module_list
  COMMAND "${CMAKE_SOURCE_DIR}/tests/smoke/test_view_module_list.sh"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_view_module_list PROPERTIES
  TIMEOUT 30
)

# Unit tests — Catch2 against compiled-in source modules.
add_subdirectory(unit)
