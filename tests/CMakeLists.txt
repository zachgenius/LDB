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

# Unit tests — Catch2 against compiled-in source modules.
add_subdirectory(unit)
