# Fixture binaries for endpoint tests.
#
# These are real ELF/Mach-O programs with known DWARF, deterministic
# struct layouts, and identifiable rodata strings. Used by smoke / golden
# tests of static-analysis endpoints.
#
# We bypass the project-wide ldb_warnings target — fixtures are C, not
# C++, and warnings here are not load-bearing.

add_executable(ldb_fix_structs c/structs.c)
set_target_properties(ldb_fix_structs PROPERTIES
  OUTPUT_NAME    structs
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/fixtures
  C_STANDARD     11
)
# Force unoptimized builds with full debug info even when CMAKE_BUILD_TYPE
# is RelWithDebInfo. Override after CMake's per-config flags by appending.
target_compile_options(ldb_fix_structs PRIVATE
  -g -O0
  -fno-omit-frame-pointer
  -fno-eliminate-unused-debug-types
)
