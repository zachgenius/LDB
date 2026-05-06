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

# Long-running fixture used by attach + memory tests. Prints PID/marker
# on stdout, then pause()s forever until killed or detached.
add_executable(ldb_fix_sleeper c/sleeper.c)
set_target_properties(ldb_fix_sleeper PROPERTIES
  OUTPUT_NAME    sleeper
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/fixtures
  C_STANDARD     11
)
target_compile_options(ldb_fix_sleeper PRIVATE
  -g -O0
  -fno-omit-frame-pointer
  -fno-eliminate-unused-debug-types
)

# Slice 1c dlopen-invalidation fixture. Attaches before any DSO
# beyond libc/libdl is loaded; the harness signals it via SIGUSR1 to
# trigger the dlopen of libpthread, then re-observes the snapshot's
# layout_digest.
#
# macOS portability gap (see docs/macos-arm64-status.md §5.2): the
# fixture and its smoke test (tests/smoke/test_live_dlopen.py) both
# bake in glibc-Linux assumptions (`-ldl`, `dlopen("libpthread.so.0")`).
# On Apple silicon the link below is best-effort (some macOS clang
# `ld` accept `-ldl` via a stub .tbd, others reject it) and the
# fixture's `dlopen("libpthread.so.0")` call would return NULL even
# if the link succeeded. Until this is rewritten as a portable
# fixture (a `#ifdef __APPLE__` branch picking a different DSO, plus
# a platform SKIP in the smoke), macOS arm64 ctest is expected to
# fail at this target. Linux ctest unaffected.
add_executable(ldb_fix_dlopener c/dlopener.c)
set_target_properties(ldb_fix_dlopener PROPERTIES
  OUTPUT_NAME    dlopener
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/fixtures
  C_STANDARD     11
)
target_compile_options(ldb_fix_dlopener PRIVATE
  -g -O0
  -fno-omit-frame-pointer
  -fno-eliminate-unused-debug-types
)
target_link_libraries(ldb_fix_dlopener PRIVATE dl)

# Slice 1c continue-round-trip fixture. main() calls work_step in a
# bounded hot loop with usleep cooperation; the harness sets a bp on
# work_step and drives process.continue twice to verify <gen> bumps
# on each round-trip and the snapshot string shape stays consistent
# across hits even though reg_digest changes (the loop index moves).
add_executable(ldb_fix_looper c/looper.c)
set_target_properties(ldb_fix_looper PROPERTIES
  OUTPUT_NAME    looper
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/fixtures
  C_STANDARD     11
)
target_compile_options(ldb_fix_looper PRIVATE
  -g -O0
  -fno-omit-frame-pointer
  -fno-eliminate-unused-debug-types
)
