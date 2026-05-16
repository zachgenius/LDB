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
if(NOT APPLE)
  # macOS: dlopen lives in libSystem; no separate -ldl needed (and some ld
  # versions reject it). The #ifdef in dlopener.c picks a macOS-native DSO.
  target_link_libraries(ldb_fix_dlopener PRIVATE dl)
endif()

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

# Chained-fixup fixture for docs/35-field-report-followups.md §3 phase 2.
# Only built on Apple Silicon hosts: the smoke test that drives this
# fixture (tests/smoke/test_xref_chained_fixup.sh) inspects an arm64
# LC_DYLD_CHAINED_FIXUPS payload, which only Apple's linker emits and
# which is only meaningfully decodable when the host can disassemble
# arm64. The CMake guard mirrors the add_test() guard in
# tests/CMakeLists.txt so a fresh `cmake --build` doesn't fail on Linux.
if(APPLE AND CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "arm64")
  add_executable(ldb_fix_chain_slot c/chain_slot.c)
  set_target_properties(ldb_fix_chain_slot PROPERTIES
    OUTPUT_NAME    chain_slot
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/fixtures
    C_STANDARD     11
  )
  target_compile_options(ldb_fix_chain_slot PRIVATE
    -arch arm64
    -g -O0
    -fno-omit-frame-pointer
  )
  # -Wl,-fixup_chains forces the linker to emit LC_DYLD_CHAINED_FIXUPS
  # even when the deployment target wouldn't have demanded it. This is
  # the flag whose output the parse_chained_fixups() pipeline targets.
  target_link_options(ldb_fix_chain_slot PRIVATE
    -arch arm64
    -Wl,-fixup_chains
  )
endif()

# C++ fixture for symbol.find demangled-name lookup (papercut #3).
# Itanium ABI mangles `ldb_fix::Widget::poke(long)` to a known mangled
# symbol; we lean on the demangled name from LLDB SBSymbol::GetName()
# and so don't pin the mangled spelling here.
add_executable(ldb_fix_cppsyms cpp/cppsyms.cpp)
set_target_properties(ldb_fix_cppsyms PROPERTIES
  OUTPUT_NAME    cppsyms
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/fixtures
  CXX_STANDARD   17
)
target_compile_options(ldb_fix_cppsyms PRIVATE
  -g -O0
  -fno-omit-frame-pointer
  -fno-eliminate-unused-debug-types
)
