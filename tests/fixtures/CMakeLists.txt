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

  # Phase-3 adversarial fixtures (docs/35-field-report-followups.md §3
  # phase 3). Each one reproduces a specific phase-2 false-positive in
  # the ADRP-pair resolver. Hand-assembled `.s` so the instruction
  # stream is deterministic and the smoke tests can pin offsets.
  # enable_language(ASM) is scoped to this CMakeLists — the rest of the
  # project compiles C/C++ only.
  enable_language(ASM)
  foreach(_phase3_fix
      xref_addclobber
      xref_fnleak
      xref_callclobber
      xref_subclobber)
    add_executable(ldb_fix_${_phase3_fix} asm/${_phase3_fix}.s)
    set_target_properties(ldb_fix_${_phase3_fix} PROPERTIES
      OUTPUT_NAME    ${_phase3_fix}
      RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/fixtures
      LINKER_LANGUAGE C
    )
    target_compile_options(ldb_fix_${_phase3_fix} PRIVATE -arch arm64)
    target_link_options(ldb_fix_${_phase3_fix} PRIVATE -arch arm64)
  endforeach()

  # Phase-3 post-review PAC-call fixture. PAC branch mnemonics
  # (BLRAA / BLRAB / BLRAAZ / BLRABZ / BRAA / BRAB / BRAAZ / BRABZ /
  # RETAA / RETAB) only exist on arm64e — clang refuses them with
  # -arch arm64. Probe the toolchain by attempting an arm64e compile
  # at configure time so a fresh Apple silicon dev box without the
  # arm64e SDK pieces SKIPs the test cleanly instead of erroring at
  # build time.
  include(CheckCSourceCompiles)
  set(_saved_required_flags ${CMAKE_REQUIRED_FLAGS})
  set(CMAKE_REQUIRED_FLAGS "-arch arm64e")
  check_c_source_compiles("int main(void){return 0;}"
    LDB_CAN_COMPILE_ARM64E)
  set(CMAKE_REQUIRED_FLAGS ${_saved_required_flags})

  if(LDB_CAN_COMPILE_ARM64E)
    add_executable(ldb_fix_xref_pac_callclobber
                   asm/xref_pac_callclobber.s)
    set_target_properties(ldb_fix_xref_pac_callclobber PROPERTIES
      OUTPUT_NAME    xref_pac_callclobber
      RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/fixtures
      LINKER_LANGUAGE C
      # Force a single-arch thin Mach-O. The default project-wide
      # CMAKE_OSX_ARCHITECTURES (arm64) plus our `-arch arm64e`
      # compile-option would otherwise produce a FAT universal binary;
      # LLDB then picks the arm64 slice, which has the PAC bytes laid
      # out the same but is reported with a non-arm64e triple, and the
      # xref disassembler reads the wrong section bytes. Overriding
      # OSX_ARCHITECTURES at the target level prevents the
      # auto-injection of project-level arch flags.
      OSX_ARCHITECTURES "arm64e"
    )
    target_compile_options(ldb_fix_xref_pac_callclobber PRIVATE -arch arm64e)
    target_link_options(ldb_fix_xref_pac_callclobber PRIVATE -arch arm64e)
  endif()
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
