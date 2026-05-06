# Fixture binaries (real ELF/Mach-O with known DWARF, used by endpoint
# tests). Build them before any target that depends on them.
add_subdirectory(fixtures)

# Pin every test's artifact-store root inside the build directory so
# that ldbd's default-to-${HOME}/.ldb fallback never writes to the
# operator's home directory during testing. Tests that need a clean
# per-run root (smoke_artifact, the unit fixture) override this with
# their own tmpdir; tests that don't touch the store at all are
# unaffected.
set(LDB_TEST_STORE_ROOT "${CMAKE_BINARY_DIR}/test-store-root")
file(MAKE_DIRECTORY "${LDB_TEST_STORE_ROOT}")

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
          "$<TARGET_FILE:ldb_fix_sleeper>"
)
set_tests_properties(smoke_view_module_list PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_process
  COMMAND "${CMAKE_SOURCE_DIR}/tests/smoke/test_process.sh"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_process PROPERTIES
  TIMEOUT 60
)

add_test(
  NAME smoke_threads
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_threads.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_threads PROPERTIES
  TIMEOUT 60
)

add_test(
  NAME smoke_frame_values
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_frame_values.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_frame_values PROPERTIES
  TIMEOUT 60
)

add_test(
  NAME smoke_attach
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_attach.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_sleeper>"
)
set_tests_properties(smoke_attach PROPERTIES
  TIMEOUT 60
)

add_test(
  NAME smoke_memory
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_memory.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_sleeper>"
)
set_tests_properties(smoke_memory PROPERTIES
  TIMEOUT 60
)

add_test(
  NAME smoke_core
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_core.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_sleeper>"
)
set_tests_properties(smoke_core PROPERTIES
  TIMEOUT 60
)

add_test(
  NAME smoke_step
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_step.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_step PROPERTIES
  TIMEOUT 60
)

add_test(
  NAME smoke_value_eval
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_value_eval.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_value_eval PROPERTIES
  TIMEOUT 60
)

add_test(
  NAME smoke_value_read
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_value_read.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_value_read PROPERTIES
  TIMEOUT 60
)

add_test(
  NAME smoke_connect_remote
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_connect_remote.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_connect_remote PROPERTIES
  TIMEOUT 60
)

add_test(
  NAME smoke_connect_remote_ssh
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_connect_remote_ssh.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_sleeper>"
)
set_tests_properties(smoke_connect_remote_ssh PROPERTIES
  TIMEOUT 60
)

add_test(
  NAME smoke_artifact
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_artifact.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_artifact PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_session
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_session.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_session PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_probe
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_probe.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_structs>"
)
set_tests_properties(smoke_probe PROPERTIES
  TIMEOUT 60
)

add_test(
  NAME smoke_mem_dump
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_mem_dump.py"
          "$<TARGET_FILE:ldbd>"
          "$<TARGET_FILE:ldb_fix_sleeper>"
)
set_tests_properties(smoke_mem_dump PROPERTIES
  TIMEOUT 60
)

add_test(
  NAME smoke_observer
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_observer.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_observer PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_observer_igmp
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_observer_igmp.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_observer_igmp PROPERTIES
  TIMEOUT 30
)

add_test(
  NAME smoke_uprobe_bpf
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_uprobe_bpf.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_uprobe_bpf PROPERTIES
  TIMEOUT 60
)

add_test(
  NAME smoke_observer_tcpdump
  COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/smoke/test_observer_tcpdump.py"
          "$<TARGET_FILE:ldbd>"
)
set_tests_properties(smoke_observer_tcpdump PROPERTIES
  TIMEOUT 30
)

# Unit tests — Catch2 against compiled-in source modules.
add_subdirectory(unit)

# Apply LDB_STORE_ROOT to every test we registered above. Tests that set
# their own value in subprocess env (smoke_artifact) override this; the
# unit fixture uses std::filesystem::temp_directory_path() and ignores
# the env var entirely. The point is to make absolutely sure no test —
# present or future — silently writes to the operator's $HOME/.ldb.
get_directory_property(_LDB_TESTS TESTS)
foreach(_t IN LISTS _LDB_TESTS)
  set_property(TEST ${_t} APPEND PROPERTY
    ENVIRONMENT "LDB_STORE_ROOT=${LDB_TEST_STORE_ROOT}")
endforeach()
