# Unit tests — Catch2 v3 amalgamated.
#
# Build sources from src/ are included directly (we don't ship a static lib
# yet; this is fine for M1 scale and avoids a CMake refactor for one test
# binary).

set(LDB_UNIT_SOURCES
  unit_main.cpp
  test_sqlite_connectivity.cpp
  test_protocol_jsonrpc.cpp
  test_protocol_version.cpp
  test_dispatcher_hello.cpp
  test_protocol_cost.cpp
  test_protocol_cbor.cpp
  test_protocol_view.cpp
  test_backend_type_layout.cpp
  test_backend_symbol_find.cpp
  test_backend_string_list.cpp
  test_backend_disasm.cpp
  test_backend_xref.cpp
  test_backend_string_xref.cpp
  test_backend_process.cpp
  test_backend_threads.cpp
  test_backend_step.cpp
  test_backend_frame_values.cpp
  test_backend_value_eval.cpp
  test_backend_value_read.cpp
  test_backend_attach.cpp
  test_backend_connect_remote.cpp
  test_backend_memory.cpp
  test_backend_core.cpp
  test_dispatcher_view_retrofit.cpp
  test_fixture_sleeper.cpp
  test_artifact_store.cpp
  test_recipe_store.cpp
  test_dispatcher_recipe_guard.cpp
  test_session_store.cpp
  test_dispatcher_session_log.cpp
  test_session_diff.cpp
  test_backend_breakpoint.cpp
  test_probe_orchestrator.cpp
  test_dispatcher_probes.cpp
  test_dispatcher_mem_dump.cpp
  test_transport_ssh.cpp
  test_transport_ssh_tunneled.cpp
  test_backend_connect_remote_ssh.cpp
  test_observers_parsers.cpp
  test_observers_live.cpp
  test_streaming_exec.cpp
  test_bpftrace_parser.cpp
  test_bpftrace_program.cpp
  test_bpftrace_live.cpp
  test_dispatcher_uprobe_bpf.cpp
  test_observer_tcpdump_parser.cpp
  test_observer_tcpdump_live.cpp
  test_dispatcher_tcpdump.cpp
  test_observer_igmp_parser.cpp
  test_dispatcher_igmp.cpp
  test_exec_allowlist.cpp
  test_dispatcher_observer_exec.cpp
  test_describe_endpoints_schema.cpp
  test_pack.cpp
  test_util_sha256.cpp
  test_protocol_provenance.cpp
  test_backend_provenance.cpp
  test_live_provenance.cpp
  test_live_provenance_bp.cpp
  test_audit_bugfixes.cpp
  test_dap_transport.cpp
  test_dap_rpc_channel.cpp
  test_dap_handlers.cpp
)

set(LDB_LIB_SOURCES
  ${CMAKE_SOURCE_DIR}/src/protocol/jsonrpc.cpp
  ${CMAKE_SOURCE_DIR}/src/protocol/version.cpp
  ${CMAKE_SOURCE_DIR}/src/protocol/cost.cpp
  ${CMAKE_SOURCE_DIR}/src/protocol/provenance.cpp
  ${CMAKE_SOURCE_DIR}/src/util/sha256.cpp
  ${CMAKE_SOURCE_DIR}/src/protocol/transport.cpp
  ${CMAKE_SOURCE_DIR}/src/protocol/view.cpp
  ${CMAKE_SOURCE_DIR}/src/util/log.cpp
  ${CMAKE_SOURCE_DIR}/src/backend/lldb_backend.cpp
  ${CMAKE_SOURCE_DIR}/src/daemon/dispatcher.cpp
  ${CMAKE_SOURCE_DIR}/src/probes/probe_orchestrator.cpp
  ${CMAKE_SOURCE_DIR}/src/store/artifact_store.cpp
  ${CMAKE_SOURCE_DIR}/src/store/recipe_store.cpp
  ${CMAKE_SOURCE_DIR}/src/store/session_store.cpp
  ${CMAKE_SOURCE_DIR}/src/store/pack.cpp
  ${CMAKE_SOURCE_DIR}/src/transport/ssh.cpp
  ${CMAKE_SOURCE_DIR}/src/transport/local_exec.cpp
  ${CMAKE_SOURCE_DIR}/src/transport/streaming_exec.cpp
  ${CMAKE_SOURCE_DIR}/src/observers/proc.cpp
  ${CMAKE_SOURCE_DIR}/src/observers/net_sockets.cpp
  ${CMAKE_SOURCE_DIR}/src/observers/exec_allowlist.cpp
  ${CMAKE_SOURCE_DIR}/src/probes/bpftrace_engine.cpp
  ${CMAKE_SOURCE_DIR}/src/observers/net_tcpdump.cpp
  ${CMAKE_SOURCE_DIR}/src/observers/net_igmp.cpp
  ${CMAKE_SOURCE_DIR}/src/dap/transport.cpp
  ${CMAKE_SOURCE_DIR}/src/dap/rpc_channel.cpp
  ${CMAKE_SOURCE_DIR}/src/dap/handlers.cpp
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
  SQLite::SQLite3
  ZLIB::ZLIB
)

# Fixture binaries consumed by tests at runtime. Paths are baked into
# the test binary via compile-time definitions; the $<TARGET_FILE:...>
# generator expression ensures the build system knows we depend on them.
add_dependencies(ldb_unit_tests ldb_fix_structs ldb_fix_sleeper ldbd)
target_compile_definitions(ldb_unit_tests PRIVATE
  LDB_FIXTURE_STRUCTS_PATH="$<TARGET_FILE:ldb_fix_structs>"
  LDB_FIXTURE_SLEEPER_PATH="$<TARGET_FILE:ldb_fix_sleeper>"
  LDB_FIXTURE_TEXT_DIR="${CMAKE_SOURCE_DIR}/tests/fixtures/text"
  LDBD_PATH="$<TARGET_FILE:ldbd>"
)

# lldb-server path for the connect_remote positive-path test. Discovery
# order matches the runtime fallback in the test:
#   1. ${LDB_LLDB_ROOT}/bin/lldb-server (the same prefix we link liblldb
#      against — Homebrew LLVM ships it).
#   2. find_program(... lldb-server) — anywhere on PATH.
# If neither found, define the macro to empty string; the test SKIPs
# the live case at runtime with a logged reason.
set(LDB_LLDB_SERVER_BIN "")
if(LDB_LLDB_ROOT AND EXISTS "${LDB_LLDB_ROOT}/bin/lldb-server")
  set(LDB_LLDB_SERVER_BIN "${LDB_LLDB_ROOT}/bin/lldb-server")
else()
  find_program(LDB_LLDB_SERVER_FOUND lldb-server)
  if(LDB_LLDB_SERVER_FOUND)
    set(LDB_LLDB_SERVER_BIN "${LDB_LLDB_SERVER_FOUND}")
  endif()
endif()
if(LDB_LLDB_SERVER_BIN)
  message(STATUS "ldb: lldb-server at ${LDB_LLDB_SERVER_BIN} "
                 "(connect_remote positive path enabled)")
else()
  message(STATUS "ldb: lldb-server not found — connect_remote positive path "
                 "will SKIP at runtime")
endif()
target_compile_definitions(ldb_unit_tests PRIVATE
  LDB_LLDB_SERVER_PATH="${LDB_LLDB_SERVER_BIN}"
)

add_test(
  NAME unit_tests
  COMMAND ldb_unit_tests --reporter console::out=- --reporter junit::out=${CMAKE_BINARY_DIR}/unit-tests.xml
)
set_tests_properties(unit_tests PROPERTIES
  TIMEOUT 90
  ENVIRONMENT "LDB_STORE_ROOT=${LDB_TEST_STORE_ROOT}"
)
