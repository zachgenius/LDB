# Daemon binary

set(LDBD_SOURCES
  main.cpp
  daemon/dispatcher.cpp
  daemon/socket_loop.cpp
  daemon/stdio_loop.cpp
  protocol/jsonrpc.cpp
  protocol/version.cpp
  protocol/cost.cpp
  protocol/notifications.cpp
  protocol/output_channel.cpp
  protocol/provenance.cpp
  protocol/transport.cpp
  protocol/view.cpp
  backend/lldb_backend.cpp
  backend/chained_fixups.cpp
  backend/xref_arm64_parsers.cpp
  probes/probe_orchestrator.cpp
  probes/rate_limit.cpp
  probes/bpftrace_engine.cpp
  probes/agent_engine.cpp
  probe_agent/protocol.cpp
  perf/perf_parser.cpp
  perf/perf_runner.cpp
  index/symbol_index.cpp
  runtime/nonstop_runtime.cpp
  runtime/nonstop_listener.cpp
  agent_expr/codec.cpp
  agent_expr/compiler.cpp
  agent_expr/evaluator.cpp
  util/base64.cpp
  backend/gdbmi/backend.cpp
  backend/gdbmi/parser.cpp
  backend/gdbmi/session.cpp
  python/embed.cpp
  store/artifact_store.cpp
  store/hypothesis.cpp
  store/recipe_store.cpp
  store/session_store.cpp
  store/pack.cpp
  store/pack_signing.cpp
  transport/ssh.cpp
  transport/local_exec.cpp
  transport/streaming_exec.cpp
  transport/rsp/framing.cpp
  transport/rsp/packets.cpp
  transport/rsp/channel.cpp
  transport/rr.cpp
  observers/proc.cpp
  observers/net_sockets.cpp
  observers/net_tcpdump.cpp
  observers/net_igmp.cpp
  observers/exec_allowlist.cpp
  util/log.cpp
  util/sha256.cpp
)

add_executable(ldbd ${LDBD_SOURCES})

target_include_directories(ldbd PRIVATE
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/src"
)

target_link_libraries(ldbd PRIVATE
  ldb_lldb
  ldb_capstone
  ldb_python
  ldb_json
  ldb_sodium
  ldb_warnings
  SQLite::SQLite3
  ZLIB::ZLIB
)

# Project version macros
target_compile_definitions(ldbd PRIVATE
  LDB_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
  LDB_VERSION_MINOR=${PROJECT_VERSION_MINOR}
  LDB_VERSION_PATCH=${PROJECT_VERSION_PATCH}
  LDB_VERSION_STRING="${PROJECT_VERSION}"
)

# ----- ldb-dap (Tier 2 §4 — DAP shim) ---------------------------------
#
# Separate binary that speaks Debug Adapter Protocol on stdio and
# spawns ldbd as a child for JSON-RPC translation. Pure protocol
# translation — does NOT link liblldb (the daemon child is the LLDB
# consumer).

set(LDB_DAP_SOURCES
  dap/main.cpp
  dap/transport.cpp
  dap/rpc_channel.cpp
  dap/handlers.cpp
  util/log.cpp
)

add_executable(ldb-dap ${LDB_DAP_SOURCES})

target_include_directories(ldb-dap PRIVATE
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/src"
)

target_link_libraries(ldb-dap PRIVATE
  ldb_json
  ldb_warnings
)

target_compile_definitions(ldb-dap PRIVATE
  LDB_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
  LDB_VERSION_MINOR=${PROJECT_VERSION_MINOR}
  LDB_VERSION_PATCH=${PROJECT_VERSION_PATCH}
  LDB_VERSION_STRING="${PROJECT_VERSION}"
)

# ----- ldb-probe-agent (post-V1 #12) --------------------------------------
#
# Built only when libbpf was found at top-level configure time. The
# subdirectory's CMakeLists short-circuits otherwise.
add_subdirectory(probe_agent)
