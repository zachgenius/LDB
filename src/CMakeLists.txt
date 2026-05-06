# Daemon binary

set(LDBD_SOURCES
  main.cpp
  daemon/stdio_loop.cpp
  daemon/dispatcher.cpp
  protocol/jsonrpc.cpp
  protocol/view.cpp
  backend/lldb_backend.cpp
  probes/probe_orchestrator.cpp
  probes/bpftrace_engine.cpp
  store/artifact_store.cpp
  store/session_store.cpp
  transport/ssh.cpp
  transport/local_exec.cpp
  transport/streaming_exec.cpp
  observers/proc.cpp
  observers/net_sockets.cpp
  observers/net_tcpdump.cpp
  observers/net_igmp.cpp
  util/log.cpp
)

add_executable(ldbd ${LDBD_SOURCES})

target_include_directories(ldbd PRIVATE
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/src"
)

target_link_libraries(ldbd PRIVATE
  ldb_lldb
  ldb_json
  ldb_warnings
  SQLite::SQLite3
)

# Project version macros
target_compile_definitions(ldbd PRIVATE
  LDB_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
  LDB_VERSION_MINOR=${PROJECT_VERSION_MINOR}
  LDB_VERSION_PATCH=${PROJECT_VERSION_PATCH}
  LDB_VERSION_STRING="${PROJECT_VERSION}"
)
