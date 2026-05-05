# Daemon binary

set(LDBD_SOURCES
  main.cpp
  daemon/stdio_loop.cpp
  daemon/dispatcher.cpp
  protocol/jsonrpc.cpp
  backend/lldb_backend.cpp
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
)

# Project version macros
target_compile_definitions(ldbd PRIVATE
  LDB_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
  LDB_VERSION_MINOR=${PROJECT_VERSION_MINOR}
  LDB_VERSION_PATCH=${PROJECT_VERSION_PATCH}
  LDB_VERSION_STRING="${PROJECT_VERSION}"
)
