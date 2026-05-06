cmake_minimum_required(VERSION 3.20)
project(ldb
  VERSION 0.1.0
  DESCRIPTION "LLM/Agent-first universal debugger"
  LANGUAGES CXX C
)

# ----- Build options ------------------------------------------------------

option(LDB_BUILD_TESTS "Build LDB tests" ON)
option(LDB_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ----- Warnings -----------------------------------------------------------

add_library(ldb_warnings INTERFACE)
target_compile_options(ldb_warnings INTERFACE
  -Wall -Wextra -Wpedantic
  -Wshadow -Wnon-virtual-dtor -Wold-style-cast
  -Wcast-align -Wunused -Woverloaded-virtual
  -Wconversion -Wsign-conversion -Wnull-dereference
  -Wdouble-promotion -Wformat=2 -Wmisleading-indentation
)
if(LDB_WARNINGS_AS_ERRORS)
  target_compile_options(ldb_warnings INTERFACE -Werror)
endif()

# ----- LLDB ---------------------------------------------------------------
#
# We link against Homebrew LLVM's liblldb (Apache-2.0/LLVM exception).
# On other systems set LDB_LLDB_ROOT to override.

if(NOT DEFINED LDB_LLDB_ROOT)
  if(APPLE AND EXISTS "/opt/homebrew/opt/llvm")
    set(LDB_LLDB_ROOT "/opt/homebrew/opt/llvm")
  elseif(EXISTS "/usr/local/opt/llvm")
    set(LDB_LLDB_ROOT "/usr/local/opt/llvm")
  elseif(EXISTS "/usr/lib/llvm-18")
    set(LDB_LLDB_ROOT "/usr/lib/llvm-18")
  elseif(EXISTS "/usr/lib/llvm-17")
    set(LDB_LLDB_ROOT "/usr/lib/llvm-17")
  endif()
endif()

if(NOT LDB_LLDB_ROOT OR NOT EXISTS "${LDB_LLDB_ROOT}")
  message(FATAL_ERROR
    "Cannot find liblldb. Set -DLDB_LLDB_ROOT=/path/to/llvm-prefix "
    "(must contain include/lldb/API and lib/liblldb.{dylib,so}).")
endif()

find_path(LDB_LLDB_INCLUDE_DIR
  NAMES lldb/API/LLDB.h
  HINTS "${LDB_LLDB_ROOT}/include"
  REQUIRED
)

find_library(LDB_LLDB_LIBRARY
  NAMES lldb
  HINTS "${LDB_LLDB_ROOT}/lib"
  REQUIRED
)

add_library(ldb_lldb INTERFACE)
target_include_directories(ldb_lldb SYSTEM INTERFACE "${LDB_LLDB_INCLUDE_DIR}")
target_link_libraries(ldb_lldb INTERFACE "${LDB_LLDB_LIBRARY}")

# ----- SQLite3 ------------------------------------------------------------
#
# Used by the artifact store (M3) — sqlite-indexed, on-disk blob store
# at ${root}/index.db, blobs under ${root}/builds/<build-id>/artifacts/.
# The same dep will also back sessions (M3) and any other on-disk index
# we add later. Required, not optional — the artifact endpoints are part
# of the canonical RPC surface from M3 onward.

# ----- zlib ---------------------------------------------------------------
#
# Used by store/pack.{h,cpp} (M5 part 5) — `.ldbpack` is gzip+tar. zlib
# is on every Linux/macOS dev box; libllvm pulls it transitively too,
# but we add an explicit find_package so the dep is intentional and
# CMake reports it at configure time.

find_package(ZLIB REQUIRED)
message(STATUS "ldb: zlib ${ZLIB_VERSION_STRING} at ${ZLIB_LIBRARIES}")

find_package(SQLite3 QUIET)
if(NOT SQLite3_FOUND)
  # macOS Homebrew installs sqlite under /opt/homebrew/opt/sqlite (the
  # system /usr/lib/libsqlite3.dylib is also fine on darwin, but the
  # bundled Homebrew sqlite is newer). Hint, then retry.
  if(APPLE AND EXISTS "/opt/homebrew/opt/sqlite")
    list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew/opt/sqlite")
  elseif(EXISTS "/usr/local/opt/sqlite")
    list(APPEND CMAKE_PREFIX_PATH "/usr/local/opt/sqlite")
  endif()
  find_package(SQLite3 REQUIRED)
endif()
message(STATUS "ldb: sqlite3 ${SQLite3_VERSION} at ${SQLite3_LIBRARIES}")

if(APPLE)
  # Make sure the linked dylib is found at runtime without DYLD_LIBRARY_PATH
  set(CMAKE_INSTALL_RPATH "${LDB_LLDB_ROOT}/lib")
  set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
  list(APPEND CMAKE_BUILD_RPATH "${LDB_LLDB_ROOT}/lib")
endif()

message(STATUS "ldb: liblldb at ${LDB_LLDB_LIBRARY}")
message(STATUS "ldb: lldb headers at ${LDB_LLDB_INCLUDE_DIR}")

# ----- Vendored deps ------------------------------------------------------

add_library(ldb_json INTERFACE)
target_include_directories(ldb_json SYSTEM INTERFACE
  "${CMAKE_SOURCE_DIR}/third_party"  # nlohmann/json.hpp
)

# ----- Project -----------------------------------------------------------

add_subdirectory(src)

if(LDB_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
