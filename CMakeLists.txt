cmake_minimum_required(VERSION 3.20)
project(ldb
  VERSION 1.6.2
  DESCRIPTION "LLM/Agent-first universal debugger"
  LANGUAGES CXX C
)

# ----- Build options ------------------------------------------------------

option(LDB_BUILD_TESTS "Build LDB tests" ON)
option(LDB_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)
option(LDB_ENABLE_CAPSTONE "Enable the opt-in Capstone disassembly backend" OFF)
option(LDB_ENABLE_PYTHON "Enable embedded Python probe callbacks (post-V1 #9)" ON)
# AUTO when unset: turn ON when libbpf is found, OFF otherwise. Keeps the
# build green on stripped boxes while making local dev "just work."
set(LDB_ENABLE_BPF_AGENT "AUTO" CACHE STRING
  "Build ldb-probe-agent (post-V1 #12). ON/OFF/AUTO.")

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

# ----- libsodium ----------------------------------------------------------
#
# Used by store/pack_signing.{h,cpp} (docs/14-pack-signing.md) — ed25519
# detached signatures over `.ldbpack` payloads. Discovery mirrors the
# Capstone shape: pkg-config first, then a manual find_library/find_path
# fallback. NOT optional — the design (docs/14 §"Crypto Choice") commits
# to libsodium being unconditional. If the host lacks it the configure
# step fails with a clear apt/brew hint rather than silently disabling
# signing.

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(LDB_SODIUM QUIET libsodium)
endif()

add_library(ldb_sodium INTERFACE)
if(LDB_SODIUM_FOUND)
  set(LDB_SODIUM_SYSTEM_INCLUDE_DIRS "")
  foreach(_inc IN LISTS LDB_SODIUM_INCLUDE_DIRS)
    list(APPEND LDB_SODIUM_SYSTEM_INCLUDE_DIRS "${_inc}")
  endforeach()
  list(REMOVE_DUPLICATES LDB_SODIUM_SYSTEM_INCLUDE_DIRS)
  target_include_directories(ldb_sodium SYSTEM INTERFACE
    ${LDB_SODIUM_SYSTEM_INCLUDE_DIRS}
  )
  target_link_directories(ldb_sodium INTERFACE
    ${LDB_SODIUM_LIBRARY_DIRS}
  )
  target_link_libraries(ldb_sodium INTERFACE
    ${LDB_SODIUM_LIBRARIES}
  )
  target_compile_options(ldb_sodium INTERFACE
    ${LDB_SODIUM_CFLAGS_OTHER}
  )
  message(STATUS "ldb: libsodium via pkg-config (${LDB_SODIUM_VERSION})")
else()
  find_path(LDB_SODIUM_INCLUDE_DIR
    NAMES sodium.h
  )
  find_library(LDB_SODIUM_LIBRARY
    NAMES sodium
  )
  if(NOT LDB_SODIUM_INCLUDE_DIR OR NOT LDB_SODIUM_LIBRARY)
    message(FATAL_ERROR
      "libsodium not found. Install libsodium-dev (Debian/Ubuntu) or "
      "libsodium (Homebrew on macOS), or set CMAKE_PREFIX_PATH to a "
      "prefix that contains include/sodium.h and lib/libsodium.{so,dylib}.")
  endif()
  target_include_directories(ldb_sodium SYSTEM INTERFACE
    "${LDB_SODIUM_INCLUDE_DIR}"
  )
  target_link_libraries(ldb_sodium INTERFACE
    "${LDB_SODIUM_LIBRARY}"
  )
  message(STATUS "ldb: libsodium at ${LDB_SODIUM_LIBRARY}")
endif()

# ----- Capstone ------------------------------------------------------------
#
# Optional disassembly backend. LLDB remains the default when this is OFF.

add_library(ldb_capstone INTERFACE)
if(LDB_ENABLE_CAPSTONE)
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(LDB_CAPSTONE QUIET capstone)
  endif()

  if(LDB_CAPSTONE_FOUND)
    set(LDB_CAPSTONE_SYSTEM_INCLUDE_DIRS "")
    foreach(_inc IN LISTS LDB_CAPSTONE_INCLUDE_DIRS)
      # Homebrew's capstone.pc reports .../include/capstone as the
      # include dir, but the source includes <capstone/capstone.h>.
      # Normalize that case back to the parent include root so both the
      # pkg-config and find_path branches agree on the public header
      # layout.
      if(EXISTS "${_inc}/capstone.h" AND NOT EXISTS "${_inc}/capstone/capstone.h")
        get_filename_component(_inc_parent "${_inc}" DIRECTORY)
        list(APPEND LDB_CAPSTONE_SYSTEM_INCLUDE_DIRS "${_inc_parent}")
      else()
        list(APPEND LDB_CAPSTONE_SYSTEM_INCLUDE_DIRS "${_inc}")
      endif()
    endforeach()
    list(REMOVE_DUPLICATES LDB_CAPSTONE_SYSTEM_INCLUDE_DIRS)
    target_include_directories(ldb_capstone SYSTEM INTERFACE
      ${LDB_CAPSTONE_SYSTEM_INCLUDE_DIRS}
    )
    target_link_directories(ldb_capstone INTERFACE
      ${LDB_CAPSTONE_LIBRARY_DIRS}
    )
    target_link_libraries(ldb_capstone INTERFACE
      ${LDB_CAPSTONE_LIBRARIES}
    )
    target_compile_options(ldb_capstone INTERFACE
      ${LDB_CAPSTONE_CFLAGS_OTHER}
    )
    target_compile_definitions(ldb_capstone INTERFACE LDB_HAVE_CAPSTONE=1)
    message(STATUS "ldb: capstone via pkg-config (${LDB_CAPSTONE_VERSION})")
  else()
    find_path(LDB_CAPSTONE_INCLUDE_DIR
      NAMES capstone/capstone.h
    )
    find_library(LDB_CAPSTONE_LIBRARY
      NAMES capstone
    )
    if(NOT LDB_CAPSTONE_INCLUDE_DIR OR NOT LDB_CAPSTONE_LIBRARY)
      message(FATAL_ERROR
        "LDB_ENABLE_CAPSTONE=ON but Capstone was not found. Install "
        "capstone development headers/libraries or set CMAKE_PREFIX_PATH.")
    endif()
    target_include_directories(ldb_capstone SYSTEM INTERFACE
      "${LDB_CAPSTONE_INCLUDE_DIR}"
    )
    target_link_libraries(ldb_capstone INTERFACE
      "${LDB_CAPSTONE_LIBRARY}"
    )
    target_compile_definitions(ldb_capstone INTERFACE LDB_HAVE_CAPSTONE=1)
    message(STATUS "ldb: capstone at ${LDB_CAPSTONE_LIBRARY}")
  endif()
else()
  message(STATUS "ldb: capstone disabled (set -DLDB_ENABLE_CAPSTONE=ON to enable)")
endif()

# ----- Python (embedded, post-V1 #9) --------------------------------------
#
# Detection via pkg-config's `python3-embed` module (the libpython3.X
# variant that includes Py_Initialize symbols, as opposed to the
# `python3` module which is suitable only for building extensions).
# Auto-disable with a notice if the host lacks python3-embed >= 3.11 —
# we don't FATAL_ERROR because the rest of the daemon should still
# build on a host that just doesn't want Python (e.g. minimal CI legs).
#
# When the gate is OFF the `python-v1` recipe format surfaces as
# kNotImplemented at dispatch time; the rest of the daemon is unchanged.

add_library(ldb_python INTERFACE)
if(LDB_ENABLE_PYTHON)
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(LDB_PYTHON QUIET python3-embed>=3.11)
  endif()

  if(LDB_PYTHON_FOUND)
    set(LDB_PYTHON_SYSTEM_INCLUDE_DIRS "")
    foreach(_inc IN LISTS LDB_PYTHON_INCLUDE_DIRS)
      list(APPEND LDB_PYTHON_SYSTEM_INCLUDE_DIRS "${_inc}")
    endforeach()
    list(REMOVE_DUPLICATES LDB_PYTHON_SYSTEM_INCLUDE_DIRS)
    target_include_directories(ldb_python SYSTEM INTERFACE
      ${LDB_PYTHON_SYSTEM_INCLUDE_DIRS}
    )
    target_link_directories(ldb_python INTERFACE
      ${LDB_PYTHON_LIBRARY_DIRS}
    )
    target_link_libraries(ldb_python INTERFACE
      ${LDB_PYTHON_LIBRARIES}
    )
    target_compile_options(ldb_python INTERFACE
      ${LDB_PYTHON_CFLAGS_OTHER}
    )
    target_compile_definitions(ldb_python INTERFACE LDB_ENABLE_PYTHON=1)
    message(STATUS "ldb: python3-embed via pkg-config (${LDB_PYTHON_VERSION})")
  else()
    set(LDB_ENABLE_PYTHON OFF)
    message(STATUS
      "ldb: python3-embed (>=3.11) not found — embedded Python disabled. "
      "Install python3-dev / python3-embed >=3.11 to enable; the daemon "
      "will still build, but recipe.create with format=python-v1 returns "
      "-32001 kNotImplemented.")
  endif()
else()
  message(STATUS "ldb: embedded Python disabled (set -DLDB_ENABLE_PYTHON=ON to enable)")
endif()

# ----- libbpf (post-V1 #12) ----------------------------------------------
#
# Optional. The probe agent binary links libbpf; the daemon never does
# (it talks to the agent over stdio). When libbpf is absent, the agent
# is skipped and recipes with engine="agent" return -32000 from the
# daemon at probe.create time. The bpftrace engine remains the default
# and unaffected.

set(LDB_BPF_AGENT_BUILD OFF)
add_library(ldb_libbpf INTERFACE)
if(NOT LDB_ENABLE_BPF_AGENT STREQUAL "OFF")
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(LDB_LIBBPF QUIET libbpf)
  endif()
  if(LDB_LIBBPF_FOUND)
    set(LDB_LIBBPF_SYSTEM_INCLUDE_DIRS "")
    foreach(_inc IN LISTS LDB_LIBBPF_INCLUDE_DIRS)
      list(APPEND LDB_LIBBPF_SYSTEM_INCLUDE_DIRS "${_inc}")
    endforeach()
    list(REMOVE_DUPLICATES LDB_LIBBPF_SYSTEM_INCLUDE_DIRS)
    target_include_directories(ldb_libbpf SYSTEM INTERFACE
      ${LDB_LIBBPF_SYSTEM_INCLUDE_DIRS}
    )
    target_link_directories(ldb_libbpf INTERFACE
      ${LDB_LIBBPF_LIBRARY_DIRS}
    )
    target_link_libraries(ldb_libbpf INTERFACE
      ${LDB_LIBBPF_LIBRARIES}
    )
    set(LDB_BPF_AGENT_BUILD ON)
    message(STATUS "ldb: libbpf via pkg-config (${LDB_LIBBPF_VERSION}) "
                   "→ ldb-probe-agent enabled")
  else()
    if(LDB_ENABLE_BPF_AGENT STREQUAL "ON")
      message(FATAL_ERROR
        "LDB_ENABLE_BPF_AGENT=ON but libbpf was not found via pkg-config. "
        "Install libbpf-dev (Debian/Ubuntu) or set PKG_CONFIG_PATH to a "
        "prefix containing libbpf.pc.")
    endif()
    message(STATUS "ldb: libbpf not found → ldb-probe-agent disabled "
                   "(set LDB_ENABLE_BPF_AGENT=ON to require it)")
  endif()
endif()

# Optional BPF source compilation. If clang AND bpftool are present, the
# agent embeds a CO-RE skeleton compiled from src/probe_agent/bpf/. If
# either is missing, the agent still builds but reports
# embedded_programs:[] and returns not_supported on attach_*.
set(LDB_BPF_HAVE_TOOLCHAIN OFF)
if(LDB_BPF_AGENT_BUILD)
  find_program(LDB_BPF_CLANG clang)
  find_program(LDB_BPF_BPFTOOL bpftool)
  if(LDB_BPF_CLANG AND LDB_BPF_BPFTOOL)
    set(LDB_BPF_HAVE_TOOLCHAIN ON)
    message(STATUS "ldb: BPF toolchain — clang=${LDB_BPF_CLANG} "
                   "bpftool=${LDB_BPF_BPFTOOL} (skeleton will be generated)")
  else()
    message(STATUS "ldb: BPF toolchain incomplete "
                   "(clang=${LDB_BPF_CLANG} bpftool=${LDB_BPF_BPFTOOL}) — "
                   "ldb-probe-agent will be built without an embedded program")
  endif()
endif()

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
