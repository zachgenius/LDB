# ldb-probe-agent — libbpf-backed BPF probe helper (post-V1 #12).
#
# Built only when libbpf is available (see top-level LDB_ENABLE_BPF_AGENT
# auto-detection). The protocol module (protocol.{h,cpp}) is *always*
# compiled — the daemon's AgentEngine links it, and the unit tests pin
# the wire shape regardless of whether the agent binary itself was built.

if(NOT LDB_BPF_AGENT_BUILD)
  return()
endif()

# -----------------------------------------------------------------------
# Optional CO-RE skeleton compile + generate. When the host has clang
# AND bpftool, we compile src/probe_agent/bpf/hello.bpf.c into a CO-RE
# object and emit src/probe_agent/bpf/hello.skel.h. The agent picks the
# skeleton up via LDB_BPF_HAS_SKELETON. Without the toolchain the agent
# is still built, just reporting embedded_programs:[] over the wire.

set(LDB_BPF_SKEL_DIR "${CMAKE_CURRENT_BINARY_DIR}/bpf")
set(LDB_BPF_SKEL_HEADER "${LDB_BPF_SKEL_DIR}/hello.skel.h")

if(LDB_BPF_HAVE_TOOLCHAIN)
  file(MAKE_DIRECTORY "${LDB_BPF_SKEL_DIR}")
  set(LDB_BPF_SRC "${CMAKE_CURRENT_SOURCE_DIR}/bpf/hello.bpf.c")
  set(LDB_BPF_OBJ "${LDB_BPF_SKEL_DIR}/hello.bpf.o")

  # libbpf header include dirs — re-derived from pkg-config because
  # ldb_libbpf is an INTERFACE library and we need the raw -I list for
  # the standalone clang invocation.
  set(_LDB_BPF_INCLUDES "")
  foreach(_d IN LISTS LDB_LIBBPF_INCLUDE_DIRS)
    list(APPEND _LDB_BPF_INCLUDES "-I${_d}")
  endforeach()

  # Architecture target. We only support x86_64 + aarch64 in phase-1;
  # gate accordingly.
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    set(_LDB_BPF_ARCH "x86")
  elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    set(_LDB_BPF_ARCH "arm64")
  else()
    set(_LDB_BPF_ARCH "x86")
  endif()

  add_custom_command(
    OUTPUT "${LDB_BPF_OBJ}"
    COMMAND "${LDB_BPF_CLANG}"
      -target bpf
      -O2 -g
      -D__TARGET_ARCH_${_LDB_BPF_ARCH}
      ${_LDB_BPF_INCLUDES}
      -c "${LDB_BPF_SRC}"
      -o "${LDB_BPF_OBJ}"
    DEPENDS "${LDB_BPF_SRC}"
    COMMENT "Compiling BPF object hello.bpf.o"
    VERBATIM
  )

  add_custom_command(
    OUTPUT "${LDB_BPF_SKEL_HEADER}"
    COMMAND "${LDB_BPF_BPFTOOL}" gen skeleton "${LDB_BPF_OBJ}" > "${LDB_BPF_SKEL_HEADER}"
    DEPENDS "${LDB_BPF_OBJ}"
    COMMENT "Generating BPF skeleton hello.skel.h"
    VERBATIM
  )

  add_custom_target(ldb_bpf_skeleton DEPENDS "${LDB_BPF_SKEL_HEADER}")
endif()

# -----------------------------------------------------------------------
# Agent binary.

set(LDB_PROBE_AGENT_SOURCES
  main.cpp
  bpf_runtime.cpp
  protocol.cpp
)

add_executable(ldb-probe-agent ${LDB_PROBE_AGENT_SOURCES})

target_include_directories(ldb-probe-agent PRIVATE
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/src"
)

target_link_libraries(ldb-probe-agent PRIVATE
  ldb_json
  ldb_libbpf
  ldb_warnings
)

if(LDB_BPF_HAVE_TOOLCHAIN)
  target_compile_definitions(ldb-probe-agent PRIVATE LDB_BPF_HAS_SKELETON=1)
  # Pull the generated header in. The skeleton lives under
  # ${CMAKE_CURRENT_BINARY_DIR}/bpf/ — match that with the include path
  # the source uses: "probe_agent/bpf/hello.skel.h".
  target_include_directories(ldb-probe-agent PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}/.."  # so probe_agent/bpf/... resolves
  )
  add_dependencies(ldb-probe-agent ldb_bpf_skeleton)
endif()
