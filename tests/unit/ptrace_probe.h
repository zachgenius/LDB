// SPDX-License-Identifier: Apache-2.0
//
// Shared SKIP-gate for live-attach unit tests (mirror of
// tests/smoke/_ptrace_probe.py). Linux's `kernel.yama.ptrace_scope`
// defaults to 1 on most distros, blocking PTRACE_ATTACH against a
// non-child inferior unless the test runner is root or carries
// CAP_SYS_PTRACE. Without a skip-gate, these tests fail noisily on
// every dev box that hasn't set ptrace_scope=0.
//
// Use:
//
//   TEST_CASE("foo: attaches to sleeper", "[backend][live]") {
//     LDB_SKIP_WITHOUT_PTRACE();
//     auto be = std::make_unique<LldbBackend>();
//     ...
//   }
//
// On non-Linux hosts the macro is a no-op (no Yama LSM). On Linux,
// skip when ptrace_scope > 0 unless root or the ldb_unit_tests binary
// carries cap_sys_ptrace.
#pragma once

#include <catch_amalgamated.hpp>

#include <cstdint>
#include <fstream>
#include <string>
#include <unistd.h>

namespace ldb::test {

#ifdef __linux__
// CAP_SYS_PTRACE is bit 19 of the capability mask. /proc/self/status
// reports CapEff as a 16-hex-char field — parse it directly, no
// libcap dependency required.
inline bool _has_cap_sys_ptrace_self() {
  std::ifstream f("/proc/self/status");
  if (!f) return false;
  std::string line;
  while (std::getline(f, line)) {
    if (line.rfind("CapEff:", 0) != 0) continue;
    auto pos = line.find_first_of("0123456789abcdefABCDEF");
    if (pos == std::string::npos) return false;
    std::uint64_t mask = 0;
    try {
      mask = std::stoull(line.substr(pos), nullptr, 16);
    } catch (...) { return false; }
    return (mask & (1ULL << 19)) != 0;  // CAP_SYS_PTRACE = 19
  }
  return false;
}
#endif

inline bool ptrace_attach_available() {
#ifndef __linux__
  return true;
#else
  std::ifstream f("/proc/sys/kernel/yama/ptrace_scope");
  if (!f) return true;  // Yama not enabled.
  int scope = -1;
  f >> scope;
  if (scope == 0) return true;
  if (::geteuid() == 0) return true;
  return _has_cap_sys_ptrace_self();
#endif
}

}  // namespace ldb::test

#define LDB_SKIP_WITHOUT_PTRACE()                                       \
  do {                                                                  \
    if (!::ldb::test::ptrace_attach_available()) {                      \
      SKIP("ptrace_scope=1 and not root / no CAP_SYS_PTRACE — "         \
           "set sysctl kernel.yama.ptrace_scope=0 or "                  \
           "setcap cap_sys_ptrace+ep on the test binary to enable");    \
    }                                                                   \
  } while (0)
