// SPDX-License-Identifier: Apache-2.0
// Tests for the memory primitives: read_memory / read_cstring /
// list_regions / search_memory.
//
// Run against the structs fixture (launched stop-at-entry) for symbol
// lookups (g_origin, g_login_template, k_schema_name) and against the
// sleeper fixture (launched stop-at-entry) for the global counter and
// k_marker tests.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"

#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstring>
#include <memory>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

using ldb::backend::LaunchOptions;
using ldb::backend::LldbBackend;
using ldb::backend::MemoryRegion;
using ldb::backend::MemorySearchHit;
using ldb::backend::ProcessState;
using ldb::backend::SymbolKind;
using ldb::backend::SymbolQuery;
using ldb::backend::TargetId;

namespace {

constexpr const char* kStructsPath  = LDB_FIXTURE_STRUCTS_PATH;
constexpr const char* kSleeperPath  = LDB_FIXTURE_SLEEPER_PATH;

struct LaunchedFixture {
  std::unique_ptr<LldbBackend> backend;
  TargetId target_id;
  ~LaunchedFixture() {
    if (backend && target_id != 0) {
      try { backend->kill_process(target_id); } catch (...) {}
    }
  }
};

LaunchedFixture launch_stop_at_entry(const char* path) {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(path);
  REQUIRE(open.target_id != 0);
  LaunchOptions opts;
  opts.stop_at_entry = true;
  auto st = be->launch_process(open.target_id, opts);
  REQUIRE(st.state == ProcessState::kStopped);
  return {std::move(be), open.target_id};
}

// Spawn the sleeper as an external process, wait for its READY line,
// then attach via the backend so we read memory from a fully-relocated
// process. Returns both the backend handle and the inferior pid.
struct AttachedSleeper {
  std::unique_ptr<LldbBackend> backend;
  TargetId target_id;
  pid_t    inferior_pid = -1;
  int      stdout_fd    = -1;

  ~AttachedSleeper() {
    if (backend && target_id != 0) {
      try { backend->detach_process(target_id); } catch (...) {}
    }
    if (inferior_pid > 0) {
      ::kill(inferior_pid, SIGKILL);
      int status = 0;
      ::waitpid(inferior_pid, &status, 0);
    }
    if (stdout_fd >= 0) ::close(stdout_fd);
  }
};

std::unique_ptr<AttachedSleeper> attach_to_sleeper() {
  int pipefd[2];
  REQUIRE(::pipe(pipefd) == 0);
  pid_t child = ::fork();
  REQUIRE(child >= 0);
  if (child == 0) {
    ::dup2(pipefd[1], STDOUT_FILENO);
    ::close(pipefd[0]);
    ::close(pipefd[1]);
    char* const argv[] = {const_cast<char*>(kSleeperPath), nullptr};
    ::execv(kSleeperPath, argv);
    _exit(127);
  }
  ::close(pipefd[1]);

  // Wait for READY line.
  std::string line;
  char buf[256];
  for (int tries = 0; tries < 50 &&
       line.find('\n') == std::string::npos; ++tries) {
    ssize_t n = ::read(pipefd[0], buf, sizeof(buf));
    if (n > 0) line.append(buf, buf + n);
    else std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  REQUIRE(line.find("READY=") != std::string::npos);

  auto a = std::make_unique<AttachedSleeper>();
  a->backend = std::make_unique<LldbBackend>();
  a->inferior_pid = child;
  a->stdout_fd    = pipefd[0];
  auto open = a->backend->create_empty_target();
  REQUIRE(open.target_id != 0);
  a->target_id = open.target_id;
  auto st = a->backend->attach(open.target_id, child);
  REQUIRE(st.state == ProcessState::kStopped);
  return a;
}

}  // namespace

TEST_CASE("mem.read: rejects oversize requests with backend::Error",
          "[backend][memory][live][error]") {
  auto fx = launch_stop_at_entry(kStructsPath);
  // 2 MiB > our 1 MiB cap; should throw.
  CHECK_THROWS_AS(fx.backend->read_memory(fx.target_id, 0x1000, 2 * 1024 * 1024),
                  ldb::backend::Error);
}

TEST_CASE("mem.read: invalid target_id throws backend::Error",
          "[backend][memory][error]") {
  auto be = std::make_unique<LldbBackend>();
  CHECK_THROWS_AS(be->read_memory(/*tid=*/9999, 0, 1),
                  ldb::backend::Error);
}

TEST_CASE("mem.read: returns 8 bytes from a relocated global on the sleeper",
          "[backend][memory][live]") {
  auto a = attach_to_sleeper();

  auto syms = a->backend->find_symbols(
      a->target_id, {"g_counter", SymbolKind::kAny});
  REQUIRE_FALSE(syms.empty());
  REQUIRE(syms[0].load_address.has_value());

  auto bytes = a->backend->read_memory(
      a->target_id, *syms[0].load_address, /*size=*/8);
  REQUIRE(bytes.size() == 8);
  // Sleeper increments g_counter only on signal-resume; we attached to
  // a process that's pause()ing, so the counter is exactly 0.
  for (auto b : bytes) CHECK(b == 0);
}

TEST_CASE("mem.read_cstr: reads the sleeper's k_marker via pointer indirection",
          "[backend][memory][live]") {
  auto a = attach_to_sleeper();

  // k_marker is a const char* const pointing to "LDB_SLEEPER_MARKER_v1".
  auto syms = a->backend->find_symbols(
      a->target_id, {"k_marker", SymbolKind::kAny});
  REQUIRE_FALSE(syms.empty());
  REQUIRE(syms[0].load_address.has_value());

  auto ptr_bytes = a->backend->read_memory(
      a->target_id, *syms[0].load_address, 8);
  REQUIRE(ptr_bytes.size() == 8);
  std::uint64_t string_addr = 0;
  for (unsigned i = 0; i < 8; ++i) {
    string_addr |= static_cast<std::uint64_t>(ptr_bytes[i]) << (i * 8u);
  }
  REQUIRE(string_addr != 0);

  auto s = a->backend->read_cstring(a->target_id, string_addr, /*max=*/256);
  CHECK(s == "LDB_SLEEPER_MARKER_v1");
}

TEST_CASE("mem.read_cstr: max_len caps the result",
          "[backend][memory][live]") {
  auto a = attach_to_sleeper();

  auto syms = a->backend->find_symbols(
      a->target_id, {"k_marker", SymbolKind::kAny});
  REQUIRE_FALSE(syms.empty());
  REQUIRE(syms[0].load_address.has_value());

  auto ptr_bytes = a->backend->read_memory(
      a->target_id, *syms[0].load_address, 8);
  REQUIRE(ptr_bytes.size() == 8);
  std::uint64_t string_addr = 0;
  for (unsigned i = 0; i < 8; ++i) {
    string_addr |= static_cast<std::uint64_t>(ptr_bytes[i]) << (i * 8u);
  }

  auto s = a->backend->read_cstring(a->target_id, string_addr, /*max=*/4);
  CHECK(s.size() <= 4);
  CHECK(s == "LDB_");
}

TEST_CASE("mem.regions: returns at least one executable region",
          "[backend][memory][live]") {
  auto fx = launch_stop_at_entry(kStructsPath);
  auto regions = fx.backend->list_regions(fx.target_id);
  REQUIRE_FALSE(regions.empty());

  bool any_exec = std::any_of(regions.begin(), regions.end(),
      [](const MemoryRegion& r) { return r.executable; });
  CHECK(any_exec);

  for (const auto& r : regions) {
    CHECK(r.size > 0);
  }
}

TEST_CASE("mem.search: finds the marker string in the sleeper's memory",
          "[backend][memory][live]") {
  auto a = attach_to_sleeper();
  std::string needle_str = "LDB_SLEEPER_MARKER_v1";
  std::vector<std::uint8_t> needle(needle_str.begin(), needle_str.end());

  auto hits = a->backend->search_memory(
      a->target_id, /*start=*/0, /*length=*/0, needle, /*max_hits=*/16);
  REQUIRE_FALSE(hits.empty());
  for (auto& h : hits) CHECK(h.address != 0);
}

TEST_CASE("mem.search: respects max_hits cap",
          "[backend][memory][live]") {
  auto a = attach_to_sleeper();
  // A single byte will match many places — useful to test the cap.
  std::vector<std::uint8_t> needle = {0x00};
  auto hits = a->backend->search_memory(
      a->target_id, 0, 0, needle, /*max_hits=*/3);
  CHECK(hits.size() <= 3);
}
