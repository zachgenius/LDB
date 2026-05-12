// SPDX-License-Identifier: Apache-2.0
// Tests for DebuggerBackend::suspend_thread — the v1.6 #21 LLDB-side
// completion (docs/26-nonstop-runtime.md §1).
//
// The endpoint is the inverse of continue_thread: park `thread_id` so
// the next process-wide resume leaves it pinned at its current PC.
// LldbBackend's implementation calls SBThread::Suspend(true), which
// works under SetAsync(false) because the bit is honoured by the NEXT
// SBProcess::Continue, not by the suspend call itself.
//
// Coverage:
//   * Live LLDB-launched fixture (sleeper, single-threaded): launch
//     stop-at-entry → suspend the only thread → verify it still
//     shows up in list_threads and the post-suspend snapshot reports
//     a sensible state.
//   * Invalid target_id throws backend::Error.
//   * No live process throws backend::Error.
//   * Unknown thread id throws backend::Error.
//
// The sleeper fixture is single-threaded so we can't directly observe
// "sibling threads kept running while this one stayed parked" from a
// unit test. Multi-threaded suspend semantics are exercised end-to-end
// when the #21 phase-2 listener feeds stop events from a real
// lldb-server target (smoke layer); the unit test here pins the
// per-thread bit-flip contract.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"

#include <memory>

using ldb::backend::LaunchOptions;
using ldb::backend::LldbBackend;
using ldb::backend::ProcessState;
using ldb::backend::TargetId;
using ldb::backend::ThreadId;

namespace {

constexpr const char* kSleeperPath = LDB_FIXTURE_SLEEPER_PATH;

}  // namespace

TEST_CASE("suspend_thread: launched-and-stopped process — call succeeds, "
          "thread remains visible",
          "[backend][thread][suspend]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kSleeperPath);
  REQUIRE(open.target_id != 0);

  LaunchOptions opts;
  opts.stop_at_entry = true;
  auto launched = be->launch_process(open.target_id, opts);
  REQUIRE(launched.state == ProcessState::kStopped);

  auto threads_before = be->list_threads(open.target_id);
  REQUIRE_FALSE(threads_before.empty());
  ThreadId tid = threads_before[0].tid;

  // Suspend doesn't change SBProcess::GetState — the bit is set on the
  // SBThread and only gates the next Continue. We verify the call
  // returns a ProcessStatus (snapshot of post-call state) and doesn't
  // throw.
  auto status = be->suspend_thread(open.target_id, tid);
  CHECK(status.state == ProcessState::kStopped);

  // The thread we just suspended must still be listed — Suspend is a
  // flag flip, not a remove.
  auto threads_after = be->list_threads(open.target_id);
  REQUIRE_FALSE(threads_after.empty());
  bool found = false;
  for (const auto& t : threads_after) {
    if (t.tid == tid) { found = true; break; }
  }
  CHECK(found);

  // Cleanup so the test doesn't leave a live process behind.
  be->kill_process(open.target_id);
}

TEST_CASE("suspend_thread: invalid target_id throws backend::Error",
          "[backend][thread][suspend][error]") {
  auto be = std::make_unique<LldbBackend>();
  CHECK_THROWS_AS(
      be->suspend_thread(/*target_id=*/9999, /*tid=*/1),
      ldb::backend::Error);
}

TEST_CASE("suspend_thread: no live process throws backend::Error",
          "[backend][thread][suspend][error]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kSleeperPath);
  REQUIRE(open.target_id != 0);

  // Target exists but no process has been launched/attached.
  CHECK_THROWS_AS(
      be->suspend_thread(open.target_id, /*tid=*/1),
      ldb::backend::Error);
}

TEST_CASE("suspend_thread: unknown thread id throws backend::Error",
          "[backend][thread][suspend][error]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kSleeperPath);
  REQUIRE(open.target_id != 0);

  LaunchOptions opts;
  opts.stop_at_entry = true;
  auto launched = be->launch_process(open.target_id, opts);
  REQUIRE(launched.state == ProcessState::kStopped);

  // A tid that doesn't match any live thread — picked above the
  // typical kernel-tid range to keep the test robust across kernels.
  CHECK_THROWS_AS(
      be->suspend_thread(open.target_id, /*tid=*/0xDEADBEEFu),
      ldb::backend::Error);

  be->kill_process(open.target_id);
}
