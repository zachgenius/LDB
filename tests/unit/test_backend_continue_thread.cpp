// Tests for DebuggerBackend::continue_thread (Tier 4 §14, scoped slice).
//
// In v0.3 the implementation is a *sync passthrough*: continue_thread
// behaves identically to continue_process. The protocol surface is
// already async-shaped so client code can switch behavior on the
// daemon-version handshake when v0.4 lands true SBProcess::SetAsync(true)
// + per-thread keep-running.
//
// These tests pin the v0.3 contract:
//   * continue_thread on a stopped process resumes it just like
//     continue_process and blocks (sync mode) until the next stop / exit.
//   * Invalid target_id throws backend::Error.
//   * No live process throws backend::Error.
//   * (Bogus tid is currently tolerated as a no-op tid argument because
//     the call falls through to a process-wide continue. This will
//     tighten in v0.4 when the tid actually selects a thread.)

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"

#include <memory>

using ldb::backend::LaunchOptions;
using ldb::backend::LldbBackend;
using ldb::backend::ProcessState;
using ldb::backend::TargetId;
using ldb::backend::ThreadId;

namespace {

constexpr const char* kFixturePath = LDB_FIXTURE_STRUCTS_PATH;

bool is_terminal(ProcessState s) {
  return s == ProcessState::kExited ||
         s == ProcessState::kCrashed ||
         s == ProcessState::kDetached;
}

}  // namespace

TEST_CASE("continue_thread: from stop-at-entry runs to completion (sync passthrough)",
          "[backend][thread][continue]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kFixturePath);
  REQUIRE(open.target_id != 0);

  LaunchOptions opts;
  opts.stop_at_entry = true;
  auto launched = be->launch_process(open.target_id, opts);
  REQUIRE(launched.state == ProcessState::kStopped);

  auto threads = be->list_threads(open.target_id);
  REQUIRE_FALSE(threads.empty());
  ThreadId tid = threads[0].tid;

  // continue_thread is a sync passthrough today: blocks until the next
  // stop or exit, just like continue_process. structs returns from main
  // almost immediately, so we should land in kExited.
  auto exited = be->continue_thread(open.target_id, tid);
  CHECK(is_terminal(exited.state));
  CHECK(exited.state == ProcessState::kExited);
}

TEST_CASE("continue_thread: invalid target_id throws backend::Error",
          "[backend][thread][continue][error]") {
  auto be = std::make_unique<LldbBackend>();
  CHECK_THROWS_AS(
      be->continue_thread(/*target_id=*/9999, /*tid=*/1),
      ldb::backend::Error);
}

TEST_CASE("continue_thread: no live process throws backend::Error",
          "[backend][thread][continue][error]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kFixturePath);
  REQUIRE(open.target_id != 0);

  // Target exists but no process has been launched/attached.
  CHECK_THROWS_AS(
      be->continue_thread(open.target_id, /*tid=*/1),
      ldb::backend::Error);
}
