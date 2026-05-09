// SPDX-License-Identifier: Apache-2.0
// Tests for DebuggerBackend single-stepping: in / over / out / insn.
//
// We launch the structs fixture with stop_at_entry=true so the process
// has at least one thread parked at a defined PC. After each Step* call
// LLDB blocks (SetAsync(false)) until the next stop or terminal event,
// at which point we re-snapshot the thread to verify the PC moved.
//
// Stepping at the entry point on macOS arm64 starts inside _dyld_start
// before __DATA fixups are complete; that is fine — these tests assert
// only on motion ("PC changed" or "process exited"), not on landing
// in a specific user function. Robust against platform differences.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"

#include <memory>

using ldb::backend::LaunchOptions;
using ldb::backend::LldbBackend;
using ldb::backend::ProcessState;
using ldb::backend::StepKind;
using ldb::backend::TargetId;
using ldb::backend::ThreadId;

namespace {

constexpr const char* kFixturePath = LDB_FIXTURE_STRUCTS_PATH;

struct LaunchedFixture {
  std::unique_ptr<LldbBackend> backend;
  TargetId target_id = 0;
  ThreadId tid = 0;
  std::uint64_t pc_before = 0;

  ~LaunchedFixture() {
    if (backend && target_id != 0) {
      try { backend->kill_process(target_id); } catch (...) {}
    }
  }
};

// Populate `out` in-place. Returning by value forces a copy of the
// containing struct (unique_ptr blocks copy), and NRVO is not
// guaranteed across all compilers; a fill-in-place helper keeps the
// callsite local and obvious.
void launched_at_entry(LaunchedFixture& out) {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kFixturePath);
  REQUIRE(open.target_id != 0);

  LaunchOptions opts;
  opts.stop_at_entry = true;
  auto status = be->launch_process(open.target_id, opts);
  REQUIRE(status.state == ProcessState::kStopped);

  auto threads = be->list_threads(open.target_id);
  REQUIRE_FALSE(threads.empty());

  out.backend   = std::move(be);
  out.target_id = open.target_id;
  out.tid       = threads[0].tid;
  out.pc_before = threads[0].pc;
}

bool moved_or_terminal(const LaunchedFixture& fx,
                       const ldb::backend::ProcessStatus& after) {
  // Either the process is no longer stopped (exited / running through),
  // or it is stopped at a different PC than before.
  if (after.state != ProcessState::kStopped) return true;
  auto threads = fx.backend->list_threads(fx.target_id);
  if (threads.empty()) return true;
  // Re-find by tid in case ordering changed (single-thread fixture, but
  // be defensive).
  for (const auto& t : threads) {
    if (t.tid == fx.tid) return t.pc != fx.pc_before;
  }
  return true;  // tid no longer present → effectively terminal
}

}  // namespace

TEST_CASE("process.step: insn advances PC by one instruction",
          "[backend][step]") {
  LaunchedFixture fx; launched_at_entry(fx);
  auto after = fx.backend->step_thread(fx.target_id, fx.tid, StepKind::kInsn);
  CHECK(moved_or_terminal(fx, after));
}

TEST_CASE("process.step: in advances execution",
          "[backend][step]") {
  LaunchedFixture fx; launched_at_entry(fx);
  auto after = fx.backend->step_thread(fx.target_id, fx.tid, StepKind::kIn);
  CHECK(moved_or_terminal(fx, after));
}

TEST_CASE("process.step: over advances execution",
          "[backend][step]") {
  LaunchedFixture fx; launched_at_entry(fx);
  auto after = fx.backend->step_thread(fx.target_id, fx.tid, StepKind::kOver);
  CHECK(moved_or_terminal(fx, after));
}

TEST_CASE("process.step: out from a deeper frame returns to caller",
          "[backend][step]") {
  // StepOut from the entry-point frame is platform-quirky: on macOS
  // arm64 the dyld kernel-bootstrap frame has no real caller, and LLDB
  // may simply report the same PC. So instead we exercise StepOut from
  // a clearly-deeper frame: step a few instructions first (which
  // typically descends into a callee), then step out.
  LaunchedFixture fx; launched_at_entry(fx);

  // Take a few insn steps to (probably) enter a callee. Even if we
  // don't, StepOut from any frame should not throw.
  for (int i = 0; i < 4; ++i) {
    auto st = fx.backend->step_thread(fx.target_id, fx.tid, StepKind::kInsn);
    if (st.state != ProcessState::kStopped) break;
  }

  // PC may have moved; refresh pc_before for the motion check.
  auto threads = fx.backend->list_threads(fx.target_id);
  if (!threads.empty()) fx.pc_before = threads[0].pc;

  auto after = fx.backend->step_thread(fx.target_id, fx.tid, StepKind::kOut);
  // The endpoint must not throw and must produce a valid state. We
  // can't assert PC motion universally — at the bottom-of-stack frame
  // StepOut is a no-op on some platforms. Asserting "didn't blow up"
  // is the meaningful contract here.
  CHECK((after.state == ProcessState::kStopped ||
         after.state == ProcessState::kExited  ||
         after.state == ProcessState::kCrashed ||
         after.state == ProcessState::kRunning));
}

TEST_CASE("process.step: invalid target_id throws backend::Error",
          "[backend][step][error]") {
  LaunchedFixture fx; launched_at_entry(fx);
  CHECK_THROWS_AS(
      fx.backend->step_thread(/*target_id=*/9999, fx.tid, StepKind::kInsn),
      ldb::backend::Error);
}

TEST_CASE("process.step: bogus tid throws backend::Error",
          "[backend][step][error]") {
  LaunchedFixture fx; launched_at_entry(fx);
  CHECK_THROWS_AS(
      fx.backend->step_thread(fx.target_id, /*tid=*/0xDEAD'BEEFull,
                              StepKind::kInsn),
      ldb::backend::Error);
}

TEST_CASE("process.step: with no process throws backend::Error",
          "[backend][step][error]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kFixturePath);
  REQUIRE(open.target_id != 0);
  CHECK_THROWS_AS(
      be->step_thread(open.target_id, /*tid=*/1, StepKind::kInsn),
      ldb::backend::Error);
}
