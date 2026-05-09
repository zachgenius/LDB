// SPDX-License-Identifier: Apache-2.0
// Tests for DebuggerBackend::evaluate_expression (value.eval).
//
// Eval failure (compile error, runtime error, timeout) is *data*, not a
// thrown error: callers want to branch on "expression didn't compile"
// without a transport-level error. Frame resolution failure (bad
// target/tid/frame_index) IS thrown — same contract as frame.locals.
//
// Tests run against the structs fixture launched stop-at-entry. On
// macOS arm64 the entry point is `_dyld_start`, before __DATA pointer
// relocations have run; integer-literal expressions are reliable from
// that frame, while expressions that dereference globals are not.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"

#include <chrono>
#include <memory>
#include <string>

using ldb::backend::EvalOptions;
using ldb::backend::EvalResult;
using ldb::backend::LaunchOptions;
using ldb::backend::LldbBackend;
using ldb::backend::ProcessState;
using ldb::backend::TargetId;
using ldb::backend::ThreadId;
using ldb::backend::ValueInfo;

namespace {

constexpr const char* kFixturePath = LDB_FIXTURE_STRUCTS_PATH;

struct LaunchedFixture {
  std::unique_ptr<LldbBackend> backend;
  TargetId target_id = 0;
  ThreadId tid = 0;
  ~LaunchedFixture() {
    if (backend && target_id != 0) {
      try { backend->kill_process(target_id); } catch (...) {}
    }
  }
};

void launched_at_entry(LaunchedFixture& fx) {
  fx.backend = std::make_unique<LldbBackend>();
  auto open = fx.backend->open_executable(kFixturePath);
  REQUIRE(open.target_id != 0);
  fx.target_id = open.target_id;
  LaunchOptions opts;
  opts.stop_at_entry = true;
  auto st = fx.backend->launch_process(open.target_id, opts);
  REQUIRE(st.state == ProcessState::kStopped);
  auto threads = fx.backend->list_threads(open.target_id);
  REQUIRE_FALSE(threads.empty());
  fx.tid = threads[0].tid;
}

}  // namespace

TEST_CASE("value.eval: integer-literal expression returns a value",
          "[backend][value][eval][live]") {
  LaunchedFixture fx;
  launched_at_entry(fx);

  EvalOptions opts;  // defaults
  auto r = fx.backend->evaluate_expression(
      fx.target_id, fx.tid, /*frame_index=*/0, "1 + 2", opts);

  REQUIRE(r.ok);
  CHECK(r.error.empty());
  // Result should have a numeric summary; we don't pin the exact string
  // because LLDB renders ints as "(int) $0 = 3" or "3" depending on path.
  // The summary is set by to_value_info from GetSummary() || GetValue().
  REQUIRE(r.value.summary.has_value());
  CHECK(r.value.summary->find('3') != std::string::npos);
  // A proper integer expression result has a non-empty type.
  CHECK_FALSE(r.value.type.empty());
}

TEST_CASE("value.eval: bitwise expression on literal constants",
          "[backend][value][eval][live]") {
  LaunchedFixture fx;
  launched_at_entry(fx);

  EvalOptions opts;
  auto r = fx.backend->evaluate_expression(
      fx.target_id, fx.tid, 0, "(int)(0xAA ^ 0x55)", opts);
  REQUIRE(r.ok);
  REQUIRE(r.value.summary.has_value());
  // 0xAA ^ 0x55 = 0xFF = 255
  CHECK((r.value.summary->find("255") != std::string::npos ||
         r.value.summary->find("0xff") != std::string::npos ||
         r.value.summary->find("0xFF") != std::string::npos));
}

TEST_CASE("value.eval: syntax error returns ok=false (data, not throw)",
          "[backend][value][eval][live]") {
  LaunchedFixture fx;
  launched_at_entry(fx);

  EvalOptions opts;
  // A clearly malformed expression. LLDB's expression parser will
  // produce a compile error; we want that surfaced as data.
  EvalResult r;
  CHECK_NOTHROW(r = fx.backend->evaluate_expression(
      fx.target_id, fx.tid, 0, "this is not++ a valid expression %%", opts));
  CHECK_FALSE(r.ok);
  CHECK_FALSE(r.error.empty());
}

TEST_CASE("value.eval: hostile expression bounded by timeout",
          "[backend][value][eval][live]") {
  LaunchedFixture fx;
  launched_at_entry(fx);

  EvalOptions opts;
  opts.timeout_us = 100'000;  // 100ms hard cap
  // An infinite loop. We can't actually call sleep() since there's no
  // libc usable from _dyld_start, but a JIT-evaluated infinite loop
  // covers the same contract: the backend MUST return within roughly
  // the timeout, with ok=false, rather than block forever.
  auto t0 = std::chrono::steady_clock::now();
  EvalResult r;
  CHECK_NOTHROW(r = fx.backend->evaluate_expression(
      fx.target_id, fx.tid, 0,
      "({ int i = 0; while (1) { i++; } i; })", opts));
  auto elapsed = std::chrono::steady_clock::now() - t0;

  CHECK_FALSE(r.ok);
  CHECK_FALSE(r.error.empty());
  // Generous wall-clock bound: 5x the timeout. We just need to verify
  // the call returned in finite time (no hang) — exact promptness is
  // LLDB's job, not ours.
  CHECK(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()
        < 5'000);
}

TEST_CASE("value.eval: invalid target_id throws backend::Error",
          "[backend][value][eval][error]") {
  LaunchedFixture fx;
  launched_at_entry(fx);
  EvalOptions opts;
  CHECK_THROWS_AS(
      fx.backend->evaluate_expression(/*tid=*/9999, fx.tid, 0, "1+1", opts),
      ldb::backend::Error);
}

TEST_CASE("value.eval: bogus thread id throws backend::Error",
          "[backend][value][eval][error]") {
  LaunchedFixture fx;
  launched_at_entry(fx);
  EvalOptions opts;
  CHECK_THROWS_AS(
      fx.backend->evaluate_expression(
          fx.target_id, /*tid=*/0xDEAD'BEEFull, 0, "1+1", opts),
      ldb::backend::Error);
}

TEST_CASE("value.eval: out-of-range frame_index throws backend::Error",
          "[backend][value][eval][error]") {
  LaunchedFixture fx;
  launched_at_entry(fx);
  EvalOptions opts;
  CHECK_THROWS_AS(
      fx.backend->evaluate_expression(
          fx.target_id, fx.tid, /*frame_index=*/9999, "1+1", opts),
      ldb::backend::Error);
}
