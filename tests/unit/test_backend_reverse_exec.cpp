// SPDX-License-Identifier: Apache-2.0
// Negative-path coverage for the backend reverse-execution methods.
// These tests do NOT require rr — they verify capability gating and
// kind-validation in LldbBackend::reverse_continue / reverse_step_thread.
//
// Positive-path (live rr record/replay) coverage lives in
// test_backend_reverse_exec_rr.cpp, which SKIPs when rr is unavailable.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"

#include <memory>
#include <string>

using ldb::backend::LldbBackend;
using ldb::backend::ReverseStepKind;

namespace {
// Match the existing rr connect_remote tests: they reuse the structs
// fixture to put a real process behind the target. Reverse-exec on it
// must fail because the target was not opened via rr://.
constexpr const char* kFixturePath = LDB_FIXTURE_STRUCTS_PATH;
}  // namespace

TEST_CASE("reverse_continue: empty target throws (no live process)",
          "[backend][reverse][error]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->create_empty_target();
  REQUIRE(open.target_id != 0);

  CHECK_THROWS_AS(be->reverse_continue(open.target_id),
                  ldb::backend::Error);
}

TEST_CASE("reverse_step_thread: empty target throws (no live process)",
          "[backend][reverse][error]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->create_empty_target();
  REQUIRE(open.target_id != 0);

  CHECK_THROWS_AS(
      be->reverse_step_thread(open.target_id, /*tid=*/1, ReverseStepKind::kInsn),
      ldb::backend::Error);
}

TEST_CASE("reverse_continue: non-rr live target is forbidden",
          "[backend][reverse][error]") {
  // open_executable + launch is the standard ProcessLaunch path; the
  // resulting target has no rr replay attached and must reject
  // reverse-continue with a clear message ("does not support reverse").
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kFixturePath);
  REQUIRE(open.target_id != 0);

  ldb::backend::LaunchOptions opts;
  opts.stop_at_entry = true;
  auto st = be->launch_process(open.target_id, opts);
  REQUIRE(st.state == ldb::backend::ProcessState::kStopped);

  try {
    be->reverse_continue(open.target_id);
    FAIL("reverse_continue on non-rr target should have thrown");
  } catch (const ldb::backend::Error& e) {
    const std::string what = e.what();
    // The dispatcher-level mapping turns this into -32003 forbidden;
    // the backend message must surface "reverse" so the operator
    // understands why.
    CHECK(what.find("reverse") != std::string::npos);
  }

  be->kill_process(open.target_id);
}

TEST_CASE("reverse_step_thread: kIn / kOver / kOut accepted at the backend",
          "[backend][reverse]") {
  // v1.3: the kind=in/over/out path is implemented via a bounded `bs`
  // loop with source-line + frame-depth termination. On a target with
  // no live process the backend still rejects (no process to step) —
  // we just want to confirm it's the no-process check that fires, not
  // a "kind not supported" guard.
  auto be = std::make_unique<LldbBackend>();
  auto open = be->create_empty_target();
  REQUIRE(open.target_id != 0);

  for (auto k : {ReverseStepKind::kIn, ReverseStepKind::kOver,
                 ReverseStepKind::kOut}) {
    try {
      be->reverse_step_thread(open.target_id, 1, k);
      FAIL("reverse_step_thread on empty target should have thrown");
    } catch (const ldb::backend::Error& e) {
      const std::string what = e.what();
      // The empty-target path should hit "no process", not the old
      // "kind not supported" message we removed in v1.3.
      CHECK(what.find("kind not supported") == std::string::npos);
    }
  }
}
