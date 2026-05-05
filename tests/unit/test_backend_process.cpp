// Tests for DebuggerBackend process lifecycle: launch / state /
// continue / kill against the structs fixture.
//
// We rely on SetAsync(false) in LldbBackend so process operations
// block until the next stop event. structs returns from main almost
// immediately, so:
//
//   • launch(stop_at_entry=true) → stops at entry, valid pid
//   • continue → blocks, returns kExited with a valid exit_code
//   • kill from kStopped → kExited (or kCrashed depending on platform)

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"

#include <memory>

using ldb::backend::LaunchOptions;
using ldb::backend::LldbBackend;
using ldb::backend::ProcessState;
using ldb::backend::ProcessStatus;
using ldb::backend::TargetId;

namespace {

constexpr const char* kFixturePath = LDB_FIXTURE_STRUCTS_PATH;

struct OpenedFixture {
  std::unique_ptr<LldbBackend> backend;
  TargetId target_id;
};

OpenedFixture open_fixture() {
  auto be = std::make_unique<LldbBackend>();
  auto res = be->open_executable(kFixturePath);
  REQUIRE(res.target_id != 0);
  return {std::move(be), res.target_id};
}

bool is_terminal(ProcessState s) {
  return s == ProcessState::kExited ||
         s == ProcessState::kCrashed ||
         s == ProcessState::kDetached;
}

}  // namespace

TEST_CASE("process.state: no process before launch yields kNone",
          "[backend][process]") {
  auto fx = open_fixture();
  auto st = fx.backend->get_process_state(fx.target_id);
  CHECK(st.state == ProcessState::kNone);
  CHECK(st.pid == 0);
}

TEST_CASE("process.launch: stop_at_entry stops the process at entry",
          "[backend][process]") {
  auto fx = open_fixture();

  LaunchOptions opts;
  opts.stop_at_entry = true;
  auto st = fx.backend->launch_process(fx.target_id, opts);

  CHECK(st.state == ProcessState::kStopped);
  CHECK(st.pid > 0);

  // Subsequent state query agrees.
  auto st2 = fx.backend->get_process_state(fx.target_id);
  CHECK(st2.state == ProcessState::kStopped);
  CHECK(st2.pid == st.pid);

  // Clean up so we don't leak a stopped process across tests.
  fx.backend->kill_process(fx.target_id);
}

TEST_CASE("process.continue: from stop-at-entry runs to completion",
          "[backend][process]") {
  auto fx = open_fixture();

  LaunchOptions opts;
  opts.stop_at_entry = true;
  auto launched = fx.backend->launch_process(fx.target_id, opts);
  REQUIRE(launched.state == ProcessState::kStopped);

  auto exited = fx.backend->continue_process(fx.target_id);
  CHECK(is_terminal(exited.state));
  CHECK(exited.state == ProcessState::kExited);

  // structs returns a XOR of byte values — between 0 and 255.
  CHECK(exited.exit_code >= 0);
  CHECK(exited.exit_code <= 255);
}

TEST_CASE("process.kill: from stop-at-entry terminates immediately",
          "[backend][process]") {
  auto fx = open_fixture();

  LaunchOptions opts;
  opts.stop_at_entry = true;
  auto launched = fx.backend->launch_process(fx.target_id, opts);
  REQUIRE(launched.state == ProcessState::kStopped);

  auto killed = fx.backend->kill_process(fx.target_id);
  CHECK(is_terminal(killed.state));
}

TEST_CASE("process.continue: with no process throws backend::Error",
          "[backend][process][error]") {
  auto fx = open_fixture();
  CHECK_THROWS_AS(fx.backend->continue_process(fx.target_id),
                  ldb::backend::Error);
}

TEST_CASE("process.kill: with no process is a no-op (idempotent)",
          "[backend][process]") {
  auto fx = open_fixture();
  auto st = fx.backend->kill_process(fx.target_id);
  CHECK(st.state == ProcessState::kNone);
}

TEST_CASE("process.launch: invalid target_id throws backend::Error",
          "[backend][process][error]") {
  auto fx = open_fixture();
  LaunchOptions opts;
  CHECK_THROWS_AS(
      fx.backend->launch_process(/*tid=*/9999, opts),
      ldb::backend::Error);
}

TEST_CASE("process.state: invalid target_id throws backend::Error",
          "[backend][process][error]") {
  auto fx = open_fixture();
  CHECK_THROWS_AS(
      fx.backend->get_process_state(/*tid=*/9999),
      ldb::backend::Error);
}

TEST_CASE("process: launching twice on the same target replaces the first",
          "[backend][process]") {
  auto fx = open_fixture();

  LaunchOptions opts;
  opts.stop_at_entry = true;
  auto first = fx.backend->launch_process(fx.target_id, opts);
  REQUIRE(first.state == ProcessState::kStopped);

  // Launching again is allowed — we treat it as kill-and-relaunch.
  auto second = fx.backend->launch_process(fx.target_id, opts);
  CHECK(second.state == ProcessState::kStopped);
  CHECK(second.pid > 0);
  CHECK(second.pid != first.pid);  // new process

  fx.backend->kill_process(fx.target_id);
}
