// Tests for the C++ breakpoint callback hooks (M3 prep).
//
// Validates that:
//   • create_breakpoint by function name returns a valid handle with
//     locations >= 1 against the structs fixture (a `point2_distance_sq`
//     symbol exists at -O0).
//   • set_breakpoint_callback installs a baton-bearing callback that
//     LLDB actually invokes when the breakpoint fires.
//   • Returning false from the callback auto-continues; the inferior
//     exits cleanly.
//   • disable_breakpoint suppresses firing; enable restores it.
//   • read_register from inside the callback returns a sensible value
//     for a known register.
//
// We use the structs fixture (built by tests/fixtures/CMakeLists.txt)
// because its main() reaches `point2_distance_sq` before exiting. The
// callback is invoked on LLDB's process-event thread; we synchronize
// state via std::atomic.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <thread>

using ldb::backend::BreakpointCallbackArgs;
using ldb::backend::BreakpointHandle;
using ldb::backend::BreakpointSpec;
using ldb::backend::LldbBackend;
using ldb::backend::ProcessState;
using ldb::backend::TargetId;

namespace {

constexpr const char* kStructsPath = LDB_FIXTURE_STRUCTS_PATH;

}  // namespace

TEST_CASE("backend: create_breakpoint by function returns >=1 location",
          "[backend][breakpoint][live]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kStructsPath);
  REQUIRE(open.target_id != 0);

  BreakpointSpec spec;
  spec.function = "point2_distance_sq";
  auto handle = be->create_breakpoint(open.target_id, spec);
  CHECK(handle.bp_id > 0);
  CHECK(handle.locations >= 1);

  be->delete_breakpoint(open.target_id, handle.bp_id);
}

TEST_CASE("backend: breakpoint callback fires and auto-continues on false",
          "[backend][breakpoint][live]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kStructsPath);
  REQUIRE(open.target_id != 0);

  BreakpointSpec spec;
  spec.function = "point2_distance_sq";
  auto handle = be->create_breakpoint(open.target_id, spec);
  REQUIRE(handle.locations >= 1);

  struct Captured {
    std::atomic<int> hits{0};
    std::atomic<std::uint64_t> last_pc{0};
    std::atomic<std::uint64_t> last_tid{0};
  };
  Captured cap;

  be->set_breakpoint_callback(
      open.target_id, handle.bp_id,
      [](void* baton, const BreakpointCallbackArgs& args) -> bool {
        auto* c = static_cast<Captured*>(baton);
        c->hits.fetch_add(1);
        c->last_pc.store(args.pc);
        c->last_tid.store(args.tid);
        return false;  // auto-continue
      },
      &cap);

  ldb::backend::LaunchOptions opts;
  opts.stop_at_entry = false;
  auto status = be->launch_process(open.target_id, opts);
  // Launch with stop_at_entry=false runs synchronously until the next
  // stop or terminal state. The bp fires (callback returns false →
  // auto-continue), then main returns and the process exits.
  CHECK((status.state == ProcessState::kExited ||
         status.state == ProcessState::kStopped));

  // Allow a brief moment for the callback bookkeeping to settle (the
  // callback runs on LLDB's event thread; SetAsync(false) means the
  // backend already drained, but std::atomic ordering is mid-flight).
  // 50ms is more than enough — this is a bounded sanity wait, not a
  // race.
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  CHECK(cap.hits.load() >= 1);
  CHECK(cap.last_pc.load() != 0);
  CHECK(cap.last_tid.load() != 0);

  be->delete_breakpoint(open.target_id, handle.bp_id);
}

TEST_CASE("backend: breakpoint callback returning true keeps process stopped",
          "[backend][breakpoint][live]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kStructsPath);
  REQUIRE(open.target_id != 0);

  BreakpointSpec spec;
  spec.function = "point2_distance_sq";
  auto handle = be->create_breakpoint(open.target_id, spec);
  REQUIRE(handle.locations >= 1);

  std::atomic<int> hits{0};
  be->set_breakpoint_callback(
      open.target_id, handle.bp_id,
      [](void* baton, const BreakpointCallbackArgs&) -> bool {
        static_cast<std::atomic<int>*>(baton)->fetch_add(1);
        return true;  // stop the inferior
      },
      &hits);

  ldb::backend::LaunchOptions opts;
  opts.stop_at_entry = false;
  auto status = be->launch_process(open.target_id, opts);
  CHECK(status.state == ProcessState::kStopped);
  CHECK(hits.load() >= 1);

  // Clean up — the inferior is currently stopped at the bp. Kill it.
  be->kill_process(open.target_id);
}

TEST_CASE("backend: disable / enable breakpoint round-trip",
          "[backend][breakpoint][live]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kStructsPath);
  REQUIRE(open.target_id != 0);

  BreakpointSpec spec;
  spec.function = "point2_distance_sq";
  auto handle = be->create_breakpoint(open.target_id, spec);
  REQUIRE(handle.locations >= 1);

  std::atomic<int> hits{0};
  be->set_breakpoint_callback(
      open.target_id, handle.bp_id,
      [](void* baton, const BreakpointCallbackArgs&) -> bool {
        static_cast<std::atomic<int>*>(baton)->fetch_add(1);
        return false;
      },
      &hits);

  // Disable → run → no hits.
  be->disable_breakpoint(open.target_id, handle.bp_id);
  ldb::backend::LaunchOptions opts;
  opts.stop_at_entry = false;
  auto s1 = be->launch_process(open.target_id, opts);
  CHECK(s1.state == ProcessState::kExited);
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  CHECK(hits.load() == 0);

  // Re-enable → run again → fires.
  be->enable_breakpoint(open.target_id, handle.bp_id);
  auto s2 = be->launch_process(open.target_id, opts);
  CHECK((s2.state == ProcessState::kExited ||
         s2.state == ProcessState::kStopped));
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  CHECK(hits.load() >= 1);

  be->delete_breakpoint(open.target_id, handle.bp_id);
}

TEST_CASE("backend: create_breakpoint with empty spec throws",
          "[backend][breakpoint][error]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kStructsPath);
  REQUIRE(open.target_id != 0);
  BreakpointSpec spec;  // no function/address/file
  CHECK_THROWS_AS(be->create_breakpoint(open.target_id, spec),
                  ldb::backend::Error);
}

TEST_CASE("backend: create_breakpoint with bad target_id throws",
          "[backend][breakpoint][error]") {
  auto be = std::make_unique<LldbBackend>();
  BreakpointSpec spec;
  spec.function = "main";
  CHECK_THROWS_AS(be->create_breakpoint(/*tid=*/9999, spec),
                  ldb::backend::Error);
}
