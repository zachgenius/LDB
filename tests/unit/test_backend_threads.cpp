// Tests for DebuggerBackend thread + frame enumeration.
//
// We launch the structs fixture with stop_at_entry=true so the process
// is paused at the entry point with a single thread and at least one
// frame on the stack. The exact entry-point function (_dyld_start on
// Mach-O, _start on ELF) and the stack depth are platform-dependent,
// so we assert on shape and invariants rather than specific names.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"

#include <memory>

using ldb::backend::FrameInfo;
using ldb::backend::LaunchOptions;
using ldb::backend::LldbBackend;
using ldb::backend::ProcessState;
using ldb::backend::TargetId;
using ldb::backend::ThreadInfo;

namespace {

constexpr const char* kFixturePath = LDB_FIXTURE_STRUCTS_PATH;

struct LaunchedFixture {
  std::unique_ptr<LldbBackend> backend;
  TargetId target_id;

  ~LaunchedFixture() {
    if (backend && target_id != 0) {
      try { backend->kill_process(target_id); } catch (...) {}
    }
  }
};

LaunchedFixture launched_at_entry() {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kFixturePath);
  REQUIRE(open.target_id != 0);

  LaunchOptions opts;
  opts.stop_at_entry = true;
  auto status = be->launch_process(open.target_id, opts);
  REQUIRE(status.state == ProcessState::kStopped);

  return {std::move(be), open.target_id};
}

}  // namespace

TEST_CASE("thread.list: stopped process exposes at least one thread",
          "[backend][threads]") {
  auto fx = launched_at_entry();
  auto threads = fx.backend->list_threads(fx.target_id);

  REQUIRE_FALSE(threads.empty());
  for (const auto& t : threads) {
    CHECK(t.tid != 0);
    CHECK(t.index >= 1);  // LLDB index ids are 1-based
    CHECK(t.pc != 0);
    // SP can theoretically be 0 in pathological cases but at the entry
    // point on Linux/macOS it's well-defined.
    CHECK(t.sp != 0);
    CHECK(t.state == ProcessState::kStopped);
  }
}

TEST_CASE("thread.list: thread ids are unique",
          "[backend][threads]") {
  auto fx = launched_at_entry();
  auto threads = fx.backend->list_threads(fx.target_id);

  for (size_t i = 0; i < threads.size(); ++i) {
    for (size_t j = i + 1; j < threads.size(); ++j) {
      CHECK(threads[i].tid != threads[j].tid);
    }
  }
}

TEST_CASE("thread.list: with no process returns empty",
          "[backend][threads]") {
  auto be = std::make_unique<LldbBackend>();
  auto res = be->open_executable(kFixturePath);
  REQUIRE(res.target_id != 0);

  auto threads = be->list_threads(res.target_id);
  CHECK(threads.empty());
}

TEST_CASE("thread.list: invalid target_id throws backend::Error",
          "[backend][threads][error]") {
  auto fx = launched_at_entry();
  CHECK_THROWS_AS(fx.backend->list_threads(/*tid=*/9999),
                  ldb::backend::Error);
}

// --- thread.frames ---------------------------------------------------------

TEST_CASE("thread.frames: at least one frame on the entry-point thread",
          "[backend][threads][frames]") {
  auto fx = launched_at_entry();
  auto threads = fx.backend->list_threads(fx.target_id);
  REQUIRE_FALSE(threads.empty());

  auto frames = fx.backend->list_frames(
      fx.target_id, threads[0].tid, /*max_depth=*/0);
  REQUIRE_FALSE(frames.empty());
}

TEST_CASE("thread.frames: every frame carries a non-zero pc and a frame index",
          "[backend][threads][frames]") {
  auto fx = launched_at_entry();
  auto threads = fx.backend->list_threads(fx.target_id);
  REQUIRE_FALSE(threads.empty());

  auto frames = fx.backend->list_frames(
      fx.target_id, threads[0].tid, /*max_depth=*/0);
  REQUIRE_FALSE(frames.empty());

  // Frames are returned innermost-first; index 0, 1, 2, ...
  for (size_t i = 0; i < frames.size(); ++i) {
    CHECK(frames[i].index == static_cast<std::uint32_t>(i));
    CHECK(frames[i].pc != 0);
  }
}

TEST_CASE("thread.frames: max_depth caps the number of frames returned",
          "[backend][threads][frames]") {
  auto fx = launched_at_entry();
  auto threads = fx.backend->list_threads(fx.target_id);
  REQUIRE_FALSE(threads.empty());

  auto unbounded = fx.backend->list_frames(
      fx.target_id, threads[0].tid, /*max_depth=*/0);
  REQUIRE_FALSE(unbounded.empty());

  std::uint32_t cap = 1;
  auto capped = fx.backend->list_frames(
      fx.target_id, threads[0].tid, cap);
  CHECK(capped.size() <= cap);
  if (!capped.empty()) {
    CHECK(capped[0].pc == unbounded[0].pc);
  }
}

TEST_CASE("thread.frames: bogus tid throws backend::Error",
          "[backend][threads][frames][error]") {
  auto fx = launched_at_entry();
  CHECK_THROWS_AS(
      fx.backend->list_frames(fx.target_id, /*tid=*/0xDEAD'BEEFull, 0),
      ldb::backend::Error);
}

TEST_CASE("thread.frames: invalid target_id throws backend::Error",
          "[backend][threads][frames][error]") {
  auto fx = launched_at_entry();
  CHECK_THROWS_AS(
      fx.backend->list_frames(/*target_id=*/9999, /*tid=*/1, 0),
      ldb::backend::Error);
}
