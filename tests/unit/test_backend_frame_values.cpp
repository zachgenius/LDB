// Tests for DebuggerBackend frame value enumeration:
// list_locals / list_args / list_registers.
//
// Run against the structs fixture launched stop-at-entry. At the entry
// point, args/locals on the innermost frame may legitimately be empty
// (we're inside dyld/_start), so we assert on shape and no-throw rather
// than presence. Registers are always populated; we assert at least
// one general-purpose program-counter register exists and that bytes
// are present for it.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"

#include <algorithm>
#include <memory>
#include <string>

using ldb::backend::LaunchOptions;
using ldb::backend::LldbBackend;
using ldb::backend::ProcessState;
using ldb::backend::TargetId;
using ldb::backend::ThreadInfo;
using ldb::backend::ValueInfo;

namespace {

constexpr const char* kFixturePath = LDB_FIXTURE_STRUCTS_PATH;

struct LaunchedFixture {
  std::unique_ptr<LldbBackend> backend;
  TargetId target_id;
  std::uint64_t tid;

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

  auto threads = be->list_threads(open.target_id);
  REQUIRE_FALSE(threads.empty());

  return {std::move(be), open.target_id, threads[0].tid};
}

bool has_pc_register(const std::vector<ValueInfo>& regs) {
  for (const auto& r : regs) {
    // arm64 = "pc", x86_64 = "rip", i386 = "eip". Tolerate any of them.
    if (r.name == "pc" || r.name == "rip" || r.name == "eip") return true;
  }
  return false;
}

}  // namespace

TEST_CASE("frame.locals: returns without error at entry frame",
          "[backend][frame][values][live]") {
  auto fx = launched_at_entry();
  auto vals = fx.backend->list_locals(fx.target_id, fx.tid, /*frame=*/0);
  // Entry frame may have no locals visible; returning is what matters.
  for (const auto& v : vals) {
    CHECK(v.kind.has_value());
    CHECK(*v.kind == "local");
  }
}

TEST_CASE("frame.args: returns without error at entry frame",
          "[backend][frame][values][live]") {
  auto fx = launched_at_entry();
  auto vals = fx.backend->list_args(fx.target_id, fx.tid, /*frame=*/0);
  for (const auto& v : vals) {
    CHECK(v.kind.has_value());
    CHECK(*v.kind == "arg");
  }
}

TEST_CASE("frame.registers: every frame has at least the program counter",
          "[backend][frame][values][live]") {
  auto fx = launched_at_entry();
  auto regs = fx.backend->list_registers(fx.target_id, fx.tid, /*frame=*/0);

  REQUIRE_FALSE(regs.empty());
  CHECK(has_pc_register(regs));

  // At least one register has bytes populated.
  bool any_bytes = std::any_of(regs.begin(), regs.end(),
      [](const ValueInfo& v) { return !v.bytes.empty(); });
  CHECK(any_bytes);

  for (const auto& r : regs) {
    CHECK_FALSE(r.name.empty());
    CHECK(r.kind.has_value());
    CHECK(*r.kind == "register");
  }
}

TEST_CASE("frame.locals: invalid target_id throws backend::Error",
          "[backend][frame][values][error]") {
  auto fx = launched_at_entry();
  CHECK_THROWS_AS(
      fx.backend->list_locals(/*target_id=*/9999, fx.tid, 0),
      ldb::backend::Error);
}

TEST_CASE("frame.args: bogus tid throws backend::Error",
          "[backend][frame][values][error]") {
  auto fx = launched_at_entry();
  CHECK_THROWS_AS(
      fx.backend->list_args(fx.target_id, /*tid=*/0xDEAD'BEEFull, 0),
      ldb::backend::Error);
}

TEST_CASE("frame.registers: out-of-range frame index throws backend::Error",
          "[backend][frame][values][error]") {
  auto fx = launched_at_entry();
  CHECK_THROWS_AS(
      fx.backend->list_registers(fx.target_id, fx.tid, /*frame=*/9999),
      ldb::backend::Error);
}
