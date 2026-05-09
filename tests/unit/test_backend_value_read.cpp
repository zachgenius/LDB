// SPDX-License-Identifier: Apache-2.0
// Tests for DebuggerBackend::read_value_path (value.read).
//
// `path` is a dotted/bracketed expression evaluated relative to a frame:
//   "g_origin"            — root identifier
//   "g_origin.x"          — struct field
//   "g_arr[2]"            — array element
//   "g_login_template.magic"
//
// Path resolution failures (no member, malformed token, unknown root)
// return a result with ok=false + a non-empty error message — they are
// *data*, not exceptions. Bad target/tid/frame_index DO throw.
//
// Tests use the structs fixture launched stop-at-entry; we deliberately
// avoid asserting on the *bytes* of the resolved value because at
// `_dyld_start` the __DATA region of a PIE binary on macOS arm64 is
// not yet relocated. The structural walk (name, type, address shape)
// works regardless.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"

#include <memory>
#include <string>

using ldb::backend::LaunchOptions;
using ldb::backend::LldbBackend;
using ldb::backend::ProcessState;
using ldb::backend::ReadResult;
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

TEST_CASE("value.read: top-level identifier resolves a global",
          "[backend][value][read][live]") {
  LaunchedFixture fx;
  launched_at_entry(fx);

  auto r = fx.backend->read_value_path(fx.target_id, fx.tid, 0, "g_origin");
  REQUIRE(r.ok);
  CHECK(r.error.empty());
  CHECK(r.value.name == "g_origin");
  // Type ought to mention point2 — exact form is "point2" or "struct point2".
  CHECK(r.value.type.find("point2") != std::string::npos);
}

TEST_CASE("value.read: dotted-path traversal into a struct field",
          "[backend][value][read][live]") {
  LaunchedFixture fx;
  launched_at_entry(fx);

  auto r = fx.backend->read_value_path(fx.target_id, fx.tid, 0,
                                       "g_origin.x");
  REQUIRE(r.ok);
  // The resolved leaf's name should be the field name, and its type
  // should be int (or a typedef thereof).
  CHECK(r.value.name == "x");
  CHECK(r.value.type.find("int") != std::string::npos);
}

TEST_CASE("value.read: nested dotted path",
          "[backend][value][read][live]") {
  LaunchedFixture fx;
  launched_at_entry(fx);

  auto r = fx.backend->read_value_path(fx.target_id, fx.tid, 0,
                                       "g_login_template.magic");
  REQUIRE(r.ok);
  CHECK(r.value.name == "magic");
  // uint32_t — the type string is platform-dependent ("uint32_t",
  // "unsigned int", "__uint32_t"), but always contains "int".
  CHECK(r.value.type.find("int") != std::string::npos);
}

TEST_CASE("value.read: indexed traversal into an array",
          "[backend][value][read][live]") {
  LaunchedFixture fx;
  launched_at_entry(fx);

  auto r = fx.backend->read_value_path(fx.target_id, fx.tid, 0, "g_arr[2]");
  REQUIRE(r.ok);
  // The element's name is implementation-defined; LLDB renders it as
  // "[2]" for array children. We just want the structural walk to
  // have succeeded and the type to match.
  CHECK(r.value.type.find("int") != std::string::npos);
}

TEST_CASE("value.read: unknown root returns ok=false (data)",
          "[backend][value][read][live]") {
  LaunchedFixture fx;
  launched_at_entry(fx);

  ReadResult r;
  CHECK_NOTHROW(r = fx.backend->read_value_path(
      fx.target_id, fx.tid, 0, "totally_made_up_symbol_name_xyz"));
  CHECK_FALSE(r.ok);
  CHECK_FALSE(r.error.empty());
}

TEST_CASE("value.read: no-such-member returns ok=false (data)",
          "[backend][value][read][live]") {
  LaunchedFixture fx;
  launched_at_entry(fx);

  ReadResult r;
  CHECK_NOTHROW(r = fx.backend->read_value_path(
      fx.target_id, fx.tid, 0, "g_origin.no_such_field"));
  CHECK_FALSE(r.ok);
  CHECK(r.error.find("no_such_field") != std::string::npos);
}

TEST_CASE("value.read: malformed path returns ok=false (data)",
          "[backend][value][read][live]") {
  LaunchedFixture fx;
  launched_at_entry(fx);

  // Trailing dot is malformed; a parser error must surface as data,
  // not a thrown exception, so the agent can branch on it.
  ReadResult r;
  CHECK_NOTHROW(r = fx.backend->read_value_path(
      fx.target_id, fx.tid, 0, "g_origin."));
  CHECK_FALSE(r.ok);
  CHECK_FALSE(r.error.empty());
}

TEST_CASE("value.read: empty path returns ok=false (data)",
          "[backend][value][read][live]") {
  LaunchedFixture fx;
  launched_at_entry(fx);

  ReadResult r;
  CHECK_NOTHROW(r = fx.backend->read_value_path(
      fx.target_id, fx.tid, 0, ""));
  CHECK_FALSE(r.ok);
  CHECK_FALSE(r.error.empty());
}

TEST_CASE("value.read: unbalanced bracket returns ok=false (data)",
          "[backend][value][read][live]") {
  LaunchedFixture fx;
  launched_at_entry(fx);

  ReadResult r;
  CHECK_NOTHROW(r = fx.backend->read_value_path(
      fx.target_id, fx.tid, 0, "g_arr[2"));
  CHECK_FALSE(r.ok);
  CHECK_FALSE(r.error.empty());
}

TEST_CASE("value.read: invalid target_id throws backend::Error",
          "[backend][value][read][error]") {
  LaunchedFixture fx;
  launched_at_entry(fx);
  CHECK_THROWS_AS(
      fx.backend->read_value_path(/*tid=*/9999, fx.tid, 0, "g_origin"),
      ldb::backend::Error);
}

TEST_CASE("value.read: bogus thread id throws backend::Error",
          "[backend][value][read][error]") {
  LaunchedFixture fx;
  launched_at_entry(fx);
  CHECK_THROWS_AS(
      fx.backend->read_value_path(
          fx.target_id, /*tid=*/0xDEAD'BEEFull, 0, "g_origin"),
      ldb::backend::Error);
}

TEST_CASE("value.read: out-of-range frame_index throws backend::Error",
          "[backend][value][read][error]") {
  LaunchedFixture fx;
  launched_at_entry(fx);
  CHECK_THROWS_AS(
      fx.backend->read_value_path(fx.target_id, fx.tid,
                                  /*frame_index=*/9999, "g_origin"),
      ldb::backend::Error);
}

TEST_CASE("value.read: struct value exposes children for direct sub-field reads",
          "[backend][value][read][live]") {
  LaunchedFixture fx;
  launched_at_entry(fx);

  auto r = fx.backend->read_value_path(fx.target_id, fx.tid, 0,
                                       "g_login_template");
  REQUIRE(r.ok);
  // A struct has children — children carry name+type metadata, which
  // is what an agent uses to plan follow-up reads in one round-trip.
  CHECK_FALSE(r.children.empty());
  // The two declared fields of dxp_login_frame are magic + sid.
  bool saw_magic = false, saw_sid = false;
  for (const auto& c : r.children) {
    if (c.name == "magic") saw_magic = true;
    if (c.name == "sid")   saw_sid = true;
  }
  CHECK(saw_magic);
  CHECK(saw_sid);
}
