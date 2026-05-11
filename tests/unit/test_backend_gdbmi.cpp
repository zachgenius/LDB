// SPDX-License-Identifier: Apache-2.0
// Integration tests for GdbMiBackend against a live `gdb` subprocess.
//
// All cases gated on `[gdbmi][live][requires_gdb]` — SKIP cleanly
// when `gdb` is not on PATH (CI legs without gdb installed, dev
// boxes that haven't apt-installed it, etc.). Coverage grows
// incrementally per the v1.4 #8 task batches; this commit covers
// the lifecycle subset (open/close, create_empty, load_core stub,
// list_targets, label_target, kill_process on no-process).

#include <catch_amalgamated.hpp>

#include "backend/gdbmi/backend.h"

#include <cstdlib>
#include <filesystem>
#include <memory>

using ldb::backend::gdbmi::GdbMiBackend;
using ldb::backend::ProcessState;

namespace {

constexpr const char* kFixturePath = LDB_FIXTURE_STRUCTS_PATH;

bool gdb_available() {
  return std::system("which gdb >/dev/null 2>&1") == 0;
}

}  // namespace

TEST_CASE("GdbMiBackend: open_executable + close round-trip",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->open_executable(kFixturePath);
  REQUIRE(open.target_id != 0);

  // No live process yet — state should be kNone.
  auto st = be->get_process_state(open.target_id);
  CHECK(st.state == ProcessState::kNone);

  // The target is listed.
  auto targets = be->list_targets();
  REQUIRE(targets.size() == 1);
  CHECK(targets[0].target_id == open.target_id);
  CHECK(targets[0].path == kFixturePath);

  // snapshot_for_target produces a stable hex token.
  auto snap = be->snapshot_for_target(open.target_id);
  CHECK(snap.rfind("gdb:", 0) == 0);
  CHECK(snap.size() > 32);

  be->close_target(open.target_id);
  CHECK(be->list_targets().empty());
}

TEST_CASE("GdbMiBackend: open_executable on missing path throws",
          "[gdbmi][live][requires_gdb][error]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  CHECK_THROWS_AS(be->open_executable("/nonexistent/path/to/binary"),
                  ldb::backend::Error);
}

TEST_CASE("GdbMiBackend: create_empty_target + label",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->create_empty_target();
  REQUIRE(open.target_id != 0);

  // No exe set yet; label_target should still work since it's
  // pure daemon-side state.
  be->label_target(open.target_id, "scratch");
  auto label = be->get_target_label(open.target_id);
  REQUIRE(label.has_value());
  CHECK(*label == "scratch");

  be->close_target(open.target_id);
}

TEST_CASE("GdbMiBackend: kill_process is a no-op when no process",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->open_executable(kFixturePath);
  // No -exec-run yet — state is kNone. kill_process must NOT throw.
  auto st = be->kill_process(open.target_id);
  CHECK(st.state == ProcessState::kNone);
  be->close_target(open.target_id);
}

TEST_CASE("GdbMiBackend: snapshot differs across targets",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto a = be->open_executable(kFixturePath);
  auto b = be->create_empty_target();
  CHECK(be->snapshot_for_target(a.target_id)
        != be->snapshot_for_target(b.target_id));
  be->close_target(a.target_id);
  be->close_target(b.target_id);
}
