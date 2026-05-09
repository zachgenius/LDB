// SPDX-License-Identifier: Apache-2.0
// Tests for the multi-binary inventory surface (Tier 3 §9):
//   • DebuggerBackend::list_targets — enumerate every open target's
//     id, triple, executable path, optional label, and live-process bit.
//   • DebuggerBackend::label_target — store a stable per-target label
//     scoped to the daemon process; uniqueness enforced.
//   • DebuggerBackend::get_target_label — lookup helper.
//
// These exercise the LldbBackend implementation against real fixture
// binaries. label_target's contract is interface-level (it's on
// DebuggerBackend), but the conflict + close_target-drops-label
// behaviour lives in LldbBackend; we pin them here so a future GDB
// backend can see the contract.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"

#include <algorithm>
#include <memory>
#include <string>

using ldb::backend::LldbBackend;
using ldb::backend::TargetId;

namespace {

constexpr const char* kStructsPath = LDB_FIXTURE_STRUCTS_PATH;
constexpr const char* kSleeperPath = LDB_FIXTURE_SLEEPER_PATH;

}  // namespace

TEST_CASE("list_targets: empty when no targets open",
          "[backend][targets]") {
  auto be = std::make_unique<LldbBackend>();
  auto out = be->list_targets();
  CHECK(out.empty());
}

TEST_CASE("list_targets: enumerates two open executables",
          "[backend][targets]") {
  auto be = std::make_unique<LldbBackend>();
  auto a = be->open_executable(kStructsPath);
  auto b = be->open_executable(kSleeperPath);
  REQUIRE(a.target_id != 0);
  REQUIRE(b.target_id != 0);
  REQUIRE(a.target_id != b.target_id);

  auto out = be->list_targets();
  REQUIRE(out.size() == 2);

  // Find each by target_id; ordering not pinned by contract.
  auto find = [&](TargetId tid) {
    return std::find_if(out.begin(), out.end(),
        [tid](const ldb::backend::TargetInfo& t) {
          return t.target_id == tid;
        });
  };
  auto ia = find(a.target_id);
  auto ib = find(b.target_id);
  REQUIRE(ia != out.end());
  REQUIRE(ib != out.end());

  // Triple should match the OpenResult triple (best-effort string equality;
  // both come from the same SBTarget::GetTriple()).
  CHECK(ia->triple == a.triple);
  CHECK(ib->triple == b.triple);

  // Path is the executable on disk for these (open_executable both).
  CHECK(ia->path == kStructsPath);
  CHECK(ib->path == kSleeperPath);

  // No labels assigned yet.
  CHECK_FALSE(ia->label.has_value());
  CHECK_FALSE(ib->label.has_value());

  // No live process — neither was launched/attached.
  CHECK_FALSE(ia->has_process);
  CHECK_FALSE(ib->has_process);
}

TEST_CASE("label_target: round-trip via list_targets and get_target_label",
          "[backend][targets][label]") {
  auto be = std::make_unique<LldbBackend>();
  auto a = be->open_executable(kStructsPath);
  REQUIRE(a.target_id != 0);

  CHECK_FALSE(be->get_target_label(a.target_id).has_value());
  be->label_target(a.target_id, "structs_bin");
  auto got = be->get_target_label(a.target_id);
  REQUIRE(got.has_value());
  CHECK(*got == "structs_bin");

  auto out = be->list_targets();
  REQUIRE(out.size() == 1);
  REQUIRE(out[0].label.has_value());
  CHECK(*out[0].label == "structs_bin");
}

TEST_CASE("label_target: re-labeling the same target replaces the label",
          "[backend][targets][label]") {
  // Decision: a second label_target() on an existing target replaces
  // the prior label. The old label string is freed and becomes
  // available for reuse on another target.
  auto be = std::make_unique<LldbBackend>();
  auto a = be->open_executable(kStructsPath);
  REQUIRE(a.target_id != 0);

  be->label_target(a.target_id, "first");
  be->label_target(a.target_id, "second");
  auto got = be->get_target_label(a.target_id);
  REQUIRE(got.has_value());
  CHECK(*got == "second");

  // The string "first" is now free — another target can claim it.
  auto b = be->open_executable(kSleeperPath);
  REQUIRE_NOTHROW(be->label_target(b.target_id, "first"));
  auto got_b = be->get_target_label(b.target_id);
  REQUIRE(got_b.has_value());
  CHECK(*got_b == "first");
}

TEST_CASE("label_target: same-target same-label is a no-op",
          "[backend][targets][label]") {
  auto be = std::make_unique<LldbBackend>();
  auto a = be->open_executable(kStructsPath);
  REQUIRE(a.target_id != 0);

  be->label_target(a.target_id, "alpha");
  // Self-relabel with the same string must NOT throw "label already taken".
  REQUIRE_NOTHROW(be->label_target(a.target_id, "alpha"));
  auto got = be->get_target_label(a.target_id);
  REQUIRE(got.has_value());
  CHECK(*got == "alpha");
}

TEST_CASE("label_target: conflict on a different target throws",
          "[backend][targets][label][error]") {
  auto be = std::make_unique<LldbBackend>();
  auto a = be->open_executable(kStructsPath);
  auto b = be->open_executable(kSleeperPath);
  REQUIRE(a.target_id != b.target_id);

  be->label_target(a.target_id, "shared");
  // b cannot take a label already owned by a.
  CHECK_THROWS_AS(be->label_target(b.target_id, "shared"),
                  ldb::backend::Error);
  // a still owns it.
  auto got = be->get_target_label(a.target_id);
  REQUIRE(got.has_value());
  CHECK(*got == "shared");
}

TEST_CASE("label_target: rejects unknown target_id",
          "[backend][targets][label][error]") {
  auto be = std::make_unique<LldbBackend>();
  CHECK_THROWS_AS(be->label_target(/*tid=*/9999, "x"),
                  ldb::backend::Error);
}

TEST_CASE("label_target: empty label is rejected",
          "[backend][targets][label][error]") {
  auto be = std::make_unique<LldbBackend>();
  auto a = be->open_executable(kStructsPath);
  CHECK_THROWS_AS(be->label_target(a.target_id, ""),
                  ldb::backend::Error);
}

TEST_CASE("close_target: drops the label and frees the string",
          "[backend][targets][label]") {
  auto be = std::make_unique<LldbBackend>();
  auto a = be->open_executable(kStructsPath);
  be->label_target(a.target_id, "structs_bin");

  be->close_target(a.target_id);
  // After close, the label is gone and another target can take the name.
  auto b = be->open_executable(kSleeperPath);
  REQUIRE_NOTHROW(be->label_target(b.target_id, "structs_bin"));
  auto got = be->get_target_label(b.target_id);
  REQUIRE(got.has_value());
  CHECK(*got == "structs_bin");

  // get_target_label on a closed target returns nullopt rather than throwing —
  // close + lookup is a benign race window for the dispatcher.
  CHECK_FALSE(be->get_target_label(a.target_id).has_value());
}

TEST_CASE("list_targets: omits closed targets",
          "[backend][targets]") {
  auto be = std::make_unique<LldbBackend>();
  auto a = be->open_executable(kStructsPath);
  auto b = be->open_executable(kSleeperPath);
  REQUIRE(be->list_targets().size() == 2);

  be->close_target(a.target_id);
  auto out = be->list_targets();
  REQUIRE(out.size() == 1);
  CHECK(out[0].target_id == b.target_id);
}
