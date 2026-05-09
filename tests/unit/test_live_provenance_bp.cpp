// SPDX-License-Identifier: Apache-2.0
// Tests for the bp_digest component of the live snapshot model —
// slice 1c of v0.3.
//
// Audit doc: docs/04-determinism-audit.md §6 (proposed).
// Spec:      docs/POST-V0.1-PROGRESS.md "1b reviewer findings folded into
//            slice 1c spec" item #1 (SW-bp memory-patch invisibility).
//
// Slice 1c extends the live snapshot from
//
//     live:<gen>:<reg_digest>:<layout_digest>
//
// to
//
//     live:<gen>:<reg_digest>:<layout_digest>:<bp_digest>
//
// where <bp_digest> is SHA-256 over the canonicalised set of active
// `lldb_breakpoint`-engine breakpoints (sorted by address). This closes
// the determinism gap where a probe.create installs a 0xCC patch in
// .text but two snapshots straddling it carry identical strings.
//
// Cross-process equality remains `(reg_digest, layout_digest, bp_digest)`
// only — `<gen>` is session-local.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"

#include <memory>
#include <regex>
#include <string>
#include <vector>

using ldb::backend::BreakpointSpec;
using ldb::backend::LaunchOptions;
using ldb::backend::LldbBackend;
using ldb::backend::ProcessState;
using ldb::backend::TargetId;

namespace {

constexpr const char* kSleeperPath  = LDB_FIXTURE_SLEEPER_PATH;
constexpr const char* kStructsPath  = LDB_FIXTURE_STRUCTS_PATH;

// Pull the bp_digest (last colon-segment) from a live snapshot string.
// Returns empty if the string isn't shaped right.
std::string bp_digest_of(const std::string& snap) {
  // shape: live:<gen>:<reg>:<layout>:<bp>
  auto last = snap.rfind(':');
  if (last == std::string::npos) return "";
  // require 4 colons total
  std::size_t n_colons = 0;
  for (char c : snap) if (c == ':') ++n_colons;
  if (n_colons < 4) return "";
  return snap.substr(last + 1);
}

}  // namespace

// --- Snapshot shape includes <bp_digest> ---------------------------------

TEST_CASE("snapshot_for_target: live snapshot shape has 5 components: live:<gen>:<reg>:<layout>:<bp>",
          "[backend][provenance][live][bp]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kSleeperPath);
  REQUIRE(open.target_id != 0);
  LaunchOptions opts;
  opts.stop_at_entry = true;
  REQUIRE(be->launch_process(open.target_id, opts).state ==
          ProcessState::kStopped);

  std::string snap = be->snapshot_for_target(open.target_id);
  static const std::regex kRe(
      R"(^live:[0-9]+:[0-9a-f]{64}:[0-9a-f]{64}:[0-9a-f]{64}$)");
  CAPTURE(snap);
  CHECK(std::regex_match(snap, kRe));

  be->kill_process(open.target_id);
  be->close_target(open.target_id);
}

// --- bp_digest with no probes is the well-defined empty-set sentinel ----

TEST_CASE("snapshot_for_target: empty-bp-set bp_digest is SHA-256 of canonical-empty input",
          "[backend][provenance][live][bp]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kSleeperPath);
  REQUIRE(open.target_id != 0);
  LaunchOptions opts;
  opts.stop_at_entry = true;
  REQUIRE(be->launch_process(open.target_id, opts).state ==
          ProcessState::kStopped);

  std::string snap = be->snapshot_for_target(open.target_id);
  std::string bp = bp_digest_of(snap);
  CAPTURE(snap);
  REQUIRE(bp.size() == 64);
  // The empty-bp set canonicalises to a u64 LE 0 (count=0). SHA-256 of
  // 8 zero bytes is a fixed, well-known value — pin it so a refactor
  // can't silently change the canonical form.
  CHECK(bp == "af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc");

  be->kill_process(open.target_id);
  be->close_target(open.target_id);
}

// --- probe.create changes the bp_digest -----------------------------------

TEST_CASE("snapshot_for_target: bp_digest changes after a breakpoint is installed",
          "[backend][provenance][live][bp]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kStructsPath);
  REQUIRE(open.target_id != 0);
  LaunchOptions opts;
  opts.stop_at_entry = true;
  REQUIRE(be->launch_process(open.target_id, opts).state ==
          ProcessState::kStopped);

  std::string snap_pre = be->snapshot_for_target(open.target_id);
  std::string bp_pre   = bp_digest_of(snap_pre);
  CAPTURE(snap_pre);
  REQUIRE(bp_pre.size() == 64);

  BreakpointSpec spec;
  spec.function = "point2_distance_sq";
  auto handle = be->create_breakpoint(open.target_id, spec);
  REQUIRE(handle.bp_id != 0);

  std::string snap_post = be->snapshot_for_target(open.target_id);
  std::string bp_post   = bp_digest_of(snap_post);
  CAPTURE(snap_post);
  CHECK(bp_post != bp_pre);

  // Removing the breakpoint restores the empty-set digest. Note <gen>
  // does NOT bump on bp create/delete (no resume happened) — so
  // (reg_digest, layout_digest) stay the same and only bp_digest
  // changes.
  be->delete_breakpoint(open.target_id, handle.bp_id);
  std::string snap_after_delete = be->snapshot_for_target(open.target_id);
  std::string bp_after_delete   = bp_digest_of(snap_after_delete);
  CAPTURE(snap_after_delete);
  CHECK(bp_after_delete == bp_pre);
  // And the entire snapshot string returns to its pre-create form.
  CHECK(snap_after_delete == snap_pre);

  be->kill_process(open.target_id);
  be->close_target(open.target_id);
}

// --- Two probes at different addresses → different bp_digest -------------

TEST_CASE("snapshot_for_target: two probes at different addresses produce different bp_digests",
          "[backend][provenance][live][bp]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kStructsPath);
  REQUIRE(open.target_id != 0);
  LaunchOptions opts;
  opts.stop_at_entry = true;
  REQUIRE(be->launch_process(open.target_id, opts).state ==
          ProcessState::kStopped);

  BreakpointSpec spec_a;
  spec_a.function = "point2_distance_sq";
  auto h_a = be->create_breakpoint(open.target_id, spec_a);
  REQUIRE(h_a.bp_id != 0);
  std::string snap_a = be->snapshot_for_target(open.target_id);
  std::string bp_a   = bp_digest_of(snap_a);
  REQUIRE(bp_a.size() == 64);

  // Add a SECOND breakpoint at a different function. Now the bp set
  // has two entries — its digest must differ from the single-probe
  // case.
  BreakpointSpec spec_b;
  spec_b.function = "main";
  auto h_b = be->create_breakpoint(open.target_id, spec_b);
  REQUIRE(h_b.bp_id != 0);
  std::string snap_b = be->snapshot_for_target(open.target_id);
  std::string bp_b   = bp_digest_of(snap_b);
  REQUIRE(bp_b.size() == 64);
  CAPTURE(snap_a);
  CAPTURE(snap_b);
  CHECK(bp_b != bp_a);

  be->delete_breakpoint(open.target_id, h_a.bp_id);
  be->delete_breakpoint(open.target_id, h_b.bp_id);
  be->kill_process(open.target_id);
  be->close_target(open.target_id);
}

// --- Disabled breakpoints do not contribute to bp_digest -----------------
//
// A disabled breakpoint is not patching memory (LLDB removes the 0xCC
// patch when the bp is disabled). Therefore it should NOT contribute to
// the SW-bp digest, otherwise the cross-snapshot determinism still
// breaks: the inferior's .text bytes would match the empty-bp case but
// the snapshot string would not.

TEST_CASE("snapshot_for_target: disabled breakpoint does not change bp_digest",
          "[backend][provenance][live][bp]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kStructsPath);
  REQUIRE(open.target_id != 0);
  LaunchOptions opts;
  opts.stop_at_entry = true;
  REQUIRE(be->launch_process(open.target_id, opts).state ==
          ProcessState::kStopped);

  std::string snap_pre = be->snapshot_for_target(open.target_id);
  std::string bp_pre   = bp_digest_of(snap_pre);

  BreakpointSpec spec;
  spec.function = "point2_distance_sq";
  auto handle = be->create_breakpoint(open.target_id, spec);
  be->disable_breakpoint(open.target_id, handle.bp_id);

  // After disable, the .text patch is gone; the bp_digest should
  // reflect the empty set again.
  std::string snap_disabled = be->snapshot_for_target(open.target_id);
  std::string bp_disabled   = bp_digest_of(snap_disabled);
  CAPTURE(snap_disabled);
  CHECK(bp_disabled == bp_pre);

  be->delete_breakpoint(open.target_id, handle.bp_id);
  be->kill_process(open.target_id);
  be->close_target(open.target_id);
}
