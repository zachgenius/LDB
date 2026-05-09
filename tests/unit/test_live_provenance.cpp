// SPDX-License-Identifier: Apache-2.0
// Tests for the live-provenance snapshot model — slice 1b of v0.3.
//
// Audit doc: docs/04-determinism-audit.md §6, §7.
// Spec:      docs/POST-V0.1-PROGRESS.md "Audit-driven corrections folded
//            into slice 1b spec".
//
// Replaces the cores-only "live" sentinel with the real shape (slice
// 1c extends the original 4-component form with <bp_digest>):
//
//     live:<gen>:<reg_digest>:<layout_digest>:<bp_digest>
//
// Determinism contract for this slice:
//   * <gen>            → monotonic per-target counter; bumps on every
//                        observed stopped→running→stopped transition AND
//                        on attach (initial value 0).
//   * <reg_digest>     → SHA-256 of canonicalised all-thread GP register
//                        tuples. Cached per <gen>.
//   * <layout_digest>  → SHA-256 of canonicalised module layout tuples.
//                        Cached per <gen>.
//   * <bp_digest>      → SHA-256 of active SW-breakpoint addresses.
//                        Computed fresh per call (slice 1c).
//
// Cross-process equality is `(reg_digest, layout_digest, bp_digest)`
// only — `<gen>` is session-local and explicitly excluded from
// cross-daemon comparisons.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"

#include <memory>
#include <regex>
#include <string>

using ldb::backend::LaunchOptions;
using ldb::backend::LldbBackend;
using ldb::backend::ProcessState;
using ldb::backend::TargetId;

namespace {

constexpr const char* kSleeperPath = LDB_FIXTURE_SLEEPER_PATH;

}  // namespace

// --- Live snapshot shape -------------------------------------------------

TEST_CASE("snapshot_for_target: live snapshot has shape live:<gen>:<hex>:<hex>",
          "[backend][provenance][live]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kSleeperPath);
  REQUIRE(open.target_id != 0);

  LaunchOptions opts;
  opts.stop_at_entry = true;
  auto st = be->launch_process(open.target_id, opts);
  REQUIRE(st.state == ProcessState::kStopped);

  std::string snap = be->snapshot_for_target(open.target_id);

  // Shape (slice 1c): "live:" + decimal gen + ":" + 64 lower-hex +
  // ":" + 64 lower-hex + ":" + 64 lower-hex (bp_digest).
  static const std::regex kLiveRe(
      R"(^live:[0-9]+:[0-9a-f]{64}:[0-9a-f]{64}:[0-9a-f]{64}$)");
  CAPTURE(snap);
  CHECK(std::regex_match(snap, kLiveRe));

  be->kill_process(open.target_id);
  be->close_target(open.target_id);
}

TEST_CASE("snapshot_for_target: two consecutive calls on a stopped target are byte-identical",
          "[backend][provenance][live]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kSleeperPath);
  REQUIRE(open.target_id != 0);

  LaunchOptions opts;
  opts.stop_at_entry = true;
  REQUIRE(be->launch_process(open.target_id, opts).state ==
          ProcessState::kStopped);

  // Issue snapshot_for_target three times in a row with no resume in
  // between. <gen> is unchanged, the cached digests stay valid.
  std::string a = be->snapshot_for_target(open.target_id);
  std::string b = be->snapshot_for_target(open.target_id);
  std::string c = be->snapshot_for_target(open.target_id);
  CHECK(a == b);
  CHECK(b == c);

  be->kill_process(open.target_id);
  be->close_target(open.target_id);
}

TEST_CASE("snapshot_for_target: <gen> bumps after resume + stop",
          "[backend][provenance][live]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kSleeperPath);
  REQUIRE(open.target_id != 0);

  LaunchOptions opts;
  opts.stop_at_entry = true;
  REQUIRE(be->launch_process(open.target_id, opts).state ==
          ProcessState::kStopped);

  std::string before = be->snapshot_for_target(open.target_id);

  // step_thread requires the live thread id (kernel tid). Pull it from
  // the listing so the call resolves to a real thread.
  auto threads_pre = be->list_threads(open.target_id);
  REQUIRE(!threads_pre.empty());
  auto stepped = be->step_thread(open.target_id,
                                 threads_pre.front().tid,
                                 ldb::backend::StepKind::kInsn);
  // The step is a stopped→running→stopped cycle regardless of post-step
  // PC, so <gen> bumps. Digests may or may not differ — for sleeper
  // after a single step the registers definitely differ (PC moved), but
  // we don't assert on that. The gen guarantee is the structural
  // invariant.
  (void)stepped;

  std::string after = be->snapshot_for_target(open.target_id);
  CAPTURE(before);
  CAPTURE(after);
  CHECK(before != after);

  be->kill_process(open.target_id);
  be->close_target(open.target_id);
}

TEST_CASE("snapshot_for_target: read-only ops do NOT bump <gen>",
          "[backend][provenance][live]") {
  // Read-only ops MUST NOT bump <gen>. process.state, list_threads,
  // list_modules, list_regions, etc. all read state; none of them
  // resume the inferior, so <gen> stays the same.
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kSleeperPath);
  REQUIRE(open.target_id != 0);
  LaunchOptions opts;
  opts.stop_at_entry = true;
  REQUIRE(be->launch_process(open.target_id, opts).state ==
          ProcessState::kStopped);

  std::string a = be->snapshot_for_target(open.target_id);
  (void)be->get_process_state(open.target_id);
  (void)be->list_threads(open.target_id);
  (void)be->list_modules(open.target_id);
  (void)be->list_regions(open.target_id);
  std::string b = be->snapshot_for_target(open.target_id);
  CAPTURE(a);
  CAPTURE(b);
  CHECK(a == b);

  be->kill_process(open.target_id);
  be->close_target(open.target_id);
}

// --- Per-endpoint stable ordering checks --------------------------------
// These guard the audit's R4 recommendation: the explicit sorts in
// list_threads / list_regions / list_modules. LLDB's internal iteration
// order happens to match the sort key on this fixture today, but the
// audit warned this stability is by accident; the sort + these tests
// turn it into a contract.

TEST_CASE("thread.list: tid ordering is ascending and stable across calls",
          "[backend][ordering][live]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kSleeperPath);
  REQUIRE(open.target_id != 0);
  LaunchOptions opts;
  opts.stop_at_entry = true;
  REQUIRE(be->launch_process(open.target_id, opts).state ==
          ProcessState::kStopped);

  auto t1 = be->list_threads(open.target_id);
  auto t2 = be->list_threads(open.target_id);
  REQUIRE(t1.size() == t2.size());

  // Stable across calls (no resume between).
  for (std::size_t i = 0; i < t1.size(); ++i) {
    CAPTURE(i);
    CHECK(t1[i].tid == t2[i].tid);
  }
  // Ascending by tid.
  for (std::size_t i = 1; i < t1.size(); ++i) {
    CAPTURE(i);
    CHECK(t1[i - 1].tid <= t1[i].tid);
  }

  be->kill_process(open.target_id);
  be->close_target(open.target_id);
}

TEST_CASE("mem.regions: base ordering is ascending and stable across calls",
          "[backend][ordering][live]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kSleeperPath);
  REQUIRE(open.target_id != 0);
  LaunchOptions opts;
  opts.stop_at_entry = true;
  REQUIRE(be->launch_process(open.target_id, opts).state ==
          ProcessState::kStopped);

  auto r1 = be->list_regions(open.target_id);
  auto r2 = be->list_regions(open.target_id);
  REQUIRE(r1.size() == r2.size());
  for (std::size_t i = 0; i < r1.size(); ++i) {
    CAPTURE(i);
    CHECK(r1[i].base == r2[i].base);
    CHECK(r1[i].size == r2[i].size);
  }
  for (std::size_t i = 1; i < r1.size(); ++i) {
    CAPTURE(i);
    CHECK(r1[i - 1].base <= r1[i].base);
  }

  be->kill_process(open.target_id);
  be->close_target(open.target_id);
}

TEST_CASE("module.list: path ordering is ascending and stable across calls",
          "[backend][ordering][live]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kSleeperPath);
  REQUIRE(open.target_id != 0);
  LaunchOptions opts;
  opts.stop_at_entry = true;
  REQUIRE(be->launch_process(open.target_id, opts).state ==
          ProcessState::kStopped);

  auto m1 = be->list_modules(open.target_id);
  auto m2 = be->list_modules(open.target_id);
  REQUIRE(m1.size() == m2.size());
  for (std::size_t i = 0; i < m1.size(); ++i) {
    CAPTURE(i);
    CHECK(m1[i].path == m2[i].path);
  }
  for (std::size_t i = 1; i < m1.size(); ++i) {
    CAPTURE(i);
    CAPTURE(m1[i - 1].path);
    CAPTURE(m1[i].path);
    CHECK(m1[i - 1].path <= m1[i].path);
  }

  be->kill_process(open.target_id);
  be->close_target(open.target_id);
}
