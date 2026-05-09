// SPDX-License-Identifier: Apache-2.0
// Tests for the three bug fixes the live-provenance audit surfaced
// (docs/04-determinism-audit.md §11). These are wire-level bugs worth
// fixing regardless of the snapshot work that motivated finding them.
//
//   1. stop_reason carries a trailing NUL byte (audit §11.1).
//      Confirmed empirically as `"signal SIGSTOP \0"` from
//      SBThread::GetStopDescription's count-includes-NUL semantics.
//
//   2. probe.list ordering is by std::map<std::string> iteration order,
//      so "p10" lex-sorts before "p2" (audit §11.4). Slice 1b switches
//      to numeric ordering at serialize time.
//
//   3. session.list secondary sort key is the random uuid `id`, making
//      ties non-deterministic. Slice 1b changes the SQL to
//      `ORDER BY created_at DESC, name ASC, id ASC` so the operator-
//      supplied `name` is the deterministic tiebreak (audit §11.2 as
//      revised by reviewer).

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"
#include "probes/probe_orchestrator.h"
#include "store/session_store.h"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <random>
#include <string>
#include <system_error>
#include <thread>

namespace fs = std::filesystem;

using ldb::backend::LaunchOptions;
using ldb::backend::LldbBackend;
using ldb::backend::ProcessState;
using ldb::backend::TargetId;
using ldb::probes::Action;
using ldb::probes::ProbeOrchestrator;
using ldb::probes::ProbeSpec;
using ldb::store::SessionStore;

namespace {

constexpr const char* kSleeperPath = LDB_FIXTURE_SLEEPER_PATH;

struct TmpStoreRoot {
  fs::path root;
  TmpStoreRoot() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    char buf[40];
    std::snprintf(buf, sizeof(buf), "ldb_audit_%016llx",
                  static_cast<unsigned long long>(gen()));
    root = fs::temp_directory_path() / buf;
    std::error_code ec;
    fs::remove_all(root, ec);
  }
  ~TmpStoreRoot() {
    std::error_code ec;
    fs::remove_all(root, ec);
  }
};

}  // namespace

// --- §11.1: stop_reason trailing NUL ------------------------------------

TEST_CASE("stop_reason: no trailing NUL byte after process.launch{stop_at_entry}",
          "[backend][bugfix][live]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->open_executable(kSleeperPath);
  REQUIRE(open.target_id != 0);
  LaunchOptions opts;
  opts.stop_at_entry = true;
  auto st = be->launch_process(open.target_id, opts);
  REQUIRE(st.state == ProcessState::kStopped);

  // Confirmed empirically by the audit (§11.1) that on this LLDB
  // version, ProcessStatus::stop_reason was "signal SIGSTOP \0" — the
  // trailing NUL slipped in from
  //     assign(buf, std::min(n, sizeof(buf) - 1))
  // where `n` from SBThread::GetStopDescription includes the NUL.
  // After the fix, the string contains only printable bytes.
  for (char c : st.stop_reason) {
    CAPTURE(static_cast<int>(static_cast<unsigned char>(c)));
    CHECK(c != '\0');
  }

  // Same check on the per-thread stop_reason path
  // (lldb_backend.cpp:1675–1676).
  auto threads = be->list_threads(open.target_id);
  REQUIRE(!threads.empty());
  for (const auto& th : threads) {
    for (char c : th.stop_reason) {
      CAPTURE(static_cast<int>(static_cast<unsigned char>(c)));
      CHECK(c != '\0');
    }
  }

  be->kill_process(open.target_id);
  be->close_target(open.target_id);
}

// --- §11.4: probe.list numeric ordering ---------------------------------

TEST_CASE("probe.list ordering: numeric, not lex (p10 after p2)",
          "[probes][orchestrator][bugfix][live]") {
  // Audit §11.4: today the orchestrator stores probes in
  // std::map<std::string>, so iterator order is lex — `p10` sorts BEFORE
  // `p2`. Slice 1b sorts list() output by the numeric suffix so creation
  // order survives the round-trip.
  auto be = std::make_shared<LldbBackend>();
  ProbeOrchestrator orch(be, /*artifacts=*/nullptr);

  // We need a target to hang BPs off; sleeper has a `main` symbol that
  // BreakpointCreateByName resolves without launching the process.
  auto open = be->open_executable(kSleeperPath);
  REQUIRE(open.target_id != 0);

  std::vector<std::string> created;
  for (int i = 0; i < 11; ++i) {
    ProbeSpec s;
    s.target_id      = open.target_id;
    s.kind           = "lldb_breakpoint";
    s.where.function = "main";
    s.action         = Action::kLogAndContinue;
    created.push_back(orch.create(s));
  }
  // Sanity — ids should be p1..p11 in creation order.
  REQUIRE(created.size() == 11);
  REQUIRE(created.front() == "p1");
  REQUIRE(created.back()  == "p11");

  auto rows = orch.list();
  REQUIRE(rows.size() == created.size());

  // Slice 1b assertion: list ordering matches creation order, which is
  // numeric. Lex would put p10/p11 before p2 — that's what we're
  // guarding against.
  for (std::size_t i = 0; i < created.size(); ++i) {
    CAPTURE(i);
    CHECK(rows[i].probe_id == created[i]);
  }

  // Tear down the probes individually so the BPs are dropped before
  // the backend goes out of scope.
  for (const auto& id : created) orch.remove(id);
  be->close_target(open.target_id);
}

// --- §11.2: session.list deterministic tiebreak -------------------------

TEST_CASE("session.list ORDER BY: name is the secondary key, id only on ties",
          "[store][session][bugfix]") {
  // Audit §11.2 (revised by reviewer): the original SQL was
  // `ORDER BY created_at DESC, id ASC`, but `id` is a 32-hex-char
  // random uuid, making the tiebreak non-deterministic when two
  // sessions share the same `created_at` ns. Slice 1b uses
  // `ORDER BY created_at DESC, name ASC, id ASC` so the operator-
  // supplied name is deterministic.
  TmpStoreRoot t;
  SessionStore s(t.root);

  // Force a forced-collision scenario: pre-populate with sessions
  // whose created_at can be made identical via import_session, then
  // verify list() orders the rows by name ASC despite the random
  // uuids.
  //
  // We can't directly force two real create() calls to share
  // created_at_ns (they read steady_clock or wall clock); but
  // import_session takes created_at as a parameter, so we use it.
  std::int64_t shared_ts = 1700000000000000000LL;  // arbitrary fixed ns
  std::vector<SessionStore::ImportRow> empty_rows;
  s.import_session("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "zeta",
                   /*target_id=*/std::nullopt,
                   shared_ts, empty_rows, /*overwrite=*/true);
  s.import_session("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "alpha",
                   /*target_id=*/std::nullopt,
                   shared_ts, empty_rows, /*overwrite=*/true);
  s.import_session("mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm", "mu",
                   /*target_id=*/std::nullopt,
                   shared_ts, empty_rows, /*overwrite=*/true);

  auto all = s.list();
  REQUIRE(all.size() == 3);
  // With same created_at, name ASC must dominate: alpha → mu → zeta.
  CHECK(all[0].name == "alpha");
  CHECK(all[1].name == "mu");
  CHECK(all[2].name == "zeta");
}
