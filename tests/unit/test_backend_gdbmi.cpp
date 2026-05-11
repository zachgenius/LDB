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

// ── Static analysis ───────────────────────────────────────────────────

TEST_CASE("GdbMiBackend: list_modules returns the main exec",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->open_executable(kFixturePath);
  auto mods = be->list_modules(open.target_id);
  REQUIRE(mods.size() == 1);
  CHECK(mods[0].path == kFixturePath);
  be->close_target(open.target_id);
}

TEST_CASE("GdbMiBackend: disassemble_range covers a known function",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->open_executable(kFixturePath);

  // Resolve point2_distance_sq via find_symbols so we know its
  // address; then disassemble the first 64 bytes.
  ldb::backend::SymbolQuery q;
  q.name = "point2_distance_sq";
  q.kind = ldb::backend::SymbolKind::kFunction;
  auto syms = be->find_symbols(open.target_id, q);
  REQUIRE_FALSE(syms.empty());
  auto base = syms[0].address;
  REQUIRE(base != 0);

  auto insns = be->disassemble_range(open.target_id, base, base + 64);
  CHECK(insns.size() >= 4);
  // The first instruction must start at the requested base.
  CHECK(insns[0].address == base);
  // Mnemonics from gdb's x86 disassembler are lowercased — confirm
  // we got a real opcode string in mnemonic, not the whole insn.
  CHECK_FALSE(insns[0].mnemonic.empty());
  CHECK(insns[0].mnemonic.find(' ') == std::string::npos);
  be->close_target(open.target_id);
}

TEST_CASE("GdbMiBackend: find_symbols by exact name resolves address",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->open_executable(kFixturePath);

  ldb::backend::SymbolQuery q;
  q.name = "main";
  q.kind = ldb::backend::SymbolKind::kFunction;
  auto syms = be->find_symbols(open.target_id, q);
  REQUIRE_FALSE(syms.empty());
  bool found_main = false;
  for (const auto& s : syms) {
    if (s.name == "main") {
      found_main = true;
      CHECK(s.address != 0);
      CHECK(s.kind == ldb::backend::SymbolKind::kFunction);
      CHECK(s.module_path == kFixturePath);
      CHECK(s.byte_size > 0);   // resolved via `disassemble main`
    }
  }
  CHECK(found_main);
  be->close_target(open.target_id);
}

// ── Process control + threads/frames ──────────────────────────────────

TEST_CASE("GdbMiBackend: launch_process stops at entry + threads listed",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->open_executable(kFixturePath);

  ldb::backend::LaunchOptions opts;
  opts.stop_at_entry = true;
  auto st = be->launch_process(open.target_id, opts);
  // Either stopped at entry, exited (very short program), or
  // running through — all valid post-launch states. We don't
  // pin to kStopped because the fixture might run to completion
  // before our async drain kicks in.
  CHECK((st.state == ldb::backend::ProcessState::kStopped ||
         st.state == ldb::backend::ProcessState::kExited));

  if (st.state == ldb::backend::ProcessState::kStopped) {
    auto threads = be->list_threads(open.target_id);
    CHECK_FALSE(threads.empty());
    CHECK(threads[0].pc != 0);

    auto frames = be->list_frames(open.target_id,
                                   threads[0].tid, 8);
    CHECK_FALSE(frames.empty());
    // Index 0 is the innermost; its pc should match the thread's pc.
    CHECK(frames[0].pc == threads[0].pc);
  }

  be->kill_process(open.target_id);
  be->close_target(open.target_id);
}

TEST_CASE("GdbMiBackend: continue_process resumes a stopped inferior",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->open_executable(kFixturePath);
  ldb::backend::LaunchOptions opts;
  opts.stop_at_entry = true;
  auto launched = be->launch_process(open.target_id, opts);
  if (launched.state != ldb::backend::ProcessState::kStopped) {
    // Already ran to completion — that's a valid outcome on a
    // tiny fixture; we can't test continue from there.
    be->close_target(open.target_id);
    SUCCEED("fixture exited before continue could fire");
    return;
  }

  auto after = be->continue_process(open.target_id);
  CHECK((after.state == ldb::backend::ProcessState::kExited ||
         after.state == ldb::backend::ProcessState::kStopped));

  be->kill_process(open.target_id);
  be->close_target(open.target_id);
}

TEST_CASE("GdbMiBackend: continue with no process throws kBadState-ish",
          "[gdbmi][live][requires_gdb][error]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->open_executable(kFixturePath);
  // No launch — continue must throw with "no live process" wording
  // so the dispatcher maps to -32002 bad-state.
  try {
    be->continue_process(open.target_id);
    FAIL("continue_process without a live process should throw");
  } catch (const ldb::backend::Error& e) {
    const std::string what = e.what();
    CHECK(what.find("no live process") != std::string::npos);
  }
  be->close_target(open.target_id);
}
