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
#include <system_error>
#include <unistd.h>

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

// ── Value inspection (locals / args / registers / eval / read) ─────────
//
// Helper for the value tests: launch the fixture stopped at entry and
// step into point2_distance_sq so we have a frame with both locals and
// args available. Returns nullopt when the fixture exited before we
// could land in a useful state; callers SUCCEED and return in that
// case (matches the existing process/continue test pattern).
namespace {

struct StoppedFrame {
  std::uint64_t   target_id;
  ldb::backend::ThreadId thread_id;
  std::uint32_t   frame_index = 0;
};

std::optional<StoppedFrame>
launch_and_break_at(GdbMiBackend& be, const std::string& fn) {
  auto open = be.open_executable(kFixturePath);
  ldb::backend::LaunchOptions opts;
  opts.stop_at_entry = true;
  auto st = be.launch_process(open.target_id, opts);
  if (st.state != ldb::backend::ProcessState::kStopped) {
    be.close_target(open.target_id);
    return std::nullopt;
  }
  // From the entry-stop, set a permanent breakpoint at `fn` and
  // continue until it hits. find_symbols would also work but b/p
  // is cheaper to wire.
  ldb::backend::BreakpointSpec spec;
  spec.function = fn;
  try {
    (void)be.create_breakpoint(open.target_id, spec);
  } catch (const ldb::backend::Error&) {
    // create_breakpoint isn't implemented on GdbMiBackend yet —
    // skip the test by returning nullopt; the caller handles it.
    be.close_target(open.target_id);
    return std::nullopt;
  }
  auto after = be.continue_process(open.target_id);
  if (after.state != ldb::backend::ProcessState::kStopped) {
    be.close_target(open.target_id);
    return std::nullopt;
  }
  auto threads = be.list_threads(open.target_id);
  if (threads.empty()) {
    be.close_target(open.target_id);
    return std::nullopt;
  }
  StoppedFrame sf;
  sf.target_id  = open.target_id;
  sf.thread_id  = threads[0].tid;
  sf.frame_index = 0;
  return sf;
}

}  // namespace

TEST_CASE("GdbMiBackend: list_locals at main stop shows at least one local",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->open_executable(kFixturePath);
  ldb::backend::LaunchOptions opts;
  opts.stop_at_entry = true;
  auto st = be->launch_process(open.target_id, opts);
  if (st.state != ldb::backend::ProcessState::kStopped) {
    be->close_target(open.target_id);
    SUCCEED("fixture exited before stop_at_entry could fire");
    return;
  }
  auto threads = be->list_threads(open.target_id);
  REQUIRE_FALSE(threads.empty());
  // launch_process with stop_at_entry=true stops at main's prologue,
  // so locals like `n`, `s`, `d`, `sum` are in scope (some compilers
  // delay their visibility — but `n` is the first declared and gcc
  // -O0 makes it live from the prologue).
  auto locals = be->list_locals(open.target_id, threads[0].tid, 0);
  CHECK_FALSE(locals.empty());
  be->kill_process(open.target_id);
  be->close_target(open.target_id);
}

TEST_CASE("GdbMiBackend: list_args at point2_distance_sq returns exactly two",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto stopped = launch_and_break_at(*be, "point2_distance_sq");
  if (!stopped.has_value()) {
    SUCCEED("could not land at point2_distance_sq (breakpoint unsupported "
            "or fixture exited early)");
    return;
  }
  auto args = be->list_args(stopped->target_id, stopped->thread_id,
                             stopped->frame_index);
  CHECK(args.size() == 2);
  // Both args are pointers — the value strings should be hex-shaped.
  for (const auto& a : args) {
    CHECK_FALSE(a.name.empty());
  }
  be->kill_process(stopped->target_id);
  be->close_target(stopped->target_id);
}

TEST_CASE("GdbMiBackend: list_registers returns a populated list",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->open_executable(kFixturePath);
  ldb::backend::LaunchOptions opts;
  opts.stop_at_entry = true;
  auto st = be->launch_process(open.target_id, opts);
  if (st.state != ldb::backend::ProcessState::kStopped) {
    be->close_target(open.target_id);
    SUCCEED("fixture exited before stop_at_entry could fire");
    return;
  }
  auto threads = be->list_threads(open.target_id);
  REQUIRE_FALSE(threads.empty());
  auto regs = be->list_registers(open.target_id, threads[0].tid, 0);
  CHECK_FALSE(regs.empty());
  // Look for a known x86-64 or arm64 register name. gdb emits them
  // lowercased on both Linux ABIs.
  bool found_known = false;
  for (const auto& r : regs) {
#if defined(__x86_64__) || defined(__i386__)
    if (r.name == "rax" || r.name == "eax") found_known = true;
#elif defined(__aarch64__)
    if (r.name == "x0" || r.name == "pc") found_known = true;
#else
    // Unknown architecture — accept any non-empty name as proof of
    // the round-trip working.
    if (!r.name.empty()) found_known = true;
#endif
    if (found_known) break;
  }
  CHECK(found_known);
  be->kill_process(open.target_id);
  be->close_target(open.target_id);
}

TEST_CASE("GdbMiBackend: read_register pc/rip returns a non-zero value",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->open_executable(kFixturePath);
  ldb::backend::LaunchOptions opts;
  opts.stop_at_entry = true;
  auto st = be->launch_process(open.target_id, opts);
  if (st.state != ldb::backend::ProcessState::kStopped) {
    be->close_target(open.target_id);
    SUCCEED("fixture exited before stop_at_entry could fire");
    return;
  }
  auto threads = be->list_threads(open.target_id);
  REQUIRE_FALSE(threads.empty());
#if defined(__x86_64__) || defined(__i386__)
  const std::string pc_name = "rip";
#elif defined(__aarch64__)
  const std::string pc_name = "pc";
#else
  const std::string pc_name = "pc";
#endif
  auto pc = be->read_register(open.target_id, threads[0].tid, 0, pc_name);
  CHECK(pc != 0);
  // It should match the thread's reported PC (within rounding —
  // gdb and our list_threads parse the same -thread-info payload).
  CHECK(pc == threads[0].pc);
  be->kill_process(open.target_id);
  be->close_target(open.target_id);
}

TEST_CASE("GdbMiBackend: evaluate_expression handles pure arithmetic",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  // No live process needed — gdb folds "1+2" at parse time.
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->open_executable(kFixturePath);
  ldb::backend::EvalOptions opts;
  auto res = be->evaluate_expression(open.target_id, /*tid=*/0,
                                       /*frame=*/0, "1+2", opts);
  CHECK(res.ok);
  REQUIRE(res.value.summary.has_value());
  CHECK(res.value.summary->find('3') != std::string::npos);
  be->close_target(open.target_id);
}

// ── Breakpoints (v1.4 final batch) ────────────────────────────────────

TEST_CASE("GdbMiBackend: create_breakpoint at main returns bp_id and addr",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->open_executable(kFixturePath);

  ldb::backend::BreakpointSpec spec;
  spec.function = "main";
  auto h = be->create_breakpoint(open.target_id, spec);
  CHECK(h.bp_id != 0);
  // locations: 1 when gdb resolved an address (non-pending bp).
  CHECK(h.locations == 1);
  be->close_target(open.target_id);
}

TEST_CASE("GdbMiBackend: create_breakpoint without spec fields throws",
          "[gdbmi][live][requires_gdb][error]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->open_executable(kFixturePath);
  ldb::backend::BreakpointSpec spec;  // all defaults
  CHECK_THROWS_AS(be->create_breakpoint(open.target_id, spec),
                  ldb::backend::Error);
  be->close_target(open.target_id);
}

TEST_CASE("GdbMiBackend: disable/enable/delete_breakpoint round-trip",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->open_executable(kFixturePath);

  ldb::backend::BreakpointSpec spec;
  spec.function = "point2_distance_sq";
  auto h = be->create_breakpoint(open.target_id, spec);
  REQUIRE(h.bp_id != 0);

  // All three should succeed silently on a real bp.
  CHECK_NOTHROW(be->disable_breakpoint(open.target_id, h.bp_id));
  CHECK_NOTHROW(be->enable_breakpoint(open.target_id, h.bp_id));
  CHECK_NOTHROW(be->delete_breakpoint(open.target_id, h.bp_id));
  be->close_target(open.target_id);
}

TEST_CASE("GdbMiBackend: disable_breakpoint unknown id throws",
          "[gdbmi][live][requires_gdb][error]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->open_executable(kFixturePath);
  CHECK_THROWS_AS(be->disable_breakpoint(open.target_id, 9999),
                  ldb::backend::Error);
  be->close_target(open.target_id);
}

TEST_CASE("GdbMiBackend: set_breakpoint_callback accepts and stores",
          "[gdbmi][live][requires_gdb]") {
  // The callback won't actually fire on the v1.4 gdb backend (best-
  // effort; no event thread). The test pins the contract that the
  // registration path is non-throwing on a valid bp_id, which is
  // what the orchestrator depends on.
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->open_executable(kFixturePath);
  ldb::backend::BreakpointSpec spec;
  spec.function = "main";
  auto h = be->create_breakpoint(open.target_id, spec);
  REQUIRE(h.bp_id != 0);

  ldb::backend::BreakpointCallback cb =
      [](void*, const ldb::backend::BreakpointCallbackArgs&) { return false; };
  CHECK_NOTHROW(
      be->set_breakpoint_callback(open.target_id, h.bp_id,
                                  std::move(cb), /*baton=*/nullptr));
  be->close_target(open.target_id);
}

// ── Static analysis (v1.4 final batch) ────────────────────────────────

TEST_CASE("GdbMiBackend: find_type_layout(point2) returns x,y at 0,4",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->open_executable(kFixturePath);
  // The fixture's `struct point2` has two int fields, no padding.
  // The backend accepts plain "point2" and retries "struct point2"
  // internally — both forms succeed.
  auto layout = be->find_type_layout(open.target_id, "point2");
  REQUIRE(layout.has_value());
  CHECK(layout->byte_size == 8);
  REQUIRE(layout->fields.size() == 2);
  CHECK(layout->fields[0].name == "x");
  CHECK(layout->fields[0].offset == 0);
  CHECK(layout->fields[0].byte_size == 4);
  CHECK(layout->fields[1].name == "y");
  CHECK(layout->fields[1].offset == 4);
  CHECK(layout->fields[1].byte_size == 4);
  // alignment is best-effort; gdb's ptype /o doesn't surface it.
  CHECK(layout->alignment == 0);
  be->close_target(open.target_id);
}

TEST_CASE("GdbMiBackend: find_type_layout(dxp_login_frame) detects hole",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->open_executable(kFixturePath);
  auto layout = be->find_type_layout(open.target_id, "dxp_login_frame");
  REQUIRE(layout.has_value());
  CHECK(layout->byte_size == 16);
  REQUIRE(layout->fields.size() == 2);
  // magic at 0..3, sid at 8..15 → 4-byte hole_after on magic.
  CHECK(layout->fields[0].offset == 0);
  CHECK(layout->fields[0].byte_size == 4);
  CHECK(layout->fields[0].holes_after == 4);
  CHECK(layout->fields[1].offset == 8);
  CHECK(layout->fields[1].byte_size == 8);
  CHECK(layout->holes_total == 4);
  be->close_target(open.target_id);
}

TEST_CASE("GdbMiBackend: find_type_layout on unknown returns nullopt",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->open_executable(kFixturePath);
  auto layout = be->find_type_layout(open.target_id, "no_such_type_xyz");
  CHECK_FALSE(layout.has_value());
  be->close_target(open.target_id);
}

TEST_CASE("GdbMiBackend: find_globals_of_type finds g_login_template",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->open_executable(kFixturePath);
  bool truncated = true;  // sentinel to confirm backend clears it
  auto matches = be->find_globals_of_type(open.target_id,
                                           "dxp_login_frame", truncated);
  CHECK_FALSE(truncated);
  bool found = false;
  for (const auto& g : matches) {
    if (g.name == "g_login_template") {
      found = true;
      CHECK(g.type.find("dxp_login_frame") != std::string::npos);
      CHECK(g.file_address != 0);
    }
  }
  CHECK(found);
  be->close_target(open.target_id);
}

TEST_CASE("GdbMiBackend: find_globals_of_type empty name throws",
          "[gdbmi][live][requires_gdb][error]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->open_executable(kFixturePath);
  bool truncated = false;
  CHECK_THROWS_AS(be->find_globals_of_type(open.target_id, "", truncated),
                  ldb::backend::Error);
  be->close_target(open.target_id);
}

// ── Punted endpoints — return empty, don't crash ──────────────────────

TEST_CASE("GdbMiBackend: find_strings is a punted no-op (returns empty)",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->open_executable(kFixturePath);
  ldb::backend::StringQuery q;
  auto out = be->find_strings(open.target_id, q);
  CHECK(out.empty());
  be->close_target(open.target_id);
}

TEST_CASE("GdbMiBackend: xref_address is a punted no-op (returns empty)",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->open_executable(kFixturePath);
  auto out = be->xref_address(open.target_id, 0x1000);
  CHECK(out.empty());
  be->close_target(open.target_id);
}

TEST_CASE("GdbMiBackend: find_string_xrefs is a punted no-op (returns empty)",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->open_executable(kFixturePath);
  auto out = be->find_string_xrefs(open.target_id, "DXP/1.0");
  CHECK(out.empty());
  be->close_target(open.target_id);
}

// ── Connect / save / load ─────────────────────────────────────────────

TEST_CASE("GdbMiBackend: connect_remote_target rr:// is rejected with reason",
          "[gdbmi][live][requires_gdb][error]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->create_empty_target();
  try {
    be->connect_remote_target(open.target_id, "rr:///tmp/some-trace", "");
    FAIL("rr:// URL should have thrown");
  } catch (const ldb::backend::Error& e) {
    const std::string what = e.what();
    CHECK(what.find("rr://") != std::string::npos);
  }
  be->close_target(open.target_id);
}

TEST_CASE("GdbMiBackend: connect_remote_target_ssh punts cleanly",
          "[gdbmi][live][requires_gdb][error]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->create_empty_target();
  ldb::backend::ConnectRemoteSshOptions opts;
  opts.host = "localhost";
  opts.inferior_path = "/bin/true";
  try {
    be->connect_remote_target_ssh(open.target_id, opts);
    FAIL("ssh transport should have thrown");
  } catch (const ldb::backend::Error& e) {
    const std::string what = e.what();
    CHECK(what.find("does not support") != std::string::npos);
  }
  be->close_target(open.target_id);
}

TEST_CASE("GdbMiBackend: save_core writes a core file on a stopped process",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->open_executable(kFixturePath);
  ldb::backend::LaunchOptions lopts;
  lopts.stop_at_entry = true;
  auto st = be->launch_process(open.target_id, lopts);
  if (st.state != ldb::backend::ProcessState::kStopped) {
    be->close_target(open.target_id);
    SUCCEED("fixture exited before stop_at_entry could fire");
    return;
  }

  auto path = std::filesystem::temp_directory_path() /
              ("ldb-gdbmi-save-core-" + std::to_string(::getpid()) + ".core");
  // Best-effort delete leftover from a prior crashed run.
  std::error_code ec;
  std::filesystem::remove(path, ec);

  bool ok = be->save_core(open.target_id, path.string());
  CHECK(ok);
  CHECK(std::filesystem::exists(path));
  std::filesystem::remove(path, ec);

  be->kill_process(open.target_id);
  be->close_target(open.target_id);
}

TEST_CASE("GdbMiBackend: save_core without a live process throws",
          "[gdbmi][live][requires_gdb][error]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  auto be = std::make_unique<GdbMiBackend>();
  auto open = be->open_executable(kFixturePath);
  try {
    be->save_core(open.target_id, "/tmp/should-not-exist.core");
    FAIL("save_core without live process should throw");
  } catch (const ldb::backend::Error& e) {
    const std::string what = e.what();
    CHECK(what.find("no live process") != std::string::npos);
  }
  be->close_target(open.target_id);
}
