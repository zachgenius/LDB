// SPDX-License-Identifier: Apache-2.0
// Evaluator tests for the agent-expression VM
// (post-V1 #25 phase-1, docs/28-agent-expressions.md §3).
//
// Coverage:
//   * Empty program → result 0, no error (convention: missing
//     predicate evaluates false).
//   * kConst8 / kConst16 / kConst32 / kConst64 — sign extension +
//     stack push.
//   * Arithmetic — add, sub, mul, div_signed; div_signed by zero
//     surfaces kDivByZero.
//   * Comparisons — eq, ne, lt, le, gt, ge (signed).
//   * Bitwise + logical.
//   * kReg via a mock backend that returns canned register values.
//   * kRef8/16/32/64 via a mock backend; little-endian decode.
//   * Failure modes — stack underflow, bad opcode, truncated
//     immediate, runaway instruction count.
//   * Anti-DoS caps — stack overflow, max program size enforced
//     by eval-time check (separate from codec-time check).

#include <catch_amalgamated.hpp>

#include "agent_expr/bytecode.h"
#include "backend/debugger_backend.h"

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

using ldb::agent_expr::EvalContext;
using ldb::agent_expr::EvalError;
using ldb::agent_expr::Op;
using ldb::agent_expr::Program;
using ldb::agent_expr::eval;
using ldb::backend::DebuggerBackend;
using ldb::backend::TargetId;
using ldb::backend::ThreadId;

namespace {

// A backend that returns canned register values + canned memory
// bytes. Throws for memory addresses not in the table so kRefN
// tests can exercise the kMemReadFailed path.
class MockBackend : public DebuggerBackend {
 public:
  using TID = TargetId;
  using ThrID = ThreadId;

  std::map<std::string, std::uint64_t>             regs;
  std::map<std::uint64_t, std::vector<std::uint8_t>> mem;

  std::uint64_t read_register(TID, ThrID, std::uint32_t,
                              const std::string& name) override {
    auto it = regs.find(name);
    return it == regs.end() ? 0 : it->second;
  }
  std::vector<std::uint8_t> read_memory(TID, std::uint64_t addr,
                                         std::uint64_t size) override {
    auto it = mem.find(addr);
    if (it == mem.end()) {
      throw ldb::backend::Error("mock: no memory at " + std::to_string(addr));
    }
    if (it->second.size() < size) {
      throw ldb::backend::Error("mock: short memory");
    }
    return std::vector<std::uint8_t>(it->second.begin(),
                                      it->second.begin() + size);
  }

  // --- Unused virtuals — stubs --------------------------------------
  ldb::backend::OpenResult open_executable(const std::string&) override { return {}; }
  ldb::backend::OpenResult create_empty_target() override { return {}; }
  ldb::backend::OpenResult load_core(const std::string&) override { return {}; }
  std::vector<ldb::backend::Module> list_modules(TID) override { return {}; }
  std::optional<ldb::backend::TypeLayout>
      find_type_layout(TID, const std::string&) override { return std::nullopt; }
  std::vector<ldb::backend::SymbolMatch>
      find_symbols(TID, const ldb::backend::SymbolQuery&) override { return {}; }
  std::vector<ldb::backend::GlobalVarMatch>
      find_globals_of_type(TID, std::string_view, bool&) override { return {}; }
  std::vector<ldb::backend::StringMatch>
      find_strings(TID, const ldb::backend::StringQuery&) override { return {}; }
  DebuggerBackend::ModuleSymbols  iterate_symbols(TID, std::string_view) override { return {}; }
  DebuggerBackend::ModuleTypes    iterate_types(TID, std::string_view)   override { return {}; }
  DebuggerBackend::ModuleStrings  iterate_strings(TID, std::string_view) override { return {}; }
  std::vector<ldb::backend::DisasmInsn>
      disassemble_range(TID, std::uint64_t, std::uint64_t) override { return {}; }
  std::vector<ldb::backend::XrefMatch>
      xref_address(TID, std::uint64_t) override { return {}; }
  std::vector<ldb::backend::StringXrefResult>
      find_string_xrefs(TID, const std::string&) override { return {}; }
  ldb::backend::ProcessStatus launch_process(TID,
      const ldb::backend::LaunchOptions&) override { return {}; }
  ldb::backend::ProcessStatus get_process_state(TID) override { return {}; }
  ldb::backend::ProcessStatus continue_process(TID) override { return {}; }
  ldb::backend::ProcessStatus continue_thread(TID, ThrID) override { return {}; }
  ldb::backend::ProcessStatus suspend_thread(TID, ThrID) override { return {}; }
  ldb::backend::ProcessStatus kill_process(TID) override { return {}; }
  ldb::backend::ProcessStatus attach(TID, std::int32_t) override { return {}; }
  ldb::backend::ProcessStatus detach_process(TID) override { return {}; }
  ldb::backend::ProcessStatus
      connect_remote_target(TID, const std::string&, const std::string&) override { return {}; }
  ldb::backend::ConnectRemoteSshResult
      connect_remote_target_ssh(TID, const ldb::backend::ConnectRemoteSshOptions&) override { return {}; }
  bool save_core(TID, const std::string&) override { return false; }
  std::vector<ldb::backend::ThreadInfo> list_threads(TID) override { return {}; }
  std::vector<ldb::backend::FrameInfo>
      list_frames(TID, ThrID, std::uint32_t) override { return {}; }
  ldb::backend::ProcessStatus
      step_thread(TID, ThrID, ldb::backend::StepKind) override { return {}; }
  ldb::backend::ProcessStatus reverse_continue(TID) override { return {}; }
  ldb::backend::ProcessStatus
      reverse_step_thread(TID, ThrID, ldb::backend::ReverseStepKind) override { return {}; }
  std::vector<ldb::backend::ValueInfo>
      list_locals(TID, ThrID, std::uint32_t) override { return {}; }
  std::vector<ldb::backend::ValueInfo>
      list_args(TID, ThrID, std::uint32_t) override { return {}; }
  std::vector<ldb::backend::ValueInfo>
      list_registers(TID, ThrID, std::uint32_t) override { return {}; }
  ldb::backend::EvalResult
      evaluate_expression(TID, ThrID, std::uint32_t, const std::string&,
                          const ldb::backend::EvalOptions&) override { return {}; }
  ldb::backend::ReadResult
      read_value_path(TID, ThrID, std::uint32_t, const std::string&) override { return {}; }
  std::string read_cstring(TID, std::uint64_t, std::uint32_t) override { return {}; }
  std::vector<ldb::backend::MemoryRegion> list_regions(TID) override { return {}; }
  std::vector<ldb::backend::MemorySearchHit>
      search_memory(TID, std::uint64_t, std::uint64_t,
                    const std::vector<std::uint8_t>&, std::uint32_t) override { return {}; }
  ldb::backend::BreakpointHandle
      create_breakpoint(TID, const ldb::backend::BreakpointSpec&) override { return {}; }
  void set_breakpoint_callback(TID, std::int32_t,
                               ldb::backend::BreakpointCallback, void*) override {}
  void disable_breakpoint(TID, std::int32_t) override {}
  void enable_breakpoint(TID, std::int32_t) override {}
  void delete_breakpoint(TID, std::int32_t) override {}
  void close_target(TID) override {}
  std::vector<ldb::backend::TargetInfo> list_targets() override { return {}; }
  void label_target(TID, std::string) override {}
  std::optional<std::string> get_target_label(TID) override { return std::nullopt; }
  std::string snapshot_for_target(TID) override { return "none"; }
  void attach_target_resource(TID,
      std::unique_ptr<DebuggerBackend::TargetResource>) override {}
};

Program just_end() {
  return Program{{static_cast<std::uint8_t>(Op::kEnd)}, {}};
}

// Helper: build a program from a sequence of bytes for terseness.
Program prog(std::initializer_list<std::uint8_t> bytes) {
  return Program{std::vector<std::uint8_t>(bytes), {}};
}

}  // namespace

TEST_CASE("evaluator: empty program → result 0",
          "[agent_expr][eval][empty]") {
  EvalContext ctx;
  auto r = eval(just_end(), ctx);
  CHECK(r.error == EvalError::kOk);
  CHECK(r.value == 0);
}

TEST_CASE("evaluator: const8 pushes a sign-extended byte",
          "[agent_expr][eval][const]") {
  EvalContext ctx;
  // kConst8 0xff (= -1 sign-extended), kEnd
  auto r = eval(prog({
      static_cast<std::uint8_t>(Op::kConst8), 0xff,
      static_cast<std::uint8_t>(Op::kEnd),
  }), ctx);
  CHECK(r.error == EvalError::kOk);
  CHECK(r.value == -1);
}

TEST_CASE("evaluator: const32 BE roundtrip",
          "[agent_expr][eval][const]") {
  EvalContext ctx;
  auto r = eval(prog({
      static_cast<std::uint8_t>(Op::kConst32),
      0x00, 0x00, 0x01, 0x00,    // 256
      static_cast<std::uint8_t>(Op::kEnd),
  }), ctx);
  CHECK(r.error == EvalError::kOk);
  CHECK(r.value == 256);
}

TEST_CASE("evaluator: add / sub / mul / div_signed",
          "[agent_expr][eval][arith]") {
  EvalContext ctx;
  // (const 6) (const 4) add → 10
  CHECK(eval(prog({0x10, 6, 0x10, 4, 0x40, 0x00}), ctx).value == 10);
  // (const 10) (const 4) sub → 6  (stack: 10 4 → 6)
  // sub: pop b, a → a-b ⇒ (const 10) pushed first, then 4, so 10-4=6
  CHECK(eval(prog({0x10, 10, 0x10, 4, 0x41, 0x00}), ctx).value == 6);
  // (const 6) (const 7) mul → 42
  CHECK(eval(prog({0x10, 6, 0x10, 7, 0x42, 0x00}), ctx).value == 42);
  // (const 20) (const 5) div_signed → 4
  CHECK(eval(prog({0x10, 20, 0x10, 5, 0x43, 0x00}), ctx).value == 4);
}

TEST_CASE("evaluator: div_signed by zero → kDivByZero",
          "[agent_expr][eval][arith][error]") {
  EvalContext ctx;
  auto r = eval(prog({0x10, 20, 0x10, 0, 0x43, 0x00}), ctx);
  CHECK(r.error == EvalError::kDivByZero);
}

TEST_CASE("evaluator: comparison opcodes",
          "[agent_expr][eval][cmp]") {
  EvalContext ctx;
  // eq(5, 5) = 1
  CHECK(eval(prog({0x10, 5, 0x10, 5, 0x50, 0x00}), ctx).value == 1);
  // eq(5, 6) = 0
  CHECK(eval(prog({0x10, 5, 0x10, 6, 0x50, 0x00}), ctx).value == 0);
  // ne(5, 6) = 1
  CHECK(eval(prog({0x10, 5, 0x10, 6, 0x51, 0x00}), ctx).value == 1);
  // lt_signed(3, 5) = 1  (3 < 5)
  CHECK(eval(prog({0x10, 3, 0x10, 5, 0x52, 0x00}), ctx).value == 1);
  // le_signed(5, 5) = 1
  CHECK(eval(prog({0x10, 5, 0x10, 5, 0x53, 0x00}), ctx).value == 1);
  // gt_signed(5, 3) = 1
  CHECK(eval(prog({0x10, 5, 0x10, 3, 0x54, 0x00}), ctx).value == 1);
  // ge_signed(5, 5) = 1
  CHECK(eval(prog({0x10, 5, 0x10, 5, 0x55, 0x00}), ctx).value == 1);
}

TEST_CASE("evaluator: bitwise + logical",
          "[agent_expr][eval][bit]") {
  EvalContext ctx;
  // bit_and(0x0f, 0x33) = 0x03
  CHECK(eval(prog({0x10, 0x0f, 0x10, 0x33, 0x60, 0x00}), ctx).value == 0x03);
  // bit_or(0x0c, 0x03) = 0x0f
  CHECK(eval(prog({0x10, 0x0c, 0x10, 0x03, 0x61, 0x00}), ctx).value == 0x0f);
  // bit_xor(0x0f, -1) = ~0x0f = 0xfffffffffffffff0 = -16
  // (kConst8 0xff sign-extends to -1, so this XORs with the sign
  // bit pattern — useful for testing wide-int behavior.)
  CHECK(eval(prog({0x10, 0x0f, 0x10, static_cast<std::uint8_t>(0xff), 0x62, 0x00}), ctx).value == -16);
  // bit_not(0) = -1
  CHECK(eval(prog({0x10, 0, 0x63, 0x00}), ctx).value == -1);
  // log_and(5, 0) = 0
  CHECK(eval(prog({0x10, 5, 0x10, 0, 0x70, 0x00}), ctx).value == 0);
  // log_or(0, 5) = 1
  CHECK(eval(prog({0x10, 0, 0x10, 5, 0x71, 0x00}), ctx).value == 1);
  // log_not(0) = 1
  CHECK(eval(prog({0x10, 0, 0x72, 0x00}), ctx).value == 1);
  // log_not(5) = 0
  CHECK(eval(prog({0x10, 5, 0x72, 0x00}), ctx).value == 0);
}

TEST_CASE("evaluator: dup / drop / swap",
          "[agent_expr][eval][stack]") {
  EvalContext ctx;
  // (const 7) dup add → 14
  CHECK(eval(prog({0x10, 7, 0x80, 0x40, 0x00}), ctx).value == 14);
  // (const 7) (const 9) drop → 7
  CHECK(eval(prog({0x10, 7, 0x10, 9, 0x81, 0x00}), ctx).value == 7);
  // (const 10) (const 3) swap sub → 3-10=-7 (sub: a-b, after swap stack is 3,10 → 3-10=-7)
  CHECK(eval(prog({0x10, 10, 0x10, 3, 0x82, 0x41, 0x00}), ctx).value == -7);
}

TEST_CASE("evaluator: kReg reads via backend.read_register",
          "[agent_expr][eval][reg]") {
  MockBackend be;
  be.regs["rax"] = 0xdeadbeef;
  EvalContext ctx;
  ctx.backend = &be;

  Program p;
  p.code = {
      static_cast<std::uint8_t>(Op::kReg), 0x00, 0x00,
      static_cast<std::uint8_t>(Op::kEnd),
  };
  p.reg_table = {"rax"};
  auto r = eval(p, ctx);
  CHECK(r.error == EvalError::kOk);
  CHECK(static_cast<std::uint64_t>(r.value) == 0xdeadbeefULL);
}

TEST_CASE("evaluator: kReg with index out of table bounds → kRegNotFound",
          "[agent_expr][eval][reg][error]") {
  MockBackend be;
  EvalContext ctx;
  ctx.backend = &be;
  Program p;
  p.code = {
      static_cast<std::uint8_t>(Op::kReg), 0x00, 0x05,   // index 5
      static_cast<std::uint8_t>(Op::kEnd),
  };
  p.reg_table = {"rax"};   // only one entry
  auto r = eval(p, ctx);
  CHECK(r.error == EvalError::kRegNotFound);
}

TEST_CASE("evaluator: kRef32 reads 4 LE bytes via backend.read_memory",
          "[agent_expr][eval][ref]") {
  MockBackend be;
  be.mem[0x1000] = {0x78, 0x56, 0x34, 0x12};   // little-endian 0x12345678
  EvalContext ctx;
  ctx.backend = &be;
  // (const32 0x1000) (kRef32) → 0x12345678
  auto r = eval(prog({
      static_cast<std::uint8_t>(Op::kConst32),
      0x00, 0x00, 0x10, 0x00,
      static_cast<std::uint8_t>(Op::kRef32),
      static_cast<std::uint8_t>(Op::kEnd),
  }), ctx);
  CHECK(r.error == EvalError::kOk);
  CHECK(r.value == 0x12345678);
}

TEST_CASE("evaluator: kRef64 read against unmapped addr → kMemReadFailed",
          "[agent_expr][eval][ref][error]") {
  MockBackend be;
  EvalContext ctx;
  ctx.backend = &be;
  auto r = eval(prog({
      static_cast<std::uint8_t>(Op::kConst32),
      0x00, 0x00, 0x10, 0x00,
      static_cast<std::uint8_t>(Op::kRef64),
      static_cast<std::uint8_t>(Op::kEnd),
  }), ctx);
  CHECK(r.error == EvalError::kMemReadFailed);
}

TEST_CASE("evaluator: stack underflow on binop with empty stack",
          "[agent_expr][eval][error][stack]") {
  EvalContext ctx;
  auto r = eval(prog({0x40, 0x00}), ctx);  // bare add
  CHECK(r.error == EvalError::kStackUnderflow);
}

TEST_CASE("evaluator: bad opcode → kBadOpcode",
          "[agent_expr][eval][error]") {
  EvalContext ctx;
  auto r = eval(prog({0xfe, 0x00}), ctx);
  CHECK(r.error == EvalError::kBadOpcode);
}

TEST_CASE("evaluator: const32 with truncated immediate → kBadImmediate",
          "[agent_expr][eval][error][imm]") {
  EvalContext ctx;
  // kConst32 + only 2 imm bytes, then kEnd — should fail decode
  // at the imm read.
  auto r = eval(prog({0x12, 0x00, 0x00, 0x00 /* end of program */}), ctx);
  CHECK(r.error == EvalError::kBadImmediate);
}

TEST_CASE("evaluator: stack overflow when program pushes deeper than cap",
          "[agent_expr][eval][error][stack][cap]") {
  // Push 65 consts (cap is 64). The 65th push hits kStackOverflow.
  std::vector<std::uint8_t> code;
  for (int i = 0; i < 65; ++i) {
    code.push_back(static_cast<std::uint8_t>(Op::kConst8));
    code.push_back(1);
  }
  code.push_back(static_cast<std::uint8_t>(Op::kEnd));
  EvalContext ctx;
  auto r = eval(Program{code, {}}, ctx);
  CHECK(r.error == EvalError::kStackOverflow);
}

TEST_CASE("evaluator: program exceeding kMaxProgramBytes is rejected",
          "[agent_expr][eval][error][cap]") {
  std::vector<std::uint8_t> code(ldb::agent_expr::kMaxProgramBytes + 1, 0x81);
  code.push_back(static_cast<std::uint8_t>(Op::kEnd));
  EvalContext ctx;
  auto r = eval(Program{code, {}}, ctx);
  CHECK(r.error == EvalError::kProgramTooLong);
}

TEST_CASE("evaluator: program without kEnd surfaces kMissingEnd",
          "[agent_expr][eval][error][end]") {
  // Just two consts, no kEnd. The evaluator runs off the end of
  // code[] and must surface kMissingEnd rather than silently
  // returning kOk — a truncated bytecode shouldn't masquerade as
  // a valid predicate result.
  EvalContext ctx;
  auto r = eval(prog({0x10, 5, 0x10, 7}), ctx);
  CHECK(r.error == EvalError::kMissingEnd);
  CHECK(r.value == 7);   // last value pushed is still surfaced
}

// --- Control flow (#25 phase-3) -------------------------------------------
//
// kIfGoto / kGoto added in phase-3. We picked opcode bytes 0x90 / 0x91
// from LDB's reserved 0x90–0x9f control-flow range rather than gdb's
// 0x20 / 0x21 (which collide with LDB's kReg at 0x20). See docs/28 §2
// and bytecode.h for the rationale.
//
// Wire layout: both ops carry a u16 BE *absolute* target pc as their
// immediate. kIfGoto pops one value and jumps only if non-zero;
// kGoto jumps unconditionally.

TEST_CASE("evaluator: kGoto jumps unconditionally over dead code",
          "[agent_expr][eval][ctrl][goto]") {
  EvalContext ctx;
  //   pc=0  kGoto       0x91
  //   pc=1  imm hi      0x00
  //   pc=2  imm lo      0x07   → target pc 7
  //   pc=3  kConst8     0x10
  //   pc=4  imm         42      (dead — should not push)
  //   pc=5  kEnd        0x00    (dead)
  //   pc=6  pad         0x10    (dead)
  //   pc=7  kConst8     0x10
  //   pc=8  imm         7
  //   pc=9  kEnd        0x00
  auto r = eval(prog({
      0x91, 0x00, 0x07,
      0x10, 42, 0x00, 0x10,
      0x10, 7, 0x00,
  }), ctx);
  CHECK(r.error == EvalError::kOk);
  CHECK(r.value == 7);
}

TEST_CASE("evaluator: kIfGoto pops non-zero and jumps",
          "[agent_expr][eval][ctrl][if_goto]") {
  EvalContext ctx;
  //   pc=0  kConst8 1     (push 1 — truthy)
  //   pc=2  kIfGoto 0x0008 → branch taken
  //   pc=5  kConst8 99    (dead)
  //   pc=7  kEnd          (dead)
  //   pc=8  kConst8 42    (live target)
  //   pc=10 kEnd
  auto r = eval(prog({
      0x10, 1,
      0x90, 0x00, 0x08,
      0x10, 99, 0x00,
      0x10, 42, 0x00,
  }), ctx);
  CHECK(r.error == EvalError::kOk);
  CHECK(r.value == 42);
}

TEST_CASE("evaluator: kIfGoto pops zero and falls through",
          "[agent_expr][eval][ctrl][if_goto]") {
  EvalContext ctx;
  //   pc=0  kConst8 0
  //   pc=2  kIfGoto 0x0008 → not taken
  //   pc=5  kConst8 99    (live — fall through)
  //   pc=7  kEnd
  //   pc=8  kConst8 42    (dead)
  //   pc=10 kEnd
  auto r = eval(prog({
      0x10, 0,
      0x90, 0x00, 0x08,
      0x10, 99, 0x00,
      0x10, 42, 0x00,
  }), ctx);
  CHECK(r.error == EvalError::kOk);
  CHECK(r.value == 99);
}

TEST_CASE("evaluator: kGoto backward branch still terminates via kEnd",
          "[agent_expr][eval][ctrl][backward]") {
  EvalContext ctx;
  // Backward jump anti-loop sanity. Layout:
  //   pc=0   kGoto 0x0006   → forward to the kIfGoto guard
  //   pc=3   kConst8 42     (the "body" — pushes 42)
  //   pc=5   kEnd           (final exit)
  //   pc=6   kConst8 0      (push 0 — guard says don't loop back)
  //   pc=8   kIfGoto 0x0003 (if non-zero would go back; 0 falls through)
  //   pc=11  kGoto 0x0003   (unconditional jump to body)
  // Execution: 0→6 (push 0), 6→8 (ifgoto with 0 → fall through),
  //            8→11 (kGoto), 11→3 (push 42), 3→5 (kEnd) → result 42.
  auto r = eval(prog({
      0x91, 0x00, 0x06,
      0x10, 42,
      0x00,
      0x10, 0,
      0x90, 0x00, 0x03,
      0x91, 0x00, 0x03,
  }), ctx);
  CHECK(r.error == EvalError::kOk);
  CHECK(r.value == 42);
}

TEST_CASE("evaluator: kGoto target past end-of-code → kBadImmediate",
          "[agent_expr][eval][ctrl][error]") {
  EvalContext ctx;
  // kGoto with target = 0x00ff (past end). Bounds check must fire.
  auto r = eval(prog({
      0x91, 0x00, 0xff,
      0x00,
  }), ctx);
  CHECK(r.error == EvalError::kBadImmediate);
}

TEST_CASE("evaluator: kIfGoto target past end-of-code → kBadImmediate (if-taken)",
          "[agent_expr][eval][ctrl][error]") {
  EvalContext ctx;
  // kConst8 1 (truthy) then kIfGoto 0x00ff (out of range).
  auto r = eval(prog({
      0x10, 1,
      0x90, 0x00, 0xff,
      0x00,
  }), ctx);
  CHECK(r.error == EvalError::kBadImmediate);
}

TEST_CASE("evaluator: kIfGoto with bad target AND zero cond still surfaces kBadImmediate",
          "[agent_expr][eval][ctrl][error][regression]") {
  // Regression for the bounds-check asymmetry: pre-fix the kIfGoto
  // handler only validated the target inside the "cond != 0" branch.
  // A predicate with a broken jump target would silently fall through
  // when cond happened to be zero — and crash on the next call when
  // cond was truthy. The target is malformed bytecode regardless of
  // whether the branch is taken, so validation must run first.
  //
  // Program: push 0, kIfGoto 0x00ff (way past end of code).
  // Pre-fix: cond pops as 0, branch not taken, kBadImmediate never
  //          surfaces; the kConst8 7 below runs and we get value=7,
  //          error=kOk. That's the silent-failure mode the fix kills.
  // Post-fix: target validated unconditionally → kBadImmediate.
  EvalContext ctx;
  auto r = eval(prog({
      0x10, 0,              // push 0 (falsy)
      0x90, 0x00, 0xff,     // kIfGoto 0x00ff — target way out of range
      0x10, 7,              // would execute pre-fix (proves silent skip)
      0x00,                 // kEnd
  }), ctx);
  CHECK(r.error == EvalError::kBadImmediate);
}

TEST_CASE("evaluator: kIfGoto with empty stack → kStackUnderflow",
          "[agent_expr][eval][ctrl][error]") {
  EvalContext ctx;
  auto r = eval(prog({
      0x90, 0x00, 0x04,
      0x00,
      0x00,
  }), ctx);
  CHECK(r.error == EvalError::kStackUnderflow);
}

TEST_CASE("evaluator: kGoto with truncated immediate → kBadImmediate",
          "[agent_expr][eval][ctrl][error][imm]") {
  EvalContext ctx;
  // Only one imm byte after kGoto.
  auto r = eval(prog({0x91, 0x00}), ctx);
  CHECK(r.error == EvalError::kBadImmediate);
}

TEST_CASE("evaluator: infinite loop via backward kGoto → kInsnLimitExceeded",
          "[agent_expr][eval][ctrl][cap]") {
  EvalContext ctx;
  // Three-op loop body so we can assert that the cap fired at the
  // expected iteration count — not on iteration 1 due to an
  // off-by-one in the counter. Each cycle dispatches exactly three
  // ops: kConst8 (push), kDrop (pop), kGoto (jump back).
  //
  //   pc=0  kConst8 1   (push 1)
  //   pc=2  kDrop       (pop it back off)
  //   pc=3  kGoto 0     (jump to pc=0, loop forever)
  //
  // The cap is kMaxInsnCount = 10000 ops. We expect to execute
  // exactly that many ops before the 10001-th increment trips the
  // check — so insn_count must equal kMaxInsnCount and the loop
  // body ran ~3333 full cycles. Asserting the exact value locks
  // both halves down: the cap didn't fire early AND the loop did
  // run for the full quota.
  auto r = eval(prog({
      0x10, 1,             // kConst8 1
      0x81,                // kDrop
      0x91, 0x00, 0x00,    // kGoto 0
  }), ctx);
  CHECK(r.error == EvalError::kInsnLimitExceeded);
  CHECK(r.insn_count == ldb::agent_expr::kMaxInsnCount);
}

TEST_CASE("evaluator: insn_count surfaces actual ops executed on success",
          "[agent_expr][eval][ctrl][cap]") {
  // Sanity check on insn_count for a normal (non-cap) run, so the
  // infinite-loop test above isn't the only thing exercising it.
  // kConst8 + kEnd = 2 ops dispatched.
  EvalContext ctx;
  auto r = eval(prog({0x10, 42, 0x00}), ctx);
  CHECK(r.error == EvalError::kOk);
  CHECK(r.value == 42);
  CHECK(r.insn_count == 2);
}
