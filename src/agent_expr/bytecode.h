// SPDX-License-Identifier: Apache-2.0
#pragma once

// Agent-expression bytecode definitions (post-V1 #25 phase-1,
// docs/28-agent-expressions.md). The opcode set is a deliberate
// subset of GDB's agent expression bytecode (gdb manual §28). We
// keep the wire format compatible with GDB so phase-3's in-target
// VM (#26 territory) can re-use it without translation.

#include "backend/debugger_backend.h"   // backend::TargetId, ThreadId

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ldb::agent_expr {

// --- Opcode table -----------------------------------------------------
//
// All multi-byte immediates are big-endian. The stack holds signed
// 64-bit values throughout.

enum class Op : std::uint8_t {
  // Halt; top-of-stack is the evaluation result.
  kEnd        = 0x00,

  // Push constants. Immediate sign-extended into int64_t.
  kConst8     = 0x10,
  kConst16    = 0x11,
  kConst32    = 0x12,
  kConst64    = 0x13,

  // Register read by name-table index (imm: 2 bytes BE).
  kReg        = 0x20,

  // Memory reads. Pop an address; push the read value. Little-endian
  // bytes from the inferior (matches the gdb-remote `m` packet).
  kRef8       = 0x30,
  kRef16      = 0x31,
  kRef32      = 0x32,
  kRef64      = 0x33,

  // Arithmetic.
  kAdd        = 0x40,
  kSub        = 0x41,
  kMul        = 0x42,
  kDivSigned  = 0x43,

  // Comparison. Push 1 if the relation holds, else 0.
  kEq         = 0x50,
  kNe         = 0x51,
  kLtSigned   = 0x52,
  kLeSigned   = 0x53,
  kGtSigned   = 0x54,
  kGeSigned   = 0x55,

  // Bitwise.
  kBitAnd     = 0x60,
  kBitOr      = 0x61,
  kBitXor     = 0x62,
  kBitNot     = 0x63,

  // Logical (treat non-zero as true).
  kLogAnd     = 0x70,
  kLogOr      = 0x71,
  kLogNot     = 0x72,

  // Stack manipulation.
  kDup        = 0x80,
  kDrop       = 0x81,
  kSwap       = 0x82,

  // Control flow (#25 phase-3).
  //
  // Opcode-byte choice: docs/28 §2 reserves 0x90–0x9f for control
  // flow; gdb's agent-expression spec puts if_goto at 0x20 and
  // goto at 0x21, but 0x20 already maps to LDB's kReg. We can't
  // satisfy both — picking 0x90 / 0x91 keeps phase-1 / phase-2
  // bytecode wire-compatible at the cost of a translation layer
  // when #26 talks to a third-party gdb-remote agent. That layer
  // is one byte rewrite per opcode and lives in the wire driver,
  // not the VM, so it doesn't bleed into the bytecode contract.
  //
  // Both ops carry a u16 BE absolute-pc immediate. Out-of-range
  // targets (jump past code.size()) surface kBadImmediate; the
  // anti-DoS kMaxInsnCount cap catches infinite backward loops.
  kIfGoto     = 0x90,
  kGoto       = 0x91,
};

// A program is the opcode stream + the register name table that
// kReg indexes into. The encoder/decoder serialises both into a
// single byte sequence (see codec.cpp).
struct Program {
  std::vector<std::uint8_t>  code;
  std::vector<std::string>   reg_table;
};

// --- Evaluation API ---------------------------------------------------

struct EvalContext {
  backend::TargetId        target      = 0;
  backend::ThreadId        tid         = 0;
  std::uint32_t            frame_index = 0;  // 0 = innermost frame
  backend::DebuggerBackend* backend    = nullptr;  // borrowed
};

enum class EvalError {
  kOk = 0,
  kStackUnderflow,
  kStackOverflow,
  kBadOpcode,
  kBadImmediate,
  kDivByZero,
  kRegNotFound,
  kMemReadFailed,
  kProgramTooLong,      // program byte count > kMaxProgramBytes
  kInsnLimitExceeded,   // execution exceeded kMaxInsnCount
  kMissingEnd,          // program ran off code[] without an explicit kEnd
};

struct EvalResult {
  EvalError    error = EvalError::kOk;
  std::int64_t value = 0;     // top-of-stack at end (or at error point)
  std::size_t  insn_count = 0;  // ops executed; surfaced so cap-fire
                                // tests can assert the cap fired at
                                // the expected iteration (not on the
                                // first cycle from an off-by-one).
};

// Caps — anti-DoS. Phase-1 ships fixed values; phase-2 may make
// them configurable per probe.
constexpr std::size_t kMaxStackDepth  = 64;
constexpr std::size_t kMaxProgramBytes = 4 * 1024;
constexpr std::size_t kMaxInsnCount   = 10'000;

// Evaluate `prog` against `ctx`. Returns the result + any error.
// The backend pointer in ctx may be null only if the program
// makes no register/memory references; otherwise kRegNotFound /
// kMemReadFailed will fire.
EvalResult eval(const Program& prog, const EvalContext& ctx);

// --- Wire codec --------------------------------------------------------
//
// On-the-wire layout (docs/28 §2 "Wire encoding of reg"):
//
//   u32 BE  program_size
//   u8[]    opcodes...
//   u16 BE  reg_table_count
//   for each reg name:
//     u16 BE  name_len
//     u8[]    name (no NUL terminator)
//
// Decoders MUST reject programs whose declared size doesn't match
// the byte count between the size field and the start of the reg
// table — silent truncation would leave the evaluator running off
// the end of a buffer.

std::vector<std::uint8_t> encode(const Program& prog);
std::optional<Program>    decode(std::string_view bytes);

// Human-readable mnemonic for an Op. Empty string for unknown
// opcodes — the evaluator's kBadOpcode handler uses this for log
// messages.
std::string_view mnemonic(Op op);

}  // namespace ldb::agent_expr
