// SPDX-License-Identifier: Apache-2.0
#include "agent_expr/bytecode.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace ldb::agent_expr {

namespace {

// Stack-based VM state for a single eval() call.
struct VmState {
  std::array<std::int64_t, kMaxStackDepth> stack{};
  std::size_t                              sp     = 0;   // points to next free
  std::size_t                              insn   = 0;   // instruction count

  bool push(std::int64_t v, EvalError* err) {
    if (sp >= kMaxStackDepth) { *err = EvalError::kStackOverflow; return false; }
    stack[sp++] = v;
    return true;
  }

  bool pop(std::int64_t* out, EvalError* err) {
    if (sp == 0) { *err = EvalError::kStackUnderflow; return false; }
    *out = stack[--sp];
    return true;
  }

  // Result value at end-of-evaluation or error point: top of stack,
  // or 0 if stack empty. Single source of truth — no last_top
  // bookkeeping spread across opcode handlers.
  std::int64_t result() const {
    return (sp == 0) ? 0 : stack[sp - 1];
  }
};

// Read a big-endian integer of `n` bytes from code[pc] and advance pc.
// Returns false on truncated read. For n < 8 the result is sign-
// extended from the `n`-byte-wide value into int64_t; for n == 8
// the bytes are already a full int64_t and no extension is needed
// (`sign_bit << 1` would be UB at bit 64 — guard explicitly).
bool read_be(const std::vector<std::uint8_t>& code, std::size_t* pc,
             std::size_t n, std::int64_t* out) {
  if (*pc + n > code.size()) return false;
  std::int64_t v = 0;
  for (std::size_t i = 0; i < n; ++i) {
    v = (v << 8) | code[*pc + i];
  }
  *pc += n;
  if (n < 8) {
    std::int64_t sign_bit = static_cast<std::int64_t>(1) << (n * 8 - 1);
    if (v & sign_bit) {
      v |= ~((sign_bit << 1) - 1);
    }
  }
  *out = v;
  return true;
}

bool read_u16_be(const std::vector<std::uint8_t>& code, std::size_t* pc,
                 std::uint16_t* out) {
  if (*pc + 2 > code.size()) return false;
  *out = static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(code[*pc]) << 8) | code[*pc + 1]);
  *pc += 2;
  return true;
}

// Decode `n` little-endian bytes into an int64_t (zero-extended).
std::int64_t decode_le(const std::vector<std::uint8_t>& bytes, std::size_t n) {
  std::int64_t v = 0;
  for (std::size_t i = 0; i < n; ++i) {
    v |= static_cast<std::int64_t>(bytes[i]) << (i * 8);
  }
  return v;
}

EvalError do_binop(VmState* vm, Op op) {
  std::int64_t b = 0, a = 0;
  EvalError err = EvalError::kOk;
  if (!vm->pop(&b, &err)) return err;
  if (!vm->pop(&a, &err)) return err;
  std::int64_t r = 0;
  switch (op) {
    case Op::kAdd:       r = a + b; break;
    case Op::kSub:       r = a - b; break;
    case Op::kMul:       r = a * b; break;
    case Op::kDivSigned:
      if (b == 0) return EvalError::kDivByZero;
      r = a / b; break;
    case Op::kEq:        r = (a == b) ? 1 : 0; break;
    case Op::kNe:        r = (a != b) ? 1 : 0; break;
    case Op::kLtSigned:  r = (a <  b) ? 1 : 0; break;
    case Op::kLeSigned:  r = (a <= b) ? 1 : 0; break;
    case Op::kGtSigned:  r = (a >  b) ? 1 : 0; break;
    case Op::kGeSigned:  r = (a >= b) ? 1 : 0; break;
    case Op::kBitAnd:    r = a & b; break;
    case Op::kBitOr:     r = a | b; break;
    case Op::kBitXor:    r = a ^ b; break;
    case Op::kLogAnd:    r = (a && b) ? 1 : 0; break;
    case Op::kLogOr:     r = (a || b) ? 1 : 0; break;
    default:             return EvalError::kBadOpcode;
  }
  if (!vm->push(r, &err)) return err;
  return EvalError::kOk;
}

EvalError do_unop(VmState* vm, Op op) {
  std::int64_t a = 0;
  EvalError err = EvalError::kOk;
  if (!vm->pop(&a, &err)) return err;
  std::int64_t r = 0;
  switch (op) {
    case Op::kBitNot: r = ~a; break;
    case Op::kLogNot: r = (a == 0) ? 1 : 0; break;
    default:          return EvalError::kBadOpcode;
  }
  if (!vm->push(r, &err)) return err;
  return EvalError::kOk;
}

EvalError do_ref(const Program& prog, std::size_t* pc, std::size_t bytes,
                  VmState* vm, const EvalContext& ctx) {
  (void)prog; (void)pc;
  std::int64_t addr = 0;
  EvalError err = EvalError::kOk;
  if (!vm->pop(&addr, &err)) return err;
  if (ctx.backend == nullptr) return EvalError::kMemReadFailed;
  std::vector<std::uint8_t> data;
  try {
    data = ctx.backend->read_memory(ctx.target,
        static_cast<std::uint64_t>(addr), bytes);
  } catch (const backend::Error&) {
    // Only swallow documented backend errors (bad address, EAGAIN
    // on detach, etc.). std::bad_alloc and other system failures
    // propagate — the evaluator can't recover from those.
    return EvalError::kMemReadFailed;
  }
  if (data.size() < bytes) return EvalError::kMemReadFailed;
  if (!vm->push(decode_le(data, bytes), &err)) return err;
  return EvalError::kOk;
}

}  // namespace

EvalResult eval(const Program& prog, const EvalContext& ctx) {
  EvalResult out;
  if (prog.code.size() > kMaxProgramBytes) {
    out.error = EvalError::kProgramTooLong;
    return out;
  }

  VmState vm;
  std::size_t pc = 0;
  while (pc < prog.code.size()) {
    if (++vm.insn > kMaxInsnCount) {
      out.error = EvalError::kInsnLimitExceeded;
      out.value = vm.result();
      out.insn_count = vm.insn - 1;   // count of ops actually executed
                                       // (the increment that tripped the
                                       // cap didn't dispatch an op)
      return out;
    }
    auto op = static_cast<Op>(prog.code[pc++]);
    EvalError step = EvalError::kOk;
    switch (op) {
      case Op::kEnd:
        out.value = vm.result();
        out.insn_count = vm.insn;
        return out;

      case Op::kConst8: {
        std::int64_t v = 0;
        if (!read_be(prog.code, &pc, 1, &v)) { step = EvalError::kBadImmediate; break; }
        if (!vm.push(v, &step))               break;
        break;
      }
      case Op::kConst16: {
        std::int64_t v = 0;
        if (!read_be(prog.code, &pc, 2, &v)) { step = EvalError::kBadImmediate; break; }
        if (!vm.push(v, &step))               break;
        break;
      }
      case Op::kConst32: {
        std::int64_t v = 0;
        if (!read_be(prog.code, &pc, 4, &v)) { step = EvalError::kBadImmediate; break; }
        if (!vm.push(v, &step))               break;
        break;
      }
      case Op::kConst64: {
        std::int64_t v = 0;
        if (!read_be(prog.code, &pc, 8, &v)) { step = EvalError::kBadImmediate; break; }
        if (!vm.push(v, &step))               break;
        break;
      }

      case Op::kReg: {
        std::uint16_t idx = 0;
        if (!read_u16_be(prog.code, &pc, &idx)) {
          step = EvalError::kBadImmediate; break;
        }
        if (idx >= prog.reg_table.size()) { step = EvalError::kRegNotFound; break; }
        if (ctx.backend == nullptr)        { step = EvalError::kRegNotFound; break; }
        std::uint64_t v = ctx.backend->read_register(
            ctx.target, ctx.tid, ctx.frame_index,
            prog.reg_table[idx]);
        if (!vm.push(static_cast<std::int64_t>(v), &step)) break;
        break;
      }

      case Op::kRef8:  step = do_ref(prog, &pc, 1, &vm, ctx); break;
      case Op::kRef16: step = do_ref(prog, &pc, 2, &vm, ctx); break;
      case Op::kRef32: step = do_ref(prog, &pc, 4, &vm, ctx); break;
      case Op::kRef64: step = do_ref(prog, &pc, 8, &vm, ctx); break;

      case Op::kAdd: case Op::kSub: case Op::kMul: case Op::kDivSigned:
      case Op::kEq:  case Op::kNe:
      case Op::kLtSigned: case Op::kLeSigned:
      case Op::kGtSigned: case Op::kGeSigned:
      case Op::kBitAnd:   case Op::kBitOr:   case Op::kBitXor:
      case Op::kLogAnd:   case Op::kLogOr:
        step = do_binop(&vm, op);
        break;

      case Op::kBitNot:
      case Op::kLogNot:
        step = do_unop(&vm, op);
        break;

      case Op::kDup: {
        if (vm.sp == 0) { step = EvalError::kStackUnderflow; break; }
        if (!vm.push(vm.stack[vm.sp - 1], &step)) break;
        break;
      }
      case Op::kDrop: {
        std::int64_t tmp;
        if (!vm.pop(&tmp, &step)) break;
        break;
      }
      case Op::kSwap: {
        if (vm.sp < 2) { step = EvalError::kStackUnderflow; break; }
        std::swap(vm.stack[vm.sp - 1], vm.stack[vm.sp - 2]);
        break;
      }

      // Control flow (#25 phase-3). Both ops carry a u16 BE absolute
      // pc immediate. A target past code.size() is malformed bytecode
      // — surface kBadImmediate so callers learn to validate jump
      // targets before installing the predicate. Anti-loop sanity
      // for backward jumps comes from kMaxInsnCount above.
      // Invariant: always validate immediates regardless of whether
      // the transfer is taken. An out-of-range target is malformed
      // bytecode at decode time — if we only check on the taken path,
      // a predicate with a broken jump silently passes when cond
      // happens to be zero and crashes the next time cond is truthy.
      // Six-months-later production bug pattern. Don't reintroduce.
      case Op::kGoto: {
        std::uint16_t target = 0;
        if (!read_u16_be(prog.code, &pc, &target)) {
          step = EvalError::kBadImmediate; break;
        }
        if (target > prog.code.size()) {
          step = EvalError::kBadImmediate; break;
        }
        pc = target;
        break;
      }
      case Op::kIfGoto: {
        std::uint16_t target = 0;
        if (!read_u16_be(prog.code, &pc, &target)) {
          step = EvalError::kBadImmediate; break;
        }
        if (target > prog.code.size()) {
          step = EvalError::kBadImmediate; break;
        }
        std::int64_t cond = 0;
        if (!vm.pop(&cond, &step)) break;
        if (cond != 0) {
          pc = target;
        }
        break;
      }

      default:
        step = EvalError::kBadOpcode;
        break;
    }
    if (step != EvalError::kOk) {
      out.error = step;
      out.value = vm.result();
      out.insn_count = vm.insn;
      return out;
    }
  }
  // Ran off the end without an explicit kEnd. A program without kEnd
  // is malformed — silently completing risks firing a probe whose
  // predicate truncated mid-stream. Surface the distinct error so
  // callers know to validate their bytecode.
  out.error = EvalError::kMissingEnd;
  out.value = vm.result();
  out.insn_count = vm.insn;
  return out;
}

}  // namespace ldb::agent_expr
