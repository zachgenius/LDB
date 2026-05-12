# Agent expressions — daemon-side VM

Post-V1 #25 (per docs/15-post-v1-plan.md, scheduled in v1.6 per
docs/17-version-plan.md). The non-stop chain's third item, following
#17 (own RSP) and #21 (non-stop runtime).

## TL;DR

- **Agent expressions** are tiny stack-based bytecode programs used
  to filter probe / breakpoint events. An agent compiles a predicate
  ("only stop here when `errno != 0` AND `pid == 1234`") into bytecode;
  the evaluator runs it at each hit and decides whether to fire the
  event upstream. The same bytecode powers conditional tracepoints
  (#26).
- **Phase-1 ships the bytecode + evaluator only**, daemon-side. No
  probe wiring, no compiler, no in-target injection. The VM reads
  registers + memory through the existing `DebuggerBackend` API.
- **Phase-2 wires it into `probe.create`** as an optional `predicate`
  field; probes evaluate it on each hit and only emit events when
  the result is non-zero. This is the agent-facing endpoint change.
- **Phase-3 (#26 territory) pushes the bytecode in-target.** GDB's
  agent injects a small VM into the inferior so predicates run at
  the breakpoint without round-tripping to the debugger. Phase-3
  reuses the same bytecode format defined here.

## 1. Why a bytecode VM at all

The alternative — a string-based expression language evaluated by a
parser — has real costs at the points where predicates matter most:

- **Tracepoints fire often.** A predicate that runs 10,000 times a
  second on a hot path can't afford a re-parse per hit. Bytecode +
  small VM = decode-once, evaluate-many.
- **In-target injection is the endgame.** Phase-3 ships the bytecode
  through the gdb-remote `qTBuffer` family into the inferior; the
  agent in the inferior evaluates without ever returning to the
  debugger. A string-AST won't pack the wire side.
- **GDB already speaks this.** The format is a small subset of GDB's
  agent expression bytecode (gdb manual §28 "Tracepoint Conditions").
  We deliberately don't extend it — interop with existing tooling is
  load-bearing for #26's gdb-remote tracepoint variant.

## 2. The bytecode

Stack of signed 64-bit integers. Programs run to completion or hit
an error; the final result is the top of stack at `end`.

```
Opcode  Mnemonic     Stack effect       Notes
------  -----------  -----------------  -----------------------------
0x00    end          —                  Halt; top-of-stack is result.
0x10    const8       — → push v         Imm: 1 byte signed
0x11    const16      — → push v         Imm: 2 bytes BE signed
0x12    const32      — → push v         Imm: 4 bytes BE signed
0x13    const64      — → push v         Imm: 8 bytes BE signed
0x20    reg          — → push r         Imm: 2 bytes BE = reg-name-table idx
0x30    ref8         a → m              Read 1 byte at *a (zero-extended)
0x31    ref16        a → m              Read 2 bytes LE at *a
0x32    ref32        a → m              Read 4 bytes LE at *a
0x33    ref64        a → m              Read 8 bytes LE at *a
0x40    add          b a → a+b
0x41    sub          b a → a-b
0x42    mul          b a → a*b
0x43    div_signed   b a → a/b          Div-by-zero → eval error
0x50    eq           b a → 1 if a==b
0x51    ne           b a → 1 if a!=b
0x52    lt_signed    b a → 1 if a<b
0x53    le_signed    b a → 1 if a<=b
0x54    gt_signed    b a → 1 if a>b
0x55    ge_signed    b a → 1 if a>=b
0x60    bit_and      b a → a&b
0x61    bit_or       b a → a|b
0x62    bit_xor      b a → a^b
0x63    bit_not      a → ~a
0x70    log_and      b a → 1 if a&&b
0x71    log_or       b a → 1 if a||b
0x72    log_not      a → 1 if a==0
0x80    dup          a → a a
0x81    drop         a →
0x82    swap         b a → a b
0x90    if_goto      a →                 Imm: 2 bytes BE absolute pc; jump if a != 0
0x91    goto         —                   Imm: 2 bytes BE absolute pc; unconditional
```

Reserved space:
- `0x92–0x9f` — remaining control flow (call/ret). Phase-3+ territory.
- `0xa0–0xaf` — string ops (cstr_read). Phase-2 if probes ask for it.
- `0xb0–0xbf` — float ops. Deferred; agent predicates today are int.

### Control-flow opcode bytes vs gdb

GDB's agent-expression spec puts `if_goto` at 0x20 and `goto` at 0x21,
but 0x20 is already `kReg` in LDB's table. We can't match gdb's bytes
for both at once. Picked 0x90 / 0x91 from the docs/28 reserved
`0x90–0x9f` control-flow range so phase-1 / phase-2 bytecode stays
wire-compatible. When #26's gdb-remote tracepoint variant talks to
a third-party agent, the wire driver rewrites these two bytes —
one-byte translation isolated from the VM contract.

The compiler (docs/29 §1 "Control flow") exposes these as the
`(if cond then else)` and `(when cond body)` special forms; agents
never need to emit raw `if_goto` / `goto` themselves.

### Wire encoding of `reg`

A program carries an inline **register name table** as a length-
prefixed list of strings, separate from the opcode stream. The
`reg` opcode takes a 16-bit index into the table. This lets the
evaluator look up a register by name through the backend's
`read_register(target, tid, frame, name)` without baking
architecture-specific reg-number-to-name maps into the bytecode.

A `Program` is:

```
[u32 BE] program_size        # bytes in opcodes[]
[opcodes ...]                # the bytecode stream

[u16 BE] reg_table_count
for each reg:
  [u16 BE] name_len
  [name_len bytes] name      # UTF-8 (typically ASCII)
```

Phase-3's in-target VM ignores the reg table — it uses GDB's
DWARF-numbered reg opcodes directly. Phase-1 + phase-2 are
daemon-side and benefit from the name indirection.

## 3. Evaluator API

```cpp
namespace ldb::agent_expr {

struct Program {
  std::vector<std::uint8_t>  code;
  std::vector<std::string>   reg_table;
};

struct EvalContext {
  backend::TargetId    target;
  backend::ThreadId    tid;
  std::uint32_t        frame_index = 0;  // typically 0 (innermost)
  backend::DebuggerBackend* backend = nullptr;
};

enum class EvalError {
  kOk,
  kStackUnderflow,
  kStackOverflow,
  kBadOpcode,
  kBadImmediate,
  kDivByZero,
  kRegNotFound,
  kMemReadFailed,
  kProgramTooLong,
};

struct EvalResult {
  EvalError    error = EvalError::kOk;
  std::int64_t value = 0;            // top-of-stack at end
};

EvalResult eval(const Program& prog, const EvalContext& ctx);

// Wire codec — used by phase-2's probe.create predicate parsing.
std::vector<std::uint8_t> encode(const Program& prog);
std::optional<Program>    decode(std::string_view bytes);

}  // namespace ldb::agent_expr
```

The evaluator:
- Caps the stack at 64 entries (`kMaxStackDepth`). Programs that
  try to push deeper hit `kStackOverflow`. Anti-DoS.
- Caps program size at 4 KiB (`kMaxProgramBytes`). Larger programs
  decode to `kProgramTooLong` (codec-time AND eval-time guards).
- Caps execution at 10,000 instructions (`kMaxInsnCount`). Runaway
  programs hit `kInsnLimitExceeded` — distinct from
  `kProgramTooLong` so agents can tell a too-big bytecode from a
  too-many-cycles execution (matters once phase-3 adds loops).
- A program that runs off the end of `code[]` without an explicit
  `kEnd` surfaces `kMissingEnd` rather than silently returning the
  top of stack — a truncated bytecode shouldn't masquerade as a
  valid predicate result.
- Returns 0 for the result if the stack is empty at `end` (a
  predicate with no value is false, by convention).

### Why daemon-side first

Reading registers + memory via `DebuggerBackend` calls into LLDB or
RspChannel. That's the production path; the in-target VM is
phase-3. Daemon-side phase-1 proves the bytecode contract + lets us
build a compiler against it without dealing with the gdb-remote
agent wire protocol simultaneously.

## 4. Failure modes

| Condition | Behaviour |
|---|---|
| Stack underflow (binary op on <2 entries) | `EvalError::kStackUnderflow`; value is whatever was at index 0 if any |
| Bad opcode (unknown byte) | `EvalError::kBadOpcode` |
| Truncated immediate (e.g. `const32` with <4 trailing bytes) | `EvalError::kBadImmediate` |
| `reg` index out of table bounds | `EvalError::kRegNotFound` |
| `read_register` returns 0 for an unknown name | Treated as zero (matches existing backend contract); no error |
| `read_memory` throws | `EvalError::kMemReadFailed` |
| Division by zero | `EvalError::kDivByZero` |
| Program byte count > kMaxProgramBytes | `EvalError::kProgramTooLong` |
| Execution exceeds kMaxInsnCount cycles | `EvalError::kInsnLimitExceeded` |
| Program runs off code[] without kEnd | `EvalError::kMissingEnd` |
| `if_goto` / `goto` target > code.size() | `EvalError::kBadImmediate` — phase-3 anti-mis-jump guard |
| `if_goto` with empty stack | `EvalError::kStackUnderflow` |

Errors stop execution; `EvalResult::value` carries whatever was on
the top of stack at the error point (useful for debugging the
predicate, not for branching on).

## 5. What this unblocks

- **Phase-2** wires the evaluator into `probe.create` as an optional
  `predicate` field (base64-encoded bytecode). The probe orchestrator
  calls `eval` on each hit; non-zero result fires the event upstream.
- **Phase-3 / #26** ships the same bytecode through the gdb-remote
  `QTDP` tracepoint family for in-target evaluation. No bytecode
  format changes; the evaluator just runs in the inferior instead
  of the daemon.
- **A small predicate compiler** (S-expressions → bytecode) can land
  as its own commit alongside phase-2. The DSL is agent-facing
  ergonomics, the bytecode is the contract.

## 6. Phase scoping

### Phase-1 (this PR's territory)

- `src/agent_expr/bytecode.h` — opcodes + Program struct + codec
  signatures.
- `src/agent_expr/evaluator.{h,cpp}` — VM + eval API.
- `src/agent_expr/codec.cpp` — encode / decode wire format.
- `tests/unit/test_agent_expr_evaluator.cpp` — opcode coverage,
  failure modes, cap enforcement.
- `tests/unit/test_agent_expr_codec.cpp` — encode/decode roundtrip,
  malformed-input handling.

### Phase-2 (separate commit)

- A simple S-expression compiler: `(eq (reg "rax") (const 42))` →
  bytecode. Lives next to the evaluator.
- `probe.create` extension: optional `predicate` field carrying
  the source S-expression OR base64-encoded bytecode. Probe
  orchestrator stores it + evaluates on hit.
- New endpoint `predicate.compile` so agents can pre-compile +
  validate ahead of probe creation.

### Phase-3 — landed in #25 phase-3

Control-flow opcodes (`if_goto` at 0x90, `goto` at 0x91) were added
ahead of the in-target VM so #26 phase-2's tracepoints can compile
predicates with branches:

- `Op::kIfGoto` / `Op::kGoto` in `src/agent_expr/bytecode.h`.
- Evaluator handlers with a u16-BE absolute-pc immediate; out-of-
  range targets surface `kBadImmediate`; backward jumps are caught
  by the existing `kMaxInsnCount` anti-loop cap.
- Compiler grows `(if cond then else)` and `(when cond body)`
  special forms (docs/29 §1). Forms emit in source order via an
  `if-not-cond, jump to else` layout — single-pass codegen
  doesn't need a back-buffer for the then-branch.

### Phase-3 / #26 (still ahead)

- gdb-remote agent injection: `QTDP` packet support, in-target VM
  via the RspChannel.
- The bytecode format is unchanged; the wire push is the new bit.
  The one-byte mismatch between LDB's 0x90/0x91 and gdb's 0x20/0x21
  for if_goto/goto is translated in the wire driver, not the VM.
