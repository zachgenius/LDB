# Predicate compiler + probe wiring

Post-V1 #25 phase-2. Companion to `docs/28-agent-expressions.md`,
which shipped the bytecode VM. Phase-1 left the VM with no
callers — this phase makes it useful by adding an S-expression
surface, a `predicate.compile` endpoint, and probe-orchestrator
integration so probes can filter on per-hit predicates.

## TL;DR

- **An S-expression DSL** is the agent-facing predicate syntax —
  `(eq (reg "rax") (const 42))`. Compiles to the existing agent_expr
  bytecode. Single-pass recursive-descent parser → AST → bytecode in
  one walk. No optimisation pass — predicates are tiny and the VM
  is already fast.
- **`predicate.compile`** is a new RPC endpoint. Takes a source
  string, returns base64-encoded bytecode + a parsed mnemonic
  listing (for debugging / agent introspection) + the reg name table.
  Validates without executing; lets agents pre-flight a predicate
  ahead of probe creation.
- **`probe.create` gains an optional `predicate` field**. Two shapes
  accepted: `{source: "<sexpr>"}` (compiled by the dispatcher) or
  `{bytecode_b64: "..."}` (already-compiled, passed through). The
  probe orchestrator stores the `Program` in its `ProbeState` and
  evaluates it on each hit. A zero result drops the event; non-zero
  passes through to the existing ring buffer / artifact pipeline.
- **No changes to the bytecode**. The phase-1 VM is exactly the
  payload. Phase-3 (#26) ships the same bytecode in-target via
  `QTDP` without touching the compiler or the VM.

## 1. S-expression DSL

The minimal surface that maps 1:1 onto the phase-1 opcode table:

```
expr := atom | list
atom := <integer> | <reg-string>
list := ( <op> <expr>* )
```

Reg references are bare strings inside `(reg ...)` — the compiler
collects them into the program's `reg_table`. Numeric literals are
decimal or `0x`-prefixed hex; negative literals work (`(const -1)`).

Op names mirror the bytecode mnemonics (`docs/28-agent-expressions.md`
§2):

```
(const <int>)           → const8/16/32/64 (smallest that fits, signed)
(reg "<name>")          → kReg with name added to reg_table
(ref8  <addr-expr>)     → kRef8   (also ref16, ref32, ref64)
(add <a> <b>)           → kAdd    (also sub, mul, div)
(eq <a> <b>)            → kEq     (also ne, lt, le, gt, ge — signed)
(and <a> <b>)           → kBitAnd (also or, xor; "land"/"lor"/"lnot" = logical)
(not <a>)               → kBitNot (logical: "lnot")
```

`(begin <e1> <e2> ... <eN>)` evaluates each in order, dropping every
result except the last — the conventional Lisp-y sequence form, and
the only way to get drop/swap behaviour without the user emitting
raw bytecode.

### Control flow (#25 phase-3)

```
(if <cond> <then> <else>)   → kIfGoto + kGoto with patched targets
(when <cond> <body>)        → sugar for (if cond body 0)
```

Both `<then>` and `<else>` are full expressions; the unchosen branch
is *not* evaluated (short-circuiting). This matters for predicates
that would otherwise divide by zero or read unmapped memory on the
"wrong" side:

```
;; Read errno only when the syscall actually returned -1
(when (eq (reg "rax") -1)
  (ref32 (reg "rdi")))

;; Filter for the slow path: stop only if the cache miss flag is set
;; AND the request-size register is above the threshold.
(if (eq (ref8 (reg "rbx")) 1)
    (gt (reg "rsi") 4096)
    0)
```

Emission layout for `(if c t e)` is "if-not-cond, jump to else"
rather than gdb's "if-cond, jump over then" — see
`src/agent_expr/compiler.cpp`'s `if` handler for the single-pass
codegen rationale. Agents who care about the exact bytecode shape
should fetch `mnemonics[]` from the `predicate.compile` response.

### Single-op convenience

Bare register references and literals at top level are equivalent
to `(reg "name")` / `(const N)` — the compiler inserts the obvious
wrap. So `42` and `(const 42)` compile identically; `rax` parses as
an error (we never silently interpret bare identifiers as registers
to avoid agents accidentally referring to mistyped names).

### Examples

```
;; Always true (the simplest predicate: a non-zero const)
1

;; Stop only when errno != 0
(ne (ref32 (reg "rax")) (const 0))

;; Pid filter
(eq (reg "fs_base") (const 0x1234))

;; Combined: errno nonzero AND pid matches
(land
  (ne (ref32 (reg "rax")) (const 0))
  (eq (reg "fs_base") (const 0x1234)))
```

## 2. Compiler architecture

`src/agent_expr/compiler.{h,cpp}`:

```cpp
struct CompileError {
  std::size_t  line   = 0;     // 1-based
  std::size_t  column = 0;     // 1-based
  std::string  message;
};

struct CompileResult {
  std::optional<Program>       program;
  std::optional<CompileError>  error;
};

CompileResult compile(std::string_view source);
```

Single-pass recursive descent. Tokeniser yields:
`Lparen`, `Rparen`, `Integer(value)`, `Symbol(name)`, `String(value)`,
`Eof`. The parser builds the AST as it tokenises (small enough
predicates that there's no win to a separate phase). Each AST node
is one of: `Const(int64)`, `RegRef(name_in_table)`, `Call(op, args)`,
`Begin(forms)`.

Code generation walks the AST post-order, emitting bytecode for
operands before the op byte. `(eq A B)` → emit(A) emit(B) kEq. For
`begin`, every expression except the last gets a trailing kDrop.

The reg_table is built lazily: each new register name in a `(reg
"name")` expression appends to the table and the index is emitted.
Repeated `(reg "rax")` references re-use the same index.

### Const sizing

`(const N)` picks the narrowest opcode that holds N as a signed
integer: -128..127 → kConst8, -32768..32767 → kConst16, etc. This
saves bytes on the wire for the common small-int case and matches
GDB's spec (gdb emits the same widening rule).

**The VM is signed-int64 throughout.** `kLtSigned` / `kGeSigned` /
etc. compare signed; there is no unsigned-compare opcode in the
phase-1 table. Agents that need unsigned semantics on byte / word
values should mask explicitly:

```
;; Test high bit of a byte: unsigned would be `(ge byte 0x80)`,
;; signed must be `(eq (and byte 0x80) 0x80)`.
(eq (and (ref8 (reg "rax")) 0x80) 0x80)
```

### Register-name resolution

`(reg "name")` looks up by name at eval time through
`backend::read_register`, which returns 0 for unknown register
names (the backend's existing "captured-as-zero" contract — see
`docs/02-ldb-mvp-plan.md`). A typo in a register name therefore
silently evaluates to 0 in the predicate, which may produce a
predicate that's always-true or always-false depending on the
surrounding comparison. **Validate register names against the
target's actual register table** (via `frame.registers` or
similar) before pinning a predicate on a probe.

### Error reporting

Tokeniser tracks (line, column) per token. Every parser/codegen
error carries that anchor. Common cases:

- `(unknown-op a b)` → "unknown opcode 'unknown-op'"
- `(eq 1)` → "eq expects 2 arguments, got 1"
- `(reg "")` → "reg name must be non-empty"
- Unbalanced parens → "expected ')'"
- Bare identifier → "unexpected identifier 'rax' — wrap registers in (reg \"rax\")"

## 3. `predicate.compile` endpoint

```jsonc
// Request
{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "predicate.compile",
  "params": {
    "source": "(ne (ref32 (reg \"rax\")) (const 0))"
  }
}

// Success response
{
  "id": "1",
  "ok": true,
  "data": {
    "bytecode_b64": "AAAA…",
    "bytes":        17,
    "mnemonics":    ["reg 0", "ref32", "const8 0", "ne", "end"],
    "reg_table":    ["rax"]
  }
}

// Error response (invalid params or compile error)
{
  "id": "1",
  "ok": false,
  "error": {
    "code": -32602,
    "message": "compile error at 1:5: unknown opcode 'unknown'"
  }
}
```

Compile-time errors are surfaced as `-32602 kInvalidParams` with the
line:column anchor baked into `message`. Empty source is allowed —
it compiles to just `kEnd`, which evaluates to 0 (the "always
false" predicate). The dispatcher rejects oversize source
(`> kMaxSourceBytes` = 16 KiB) at -32602 before even tokenising.

## 4. `probe.create` predicate field

`probe.create` accepts an optional top-level `predicate` field:

```jsonc
"predicate": {
  // Exactly one of:
  "source":       "(...)",
  "bytecode_b64": "AAAA..."
}
```

- `source` is compiled at probe-create time. Compile errors fail
  the create with `-32602`.
- `bytecode_b64` is decoded + validated (the existing codec). Bad
  base64 or malformed bytecode also fails `-32602`.
- Both forms are stored as `Program` in `ProbeState`.
- On each breakpoint hit, the orchestrator calls
  `agent_expr::eval(program, ctx)` with the existing event context
  (target_id, tid, frame=0, backend). Non-zero result → emit event
  as today. Zero result → silently drop the event AND auto-continue
  the inferior (action ignored — predicate-filtered probes never
  stop).
- Eval errors (kStackUnderflow, kMemReadFailed, …) are logged to
  stderr and the event is dropped (treated as "predicate didn't
  match"). The probe's `hit_count` still increments — agents need
  to know that the breakpoint fired and the predicate filtered it.

The orchestrator's `ListEntry` grows two new optional fields:
`predicate_bytes` (non-zero when a predicate is attached) and
`predicate_dropped` (per-probe count of events filtered out). These
let agents reason about filter rates from `probe.list` alone.

## 5. Failure modes (delta from docs/28 §4)

| Condition | Behaviour |
|---|---|
| Empty `predicate` object | -32602 kInvalidParams ("predicate must set source or bytecode_b64") |
| Both `source` and `bytecode_b64` set | -32602 ("predicate must set exactly one of source / bytecode_b64") |
| `source` parse error | -32602 with line:column anchor |
| `bytecode_b64` not valid base64 | -32602 ("predicate.bytecode_b64: invalid base64") |
| `bytecode_b64` decodes to malformed program | -32602 ("predicate.bytecode_b64: malformed bytecode") |
| Predicate eval error at hit time | log to stderr, drop event, increment hit_count + predicate_dropped |
| Predicate result == 0 at hit time | drop event, auto-continue, increment hit_count + predicate_dropped |
| Predicate on `uprobe_bpf` / `agent` probe | -32602 ("predicate is only supported for kind='lldb_breakpoint'") — phase-2 doesn't push bytecode into BPF / agent paths |

## 6. Phase scoping

### Phase-2 (this PR's territory)

- `src/agent_expr/compiler.{h,cpp}` — S-expression parser + AST +
  bytecode emitter. Single-pass; no separate optimization phase.
- `predicate.compile` endpoint.
- `probe.create` extension: optional `predicate` field with the
  source-or-bytecode shape.
- ProbeOrchestrator: store `Program` per probe; evaluate on hit;
  drop event on zero result; track `predicate_dropped` count.
- Unit tests for the compiler (parser cases + codegen) and the
  dispatcher endpoint (wire shape, compile error mapping).
- Integration test for probe + predicate via the existing live
  breakpoint smoke (a probe that fires only when a captured
  register matches a value).

### Phase-3 — landed in #25 phase-3

Control-flow forms (`(if ...)`, `(when ...)`) compile to the
`kIfGoto` + `kGoto` opcodes (`docs/28-agent-expressions.md` §2).
Required by #26 phase-2's in-target VM for efficient predicate
short-circuiting — the alternative was to round-trip each branch
through the VM as a separate program.

- `src/agent_expr/compiler.cpp` grows two special-form handlers
  (`if`, `when`) that emit `kLogNot` + `kIfGoto` + `kGoto` with
  back-patched u16 BE targets.
- Tests cover short-circuit behaviour (the unchosen branch's
  `(div 1 0)` does not execute), nested `(if (if ...) ...)`
  codegen, and arity-error anchoring.

### Phase-3 / #26 (still ahead)

- gdb-remote tracepoint vocabulary (`QTDP`, `QTStart`, etc.). Same
  bytecode format flows over the wire to an in-target VM.
- Tracepoints are no-stop probes — they emit data continuously
  without stopping the inferior. Builds on the listener
  notification surface from #21 phase-2.
- `call` opcode (still reserved at 0x92–0x9f) for in-target
  function dispatch; deferred until an actual use case lands.
