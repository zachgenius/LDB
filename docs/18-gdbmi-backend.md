# GDB/MI Backend

Post-V1 plan #8 — second `DebuggerBackend` implementation, targeting
full parity with `LldbBackend` on the methods that have a natural MI
equivalent. The primary goal is **abstraction validation**, not
production parity: every place where LldbBackend leaks LLDB-isms
through the interface should surface here as either a clean port or
an explicit documented gap. Bugs in `DebuggerBackend.h` are easier
to fix when a second backend forces them visible.

Per `docs/17-version-plan.md` v1.4, this is the load-bearing first
item — it lands before any Tier-3 backend rewrites (own DWARF
reader, own RSP client, own ptrace driver) so we don't discover the
abstraction is wrong after months of those.

## Scope decision

v1.4 GdbMiBackend implements **every** virtual on `DebuggerBackend`
(49 of them) — methods with no MI equivalent throw
`backend::Error("not supported on GdbMiBackend")`, which the
dispatcher already maps to `-32003` forbidden via the existing
error-code path. The breakdown:

| Category | Methods | MI support |
|---|---|---|
| **Target/process lifecycle** | `open_executable`, `create_empty_target`, `attach`, `detach_process`, `launch_process`, `kill_process`, `close_target`, `load_core`, `connect_remote_target`, `connect_remote_target_ssh`, `save_core`, `list_targets`, `label_target`, `get_target_label` | full — MI has `-file-exec-and-symbols`, `-target-attach`, `-target-detach`, `-exec-run`, `-target-select`, `-target-disconnect`, `-gdb-exit`. Label is a daemon-side map (same as LldbBackend). |
| **Static analysis** | `list_modules`, `find_type_layout`, `find_symbols`, `find_globals_of_type`, `find_strings`, `disassemble_range`, `xref_address`, `find_string_xrefs` | full — `-file-list-shared-libraries`, `info types`, `-symbol-info-functions`, `-symbol-info-variables`, `info strings`, `-data-disassemble`. xref/string-xref piggyback on disasm output. |
| **Process control** | `continue_process`, `continue_thread`, `step_thread`, `reverse_continue`, `reverse_step_thread`, `get_process_state` | full — `-exec-continue`, `-exec-continue --thread`, `-exec-step`/`-exec-next`/`-exec-finish`, `-exec-reverse-*`. State derived from async stop records. |
| **Threads / frames / values** | `list_threads`, `list_frames`, `list_locals`, `list_args`, `list_registers`, `evaluate_expression`, `read_value_path`, `read_register` | full — `-thread-info`, `-stack-list-frames`, `-stack-list-locals`, `-stack-list-arguments`, `-data-list-register-values`, `-data-evaluate-expression`. |
| **Memory** | `read_memory`, `read_cstring`, `list_regions`, `search_memory` | full — `-data-read-memory-bytes`, `info proc mappings`, `find` command. |
| **Breakpoints** | `create_breakpoint`, `set_breakpoint_callback`, `disable_breakpoint`, `enable_breakpoint`, `delete_breakpoint` | full — `-break-insert`, `-break-disable`, `-break-enable`, `-break-delete`. Callbacks fire on `*stopped,reason="breakpoint-hit"` async records. |
| **Daemon-construct surface** | `attach_target_resource`, `snapshot_for_target` | full — same daemon-side state as LldbBackend; no MI calls involved. |

No methods are unimplemented in v1.4. Where MI is materially worse
than SBAPI (rich SBValue introspection, type-info-by-name with full
DWARF detail, etc.) the implementation accepts coarser results
rather than throwing — documented per-method below.

## MI protocol primer

GDB/MI (`gdb --interpreter=mi3`) is a line-based, two-channel
protocol. Each line is one of:

| Prefix | Kind | Example |
|---|---|---|
| `^` | result record | `^done,bkpt={number="1",...}` |
| `*` | exec-async record | `*stopped,reason="breakpoint-hit",thread-id="1",...` |
| `+` | status-async record | `+download,{...}` (rare; mostly remote progress) |
| `=` | notify-async record | `=thread-group-added,id="i1"` |
| `~` | console-stream | `~"prompt output...\n"` (informational) |
| `&` | log-stream | `&"warning text\n"` (gdb's own warnings) |
| `@` | target-stream | inferior's stdout (rare in our flows) |
| `(gdb)` | prompt | terminator after each result+async batch |

Commands are issued as either:
- **MI commands** with a leading dash: `-break-insert main`, optionally
  with a token: `42-break-insert main`. Tokens echo on the result
  record (`42^done,...`) so an async-out-of-order multiplexer can
  pair responses with requests.
- **CLI fall-through**: bare gdb commands (`info proc mappings`,
  `find 0x... ...`). Output appears as `~"..."` console-stream
  records terminated by `^done`. We use this for commands MI
  doesn't expose — bounded use.

Values inside MI records are `name=value` pairs; `value` is one of:
- C-style quoted string: `"foo bar"`, with escapes `\"` `\\` `\n` `\t`.
- Tuple (object): `{a="1",b="2"}` (curly braces, comma-separated).
- List (array): `[v1,v2]` or `[a="1",a="2"]` (named-element variant
  appears in some commands' output — keep parser lenient).

## Subprocess lifecycle

`GdbMiBackend` ctor spawns one `gdb --interpreter=mi3 --quiet
--nx --silent` process per backend instance:

- `--interpreter=mi3` selects the current MI dialect.
- `--quiet` / `--silent` suppress the startup banner that streams as
  `~"..."` console records on every spawn (annoying, no value).
- `--nx` skips user `.gdbinit` — the daemon's command flow is
  reproducible regardless of operator settings.

The child's stdin / stdout / stderr are pipes. A dedicated reader
thread drains stdout line-by-line into a queue indexed by the
optional MI token so request → response pairing works under async
events (a breakpoint hit can interleave with a long-running
`-data-disassemble`). Stderr is logged to the daemon's stderr via
`ldb::log::warn` for triage.

On `~GdbMiBackend` we send `-gdb-exit` and wait up to 500 ms;
SIGTERM and then SIGKILL escalate if it hangs.

## ID model

`DebuggerBackend` uses `TargetId` (opaque u64) and `ThreadId` (u64
== kernel tid). GDB's natural ids are:
- **Inferior** (gdb's term for what LDB calls a target): `i1`, `i2`,
  ... — string ids tied to the lifecycle of an inferior.
- **Thread**: numeric inside MI, format like `1`, `1.2` (per-inferior),
  not the kernel tid.

We map both directions:
- `TargetId` ↔ `i<n>`: a private `target_id_to_gdb_inferior_`
  map maintained by `open_executable` / `create_empty_target` /
  `load_core` / `connect_remote_target` / `close_target`.
- `ThreadId` ↔ MI thread-id: derived from `-thread-info` results
  (which report both gdb's internal id and the kernel tid).
  LDB's caller-facing tid is always the kernel tid (matches
  LldbBackend); GdbMiBackend translates per-call.

`FrameInfo.index` is identical across backends (0 = innermost).

## Register naming

GDB and LLDB disagree on register names in two ways:
- **Case**: gdb's `rax`, LLDB's `rax` — same lowercase, no work.
- **Flags register**: gdb's `eflags` / `cpsr`, LLDB's `rflags` /
  `cpsr`. Map `eflags` ↔ `rflags` for x86-64. ARM names match.
- **SSE/AVX**: gdb exposes `xmm0`..`xmm15` (and `ymm0`/`zmm0` on
  AVX hosts); LLDB exposes the same names. No translation needed
  for the common cases.

Canonicalisation happens at the boundary: `read_register` accepts
either name; `list_registers` emits whatever gdb returned (no
back-translation — the test suite can pin the per-backend output
since it differs in other ways too).

## Error code mapping

| gdb MI error pattern | LDB error |
|---|---|
| `^error,msg="No symbol \"X\""` | `backend::Error("symbol not found: X")` → dispatcher -32000 |
| `^error,msg="No threads."` | "no process" → -32002 bad-state |
| `^error,msg="The program is not being run."` | "no process" → -32002 |
| `^error,msg="Cannot ... target supports..."` | "not supported on this target" → -32003 forbidden |
| `^error,msg="Cannot access memory at..."` | "invalid memory access" → -32000 |
| Other `^error,msg=...` | -32000 with the verbatim msg |

The dispatcher's existing error-classifier handles these without
changes; we just need to make `backend::Error::what()` carry text
matching the patterns it already inspects.

## Method-by-method mapping table

For brevity, only non-obvious mappings are spelled out. Trivial
mappings (e.g. `-break-disable N` for `disable_breakpoint`) are
left implicit.

### Static analysis

- **list_modules** → `-file-list-shared-libraries` returns
  `name`, `from`, `to`, `loaded`, `symbols-loaded` per entry. Plus
  the main executable from `-file-list-exec-source-files` (no — that's
  source files; the main exec comes from `info files` parsing). We
  splice both into the `Module` list. `build_id` requires a separate
  pass via `info files` parsing (gdb prints "BuildID: ..." for ELFs);
  on macOS it's `UUID:`.
- **find_type_layout** → `ptype /o <name>` (CLI fall-through; MI's
  `-symbol-info-types` is too coarse). Parse the resulting
  `~"struct foo { ... }"` records into `TypeLayout`. Where ptype
  doesn't emit offset annotations (older gdb), fall back to
  per-member-offset computation via `offsetof` evaluation.
- **find_symbols** → `-symbol-info-functions --name <pattern>` +
  `-symbol-info-variables --name <pattern>`. Returns symbol name,
  type, file, line. Address requires a separate `info address`
  per symbol (slow for large result sets — fall back to
  `(unsigned long long)&<name>` evaluation, which gdb folds at
  compile time).
- **find_strings** → no MI equivalent. Use `find` on `.rodata`
  segment ranges, parse the resulting addresses, dereference each
  via `-data-read-memory-bytes` to get the string content. This is
  expensive on large binaries; consider a `--min-len` early filter.
- **disassemble_range** → `-data-disassemble -s ADDR_LO -e ADDR_HI
  --opcodes 1` returns `{address, inst, opcodes, func-name?,
  offset?}` per instruction. Maps cleanly to `DisasmInsn`.
- **xref_address / find_string_xrefs** → no MI equivalent. Walk
  every text-segment instruction via `-data-disassemble`, scan for
  literal address operands. Slow but correct; matches LldbBackend's
  approach.

### Process control

- **launch_process** → `-exec-run --start` (the `--start` flag stops
  at `main` if `stop_at_entry` is requested, otherwise `-exec-run`
  with a temporary breakpoint at `main`). `stop_at_entry` itself
  maps to `set stop-on-solib-events 1` + `tbreak main` per gdb's
  semantics. Async stop record is the source of truth for the
  post-launch `ProcessStatus`.
- **continue_process** → `-exec-continue`. Pump stdout until the
  next `*stopped` record arrives, parse `reason`, snapshot the
  process state.
- **step_thread** → `-exec-step --thread N` / `-exec-next --thread N`
  / `-exec-finish --thread N` / `-exec-step-instruction --thread N`
  for kIn/kOver/kOut/kInsn respectively.
- **reverse_continue / reverse_step_thread** → `-exec-reverse-continue`
  / `-exec-reverse-step` etc. Requires `record` to be active (gdb's
  built-in process record-and-replay) OR a remote target speaking
  the reverse-aware vCont packets (rr's gdbserver). If neither is
  active, gdb returns `^error,msg="Target child does not support
  this command."`; we map that to -32003.

### Threads / frames / values

- **list_threads** → `-thread-info` returns `threads=[...]` with
  per-thread `id` (gdb's), `target-id` (kernel pid/tid pair as a
  string we parse), `state`, `name`, plus a `frame` substructure
  with PC. We synthesize the kernel tid from `target-id`.
- **list_frames** → `-stack-list-frames 0 N` with `-thread-select N`
  first.
- **list_locals / list_args** → `-stack-list-locals 1` (1 = with
  values) / `-stack-list-arguments 1 N M`. Values come as MI
  strings; we wrap into `ValueInfo` and cap bytes at the same
  `kValueByteCap` LldbBackend uses.
- **evaluate_expression** → `-data-evaluate-expression "<expr>"`.
  Result is a string; type info isn't emitted natively, so we
  follow up with `ptype <expr>` (CLI) to populate `EvalResult.type`.

### Memory

- **read_memory** → `-data-read-memory-bytes addr count`. Limit is
  the same `kMemReadCap` LldbBackend uses.
- **read_cstring** → read_memory with successively larger windows
  until a NUL is seen, capped at `max_len`.
- **list_regions** → CLI `info proc mappings` parsed line-by-line.
  On macOS gdb (rare; Apple ships their own) the output differs;
  document as Linux-first for v1.4 and SKIP / return empty on macOS.
- **search_memory** → CLI `find /b ADDR_LO, ADDR_HI, b0, b1, ...`.

## Test strategy

Two surfaces, mirroring LldbBackend's coverage:

1. **MI parser unit tests** — `tests/unit/test_mi_parser.cpp` with
   canned MI fixtures (text strings the parser sees from gdb).
   No live gdb required; runs everywhere ctest does. Covers:
   - result records (`^done`, `^running`, `^error`, with and without
     payloads, with and without tokens)
   - async records (`*stopped`, `=thread-group-added`)
   - stream records (`~`, `&`)
   - nested tuples / lists / mixed
   - escape handling in quoted strings

2. **GdbMiBackend live tests** — `tests/unit/test_backend_gdbmi.cpp`
   with `[gdbmi][live][requires_gdb]` tags. Skip if `gdb` not on
   `PATH`. Use the existing `structs` fixture binary; exercise
   each implemented method against it.

3. **Cross-backend agent-workflow smoke** —
   `tests/smoke/test_agent_workflow_gdbmi.py`. Re-runs the static
   RE workflow from `test_agent_workflow.py` against
   `ldbd --backend=gdb`. Asserts the wire-level shape matches
   (every endpoint returns the same JSON keys; values may differ
   per backend). SKIPs without gdb.

## Backend selection

Daemon gains `--backend=lldb|gdb` (default `lldb`) and respects
`LDB_BACKEND=gdb` env var. `hello.data.capabilities.backend` echoes
the active backend so agents can branch on it.

Implementation: `main.cpp` constructs `std::shared_ptr<DebuggerBackend>`
of the right concrete type before passing to `Dispatcher`. No
runtime switching mid-session — the choice is locked at daemon
startup.

## Known leaks the abstraction may need to fix

Items I expect to find leaking from `DebuggerBackend.h` during
implementation:

- **`save_core(path)`** — LLDB's SBProcess::SaveCore produces a real
  ELF/Mach-O core. gdb's `generate-core-file` produces an ELF
  too, but the contents differ (gdb omits some pages LLDB
  includes). The method signature implies "produces a loadable
  core"; behavior parity is achievable but the output is not
  byte-identical. May need a `CoreFlavour` enum returned to make
  this honest.

- **`snapshot_for_target`** — LldbBackend computes a SHA-256 over
  the module set + register state. The same hash strategy works
  here, but the *input* differs (gdb's module reporting differs
  in detail), so the snapshot value will differ across backends
  for the same logical state. That's by design — the snapshot is
  a backend-specific opaque token — but worth documenting.

- **`evaluate_expression`** with C++ overloads — LLDB has
  `SBExpressionOptions::SetSuppressPersistentResult`; gdb's
  `-data-evaluate-expression` doesn't suppress. Cosmetic;
  agents won't notice.

- **`list_targets`** — Both backends produce roughly the same
  shape, but gdb's `triple` field is populated from `info
  configuration`'s "configured target" line and may be coarser.

The expectation is that we close on these, and any others that
emerge, inside v1.4 — that's the whole point of doing this
exercise rather than going straight to a Tier-3 backend rewrite.

## Open questions, deferred

- **`probe.*` family** — probes are LDB constructs (mix of LLDB
  breakpoint callbacks and bpftrace uprobes). GdbMiBackend honors
  the breakpoint-callback half via the same `*stopped,reason=
  "breakpoint-hit"` path it uses for `create_breakpoint`. The
  uprobe-BPF half stays Linux-only and routes through the same
  `bpftrace_engine.cpp` as today — orthogonal to the backend
  choice.

- **`observer.*` family** — observers read `/proc`, `ss`, `tcpdump`
  output. Backend-independent; GdbMiBackend passes through unchanged.

- **`session.*` / `artifact.*` / `recipe.*`** — pure store layer;
  not touched by the backend choice.

- **Multi-target / multi-inferior** — gdb supports multiple
  inferiors in one session; our `TargetId` abstraction already
  accommodates this. v1.4 implements per-target and we'll see
  how much of the multi-target work LldbBackend has done in the
  existing impl crosses over.
