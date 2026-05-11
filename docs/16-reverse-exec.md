# Reverse Execution

Tier 1 post-V1 item #2 from `docs/15-post-v1-plan.md`. The roadmap calls
this "wrap LLDB CLI via `SBCommandInterpreter`" — that turns out to be a
near-miss in two ways, both worth documenting.

## What we actually ship

Three endpoints, all returning the standard process-status shape:

- `process.reverse_continue({target_id})`
- `process.reverse_step    ({target_id, tid, kind})`
- `thread.reverse_step     ({target_id, tid, kind})`

`kind` accepts the same `in|over|out|insn` strings as forward step, but
**v0.3 implements only `insn`**. The other three are reserved at the
wire layer and rejected with `-32602` invalid params — they need
client-side reverse-step-over emulation (decode the current instruction,
set internal stops, send reverse-continue, watch for the stop) which is
deferred to a follow-up.

`process.reverse_step` and `thread.reverse_step` are wire-distinct but
route to the same backend method, mirroring the `process.continue` /
`thread.continue` split described in `docs/11-non-stop.md` — the split
exists so async-aware clients (v0.4+) don't need to change their call
sites when per-thread reverse becomes meaningful.

## Why the plan's premise was wrong

The plan said:

> rr is reachable via `rr://` URL but reverse-exec falls through to
> LLDB CLI. Cheapest approach: wrap LLDB CLI via `SBCommandInterpreter`.

Both halves of that are misleading:

1. **LLDB has no reverse CLI commands.** `apropos reverse` on LLDB 22
   returns nothing. There is no `process reverse-continue`, no
   `_regexp-reverse-*`. `SBCommandInterpreter::HandleCommand("process
   reverse-continue")` returns "not a known command."
2. **There is no `SBProcess::ReverseContinue` API.** SBAPI exposes no
   reverse-exec entry point at all.

The actually-cheap path is one level down: LLDB's `gdb-remote` process
plugin mounts a CLI subcommand `process plugin packet send <packet>`
that injects a raw GDB RSP packet. rr's gdbserver implements `bc`
(reverse-continue) and `bs` (reverse-step, one instruction) — those are
the only reverse-exec primitives in the GDB protocol. We send them and
pump LLDB's event listener for the next stop, the same pattern as
`connect_remote_target`.

## Mechanism

```
target.connect_remote rr://<trace>  →  marks target reverse_capable=true
                                          |
process.reverse_continue ────────────┐    |
                                     ▼    ▼
                       SBDebugger.SetSelectedTarget(target)
                       SBCommandInterpreter.HandleCommand(
                           "process plugin packet send bc")
                                     |
                              ┌──────┴──────┐
                              ▼             ▼
                          succeeded?    ro.GetError() →
                              |             throw classified
                              |             backend::Error
                              ▼
                       pump listener for stop event (5s timeout)
                              |
                              ▼
                       snapshot(proc) → ProcessStatus
```

`reverse_step_thread(kInsn)` follows the same shape with `bs` instead
of `bc`, after calling `SBProcess::SetSelectedThreadByID(tid)` so rr
applies the step to the right thread.

Stdout is silenced around the `HandleCommand` call via the same
`dup2(/dev/null)` pattern used in `save_core` and `connect_remote_target`,
because the gdb-remote plugin occasionally writes diagnostics to C
stdio that would corrupt the JSON-RPC channel.

## Capability gating

The backend stores a per-target `is_reverse_capable` bool in
`Impl::reverse_capable`. It is set to true when `connect_remote_target`
parses an `rr://` URL successfully; cleared on `close_target`. Other
transports (future replay daemons, hardware-trace replay) will set the
same flag when they land. The backend methods consult the flag and
throw `"target does not support reverse execution"` for non-rr targets,
which the dispatcher maps to `-32003` forbidden.

## Failure semantics

| Wire case                                  | Code     | Cause                                                           |
|--------------------------------------------|----------|-----------------------------------------------------------------|
| Missing `target_id`                        | `-32602` | Dispatcher pre-check.                                           |
| Missing `tid` / `kind` (reverse_step)      | `-32602` | Dispatcher pre-check.                                           |
| `kind=in` / `over` / `out`                 | `-32602` | Reserved; v0.3 supports `insn` only.                            |
| `kind` not one of in/over/out/insn         | `-32602` | Unknown kind string.                                            |
| Unknown `target_id`                        | `-32000` | Backend lookup miss.                                            |
| No live process                            | `-32002` | Backend state check.                                            |
| Target not reverse-capable                 | `-32003` | Per-target capability flag is false (not opened via rr://).     |
| `bc` / `bs` packet failure from rr         | `-32000` | gdb-remote plugin returned a non-Succeeded SBCommandReturnObject. |
| Stop-event pump timeout                    | (success with state from last snapshot — see below) | 5s deadline elapsed; snapshot returns whatever rr most recently reported. |

Timeout behavior is deliberately not an error: rr's stop reply may
genuinely take longer than 5 s on very large traces. The endpoint
returns the most-recent process state. A future enhancement could
surface a `stale: true` field via the view layer.

## Reverse-step-over / reverse-step-into

These were considered for v0.3 and deferred. The mechanical issue: GDB
RSP defines exactly two reverse primitives (`bc`, `bs`). Everything
else is a client-side construction:

- **reverse-step-into** (`kIn`) ≈ `bs` repeatedly until a source-line
  boundary is crossed. Cheap, but requires DWARF line-table walking
  per step — sequence-of-`bs` is doable but the stop-reason path needs
  more work.
- **reverse-step-over** (`kOver`) ≈ disassemble the current
  instruction, decide whether it's a call, set an internal breakpoint
  at the next instruction in the *current* frame, then `bc`. The
  breakpoint placement is the tricky bit (must survive the reverse
  direction, must not fire on the original `bc` cursor).
- **reverse-step-out** (`kOut`) ≈ unwind one frame, set an internal
  breakpoint at the return address site, `bc`. Same internal-bp
  difficulties.

Track these in `docs/15-post-v1-plan.md` Tier 2 (likely a small follow-up
session each) once the `bs` foundation is field-tested.

## Test coverage

- `tests/unit/test_dispatcher_reverse_exec.cpp` — dispatcher routing
  with a `CountingStub`, kind validation, schema presence.
- `tests/unit/test_backend_reverse_exec.cpp` — `LldbBackend` negative
  path (no live process, non-rr target, `kIn`/`kOver` kinds).
- `tests/unit/test_backend_reverse_exec_rr.cpp` — live round-trip via
  rr; SKIPs when rr is unavailable or `rr record` fails
  (`perf_event_paranoid`, `ptrace_scope`, unsupported CPU microarch).
- `tests/smoke/test_reverse_exec.py` — JSON-RPC end-to-end through
  `ldbd`. Negative paths run unconditionally; live path SKIPs without
  rr.

## Open issues for follow-up

- **No protocol-level cost annotation.** `cost_hint: high` reflects
  that pumping the listener can block for 5 s. A measured p50 from
  session-store telemetry would be more honest — that lines up with
  post-V1 item #4 in `docs/15-post-v1-plan.md`.
- **Stop-reason fidelity.** `snapshot(proc)` reads whatever
  `SBProcess::GetState()` reports, but rr's stop reasons (e.g.
  reverse-singlestep-stop, beginning-of-trace) don't always have a
  clean SBAPI mapping. Worth a follow-up to pin down for v1.2.
