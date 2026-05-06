# Non-stop debugging — protocol shape vs runtime gap

**Status:** v0.3 ships the *protocol surface* for per-thread resume.
**True non-stop runtime is deferred to v0.4+** (Tier 4 §14 scoped slice).

This document explains exactly what the daemon does today, what agents
can rely on, and what will change when v0.4 lights up
`SBProcess::SetAsync(true)`. The split exists so client code (DAP shim,
agents, the `ldb` CLI) is *async-ready* — the wire shape is stable now,
behavior switches on a daemon-version handshake when v0.4 lands.

## TL;DR for agents

> In v0.3, `thread.continue({tid})` and `process.continue({tid})` are
> equivalent to `process.continue` — the WHOLE process resumes,
> regardless of which `tid` you pass. Treat per-thread resume as a
> hint that has no runtime effect yet. The endpoint exists so your
> client code doesn't need to change when async-mode lands.

## What ships in v0.3

### Read path — already correct

`thread.list` returns each thread's `state` field
(`stopped`/`running`/`exited`/...). In sync mode this is the
whole-process state replicated per-thread, which is exactly what an
async-mode agent would observe in a single-threaded inferior or in the
common case where `process.continue` (no tid) just resumed everything.
Agents can write code against this field today and the *meaning* of
the field — "what is this thread doing right now" — is preserved into
v0.4.

### Write path — wire-shape parity

| Endpoint                              | v0.3 runtime                                        | v0.4+ runtime                                      |
|---------------------------------------|-----------------------------------------------------|----------------------------------------------------|
| `process.continue({target_id})`       | Whole-process resume. Blocks until next stop/exit. | Same.                                              |
| `process.continue({target_id, tid})`  | **Whole-process resume** (passthrough). `tid` logged but otherwise ignored. | Per-thread resume; sibling threads stay stopped.   |
| `thread.continue({target_id, tid})`   | **Whole-process resume** (passthrough).            | Per-thread resume; sibling threads stay stopped.   |
| `process.step({target_id, tid, kind})`| Single-step the named thread.                       | Same — steps already work per-thread today.        |

The `process.continue+tid` and `thread.continue` calls are routed
through a new backend method `continue_thread(target_id, thread_id)`
which, in `LldbBackend`, forwards into `continue_process`. This is the
expansion point — when v0.4 lands we change the implementation, not
the wire shape.

### `describe.endpoints` disclosure

Both endpoints' summaries explicitly call out the v0.3 sync semantics
and the v0.4+ expectation, so an agent reading the catalog at session
start sees the gap without consulting this file:

* `thread.continue` summary leads with `WARNING: in v0.3 this is SYNC ...`
* `process.continue` summary documents the optional `tid` and notes
  it's sync passthrough.

## Why we can't just flip the switch

`LldbBackend` is constructed with `SBDebugger::SetAsync(false)`. Every
endpoint that depends on the next-stop blocking semantics relies on
that — `process.continue` returns the post-stop state, `process.step`
returns the post-step state, `attach` blocks until the inferior is
quiesced, `connect_remote_target` blocks until the gdbstub reports a
stable state. A single `SetAsync(true)` flip would break every one of
these endpoints simultaneously.

True async mode requires:

1. **Event-loop pump.** A dedicated thread (or epoll integration)
   drains `SBListener::WaitForEvent`, classifies events
   (`eBroadcastBitStateChanged`, `eBroadcastBitInterrupt`,
   `eBroadcastBitSTDOUT`, ...), and updates per-thread state.
2. **Per-thread runtime state machine.** Track `running` /
   `stopped-with-reason` per thread, not per process. `thread.list`'s
   `state` field becomes per-thread truthful instead of replicated.
3. **Suspend / resume primitives.** `SBThread::Suspend` /
   `SBThread::Resume` to pin sibling threads while one resumes; the
   process is "running" while any thread is running.
4. **Endpoint review.** Each endpoint that today assumes "after
   Continue() returns, we're stopped" needs to either retain its sync
   contract via "wait for any-stop" wrapper or migrate to an
   explicitly-async return shape (e.g. `{state: "running", request_id}`
   plus a push-event mechanism).
5. **Push events.** `thread.stopped` / `thread.running` notifications
   so the client doesn't need to poll `process.state`.

Each of those is multi-day surgery. Doing them all in one milestone
would block every higher slice; doing the protocol surface now lets
the client and DAP shim code stabilize against the v0.4-shape
endpoints without coupling to the runtime work.

## Specifically deferred to v0.4+

These are intentionally **not shipped** in v0.3 and have no protocol
surface yet:

* **`thread.stop({tid})`** — selectively stop one thread. Requires
  async mode to make sense: in sync mode the process is either fully
  stopped or fully running (and a "running" sync mode means the daemon
  is mid-`Continue()` and not servicing RPCs). The endpoint will
  arrive with v0.4.
* **Push-based events.** Today every state change is observed by
  polling `process.state` or `thread.list`. v0.4 will add a JSON-RPC
  notification channel (or a long-poll endpoint) for
  `thread.stopped`/`thread.running`/`process.exited`.
* **True per-thread keep-running.** The whole point of the slice —
  resume thread A while thread B stays at its breakpoint. v0.4
  `continue_thread` implementation calls
  `SBThread::Suspend()` on every other thread, then
  `SBProcess::Continue()`, and unsuspends siblings on the next stop.
* **Per-thread `<gen>` provenance.** Today the live-state generation
  counter is per-target (`live_state[tid]`). With per-thread
  keep-running, drift becomes per-thread; the audit at
  `docs/POST-V0.1-PROGRESS.md §3` already flags this in "Snapshot-ID
  gaps".

## Versioning

The plan is to bump the protocol minor version when v0.4 ships true
non-stop. Agents that care can negotiate via `hello.protocol_min`:

* Daemon at `0.3.x` advertises `thread.continue` with the v0.3-sync
  semantics in its `summary` and serves it as a passthrough.
* Daemon at `0.4.x` advertises `thread.continue` with v0.4 semantics
  in its `summary` and actually does per-thread resume.
* A client written against v0.3 keeps working: it calls
  `thread.continue` and observes a stop event — same as v0.3.
* A client written for v0.4 negotiates `protocol_min: "0.4"` and gets
  a hard `-32011` against a v0.3 daemon, so it can fall back to
  `process.continue` (no tid).

## Implementation pointers (for v0.4 worker)

* Backend hook: `DebuggerBackend::continue_thread` (already declared,
  v0.3 implementation is a passthrough). Re-implement in
  `LldbBackend` to use `SBThread::Suspend` / `SBProcess::Continue`.
* Async-mode init: see `LldbBackend` ctor — currently
  `SBDebugger::SetAsync(false)`. The flip is one line; the rest is
  the event-loop pump, see (1)-(5) above.
* Tests: `tests/unit/test_backend_continue_thread.cpp` pins the v0.3
  passthrough contract. v0.4 will need new cases asserting that
  sibling threads stay at their PCs while the named thread runs.
* DAP shim: `tests/unit/test_dap_handlers.cpp` `continue` request
  currently maps to `process.continue` (no tid). Once v0.4 lands the
  shim should map to `thread.continue` when DAP's `singleThread`
  flag is true.

## References

* `docs/02-ldb-mvp-plan.md` — v0.3 endpoint catalogue.
* `docs/03-ldb-full-roadmap.md` Track B — "Non-stop debugging:
  LLDB has it for some targets; we expose it through the protocol
  with a per-thread state model."
* `docs/POST-V0.1-PROGRESS.md` Tier 4 §14 — slice tracking.
* `src/backend/debugger_backend.h` — `continue_thread` interface
  contract comment.
* `src/backend/lldb_backend.cpp` — `continue_thread` v0.3
  passthrough implementation.
