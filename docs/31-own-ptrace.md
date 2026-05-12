# Own Linux ptrace driver — deferred design note

Post-V1 plan item **#20** from `docs/15-post-v1-plan.md`, listed in
v1.6's non-stop chain per `docs/17-version-plan.md` with the explicit
qualifier:

> Last resort; only if upstream LLDB gaps haven't closed by then.

This note exists so that **if** the trigger fires — a concrete kernel-
feature gap, a measured performance ceiling, or a divergence between
what we need and what LLDB's `NativeProcessLinux` offers — the next
contributor doesn't start from a blank page. It does **not** commit
us to building this. The default disposition remains "defer."

## TL;DR

- **Deferred indefinitely.** Upstream LLDB owns the Linux ptrace
  path via `NativeProcessLinux`; LDB has not hit a hard blocker
  yet. The roadmap (`docs/03-ldb-full-roadmap.md` §7) is explicit:
  replacement is last resort behind "no upstream fix in flight."
- **Triggering signals are concrete.** A handful of specific
  features (PTRACE_GET_SYSCALL_INFO, seccomp-aware tracing, io_uring
  observability) and a handful of measurable gaps (per-thread event
  throughput, displaced-stepping latency) form the trip-wire. None
  has fired yet.
- **Scope when triggered** is a new `LinuxPtraceBackend` slotted
  under the existing `DebuggerBackend` abstraction — the same
  abstraction v1.4 #8 (GdbMiBackend) validated. We do not "rewrite
  LLDB"; we replace exactly the Linux process layer.
- **What we'd lose is non-trivial.** LLDB's expression evaluator,
  thread plans, plugin ecosystem, and many years of edge-case
  hardening live above the process layer. An own ptrace driver is
  not a "drop LLDB" move — it's a backend-swap for the bottom of
  the stack.

## 1. Why deferred

Upstream LLDB's `NativeProcessLinux` (under
`lldb/source/Plugins/Process/Linux/`) owns the ptrace surface and
tracks the Linux kernel actively. It handles:

- `PTRACE_ATTACH` / `PTRACE_SEIZE` / `PTRACE_INTERRUPT` discipline.
- Per-tid `waitpid()` and signal demultiplexing.
- `PTRACE_GETREGSET` / `NT_PRSTATUS` register access (x86-64,
  arm64, riscv64).
- Hardware breakpoint / watchpoint registers (DR0–DR7 on x86;
  `BVR`/`BCR`/`WVR`/`WCR` on arm64).
- Software single-step on architectures that lack it
  (`PTRACE_SINGLESTEP` fallback / displaced stepping).
- Signal injection (`PTRACE_CONT` with `WSTOPSIG`).
- Auxv reading for the dynamic loader's r_debug rendezvous.

LDB exercises all of this through `SBProcess` and never has to
think about kernel ABI. The v1 backend's `LldbBackend`
(`src/backend/lldb_backend.cpp`) is thin precisely because LLDB
already abstracted Linux/macOS process control behind a uniform
SBAPI surface.

**The work required to replace this is substantial** (see §4) and
the payoff is unclear unless a specific upstream gap is forcing
the issue. The watchlist in `docs/15-post-v1-plan.md` §5 records
the disposition succinctly:

> Own ptrace driver (#20) may not be needed if LLDB closes its
> gaps. Roadmap §7 explicitly says replacement is last resort
> behind "no upstream fix in flight." Watch the LLDB issue tracker.

## 2. Triggering signals

What would make us reconsider — in order from "watch closely" to
"start building":

### 2.1. Specific kernel features LLDB doesn't expose

- **`PTRACE_GET_SYSCALL_INFO`** (Linux 5.3+). Gives us structured
  per-syscall enter/exit info — entry args, exit code, seccomp
  data — without parsing the syscall ABI by architecture. LLDB's
  syscall tracing today uses `PTRACE_SYSCALL` and re-derives the
  data by reading registers; the structured info is cleaner and
  cheaper. **Not a hard blocker today** because we don't yet
  surface syscall-tracing endpoints; if `probe.create` ever grows
  a `kind: "syscall"` path the gap becomes visible.

- **Seccomp-aware tracing**. `SECCOMP_RET_TRACE` lets a seccomp
  filter request a ptrace-stop on specific syscalls without paying
  the full `PTRACE_SYSCALL` cost for every syscall. LLDB doesn't
  expose this; a probe-agent that wants to watch only `openat`
  pays for tracing on every `clock_gettime` too. Trigger: an agent
  workload where syscall-tracing overhead is the bottleneck.

- **io_uring observability**. `io_uring` submissions don't go
  through the syscall ABI — they're written to a shared ring and
  the kernel picks them up asynchronously. Tracing this requires
  either kernel-side tracepoints (eBPF) or `PTRACE_O_TRACESYSGOOD`
  + manual SQE/CQE inspection through `process_vm_readv`. LLDB
  does neither. Trigger: explicit user request to debug an
  io_uring-heavy server.

- **PIDFD support**. `pidfd_open` + `pidfd_send_signal` give us a
  race-free reference to a process across exec/exit. Useful for
  the non-stop runtime (#21) when a tid disappears mid-RPC. LLDB
  uses raw pids; we'd inherit the TOCTOU window. Trigger: a
  non-stop workload hitting reused-tid bugs.

### 2.2. Measurable performance gaps

- **Per-thread event throughput**. The current `vCont`-over-LLDB
  path serialises thread events through `SBListener::WaitForEvent`,
  which has a documented latency floor in the
  hundreds-of-microseconds range. An own ptrace loop reading
  `waitpid()` directly can in principle do an order of magnitude
  better. Trigger: a `tracepoint.*` workload that the rate limiter
  has to clamp purely because of round-trip latency, not because
  the agent wants the rate clamped.

- **Displaced-stepping latency**. Non-stop displaced stepping
  copies the instruction at the breakpoint into a scratch page,
  steps, and patches PC back. LLDB does this inside the process
  plugin; we have zero visibility into the timing. Trigger:
  #21's non-stop runtime hitting an unexpected latency floor that
  profiling pins on the displaced-step path.

- **Wakeup batching**. A tight `vCont;c` → `vCont;t` loop can pay
  `waitpid()` syscall overhead per event. LLDB doesn't batch.
  An own driver could use `pidfd` + `epoll` to multiplex many
  tids on one wakeup. Trigger: non-stop runtime profiles showing
  `waitpid` dominating.

### 2.3. macOS-shaped consideration

ptrace is Linux-specific in this design's scope. macOS uses Mach
exceptions (via `task_for_pid` and `mach_port_t` exception
handlers), which is a separate driver entirely. If we ever own
the macOS process layer it lives in a sibling note (`MachExcBackend`,
not in this note). Listed here so a future contributor doesn't
read this note and conclude it should grow a macOS path — it
should not.

## 3. Scope when triggered — phase-1 shape

When (if) a trigger fires, the work breaks into a phase-1 that is
narrow enough to verify against `LldbBackend` and a phase-2 that
extends to features LLDB doesn't cover.

### 3.1. `LinuxPtraceBackend` — new `DebuggerBackend` implementation

Sits alongside `LldbBackend` and `GdbMiBackend` (v1.4 #8) under
`src/backend/`. Constructor takes a Linux pid (attach) or a
launch spec (fork+exec); destructor detaches cleanly. The
abstraction is already there — v1.4 #8 paid for it.

Phase-1 implements **only** the endpoints currently covered by
`DebuggerBackend`:

- `process.*` — attach, detach, continue, interrupt, step.
- `thread.*` — list, select, continue, step.
- `module.list`, `register.read/write`, `memory.read/write`.
- Breakpoint set/remove (software bp via `INT3` write + restore).

It does **not** implement:

- Expression evaluation (`evaluate.*`) — stays on LldbBackend.
- DWARF parsing / type layouts — stays on LldbBackend.
- Symbol resolution — stays on the v1.5 #18 symbol index (which
  itself sits over LLDB's reader).

The split is deliberate. Process control is what ptrace gives us;
debug info is an orthogonal concern. A single target can have
two backends attached — `LinuxPtraceBackend` for process control,
`LldbBackend` (read-only) for DWARF + expressions. The
`DebuggerBackend` interface needs no shape change to support this;
the dispatcher selects per-endpoint family.

### 3.2. Core syscalls

```
ptrace(PTRACE_SEIZE,    pid, 0, options)    // attach without stop
ptrace(PTRACE_INTERRUPT,pid, 0, 0)          // bring it to stop
ptrace(PTRACE_CONT,     tid, 0, sig)        // resume; sig forwards
ptrace(PTRACE_SINGLESTEP, tid, 0, sig)      // single-step
ptrace(PTRACE_SYSCALL,  tid, 0, sig)        // stop on syscall enter/exit
ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &iov)  // GP registers
ptrace(PTRACE_SETREGSET, tid, NT_PRSTATUS, &iov)
ptrace(PTRACE_PEEKUSER, tid, off, 0)        // x86 DR registers
ptrace(PTRACE_POKEUSER, tid, off, val)
ptrace(PTRACE_GETSIGINFO, tid, 0, &sig)     // signal details on stop
ptrace(PTRACE_GETEVENTMSG, tid, 0, &msg)    // clone/fork tid, exit code
process_vm_readv(pid, ...)                  // bulk memory read
process_vm_writev(pid, ...)                 // bulk memory write
```

`process_vm_readv` / `_writev` are the bulk memory paths;
`PTRACE_PEEKDATA` / `POKEDATA` stay as the fallback for early-
attach scenarios where `/proc/<pid>/mem` isn't yet mapped.

### 3.3. Async event loop

```
   signalfd(SIGCHLD)
        │
        ▼
   epoll_wait
        │
        ▼
   waitpid(-1, &status, WNOHANG | __WALL)
        │
        ▼
   demux: stop event → StopEvent queue (per-tid)
          exit event → ProcessExit queue
          clone/fork → child enrolled, options inherited
          syscall → SyscallEvent queue (when PTRACE_SYSCALL active)
```

The structure mirrors v1.6 #17's RspChannel reader thread (per
`docs/25-own-rsp-client.md` §2.4). One reader thread feeds a
bounded `StopEvent` queue; the dispatcher's RPC loop drains via
`recv(timeout_ms)`. This is the same plumbing #21's non-stop
runtime needs — if #20 lands, #21 reuses the queue.

`signalfd(SIGCHLD)` lets us multiplex SIGCHLD into `epoll` so the
reader thread blocks on one fd regardless of how many children
exist. The alternative — sigwaitinfo or a SIGCHLD handler — is
both messier and less composable with `pidfd_open` for the future
batching work in §2.2.

### 3.4. Per-tid tracking

```cpp
struct TidState {
  pid_t          tid;
  TidStatus      status;   // running | stopped | exiting | exited
  int            last_sig; // for resume signal forwarding
  std::uint64_t  last_event_seq;
  std::optional<DisplacedStep>  in_displaced_step;
  std::optional<std::uint64_t>  pending_pc_patch;
};

std::unordered_map<pid_t, TidState>  tids_;
std::mutex                            tids_mu_;
```

Per-tid state is the load-bearing data structure for non-stop.
LLDB has the equivalent internally; in an own driver it's our
problem. Clone/fork events automatically enrol new tids with
inherited ptrace options.

### 3.5. DWARF unwinding

LLDB's unwinder builds frames from `.eh_frame` / `.debug_frame`
plus arch-specific fallbacks (frame pointer chain, signal trampoline
recognition). An own ptrace driver still owes us frame walks for
the `process.backtrace` endpoint.

Two viable paths:

- **libunwind (the LLVM one, not the gnu one)**. Apache 2.0,
  already a transitive dep of the LLDB toolchain. We'd link
  `liblldb`-less by depending on `libunwind` directly. Cost:
  vendor-or-link decision + ~one engineer-week.
- **Own walker** over `.eh_frame`. About 1500–2000 lines of code,
  better integration with the rest of LDB's debug-info path
  (v1.5 #18 / #19 territory). Cost: ~one engineer-month.

Phase-1 picks **libunwind**. The own walker is only worth
building if v1.5 #19 (own DWARF reader) lands first — which the
v1.5 design note (`docs/23-symbol-index.md` §2) recommends
against unless a concrete gap forces it.

### 3.6. Module enumeration

`/proc/<pid>/maps` gives us load addresses; r_debug rendezvous via
`auxv` (AT_BASE) + `_dl_debug_state` callback gives us
load/unload events. LLDB does this; we redo it. Standard ABI,
no surprises.

## 4. What we'd lose

LLDB above the process layer is mature and not easily replaced.
Specifically, by swapping `LldbBackend` for `LinuxPtraceBackend`
on the process-control axis we lose **direct access to**:

- **Expression evaluation**. `evaluate.expression` runs Clang
  against the inferior's source / debug info. Not even attempted
  in an own ptrace driver; the dispatcher routes evaluation to
  whichever backend supports it.
- **Thread plans**. LLDB's `ThreadPlanStepInRange`, `ThreadPlanStepOverRange`
  encode the high-level step semantics (step into a callsite, step
  over a function, step out to caller). Phase-1's own driver
  exposes raw single-step; the dispatcher's existing `step.in/over/out`
  handlers re-implement the plan logic from address + line tables.
  This is doable but non-trivial.
- **Plugin ecosystem**. LLDB's process plugins handle JIT debug,
  Linux core files, Mach-O core files, Windows minidumps. None of
  those go through ptrace; an own ptrace driver is orthogonal.
- **Many years of edge-case hardening**. PIE binaries, threads
  with exotic signal masks, `vfork`, `clone(CLONE_VM)` without
  `CLONE_THREAD`, the kernel's particular `PTRACE_O_TRACEEXIT`
  ordering quirks. LLDB has been hit by all of these and patched.
  Our driver would be hit by them fresh.

The cumulative cost of this "loss" is mostly **maintenance** — we
become responsible for tracking kernel ABI changes ourselves
(syscall number renumbering on new architectures, regset format
churn, ptrace option behavioural fixes).

## 5. What we'd gain

- **Direct control over the event loop**. The async pump goes
  from "convince LLDB's listener to push us non-stop events" to
  "the queue is ours, drain it on our schedule." This is the
  same lever v1.6 #17 (own RSP client) buys for remote targets;
  #20 buys it for local Linux.
- **No SBAPI quirks**. LLDB's process layer has corners — stop
  reasons that don't round-trip cleanly to JSON, register names
  that vary across LLDB versions, breakpoint set/unset races
  during continue. We see each of these in the wild via smoke
  tests. An own driver makes the contract one we own.
- **Smaller binary**. Phase-1's `LinuxPtraceBackend` is ~3000
  lines of code + libunwind. Removing `liblldb` from the link
  for Linux-only deployments drops ~80 MB from the binary
  footprint. (Deployments still wanting expressions keep LLDB
  for the eval path; this is about the local-process-control
  axis only.)
- **No `liblldb` runtime dep for embedded / probe-agent scenarios**.
  v1.4 #12's `ldb-probe-agent` is a static native binary today;
  an own ptrace driver lets it grow into a full debugger on the
  target without dragging `liblldb` along.
- **Direct kernel-feature access**. The §2.1 features (syscall
  info, seccomp tracing, pidfd) become straight syscalls instead
  of "wait for LLDB to add a plugin."

## 6. Migration shape (when triggered)

The migration mirrors v1.4 #8 (GdbMiBackend) — parallel backend,
opt-in initially, default flip later:

1. **Phase-1, new module.** `src/backend/linux_ptrace_backend.{h,cpp}`
   ships as a new `DebuggerBackend` implementation. Selectable via
   `target.open({backend: "ptrace"})` and `target.attach({backend: "ptrace"})`.
   Default stays on LldbBackend.
2. **Phase-1 smoke tests.** A new family
   `tests/smoke/test_ptrace_backend_parity.py` runs every existing
   process / thread / memory / register smoke against both backends
   and asserts byte-equal JSON. Whatever drifts gets fixed.
3. **Phase-2 features.** PTRACE_GET_SYSCALL_INFO surfaced via a
   new `process.syscall_trace_start/stop` family. Seccomp-tracing
   integration. pidfd-based TOCTOU-free tid handling.
4. **Phase-3 default flip.** Once the matrix is green for ~one
   release cycle, `target.open` on Linux defaults to
   `backend: "ptrace"`; `LldbBackend` is the escape hatch for
   the expression / DWARF / non-Linux paths.

No wire break. Existing endpoints keep the same shape; the
dispatcher routes through whichever backend is bound.

## 7. Failure matrix (anticipated)

| Failure | Behaviour |
|---|---|
| `ptrace(PTRACE_SEIZE)` returns EPERM (no permission, yama disabled, etc.) | `-32000 kBackendError` with the errno text; hint to check `kernel.yama.ptrace_scope` |
| `ptrace(PTRACE_SEIZE)` returns ESRCH (race: pid exited) | `-32000` "target exited before attach" |
| `waitpid` returns ECHILD when we expected a tid | TidState already marked exiting; drop the wait result, no event emitted |
| `process_vm_readv` returns EFAULT | Treat as partial read; return the bytes we got + an EOR marker. Same shape as LldbBackend's partial reads. |
| `INT3` write fails (page is read-only and we haven't mmaped over it) | `-32000` "breakpoint write failed; address may be in a read-only mapping not yet shadowed" + hint to use hw breakpoint |
| Single-step over a syscall returns into the kernel | Phase-1 handles by issuing a second step to land at the syscall return; phase-2 may displace-step the syscall itself |
| Hardware breakpoint slot exhausted (4 DR slots on x86) | `-32003 kNotSupported` with the slot count and a list of currently-bound hw bps |
| `clone` event for a thread the agent doesn't know about | Auto-enrol the tid with inherited options; surface as a `ThreadCreated` event on the StopEvent queue |
| `PTRACE_O_TRACEEXEC` fires on `execve` | Tear down the old mapping cache + re-read `/proc/<pid>/maps` + re-resolve modules; surface as `TargetExeced` event |

The general principle is **fail to the same JSON shape LldbBackend
fails to**. The parity smoke (§6.2) keeps this honest.

## 8. Recommendation

**Keep this deferred.** None of §2's triggering signals has fired.
LLDB's `NativeProcessLinux` is mature; the v1 backend is thin
specifically because that maturity is load-bearing. Re-evaluate:

- When v1.6 #21 (non-stop runtime) lands and the latency profile
  is in hand — if the bottleneck is LLDB's listener path, this
  note's §2.2 has the receipts.
- When a concrete user workload needs §2.1's kernel features —
  not "would be nice," but "we cannot make progress without it."
- When `liblldb`'s ABI breaks force a pin of an old LLDB version
  for some unrelated reason — at which point owning the Linux
  process layer becomes part of the "what do we still need LLDB
  for?" inventory.

Until then, this note is the down payment. Reading it should be
enough to start phase-1 without re-discovering the design.

## 9. Cross-references

- `docs/03-ldb-full-roadmap.md` §7 — "Own ptrace driver is last
  resort behind 'no upstream fix in flight.'"
- `docs/15-post-v1-plan.md` #20 — catalog entry + watchlist.
- `docs/17-version-plan.md` v1.6 — non-stop chain ordering.
- `docs/11-non-stop.md` — what #21 needs that #20 would help
  deliver.
- `docs/25-own-rsp-client.md` — sibling "own the boundary" move
  for remote targets; the async-pump pattern transfers.
- `src/backend/debugger_backend.h` — the abstraction a future
  `LinuxPtraceBackend` would implement.
- LLDB source: `lldb/source/Plugins/Process/Linux/NativeProcessLinux.cpp`
  — the upstream code this would replace, when triggered.
