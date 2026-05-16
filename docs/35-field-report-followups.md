# Field Report Follow-ups (2026-05-16)

Three items deferred from `fix/target-open-lazy-load` (commits `8cb6915`
+ `191b049`). Source: a RE engineer driving LDB against a 503 MB iOS
arm64 Mach-O. The killer (`target.open` runtime + response size) was
fixed in that branch. This doc captures the design + sequencing for
what's left.

Read in order: §1 → §2 → §3. They're independent in terms of code
seams but interact in terms of which test fixtures we need on hand
(see §4).

---

## 1. CLI sibling lookup for `ldbd`

### Problem

`tools/ldb/ldb` looks up the daemon via, in order:

1. `--ldbd PATH` flag if given.
2. `$PATH` (`shutil.which("ldbd")`).
3. `./build/bin/ldbd` relative to the user's CWD.

For an in-tree dev flow this is awkward: `ldb` lives at
`<repo>/tools/ldb/ldb`, `ldbd` lives at `<repo>/build/bin/ldbd`, and
neither is on `$PATH`. Running `ldb target.open ...` from anywhere
other than the repo root fails with "ldbd not found." The reporter hit
this and had to pass `--ldbd /Users/.../build/bin/ldbd` on every
invocation.

### Proposed fix

Add a **sibling-lookup heuristic** between steps 2 and 3:

```python
def find_ldbd_sibling() -> Optional[str]:
    # tools/ldb/ldb -> tools/ldb -> tools -> <repo>
    repo_root = Path(__file__).resolve().parent.parent.parent
    cand = repo_root / "build" / "bin" / "ldbd"
    return str(cand) if cand.is_file() and os.access(cand, os.X_OK) else None
```

Insert into `find_ldbd()` in `tools/ldb/ldb`:

```python
def find_ldbd(explicit: Optional[str]) -> str:
    if explicit:
        # Validate executability up front; otherwise the failure
        # surfaces deep inside subprocess.Popen as a confusing EACCES.
        if not os.access(explicit, os.X_OK):
            raise SystemExit(f"ldb: --ldbd {explicit!r} not executable")
        return explicit
    if which := shutil.which("ldbd"):
        return which
    if sibling := find_ldbd_sibling():
        return sibling
    if os.path.isfile("./build/bin/ldbd"):
        return "./build/bin/ldbd"
    raise SystemExit("ldb: ldbd not found; pass --ldbd PATH")
```

### Out of scope (for this slice)

- **`make install` target** — pulling `ldb` + `ldbd` into a configurable
  prefix (e.g. `~/.local/bin`) is the right answer for shipping, but
  it's a CMake-side change and changes the install surface for
  downstream packagers. Track separately.
- **Auto-build if the sibling is missing-but-source-present.** Too
  magical; would mask a stale-build bug.

### Tests

- Add to `tests/smoke/test_ldb_cli.py` (or a new
  `test_cli_sibling_lookup.py`): with `$PATH` scrubbed of `ldbd` and no
  `--ldbd` flag, the CLI still finds the in-tree daemon.
- Keep the existing `--ldbd PATH` precedence behaviour and pin it in
  the same test.

### Risk

Low. Pure Python, no daemon-side changes, narrow heuristic gated on
`__file__` landing under a recognisable repo layout. False-positive
case: someone vendors `tools/ldb/ldb` into their own repo with a
different layout — they won't have a sibling `build/bin/ldbd`, the
heuristic returns `None`, fall-through to the existing fallback path.
No regression possible.

### Effort

~30 min: 10 min code + 15 min test + 5 min worklog.

---

## 2. Persistent socket-attached daemon

### Problem

Every `ldb <subcommand>` spawns a fresh `ldbd --stdio` child, sends one
request, and reaps the child. `target_id` and any other daemon-side
state die with the subprocess. The reporter wanted to issue several
calls in sequence — `target.open`, then `symbol.find`, then
`disasm.function` — from a shell script, *without* having to hold open
a single Python-driven REPL.

Current options for state persistence:

- **`--repl`** — interactive REPL with persistent daemon. Works, but
  requires the agent to drive stdin (awkward from a shell script that
  wants one process per command).
- **A wrapper script that drives the REPL** — possible but ugly; every
  user has to invent it.

### Proposed design

A new `ldbd --listen unix:/path/to/ldbd.sock` mode + a `ldb --socket
/path/to/ldbd.sock` client knob.

#### Wire shape

Same JSON-RPC framing the stdio mode already uses; just a different
fd source. `read_message` / `write_response` in `src/protocol/` are
already abstracted over `std::istream`/`std::ostream` (and the
`OutputChannel`). The change is the listener layer.

Server side, sketch:

```cpp
// new src/daemon/socket_listener.cpp
//
// accept() loop. Each connection gets its own thread that wraps the
// connection fd in iostream-compatible socketbufs and calls the same
// run_stdio_loop dispatcher path. Connections share the Dispatcher
// (and therefore the backend's target table), so target_id from one
// connection is visible to the next.
```

Lifecycle questions to resolve before code:

| Question | Tentative answer |
|---|---|
| Where does the socket live? | `$XDG_RUNTIME_DIR/ldbd.sock` if set, else `$TMPDIR/ldbd-$UID.sock`. Never world-readable. |
| When does the daemon exit? | Phase 1: explicit `daemon.shutdown` RPC or SIGTERM. Phase 2: idle timeout (no connections for N seconds). |
| What if two `ldbd --listen` race on the same path? | One acquires an `flock()` on `${sock}.lock`; the second fails fast with "daemon already listening." |
| Auto-spawn from the client? | Phase 1: **no.** The user runs `ldbd --listen ...` once explicitly. Phase 2: client tries `connect()`, falls back to `fork+exec(ldbd --listen ...)` if `ECONNREFUSED`/`ENOENT`. |
| Auth? | uid-only via filesystem permissions (mode 0600 on the socket, parent dir 0700). No cross-user access. Document it; don't add token auth in phase 1. |
| Concurrent calls from multiple clients? | Dispatcher is already thread-safe enough for the read-only static surface (uses `impl_->mu`). Audit the mutable paths (probes, sessions, breakpoints) before exposing — possibly serialise per-target via a per-target mutex in phase 1. |

#### Trust model

Phase 1 explicitly assumes **the uid is a single trust domain**.
That assumption shapes every access-control decision in the daemon:

- Socket inode lives at mode 0600; parent dir at 0700 when the
  daemon creates it.
- The daemon refuses to use a pre-existing parent that is a symlink,
  is owned by another uid, or has group/other permission bits set.
- The sidecar lockfile is opened with `O_NOFOLLOW` to refuse a pre-
  staged symlink (otherwise a same-uid attacker could pre-create
  `${PATH}.lock` as a symlink to e.g. `~/.ssh/authorized_keys` and
  have our `ftruncate`+`pwrite(pid)` corrupt the symlink target).
- Every accepted connection is run through `getpeereid()`; peers
  whose uid differs from the daemon's are rejected before the first
  byte is read.
- Accepted connections carry a 300-second `SO_RCVTIMEO` so a stalled
  peer doesn't pin the daemon's accept loop indefinitely.

Explicitly **out of scope** for phase 1:

- **Shared-uid hosts.** Multi-tenant CI runners, NFS-homed uid where
  several humans share one account, LLM/agent sandboxes that run
  inside the daemon's uid — all of these collapse the trust
  boundary the phase-1 design relies on. Anyone wanting LDB in that
  shape should wait for phase 2.
- **Cross-uid access.** No SUID, no group-readable sockets, no
  cross-user proxying. The "two engineers share a host" pattern
  requires phase 2.

Phase-2 will add token auth (the daemon hands out a one-shot bearer
on startup; the client presents it before the first RPC) so the
shared-uid and cross-uid cases become tractable without re-doing
the filesystem permissions story.

#### Client side

`tools/ldb/ldb`:

```python
class DaemonSpec:
    local_ldbd: str | None
    ssh_target: str | None
    socket_path: str | None  # NEW

def spawn_daemon(spec, fmt, verbose):
    if spec.socket_path:
        return connect_socket(spec.socket_path, fmt, verbose)
    # ... existing ssh + local-exec paths ...
```

`connect_socket()` opens the unix socket, returns a fake `Popen`-like
object whose `stdin`/`stdout` are the socket's send/recv halves so the
existing `JsonTransport`/`CborTransport` plumbing works unchanged.

The CLI gets a new top-level option `--socket PATH` plus env override
`LDB_SOCKET`. Mutually exclusive with `--ssh` and `--ldbd`.

#### Tests

- `tests/smoke/test_socket_lifecycle.py`: start `ldbd --listen`,
  connect twice from two `ldb` processes, assert target_id from
  connection #1 is reachable from connection #2.
- Unit test for the listener's `flock` collision behaviour (two
  `ldbd --listen` on the same path → second exits 1).
- Tests for the file-mode and parent-dir-mode being uid-only.

### Risks

- **Concurrency audit is non-trivial.** Today's dispatcher assumes
  single-client semantics — one RPC at a time, completing before the
  next is read. Phase 1 mitigates by serialising all requests through
  a single per-daemon mutex (correct, dumb, slow); phase 2 can refine
  per-target.
- **Long-running daemon is a new failure mode** — a state leak in
  any endpoint that didn't matter when the daemon lived for ~50ms
  now lives for hours. Audit `Dispatcher` for `std::vector`s that
  only grow (e.g. event histories, diff caches).
- **`--listen` reuses the JSON-RPC framing but multiplexes connections
  over one dispatcher.** Notifications (`thread.event` etc.) currently
  go to one `OutputChannel`. We need per-connection sinks; the
  existing `notif_sink` plumbing in `src/main.cpp:288` is single-
  consumer. This is the biggest non-obvious work.

### Effort

Probably 2–3 days. Roughly:

- Day 1: socket-listener skeleton + flock + single-client path; tests.
- Day 2: notification-sink refactor for multi-client; concurrency
  audit + per-target serialisation.
- Day 3: client-side `--socket` + auto-spawn fallback + lifecycle
  tests (idle timeout, signal handling).

If this slips, phase-1 (single-client persistent socket) is the
useful core; phase-2 (multi-client + auto-spawn) can land as a
separate branch.

### Phase 2 — what shipped (this branch)

Phase-2 lands six items in order; see the commit log for the
individual SHAs and the rationale per piece.

1. **Multi-subscriber notification sinks** (runtime change).
   `NonStopRuntime` now owns a subscriber SET protected by
   `sinks_mu_`. Each connection registers its own
   `NotificationSink` via `add_notification_sink` and drops it on
   disconnect via `remove_notification_sink`. The pre-phase-2
   single-atomic-sink-pointer design was race-free only because
   phase-1 allowed at most one connection alive at a time.
   Post-review honesty fix (I1): the subscriber set is
   broadcast-to-all — every live subscriber receives every
   notification; per-target filtering happens at the client. The
   prior wording ("without cross-talk") implied server-side
   target_id routing, which is a phase-3 item. Subscriber storage
   is `std::shared_ptr<NotificationSink>` so a concurrent disconnect
   can't free a sink mid-emit (post-review C1 fix). The legacy
   `set_notification_sink(sink)` API survives as a clear-then-add
   shim for stdio mode.

2. **Multi-client socket listener.** `socket_loop.cpp`'s accept
   loop now spawns a `std::thread` per accepted connection. The
   shared `Dispatcher` serialises overlapping RPC service through
   a new `dispatch_mu_` outer mutex (acquired for the entire
   `dispatch()` lifetime). Documented concurrency audit:
     - `LldbBackend::Impl::mu` (existing): every public method
       takes it; phase-3 chained-fixups branch's mu-drop-during-
       file-IO pattern stays intact.
     - `ProbeOrchestrator::mu_` (existing): every public method
       takes it; callback paths re-acquire on re-entry.
     - `SessionStore`, `ArtifactStore`: each has its own internal
       mutex around sqlite. Single-writer assumption preserved
       by WAL.
     - `NonStopRuntime`: state-map shared_mutex + the new
       subscriber-set shared_mutex.
     - `Dispatcher`'s own mutable state (target_main_module_,
       diff_cache_, cost_samples_, python_unwinders_,
       rsp_channels_, active_session_writer_) — NOT thread-safe,
       now covered by `dispatch_mu_`. Phase-3 refinement could
       shard by target_id; not done here because the dispatcher
       state would need to migrate to a per-target map first.

3. **Client-side auto-spawn.** `tools/ldb/ldb` detects
   ECONNREFUSED / ENOENT / ENXIO on the unix-socket connect()
   and `fork+exec`s `ldbd --listen unix:PATH` detached
   (`start_new_session=True` ⇒ setsid; stdin/stdout/stderr all
   redirected to /dev/null to avoid pipe-inheritance hangs in
   wrappers that capture_output the CLI; `LDB_LDBD_LOG_FILE`
   redirects stderr instead for operators who want diagnostics).
   Spawned daemon outlives the client. Resolution order for the
   ldbd binary: `$LDB_LDBD_SPAWN` → `shutil.which("ldbd")` →
   sibling-of-`ldb` heuristic.

4. **Signal-driven accept-loop wakeup.** A self-pipe
   (`g_shutdown_pipe`) replaces the bare `accept()` with
   `poll(srv, pipe)`. The signal handler writes a byte (write(2)
   is async-signal-safe); the accept loop wakes on POLLIN,
   drains the pipe (both ends are `O_NONBLOCK` so the drain
   loop terminates with EAGAIN), and checks `g_shutdown`.
   Documented scope: shutdown stops accepting new RPCs
   immediately but lets the currently-executing dispatch run to
   completion — interrupting an in-flight LldbBackend SBAPI
   call from outside is genuinely impossible against the LLDB
   ABI.

5. **`--listen-idle-timeout N`.** Opt-in shutdown when no
   workers are alive and no new connection arrives within N
   seconds. The accept loop's `poll()` timeout becomes
   `N * 1000ms` when `live_workers == 0`; on `poll() == 0`, the
   loop rechecks live_workers (closing the race where a worker
   raced in during the gap) and, if still zero, exits cleanly.
   A new atomic `g_live_workers` is bumped before
   `std::thread` construction and decremented on worker exit;
   workers write a wake byte to the self-pipe on exit so the
   accept loop re-evaluates the timeout on platforms where
   `poll`'s deadline survives spurious wakes.

6. **`daemon.shutdown` RPC.** Dispatcher endpoint that invokes
   a callback wired by `socket_loop.cpp` (sets `g_shutdown` +
   writes to self-pipe). Returns -32002 with a "not supported
   in this mode" message when run under `--stdio` (no
   callback). Listed in `describe.endpoints`. The reply
   (`{ok:true}`) is sent first; the accept loop's poll wakes
   on the next byte from the self-pipe.

### Phase 3 — carried forward

Items deferred from the phase-2 work, in roughly priority order:

- **Token auth for shared-uid environments.** Phase-1's trust
  model (above) excludes shared-uid hosts. Phase-3 sketch:
  daemon writes a one-shot bearer to `${PATH}.token` (mode
  0600) at startup; the client reads it and presents it on the
  first frame; daemon rejects connections that don't present
  it. The token rotates on restart.
- **Target_id-aware notification routing.** Phase-2's subscriber
  set is broadcast-to-all: every live `OutputChannel` receives
  every async notification regardless of which target_id it
  originated from. Clients filter by `params.target_id` today.
  Phase-3: have `NonStopRuntime` accept a target_id filter at
  subscription time so the daemon does the filtering and per-
  client traffic stays scoped to the targets they actually opened.
- **Per-target dispatcher sharding (true per-connection
  parallelism).** Phase-2 serialises all dispatch through
  `dispatch_mu_`, so two clients hitting separate target_ids
  still queue at the dispatcher. The dispatcher's per-target
  mutable state (target_main_module_, the diff cache keyed by
  snapshot, the cost-samples ring) would migrate to a per-target
  map under a per-target mutex; the truly-global pieces
  (active_session_writer_, recipe loader bookkeeping) stay under
  the outer mutex. Phase-3 problem, not phase-2: today's workloads
  don't appear to spend significant time contended on
  `dispatch_mu_`.
- **True in-flight RPC cancellation.** Phase-2 stops accepting
  new RPCs on shutdown but waits for in-flight workers to
  finish their current dispatch. LLDB SBAPI calls aren't
  externally interruptible against the binary ABI; a real
  cancellation story would require an `SBHostInterrupt`-style
  shim plus dispatcher-side cooperation. Out of scope for
  socket-daemon work; tracked separately.
- **Worker reaping mid-flight.** Today the worker thread list
  grows for the daemon's lifetime; phase-2 only joins on
  shutdown. A long-lived daemon servicing many short-lived
  connections accumulates `std::thread` state until exit.
  Negligible at realistic session counts (~24 bytes per
  entry) but a 20-line refactor away if it ever matters: each
  worker posts its `thread::id` into a `done_ids` deque under
  `done_mu` before returning; the main loop's idle paths join
  + erase any threads in that list. Sketch left in
  `socket_loop.cpp`'s `reap_finished_workers` lambda.
- **TLS / cross-host transports.** Out of scope for socket-
  daemon; the existing `--ssh` knob plus the socket path
  inside the SSH tunnel covers the practical cross-host
  story.
- **Connection multiplexing within a single client.** One
  client opening N parallel RPCs over one socket is a phase-3
  story that requires both ID-tagged request/response routing
  and a per-channel dispatcher state model. Not on any
  current roadmap.

---

## 3. ARM64e chained fixups for selrefs / xref indexing

### Problem

On iOS 13+ / macOS 11+ ARM64e binaries, pointer-bearing sections
(`__objc_selrefs`, `__objc_classrefs`, `__got`, `__auth_got`, etc.)
no longer store raw VAs. Each 64-bit slot is a chained-fixup
descriptor:

```
[63]    bind/rebase flag
[62:51] next chain link offset (0 = end of chain)
[50:32] auth diversifier + key
[31: 0] rebase target offset (relative to image base) OR bind ordinal
```

Exact layout is per the `dyld_chained_fixups_header` + `dyld_chained_ptr_64e`
union in `<mach-o/fixup-chains.h>`. The OS's dyld applies these at load
time; static-analysis tools see only the encoded form on disk.

LDB's xref and string-xref pipelines (`xref.address`, `string.xref`,
the symbol-index correlation passes) scan section bytes looking for
literal 64-bit VAs that match a target. On a chained-fixup binary,
**none of the values in the relevant sections are literal VAs**, so
LDB silently produces zero or wrong results. Field report: the
reporter routed around LDB and wrote a custom ARM64 disassembler.

### Proposed approach

A new pre-pass in the symbol indexer (see `docs/23-symbol-index.md`)
that materialises a per-module "logical pointer map":

```cpp
// new include/ldb/backend/chained_fixups.h
namespace ldb::backend {

// Parse LC_DYLD_CHAINED_FIXUPS from a module's bytes; for each pointer
// slot in the rebase/bind regions, compute the logical pointer value
// that dyld would have written.
struct ChainedFixupMap {
  // file_addr → logical pointer value (image_base + rebase_offset for
  // rebases; bind_target_addr for binds with a resolved symbol;
  // 0 for unresolved binds).
  std::unordered_map<std::uint64_t, std::uint64_t> resolved;
};

ChainedFixupMap parse_chained_fixups(const lldb::SBModule& m);

}  // namespace ldb::backend
```

The map is built once per module (cached under
`symbol_index.cache_root/<build_id>/fixups.bin`) and consulted by:

- `xref_address` — before treating a 64-bit slot as a literal pointer,
  look up the resolved value from the map.
- `find_string_xrefs` — same.
- `correlate.symbols` / `correlate.strings` — same.

### Implementation sketch

1. **Load command iteration.** `SBModule::GetObjectFileHeaderAddress()`
   + raw byte reads of the `LC_DYLD_CHAINED_FIXUPS` segment-relative
   payload. LLDB's SBAPI doesn't expose the chained-fixup tables
   directly, so this is byte-level Mach-O parsing.
2. **Header parsing.** `dyld_chained_fixups_header` →
   `dyld_chained_starts_in_image` → per-segment
   `dyld_chained_starts_in_segment` → per-page chain start.
3. **Chain walking.** For each starting page offset, walk the chain
   via `next` deltas, decoding each 64-bit value as either a rebase
   or a bind. Stop when `next == 0`.
4. **Materialisation.** Rebases resolve to `image_base + target_offset`;
   binds resolve via the imports table to a symbol whose load address
   may or may not be known (return 0 if unknown — caller-of-callers
   can filter).
5. **Cache invalidation.** Keyed on the module's build-id; immutable.

### Phase 1 — what shipped (commits `1c0c8bb`, `359e738`, `d99cff9`)

- `include/ldb/backend/chained_fixups.h` — public `parse_chained_fixups()`
  + `ChainedFixupMap` (rva-keyed) + `SegmentInfo` callers populate from
  Mach-O LC_SEGMENT_64s.
- `src/backend/chained_fixups.cpp` — header walk, per-segment chain
  walk, ARM64E (formats 1/9/12) + PTR_64 / PTR_64_OFFSET (formats 2/6)
  decode. Multi-start pages, 32-bit formats, and bind resolution all
  throw `phase 2` errors.
- `tests/unit/test_chained_fixups.cpp` — five hand-built vectors
  covering single-page, multi-page, auth-rebase, USERLAND, and the
  unsupported-format error path.

### Phase 2 — what shipped (this branch)

The minimal wire-up needed to stop `xref.address` returning empty on
chained-fixup binaries. Real iOS app validation deferred to phase 3.

- `include/ldb/backend/chained_fixups.h` — new
  `extract_chained_fixups_from_macho(bytes, size)` helper. Walks
  `LC_SEGMENT_64` + `LC_DYLD_CHAINED_FIXUPS` from raw Mach-O bytes;
  returns empty map on non-Mach-O / no-chained-fixup inputs (Linux
  ELF, FAT binaries, classic LC_DYLD_INFO_ONLY) so callers can wire
  it unconditionally without a Mach-O sniff.
- `src/backend/lldb_backend.cpp` — `LldbBackend::Impl` gets
  `chained_fixup_maps` / `chained_fixup_loaded` per-target caches
  (lazy-init on first xref query; reaped in `close_target`). No
  on-disk cache — phase 3.
- `xref_address` — keeps the literal-operand + RIP-relative scans
  intact, then runs an ARM64 ADRP-pair resolver. ADRP records the
  absolute target page per destination register; the next consumer
  (`add xN, src, #imm` or `ldr xN, [src, #imm]`) computes
  `page + imm`. The target is matched against (a) the caller's
  needle directly, and (b) the chained-fixup map's `slot_rva →
  resolved_value` table for LDR-style consumers (slot-load
  indirection). Results from all paths are deduped by instruction
  address. Logic is sequential, single-pass — no liveness analysis;
  the "last ADRP wins for this register" heuristic matches what
  compiler-emitted ADRP+immediate-use code expects.
- `tests/unit/test_chained_fixups.cpp` — two new cases covering the
  Mach-O extractor: null / ELF magic → empty map; minimal arm64
  Mach-O with one segment + one LC_DYLD_CHAINED_FIXUPS round-trips
  through Vector A's payload.
- `tests/fixtures/c/chain_slot.c` + `tests/smoke/test_xref_chained_fixup.sh`
  — Apple-silicon-arm64-gated synthetic fixture. A pointer slot in
  `__DATA/__data` rebases to a string in `__TEXT/__cstring`;
  `reference_string()` loads through the slot via ADRP+LDR. Smoke
  test pins both `xref.addr` and `string.xref` against the string's
  file address. Without the wire-up the result is empty; with it,
  the LDR inside `reference_string` is surfaced.

### Phase 3 — acceptance criteria for the ADRP-pair resolver

The phase-2 resolver is a "last ADRP wins for this register" heuristic.
That subsumes the common compiler-emitted single-def-then-immediate-use
case but produces false positives across control flow (calls clobber
caller-saved regs; branches end basic blocks). Phase 3 closes those
gaps. Acceptance gates:

- **BL / BLR** clears `adrp_regs` entries for `x0`–`x18` and `x30`
  (AAPCS64 call-clobber set — anything else is callee-saved and may
  still hold the prior ADRP).
- **RET / unconditional B / BR Xn** clears all of `adrp_regs` (function
  boundary; the next block can't safely assume any prior page).
- **ADD `dst, src, #imm`** with `src != dst`: clears `adrp_regs[dst]`.
  Phase 3 does NOT propagate the chain through arithmetic — modelling
  proper dataflow (especially through SXTW / LSL shifts) is out of
  scope. The clear is the conservative answer.
- **ADD `dst, dst, #imm`**: clears `adrp_regs[dst]` for the same
  reason — the value is no longer the ADRP page.
- **MOV `dst, src`**: clears `adrp_regs[dst]` unless `src` is also
  tracked (in which case propagate the page through MOV). The simple
  shape is the only one worth modelling — anything register-to-register
  with a shift is real dataflow.
- **FAT (universal) Mach-O**: parse the slice matching the SBTarget's
  triple (or, if absent, prefer arm64e over arm64 over x86_64) instead
  of returning an empty fixup map. Today extract_chained_fixups_from_macho
  silently no-ops on FAT magic.
- **Adversarial smoke tests**: at minimum cover call-clobber (ADRP →
  BL → LDR-against-stale-register), cross-function (function boundary
  doesn't carry ADRP state forward), and ADD-then-LDR (LDR against an
  ADD-derived address that phase 3 must NOT resolve). The phase-2
  fixture (`chain_slot.c`) only exercises the happy path; the
  regression bar for phase 3 is **zero false positives** from these
  patterns.
- **`provenance.warnings` field** on `xref.address` responses: count
  of "ADRP-pair resolutions skipped due to ambiguity" (e.g. a tracked
  ADRP that was clobbered by an untracked instruction between def and
  use). A non-zero count surfaces to the caller that the heuristic
  isn't authoritative on this binary, which the agent can use to
  prefer the chained-fixup map or fall back to symbol-index correlate.

### Phase 3 — what shipped (this branch)

All seven acceptance gates above closed. Commits on the phase-3
branch (each addresses one or more gates):

- **TDD-red fixtures** (commit `adc083a`): three hand-assembled
  ARM64 fixtures (`tests/fixtures/asm/xref_{addclobber,fnleak,
  callclobber}.s`) + Python smoke drivers
  (`tests/smoke/test_xref_{addclobber,fnleak,callclobber}.py`)
  reproducing the phase-2 false positives. Built and tests added
  before the implementation; they FAILED against `25f35de` with the
  expected single-match output.

- **ADRP-pair register-state clobber rules** (commit `7419945`):
  gates 1 (function-boundary reset, lazy `function_name_at`), 2
  (AAPCS64 BL/BLR caller-saved set), 3 (ADD always clears dst), 4
  (MOV propagate-or-clobber). All three adversarial smoke tests
  flip to green; ctest 73/73.

- **FAT (universal) Mach-O slice selection** (commit `eebebca`):
  gate 5. Refactored thin-Mach-O walk into a helper; new FAT
  dispatcher iterates fat_arch[] / fat_arch_64[], prefers arm64e
  > arm64. Three new unit tests cover slice picking, arm64e
  preference, and malformed-FAT rejection.

- **`provenance.warnings` field** (commit `c01fa47`): gate 7.
  `XrefProvenance` struct in `debugger_backend.h`; xref.address
  takes an optional out-param. Dispatcher attaches the provenance
  block to the response only when something was skipped. Phase 3
  populates one case (register-offset LDR with tracked base);
  phase 4 will accumulate more.

### Phase 3 — post-review cleanup (this branch, post-`96d079b`)

A linus-style review of the five phase-3 commits surfaced a punch
list of silent false-positive vectors and false-negatives in the
same family the spec was meant to close. Every reviewer-flagged
item landed on this branch:

- **SUB clobber** (commit `f57b16c`): `sub xN, xN, #imm` has
  identical destination-write semantics to ADD but was missed by
  the original phase-3 patch. Extend gate 3 to cover ADD / SUB /
  ADDS / SUBS; only ADD has a match-emit (no compiler computes
  targets as `page - imm`). New fixture
  `tests/fixtures/asm/xref_subclobber.s` + smoke.

- **PAC-authenticated branch family** (commit `62b6e47`): arm64e's
  BLRAA / BLRAB / BLRAAZ / BLRABZ are AAPCS64 calls — same clobber
  set as BL / BLR — and BRAA / BRAB / BRAAZ / BRABZ end basic
  blocks like BR, and RETAA / RETAB end functions like RET. The
  original phase-3 matched only bare spellings. Refactor the post-
  emit switch to use `is_call` / `is_indirect_branch` /
  `is_return` named flags that fold in the PAC variants. New
  fixture `tests/fixtures/asm/xref_pac_callclobber.s` — gated on
  the arm64e toolchain (CMake `CheckCSourceCompiles` probe;
  fixture built thin via `OSX_ARCHITECTURES` override to avoid the
  default fat-slice path that downcasts to arm64).

- **Pre/post-indexed LDR/STR writeback** (commit `8e46141`):
  `ldr xN, [xM, #imm]!` (pre) and `ldr xN, [xM], #imm` (post)
  rewrite the base register as a side effect. The phase-3 resolver
  emitted the match for the legitimate effective address but never
  cleared `adrp_regs[xM]`, leaving a downstream LDR free to false-
  match the stale page. New `AdrpResolved::has_writeback` /
  `writeback_base` fields; post-emit clobber + provenance
  `adrp_pair_writeback_cleared` counter + human-readable warning.
  Fixture exercises both shapes.

- **STR / STUR / STRH / STRB / STP / LDUR consumers** (commit
  `306363a`): phase 3 modelled only LDR-family loads, so stores
  through an ADRP-tracked base were invisible to `xref.addr` — a
  user asking "what writes to this global?" got an empty answer.
  Refactor the address-operand parsing into a reusable helper
  (`parse_adrp_addr_operand`); collapse the resolver into three
  buckets (is_load, is_store_one_reg, is_store_pair) that share
  the same parser. STP gets a two-register prefix-skip. Fixture
  covers STR / STP / STRB.

- **Nits N5–N10** (commit `01494da`): apply_mov_state return-value
  used to short-circuit `resolve_adrp_consumer`; AAPCS64 clobber
  replaced with allocation-free iterate-and-erase + predicate
  helper; MOV source classifier replaces the brittle first-char
  heuristic with explicit alias-name comparison; FAT64 unit test
  for the `0xCAFEBABF` magic + 32-byte `fat_arch_64` path that
  the prior FAT tests left uncovered; FAT slice picker comment
  documents the empty-map fallthrough hazard (phase-4 follow-up:
  thread SBTarget's triple through the extractor); x29/x30
  comment fixed to state AAPCS64 callee-saved semantics
  correctly.

Post-cleanup ctest: 77/77. Eight phase-3 smokes (the original
three plus xref_subclobber, xref_writeback_ldr, xref_str,
xref_pac_callclobber, and the FAT64 unit test) all pass.

### Phase 4 — what shipped (this branch)

Seven items closed. Each commit on the phase-4 branch lands one
acceptance gate; ctest 85/85 at branch tip.

- **MOV-source classifier lift** (commit `fdbd1d5`): item 5.
  Move `MovSrcKind` + `classify_mov_source` out of
  `lldb_backend.cpp`'s anonymous namespace into
  `xref_arm64_parsers.{h,cpp}` so unit tests can pin the alias-
  name-first match order (xzr / wzr / sp / wsp / lr token-compared
  BEFORE the prefix heuristic). Seven new unit tests under
  `[xref][arm64]` cover the zero, immediate, stack-pointer,
  link-register, xN/wN, and kOther arms. No behaviour change;
  the lifted function is byte-identical to the previous in-place
  implementation. 33 assertions / 13 cases pass.

- **Conditional-branch boundary reset** (commit `311c439`):
  item 1. Phase 3 reset adrp_regs on RET / unconditional B / BR
  only. Phase 4 adds a check for conditional branches (b.cond /
  cbz / cbnz / tbz / tbnz) whose target sits in a different
  function — the scanner parses the target operand (LLDB renders
  it as `0xNNNNNNN`), resolves to a function name, and resets
  adrp_regs when distinct from the current function. Skip the
  parse when adrp_regs is empty (function_name_at dominates
  cost). New provenance counter `adrp_pair_cond_branch_reset`
  signals when the path fires. Provenance schema also opens
  `adrp_pair_function_start_reset` (item 3) and
  `adrp_pair_unresolvable_load` (item 4) so the dispatcher
  serialisation path doesn't need a second pass. Smoke fixture
  `xref_condbranch.s` + `test_xref_condbranch.py` pin the
  counter bump.

- **FAT triple-aware slice picker** (commit `f10c04c`): item 2.
  Phase 3's picker preferred arm64e > arm64 unconditionally; FAT
  binaries where LLDB loaded the arm64 slice but the picker chose
  arm64e produced zero matches due to image_base mismatch.
  Phase 4 adds an optional `std::string_view triple` parameter to
  `extract_chained_fixups_from_macho()`; the dispatcher passes
  `SBTarget::GetTriple()` through; the picker classifies the
  triple ("arm64e-" / "arm64-" / "x86_64-") into the preferred
  (cpu_type, cpu_subtype) pair and tries the matching slice
  first. ARM64_ALL (subtype 0) match also accepts ARM64_V8
  (subtype 1) — the LLDB triple "arm64-" can land on either
  subtype. Falls back to phase-3 preference order on empty
  triple, unknown arch, or matching slice without chained fixups.
  Four new unit tests under `[chained_fixups][macho][fat][triple]`
  pin arm64 triple → arm64 slice, arm64e triple → arm64e slice,
  empty triple → phase-3 default, missing-matching-slice → phase-3
  fallback. 18/18 [chained_fixups] tests pass.

- **Stripped-binary function-start backstop** (commit `9b820b1`):
  item 3. Phase 3's gate 1 uses `function_name_at()` to detect
  function boundaries; in a stripped Mach-O without LC_SYMTAB
  local symbols, `function_name_at` would return "" for adjacent
  functions and gate 1 silently treats them as one. Phase 4
  records every B / BL / conditional-branch target inside the
  current code section as a function-start hint. The check fires
  BEFORE gate 1: when the scanner reaches an instruction whose
  address is in the `function_starts` set, adrp_regs resets and
  the new `adrp_pair_function_start_reset` counter bumps. (On
  macOS / Apple-silicon LLDB synthesises `___lldb_unnamed_symbol_<addr>`
  names so gate 1 still works; phase 4's set is the backstop for
  platforms or patterns where synthesised names don't disambiguate.)
  Smoke fixture `xref_stripped_fnleak.s` uses `strip -x` post-link
  to drop the local function labels; the smoke asserts zero false-
  positive matches (gate 1 + function_starts together; correctness
  is what matters, not which path fired).

- **PC-relative literal-load provenance** (commit `c83d3b0`):
  item 4. Phase 3's gate 7 bumped `adrp_pair_skipped` for register-
  offset LDRs with a tracked base. Phase 4 extends the family to
  PC-relative literal loads (`ldr xN, #imm` / `ldr xN, 0xNNNN`)
  which bypass the ADRP+pair pattern entirely. Detection shape
  fires in the "memop didn't match resolve_adrp_consumer"
  fallback when the operand is immediate-shaped (`#` / `0` / `-`)
  rather than the `[xN, ...]` bracket. New
  `adrp_pair_unresolvable_load` counter signals when the
  resolver gave up on a load. Smoke fixture `xref_pcrel_literal.s`
  pins the counter bump.

- **BindInfo schema** (commit `31121eb`): item 6 (scope-guard
  invoked). The phase-4 spec allowed shipping only the schema if
  the imports-table walk became too complex for one branch. The
  walk spans three import-record formats (DYLD_CHAINED_IMPORT /
  _IMPORT_ADDEND / _IMPORT_ADDEND64), ordinal indexing, string-
  table lookup, optional SBTarget::FindSymbols, and runtime
  resolved_addr semantics — roughly 150 LOC of byte-level parser
  across three layouts. Ship only the schema additions:
    * New `BindInfo` struct: name, addend, ordinal, resolved_addr.
    * New `ChainedFixupMap::binds` map: rva → BindInfo, populated
      by phase 5's walk; today's parser leaves it empty.
  Three new unit tests pin the empty defaults. Phase 5 wires the
  actual walk and flips these to populated.

- **Real-binary validation fixture** (commit `5de6798`): item 7.
  A moderate-size C-compiled fixture (`tests/fixtures/c/real_world_xref.c`)
  exercising the resolver in shapes closer to real iOS app
  binaries: static const string table with selref-style ADRP+LDR
  through __DATA_CONST chained-fixup slots, multiple functions in
  one TU, a conditional-branch tail-call to a different function,
  malloc/free imports. Built with `-O1 -Wl,-fixup_chains` so the
  string table becomes a chained-rebase region. Smoke test pins
  every k_string_table[] entry surfaces at least one xref and a
  non-pointer literal returns zero false positives. Spot-check
  against `/usr/bin/uname` (arm64e-apple-macosx26.3.0; FAT picker
  selected the arm64e slice correctly) — 8 sampled strings each
  returned 1 xref with empty provenance. Documented as a manual
  probe rather than CI assertion because system binaries change
  across macOS versions.

### Phase 5 — carried forward

Items not in phase-4 scope or deferred from phase-4's scope guard:

- **Bind resolution (full)** — phase 4 shipped the BindInfo schema
  and ChainedFixupMap::binds map; the imports-table walk (three
  formats, ordinal lookup, string-table dereference, optional
  SBTarget::FindSymbols for resolved_addr) is phase 5. Phase 5
  populates binds for every chain entry and surfaces them as
  xrefs when target_addr matches a bound symbol's resolved
  address.

- **Auth-rebase key-class filtering** — phase 3/4 don't
  distinguish PAC key classes on rebase slots. A consumer that
  uses `__auth_got` indirection vs `__got` is conflated.

- **On-disk cache** of the fixup map keyed on `build_id` — phase
  2's per-target rebuild is cheap at fixture scale (~1 ms on
  33 KB) but a real WeChat-class binary (500 MB+) needs
  measurement before deciding the cache substrate.

- **`correlate.symbols` / `correlate.strings`** wire-up. The
  symbol-index path doesn't consult the fixup map yet — it scans
  raw section bytes and treats them as literal pointers.

- **Multi-module support.** `xref_address` only scans the main
  executable (module index 0).

- **Full dataflow analysis** — basic-block CFG + liveness instead
  of the single-pass last-ADRP-per-register heuristic. The phase-4
  conditional-branch reset and function_starts backstop are the
  conservative answer; full CFG would close the
  back-branch-into-same-page-register edge case but materially
  changes the resolver's cost model.

- **Real iOS .ipa smoke (CI)** — phase 4 added the C fixture and
  documented a manual `/usr/bin/uname` probe. CI assertions on
  real iOS binaries are licence-sensitive and platform-fragile;
  defer to spot-checks documented in the worklog.

### Out of scope (phase 2)

Carried over to phase 3 (most of these now live in the phase-4
list above):

- **On-disk cache** of the fixup map keyed on `build_id`. Today the
  map is rebuilt on every `target.open`. Cheap enough at fixture
  scale (33 KB binary → ~1 ms); needs measuring on real WeChat-
  scale targets before deciding the cache substrate.
- **`correlate.symbols` / `correlate.strings`** wire-up. The symbol-
  index path doesn't consult the fixup map yet — it scans raw
  section bytes and treats them as literal pointers.
- **Bind resolution.** Phase 1 records `slot_rva → 0` for binds; the
  imports table parse + lazy load-address resolution lives in
  phase 3 once the symbol-index has a stable cross-module surface.
- **Multi-module support.** xref_address only scans the main
  executable (module index 0), same as before phase 2.
- **WeChat-scale validation.** Synthetic fixture is sufficient for
  this branch. Real iOS app smoke is a separate work item; the
  symptom in the field report is the slot-load case the fixture
  reproduces.

### Test plan

Real iOS Mach-O fixtures are licence-sensitive and large; ship a
**synthetic ARM64e binary** instead:

- A tiny C++ program with one Obj-C++ TU containing 3–4 selectors.
- Compile with `clang -arch arm64e -mmacosx-version-min=11.0
  -fuse-ld=lld -Wl,-fixup_chains`.
- Verify `LC_DYLD_CHAINED_FIXUPS` is present via `otool -l`.
- Add to `tests/fixtures/`; CMake target gated on `arch=arm64e` host
  capability.

Tests:

- Unit: feed known LC_DYLD_CHAINED_FIXUPS bytes through
  `parse_chained_fixups()`; assert the resolved map matches the
  pre-dyld values dumped by `dyld_info --fixups`.
- Smoke: `xref.address` against a selref pointer in the fixture
  returns the call site that loads it; without the fix, the same
  call returns empty.

### Risks

- **Spec drift.** Chained-fixup format has revved across iOS versions
  (v1 with `dyld_chained_ptr_64`, v2 with `dyld_chained_ptr_64e`,
  segmented chains, page-overflow fixups). The reference is
  `<mach-o/fixup-chains.h>` from the host SDK — track upstream
  cdefs. Phase 1 implements the most-common subset (ARM64E
  page-relative pointers); phase 2 covers split-segment and the
  legacy v1 binaries.
- **No SBAPI escape hatch.** We're parsing Mach-O bytes manually,
  parallel to LLDB. If LLDB later exposes a chained-fixup decoder
  via SBAPI, swap to it.
- **Cross-OS portability.** Linux ELF doesn't have an analogue; the
  pre-pass should no-op on non-Mach-O modules.

### Effort

Probably a week of focused work, dominated by:

- 1–2 days: fixture-generation pipeline.
- 2 days: parser + unit tests.
- 1 day: indexer wire-up + smoke.
- 1 day: cache-format + the "what happens on stale dyld_info"
  failure mode.

This is the largest of the three and the only one with cross-cutting
correctness implications. It should land *after* the symbol-index
work in `docs/23-symbol-index.md` matures so we have a stable caching
substrate to plug into.

---

## 4. Sequencing

Recommended order (smallest blast radius first; user value last):

1. **§1 CLI sibling lookup** — half-hour fix that gets the in-tree
   dev flow unstuck. No design risk.
2. **§2 socket daemon, phase 1 (single-client persistent)** — useful
   on its own; tests catch concurrency assumptions before phase 2.
3. **§3 chained-fixups parser**, behind a build flag
   (`-DLDB_ENABLE_CHAINED_FIXUPS=ON`) initially. Land after the
   symbol-index cache work; gate the new code path on
   `static.module_uses_chained_fixups()` so non-iOS workflows pay
   nothing.
4. **§2 socket daemon, phase 2 (multi-client + auto-spawn)** —
   ergonomics polish. Defer until phase 1 has shipped and we know
   whether anyone actually wanted multi-client.

§1 and §3 don't interact. §2 and §3 cross paths only if a
`--listen`-mode daemon is asked to handle a chained-fixup binary —
i.e. the long-running daemon walks the same code path the short-
lived one does, so no extra integration cost.

## 5. Out of scope (for all three)

- **CLI install target / packaging.** Separate concern; tracked in
  `docs/03-ldb-full-roadmap.md` under v2 distribution.
- **Windows host support.** Unix-socket transport assumes a unix
  domain socket; named pipes on Windows is a separate transport
  abstraction, not a phase-2 follow-up of §2.
- **GUI client / web UI.** The socket transport is a prerequisite for
  one, but the UI itself is a different project entirely.
- **Rewriting xref scanning in Rust / Capstone-only.** §3 lives
  inside whatever language the existing indexer uses (C++).
