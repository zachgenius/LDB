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
