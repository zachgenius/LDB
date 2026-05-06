# macOS arm64 — code-path status, validation gap, risk register

> Living audit of every code path in LDB that has macOS-specific
> behavior, the validation status of each, and what needs human
> sign-off on real macOS arm64 hardware before the MVP plan §1 line
> "macOS arm64 builds and runs (parity through SBAPI; not separately
> optimized)" can be promoted to a first-class, gate-tested claim.
>
> **This document was produced by a Linux-side audit only.** No
> assertions in this file are validated on macOS arm64 hardware. The
> reference dev box for this audit is Pop!_OS 24.04 / GCC 13.3.0 /
> LLVM 22.1.5 prebuilt tarball. Anything tagged "needs macOS sign-off"
> is taken on the strength of (a) static reading of the code, (b) the
> last macOS-validated commit recorded in `WORKLOG.md`, and (c) the
> SBAPI being a portable surface — none of which substitute for a
> real `ctest` run on Apple silicon.
>
> Last updated against `master` HEAD `c3b69c0` (post-1c-merge —
> Tier 1 §1 complete; Tier 1 §2 = this audit).

---

## 1. Audit methodology

Inventory was produced by these greps over `src/`, `include/`,
`tests/`, and `docs/`:

```
grep -rn '__APPLE__\|__linux__\|TARGET_OS_MAC\|_WIN32' src/ include/ tests/
grep -rn 'Mach-O\|debugserver\|__TEXT\|__DATA\|dyld\|SBPlatform' ...
grep -rn '\.dylib\|/Library/Developer\|/opt/homebrew' ...
grep -rn 'PIE\|ASLR\|rip_relative\|adrp\|RIP' ...
grep -rn 'eSectionTypeOther\|eSectionTypeDataCString\|is_data_section' ...
```

Each match was classified into one of:

- **PR1** — Mac-specific code we wrote (e.g. `maybe_seed_apple_debugserver`).
- **PR2** — cross-platform code that branches on / is sensitive to Mach-O semantics.
- **PR3** — documentation reference only (no runtime effect).
- **PR4** — recent Linux-targeted change that COULD have introduced a Mach-O regression.

Counts:

| Class | Count |
|------:|:------|
| PR1   | 1     |
| PR2   | 8     |
| PR3   | many (in worklog + docs; not separately tracked) |
| PR4   | 3 distinct findings (see §5) |

---

## 2. PR1 — explicitly Mac-specific code paths

### 2.1 `maybe_seed_apple_debugserver` (`src/backend/lldb_backend.cpp:269-291`)

**What it does:** Sets `LLDB_DEBUGSERVER_PATH` to an Apple-signed
`debugserver` binary (Command Line Tools or Xcode Resources) before
`SBDebugger::Initialize` runs. Wrapped in `#ifdef __APPLE__`; on
non-Apple platforms it compiles to a no-op.

**Why it exists:** Homebrew LLVM's distribution does NOT ship a
debugserver binary (worklog 2026-05-06, M2 setup). Without a signed
debugserver, `SBProcess::Launch` and `SBProcess::Attach` fail
silently with `"failed to launch or debug process"` and the agent has
no useful diagnostic. Auto-discovery makes the unit-test suite work
out of the box on Apple silicon.

**Last validated:** macOS arm64 ctest 23/23 PASS at the M3 closeout
(worklog cont. 14, 2026-05-06; commit `6c24a19` and earlier on the
M3 line). Build-time presence of `__APPLE__` is the only branch.

**Linux-side verification:** `__APPLE__` is undefined; the function
body compiles to `return;`. No effect on the Linux build. Confirmed
via the Linux dev-host bring-up (worklog 2026-05-06, commit `e1cf38f`
context — the function was present and compiled cleanly).

**Needs human sign-off if:** Apple Command Line Tools / Xcode are
installed at a path other than the two we probe
(`/Library/Developer/CommandLineTools/...` or
`/Applications/Xcode.app/...`). The function logs a warning in that
case; agents will see launches fail with the bare "could not find a
signed debugserver" message in stderr.

---

## 3. PR2 — cross-platform code with Mach-O-sensitive behavior

### 3.1 `is_data_section` (`src/backend/lldb_backend.cpp:679-701`)

**Mach-O behavior:** Accepts the typed `eSectionType*` family —
`eSectionTypeDataCString` covers `__TEXT/__cstring` /
`__DATA/__cstring`, `eSectionTypeData` and friends cover
`__DATA/__data`, `__DATA_CONST/__const`, etc.

**ELF behavior:** Adds an `eSectionTypeOther` branch that name-checks
`.rodata*` and `.data.rel.ro*`. **Deliberately does NOT accept all
`eSectionTypeOther`** (would scan `.interp` / `.plt` / `.eh_frame`
and produce noise — see worklog 2026-05-06, commit `e1cf38f`).

**Last macOS-validated:** Pre-`e1cf38f`, in the M3 closeout
(worklog cont. 14). The `e1cf38f` commit is purely additive on the
ELF side: it adds the `eSectionTypeOther` named branch but doesn't
touch the typed cases that Mach-O uses. Verified by reading the diff.

**Comment status:** Already commented on lines 670-678 — explains
both the Mach-O typed coverage and why we don't accept all
`eSectionTypeOther`. No new comment needed.

### 3.2 Section-name leaf-match in `string.list` (`src/backend/lldb_backend.cpp:809-836`)

**Mach-O behavior:** A caller passing `q.section_name = "__TEXT/__cstring"`
matches by full hierarchical name; passing `"__cstring"` matches by
leaf. Both forms work.

**ELF behavior:** A caller passing `".rodata"` matches the LLDB-invented
`PT_LOAD[2]/.rodata` via the leaf match; passing the full
`PT_LOAD[2]/.rodata` form also works. ELF callers generally can't
predict LLDB's segment-bracket numbering, so leaf match is mandatory
on Linux (worklog 2026-05-06, commit `e1cf38f`).

**Last macOS-validated:** Pre-`e1cf38f`. The leaf-match addition is
purely additive — the prior full-hierarchical-name match still
matches Mach-O `__TEXT/__cstring` if the caller uses that form. No
behavioral change to the macOS-typed path.

**Comment status:** Already commented (lines 810-815). No new comment
needed.

### 3.3 `xref_address` — RIP-relative vs ADRP+ADD (`src/backend/lldb_backend.cpp:1129-1162`)

**Mach-O / arm64 behavior:** ADRP+ADD pairs reference strings via
page-aligned + offset arithmetic. LLDB's disassembler annotates the
ADD instruction's COMMENT field with the resolved absolute hex
address (and often the quoted string itself). Detection runs through
the existing `string_references_address(i.comment, target_addr)` path
on line 1136 and the comment-text scan in `find_string_xrefs`
(lines 1232-1242).

**ELF / x86-64 behavior:** RIP-relative loads
(`leaq 0x2e5a(%rip), %rax`) carry an offset, not an absolute target.
The new `rip_relative_targets` helper (lines 1003-1085) parses the
offset, computes `next_insn_addr + signed_offset`, and matches against
the needle. Returns `false` immediately if the operand string contains
no `rip` / `RIP` substring.

**Mach-O regression risk for `rip_relative_targets`:** Audited.
arm64 instructions don't reference `rip`, so the early-return on
line 1008-1011 fires and the function returns `false`. **No false
positives or false negatives on Mach-O arm64.** Confirmed by static
read of the function — the only path to a `true` return requires
`window_has_rip(...)` to return `true`, which can't happen on arm64
operands.

**Last macOS-validated:** Pre-`e1cf38f`. The ELF helper is
*additionally* called from `xref_address` but NEVER a substitute for
the comment-text path. macOS arm64 continues to detect xrefs via the
absolute-hex path that Mach-O ADRP+ADD pairs already exercise.

**Comment status:** Already commented (lines 990-1002, 1117-1120,
1212). No new comment needed.

### 3.4 `string.list` recursion into Mach-O segment subsections (`src/backend/lldb_backend.cpp:777-787`)

**Mach-O behavior:** `__TEXT` is a *segment* containing subsections
(`__TEXT/__cstring`, `__TEXT/__text`, ...). The default scan must
recurse so cstring strings are reached. The recursion was added at
`a895cb9` (M2 string.list).

**ELF behavior:** No segment nesting. Recursion is harmless (most
ELF sections have no subsections).

**Comment status:** Already commented (lines 777-779). No new comment
needed.

### 3.5 Connect-remote listener pump (`src/backend/lldb_backend.cpp:1595-1621`)

**Mach-O / debugserver behavior:** Apple's signed `debugserver` may
deliver the initial stop synchronously, in which case `proc.GetState()`
already reflects a real state on the first iteration of the loop and
`break`s immediately.

**Linux / lldb-server gdbserver behavior:** Stop arrives as an event
on the listener; the loop pumps `WaitForEvent(1u, ev)` for up to 2s
until state settles out of `eStateInvalid` / `eStateConnected`.

**Last macOS-validated:** macOS arm64 ctest passed `target.connect_remote`
negative-path tests at M2 closeout (worklog cont. 10, 2026-05-06)
SKIPped the positive path due to Homebrew lldb-server crashing.
**The pump-listener loop has never run against debugserver on macOS.**
This is acceptable: if the stop is synchronous, the loop's first-iteration
break covers it; if the stop is event-driven, the same code that works
on Linux works against debugserver too (per SBAPI contract).

**Comment status:** Already commented (lines 1595-1601). No new
comment needed. Listed in §5 risk register as low-medium.

### 3.6 `compute_bp_digest` arch-agnostic patch byte (`src/backend/lldb_backend.cpp:2981-3032`)

**Mach-O / arm64 behavior:** SW breakpoints on arm64 use a `BRK #0`
opcode (not `0xCC`). The digest hashes a SENTINEL byte (`0xCC`) for
all arches — agreed canonical form. Cross-process equality holds
because both daemons hash the same sentinel for the same load address.

**ELF / x86-64 behavior:** SW breakpoints use `0xCC`, which happens to
match the sentinel. Agent-visible bytes via `mem.read` will see
`0xCC` on x86-64 and `BRK #0` on arm64; the digest is invariant under
arch.

**Comment status:** Already commented (lines 2961-2999). Cross-arch
contract is explicit.

**Risk:** None for Mach-O. The "patch byte" decision is a deliberate
cross-arch normalization, not a Linux-targeted assumption.

### 3.7 `compute_reg_digest` GPR-set name fallback (`src/backend/lldb_backend.cpp:2915-2924`)

**Mach-O / arm64 behavior:** The GPR set may be named "General Purpose
Registers" (the primary lookup on line 2915-2916), or potentially a
different label. The fallback on lines 2920-2923 picks the first
register set if the named lookup fails.

**ELF / x86-64 behavior:** Same — typically named "General Purpose
Registers". Confirmed working on Pop!_OS 24.04 against LLVM 22.1.5
(worklog 2026-05-06).

**Comment status:** Already commented (lines 2917-2919) — explicitly
mentions the platform variation.

**Risk:** Low. If macOS arm64 LLDB names the set differently AND
LLDB's set ordering doesn't put the GPR set first, the fallback
silently hashes a non-GPR set, producing a digest that doesn't
cross-match between daemons. **Needs sign-off via an explicit macOS
run of `tests/smoke/test_live_provenance.py`.**

### 3.8 SaveCore stdout guard (`src/backend/lldb_backend.cpp:1759-1777`)

**Mach-O / Darwin behavior:** `SBProcess::SaveCore` writes per-region
progress messages to stdout. The dup2-over-/dev/null guard prevents
JSON-RPC corruption.

**ELF / Linux behavior:** Same chatter on Linux (verified at M2
closeout). Same guard applies.

**Comment status:** Already commented (lines 1759-1762). The `Default
flavor "" lets LLDB pick the right format` comment on lines 1770-1771
covers the Mach-O-on-Darwin / ELF-on-Linux dispatch.

**Risk:** None. The guard is symmetric across platforms.

---

## 4. PR3 — documentation references only

The codebase has many comments, fixture-test docstrings, and worklog
entries that mention macOS, debugserver, Mach-O, dyld, etc. None
have runtime effect. These are not separately catalogued here; see
the worklog entries dated `2026-05-06 (cont. *)` for the M2/M3 macOS
provenance, and `2026-05-06 — Linux dev-host bring-up` (the moment
some Mach-O assumptions were de-baked on the Linux side).

---

## 5. PR4 — Linux-targeted recent changes audited for Mach-O regression

### 5.1 `e1cf38f` — `is_data_section` / leaf section-name match / `rip_relative_targets`

**Status:** AUDITED. Preserves macOS arm64 path.

- `is_data_section`: ELF branch is a `case eSectionTypeOther:` block
  added next to the existing typed-cases. Mach-O typed cases are
  untouched. **No regression.**
- Leaf section-name match: additive. Full-hierarchical-name match
  still wins first; leaf match is the new fallback. macOS callers
  passing `"__TEXT/__cstring"` still hit the full-name branch.
  **No regression.**
- `rip_relative_targets`: gated on `operands.find("rip")` early
  return. arm64 operands don't contain `rip` / `RIP`. The function
  is appended to the existing `string_references_address(operands,
  ...)` and `string_references_address(comment, ...)` checks, not
  replacing them. **No regression** — confirmed by static read.

The commit message itself ends with: "preserves macOS arm64 path
(no behavior change for typed sections / absolute-hex operands /
synchronous-stop servers)." The static audit agrees.

**Verdict:** Low regression risk. Smoke surface untouched on Mach-O.

### 5.2 `a466a64` — slice 1c dlopen invalidation: `tests/fixtures/c/dlopener.c` + `target_link_libraries(... dl)`

**Status:** AUDITED. **HIGH-PRIORITY MACOS REGRESSION RISK.**

The fixture introduced for the dlopen-invalidation test arc is
Linux-glibc-specific in two places:

1. **`tests/fixtures/CMakeLists.txt:53`** —
   `target_link_libraries(ldb_fix_dlopener PRIVATE dl)` injects
   `-ldl` into the link command. macOS does not have `libdl.dylib`
   as a separate library (dlopen is in libSystem); some macOS clang
   ld implementations silently accept `-ldl` via a stub `.tbd`
   file, others do not. Either way this is a Linux-specific
   linker flag with no positive effect on macOS.

2. **`tests/fixtures/c/dlopener.c:55`** —
   `dlopen("libpthread.so.0", RTLD_NOW | RTLD_GLOBAL)` is a glibc
   SONAME. macOS would expect `"libpthread.dylib"` (which is
   actually a re-export of libSystem and is always already loaded,
   so the test would always SKIP at the harness level). On macOS
   this returns NULL.

3. **`tests/smoke/test_live_dlopen.py`** has no platform SKIP. If
   the fixture builds, the test runs; if `dlopen` returns NULL,
   the inferior exits with `"dlopen failed: ..."` and the test
   fails — not SKIPs.

**Why this matters:** Any macOS user running `ctest` against this
HEAD will either fail to build (if `-ldl` is rejected by their ld)
or fail at `smoke_live_dlopen` runtime. **This is a regression of
the macOS-runs claim introduced by slice 1c.**

**Recommended fix (for a future macOS-validated session, NOT this
audit):**

- Wrap `target_link_libraries(ldb_fix_dlopener PRIVATE dl)` in
  `if(NOT APPLE)`.
- In `dlopener.c`, `#ifdef __APPLE__` use `"libcurl.dylib"` (or
  any DSO not pulled in by libc) and have the harness adjust its
  expected module name. OR: `#ifdef __APPLE__` print a marker that
  tells the harness to SKIP.
- In `tests/CMakeLists.txt`, gate `add_test(... smoke_live_dlopen)`
  on `if(NOT APPLE)` until the fixture is portable.

**This audit does NOT apply that fix** — per the brief, code
changes that can't be validated on Linux ctest are out of scope.
The fix must land in a session that has macOS hardware to verify.

**A pointer comment has been added to `tests/fixtures/CMakeLists.txt`
flagging the macOS gap.**

### 5.3 `de5db21` — slice 1c live↔core determinism gate

**Status:** AUDITED. Documents Linux-specific exclusions; macOS
behavior unknown.

`tests/smoke/test_live_determinism_gate.py` has an exclusion list
for endpoints whose `data` differs between live target and core
file. The exclusions are explicitly Linux-flavored:

- `module.list` — Linux core dumps surface a `[vdso]` module.
- `mem.regions` — Linux core dumps omit some VDSO/vsyscall mappings.
- `thread.list` — `name` is kernel-side metadata only on Linux.
- `triple` field difference — `"x86_64-unknown-linux"` vs
  `"x86_64-unknown-linux-gnu"`.

**On macOS arm64:** Mach-O cores have different coverage. There's
no [vdso], no /proc/PID/comm, and the triple format differs. The
test SKIPs cleanly if `process.save_core` returns
`saved=false` — which it should NOT on macOS, since SaveCore on
Mach-O is well-supported. So the test will run and the assertions
will hit the exclusion list.

**Risk:** Medium. The included endpoints are static / DWARF-driven
(`symbol.find`, `string.list`, `disasm.function`). These should be
byte-identical live↔core on Mach-O for the same reason as on ELF
(file_addr arithmetic over on-disk DWARF). But this has not been
verified on macOS arm64 hardware.

**Needs sign-off:** Run `ctest --test-dir build -R smoke_live_determinism_gate`
on macOS arm64 and confirm the included endpoints round-trip.

---

## 6. Known macOS limitations (do not need a "fix"; document and live with)

- **Homebrew LLVM 22.1.x ships a broken `lldb-server` on macOS arm64.**
  Live `target.connect_remote` against a locally-spawned `lldb-server
  gdbserver` SKIPs cleanly via the smoke test's port-probe (worklog
  2026-05-06 cont. 10). On real macOS workflows the agent should
  point `target.connect_remote_ssh` at `debugserver` on the remote
  via `remote_lldb_server`, since that's the only working server
  for Mach task interactions.

- **PIE + stop-at-entry on macOS arm64 leaves `__DATA` unrelocated**
  (worklog cont. 14, M3 closeout). Tests that dereference relocated
  pointers (e.g. `mem.dump_artifact` of a `k_marker` pointer)
  attach to a `pause()`'d sleeper instead. Tests that only need
  static layout (e.g. `mem.read` of a known address range) launch
  stop-at-entry. The existing test suite respects this.

- **Globals invisible from `_dyld_start` frame scope on macOS arm64**
  (worklog cont. 12). `resolve_root_identifier` falls back to
  `target.FindGlobalVariables` (lines 2244-2249). Confirmed working
  in `value.read` smoke at M2.

- **`StepOut` from `_dyld_start` returns the same PC** on macOS
  arm64 (worklog cont. 11). The `step` smoke test's PC-motion
  assertion is across the sequence of `insn → in → over → insn`,
  not per-call.

- **macOS Mach-O OSO debug info works without `.dSYM`** (worklog
  M1 entry, 2026-05-06). LLDB resolves DWARF from the original `.o`
  files via `LC_OSO` load commands. No fixture needs `dsymutil`.

---

## 7. macOS arm64 first-class sign-off checklist

Before MVP §1 line "macOS arm64 builds and runs" can be promoted to
a first-class, gate-tested claim, the following must succeed on
real Apple silicon hardware (M1/M2/M3/M4 Mac):

- [ ] Clean checkout of the worktree builds with `cmake -B build -G
  Ninja && cmake --build build` against Apple clang. **Including
  `tests/fixtures/c/dlopener.c`** (resolves §5.2 finding).
- [ ] `ctest --test-dir build --output-on-failure` is 39/39 PASS
  (or N/N with a documented set of intentional SKIPs, e.g.
  `target.connect_remote` positive path due to Homebrew
  lldb-server).
- [ ] **`smoke_live_dlopen` either passes or has a portable SKIP**
  on macOS (resolves §5.2 finding).
- [ ] **`smoke_live_determinism_gate` passes** on macOS — the
  static-DWARF endpoints (`symbol.find`, `string.list`,
  `disasm.function`) round-trip live↔core byte-identically
  (resolves §5.3).
- [ ] **Reference workflow §5 of `02-ldb-mvp-plan.md`** runs
  end-to-end against the structs/sleeper fixtures: static struct
  recovery → passive probe → stub responder iteration → live
  attach → memory extraction. This is the acceptance test for the
  whole MVP — never validated on macOS arm64 in the current run.
- [ ] Build is warning-clean under Apple clang's `-Wall -Wextra
  -Wpedantic -Wshadow -Wconversion -Wsign-conversion` (worklog
  M3 entry confirms it was at M3 closeout; we have not re-checked
  since the post-1c `master`).
- [ ] Stop-at-entry semantics match the Linux behavior for the
  endpoints we test. Specifically: `process.launch
  stop_at_entry=true` lands in `_dyld_start`; live snapshot's
  `<gen>` starts at 0; subsequent `process.continue` bumps `<gen>`.
- [ ] `LDB_DEBUGSERVER_PATH` is set automatically via
  `maybe_seed_apple_debugserver` and the daemon launches inferiors
  without manual env config.

When this checklist is green on macOS arm64, surface a follow-up
slice in `POST-V0.1-PROGRESS.md` to mark Tier 1 §2 as ✅ and update
`02-ldb-mvp-plan.md` §1.

---

## 8. Risk register — ordered by regression likelihood

| # | Finding | Likelihood | Severity | Notes |
|---|---|---|---|---|
| 1 | §5.2 — `dlopener` fixture `-ldl` + glibc SONAME | **HIGH** | **HIGH (build break)** | Fixture introduced in slice 1c (`a466a64`); Linux-only assumptions. macOS build / ctest will fail until fixed. Pointer comment added in `tests/fixtures/CMakeLists.txt`. |
| 2 | §5.3 — live↔core determinism gate exclusion list is Linux-flavored | MEDIUM | LOW (test-only) | Test will run on macOS; included endpoints (`symbol.find`, `string.list`, `disasm.function`) likely round-trip OK but not proven. |
| 3 | §3.7 — `compute_reg_digest` GPR-set name | LOW-MEDIUM | LOW (cross-process determinism only) | Fallback to "first set" handles name variation, but ordering on macOS LLDB unproven. |
| 4 | §3.5 — `connect_remote_target` listener pump on `debugserver` | LOW | LOW | Synchronous-stop case covered by the loop's first-iteration break. Never run live on macOS; only the Linux lldb-server path is exercised. |
| 5 | §6 — Homebrew `lldb-server` broken on macOS arm64 | KNOWN | LOW (positive-path SKIP) | Workaround: route via `target.connect_remote_ssh` to a remote that has `debugserver`. |

---

## 9. What this audit DID and DID NOT do

**Did:**

- Inventoried every `__APPLE__`, `__linux__`, Mach-O / dyld /
  debugserver, `.dylib`, `/Library/Developer`, `/opt/homebrew`,
  `PIE`, `ASLR`, `rip_relative`, `adrp`, `eSectionTypeOther`,
  `eSectionTypeDataCString`, `is_data_section` reference in the
  source tree.
- Classified each into PR1/PR2/PR3/PR4.
- Read and verified the post-v0.1-cut commits (specifically
  `e1cf38f`, `a466a64`, `de5db21`) for Mach-O regression risk.
- Confirmed `ctest 39/39 PASS` on the Linux dev host at this
  HEAD — the Linux baseline is intact.
- Wrote this document.

**Did NOT:**

- Run any test on macOS arm64. **The author of this audit has no
  Apple-silicon hardware available.** Every claim here that touches
  runtime behavior is either backed by a previously-validated
  worklog entry or marked "needs macOS sign-off."
- Patch the §5.2 fixture build break. Per the brief, fixes that
  cannot be validated on Linux ctest are out of scope. A pointer
  comment in `tests/fixtures/CMakeLists.txt` flags the gap for
  the next session that has macOS hardware.
- Promote MVP §1 line to first-class. That's the user's call after
  the §7 checklist runs green on real Apple silicon.

---
