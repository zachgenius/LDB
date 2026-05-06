# Post-v0.1 Autonomous Progress Tracker

> Living document maintained by the lead agent during the post-v0.1
> autonomous run. Updated at every slice-merge gate. Per-slice deep
> notes live in `docs/WORKLOG.md`; this file is the single-glance
> view of where the run is.

## Status legend

- ⏳ **dispatched** — worker agent in flight
- 🔍 **review** — worker complete, reviewer agent in flight
- 🛠 **rework** — reviewer flagged issues, fixing
- ✅ **merged** — landed on `master`, ctest green, pushed to origin
- ⏭ **deferred** — out of scope for this autonomous run; reason recorded
- ⛔ **blocked** — needs human input; surfaced to the user

## Headline

| | |
|---|---|
| **HEAD at run start** | `c16adf0` (formal README post-MVP-cut) |
| **HEAD now** | (updated post-§3b/§3c-merge — Tier 1 complete modulo macOS hw) |
| **ctest at HEAD** | 41/41 green |
| **Tag** | `v0.1` |

## Tier 1 — Foundational

| # | Slice | Status | Worker | Reviewer | Merge commit |
|---|---|---|---|---|---|
| 1a | Live provenance — endpoint determinism audit | ✅ | `a05ab0000ec0248b1` | (inline review) | — |
| 1b | Live provenance — implementation (snapshot model + per-endpoint fixes) | ✅ | `a1da55c9959d40268` | `a379567ea90e9472a` | (merge commit on master) |
| 1c | Live provenance — CI determinism gate extended to live targets | ✅ | `a715e629b235a9434` | `afc1d3706a3b11696` | (merge commit on master) |
| 2 | macOS arm64 hardening pass — Linux-side audit ✅; **hardware sign-off pending user** (see Blockers § below; checklist at `docs/macos-arm64-status.md` §7) | ✅ (audit) | `aa58d23c1330389d6` | `ac66801b1b097bec0` | (merge commit on master) |
| 3a | Public release polish — protocol semver + version handshake in `hello` | ✅ | `a7041ead1a14a3982` | `a78224fdd55f8d151` | (merge commit on master) |
| 3b | Public release polish — GitHub Actions CI (Linux matrix) | ✅ | `ae87f7bbcc272c6c3` | `a6b3fa92218603d1a` | (merge commit on master) |
| 3c | Public release polish — `CONTRIBUTING.md` + commit-style + PR template | ✅ | `a48c7d2b9bc02c163` | `acf25642e78adebf8` | (merge commit on master + `f4b2229` fix) |

## Tier 2 — Force multipliers

| # | Slice | Status | Worker | Reviewer | Merge commit |
|---|---|---|---|---|---|
| 4 | DAP shim — auto-generated from `describe.endpoints` | — | — | — | — |
| 5 | Native libbpf probe agent | ⏭ | — | — | — |
| 6 | Probe recipes — promote replayable session traces to named recipes | — | — | — | — |

## Tier 3 — Differentiator wave

| # | Slice | Status | Worker | Reviewer | Merge commit |
|---|---|---|---|---|---|
| 7 | Artifact knowledge graph — typed relations | — | — | — | — |
| 8 | Hot reload of Python extensions | — | — | — | — |
| 9 | Multi-binary sessions — N targets per session | — | — | — | — |
| 10 | Cross-binary correlation — needs symbol index foundation | — | — | — | — |
| 11 | `session.diff(s1, s2)` | — | — | — | — |
| 12 | Semantic queries v1 — heap walk, mutex graph | — | — | — | — |

## Tier 4 — Power features

| # | Slice | Status | Worker | Reviewer | Merge commit |
|---|---|---|---|---|---|
| 13 | `rr` integration — replay via remote-target URL | — | — | — | — |
| 14 | Non-stop debugging — per-thread state model | — | — | — | — |
| 15 | Hardware tracing — Intel PT / ARM ETM as a probe source | — | — | — | — |
| 16 | In-target conditional probes — agent-expression bytecode | — | — | — | — |
| 17 | Tracepoints — no-stop collection | — | — | — | — |

## Deferral rationale

| Item | Why |
|---|---|
| **5 — Native libbpf probe agent** | The roadmap explicitly says replace `bpftrace` shellout "when measurement justifies it." We have no measurement evidence that the shellout is too slow. Speculative replacement violates the progressive-replacement strategy in §03 §7. Will revisit when a workload exposes the latency. |

## Blockers / decisions surfaced for user

The Tier 1 §2 audit (commit at `aa58d23c1330389d6` review by `ac66801b1b097bec0`) surfaced 4 items that need your attention. **Slice 1c silently shipped a macOS arm64 regression that the autonomous reviewer missed because it had no Apple-silicon CI.** Full detail and the remediation checklist are in `docs/macos-arm64-status.md`.

### B1 — HIGH: slice 1c dlopener fixture is a macOS arm64 build break

`tests/fixtures/CMakeLists.txt:64` unconditionally `target_link_libraries(... PRIVATE dl)`; `tests/fixtures/c/dlopener.c:55` calls `dlopen("libpthread.so.0", ...)` (glibc SONAME); `tests/smoke/test_live_dlopen.py` has no `if sys.platform == 'darwin'` SKIP. Two failure modes on macOS arm64:
1. Build break — macOS clang ld may reject `-ldl` (no `libdl.tbd` stub on some SDKs).
2. Runtime — `dlopen("libpthread.so.0")` returns NULL on macOS; smoke fails before observation point.

**Fix outline** in `docs/macos-arm64-status.md §5.2`. Three fix points: gate `target_link_libraries`, `#ifdef __APPLE__` branch in C, and gate `add_test`. **Must be fixed in a session with macOS hardware before any "Tier 1 §2 ✅" claim.**

### B2 — MEDIUM: `compute_reg_digest` GPR-set-name fallback is unverified on macOS arm64

If macOS LLDB names the GPR register set differently AND doesn't order it first, `<reg_digest>` silently hashes a non-GPR set, breaking cross-daemon `live:` snapshot equality without any visible error. Audit §3.7 / §8 row 3. Cleared by an explicit `tests/smoke/test_live_provenance.py` run on Apple silicon.

### B3 — MEDIUM: live↔core determinism gate exclusion list is Linux-flavored

`tests/smoke/test_live_determinism_gate.py` excludes `[vdso]`, kernel-side `threads[*].name`, triple-suffix drift — none of those exist on Mach-O. Included endpoints (`symbol.find`, `string.list`, `disasm.function`) should round-trip on macOS but unproven. Audit §5.3 / §7 checkbox 4.

### B5 — LOW: AI-assist disclosure stance (policy call, not correctness)

Per §3c the worker made AI-assist co-author trailer **hard-required** in `CONTRIBUTING.md`. This matches `CLAUDE.md`'s internal rule and the project's agent-first stance, but a drive-by external typo-fixer using Copilot autocomplete now hits a hard policy gate. The §3c reviewer flagged this as a policy call worth surfacing — not a correctness issue. Options:
- **Keep as hard-required** (current state). Consistent with internal rule.
- **Soften to "strongly encouraged"** — easier on drive-by contributions, still nudges honesty.
The rule is unenforceable in practice (you can't tell), so the practical difference is the tone of the doc. Your call.

### B6 — TRACKED: §3b minor follow-ups (not blocking)

From the §3b reviewer:
1. **`tags: "v*.*"`** matches `v0.2.0` / `v1.0` but not `v1` (single segment). Confirm versioning convention before tagging anything that could trip this.
2. **First push will be the live CI validation.** `check_ci_yaml` is structural only; semantic CI failures (wrong action input names, etc.) only surface on the runner. Worker disclosed; track whether the first run lands green.
3. **`actions/upload-artifact@v4` retention defaults differ from v3** — explicitly set; future v5 migration needs re-checking.

### B7 — TRACKED: §3c minor follow-ups (not blocking)

From the §3c reviewer:
1. **Dangling template references**: `CONTRIBUTING.md` directs feature-idea reporters to "the `feature` or `rfc` template" but only `bug_report.yml` ships. Either reword or add stubs in a follow-up.

### B4 — LOW (informational): Tier 1 §2 cannot be promoted to ✅ without Apple silicon

This audit closed the Linux-side static review and produced an actionable sign-off checklist (`docs/macos-arm64-status.md §7`). §2 stays at "audit ✅ / hw sign-off pending" until a session on Apple silicon clears the checklist. Lead-agent run continues with §3 (release polish) as the next slice.

## 1c reviewer findings (tracked, none blocking)

1. **Single-daemon dlopen-during-continue smoke deferred** — listener+drain mechanism has no end-to-end test that proves it correctly invalidates layout cache from within one daemon. Worker rationale ("drain runs on every snapshot") is plausible but unverified. Track for follow-up.
2. **`module.list` exclusion docstring incomplete** — also drifts on `ld-linux-*.so.2` and a duplicate [vdso] entry, not just [vdso] + triple as documented.
3. **`close_target` doesn't explicitly `StopListeningForEvents`** — broadcaster is destroyed by `DeleteTarget` so subscription becomes inert; not a correctness bug but tidier to teardown explicitly.
4. **`describe.endpoints` size in worklog** — 56,724 vs actual 56,652. Minor doc nit.
5. **Listener is per-backend not per-target** — defensible design choice, not what brief specified.

## 1b reviewer findings folded into slice 1c spec

The reviewer's pass on 1b approved the merge but flagged 4 issues for slice 1c:

1. **SW-bp memory-patch invisibility** — Two snapshots straddling `probe.create` (with the same `<gen>`) carry identical strings even though `.text` was patched with `0xCC`. 1c should fold breakpoint-patch addresses into `<layout_digest>` OR document the gap in the deterministic-only view spec. Add a regression test that creates a probe and asserts the snapshot string changes.
2. **dlopen-without-resume gap** — `<gen>` does NOT bump on dlopen. Two `module.list` calls before/after a dlopen would have different output but same `<gen>` AND same cached `<layout_digest>`. 1c should subscribe to `eBroadcastBitModulesLoaded` (or similar) to invalidate `<layout_digest>` independently of `<gen>`.
3. **No `process.continue` round-trip in 1b's smoke test** — SIGSTOP-via-tracer relationship absorbs the cycle. 1c's CI gate needs a different approach (spawning a fixture that runs to a placed breakpoint, then observing the gen bump).
4. **`describe.endpoints` size doc nit** — 56,652 vs 56,805. Trivial.

## Audit-driven corrections folded into slice 1b spec

The reviewer's pass on 1a found 5 issues to track for the implementation slice. Folded into 1b's brief verbatim:

1. **§11.2 bug claim is wrong** — `session.list` and `artifact.list` already have `ORDER BY`. Real concern is tiebreak on random uuid `id`. Implementation slice must read the SQL before "fixing" it.
2. **Counts inconsistent** — §1 says "60 catalogued"; §4 says 56; §9 lists 9 EXC; §4 totals 8. Actual catalog is 62 (verified). Reconcile during impl.
3. **Snapshot-ID gaps** — non-stop mode (per-thread `<gen>` or out-of-scope), SW-breakpoint memory patches, dlopen layout cache invalidation, cross-process gen=0 collisions, register-fetch cost on high-thread remote targets.
4. **§7 vs §3 ORDER BY keys clash** — §3.8/3.9 want `(build_id, name)` / `(name, id)`; existing SQL uses `(created_at DESC, id ASC)` / `(id ASC)`. Pick one before slice 2 starts.
5. **`describe.endpoints` size: 56,805 bytes**, not "56 KB". Trivial doc nit.

## Conventions for this run

- Every worker is TDD-strict — failing test first, confirm-fail-for-the-right-reason, implement, green.
- Every worker is followed by a **reviewer agent** that re-reads the diff and verifies: TDD trail in commits, no weakened assertions, no regressions, project conventions, honest worklog.
- Worker and reviewer both run in **isolated worktrees** off `master`.
- Reviewer can FAIL the slice. On fail: I rework via the worker (or surface to user if architectural).
- Merge order is sequential — no parallel merges into `master` during this run, to keep the merge graph readable.
- After each merge: `cmake --build && ctest` must be 100% green or the merge is reverted.
- This file is updated at every merge gate.
