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
| **HEAD now** | (updated post-1a-merge) |
| **ctest at HEAD** | 35/35 green |
| **Tag** | `v0.1` |

## Tier 1 — Foundational

| # | Slice | Status | Worker | Reviewer | Merge commit |
|---|---|---|---|---|---|
| 1a | Live provenance — endpoint determinism audit | ✅ | `a05ab0000ec0248b1` | (inline review) | — |
| 1b | Live provenance — implementation (snapshot model + per-endpoint fixes) | 🔍 | `a1da55c9959d40268` | — | — |
| 1c | Live provenance — CI determinism gate extended to live targets | — | — | — | — |
| 2 | macOS arm64 hardening pass (Linux-side fixes; macOS sign-off deferred to user) | — | — | — | — |
| 3a | Public release polish — protocol semver + version handshake in `hello` | — | — | — | — |
| 3b | Public release polish — GitHub Actions CI (Linux matrix) | — | — | — | — |
| 3c | Public release polish — `CONTRIBUTING.md` + commit-style + PR template | — | — | — | — |

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

_(none so far)_

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
