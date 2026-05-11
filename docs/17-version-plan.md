# Post-V1 Version Plan

How the 25 remaining items from `docs/15-post-v1-plan.md` bundle into the
next three minor versions. Companion to `docs/15` — that doc is the item
catalog and ordering rationale; this one is the release shape.

All three versions are additive on top of v1.2.0. **v2.0 is reserved for
breaking wire changes**; the current plan introduces none. If
`#15` live-process provenance reveals a deterministic-replay requirement
that breaks an existing endpoint contract, that is the v2.0 trigger.

## v1.3 — "Agent UX polish"

Visible quality-of-life wins with no architecture moves. Each item is
small and the version ships fast.

| Item | Scope |
|---|---|
| **#3** Hot-reload of probe recipes | `recipe.reload`, file-watcher under `LDB_RECIPE_DIR` |
| **#5** Diff-mode view descriptors | `view.diff_against=<snapshot>` on read-path endpoints |
| **#6** Hypothesis-tracking artifact type | `hypothesis` mime, `confidence` + `evidence_refs` fields |
| **#7** Token-budget regression CI gate | Smoke records `_cost.tokens_est`, fails on ±10% drift |
| **#4** Measured cost preview | Replace `cost_hint: low/medium/high` with p50 from session-store telemetry. Lands after #7 collects data |
| **Reverse-step `kind=in/over/out`** (carve-out from v1.2) | Client-side step-over emulation over the `bc` packet path — finishes v1.2's reverse-exec story |

**Tagline:** *"The agent surface gets noticeably better without changing
the architecture."*

## v1.4 — "Backend abstraction + observability"

The bet: validate `DebuggerBackend` with a real second implementation
(`#8`) **before** spending Tier-3 effort on rewriting LLDB pieces. If
the abstraction leaks LLDB-isms, find out cheaply now. Bundles the
Tier-2 wins so the release ships visible UX too — multi-backend support,
a real CLI REPL, user-scriptable probes, deployable agents.

| Item | Scope |
|---|---|
| **#8** GDB/MI second backend | `GdbMiBackend` over `gdb --interpreter=mi3`. Biggest single item; short design note first |
| **#10** CLI interactive REPL | `prompt_toolkit` or readline; persistent session; `:explain` / `:cost` / `:replay` meta-commands |
| **#9** Embedded Python probe callbacks | Probes go from C++-only to user-scriptable. Sandbox question resolved in design |
| **#14** Custom Python frame unwinders | Shares DX with `#9` — embed Python once, deliver twice |
| **#11** ssh-remote daemon mode | `ldbd` runs on the target via SSH-launched stdio |
| **#12** libbpf-based `ldb-probe-agent` | Replace bpftrace shellout with static native binary + CO-RE BTF |
| **#13** `perf record/report` integration | Sibling to probes; reuses `#12`'s event-shape work |

**Tagline:** *"LDB grows from one-backend / one-language probes to a
multi-backend, scriptable, deployable platform."*

## v1.5 — "Own the critical path: live replay + non-stop"

The flagship release. Three logical chains, all converging on a single
message: LDB no longer leans on LLDB for the *interesting* operations —
DWARF parsing, symbol indexing, RSP transport, async runtime,
deterministic replay.

**v1.5 is materially larger than v1.3 / v1.4.** Treat the boundary
between v1.5 and a possible v1.6 as a fluid call to be made once the
critical chain is underway; the natural cut is between the
indexing/replay chain and the non-stop chain.

### Critical chain (sequential)

| Item | Scope |
|---|---|
| **#18 design note** | Re-evaluates whether `#19` is actually needed (`docs/15` watchlist flags `#19` ROI as questionable) |
| **#19** Own DWARF reader | `libDebugInfoDWARF` direct — only if `#18` design says yes |
| **#18** Own symbol index | Cross-binary, build-ID keyed, persistent on-disk |
| **#15** Live-process provenance | Per-endpoint determinism audit. Easier after `#18` owns timestamps + ordering |
| **#16** `session.fork` / `session.replay` | The prize; blocked on `#15` |

### Non-stop chain (parallelizable with critical chain)

| Item | Scope |
|---|---|
| **#17** Own RSP client | Reverse-step `kind=in/over/out` becomes free here; gates `#20` and `#21` |
| **#21** Non-stop runtime + displaced stepping | Per-thread suspend/resume. Provenance must extend to async (so it lands after `#15`) |
| **#25** In-target agent-expression predicates | Compile probe predicates to GDB AE bytecode |
| **#26** Tracepoints (no-stop collection) | Depends on `#21` + `#25` |
| **#20** Own Linux ptrace driver | Last resort; only if upstream LLDB gaps haven't closed by then |

### Specialized / opt-in (defer based on real user pull)

| Item | Scope |
|---|---|
| **#22** Hardware tracing | Intel PT / ARM ETM via perf or LLDB trace plugin. Linux x86-64 first |
| **#24** criu snapshot/fork | Linux-only opt-in; fragile (eBPF, io_uring, GPU contexts break it) |
| **#23** JIT debugging client | Defer indefinitely; revisit only on actual user demand |

**Tagline:** *"LDB owns its critical path — DWARF, symbols, RSP,
indexing, replay, async runtime."*

## Notes on version cadence

- **No breaks.** Plan's §1.0 promise: no breaking wire changes since
  v1.0.0. All three versions above are additive. v2.0 is the trigger
  for any real break.
- **v1.4's `#8` is load-bearing.** It validates the
  `DebuggerBackend` abstraction before any Tier-3 backend rewrites.
  Skipping it means risking expensive course corrections deep into
  v1.5's critical chain. Land `#8` first within v1.4.
- **v1.5 needs honest cut points.** Recommend cutting v1.5 once the
  critical chain (`#18`, `#19`, `#15`, `#16`) lands and shipping the
  non-stop chain as v1.6. Decide at the time based on schedule and
  user pull.
- **`#23` JIT debugging stays speculative.** Plan's watchlist says
  defer indefinitely; revisit only on real user demand. It is in v1.5
  by completeness, not by commitment.
