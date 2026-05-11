# Post-V1 Plan

Working map of deferred work after the `v1.1.0` tag. Cross-references
`README.md` §"Out of scope (post-v1.x)", `docs/03-ldb-full-roadmap.md`,
and the current 82-endpoint dispatcher surface. Use this doc as the
ordering source of truth; the roadmap remains the strategic narrative.

## 1. Already shipped (despite roadmap listing as future)

These appear in `docs/03-ldb-full-roadmap.md` as "future" but are live
in v1.1.0. Skip when re-planning.

- `session.diff` — `src/daemon/dispatcher.cpp:1622`.
- `correlate.types` / `correlate.symbols` / `correlate.strings` —
  `dispatcher.cpp:1054`, `:1095`, `:1114`.
- Recipes: `recipe.create` / `from_session` / `list` / `get` / `run` /
  `delete` / `lint` — `dispatcher.cpp:1817–1927`.
- `artifact.relate` / `relations` / `unrelate` — `dispatcher.cpp:1493–1542`.
- `static.globals_of_type` — `dispatcher.cpp:1008` (one semantic query;
  heap/mutex/flow still deferred).
- DAP shim (`ldb-dap`) — `src/dap/`, `docs/07-dap-shim.md`.
- `rr://` URL integration via `target.connect_remote` — `src/transport/rr.cpp`.
  Reverse-execution *endpoints* still deferred.
- Capstone opt-in disassembler — `-DLDB_ENABLE_CAPSTONE=ON`, `docs/12-capstone-disasm.md`.
- Linux arm64 + macOS arm64 CI legs — `.github/workflows/ci.yml`.
- Multi-binary sessions — `session.targets` (`dispatcher.cpp:1663`).
- CBOR transport, schema-typed endpoints, `_cost` / `_provenance` envelopes,
  view descriptors.
- Non-stop *protocol surface* (`thread.continue`, `process.continue+tid`)
  — sync-backed today; true async runtime still deferred per
  `docs/11-non-stop.md`.

## 2. Truly remaining work

### Tier 1 — small, scoped, no design doc

1. **`.ldbpack` signing** — in flight on `feat/pack-signing`. Design in
   `docs/14-pack-signing.md`. Touches `src/store/pack.{cpp,h}` and four
   export/import endpoints.
2. **Reverse-execution endpoints** — `process.reverse_continue`,
   `process.reverse_step`, `thread.reverse_step`. rr is reachable
   via `rr://` URL but reverse-exec falls through to LLDB CLI. Cheapest
   approach: wrap LLDB CLI via `SBCommandInterpreter`. ~1 session.
3. **Hot-reload of probe recipes** — `recipe.reload({recipe_id})` plus a
   file-watching path under `LDB_RECIPE_DIR`. Hooks into existing
   `recipe.lint` validation.
4. **`describe.endpoints` cost preview measured, not estimated** —
   today `cost_hint` is `low|medium|high`. Roll p50 from session-store
   telemetry.
5. **Diff-mode / change-only view descriptors** — surface
   `view.diff_against=<snapshot>` on read-path endpoints. Listed v0.2
   in the roadmap; not yet wired in `view::apply_to_array`.
6. **Hypothesis-tracking artifact type** — pure store work: add
   `hypothesis` mime type to `artifact.put`, validate `confidence` +
   `evidence_refs` fields, default report template.
7. **Token-budget regression CI gate** — promised in roadmap §4
   per-release DoD but no test surfaces it. Smoke that records
   `_cost.tokens_est` totals across the agent workflow and fails on
   ±10% drift.

### Tier 2 — medium, short design note first

8. **GDB/MI second backend** — proves `DebuggerBackend` abstraction
   (`src/backend/debugger_backend.h`) is clean. `GdbMiBackend` over
   `gdb --interpreter=mi3`. Design: register-name canonicalisation,
   thread-id mapping, target-id model (MI is single-target), error
   code mapping. ~1 design note + 2–3 weeks.
9. **Embedded Python for user-authored probe callbacks** — probes are
   C++-only in `src/probes/probe_orchestrator.cpp`. LLDB already links
   libpython3.11. Design: callback ABI, sandboxing, lifetime,
   error propagation into the structured event channel.
10. **CLI interactive REPL** — `tools/ldb/ldb` is one-shot today.
    `prompt_toolkit` or readline, persistent session, `:explain` /
    `:cost` / `:replay` meta-commands.
11. **ssh-remote daemon mode** — `ldbd` runs on the target via
    SSH-launched stdio. Design: stdio framing over ssh exec channel,
    build-ID asymmetry, where artifact store lives.
12. **libbpf-based `ldb-probe-agent`** — replace `bpftrace_engine.cpp`
    shellout. Static native binary on target, CO-RE BTF. Design:
    agent↔daemon protocol, deployment story.
13. **`perf record/report` integration** — sibling to probes.
    Ingestion format (perf.data parse vs perf-script JSON),
    event-shape unification with probe events.
14. **Custom Python frame unwinders** for async runtimes. Design:
    `SBUnwindPlan` plugin API exposure, registration discipline,
    invocation cost.

### Tier 3 — flagship, full design + multi-week

15. **Live-process provenance** — README's #1 deferred item.
    Resume-counter + register-hash snapshot model, per-endpoint
    determinism audit (extending `docs/04-determinism-audit.md`).
    Hard part: enumerating non-deterministic sources across 82
    endpoints — timestamps, ASLR, scheduling, `/proc` ordering.
16. **`session.fork` + `session.replay`** — blocked on #15.
17. **Own RSP client** — replaces LLDB's `process gdb-remote`.
    Unlocks gdbserver/QEMU/OpenOCD direct talk, custom q-packets,
    packet-level retry control. Probably makes #2 (reverse-exec)
    free.
18. **Own symbol index** — cross-binary, build-ID keyed, persistent
    on-disk. Today's `correlate.*` re-derives across targets each
    call.
19. **Own DWARF reader** — `libDebugInfoDWARF` direct. Decouples
    indexer from full LLDB. Lands before #18 since the index needs
    the reader for population.
20. **Own Linux ptrace driver** — replaces LLDB's `ProcessLinux`.
    Required for proper non-stop/displaced stepping if upstream gaps
    don't close.
21. **Non-stop + displaced stepping runtime** — `docs/11-non-stop.md`
    has the surgery list: event-loop pump, per-thread state machine,
    suspend/resume primitives, endpoint review, push events.
22. **Hardware tracing** — Intel PT / ARM ETM via perf or LLDB trace
    plugin. Linux-x86_64 first.
23. **JIT debugging client** — GDB JIT interface for V8/JVM/Python/.NET.
24. **criu snapshot / fork** — Linux only; opt-in best-effort.
25. **In-target agent-expression predicates** — compile probe predicates
    to GDB-compatible agent-expression bytecode, ship to gdbserver /
    lldb-server. Makes tracepoints worth having.
26. **Tracepoints (no-stop collection)** — depends on #25 and #21.

## 3. Dependency graph

```
#1 pack-signing                 (standalone)

#2 reverse-exec endpoints  ────────────────────────┐
                                                   ├── replaced by
#17 own RSP client  ──────────────────────────────-┘    reverse-exec falls out naturally

#15 live-process provenance ─→ #16 session.fork/replay
                            ─→ #21 non-stop (provenance must extend to async state)

#19 own DWARF reader ─→ #18 own symbol index

#17 own RSP client ─→ #21 non-stop runtime
                  ─→ #20 own ptrace driver (only if LLDB gaps justify)

#25 in-target predicates ─→ #26 tracepoints/no-stop collection
#21 non-stop runtime     ─→ #26

#9  embedded Python probes ─→ #14 custom Python unwinders share DX

#12 libbpf probe agent ─→ #13 perf integration
                      ─→ #22 hardware tracing
```

The critical chain is **#19 → #18 → easier #15 audit → #16**. Most
expensive single sequence; gates the largest user-visible feature
(`session.replay` against live targets).

## 4. Suggested execution order

After `feat/pack-signing` (#1) lands:

1. **Reverse-exec endpoints via `SBCommandInterpreter` wrapper (#2).**
   1 session. Reuses the `connect_remote_target` smoke path.
2. **Hot-reload of probe recipes (#3).** 1–2 sessions. Direct
   quality-of-life win; no backend churn.
3. **Token-budget regression CI gate (#7).** 1 session. Locks in the
   agent-cost north-star metric before bigger features move it.
4. **Hypothesis-tracking artifact type (#6).** 1–2 sessions. Track C
   differentiator using only the artifact store.
5. **GDB/MI second backend (#8).** 2–3 weeks with a design note first.
   Biggest infra payoff per dollar: validates `DebuggerBackend`,
   surfaces every LLDB-ism that leaked, sets up the testing pattern
   for #17 (own RSP) and #20 (own ptrace).
6. **Embedded Python probe callbacks (#9).** 2–3 weeks after #8.
   Probes already exist; embedding Python in the callback path
   unlocks user-authored predicates and sets up the eventual #25
   in-target predicate story (shared evaluation surface).

This ordering keeps each release shipping something visible (#1–#4 are
user-facing) while building toward Tier 3 without ten silent weeks
between releases.

## 5. Risks / watchlist

- **Own DWARF reader (#19) ROI is questionable.** LLDB's reader is
  mature and tracks upstream changes. The roadmap rationale is
  "decouple indexer from full LLDB" — but that's a means, not an
  end. If the goal is cross-binary indexing, caching SBAPI-derived
  data into our own index format may be sufficient. Re-evaluate after
  #18 design note.
- **JIT debugging (#23) is large; audience is narrow.** Most agent RE
  targets are native ELF/Mach-O. Defer indefinitely; revisit only on
  real user pull.
- **Own ptrace driver (#20) may not be needed if LLDB closes its gaps.**
  Roadmap §7 explicitly says replacement is last resort behind
  "no upstream fix in flight." Watch the LLDB issue tracker.
- **criu (#24) is fragile in practice.** Many real processes don't
  survive a CRIU dump (eBPF maps, io_uring, GPU contexts). Ship as
  opt-in best-effort; don't promise.
- **Embedded Python (#9) sandbox question.** A user-authored Python
  probe runs in `ldbd`'s address space with full access. Constrain
  via subinterpreters / seccomp or document the trust assumption
  explicitly.
- **Hardware tracing (#22) on macOS is essentially absent.** Intel PT
  is x86-only and Linux-only in practice; ARM ETM access requires
  kernel support that's not universal. Scope to Linux x86-64 in the
  initial cut.
- **Non-stop runtime (#21) endpoint review is larger than the doc
  admits.** `docs/11-non-stop.md` lists ~5 sync-blocking endpoints;
  the real number after audit will be closer to 15–20 once
  `probe.events` streaming and observer-exec timing are factored in.
