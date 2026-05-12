# Tracepoints — no-stop collection

Post-V1 #26 phase-1 (final item in v1.6's non-stop chain per
docs/17-version-plan.md). Builds on:

  * **#21** Non-stop runtime — gives us per-thread state + push
    notifications so a tracepoint hit doesn't have to interrupt
    the inferior.
  * **#25** Agent-expression predicates — gives us filters that
    run cheaply at hit time so high-frequency tracepoints don't
    drown the agent in events.

## TL;DR

- **A tracepoint is a no-stop probe with a rate limit.** Same
  underlying machinery as `probe.create(kind="lldb_breakpoint")`:
  same `where`, same `predicate`, same `capture` shape. The
  differences:
  * Action is locked to log-and-continue (no `stop`, no
    `store_artifact`). The inferior never pauses.
  * Rate limit is enforced at the orchestrator. Existing probes
    parse `rate_limit_text` but never honour it; tracepoints
    must.
  * The wire surface is `tracepoint.*` instead of `probe.*`. The
    semantic distinction matters: an agent reading
    `probe.create(action=stop)` knows it can lose state on hit;
    `tracepoint.create` is a contract that says "this never
    stops the world."
- **Phase-1 ships daemon-side only.** The hit fires on LLDB's
  process-event thread (existing breakpoint callback); the
  predicate evaluates daemon-side; the captured event lands in
  the orchestrator's ring buffer. Same path as today's probes,
  just with the no-stop + rate-limit invariants.
- **Phase-2 wires `QTDP` for RSP-backed targets** — push the
  tracepoint definition (where + predicate bytecode + capture
  spec) into the in-target agent via the gdb-remote tracepoint
  family. The in-target agent runs the predicate without a
  daemon round-trip; events stream up via `QTFrame` / async
  `T05` stop replies.
- **No new opcodes.** The agent-expression VM from #25 is the
  payload. Phase-3 will add control-flow opcodes (`if_goto`,
  `goto`) that in-target loops want; daemon-side phase-1
  doesn't need them.

## 1. Wire surface

```
tracepoint.create({
  target_id,
  where: {function | address | file+line},
  predicate?:  {source} | {bytecode_b64},
  capture?:    {registers, memory},   // same shape as probe.create
  rate_limit?: "<N>/<unit>",          // "1000/s", "10/ms", "500/total"
})
  → {tracepoint_id, kind: "tracepoint"}

tracepoint.list({target_id?})  → {tracepoints: [{
  tracepoint_id, where_expr, enabled, hit_count,
  has_predicate, predicate_dropped, predicate_errored,
  rate_limited,
}], total}

tracepoint.enable({tracepoint_id})  → {tracepoint_id, enabled: true}
tracepoint.disable({tracepoint_id}) → {tracepoint_id, enabled: false}
tracepoint.delete({tracepoint_id})  → {tracepoint_id, deleted: true}

tracepoint.frames({tracepoint_id, since?, max?}) → {
  frames: [...],         // same shape as probe.events
  total,
  next_since,
}
```

The `tracepoint.frames` query is intentionally distinct from
`probe.events` even though it returns the same shape. Future
phases will add tracepoint-only fields (frame_number,
collection_timestamp from `QTFrame`'s metadata) that don't
belong on the probe surface.

## 2. Rate limit grammar

The `rate_limit` field accepts a small grammar:

```
rate_limit := <int> "/" <unit>
unit       := "s"   | "ms"  | "us" | "total"
```

- `"1000/s"` — at most 1000 events per second (sliding window).
- `"10/ms"` — at most 10 events per millisecond.
- `"500/total"` — at most 500 events lifetime; after that, every
  hit is dropped.

When the limit is exceeded, the orchestrator drops the event
silently and increments `rate_limited`. This counter is exposed
on `tracepoint.list` (and `probe.list` for symmetry) so an agent
can tell "the inferior is running" from "the tracepoint is firing
faster than the limit allows."

The grammar lives in `src/probes/rate_limit.{h,cpp}` so the
existing probe.* path can use it too (the field has been
documented-as-parsed-but-unenforced since M3; tracepoints make
honouring it load-bearing).

## 3. Why not just `probe.create(kind="tracepoint")`?

We could fold tracepoints into the existing `probe.create`
endpoint with a new `kind`. We don't, for three reasons:

1. **Different semantic guarantee.** `probe.create(action=stop)`
   exists and stops the world; an agent reading `probe.list`
   today doesn't know which probes are stoppy. A separate
   `tracepoint.*` endpoint family makes the no-stop contract
   visible at the wire layer.

2. **Tracepoints will diverge from probes.** Phase-2 ships
   QTDP-driven in-target collection; that requires a
   `tracepoint.collect_spec` shape that doesn't make sense for
   stop-the-world probes. Splitting the surface now means
   phase-2 doesn't have to rebrand existing endpoints.

3. **Agent ergonomics.** `tracepoint.create` reads more honestly
   than `probe.create(kind="tracepoint", action="log_and_continue")`.
   The verbosity tax adds up for the kind of agent workflow
   tracepoints exist to support — many tracepoints, set/unset
   often.

The orchestrator is shared. The dispatcher routes via different
endpoint handlers but constructs the same `ProbeSpec` underneath
(`kind = "tracepoint"`). All the probe machinery — predicate
evaluation, capture, ring buffer, hit_seq — applies unchanged.

## 4. Failure modes

| Condition | Behaviour |
|---|---|
| `action` set on tracepoint.create | -32602 ("tracepoint action is always log-and-continue") |
| `predicate` on tracepoint.create | accepted (same compile/decode path as probe.create) |
| Malformed `rate_limit` (no `/`, unknown unit, non-integer) | -32602 with a hint to the grammar |
| `rate_limit = "0/s"` | -32602 ("rate_limit must be positive") |
| Rate exceeded at hit time | event dropped, `rate_limited` counter incremented, inferior auto-continues |
| Predicate evaluates to zero | event dropped, `predicate_dropped` counter incremented (existing #25 behaviour) |
| Predicate errors | event dropped, `predicate_errored` counter incremented |
| Tracepoint on uprobe_bpf / agent kind | not supported — `tracepoint.create` always uses `kind="tracepoint"`; the BPF / agent paths have their own tracing surface (bpftrace itself is a tracepoint engine; the agent's QTDP path is phase-3) |

## 5. Phase scoping

### Phase-1 (this PR's territory)

- `src/probes/rate_limit.{h,cpp}` — grammar parser + windowed
  enforcement. Used by both probe.* and tracepoint.* paths.
- `ProbeOrchestrator` extension:
  * `Action::kLogAndContinue` already does what tracepoints
    need; no new action variant required.
  * `rate_limit_text` is now PARSED + ENFORCED. The pre-existing
    "parsed but not enforced" comment in `probe_orchestrator.h`
    gets removed.
  * `ListEntry.rate_limited` counter; surface on probe.list /
    probe.info / tracepoint.list.
- `tracepoint.*` dispatcher endpoints (6 total): create, list,
  enable, disable, delete, frames.
- describe.endpoints entries for the 6 new endpoints.
- Unit tests: rate_limit grammar, dispatcher routing, parse
  errors, rate-limit enforcement against a mocked clock.

### Phase-2 (separate commit)

- Add `QTDP` / `QTStart` / `QTStop` / `QTFrame` to the rsp
  packets vocabulary.
- For RSP-backed targets, `tracepoint.create` emits QTDP to push
  the bytecode + capture spec to the server; `tracepoint.enable`
  emits QTStart; events flow back as async stop replies + are
  drained via QTFrame.
- LldbBackend integration: deferred — LLDB's tracepoint API
  surface is fragmented. Daemon-side phase-1 covers the LLDB
  path adequately.

### Phase-3 (post-v1.6)

- Add `if_goto` / `goto` to the agent-expression opcode table
  so in-target predicates can short-circuit common-case checks.
- `tracepoint.collect_spec` for in-target memory + register
  capture (server-side allocation; events ship pre-formatted
  to the daemon).
