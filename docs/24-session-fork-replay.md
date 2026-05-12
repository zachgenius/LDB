# `session.fork` + `session.replay`

> Post-V1 plan item #16, phase-1. v1.5's critical chain ends here:
> `#18` (own symbol index) → `#15` (live-process provenance) →
> **`#16` (session.fork + session.replay)**. Phase-1 ships fork +
> deterministic-row replay; phase-2 picks up incremental and partial
> replay against live targets once #15 fully lifts the determinism
> gate over correlate.* / live-state endpoints. See
> `docs/15-post-v1-plan.md` §3 for the dependency graph.

## 1. Motivation

The dispatcher already records every RPC in a per-session
`rpc_log(seq, method, request, response, ok, duration_us)` table
(`docs/02-ldb-mvp-plan.md §3.4`, shipped M3 part 2). The provenance
gate (`docs/04-determinism-audit.md`) already enforces — in CI, via
`tests/smoke/test_provenance_replay.py` — that any response carrying
`_provenance.deterministic == true` is byte-identical across daemon
processes for the same `(method, params, snapshot)` tuple.

What's been missing is a way to *use* that. Two specific user stories:

1. **Branch an investigation.** Agent has spent N RPCs establishing
   facts about a trace ("the corrupt pointer is in `dxp_login_frame`,
   the path through `sym_a → sym_b` is the only producer of it"). It
   now wants to try hypothesis X without losing the established
   context. Today the only option is `session.export → session.import`
   into a new id, which is heavyweight (gzipped tarball round-trip
   through the filesystem) and loses the parent linkage.
2. **Re-run a session.** Agent has a recorded `rpc_log` from a prior
   day. It wants to replay it against the same artifacts on a fresh
   daemon process and confirm the deterministic responses haven't
   drifted (e.g. after an LLDB upgrade, a `.ldbpack` round-trip, or
   a CI environment change). Today the only thing that does this is
   the provenance-replay smoke test, which hardcodes seven RPC pairs.

Both stories want to lean on the same primitive: walk an existing
rpc_log and either (a) snapshot it into a new session id (fork),
or (b) dispatch each row against a fresh daemon and compare
responses (replay).

## 2. Surface

Two new dispatcher endpoints. Both are register-target-free
(`requires_target=false`) and store-store-dependent (return
`-32002 kBadState` when the session store is not configured).

### 2.1 `session.fork`

```jsonc
// request
{
  "source_session_id": "<32-hex>",
  "name":              "hypothesis-X",          // optional; defaults to "<source.name> (fork)"
  "description":       "trying alternate path", // optional, stored in meta but not used
  "until_seq":         42                       // optional; 0 or absent = "fork at the head"
}

// response
{
  "session_id":        "<32-hex>",   // new id
  "source_session_id": "<32-hex>",   // echoed back so the caller has the pair
  "name":              "hypothesis-X",
  "created_at":        1715500000000000000,
  "path":              "<absolute>",
  "forked_at_seq":     42,           // the seq we cut at; <= until_seq, == source.max_seq when until_seq==0
  "rows_copied":       42
}
```

Semantics:

- Allocate a fresh 32-hex session id (same generator as `session.create`).
- Open a sqlite transaction on the new session db. Copy every
  `rpc_log` row from the source whose `seq <= until_seq` (or every
  row when `until_seq == 0`), preserving `ts_ns / method / request /
  response / ok / duration_us`. The new session re-assigns
  `seq` from 1 because sqlite `AUTOINCREMENT` is per-table; the
  preserved data is the row payload, not the row id (the dispatcher
  has never made `seq` an externally-stable identity).
- Commit the transaction. Insert the index row.
- The parent session is untouched. Concurrent appends to the parent
  during the fork are NOT visible to the child — the fork operates
  on the snapshot it read at row-copy time. (The dispatcher is
  single-threaded today and the fork happens while the caller is
  blocked on the response, so the parent can't append during the
  fork; this matches the WAL semantics for read+write to the same
  db family.)
- `until_seq` past the parent's max is allowed: copy what exists,
  report `forked_at_seq` as the actual cut. `until_seq < 0` is
  invalid params.
- `source_session_id` must exist; `-32000 kBackendError` otherwise.

### 2.2 `session.replay`

```jsonc
// request
{
  "session_id": "<32-hex>",          // required
  "against":   "/path/to/binary",    // optional; explained below
  "strict":    false                  // optional, default false
}

// response — array of step results plus aggregate summary
{
  "session_id":              "<32-hex>",
  "total_steps":             42,
  "replayed":                40,     // total_steps - skipped
  "skipped":                 2,      // session.* meta-rows
  "deterministic_matches":   35,
  "deterministic_mismatches":1,      // rows that claimed deterministic but bytes differed
  "errors":                  0,      // rows that errored in replay but succeeded originally
  "divergences": [                   // every non-match, every replay-side error
    {
      "seq":              17,
      "method":           "string.list",
      "reason":           "deterministic_mismatch" | "live_response_drift" | "replay_error" | "captured_error",
      "expected_snapshot": "core:7a8b...",
      "observed_snapshot": "core:7a8b...",
      "expected_ok":       true,
      "observed_ok":       true
      // for replay_error: "observed_error": {"code": -32000, "message": "..."}
    }
  ]
}
```

Semantics, row-by-row:

1. **Skip session.\* meta-calls.** Rows whose method starts with
   `session.` are not re-dispatched. They contributed bookkeeping
   (attach/detach, info/list) — replaying them against a fresh
   dispatcher would either no-op (session.list returns whatever the
   fresh store has) or recurse infinitely (session.replay-of-a-
   session-that-contains-session.replay is the prompt's "replay-
   internal recursion"). The summary counts them in `skipped`.
2. **Skip target.* rows when `against` is supplied.** When the
   caller passes `against`, the dispatcher pre-opens that target
   and rewrites every subsequent row's `params.target_id` to the
   freshly-minted id. The original `target.open` / `target.attach`
   row is then skipped (it would mint a *different* target_id and
   leave us without a stable handle). When `against` is absent, the
   target.* rows are re-dispatched normally; this assumes the
   recorded paths still exist on disk, which is the common case
   for replay-against-same-machine.
3. **For every other row,** synthesize a `Request` from the
   captured `request_json` (method + params; the original
   request `id` field is irrelevant for replay), dispatch via the
   private `Dispatcher::dispatch_inner` path, and compare:
   - Pull the captured `response_json` and extract
     `_provenance.deterministic` from its `data` block (when
     present). The provenance decorator runs in `Dispatcher::dispatch`,
     not `dispatch_inner`, so we have to call `dispatch` here to
     have a determinism flag to compare against — but we suppress
     the rpc_log append (an attached writer during replay would
     poison the replay session's own log).
   - If the captured row was `deterministic == true`:
     - The observed response's `_provenance.snapshot` must be
       byte-equal to the captured snapshot AND the observed `data`
       block must be byte-equal to the captured `data` block.
     - On match: `deterministic_matches += 1`.
     - On mismatch: `deterministic_mismatches += 1`, append a
       divergence with `reason: "deterministic_mismatch"`. If
       `strict == true` AND the row was the first deterministic
       mismatch, stop the loop here and return the summary.
   - If the captured row was `deterministic == false` or
     `_provenance` was absent (live state, wall-clock,
     `hello`/`describe.endpoints` against a no-target dispatcher):
     - Don't compare bytes. Just record that the replay produced a
       response; tag as `reason: "live_response_drift"` ONLY when
       `ok` flipped (true → false or false → true), otherwise leave
       the row out of the divergence list. The aggregate counter
       for live drift is `errors` only when the replay errored on
       a row that had succeeded originally; ok-flipped-the-other-
       way (replay succeeds on a row that had failed originally) is
       reported but doesn't increment `errors`.
   - If the captured row was `ok == false` (the original RPC
     itself errored): we still dispatch it. If replay also errors
     with the same `error.code`, that's a match (no divergence
     emitted). If replay errors with a different code or succeeds,
     append `reason: "captured_error"` and record the observed
     state.
4. **Suppress the active session writer during replay.** The
   replay handler takes the dispatcher's `active_session_writer_`
   slot, moves it to a local variable, dispatches every row, then
   restores it. This ensures the replay session itself doesn't
   end up logged into whatever session the agent had attached
   when it called `session.replay`. (See §5 — "Idempotency".)

### 2.3 Request validation

`session.fork`:
- `source_session_id`: required, non-empty string, 32 lowercase hex
  chars. `-32602 kInvalidParams` on shape; `-32000 kBackendError` on
  "session not found."
- `name`: optional string. If absent or empty, default to
  `<source.name> + " (fork)"`. Must be <= 256 chars when present.
- `description`: optional string, stored in `meta` table but not
  surfaced on the response. Capped at 4096 chars.
- `until_seq`: optional integer >= 0. `0` (or absent) means head.
  Negative integers are `-32602`.

`session.replay`:
- `session_id`: required, non-empty string, 32-hex. Errors as above.
- `against`: optional. When present, must be either a non-negative
  integer (treated as a literal pre-existing `target_id`) or a
  non-empty string (treated as a binary path passed to `target.open`).
- `strict`: optional boolean, default false.

### 2.4 Cost / pagination

`session.replay`'s response carries the full `divergences` array
inline. For sessions with hundreds of mismatches, the response can
get large; we accept the `view: {limit, offset}` shape on the
divergences array, applied via `protocol::view::apply_to_array`.
`cost_hint` is `unbounded` (same family as `session.diff`). Agents
that want a summary-only call pass `view.limit=0` — the summary
counters still come back. The cost preview (post-V1 plan #4) will
record measured tokens; this is fine — the divergence array is the
endpoint's dominant cost.

`session.fork` is a sqlite copy; `cost_hint` is `medium` because the
copy is O(rows) but bounded by the source session's size.

## 3. Provenance gate, restated

`docs/04-determinism-audit.md` §1 establishes the contract for any
response whose `_provenance.deterministic == true`: identical
`(method, params, snapshot)` against the same daemon-process state
yields byte-identical `data`. The replay handler's correctness rule
is exactly this contract, restricted to the captured rows:

> For every captured row R in the source session whose captured
> `_provenance.snapshot` is deterministic-flavored AND whose fresh
> dispatch produces the *same* deterministic snapshot, replay MUST
> produce byte-equal `data`.

When the snapshot strings differ (e.g. the source was core-loaded
from a file that no longer exists on this host), the contract no
longer applies; the replay row is tagged
`reason: "deterministic_mismatch"` with the snapshot drift visible
in `expected_snapshot` / `observed_snapshot`.

When either side is non-deterministic (snapshot doesn't start with
`core:`), replay is *informational only* — we surface the observed
response, but byte-identity is not expected. The summary counters
report drift; nothing fails.

### 3.1 Capturing the snapshot at write time

The existing `rpc_log` row stores `response_json` as
`{"ok": resp.ok, "data": resp.data}` — the wire-format
`_provenance` / `_cost` blocks are added in `serialize_response`,
NOT inside `resp.data`, so they don't survive the capture path
that `Dispatcher::dispatch` runs into `Writer::append`. Without
the captured snapshot, replay can't reconstruct the original
determinism gate; it would have to fall back to "compare bytes
only when the *new* dispatch is deterministic," which is unsound
when the captured snapshot was non-deterministic (we'd compare
against non-deterministic bytes that were never promised to match).

The fix is to extend `Writer::append` (and the row schema) to
also record the dispatcher's `resp.provenance_snapshot` for the
captured response. The schema migration is additive:

```sql
ALTER TABLE rpc_log ADD COLUMN snapshot TEXT NOT NULL DEFAULT '';
```

`SessionStore::LogRow` gains a `snapshot` string field;
`Writer::append` takes a `std::string_view snapshot` parameter
and binds it into the new column. Rows recorded before this
change read back as snapshot=""; replay treats those as
"snapshot unknown — non-deterministic by default" and skips
byte comparison.

## 4. Schema decisions

**Why a separate `until_seq` parameter and not just `from_seq +
limit`?** Agents think in terms of "fork at this point" (a
boundary), not "give me a window starting here." `from_seq` is a
phase-2 *incremental replay* parameter — the symmetric pair makes
sense once we want to resume a partial replay; in phase-1 the only
boundary is the cut.

**Why is `seq` not preserved across fork?** Sqlite's AUTOINCREMENT
is per-table. We could preserve seq by inserting explicitly into
the `seq` column, but the existing schema declares `seq INTEGER
PRIMARY KEY AUTOINCREMENT` which makes that a sharper edge than it's
worth — any future re-attach + append on the forked session would
have to dodge already-occupied seq values. The row payload
(method/request/response/ts/ok/duration) is what's semantically
interesting; `seq` is a strict-monotonic ID, not an attestation.

**Why does replay dispatch through `dispatch` not `dispatch_inner`?**
Because the determinism flag lives in `_provenance`, and
`_provenance` is decorated in the outer `dispatch` (see
`decorate_provenance` in `dispatcher.cpp:558`). Calling
`dispatch_inner` would give us the raw `data` without the snapshot
context, so we couldn't tell whether the captured row was supposed
to be byte-identical. The active-writer suppression (see §2.2 step
4) is what makes the outer `dispatch` safe to call recursively
inside the replay handler.

**Why does fork copy rows in a single transaction?** sqlite WAL
gives us atomic visibility — a partial fork would leave a session
with N/M rows visible while M/M was the intended count. The
fork is also bounded (the source session is the entire transaction
input; sqlite has no trouble with rpc_log sizes up to the low
millions). The transaction matches the import-side path in
`SessionStore::import_session`.

**Why is the response `divergences` array the full bag rather than
the diff against the original?** Because the row-by-row replay is
already linear in the source size, and the diff against the
original is what `session.diff` does already (it does LCS alignment
on (method, params) tuples). `session.replay` is "did the same
calls produce the same answers", not "what's different between two
investigations." A caller who wants the LCS view runs
`session.replay` followed by `session.diff` against the original.

## 5. Idempotency

`session.replay` must be re-runnable. Concretely:

- A fresh `ldbd` process against the same `LDB_STORE_ROOT` and the
  same `session_id` must produce a `session.replay` response with
  the same `total_steps / replayed / skipped /
  deterministic_matches / deterministic_mismatches / errors` counts
  on call N as on call N+1.
- The `divergences` array must be byte-equal across calls (modulo
  reason-specific fields like `observed_error.message` which can
  leak `errno` text the OS feels like changing — those are tagged
  `reason: "replay_error"` and excluded from byte-identity
  expectations in the test).
- Replay must not mutate the source session's rpc_log. The active-
  writer suppression (§2.2 step 4) is the load-bearing guarantee
  here; the replay handler must restore the writer slot even on
  exception, hence the RAII guard.

`session.fork` is idempotent in a weaker sense: calling it twice
produces two different sessions (fresh ids each time). What's
guaranteed is that the *content* of a fork at `until_seq=K`
against the same source is byte-equal across calls — every row
payload is preserved, and `seq` re-numbering is deterministic
(insertion order = source seq order).

## 6. Failure matrix

| Condition | Behavior |
|---|---|
| `session_id` / `source_session_id` doesn't exist | `-32000 kBackendError`, message includes the id |
| `session.replay` against a session whose rpc_log is empty | `total_steps=0, replayed=0, divergences=[]`. Returns ok. |
| Captured row references a `target_id` that no longer exists when `against` is absent | Replay calls `target.open` from the captured row; if the path on disk is gone, `target.open` errors → recorded as `reason: "replay_error"` and processing continues (or stops, if `strict`). |
| Captured row is a non-deterministic call (live state, observers, probes) | Dispatched normally. `deterministic` was false in capture; bytes are not compared; if ok flipped, surface as drift. |
| Captured row is `_provenance.snapshot == "live"` (live target) | Same as above. v1.5 #15 phase-1 might extend determinism to live targets; replay reads the captured flag, so future-proofed. |
| Captured row is `_provenance.snapshot == "none"` (no target) with `deterministic == false` | Dispatched normally, bytes not compared. (`hello`, `describe.endpoints` etc. — their responses *are* deterministic in practice but the gate doesn't claim it; replay defers to the gate.) |
| `until_seq` past source max | Copy what exists, report `forked_at_seq = source.max_seq`. |
| `until_seq` < 0 | `-32602 kInvalidParams`. |
| `strict=true` and a deterministic row mismatches | Stop the loop, return summary with `divergences` containing only that one row. `replayed` reflects rows processed up to and including the failed row. |
| Replay dispatch throws a non-`backend::Error` exception | Caught by the outer `dispatch_inner` try/catch and surfaced as `-32603 kInternalError` for that row's observed response; recorded as `reason: "replay_error"`. The replay loop continues unless `strict`. |
| Source session was imported from a `.ldbpack` (no rebuild artifacts) | If the original target binaries aren't materialised on this host, `target.open` rows error. Replay reports those errors and continues — agents importing for replay should bundle the binaries via `.ldbpack`'s artifact-store side. Documented in phase-2 scope (cross-host replay). |

## 7. Phase-2 scope (not in this commit)

Tracked for follow-up; documented here so the wire shape doesn't
have to break to add them.

- **Incremental replay**: `from_seq` parameter on `session.replay`
  that resumes from a given row. Today the only way to "replay
  past row K" is to fork at K and replay the fork.
- **Partial replay (method filter)**: `methods: ["string.*",
  "type.*"]` to only replay matching rows. Useful for "did the
  type layouts drift after the toolchain update."
- **Cross-host replay**: when the source session was produced on a
  different host (imported via `.ldbpack`), the binary paths
  recorded in `target.open` rows won't exist locally. The agent
  has to either (a) bundle binaries in the pack and stage them
  before replay, or (b) supply a `path_remap: [["/old", "/new"]]`
  parameter. The pack export already includes artifacts; phase-2
  adds the remap.
- **Forked-from-forked**: a fork of a fork. The `meta` table on
  the new session db could carry a `forked_from` key. Phase-1
  intentionally doesn't write that — we don't want to commit to
  a lineage graph schema until we have a real consumer.
- **Replay diff vs original**: a single endpoint that's
  effectively `session.replay → session.diff(original, replayed)`.
  Useful but not minimal-viable.
- **Live-target replay strictness**: once `#15` lifts the
  determinism gate over live-state endpoints, the replay handler
  starts treating those rows as comparable too. Today it doesn't
  even try — the gate says "deterministic=false" and we honor it.

## 8. Implementation outline

Per `CLAUDE.md`, TDD strict:

1. **Failing unit test** for `SessionStore::fork_session` in
   `tests/unit/test_session_fork.cpp`:
   - Source session with N appended rows.
   - `fork_session(source.id, "child", "", until_seq=0)` returns
     a fresh id, and `read_log(child)` returns the same N rows
     with byte-equal request/response/method/ok/duration/ts.
   - `fork_session(source.id, "child", "", until_seq=K)` for
     `K < N` returns only K rows.
   - Parent unchanged: `read_log(source)` still returns N rows
     after the fork.
2. **Implement `SessionStore::fork_session`** in
   `src/store/session_store.cpp`. Header method addition. Behavior:
   - Look up the source path under the index mutex.
   - Allocate fresh id and per-session db path via the same helpers
     as `create()`.
   - Open the source db read-only and the new db read-write.
   - `BEGIN IMMEDIATE` on the new db, INSERT-from-prepared-SELECT
     loop (we can't ATTACH across two read-only/read-write handles
     reliably and want explicit rollback semantics; one prepared
     `SELECT seq, ts_ns, method, request, response, ok, duration_us
     FROM rpc_log WHERE (?1 = 0 OR seq <= ?1) ORDER BY seq ASC` on
     the source paired with a prepared `INSERT INTO rpc_log
     (ts_ns, method, request, response, ok, duration_us) VALUES(...)`
     on the destination). Step the SELECT; bind each row to the
     INSERT; step it. Track `rows_copied` and the last seen
     `seq` (that's `forked_at_seq`).
   - COMMIT.
   - Insert the index row (same shape as `create()`).
3. **Failing unit test** for the dispatcher handler in
   `tests/unit/test_dispatcher_session_replay.cpp`:
   - Build a session with 3-4 deterministic calls
     (`artifact.put`, `session.list`, `describe.endpoints` and one
     `hello` — the same calls listed in `test_provenance_replay.py`'s
     `deterministic_calls`, scoped to no-target rows so we don't
     need a real binary in the unit test).
   - Call `session.replay` on that session against the same
     dispatcher.
   - Assert: `total_steps == 4`, `skipped == 1` (the
     `session.attach` row from the recording phase),
     `deterministic_matches == 3` (the three deterministic
     captures), `deterministic_mismatches == 0`, `errors == 0`,
     `divergences` empty.
   - A second assertion that `strict: true` is honored on a
     fabricated mismatch — we don't have a way to fabricate one
     in a unit test (the calls *should* match), so we test the
     code path via a simpler injection: short-circuit when no rows
     need replay, return success-summary.
4. **Implement `Dispatcher::handle_session_fork` and
   `handle_session_replay`** in `src/daemon/dispatcher.cpp`:
   - `handle_session_fork`: parse params, call
     `sessions_->fork_session`, render response.
   - `handle_session_replay`: parse params, fetch
     `sessions_->read_log(session_id)`, optionally pre-open
     `against`, walk rows, dispatch each via `dispatch` with the
     active writer suppressed via local RAII guard, compare
     responses, accumulate counters.
   - Register both in `dispatch_inner` (the `// session.*` block)
     and in `handle_describe_endpoints` (the `// session.*` block).
5. **Smoke test** `tests/smoke/test_session_replay.py`:
   - Spawn `ldbd` with a fresh `LDB_STORE_ROOT`.
   - `target.open` the `ldb_fix_structs` fixture, `session.create`,
     `session.attach`, run a handful of deterministic calls
     (`module.list`, `type.layout` of a known struct, `symbol.find`,
     `string.list` with bounded scope, `describe.endpoints`),
     `session.detach`.
   - `session.replay` against the captured session.
   - Assert `divergences == []` and the determinism-match count
     equals the number of captured deterministic rows.

Total estimated diff: ~150 LOC store + ~250 LOC dispatcher + ~150 LOC
header/describe + ~400 LOC tests. One commit per layer (TDD red ->
green per `CLAUDE.md`).

## 9. Worked-example wire shape

A session with 3 rows captured before `session.detach`:

```jsonc
// row 1 — session.attach (will be skipped)
{"seq": 1, "method": "session.attach", ...}

// row 2 — hello (deterministic_provenance=false; "none" snapshot)
{"seq": 2, "method": "hello",
 "response": {"ok": true, "data": {...,
   "_provenance": {"snapshot": "none", "deterministic": false}}}}

// row 3 — describe.endpoints (same as row 2 wrt provenance)
{"seq": 3, "method": "describe.endpoints", ...}

// row 4 — target.open against /tmp/ldb_fix_structs
//   (deterministic=false because LLDB-side allocations vary)
{"seq": 4, "method": "target.open",
 "response": {"ok": true, "data": {"target_id": 1, ...}}}
```

A `session.replay` against that session, with `against` absent:

```jsonc
{
  "session_id":              "<source-id>",
  "total_steps":             4,
  "replayed":                3,
  "skipped":                 1,   // session.attach
  "deterministic_matches":   0,   // no deterministic=true rows
  "deterministic_mismatches":0,
  "errors":                  0,
  "divergences":             []   // ok flipped on no row
}
```

A `session.replay` against the same session, with
`against="/tmp/ldb_fix_structs"`:

```jsonc
{
  "session_id":              "<source-id>",
  "total_steps":             4,
  "replayed":                2,    // hello + describe.endpoints
  "skipped":                 2,    // session.attach + target.open
                                   //  (target.open is skipped because
                                   //   `against` pre-opened a fresh target)
  "deterministic_matches":   0,
  "deterministic_mismatches":0,
  "errors":                  0,
  "divergences":             []
}
```

## 10. Cross-references

- `docs/02-ldb-mvp-plan.md §3.4` — session schema.
- `docs/04-determinism-audit.md` — provenance gate.
- `docs/15-post-v1-plan.md` §3 — dependency graph; #16 is blocked
  on #15 which is in flight in a parallel worktree.
- `src/store/session_store.{h,cpp}` — `SessionStore` API.
- `src/daemon/dispatcher.cpp` — dispatcher; lines 555-630 are the
  outer `dispatch()` with provenance/cost decoration we lean on
  during replay.
- `tests/smoke/test_provenance_replay.py` — the existing cross-
  daemon byte-identity smoke; `session.replay` is its
  generalization.
