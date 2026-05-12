# Own symbol index — design note

Post-V1 plan items **#18 (own symbol index)** and **#19 (own DWARF
reader)** from `docs/15-post-v1-plan.md`, and the first commit in
v1.5's critical chain per `docs/17-version-plan.md`. The roadmap
calls these items "the largest user-visible feature gate"
(`session.replay` against live targets needs deterministic, cross-
binary, ordering-stable symbol/type queries).

This note answers two questions before any code is written:

1. **Do we need an own DWARF reader (#19)?**
2. **What does the own symbol index (#18) actually look like — schema,
   population, invalidation, query surface?**

## TL;DR

- **No own DWARF reader for v1.5.** The roadmap watchlist already
  flagged #19 ROI as questionable; the analysis below confirms it.
  Cache SBAPI-derived data into our own index instead. The decoupling
  goal (#19's stated rationale) is achieved by the cache boundary, not
  by replacing LLDB's reader.
- **Own symbol index is a SQLite database** under `LDB_STORE_ROOT/
  symbol_index.db`, keyed by `(build_id, kind, name)` with a per-row
  `populated_at` timestamp + `(file_mtime_ns, file_size)` cache key
  for invalidation. Re-uses the existing ArtifactStore sqlite
  conventions (connection pool, PRAGMA discipline, schema-version
  table).
- **Population is lazy on first query, cached forever.** First
  `correlate.symbols` against `build_id=X` walks LLDB's symbol table
  once and writes every row. Subsequent calls against the same
  `build_id` (in the same target or across targets, even in a
  different ldbd process on the same host) hit the index directly.
- **Migration is invisible to callers.** `correlate.*`'s wire shape
  is unchanged; the dispatcher routes the query through the index
  when it's hot, falls through to the existing backend path on miss
  and writes the result back.

## 1. Today's pain

`docs/15-post-v1-plan.md` says today's `correlate.*` "re-derives
across targets each call." Concretely:

- `handle_correlate_symbols` (`dispatcher.cpp:4166`) loops over the
  caller-supplied `target_ids` and calls
  `backend_->find_symbols(tid, query)` for each.
- `LldbBackend::find_symbols` (`lldb_backend.cpp:698`) issues
  `SBTarget::FindSymbols` / `FindFunctions` per call.
- There is **no caching**. Every `correlate.symbols name=foo
  target_ids=[1,2,3]` walks each target's symbol table fresh, even
  when targets 1/2/3 share a build_id (e.g. agent sweeps across a
  hundred core dumps of the same binary).

Same shape applies to `correlate.types` (re-runs `find_type_layout`)
and `correlate.strings` (re-runs `find_strings`). Each LLDB query
walks debug info and accelerator tables; cold-cache cost is
~hundred-millisecond per binary per call.

User-visible symptoms:

- Agents that fan out across many targets pay O(N) latency where the
  shared structure should make it O(1).
- `session.replay` against a captured trace re-runs every correlate
  query at replay time — currently feasible only because traces are
  small; large traces stall.
- The same investigation re-run a minute later does the same work
  again, because LLDB's in-process caches don't survive process exit.

## 2. Why not an own DWARF reader (#19)?

The roadmap rationale for #19 is "decouple indexer from full LLDB."
That's a means, not an end. The actual decoupling we want is:

- **Lifetime**: the index lives on disk; LLDB process exits don't
  drop it.
- **Cross-binary**: querying build_id X doesn't require an open
  SBTarget for any binary using X.
- **Replay**: a replayed session queries the same index a live
  session would.

**All three are achieved by the cache boundary**, regardless of who
populates it. Owning the DWARF reader on top of that buys:

| Benefit                                       | Already covered by cache? |
|-----------------------------------------------|---------------------------|
| Index survives LLDB process death             | Yes — sqlite on disk      |
| Cross-binary query without open SBTarget      | Yes — query the cache     |
| Replay reads same data live read              | Yes — cache is the source |
| Independent of `liblldb` ABI break            | No                        |
| Faster cold population (skip LLDB plumbing)   | Marginal                  |
| Custom DWARF extensions (e.g. DWARF 5 split)  | No (rarely needed today)  |

The remaining unique-to-#19 wins are real but specialised. LLDB's
DWARF reader tracks upstream LLVM, handles split-DWARF, DWARF 5 line
tables, and the dozens of GCC/Clang quirks we'd otherwise have to
chase ourselves. The maintenance burden of forking
`libDebugInfoDWARF` is ~one engineer continuously; the wins above
don't justify it.

**Decision: no own DWARF reader in v1.5.** Re-evaluate if:

- A specific endpoint needs a DWARF extension LLDB doesn't expose
  via SBAPI (none today).
- `liblldb` ABI breaks force us to pin a specific LLDB version
  anyway.
- The cache hit rate is so high that the marginal cold-population
  speedup matters (sub-second cold runs aren't a sign of this).

The decoupling goal is real; the means is the cache boundary, not
the reader.

## 3. Index schema

SQLite at `${LDB_STORE_ROOT}/symbol_index.db`. **Separate database
file**, not a new family on the artifact-store DB: symbol-index
queries are read-heavy and concurrent-friendly while artifact writes
are infrequent. A separate file keeps `PRAGMA journal_mode`
independently tunable, lets `symbol_index.db` run `WAL` +
`synchronous=NORMAL` without compromising artifact durability, and
means index corruption never threatens artifacts.

### 3.1. Tables

```sql
-- One row per binary we've indexed. build_id is the primary cache
-- key; (file_mtime_ns, file_size) form the cache-invalidation tuple.
CREATE TABLE IF NOT EXISTS binaries (
  build_id      TEXT NOT NULL PRIMARY KEY,
  path          TEXT NOT NULL,       -- last-seen on-disk path
  file_mtime_ns INTEGER NOT NULL,
  file_size     INTEGER NOT NULL,
  arch          TEXT NOT NULL,       -- e.g. "x86_64-linux"
  populated_at  INTEGER NOT NULL,    -- unix ns; "this is when we walked"
  schema_ver    INTEGER NOT NULL     -- bumps drop the row on read
);

-- Symbol rows mirror backend::SymbolHit (lldb_backend.h) so the row →
-- response shape conversion is a memcpy-equivalent.
CREATE TABLE IF NOT EXISTS symbols (
  build_id      TEXT NOT NULL,
  name          TEXT NOT NULL,       -- mangled
  demangled     TEXT,                -- nullable for non-C++
  kind          TEXT NOT NULL,       -- function|data|other
  address       INTEGER NOT NULL,    -- file-relative; runtime adds slide
  size          INTEGER NOT NULL,
  module_path   TEXT NOT NULL,
  source_file   TEXT,                -- nullable
  source_line   INTEGER,             -- nullable
  PRIMARY KEY (build_id, name, address),
  FOREIGN KEY (build_id) REFERENCES binaries(build_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS symbols_by_demangled
  ON symbols(build_id, demangled);
CREATE INDEX IF NOT EXISTS symbols_by_kind_addr
  ON symbols(build_id, kind, address);

-- Type layouts. Members stored as JSON in a TEXT column because:
--   (a) member counts are bounded (typical: <50, p99: <200);
--   (b) we never query "find me types where some member matches X";
--   (c) the response shape is JSON anyway, so we save a serialise step.
CREATE TABLE IF NOT EXISTS types (
  build_id      TEXT NOT NULL,
  name          TEXT NOT NULL,       -- canonical, after typedef-strip
  byte_size     INTEGER NOT NULL,
  members_json  TEXT NOT NULL,
  PRIMARY KEY (build_id, name),
  FOREIGN KEY (build_id) REFERENCES binaries(build_id) ON DELETE CASCADE
);

-- Strings harvested from rodata. Reuses the string-list endpoint's
-- shape so correlate.strings becomes a simple SELECT.
CREATE TABLE IF NOT EXISTS strings (
  build_id      TEXT NOT NULL,
  address       INTEGER NOT NULL,
  text          TEXT NOT NULL,
  section       TEXT NOT NULL,
  PRIMARY KEY (build_id, address),
  FOREIGN KEY (build_id) REFERENCES binaries(build_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS strings_by_text ON strings(build_id, text);
```

### 3.2. PRAGMA choices

```sql
PRAGMA journal_mode=WAL;            -- many readers, one writer
PRAGMA synchronous=NORMAL;          -- losing the cache on crash is fine
PRAGMA temp_store=MEMORY;
PRAGMA foreign_keys=ON;             -- so binaries->rows CASCADE works
PRAGMA cache_size=-65536;           -- 64 MiB page cache
```

`synchronous=NORMAL` is intentional: the index is a cache. If a
crash drops the last 100 ms of writes, the next query re-walks LLDB.
Trade-off vs `FULL` is ~100x faster inserts during population.

### 3.3. Schema versioning

`kSymbolIndexSchemaVersion` (constant in `symbol_index.h`) compared
against `PRAGMA user_version` at startup. Mismatch → drop and
recreate every table. No in-place migrations — the cache is
recoverable from LLDB at worst-case cost.

## 4. Population strategy

**Lazy on first query, no background thread.** The dispatcher
routes a `correlate.*` query as:

```
1. Resolve build_id for each target_id (already in TargetState).
2. For each build_id:
     a. SELECT binaries WHERE build_id = ?
        - row absent, OR
        - file_mtime_ns / file_size differs from stat() →
          "needs population".
3. If any build_id needs population:
     a. Begin transaction.
     b. Walk LLDB's symbol / type / strings tables, batch INSERT,
        upsert the binaries row.
     c. Commit.
4. Issue the actual query against the now-warm index.
```

**Why lazy, not eager:**

- We don't know which targets the agent will care about until it
  asks. Pre-populating every loaded module on target.open would
  walk hundreds of MB of debug info per open, most of it never
  queried.
- Lazy means cold-cache cost is paid once per binary per
  investigation, hidden behind the first slow query. Subsequent
  queries are <1 ms.
- The smoke-test surface stays simple: every test starts cold,
  populates on first call, validates the second call returns the
  same shape.

**Why no background thread:**

- Single-writer SQLite + the dispatcher's single-threaded model
  means population always blocks the calling RPC. Backgrounding
  would buy parallelism only if the dispatcher learns async — out
  of scope for v1.5 (see #21 non-stop runtime). Honest trade:
  agents pay cold-cache latency once.

**Bulk population endpoint (opt-in):**

`index.warm({target_ids})` walks every supplied target's
symbols/types/strings into the cache. Useful for replay setup
(`session.replay` populates the cache before re-issuing correlate
queries) and for agents that know they're about to do a wide sweep.
Phase-1 implements this as a thin loop over the
populate-on-first-query path.

## 5. Cache invalidation

Three triggers:

1. **File mtime/size change** — detected on every query against a
   cached build_id. Mismatch → re-walk and replace.
2. **Schema version bump** — detected at daemon startup. Drop all
   tables, restart cold.
3. **Explicit invalidation** — `index.invalidate({build_id})`.
   Useful when the agent knows a binary was patched in-place.
   Implemented as `DELETE FROM binaries WHERE build_id = ?`
   (CASCADE drops rows).

We don't track DWARF section hashes — file mtime + size catches
every real-world change short of timestamp-preserving in-place
patches. Operators who care can call `index.invalidate` after
their patch step.

## 6. Query surface

No new endpoints for v1.5 phase-1. Existing `correlate.types /
symbols / strings` route through the index without wire-shape
changes. Smoke tests that pin the current shape pass unchanged.

**Phase-2 endpoints** (separate commit, not part of #18):

- `symbol.find({build_id, query})` — direct query against the index
  without going through correlate's per-target shape.
- `symbol.xref({build_id, address})` — what references this?
  Today done by walking; index makes it a sqlite query.
- `index.stats({build_id?})` — operator-facing diagnostics
  (row counts, last-populated timestamp, file mtime).

## 7. Lifetime + threading

The index module is a singleton at the daemon level, owned by the
Dispatcher (lifetime matches `Dispatcher::~Dispatcher`). One sqlite
connection per dispatcher; PRAGMA `WAL` means multiple readers are
fine even though we currently have a single-threaded dispatcher
(forward-compat for v1.6's non-stop runtime where event-loop pumps
may read the index concurrently).

The population path holds the write lock for the duration of one
binary's walk. Typical: 50–500 ms per binary. During that window
other read queries against the same build_id wait; queries against
other build_ids proceed. Acceptable given the per-binary-once cost
model.

## 8. Migration plan

**Phase-1 (this design's deliverable):**

1. New `src/index/symbol_index.{h,cpp}` with SQLite schema +
   read/write APIs + cache-invalidation logic.
2. Dispatcher's `handle_correlate_*` checks the index first, falls
   through to the existing backend path on miss and writes the
   result back.
3. Unit tests: schema round-trip, invalidation on mtime change,
   schema-version bump drops + recreates.
4. Smoke test: existing `smoke_correlate` should pass unchanged;
   new `smoke_index_cold_warm` exercises first-cold-then-warm and
   asserts the second call is faster + returns the same shape.

**Phase-2 (separate commit):**

1. `index.warm` / `index.invalidate` / `symbol.find` /
   `symbol.xref` / `index.stats` endpoints.
2. Replay-aware: `session.replay` calls `index.warm` for every
   build_id referenced in the trace before re-issuing correlate
   queries.

**Phase-3 (v1.6 territory):**

1. Cross-process: the index file is sharable across LDB instances
   on the same host. A second LDB process reads what the first
   populated.
2. Distributable index packs: `.ldbpack` extension that bundles
   `symbol_index.db` rows for a specific build_id, signed via the
   existing ed25519 surface.

## 9. Failure matrix

| Failure                                              | Behaviour                                              |
|------------------------------------------------------|--------------------------------------------------------|
| `LDB_STORE_ROOT` unset                               | Index disabled; `correlate.*` falls through to backend |
| `symbol_index.db` corrupted                          | Auto-drop on startup, log warning, reset cache         |
| File mtime check fails (file removed)                | Treat as cache miss; serve from backend, don't reindex |
| sqlite disk-full during population                   | Rollback transaction, fall through to backend, log     |
| build_id missing from binary (stripped, no `.note`)  | Skip indexing for that binary; backend continues       |

Unifying principle: **the index is a cache. It can fail safe —
correlate keeps working, just slower.** Index-aware endpoints
(`index.stats`, `symbol.find`) surface index-disabled state as
`-32002 kBadState` with a hint pointing at `LDB_STORE_ROOT`.

## 10. Out of scope for #18 phase-1

- Cross-binary type / symbol *unification* (e.g. "this `struct
  sk_buff` in /vmlinux is the same type as the one in libxdp").
  The schema supports it via a future `canonical_type_id` column;
  v1.5 ships per-binary only.
- DWARF expression evaluation (location lists, frame base
  expressions). Backend still owns this via LLDB.
- Source-level breakpoint resolution (line tables). Stays in LLDB.
- Inlined-function expansion. Already in LLDB; we cache the
  resolved-symbol output, not the line table.

## 11. Risks / open questions

- **Index size on disk.** Linux glibc-debuginfo is ~10 MB of DWARF
  per build; the indexed form is probably ~2–3 MB. For an agent
  investigating a typical service binary + libc + a few libs,
  total index ~20 MB. Worst case: kernel debuginfo (~1 GB DWARF)
  → ~200 MB index. Phase-1 doesn't paginate; if this becomes a
  real complaint, partition by build_id and lazy-attach.
- **Walk-time vs LLDB version.** Per-binary cold-walk depends on
  how LLDB exposes its symbol table to us. A future LLDB version
  offering a bulk iteration API could shave 2–3x off the cold
  path. Today we iterate `SBTarget::FindSymbols` with a wildcard
  and post-filter — wasteful but correct.
- **Race on `(build_id, path)` collision.** Two binaries with the
  same build_id but different paths shouldn't happen, but if they
  do (someone rebuilt with deterministic flags then moved), the
  cache row's `path` is whichever-was-last. Not a correctness
  issue — symbol data is build_id-keyed; addresses and names are
  still right.
- **Schema bumps cost every dev box a one-time cache rebuild.**
  Worth the trade for "no migrations." Document in the worklog
  when we bump.

## 12. Why this is the right v1.5 starting point

The plan's critical chain reads **#18 → #15 → #16**. Each blocks
the next:

- **#15 (live-process provenance)** wants ordering-stable
  timestamps and a per-endpoint determinism audit. Having an own
  index means we control symbol-resolution timestamps (instead of
  inheriting whatever LLDB stamps on `SBSymbol` resolution), which
  simplifies the audit.
- **#16 (session.fork / session.replay)** wants the same correlate
  query at replay time to return the same answer it did live.
  Today it does — but only because LLDB happens to be
  deterministic for fixed inputs. An own index makes that
  guarantee load-bearing rather than emergent.

Skipping #18 and going straight to #15 / #16 is feasible but loads
extra constraints onto the determinism audit (we'd have to verify
LLDB's symbol-resolution stability across versions, which is a
larger and never-finished task). Landing #18 first turns "LLDB is
hopefully deterministic" into "our cache is deterministic by
construction; LLDB is the populator and its output is captured."

That's the design. Implementation lands in the next commit.

---

## Phase-1 implementation addendum (post-design)

This section documents three behaviours that landed in code but
weren't in the original design above. Recorded here so #15 / #16
implementers don't have to read the dispatcher to learn the
contract.

### A. `iterate_symbols` dedupes by `(schema-name, address)`

The schema PK is `(build_id, name, address)` where `name` is what
`symbol_match_to_row` writes — `mangled` if non-empty, else `name`.
LLDB exposes PLT trampolines, weak aliases, and IFUNC resolvers as
multiple `SBSymbol`s at the same `(name, address)` pair; without
dedupe the second `INSERT` rejects with a UNIQUE constraint and
fails the whole transaction. Mirror of the `SymbolDedupeKey` logic
in `find_symbols` so the cached set matches the cold path exactly.

### B. `correlate.strings` keeps disasm fallback when the string exists

The design's §6 said correlate.strings becomes "a simple SELECT" once
the index is hot. That's only half-true: the wire response also
carries disasm-derived `callsites` (xrefs from `find_string_xrefs`),
and the index doesn't yet cache xrefs (phase-2 `symbol.xref` work).
So the dispatcher short-circuits ONLY when the cache is hot AND
`query_strings` returns empty for the requested text — i.e. when we
KNOW the string isn't present and the xref result must be empty.
When the string IS present, the cold-path `find_string_xrefs` still
runs to produce `callsites`.

### C. `kIterateBucketCap` truncation requires a fall-through safety net

`iterate_symbols` / `iterate_types` / `iterate_strings` cap each
bucket at 100,000 rows for kernel-debuginfo-class binaries. A
truncated index would silently turn "this symbol was capped" into
"this symbol does not exist." The dispatcher now plumbs a
`truncated` flag on `ModuleSymbols/Types/Strings` through
`ensure_indexed` as a `cap_note`; when the indexed query returns
empty AND the cap fired during population, the handler falls
through to backend `find_*` instead of trusting the cache. Genuine
"missing" (cap didn't fire) is still short-circuited from the
index, so correlate.types against a real not-present name stays
sub-millisecond.

### D. Backends without bulk iteration are detected, not poisoned

`GdbMiBackend::iterate_*` (and any future backend that can't do
bulk enumeration) returns all-empty buckets. The dispatcher detects
"every bucket empty after iterate_*" and refuses to populate —
otherwise the binary would be marked `kHot` with zero rows and
every later correlate.* call would silently short-circuit to an
empty result, permanently bypassing the backend's working `find_*`
path. `ensure_indexed` returns false in this case; the dispatcher
falls through to `find_*` exactly as it does when `LDB_STORE_ROOT`
is unset.

### E. Main module is captured at `target.open`, not derived later

The original design (§4) said "build_id is already in TargetState."
There is no TargetState. The dispatcher caches `(target_id →
{build_id, path})` from `OpenResult.modules[0]` in
`handle_target_open` and clears it in `handle_target_close`. The
older "first module with non-empty uuid+path from `list_modules`"
heuristic stays as a fallback for targets opened via `load_core`
/ `create_empty_target` (cores don't typically go through
correlate, and create_empty is followed by `target.attach` which
should plumb the executable through the future TargetState
work). The first-module-with-uuid heuristic picks the wrong module
on real-world Linux paths (`/usr/bin/...` sorts after `/lib/...`
where libc/ld-linux live), so for executables opened via
`target.open` the cached value is load-bearing for correctness.
