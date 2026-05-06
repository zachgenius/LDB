# Artifact knowledge graph (post-v0.1 §7, Tier 3)

LDB's artifact store holds the bytes the agent has captured: memory
dumps, decoded payloads, recipe blobs, schema files. From v0.3 onward,
artifacts can also be linked by **typed relations**, forming a small
knowledge graph that travels with the investigation.

The motivating example from the roadmap:

> "this XML is the schema parsed by `xml_parse` which is called from
> `init_schema` in build `<bid>`"

The agent learns these facts during an investigation (from a stack
walk, a strings sweep, a manual hypothesis); the relation graph is
where the facts get pinned so a future replay or a teammate's import
sees them.

## Data model

One relation:

```text
ArtifactRelation {
  id          : int64    (autoincrement, opaque, stable handle)
  from_id     : int64    (artifact id — source endpoint)
  to_id       : int64    (artifact id — target endpoint)
  predicate   : string   (free-form, non-empty)
  meta        : object   (small, optional)
  created_at  : int64    (unix epoch nanoseconds)
}
```

Storage is the same `index.db` as artifacts (sqlite, WAL):

```sql
CREATE TABLE artifact_relations(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  from_id INTEGER NOT NULL,
  to_id INTEGER NOT NULL,
  predicate TEXT NOT NULL,
  meta TEXT,                    -- JSON
  created_at INTEGER NOT NULL,  -- unix epoch nanoseconds
  FOREIGN KEY(from_id) REFERENCES artifacts(id) ON DELETE CASCADE,
  FOREIGN KEY(to_id)   REFERENCES artifacts(id) ON DELETE CASCADE
);
CREATE INDEX idx_relations_from ON artifact_relations(from_id);
CREATE INDEX idx_relations_to   ON artifact_relations(to_id);
CREATE INDEX idx_relations_pred ON artifact_relations(predicate);
```

### `ON DELETE CASCADE` contract

Deleting an artifact (`artifact.delete`, or `ArtifactStore::remove`)
drops every relation whose `from_id` or `to_id` references it. This is
the GC contract the agent relies on: there is no "orphan relation"
state to clean up separately.

### Predicate policy

Predicates are **free-form short strings**, not a closed enum. A closed
enum would force every new relation kind through a daemon update, which
defeats the point of an agent-first store. Empty predicates are
rejected by the daemon with `-32602`.

There are no reserved keywords in this slice. Common predicates the
agent should prefer for legibility:

| Predicate         | Meaning                                                     |
|-------------------|-------------------------------------------------------------|
| `parsed_by`       | "this blob is parsed by that artifact" (e.g. XML→parser)    |
| `extracted_from`  | "this blob is a slice of that one" (e.g. frame→full capture) |
| `called_by`       | "this routine is invoked by that one"                       |
| `ancestor_of`     | "this artifact is a prior version of that one"              |
| `contains`        | "this archive contains that artifact"                       |
| `references`      | "this code references that data"                            |

Use whatever predicate makes sense for the investigation; the catalog
above is descriptive, not prescriptive.

## Wire surface

Three endpoints, all under `artifact.*`:

### `artifact.relate`

```jsonrpc
→ {"method":"artifact.relate", "params":{
     "from_id": 12, "to_id": 34,
     "predicate": "parsed_by",
     "meta": {"function": "xml_parse", "line": 42}
   }}
← {"ok": true, "data":{
     "relation_id": 7, "from_id": 12, "to_id": 34,
     "predicate": "parsed_by",
     "created_at": 1746547200123456789
   }}
```

Both endpoint ids must already exist; missing ids surface as `-32000`
(`backend::Error`). Predicate must be non-empty.

### `artifact.relations`

```jsonrpc
→ {"method":"artifact.relations", "params":{
     "artifact_id": 12,
     "predicate":   "parsed_by",
     "direction":   "out"
   }}
← {"ok": true, "data":{
     "relations": [{...}, {...}],
     "total": 2
   }}
```

All filters are optional. `direction` is one of `"out"` (edges from
`artifact_id`), `"in"` (edges to it), or `"both"` (default). When
`artifact_id` is omitted, `direction` is irrelevant and every relation
is returned.

The standard view spec applies to the `relations` array
(`limit`/`offset`/`fields`/`summary`).

### `artifact.unrelate`

```jsonrpc
→ {"method":"artifact.unrelate", "params":{"relation_id": 7}}
← {"ok": true, "data":{"relation_id": 7, "deleted": true}}
```

Idempotent: a second call returns `deleted: false` (not an error).
This is the symmetric pair to `artifact.delete`'s id-level GC.

## `.ldbpack` round-trip

Relations are exported alongside artifacts. The pack manifest grows a
top-level `"relations"` array; each entry encodes endpoints as
`(build_id, name)` pairs (sqlite autoincrement IDs are not portable).
On import, each endpoint is resolved via `get_by_name` to the
destination store's freshly-assigned ids.

```json
{
  "format": "ldbpack/1",
  "sessions": [...],
  "artifacts": [...],
  "relations": [
    {
      "from_build_id": "build-cafe", "from_name": "schema.xml",
      "to_build_id":   "build-cafe", "to_name":   "frame.bin",
      "predicate": "parsed_by",
      "meta": {"function": "xml_parse"},
      "created_at": 1746547200123456789
    }
  ]
}
```

`pack_session` emits every relation in the source store. `pack_artifacts`
filters to relations whose **both** endpoints landed in the exported
artifact set; cross-set edges are dropped silently — the producer
decides what constitutes a coherent slice.

A relation whose endpoint can't be resolved on import (typically under
`conflict_policy=skip` when a duplicate artifact was preserved-as-local
and the relation's endpoint mapping is therefore ambiguous) is reported
in the `skipped` list with reason `"endpoint not present after import"`.

## What's deferred

- **Auto-derivation from session logs.** Inferring relations from
  `rpc_log` entries (e.g. `mem.dump_artifact` at PC X "extracted_from"
  the binary at the same PC) is a v0.5 follow-up. This slice ships the
  manual-attach path only.
- **Recursive graph queries.** Single-hop only — no `SHORTEST_PATH` or
  transitive closure. The agent walks multi-hop queries in user-space
  by issuing `artifact.relations` repeatedly.
- **Predicate enum.** Free-form strings stay. The table above is
  descriptive; daemon enforcement is just "non-empty".
- **Relation versioning.** The id is the only stable handle. Updating a
  relation = `artifact.unrelate` + `artifact.relate`.
- **Performance for >10K relations.** Indexes are in place; the schema
  is fine for typical investigation scale. Bigger graphs are a problem
  for v0.5.

## See also

- Roadmap: `docs/03-ldb-full-roadmap.md`, Track C.
- Plan: `docs/02-ldb-mvp-plan.md` §4.7 (artifact RPC).
- Sibling slice: §6 `artifact.delete` (the GC primitive that triggers
  the CASCADE), §10 `recipe.from_session` (which produces artifacts the
  agent will then relate).
