# Probe Recipes — Replayable RPC Sequences

> Tier 2 §6 of `docs/POST-V0.1-PROGRESS.md`. v0.4 of the roadmap promoted to v0.2.
> Storage format: `recipe-v1`. Wire format: schema-typed JSON-RPC.

A **recipe** is a named, parameterized sequence of RPC calls extracted
from a session's `rpc_log`. Agents use recipes to replay common
investigation patterns ("open this binary, layout these N structs, find
these strings, set up this probe set") as a single call rather than
re-issuing each RPC by hand.

## Why bother

The agent's investigative work tends to repeat:

- "When something looks like a BTP frame, do steps A/B/C."
- "When examining a memory leak, walk the heap pattern this way."
- "When booting a target binary the first time, capture this set of layouts."

Without recipes, the agent re-discovers the sequence from scratch per
session. With recipes, the playbook is named, named playbooks are
shareable (recipes round-trip across `.ldbpack` for free), and the
agent's "what worked last time" memory becomes addressable by id.

## Endpoint set

```
recipe.create({name, description?, calls, parameters?})
  → {recipe_id, name, call_count}

recipe.from_session({source_session_id, name, description?, filter?})
  → {recipe_id, name, call_count}

recipe.list({})
  → {recipes: [...summary...], total}

recipe.get({recipe_id})
  → {recipe_id, name, description?, parameters, calls, ...}

recipe.run({recipe_id, parameters?})
  → {responses: [{seq, method, ok, data?, error?}], total}

recipe.delete({recipe_id})
  → {recipe_id, deleted}
```

Plus the sibling GC primitive:

```
artifact.delete({id})
  → {id, deleted}
```

## Storage model

Recipes are persisted as `format: "recipe-v1"` artifacts under the
synthetic `build_id "_recipes"`, with name `recipe:<recipe-name>`. The
artifact's bytes carry the recipe envelope as compact JSON; the
artifact's meta mirrors high-level fields so `recipe.list` doesn't need
to read+parse every blob.

```jsonc
// Envelope (artifact bytes), recipe-v1
{
  "description": "BTP recovery boot pattern",
  "parameters": [
    {"name": "path",      "type": "string"},
    {"name": "target_id", "type": "integer"}
  ],
  "calls": [
    {"method": "target.open", "params": {"path": "{path}"}},
    {"method": "module.list", "params": {"target_id": "{target_id}"}},
    {"method": "type.layout", "params": {"target_id": "{target_id}",
                                          "name": "btp_state"}}
  ]
}
```

The decision to reuse the artifact store rather than introduce a fresh
sqlite table:

- **Build-ID-keyed addressing** is already there (`_recipes` is a
  synthetic build-id; recipes share the same SQL contract as a normal
  artifact under that build).
- **`.ldbpack` portability** comes for free — recipes round-trip across
  machines without a new pack format.
- **Single delete path**: `recipe.delete` is a thin type-checked wrapper
  over `artifact.delete`; no orphaning between two stores.

The cost is one artifact-list filter — `RecipeStore::list()` queries
`build_id = "_recipes"` and filters to `format = "recipe-v1"`. Cheap.

## Parameter substitution (MVP)

The recipe author pre-templatizes each call's params: any **STRING**
value matching the literal `"{slot}"` (whole-string match, no
substring) is treated as a substitution slot.

At `recipe.run` time, the dispatcher walks every `calls[i].params`
recursively (objects, arrays, nested) and replaces each placeholder
with:

1. The caller's `parameters[slot]` value (if supplied), OR
2. The slot's declared `default` value (if any), OR
3. Surfaces `kInvalidParams` ("missing required parameter '<slot>'")
   BEFORE any RPC is dispatched.

The substituted value can be any JSON type the caller supplies — an
integer placeholder `"{target_id}"` becomes the number `1`, not the
string `"1"`.

A placeholder that matches no declared slot is treated as a literal —
a string that happens to look like a placeholder. This is intentional:
the alternative ("error on unknown slot") would force every recipe
author to declare every brace-string they ever write into a call's
params. The recipe.create author MAY declare extra slots that are
unused; that's fine.

### What's deferred (v0.5+)

- **Substring substitution**: `"prefix-{name}-suffix"` — parser
  complexity that doesn't pay for itself yet.
- **JSONPath targeting**: `replaces: "$.params.path"` — a real
  JSONPath dialect adds dependency weight; the whole-string match
  covers the typical-case at zero cost.
- **Auto-detection of repeated values across calls** during
  `recipe.from_session`: the v0.5 follow-up. For now, the agent
  re-creates the recipe via `recipe.create` if it wants slots.
- **Type coercion**: an `"integer"` slot accepts whatever JSON type
  the caller supplies; the dispatcher trusts the value. A future
  version may enforce slot types at substitute-time.

## Error policy

`recipe.run` is **stop-on-first-error**. After the first failure the
loop breaks; the failing entry is the last in `responses`, and the
caller can examine `responses[-1]` to see what blew up. The wrapper
itself returns `ok=true` — the failure is per-call, not per-recipe.

A missing required parameter surfaces as `responses[0].ok = false`
with `error.code = -32602` (kInvalidParams) and `error.message`
naming the slot. No RPCs are dispatched.

## Extraction from sessions

`recipe.from_session` walks the source session's `rpc_log` in
seq-ascending order and applies:

- `filter.since_seq` / `until_seq` — half-open seq-range cap.
- `filter.include_methods` — an explicit allowlist; if specified,
  ONLY these methods are kept.
- `filter.exclude_methods` — additional removals (composes with the
  default strip set if `include_methods` is not specified).
- The default strip set: `hello`, `describe.endpoints`,
  `session.create`, `session.attach`, `session.detach`,
  `session.list`, `session.info`, plus all `recipe.*` methods. These
  are protocol bookkeeping, not investigation steps worth replaying.
- Failed (ok=false) calls are dropped — they're not worth replaying.

The remaining calls form the recipe body, in original order, with the
serialized `params` field preserved verbatim. Auto-detection of
repeated values (e.g. the same `target_id` appearing 10 times → likely
a parameter, surface as `target_id`) is **deferred**; the produced
recipe has no slots. Re-create via `recipe.create` if you want
parameterization.

## Examples

### Capture and replay a layout pattern

```jsonc
// 1. While attached to session "btp_dig", do the work
{"method": "session.attach", "params": {"id": "<sid>"}}
{"method": "target.open", "params": {"path": "/usr/bin/btpd"}}
{"method": "module.list", "params": {"target_id": 1}}
{"method": "type.layout", "params": {"target_id": 1, "name": "btp_frame"}}
{"method": "type.layout", "params": {"target_id": 1, "name": "btp_state"}}
{"method": "session.detach"}

// 2. Promote to recipe (literal replay, no slots).
{"method": "recipe.from_session",
 "params": {"source_session_id": "<sid>", "name": "btp_layouts"}}

// 3. Re-create with parameters (target_id may differ next time).
{"method": "recipe.create",
 "params": {"name": "btp_layouts",
            "parameters": [
              {"name": "binary",    "type": "string"},
              {"name": "target_id", "type": "integer"}
            ],
            "calls": [
              {"method": "target.open",
               "params": {"path": "{binary}"}},
              {"method": "module.list",
               "params": {"target_id": "{target_id}"}},
              {"method": "type.layout",
               "params": {"target_id": "{target_id}",
                          "name": "btp_frame"}},
              {"method": "type.layout",
               "params": {"target_id": "{target_id}",
                          "name": "btp_state"}}
            ]}}

// 4. Replay against a different binary.
{"method": "recipe.run",
 "params": {"recipe_id": <id>,
            "parameters": {"binary": "/usr/bin/btpd-v2",
                           "target_id": 1}}}
```

## Done criteria (closed)

- [x] 6 endpoints exist: recipe.{create, from_session, list, get, run, delete}
- [x] artifact.delete added as sibling
- [x] Recipes stored as `format: "recipe-v1"` artifacts
- [x] Parameter substitution works (string-equality MVP)
- [x] Round-trip: session → from_session → run reproduces original responses
- [x] Failing-then-green tests
- [x] Build warning-clean
- [x] ctest green: 41 → 42 (smoke_recipe added; +10 unit cases inside unit_tests)
