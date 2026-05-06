<!--
Thanks for the PR. Tick the boxes that apply; delete sections that don't.
The full contributor guide is in CONTRIBUTING.md at the repo root.
-->

## Summary

<!-- One sentence: why does this exist? Not what changed — why. -->

## Changes

<!-- Bullet list of the substantive changes. Skip if the diff is small and obvious. -->
-
-

## Test plan

- [ ] Unit tests added for new behavior (`tests/unit/`)
- [ ] Smoke tests added or updated if the wire shape changed (`tests/smoke/`)
- [ ] `cmake --build build && ctest --test-dir build --output-on-failure` is 100% green locally
- [ ] Build is warning-clean under the project flags (`-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion ...`)
- [ ] Tests that SKIP on my machine due to optional deps are noted below

<!-- If anything SKIPs, list it here so the reviewer doesn't spend time hunting:
SKIPped on my box: smoke_observer_tcpdump (no CAP_NET_RAW), …
-->

## Protocol changes

- [ ] No protocol changes
- [ ] Minor protocol bump (additive only); `kProtocolVersionMinor` updated; policy in `docs/05-protocol-versioning.md` followed
- [ ] Major protocol bump (breaking); RFC issue opened first and linked below

<!-- If you bumped the protocol, link the RFC issue: -->

## Determinism

- [ ] No new endpoint, OR
- [ ] New endpoint is deterministic against `(method, params, snapshot)` on the cores-only branch
- [ ] If non-deterministic, it is added to the determinism-gate exclusion list with a one-line rationale (`tests/smoke/test_provenance_replay.py` / `tests/smoke/test_live_determinism_gate.py`)
- [ ] Live-process determinism considered — see `docs/04-determinism-audit.md` if the endpoint runs against live targets

## Cost

- [ ] `_cost.bytes` and `tokens_est` for the new endpoint(s) are documented (in the schema, the worklog, or both)
- [ ] No O(N²) growth in response size unless capped by a `view` descriptor (`limit`, `summary`, `fields`)
- [ ] `cost_hint` is set: `low` / `medium` / `high` / `unbounded`

## Schema

- [ ] `describe.endpoints` updated with full draft-2020-12 schema for the new params and returns
- [ ] `requires_stopped` set correctly (true only if the endpoint truly cannot run on a running target)
- [ ] `requires_target` set correctly
- [ ] Schema drift test (`test_describe_endpoints_schema`) updated if a new shape is asserted

## Worklog

- [ ] Updated `docs/WORKLOG.md` with a session entry (newest at top)
- [ ] Not applicable (small fix, doc-only, etc.)

## AI-assisted

- [ ] No AI assistance
- [ ] AI-assisted; co-author trailer added to commits (e.g. `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`)

## Linked issues

<!-- Closes #NNN, refs #MMM. If this is the implementation of an RFC, link it. -->
