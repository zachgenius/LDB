#pragma once

#include <nlohmann/json.hpp>
#include <string>

// Provenance metadata — the `_provenance` field on every successful
// JSON-RPC response per docs/02-ldb-mvp-plan.md §3.5 (cores-only MVP
// scope settled in dc01e5f).
//
//   "_provenance": {"snapshot": "<value>", "deterministic": <bool>}
//
//   • core-loaded target  → snapshot = "core:<lowercase-hex-sha256>",
//                            deterministic = true.
//   • live target         → snapshot = "live", deterministic = false.
//   • no target / unknown → snapshot = "none", deterministic = false.
//
// The contract is: identical (method, params, snapshot) against the
// same core MUST yield byte-identical `data`. This is the deterministic-
// protocol gate enforced by tests/smoke/test_provenance_replay.py.
//
// Errors do NOT carry `_provenance` (consistent with `_cost`), since
// provenance only attaches to a *result* — an error didn't consult any
// inferior state.

namespace ldb::protocol::provenance {

using nlohmann::json;

// Build the `_provenance` object from a snapshot string. Determinism is
// derived from the prefix: "core:..." → true, otherwise false. This
// keeps the rule in one place — the dispatcher passes only the snapshot
// through and lets this helper compute determinism.
json compute(const std::string& snapshot);

// Returns true iff the snapshot represents a deterministic source
// (currently "core:<hex>"; "live" and "none" are non-deterministic).
bool is_deterministic(const std::string& snapshot);

}  // namespace ldb::protocol::provenance
