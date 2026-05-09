// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <nlohmann/json.hpp>

// Cost-preview metadata — the `_cost` field on every successful
// JSON-RPC response per docs/02-ldb-mvp-plan.md §3.2:
//
//   "_cost": {"bytes": N, "items": M, "tokens_est": T}
//
// The agent uses this to budget-check before pulling a big response.
// Errors do NOT carry `_cost`; they're short by definition.
//
// `bytes`     : exact serialized byte count of the response's `data`.
// `items`     : present iff `data` has one obvious array-valued key.
//               Heuristic: pick a known plan keyword first
//               (modules, regions, frames, ...); otherwise the only
//               array-valued key. If `data` is itself a top-level
//               JSON array, `items` is its size. Otherwise absent.
// `tokens_est`: (bytes + 3) / 4 — a byte-level approximation, NOT
//               literal tokens. The same formula is used for CBOR
//               output once that lands.

namespace ldb::protocol::cost {

using nlohmann::json;

// Compute the `_cost` object for a given response data payload.
// Returns a JSON object with the keys described above.
json compute_cost(const json& data);

}  // namespace ldb::protocol::cost
