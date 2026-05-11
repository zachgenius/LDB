// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// View descriptors — declarative shaping of array-returning RPC
// responses. The first cut supports:
//
//   • fields  : keep only the named keys on each object item
//   • limit   : cap the number of items returned
//   • offset  : skip the first N items
//   • summary : return a small sample plus the total count
//
// The agent puts the descriptor inside the request's `params.view`
// object. See docs/02-ldb-mvp-plan.md §3.3.
//
// Deferred to later commits: tabular, max_string, max_bytes, cursor.

namespace ldb::protocol::view {

struct Spec {
  std::vector<std::string> fields;     // empty = no projection
  std::optional<std::uint64_t> limit;  // unset = no cap
  std::uint64_t offset = 0;
  bool summary = false;
  // Snapshot to diff the current response array against. When set,
  // diff-aware endpoints (currently module.list / thread.list) emit
  // a set-symmetric-difference of items annotated with diff_op,
  // instead of the full array. Endpoints that haven't opted in
  // silently ignore this field; describe.endpoints documents
  // per-endpoint support. See compute_diff for the math.
  std::optional<std::string> diff_against;
};

// Default sample size used when summary=true.
constexpr std::size_t kSummarySampleSize = 5;

// Parse a Spec from a request's params object. Reads `params["view"]`
// if present; returns a default-constructed Spec otherwise. Throws
// std::invalid_argument for malformed view (wrong type, negative
// numbers, non-string entries in fields).
Spec parse_from_params(const nlohmann::json& params);

// Apply a Spec to an array of items, producing a JSON object whose
// shape is:
//
//   {
//     <items_key>: [...projected and sliced items...],
//     "total"     : <original size>,            // always present
//     "next_offset": <offset+limit>,            // present iff limit
//                                               // truncated and there's more
//     "summary"   : true                        // present iff summary mode
//   }
//
// `items` is taken by value to allow in-place mutation. Pass with
// std::move when ownership transfer is desired.
nlohmann::json apply_to_array(nlohmann::json items, const Spec& spec,
                              std::string_view items_key);

// Compute the set-symmetric-difference between two arrays of objects
// (post-V1 plan #5). Items in `current` but not in `baseline` get
// diff_op="added"; items in `baseline` but not in `current` get
// diff_op="removed". Equality is whole-item JSON-bytes equality
// (order-independent). Returns a JSON array.
//
// A modified item — same identity but different fields — surfaces as
// one "removed" entry (the old shape) plus one "added" entry (the new
// shape). Identity-keyed change detection ("name=X changed from
// addr=A to addr=B") is a v1.4+ enhancement.
nlohmann::json compute_diff(const nlohmann::json& baseline,
                            const nlohmann::json& current);

}  // namespace ldb::protocol::view
