// SPDX-License-Identifier: Apache-2.0
#include "protocol/cost.h"

#include <array>
#include <optional>
#include <string>
#include <string_view>

namespace ldb::protocol::cost {

namespace {

// Plan §3.2 enumerates the well-known array keys. When more than one
// array is present in `data`, prefer one of these (in this order) so
// the heuristic remains stable across releases.
//
// Add new collection-style keys here as endpoints land — entries are
// case-sensitive and matched against exact key names. Never remove an
// entry without bumping the protocol version: agents may rely on the
// reported `items` for budget decisions.
constexpr std::array<std::string_view, 24> kKnownArrayKeys = {
    "groups",    "packets",   "sockets",   "modules",   "events",
    "endpoints", "threads",   "frames",    "regions",   "artifacts",
    "sessions",  "probes",    "strings",   "fds",       "maps",
    "symbols",   "xrefs",     "addresses", "matches",   "entries",
    "values",    "fields",    "rows",      "items",
};

// Find the array-valued key inside an object payload. Returns the
// chosen array's size. Returns std::nullopt when the heuristic can't
// pick a single array.
std::optional<std::size_t> pick_array_size(const json& obj) {
  // Step 1: prefer a known plan keyword if present and array-valued.
  for (auto k : kKnownArrayKeys) {
    auto it = obj.find(std::string(k));
    if (it != obj.end() && it->is_array()) {
      return it->size();
    }
  }
  // Step 2: fall back to "the only array-valued key in data".
  std::size_t array_count = 0;
  std::size_t chosen = 0;
  for (auto it = obj.begin(); it != obj.end(); ++it) {
    if (it->is_array()) {
      ++array_count;
      chosen = it->size();
      if (array_count > 1) return std::nullopt;
    }
  }
  if (array_count == 1) return chosen;
  return std::nullopt;
}

}  // namespace

json compute_cost(const json& data) {
  std::string dumped = data.dump();
  std::size_t bytes = dumped.size();
  std::size_t tokens_est = (bytes + 3) / 4;

  json out;
  out["bytes"] = bytes;
  if (data.is_array()) {
    out["items"] = data.size();
  } else if (data.is_object()) {
    if (auto n = pick_array_size(data); n.has_value()) {
      out["items"] = *n;
    }
  }
  out["tokens_est"] = tokens_est;
  return out;
}

}  // namespace ldb::protocol::cost
