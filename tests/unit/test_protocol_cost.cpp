// Tests for src/protocol/cost — _cost preview metadata helper.
//
// Plan §3.2: every successful response carries
//   "_cost": {"bytes": N, "items": M, "tokens_est": T}
// where bytes is the exact serialized byte count of `data`,
// items is present iff `data` has one obvious array key,
// and tokens_est = (bytes + 3) / 4 (round up).
//
// This file exercises the pure helper in isolation. The integration
// (the helper called from serialize_response) is covered separately.

#include <catch_amalgamated.hpp>

#include "protocol/cost.h"
#include "protocol/jsonrpc.h"

using ldb::protocol::cost::compute_cost;
using ldb::protocol::json;

TEST_CASE("compute_cost: empty object data has bytes==2, no items",
          "[protocol][cost]") {
  json data = json::object();
  json c = compute_cost(data);
  REQUIRE(c.contains("bytes"));
  REQUIRE(c["bytes"].get<std::size_t>() == 2);  // "{}"
  REQUIRE_FALSE(c.contains("items"));
  REQUIRE(c["tokens_est"].get<std::size_t>() == 1);  // (2+3)/4 == 1
}

TEST_CASE("compute_cost: bytes is exact length of dump()",
          "[protocol][cost]") {
  json data = {{"hello", "world"}, {"n", 42}};
  std::string dumped = data.dump();
  json c = compute_cost(data);
  REQUIRE(c["bytes"].get<std::size_t>() == dumped.size());
}

TEST_CASE("compute_cost: tokens_est is ceil(bytes/4)",
          "[protocol][cost]") {
  // bytes=2 → (2+3)/4 = 1
  REQUIRE(compute_cost(json::object())["tokens_est"].get<std::size_t>() == 1);

  // craft data to land bytes on each residue mod 4. We don't care which
  // exact size; just that the formula is (bytes+3)/4 in every case.
  json data = {{"a", 1}};
  std::size_t b = data.dump().size();
  std::size_t expected = (b + 3) / 4;
  REQUIRE(compute_cost(data)["tokens_est"].get<std::size_t>() == expected);
}

TEST_CASE("compute_cost: single-array-key data populates items",
          "[protocol][cost]") {
  json data;
  data["modules"] = json::array({"m1", "m2", "m3", "m4"});
  json c = compute_cost(data);
  REQUIRE(c.contains("items"));
  REQUIRE(c["items"].get<std::size_t>() == 4);
}

TEST_CASE("compute_cost: known plan keyword wins over scalar siblings",
          "[protocol][cost]") {
  // Per plan: a `regions` array with a sibling `target_id` scalar still
  // counts as items=N — there's only one array-valued key.
  json data;
  data["regions"] = json::array({1, 2, 3, 4, 5});
  data["target_id"] = 1;
  json c = compute_cost(data);
  REQUIRE(c.contains("items"));
  REQUIRE(c["items"].get<std::size_t>() == 5);
}

TEST_CASE("compute_cost: known plan keywords ranked over unknown arrays",
          "[protocol][cost]") {
  // Two arrays: prefer the known "modules" over an unknown "extras".
  json data;
  data["extras"] = json::array({1, 2, 3});         // unknown key
  data["modules"] = json::array({"m1", "m2"});     // listed in plan heuristic
  json c = compute_cost(data);
  REQUIRE(c.contains("items"));
  REQUIRE(c["items"].get<std::size_t>() == 2);
}

TEST_CASE("compute_cost: multiple unknown arrays => omit items",
          "[protocol][cost]") {
  json data;
  data["foos"] = json::array({1, 2});
  data["bars"] = json::array({1});
  json c = compute_cost(data);
  REQUIRE_FALSE(c.contains("items"));
}

TEST_CASE("compute_cost: data has no arrays => no items",
          "[protocol][cost]") {
  json data = {{"k", "v"}, {"n", 7}};
  json c = compute_cost(data);
  REQUIRE_FALSE(c.contains("items"));
}

TEST_CASE("compute_cost: scalar data => no items, bytes=length",
          "[protocol][cost]") {
  json data = json(42);
  json c = compute_cost(data);
  REQUIRE(c["bytes"].get<std::size_t>() == 2);  // "42"
  REQUIRE_FALSE(c.contains("items"));
}

TEST_CASE("compute_cost: top-level array-only data populates items via fallback",
          "[protocol][cost]") {
  // If `data` IS an array (rare but possible), items=size.
  json data = json::array({1, 2, 3, 4, 5, 6, 7});
  json c = compute_cost(data);
  REQUIRE(c.contains("items"));
  REQUIRE(c["items"].get<std::size_t>() == 7);
}

TEST_CASE("compute_cost: empty array under known key => items==0",
          "[protocol][cost]") {
  json data;
  data["modules"] = json::array();
  json c = compute_cost(data);
  REQUIRE(c.contains("items"));
  REQUIRE(c["items"].get<std::size_t>() == 0);
}
