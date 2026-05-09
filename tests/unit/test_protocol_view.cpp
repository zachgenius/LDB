// SPDX-License-Identifier: Apache-2.0
// Tests for src/protocol/view — view descriptors.
//
// First-cut features: fields (projection), limit + offset (pagination),
// summary (count + sample). Deferred to later commits: tabular,
// max_string, max_bytes, cursor.

#include <catch_amalgamated.hpp>

#include "protocol/view.h"

using ldb::protocol::view::Spec;
using ldb::protocol::view::apply_to_array;
using ldb::protocol::view::parse_from_params;
using nlohmann::json;

// --- parse_from_params ------------------------------------------------------

TEST_CASE("view::parse: absent view yields default spec",
          "[protocol][view][parse]") {
  Spec s = parse_from_params(json::object());
  CHECK(s.fields.empty());
  CHECK_FALSE(s.limit.has_value());
  CHECK(s.offset == 0);
  CHECK_FALSE(s.summary);
}

TEST_CASE("view::parse: all four fields parsed",
          "[protocol][view][parse]") {
  json p = {{"view", {{"fields", {"name", "uuid"}},
                      {"limit", 10},
                      {"offset", 5},
                      {"summary", false}}}};
  Spec s = parse_from_params(p);
  REQUIRE(s.fields.size() == 2);
  CHECK(s.fields[0] == "name");
  CHECK(s.fields[1] == "uuid");
  CHECK(s.limit.has_value());
  CHECK(*s.limit == 10);
  CHECK(s.offset == 5);
  CHECK_FALSE(s.summary);
}

TEST_CASE("view::parse: summary=true",
          "[protocol][view][parse]") {
  json p = {{"view", {{"summary", true}}}};
  Spec s = parse_from_params(p);
  CHECK(s.summary);
}

TEST_CASE("view::parse: rejects non-object view",
          "[protocol][view][parse][error]") {
  json p = {{"view", "oops"}};
  CHECK_THROWS_AS(parse_from_params(p), std::invalid_argument);
}

TEST_CASE("view::parse: rejects non-array fields",
          "[protocol][view][parse][error]") {
  json p = {{"view", {{"fields", "oops"}}}};
  CHECK_THROWS_AS(parse_from_params(p), std::invalid_argument);
}

TEST_CASE("view::parse: rejects non-string entries in fields",
          "[protocol][view][parse][error]") {
  json p = {{"view", {{"fields", {1, 2, 3}}}}};
  CHECK_THROWS_AS(parse_from_params(p), std::invalid_argument);
}

TEST_CASE("view::parse: rejects negative limit",
          "[protocol][view][parse][error]") {
  json p = {{"view", {{"limit", -1}}}};
  CHECK_THROWS_AS(parse_from_params(p), std::invalid_argument);
}

TEST_CASE("view::parse: rejects negative offset",
          "[protocol][view][parse][error]") {
  json p = {{"view", {{"offset", -3}}}};
  CHECK_THROWS_AS(parse_from_params(p), std::invalid_argument);
}

TEST_CASE("view::parse: rejects non-bool summary",
          "[protocol][view][parse][error]") {
  json p = {{"view", {{"summary", 1}}}};
  CHECK_THROWS_AS(parse_from_params(p), std::invalid_argument);
}

// --- apply_to_array ---------------------------------------------------------

namespace {
json sample_modules() {
  json arr = json::array();
  for (int i = 0; i < 10; ++i) {
    arr.push_back({{"name", "mod" + std::to_string(i)},
                   {"uuid", std::string(8, char('A' + i))},
                   {"size", i * 100}});
  }
  return arr;
}
}  // namespace

TEST_CASE("view::apply: default spec returns all items unchanged",
          "[protocol][view][apply]") {
  json out = apply_to_array(sample_modules(), Spec{}, "items");
  REQUIRE(out["items"].is_array());
  CHECK(out["items"].size() == 10);
  CHECK(out["items"][0]["name"] == "mod0");
  CHECK(out["items"][0]["uuid"] == "AAAAAAAA");
  CHECK(out["items"][0]["size"] == 0);
  // total is always populated so the agent can plan.
  CHECK(out["total"] == 10);
  // No next_offset when everything is included.
  CHECK_FALSE(out.contains("next_offset"));
}

TEST_CASE("view::apply: limit truncates the array",
          "[protocol][view][apply]") {
  Spec s; s.limit = 3;
  json out = apply_to_array(sample_modules(), s, "items");
  CHECK(out["items"].size() == 3);
  CHECK(out["total"] == 10);
  CHECK(out["next_offset"] == 3);
}

TEST_CASE("view::apply: offset skips items",
          "[protocol][view][apply]") {
  Spec s; s.offset = 7;
  json out = apply_to_array(sample_modules(), s, "items");
  CHECK(out["items"].size() == 3);   // 10 - 7
  CHECK(out["items"][0]["name"] == "mod7");
  CHECK_FALSE(out.contains("next_offset"));
}

TEST_CASE("view::apply: offset + limit combine correctly",
          "[protocol][view][apply]") {
  Spec s; s.offset = 5; s.limit = 3;
  json out = apply_to_array(sample_modules(), s, "items");
  CHECK(out["items"].size() == 3);
  CHECK(out["items"][0]["name"] == "mod5");
  CHECK(out["items"][2]["name"] == "mod7");
  CHECK(out["total"] == 10);
  CHECK(out["next_offset"] == 8);
}

TEST_CASE("view::apply: offset past end yields empty",
          "[protocol][view][apply]") {
  Spec s; s.offset = 999;
  json out = apply_to_array(sample_modules(), s, "items");
  CHECK(out["items"].size() == 0);
  CHECK(out["total"] == 10);
  CHECK_FALSE(out.contains("next_offset"));
}

TEST_CASE("view::apply: fields project each object item",
          "[protocol][view][apply]") {
  Spec s; s.fields = {"name", "size"};
  json out = apply_to_array(sample_modules(), s, "items");
  REQUIRE(out["items"].size() == 10);
  for (const auto& item : out["items"]) {
    CHECK(item.contains("name"));
    CHECK(item.contains("size"));
    CHECK_FALSE(item.contains("uuid"));   // not requested
  }
}

TEST_CASE("view::apply: unknown fields are silently ignored",
          "[protocol][view][apply]") {
  Spec s; s.fields = {"name", "no_such_field"};
  json out = apply_to_array(sample_modules(), s, "items");
  REQUIRE(out["items"].size() == 10);
  CHECK(out["items"][0].contains("name"));
  CHECK_FALSE(out["items"][0].contains("no_such_field"));
}

TEST_CASE("view::apply: summary returns sample plus total, sets summary=true",
          "[protocol][view][apply]") {
  Spec s; s.summary = true;
  json out = apply_to_array(sample_modules(), s, "items");
  CHECK(out["summary"] == true);
  CHECK(out["total"] == 10);
  // Sample defaults to 5 — agent can pull more with explicit limit if it
  // wants. Asserting <= 5 keeps the contract loose enough to tune later.
  CHECK(out["items"].size() <= 5);
  CHECK(out["items"].size() >= 1);
}

TEST_CASE("view::apply: combined fields + limit + offset works",
          "[protocol][view][apply]") {
  Spec s;
  s.fields = {"name"};
  s.offset = 4;
  s.limit  = 2;
  json out = apply_to_array(sample_modules(), s, "items");
  REQUIRE(out["items"].size() == 2);
  CHECK(out["items"][0]["name"] == "mod4");
  CHECK(out["items"][1]["name"] == "mod5");
  CHECK_FALSE(out["items"][0].contains("uuid"));
  CHECK(out["next_offset"] == 6);
}

TEST_CASE("view::apply: empty input array",
          "[protocol][view][apply]") {
  Spec s;
  json out = apply_to_array(json::array(), s, "items");
  CHECK(out["items"].is_array());
  CHECK(out["items"].size() == 0);
  CHECK(out["total"] == 0);
}

TEST_CASE("view::apply: non-object items pass through fields-projection unchanged",
          "[protocol][view][apply]") {
  json arr = json::array({1, 2, 3});
  Spec s; s.fields = {"x"};   // would project objects, but items aren't objects
  json out = apply_to_array(std::move(arr), s, "items");
  REQUIRE(out["items"].size() == 3);
  CHECK(out["items"][0] == 1);
}
