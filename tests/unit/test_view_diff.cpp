// SPDX-License-Identifier: Apache-2.0
// Unit tests for protocol::view diff-mode helpers (post-V1 plan #5).
//
// Two stateless pieces:
//
//   * compute_diff(baseline, current) returns the set-symmetric-
//     difference of the two arrays under whole-item JSON equality.
//     Items present in `current` but not in `baseline` are emitted
//     with diff_op="added"; items present in `baseline` but not in
//     `current` are emitted with diff_op="removed". No "changed" —
//     a modified item appears as one removed + one added entry.
//     The result is an ARRAY of items, each with diff_op prepended;
//     callers feed it to apply_to_array as usual.
//
//   * Spec.diff_against parses from view.diff_against (string).
//
// Caching of baselines is a Dispatcher concern (DiffCache); this
// translation unit only validates the stateless math.

#include <catch_amalgamated.hpp>

#include "protocol/view.h"

#include <nlohmann/json.hpp>

using nlohmann::json;
using ldb::protocol::view::compute_diff;
using ldb::protocol::view::parse_from_params;

TEST_CASE("view.diff: same arrays produce empty diff",
          "[protocol][view][diff]") {
  json baseline = json::array({
      json{{"name", "a"}, {"value", 1}},
      json{{"name", "b"}, {"value", 2}},
  });
  json current = baseline;  // identical
  auto d = compute_diff(baseline, current);
  CHECK(d.is_array());
  CHECK(d.size() == 0);
}

TEST_CASE("view.diff: items added between baseline and current",
          "[protocol][view][diff]") {
  json baseline = json::array({
      json{{"name", "a"}},
  });
  json current = json::array({
      json{{"name", "a"}},
      json{{"name", "b"}},
      json{{"name", "c"}},
  });
  auto d = compute_diff(baseline, current);
  REQUIRE(d.is_array());
  REQUIRE(d.size() == 2);
  for (const auto& el : d) {
    CHECK(el.value("diff_op", std::string{}) == "added");
    const std::string nm = el.value("name", std::string{});
    CHECK((nm == "b" || nm == "c"));
  }
}

TEST_CASE("view.diff: items removed between baseline and current",
          "[protocol][view][diff]") {
  json baseline = json::array({
      json{{"name", "a"}},
      json{{"name", "b"}},
  });
  json current = json::array({
      json{{"name", "a"}},
  });
  auto d = compute_diff(baseline, current);
  REQUIRE(d.size() == 1);
  CHECK(d[0].value("diff_op", std::string{}) == "removed");
  CHECK(d[0].value("name", std::string{}) == "b");
}

TEST_CASE("view.diff: modified item appears as removed + added pair",
          "[protocol][view][diff]") {
  json baseline = json::array({
      json{{"name", "lib"}, {"addr", 0x1000}},
  });
  json current = json::array({
      json{{"name", "lib"}, {"addr", 0x2000}},  // load address changed
  });
  auto d = compute_diff(baseline, current);
  REQUIRE(d.size() == 2);
  bool saw_added = false, saw_removed = false;
  for (const auto& el : d) {
    auto op = el.value("diff_op", std::string{});
    if (op == "added") saw_added = true;
    if (op == "removed") saw_removed = true;
  }
  CHECK(saw_added);
  CHECK(saw_removed);
}

TEST_CASE("view.diff: order of input arrays doesn't matter",
          "[protocol][view][diff]") {
  json baseline = json::array({
      json{{"name", "a"}},
      json{{"name", "b"}},
  });
  json current = json::array({
      json{{"name", "b"}},  // same set, reordered
      json{{"name", "a"}},
  });
  auto d = compute_diff(baseline, current);
  CHECK(d.size() == 0);
}

TEST_CASE("view.diff: diff_against parsed from view spec",
          "[protocol][view][diff]") {
  json params = json{{"view", json{
      {"diff_against", "core:abc123"},
      {"limit", 50},
  }}};
  auto spec = parse_from_params(params);
  REQUIRE(spec.diff_against.has_value());
  CHECK(*spec.diff_against == "core:abc123");
  REQUIRE(spec.limit.has_value());
  CHECK(*spec.limit == 50u);
}

TEST_CASE("view.diff: absent diff_against → nullopt",
          "[protocol][view][diff]") {
  json params = json{{"view", json{{"limit", 10}}}};
  auto spec = parse_from_params(params);
  CHECK_FALSE(spec.diff_against.has_value());
}

TEST_CASE("view.diff: non-string diff_against → throws",
          "[protocol][view][diff][error]") {
  json params = json{{"view", json{{"diff_against", 42}}}};
  CHECK_THROWS_AS(parse_from_params(params), std::invalid_argument);
}
