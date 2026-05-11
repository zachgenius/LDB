// SPDX-License-Identifier: Apache-2.0
// Unit tests for the hypothesis-v1 envelope validator
// (post-V1 plan #6).
//
// Contract under test:
//
//   * `validate_hypothesis_envelope(env)` accepts a JSON envelope with
//     required fields:
//       - confidence: number in [0, 1]
//       - evidence_refs: array of integers (empty array allowed —
//         a hypothesis can be conjectural with no supporting evidence
//         yet, and the operator can attach evidence later via
//         artifact.relate)
//     and rejects anything else with a human-readable error mentioning
//     the offending field so the dispatcher's -32602 message is useful.
//   * Optional fields (statement, rationale, free-form sub-objects) are
//     accepted verbatim; the validator does not gatekeep them.
//   * `default_hypothesis_template()` returns a JSON object that itself
//     passes validation — agents can fetch it, fill in optional fields,
//     and put without re-checking.

#include <catch_amalgamated.hpp>

#include "store/hypothesis.h"

#include <nlohmann/json.hpp>

using ldb::store::default_hypothesis_template;
using ldb::store::validate_hypothesis_envelope;
using nlohmann::json;

TEST_CASE("hypothesis: minimal valid envelope accepted",
          "[store][hypothesis]") {
  json env = {
      {"confidence", 0.75},
      {"evidence_refs", json::array({42, 7})},
  };
  auto r = validate_hypothesis_envelope(env);
  CHECK(r.ok);
  CHECK(r.error.empty());
}

TEST_CASE("hypothesis: confidence boundary values accepted",
          "[store][hypothesis]") {
  for (double c : {0.0, 1.0, 0.5}) {
    json env = {
        {"confidence", c},
        {"evidence_refs", json::array()},
    };
    auto r = validate_hypothesis_envelope(env);
    CHECK(r.ok);
  }
}

TEST_CASE("hypothesis: empty evidence_refs accepted",
          "[store][hypothesis]") {
  json env = {
      {"confidence", 0.5},
      {"evidence_refs", json::array()},
  };
  auto r = validate_hypothesis_envelope(env);
  CHECK(r.ok);
}

TEST_CASE("hypothesis: extra optional fields ignored by the validator",
          "[store][hypothesis]") {
  json env = {
      {"confidence", 0.4},
      {"evidence_refs", json::array({1})},
      {"statement", "the parser drops packets >256B"},
      {"rationale", "see disasm at btp_parse+0x140"},
      {"author", "agent-7"},
      {"misc", json::object({{"x", 1}, {"y", 2}})},
  };
  auto r = validate_hypothesis_envelope(env);
  CHECK(r.ok);
}

TEST_CASE("hypothesis: top-level not an object → rejected",
          "[store][hypothesis][error]") {
  auto r = validate_hypothesis_envelope(json::array());
  CHECK_FALSE(r.ok);
  CHECK(r.error.find("object") != std::string::npos);
}

TEST_CASE("hypothesis: confidence missing → rejected",
          "[store][hypothesis][error]") {
  json env = {
      {"evidence_refs", json::array({1})},
  };
  auto r = validate_hypothesis_envelope(env);
  CHECK_FALSE(r.ok);
  CHECK(r.error.find("confidence") != std::string::npos);
}

TEST_CASE("hypothesis: confidence wrong type → rejected",
          "[store][hypothesis][error]") {
  json env = {
      {"confidence", "very high"},
      {"evidence_refs", json::array()},
  };
  auto r = validate_hypothesis_envelope(env);
  CHECK_FALSE(r.ok);
  CHECK(r.error.find("confidence") != std::string::npos);
}

TEST_CASE("hypothesis: confidence < 0 → rejected",
          "[store][hypothesis][error]") {
  json env = {
      {"confidence", -0.1},
      {"evidence_refs", json::array()},
  };
  auto r = validate_hypothesis_envelope(env);
  CHECK_FALSE(r.ok);
  CHECK(r.error.find("confidence") != std::string::npos);
}

TEST_CASE("hypothesis: confidence > 1 → rejected",
          "[store][hypothesis][error]") {
  json env = {
      {"confidence", 1.01},
      {"evidence_refs", json::array()},
  };
  auto r = validate_hypothesis_envelope(env);
  CHECK_FALSE(r.ok);
  CHECK(r.error.find("confidence") != std::string::npos);
}

TEST_CASE("hypothesis: evidence_refs missing → rejected",
          "[store][hypothesis][error]") {
  json env = {
      {"confidence", 0.5},
  };
  auto r = validate_hypothesis_envelope(env);
  CHECK_FALSE(r.ok);
  CHECK(r.error.find("evidence_refs") != std::string::npos);
}

TEST_CASE("hypothesis: evidence_refs wrong type → rejected",
          "[store][hypothesis][error]") {
  json env = {
      {"confidence", 0.5},
      {"evidence_refs", "1, 2, 3"},
  };
  auto r = validate_hypothesis_envelope(env);
  CHECK_FALSE(r.ok);
  CHECK(r.error.find("evidence_refs") != std::string::npos);
}

TEST_CASE("hypothesis: evidence_refs items wrong type → rejected",
          "[store][hypothesis][error]") {
  json env = {
      {"confidence", 0.5},
      {"evidence_refs", json::array({1, "two", 3})},
  };
  auto r = validate_hypothesis_envelope(env);
  CHECK_FALSE(r.ok);
  // Either evidence_refs or the items themselves must be flagged.
  CHECK(r.error.find("evidence_refs") != std::string::npos);
}

TEST_CASE("hypothesis: default template itself validates",
          "[store][hypothesis]") {
  auto tmpl = default_hypothesis_template();
  REQUIRE(tmpl.is_object());
  auto r = validate_hypothesis_envelope(tmpl);
  CHECK(r.ok);
  // The template should contain at least the required fields and the
  // canonical advisory ones — otherwise agents won't know what's
  // available to fill in.
  CHECK(tmpl.contains("confidence"));
  CHECK(tmpl.contains("evidence_refs"));
  CHECK(tmpl.contains("statement"));
}
