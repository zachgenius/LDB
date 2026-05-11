// SPDX-License-Identifier: Apache-2.0
#include "store/hypothesis.h"

namespace ldb::store {

HypothesisValidation
validate_hypothesis_envelope(const nlohmann::json& env) {
  HypothesisValidation r;

  if (!env.is_object()) {
    r.error = "hypothesis envelope must be a JSON object";
    return r;
  }

  // confidence: required, number in [0..1].
  if (!env.contains("confidence")) {
    r.error = "missing required field 'confidence' (number in [0..1])";
    return r;
  }
  const auto& conf = env["confidence"];
  if (!conf.is_number()) {
    r.error = "field 'confidence' must be a number in [0..1]";
    return r;
  }
  // nlohmann::json::get<double> coerces from any number type. Use the
  // resulting double for the range check so integer 0 / 1 are accepted.
  double c = conf.get<double>();
  if (!(c >= 0.0 && c <= 1.0)) {
    r.error = "field 'confidence' out of range [0..1]";
    return r;
  }

  // evidence_refs: required, array of integers (empty allowed — see
  // hypothesis.h rationale).
  if (!env.contains("evidence_refs")) {
    r.error = "missing required field 'evidence_refs' "
              "(array of artifact_id integers)";
    return r;
  }
  const auto& refs = env["evidence_refs"];
  if (!refs.is_array()) {
    r.error = "field 'evidence_refs' must be an array";
    return r;
  }
  for (std::size_t i = 0; i < refs.size(); ++i) {
    const auto& el = refs[i];
    if (!el.is_number_integer() && !el.is_number_unsigned()) {
      r.error = "field 'evidence_refs' element " + std::to_string(i) +
                " must be an integer artifact_id";
      return r;
    }
  }

  r.ok = true;
  return r;
}

nlohmann::json default_hypothesis_template() {
  return nlohmann::json{
      {"confidence",    0.5},
      {"evidence_refs", nlohmann::json::array()},
      {"statement",     ""},
      {"rationale",     ""},
      {"author",        ""},
  };
}

}  // namespace ldb::store
