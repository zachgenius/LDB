// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <nlohmann/json.hpp>

#include <string>

// Hypothesis artifact format (post-V1 plan #6).
//
// A hypothesis is a structured belief the agent has formed during an
// investigation: "the parser drops UDP packets larger than 256 bytes,"
// "the auth bypass is keyed on a global counter that resets on
// reboot," etc. Promoting it into the artifact store turns volatile
// agent state into a durable, queryable, exportable record — the
// hypothesis can be cited by future calls, related to the evidence
// that backs it, exported as part of a .ldbpack, and re-examined when
// the investigation resumes.
//
// Wire shape:
//
//   format = "hypothesis-v1"
//   bytes  = JSON envelope with at least:
//              confidence: number in [0..1]
//              evidence_refs: array of artifact_id integers
//            and optionally:
//              statement   — short human-readable claim
//              rationale   — why the agent believes it
//              author      — agent / operator identifier
//              <free-form> — anything else; the validator does not
//                            gatekeep extra keys
//
// Validation runs at artifact.put time when the caller declares
// format="hypothesis-v1". Failures surface as JSON-RPC -32602
// (invalid params) with a message naming the offending field.

namespace ldb::store {

constexpr const char* kHypothesisFormat = "hypothesis-v1";

struct HypothesisValidation {
  bool        ok = false;
  std::string error;   // empty iff ok
};

// Validate a JSON envelope against the hypothesis-v1 schema. Returns
// {ok=true} on success; {ok=false, error=<diagnostic>} otherwise.
// The diagnostic mentions the offending field name so the dispatcher
// can pass it straight through to the JSON-RPC error message.
HypothesisValidation
validate_hypothesis_envelope(const nlohmann::json& env);

// Build a starter envelope that itself passes validation. Agents fetch
// the template, fill in optional fields, and put without re-checking
// shape. confidence defaults to 0.5 (no prior); evidence_refs starts
// empty.
nlohmann::json default_hypothesis_template();

}  // namespace ldb::store
