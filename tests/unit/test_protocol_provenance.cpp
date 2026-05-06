// Tests for src/protocol/provenance — _provenance preview metadata
// helper plus the integration into serialize_response / response_to_json
// (the JSON and CBOR serialization paths).
//
// Plan §3.5 (cores-only MVP): every successful response carries
//   "_provenance": {"snapshot": "<value>", "deterministic": <bool>}
// where snapshot is "core:<hex>" / "live" / "none", and deterministic
// is true iff the snapshot starts with "core:".

#include <catch_amalgamated.hpp>

#include "protocol/jsonrpc.h"
#include "protocol/provenance.h"

#include <nlohmann/json.hpp>

using ldb::protocol::ErrorCode;
using ldb::protocol::Response;
using ldb::protocol::json;
using ldb::protocol::make_err;
using ldb::protocol::make_ok;
using ldb::protocol::serialize_response;

// --- Pure helper ---------------------------------------------------------

TEST_CASE("provenance::compute: core: prefix is deterministic",
          "[protocol][provenance]") {
  std::string snap = "core:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  json p = ldb::protocol::provenance::compute(snap);
  REQUIRE(p["snapshot"].get<std::string>() == snap);
  REQUIRE(p["deterministic"].get<bool>() == true);
}

TEST_CASE("provenance::compute: live is non-deterministic",
          "[protocol][provenance]") {
  json p = ldb::protocol::provenance::compute("live");
  REQUIRE(p["snapshot"].get<std::string>() == "live");
  REQUIRE(p["deterministic"].get<bool>() == false);
}

TEST_CASE("provenance::compute: none is non-deterministic",
          "[protocol][provenance]") {
  json p = ldb::protocol::provenance::compute("none");
  REQUIRE(p["snapshot"].get<std::string>() == "none");
  REQUIRE(p["deterministic"].get<bool>() == false);
}

TEST_CASE("provenance::compute: bare \"core\" without payload is non-deterministic",
          "[protocol][provenance]") {
  // Defensive: only the literal "core:..." form is deterministic. A
  // plain "core" token (no colon, no hex) shouldn't trip the gate.
  REQUIRE_FALSE(
      ldb::protocol::provenance::is_deterministic("core"));
  REQUIRE_FALSE(
      ldb::protocol::provenance::is_deterministic("core:"));
}

// --- Integration via serialize_response ---------------------------------

TEST_CASE("serialize_response: ok response carries _provenance",
          "[protocol][serialize][provenance]") {
  Response r = make_ok(json("r9"), json{{"hello", "world"}});
  std::string s = serialize_response(r);
  json j = json::parse(s);
  REQUIRE(j["ok"] == true);
  REQUIRE(j.contains("_provenance"));
  REQUIRE(j["_provenance"].contains("snapshot"));
  REQUIRE(j["_provenance"].contains("deterministic"));
  // Default (no dispatcher decoration) is the "none" sentinel.
  REQUIRE(j["_provenance"]["snapshot"].get<std::string>() == "none");
  REQUIRE(j["_provenance"]["deterministic"].get<bool>() == false);
}

TEST_CASE("serialize_response: provenance honors dispatcher-set snapshot",
          "[protocol][serialize][provenance]") {
  Response r = make_ok(json("r1"), json::object());
  r.provenance_snapshot =
      "core:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
  std::string s = serialize_response(r);
  json j = json::parse(s);
  REQUIRE(j["_provenance"]["snapshot"].get<std::string>() ==
          r.provenance_snapshot);
  REQUIRE(j["_provenance"]["deterministic"].get<bool>() == true);
}

TEST_CASE("serialize_response: live snapshot serializes deterministic=false",
          "[protocol][serialize][provenance]") {
  Response r = make_ok(json("r1"), json::object());
  r.provenance_snapshot = "live";
  std::string s = serialize_response(r);
  json j = json::parse(s);
  REQUIRE(j["_provenance"]["snapshot"].get<std::string>() == "live");
  REQUIRE(j["_provenance"]["deterministic"].get<bool>() == false);
}

TEST_CASE("serialize_response: error response has no _provenance",
          "[protocol][serialize][provenance]") {
  Response r = make_err(json(7), ErrorCode::kMethodNotFound,
                        "no such method 'foo'");
  std::string s = serialize_response(r);
  json j = json::parse(s);
  REQUIRE(j["ok"] == false);
  REQUIRE_FALSE(j.contains("_provenance"));
}

TEST_CASE("serialize_response: _cost.bytes unaffected by _provenance",
          "[protocol][serialize][provenance]") {
  // Plan invariant: `_cost.bytes` is the serialized length of `data`,
  // and adding `_provenance` next to `_cost` (not inside) must not
  // change that count.
  Response r = make_ok(json("r1"), json{{"k", "v"}});
  r.provenance_snapshot = "core:0123";
  std::string s = serialize_response(r);
  json j = json::parse(s);
  std::string data_dump = json{{"k", "v"}}.dump();
  REQUIRE(j["_cost"]["bytes"].get<std::size_t>() == data_dump.size());
}
