// Tests for src/protocol/jsonrpc — request parsing and response serialization.
//
// These cover the existing parser/serializer: round-trip of request shapes,
// notification handling (id absent), and error responses. Acts as the
// regression net before we evolve the protocol in M1+ (CBOR, view
// descriptors, streaming).

#include <catch_amalgamated.hpp>

#include "protocol/jsonrpc.h"

using ldb::protocol::ErrorCode;
using ldb::protocol::Request;
using ldb::protocol::Response;
using ldb::protocol::json;
using ldb::protocol::make_err;
using ldb::protocol::make_ok;
using ldb::protocol::parse_request;
using ldb::protocol::serialize_response;

TEST_CASE("parse_request: minimal valid request", "[protocol][parse]") {
  Request r = parse_request(R"({"id":"r1","method":"hello"})");
  REQUIRE(r.id.has_value());
  REQUIRE(r.id->is_string());
  REQUIRE(r.id->get<std::string>() == "r1");
  REQUIRE(r.method == "hello");
  REQUIRE(r.params.is_object());
  REQUIRE(r.params.empty());
}

TEST_CASE("parse_request: numeric id", "[protocol][parse]") {
  Request r = parse_request(R"({"id":42,"method":"x"})");
  REQUIRE(r.id.has_value());
  REQUIRE(r.id->is_number_integer());
  REQUIRE(r.id->get<int>() == 42);
}

TEST_CASE("parse_request: notification has no id", "[protocol][parse]") {
  Request r = parse_request(R"({"method":"ping"})");
  REQUIRE_FALSE(r.id.has_value());
  REQUIRE(r.method == "ping");
}

TEST_CASE("parse_request: object params preserved", "[protocol][parse]") {
  Request r = parse_request(
      R"({"id":1,"method":"target.open","params":{"path":"/bin/ls"}})");
  REQUIRE(r.params.is_object());
  REQUIRE(r.params.contains("path"));
  REQUIRE(r.params["path"].get<std::string>() == "/bin/ls");
}

TEST_CASE("parse_request: array params preserved", "[protocol][parse]") {
  Request r = parse_request(R"({"id":1,"method":"x","params":[1,2,3]})");
  REQUIRE(r.params.is_array());
  REQUIRE(r.params.size() == 3);
  REQUIRE(r.params[0].get<int>() == 1);
  REQUIRE(r.params[2].get<int>() == 3);
}

TEST_CASE("parse_request: jsonrpc version 2.0 accepted", "[protocol][parse]") {
  REQUIRE_NOTHROW(parse_request(R"({"jsonrpc":"2.0","id":1,"method":"x"})"));
}

TEST_CASE("parse_request: jsonrpc wrong version rejected",
          "[protocol][parse][error]") {
  REQUIRE_THROWS(parse_request(R"({"jsonrpc":"1.0","id":1,"method":"x"})"));
}

TEST_CASE("parse_request: missing method rejected",
          "[protocol][parse][error]") {
  REQUIRE_THROWS(parse_request(R"({"id":1})"));
}

TEST_CASE("parse_request: non-string method rejected",
          "[protocol][parse][error]") {
  REQUIRE_THROWS(parse_request(R"({"id":1,"method":42})"));
}

TEST_CASE("parse_request: malformed json rejected",
          "[protocol][parse][error]") {
  REQUIRE_THROWS(parse_request("not-json"));
}

TEST_CASE("parse_request: top-level array rejected",
          "[protocol][parse][error]") {
  REQUIRE_THROWS(parse_request(R"([1,2,3])"));
}

TEST_CASE("parse_request: invalid params type rejected",
          "[protocol][parse][error]") {
  REQUIRE_THROWS(
      parse_request(R"({"id":1,"method":"x","params":"oops"})"));
}

TEST_CASE("serialize_response: ok with data", "[protocol][serialize]") {
  Response r = make_ok(json("r9"), json{{"hello", "world"}});
  std::string s = serialize_response(r);
  json j = json::parse(s);
  REQUIRE(j["jsonrpc"] == "2.0");
  REQUIRE(j["id"] == "r9");
  REQUIRE(j["ok"] == true);
  REQUIRE(j["data"]["hello"] == "world");
  REQUIRE_FALSE(j.contains("error"));
}

TEST_CASE("serialize_response: error preserves code and message",
          "[protocol][serialize][error]") {
  Response r = make_err(json(7), ErrorCode::kMethodNotFound,
                        "no such method 'foo'");
  std::string s = serialize_response(r);
  json j = json::parse(s);
  REQUIRE(j["ok"] == false);
  REQUIRE(j["error"]["code"] == static_cast<int>(ErrorCode::kMethodNotFound));
  REQUIRE(j["error"]["message"] == "no such method 'foo'");
  REQUIRE_FALSE(j.contains("data"));
}

TEST_CASE("serialize_response: error with data payload",
          "[protocol][serialize][error]") {
  Response r = make_err(json(1), ErrorCode::kInvalidParams, "bad",
                        json{{"missing", "path"}});
  std::string s = serialize_response(r);
  json j = json::parse(s);
  REQUIRE(j["error"]["data"]["missing"] == "path");
}

TEST_CASE("serialize_response: missing id becomes null", "[protocol][serialize]") {
  Response r = make_err(std::nullopt, ErrorCode::kParseError, "bad");
  std::string s = serialize_response(r);
  json j = json::parse(s);
  REQUIRE(j["id"].is_null());
}

TEST_CASE("serialize_response: single line, no embedded newlines",
          "[protocol][serialize]") {
  Response r = make_ok(json("r1"), json{{"a", 1}, {"b", "two"}});
  std::string s = serialize_response(r);
  // Line-delimited transport requires no internal newlines.
  REQUIRE(s.find('\n') == std::string::npos);
}

TEST_CASE("round-trip: request → dispatched-elsewhere → response → parse",
          "[protocol][roundtrip]") {
  // Parse a request, simulate a handler producing a response, serialize,
  // re-parse the response. Verifies the line is well-formed JSON throughout.
  Request req = parse_request(R"({"id":"abc","method":"hello"})");
  Response resp =
      make_ok(req.id, json{{"name", "ldbd"}, {"version", "0.1.0"}});
  std::string wire = serialize_response(resp);
  json reparsed = json::parse(wire);
  REQUIRE(reparsed["id"] == "abc");
  REQUIRE(reparsed["data"]["name"] == "ldbd");
}

// --- Cost-preview metadata (M5 part 1, plan §3.2) ----------------------

TEST_CASE("serialize_response: ok response carries _cost",
          "[protocol][serialize][cost]") {
  Response r = make_ok(json("r9"), json{{"hello", "world"}});
  std::string s = serialize_response(r);
  json j = json::parse(s);
  REQUIRE(j["ok"] == true);
  REQUIRE(j.contains("_cost"));
  REQUIRE(j["_cost"].contains("bytes"));
  REQUIRE(j["_cost"].contains("tokens_est"));
  // `data` here has no arrays, so `items` MUST be absent.
  REQUIRE_FALSE(j["_cost"].contains("items"));
  // bytes is exact serialized length of data.
  std::string data_dump = json{{"hello", "world"}}.dump();
  REQUIRE(j["_cost"]["bytes"].get<std::size_t>() == data_dump.size());
  // tokens_est = ceil(bytes/4).
  REQUIRE(j["_cost"]["tokens_est"].get<std::size_t>()
          == (data_dump.size() + 3) / 4);
}

TEST_CASE("serialize_response: ok response with array key populates items",
          "[protocol][serialize][cost]") {
  Response r = make_ok(json("r1"),
                       json{{"modules", json::array({"a", "b", "c"})}});
  std::string s = serialize_response(r);
  json j = json::parse(s);
  REQUIRE(j["_cost"].contains("items"));
  REQUIRE(j["_cost"]["items"].get<std::size_t>() == 3);
}

TEST_CASE("serialize_response: error response has no _cost",
          "[protocol][serialize][cost]") {
  Response r = make_err(json(7), ErrorCode::kMethodNotFound,
                        "no such method 'foo'");
  std::string s = serialize_response(r);
  json j = json::parse(s);
  REQUIRE(j["ok"] == false);
  REQUIRE_FALSE(j.contains("_cost"));
}

TEST_CASE("serialize_response: ok with empty data still carries _cost",
          "[protocol][serialize][cost]") {
  // An empty object IS valid data — the helper should still report bytes=2
  // (the literal "{}") so the agent has a number to budget against.
  Response r = make_ok(json("r1"), json::object());
  std::string s = serialize_response(r);
  json j = json::parse(s);
  REQUIRE(j.contains("_cost"));
  REQUIRE(j["_cost"]["bytes"].get<std::size_t>() == 2);
  REQUIRE_FALSE(j["_cost"].contains("items"));
}
