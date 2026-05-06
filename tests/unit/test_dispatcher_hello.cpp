// Tests for the `hello` handshake (Tier 1 §3a, plan §3 + roadmap §4).
//
// `hello` carries protocol-version negotiation: the daemon advertises
// its current version and the oldest version it still serves; the
// client may send `protocol_min` to assert "I won't talk to a daemon
// older than this." Mismatch returns -32011.
//
// Cases covered:
//   * No params → ok, response carries protocol{version, major, minor,
//     min_supported}.
//   * Same-or-older `protocol_min` → ok.
//   * `protocol_min` higher than current → -32011.
//   * Malformed `protocol_min` (string) → -32602.
//   * Wrong-type `protocol_min` (number) → -32602.
//
// The describe.endpoints schema for `hello` is updated separately in
// test_describe_endpoints_schema.cpp.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"
#include "daemon/dispatcher.h"
#include "protocol/jsonrpc.h"
#include "protocol/version.h"

#include <memory>
#include <string>

using ldb::backend::LldbBackend;
using ldb::daemon::Dispatcher;
using ldb::protocol::ErrorCode;
using ldb::protocol::kProtocolVersionMajor;
using ldb::protocol::kProtocolVersionMinor;
using ldb::protocol::kProtocolVersionString;
using ldb::protocol::kProtocolMinSupportedMajor;
using ldb::protocol::kProtocolMinSupportedMinor;
using ldb::protocol::Request;
using ldb::protocol::Response;
using ldb::protocol::json;

namespace {

Request make_hello(const json& params = json::object()) {
  Request r;
  r.id = "h1";
  r.method = "hello";
  r.params = params;
  return r;
}

Dispatcher make_dispatcher() {
  auto be = std::make_shared<LldbBackend>();
  return Dispatcher{be};
}

}  // namespace

TEST_CASE("hello: no params returns protocol block",
          "[hello][handshake]") {
  auto d = make_dispatcher();
  auto resp = d.dispatch(make_hello());
  REQUIRE(resp.ok);
  REQUIRE(resp.data.contains("name"));
  REQUIRE(resp.data["name"] == "ldbd");
  REQUIRE(resp.data.contains("version"));      // daemon version
  REQUIRE(resp.data.contains("formats"));
  REQUIRE(resp.data.contains("protocol"));
  const auto& p = resp.data["protocol"];
  REQUIRE(p["major"].get<int>() == kProtocolVersionMajor);
  REQUIRE(p["minor"].get<int>() == kProtocolVersionMinor);
  REQUIRE(p["version"].get<std::string>() ==
          std::string(kProtocolVersionString));
  REQUIRE(p["min_supported"].get<std::string>() ==
          std::to_string(kProtocolMinSupportedMajor) + "." +
          std::to_string(kProtocolMinSupportedMinor));
}

TEST_CASE("hello: protocol_min equal to current → ok",
          "[hello][handshake]") {
  auto d = make_dispatcher();
  auto resp = d.dispatch(make_hello(json{
      {"protocol_min", kProtocolVersionString}}));
  REQUIRE(resp.ok);
  REQUIRE(resp.data["protocol"]["version"] == kProtocolVersionString);
}

TEST_CASE("hello: protocol_min lower than current → ok",
          "[hello][handshake]") {
  // "0.0" — client accepts anything >= 0.0. Daemon at 0.1 satisfies.
  auto d = make_dispatcher();
  auto resp = d.dispatch(make_hello(json{{"protocol_min", "0.0"}}));
  REQUIRE(resp.ok);
}

TEST_CASE("hello: protocol_min higher than current → -32011",
          "[hello][handshake][error]") {
  auto d = make_dispatcher();
  // The client requires a minor higher than ours.
  std::string requested =
      std::to_string(kProtocolVersionMajor) + "." +
      std::to_string(kProtocolVersionMinor + 1);
  auto resp = d.dispatch(make_hello(json{{"protocol_min", requested}}));
  REQUIRE_FALSE(resp.ok);
  REQUIRE(resp.error_code == ErrorCode::kProtocolVersionMismatch);
  // Message names both sides so a planning agent can act on it.
  REQUIRE(resp.error_message.find(requested) != std::string::npos);
  REQUIRE(resp.error_message.find(kProtocolVersionString) !=
          std::string::npos);
}

TEST_CASE("hello: protocol_min with higher major → -32011",
          "[hello][handshake][error]") {
  auto d = make_dispatcher();
  std::string requested = std::to_string(kProtocolVersionMajor + 1) + ".0";
  auto resp = d.dispatch(make_hello(json{{"protocol_min", requested}}));
  REQUIRE_FALSE(resp.ok);
  REQUIRE(resp.error_code == ErrorCode::kProtocolVersionMismatch);
}

TEST_CASE("hello: malformed protocol_min string → -32602",
          "[hello][handshake][error]") {
  auto d = make_dispatcher();
  auto resp = d.dispatch(make_hello(json{{"protocol_min", "abc"}}));
  REQUIRE_FALSE(resp.ok);
  REQUIRE(resp.error_code == ErrorCode::kInvalidParams);
}

TEST_CASE("hello: numeric protocol_min → -32602",
          "[hello][handshake][error]") {
  auto d = make_dispatcher();
  auto resp = d.dispatch(make_hello(json{{"protocol_min", 0.1}}));
  REQUIRE_FALSE(resp.ok);
  REQUIRE(resp.error_code == ErrorCode::kInvalidParams);
}

TEST_CASE("hello: empty-string protocol_min → -32602",
          "[hello][handshake][error]") {
  auto d = make_dispatcher();
  auto resp = d.dispatch(make_hello(json{{"protocol_min", ""}}));
  REQUIRE_FALSE(resp.ok);
  REQUIRE(resp.error_code == ErrorCode::kInvalidParams);
}

TEST_CASE("hello: protocol_min semantics is daemon_version >= protocol_min",
          "[hello][handshake]") {
  // Pin the contract documented in docs/05-protocol-versioning.md:
  // `protocol_min` is the client's FLOOR. The daemon is OK iff its
  // current version >= protocol_min. `min_supported` is informational
  // metadata advertising the oldest version the daemon would ever
  // serve — it does NOT enter the satisfy check, because a request
  // below the floor is still trivially satisfied by a daemon at a
  // higher version.
  auto d = make_dispatcher();
  // Major below current is always satisfied.
  if (kProtocolVersionMajor > 0) {
    auto resp = d.dispatch(make_hello(json{
        {"protocol_min", std::to_string(kProtocolVersionMajor - 1) + ".0"}}));
    REQUIRE(resp.ok);
  }
  // Minor below current within same major is always satisfied.
  if (kProtocolVersionMinor > 0) {
    auto resp = d.dispatch(make_hello(json{
        {"protocol_min", std::to_string(kProtocolVersionMajor) + "." +
                         std::to_string(kProtocolVersionMinor - 1)}}));
    REQUIRE(resp.ok);
  } else {
    // current minor is 0; just check 0.0 explicitly.
    auto resp = d.dispatch(make_hello(json{{"protocol_min", "0.0"}}));
    REQUIRE(resp.ok);
  }
}
