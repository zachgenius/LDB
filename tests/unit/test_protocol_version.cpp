// Tests for src/protocol/version — semver constants, parser, and the
// new `kProtocolVersionMismatch` error code (Tier 1 §3a).
//
// Spec: docs/03-ldb-full-roadmap.md §4 — "Semantic versioning on the
// protocol — protocol minor version bumps are backward-compatible, major
// bumps require migration; agents send `protocol_min` in `hello`."
//
// The wire negotiation is exercised in test_dispatcher_hello.cpp; this
// file is the pure-protocol layer (no dispatcher / backend).

#include <catch_amalgamated.hpp>

#include "protocol/jsonrpc.h"
#include "protocol/version.h"

#include <optional>
#include <string>

using ldb::protocol::ErrorCode;
using ldb::protocol::kProtocolVersionMajor;
using ldb::protocol::kProtocolVersionMinor;
using ldb::protocol::kProtocolMinSupportedMajor;
using ldb::protocol::kProtocolMinSupportedMinor;
using ldb::protocol::kProtocolVersionString;
using ldb::protocol::ProtocolVersion;
using ldb::protocol::parse_protocol_version;

TEST_CASE("kProtocolVersionString matches major.minor", "[protocol][version]") {
  std::string expect = std::to_string(kProtocolVersionMajor) + "." +
                       std::to_string(kProtocolVersionMinor);
  REQUIRE(std::string(kProtocolVersionString) == expect);
}

TEST_CASE("min-supported is non-negative and <= current",
          "[protocol][version]") {
  REQUIRE(kProtocolMinSupportedMajor >= 0);
  REQUIRE(kProtocolMinSupportedMinor >= 0);
  // (min_major, min_minor) <= (cur_major, cur_minor) lexicographically.
  if (kProtocolMinSupportedMajor == kProtocolVersionMajor) {
    REQUIRE(kProtocolMinSupportedMinor <= kProtocolVersionMinor);
  } else {
    REQUIRE(kProtocolMinSupportedMajor < kProtocolVersionMajor);
  }
}

TEST_CASE("parse_protocol_version: well-formed inputs", "[protocol][version]") {
  auto v = parse_protocol_version("0.1");
  REQUIRE(v.has_value());
  REQUIRE(v->major == 0);
  REQUIRE(v->minor == 1);

  v = parse_protocol_version("1.0");
  REQUIRE(v.has_value());
  REQUIRE(v->major == 1);
  REQUIRE(v->minor == 0);

  v = parse_protocol_version("12.345");
  REQUIRE(v.has_value());
  REQUIRE(v->major == 12);
  REQUIRE(v->minor == 345);
}

TEST_CASE("parse_protocol_version: malformed inputs return nullopt",
          "[protocol][version]") {
  REQUIRE_FALSE(parse_protocol_version("").has_value());
  REQUIRE_FALSE(parse_protocol_version("abc").has_value());
  REQUIRE_FALSE(parse_protocol_version("1").has_value());
  REQUIRE_FALSE(parse_protocol_version("1.").has_value());
  REQUIRE_FALSE(parse_protocol_version(".1").has_value());
  REQUIRE_FALSE(parse_protocol_version("1.1.1").has_value());
  REQUIRE_FALSE(parse_protocol_version("1.0.0").has_value());
  REQUIRE_FALSE(parse_protocol_version("-1.0").has_value());
  REQUIRE_FALSE(parse_protocol_version("1.-1").has_value());
  REQUIRE_FALSE(parse_protocol_version(" 1.0").has_value());
  REQUIRE_FALSE(parse_protocol_version("1.0 ").has_value());
  REQUIRE_FALSE(parse_protocol_version("1.0a").has_value());
  REQUIRE_FALSE(parse_protocol_version("a.0").has_value());
}

TEST_CASE("ProtocolVersion comparison operators", "[protocol][version]") {
  ProtocolVersion v00{0, 0};
  ProtocolVersion v01{0, 1};
  ProtocolVersion v02{0, 2};
  ProtocolVersion v10{1, 0};
  ProtocolVersion v11{1, 1};

  REQUIRE(v01 == ProtocolVersion{0, 1});
  REQUIRE_FALSE(v01 == v02);

  REQUIRE(v00 < v01);
  REQUIRE(v01 < v02);
  REQUIRE(v02 < v10);
  REQUIRE(v10 < v11);

  REQUIRE(v01 <= v01);
  REQUIRE(v01 <= v02);
  REQUIRE(v02 >= v01);
  REQUIRE(v10 > v02);
  REQUIRE(v10 > v01);
  REQUIRE_FALSE(v01 > v10);
}

TEST_CASE("kProtocolVersionMismatch error code is -32011",
          "[protocol][version][error]") {
  REQUIRE(static_cast<int>(ErrorCode::kProtocolVersionMismatch) == -32011);
}
