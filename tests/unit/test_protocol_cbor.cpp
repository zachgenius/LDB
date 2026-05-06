// Tests for src/protocol/transport — wire-format read_message/write_message
// supporting line-delimited JSON and length-prefixed CBOR (M5 part 3).
//
// Transport rules:
//   - JSON: one JSON object per `\n`-terminated line (M0 default).
//   - CBOR: 4-byte big-endian uint32 frame length, then exactly that many
//     bytes of RFC 8949 CBOR. Back-to-back frames have no separator.
//   - read_message returns nullopt on clean EOF, throws protocol::Error on
//     malformed framing or unparseable bytes.

#include <catch_amalgamated.hpp>

#include "protocol/transport.h"

#include <arpa/inet.h>

#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

using ldb::protocol::Error;
using ldb::protocol::WireFormat;
using ldb::protocol::json;
using ldb::protocol::read_message;
using ldb::protocol::write_message;

namespace {

std::string ss_to_string(std::stringstream& s) { return s.str(); }

}  // namespace

TEST_CASE("transport JSON: round-trip object", "[transport][json]") {
  json req = {
    {"jsonrpc", "2.0"},
    {"id", "r1"},
    {"method", "hello"},
    {"params", json::object()},
  };

  std::stringstream out;
  write_message(out, req, WireFormat::kJson);

  std::string framed = ss_to_string(out);
  REQUIRE(!framed.empty());
  REQUIRE(framed.back() == '\n');

  std::stringstream in(framed);
  auto got = read_message(in, WireFormat::kJson);
  REQUIRE(got.has_value());
  REQUIRE(*got == req);
}

TEST_CASE("transport JSON: skips blank lines", "[transport][json]") {
  std::stringstream in("\n\n{\"id\":1,\"method\":\"x\"}\n\n");
  auto got = read_message(in, WireFormat::kJson);
  REQUIRE(got.has_value());
  REQUIRE((*got)["method"] == "x");

  // Subsequent calls drain the trailing blanks and return nullopt at EOF.
  auto eof = read_message(in, WireFormat::kJson);
  REQUIRE_FALSE(eof.has_value());
}

TEST_CASE("transport JSON: clean EOF returns nullopt", "[transport][json]") {
  std::stringstream in("");
  auto got = read_message(in, WireFormat::kJson);
  REQUIRE_FALSE(got.has_value());
}

TEST_CASE("transport JSON: malformed line throws", "[transport][json]") {
  std::stringstream in("{ not json\n");
  REQUIRE_THROWS_AS(read_message(in, WireFormat::kJson), Error);
}

TEST_CASE("transport CBOR: round-trip request", "[transport][cbor]") {
  json req = {
    {"jsonrpc", "2.0"},
    {"id", "r1"},
    {"method", "target.open"},
    {"params", {{"path", "/bin/ls"}}},
  };

  std::stringstream out;
  write_message(out, req, WireFormat::kCbor);

  std::string framed = ss_to_string(out);
  REQUIRE(framed.size() >= 4);  // at least the length prefix

  // First 4 bytes = big-endian length.
  uint32_t be_len = 0;
  std::memcpy(&be_len, framed.data(), 4);
  uint32_t len = ntohl(be_len);
  REQUIRE(len + 4 == framed.size());

  std::stringstream in(framed);
  auto got = read_message(in, WireFormat::kCbor);
  REQUIRE(got.has_value());
  REQUIRE(*got == req);
}

TEST_CASE("transport CBOR: back-to-back frames", "[transport][cbor]") {
  json a = {{"id", 1}, {"method", "hello"}};
  json b = {{"id", 2}, {"method", "describe.endpoints"}};
  json c = {{"id", 3}, {"method", "target.close"}};

  std::stringstream io;
  write_message(io, a, WireFormat::kCbor);
  write_message(io, b, WireFormat::kCbor);
  write_message(io, c, WireFormat::kCbor);

  // Re-position to read.
  std::string framed = io.str();
  std::stringstream in(framed);

  auto ra = read_message(in, WireFormat::kCbor);
  auto rb = read_message(in, WireFormat::kCbor);
  auto rc = read_message(in, WireFormat::kCbor);
  REQUIRE(ra.has_value());
  REQUIRE(rb.has_value());
  REQUIRE(rc.has_value());
  REQUIRE(*ra == a);
  REQUIRE(*rb == b);
  REQUIRE(*rc == c);

  auto eof = read_message(in, WireFormat::kCbor);
  REQUIRE_FALSE(eof.has_value());
}

TEST_CASE("transport CBOR: clean EOF returns nullopt", "[transport][cbor]") {
  std::stringstream in("");
  auto got = read_message(in, WireFormat::kCbor);
  REQUIRE_FALSE(got.has_value());
}

TEST_CASE("transport CBOR: short prefix throws", "[transport][cbor]") {
  // Only 2 of the 4 prefix bytes — that's a torn frame, not clean EOF.
  std::string buf;
  buf.push_back('\x00');
  buf.push_back('\x10');
  std::stringstream in(buf);
  REQUIRE_THROWS_AS(read_message(in, WireFormat::kCbor), Error);
}

TEST_CASE("transport CBOR: truncated body throws", "[transport][cbor]") {
  // Prefix says 100 bytes but we only supply 5.
  std::string buf(4, '\0');
  uint32_t be_len = htonl(100);
  std::memcpy(buf.data(), &be_len, 4);
  buf.append("hello");
  std::stringstream in(buf);
  REQUIRE_THROWS_AS(read_message(in, WireFormat::kCbor), Error);
}

TEST_CASE("transport CBOR: invalid CBOR bytes throw", "[transport][cbor]") {
  // Length prefix says 4 bytes, body is invalid CBOR.
  std::string buf(4, '\0');
  uint32_t be_len = htonl(4);
  std::memcpy(buf.data(), &be_len, 4);
  // 0xff is the indefinite-length break byte — never legal as a top-level
  // value on its own; nlohmann's strict from_cbor rejects it.
  buf.append("\xff\xff\xff\xff", 4);
  std::stringstream in(buf);
  REQUIRE_THROWS_AS(read_message(in, WireFormat::kCbor), Error);
}

TEST_CASE("transport CBOR: zero-length frame throws", "[transport][cbor]") {
  // Length prefix of 0 — there's no valid CBOR encoding in 0 bytes; this
  // would otherwise loop the daemon on the same offset forever.
  std::string buf(4, '\0');
  std::stringstream in(buf);
  REQUIRE_THROWS_AS(read_message(in, WireFormat::kCbor), Error);
}

TEST_CASE("transport CBOR: write produces big-endian length", "[transport][cbor]") {
  json small = {{"k", "v"}};
  std::stringstream out;
  write_message(out, small, WireFormat::kCbor);
  std::string framed = out.str();
  REQUIRE(framed.size() > 4);
  // First 3 bytes of the length prefix must be zero (frame << 16 MiB).
  REQUIRE(static_cast<unsigned char>(framed[0]) == 0);
  REQUIRE(static_cast<unsigned char>(framed[1]) == 0);
  REQUIRE(static_cast<unsigned char>(framed[2]) == 0);
  // Fourth byte = (length & 0xff). At minimum 1 byte of CBOR for a map.
  REQUIRE(static_cast<unsigned char>(framed[3]) > 0);
}
