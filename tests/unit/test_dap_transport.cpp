// Tests for src/dap/transport — DAP `Content-Length:`-framed read/write.
//
// DAP uses HTTP-style headers to delimit each JSON body. Different from
// ldbd's two stdio framings (line-delimited JSON, length-prefixed CBOR),
// so the shim can't reuse src/protocol/transport — these tests pin the
// exact spec-compliant behavior of the DAP-side framer.

#include <catch_amalgamated.hpp>

#include "dap/transport.h"

#include <sstream>
#include <string>

using ldb::dap::Error;
using ldb::dap::json;
using ldb::dap::read_dap_message;
using ldb::dap::write_dap_message;

TEST_CASE("write_dap_message: emits canonical framing", "[dap][transport]") {
  std::ostringstream out;
  json body = {{"seq", 1}, {"type", "request"}, {"command", "initialize"}};
  write_dap_message(out, body);

  const std::string s = out.str();
  // Must start with `Content-Length: `, contain `\r\n\r\n`, and the byte
  // count must equal the body's serialized length.
  auto cl_pos = s.find("Content-Length: ");
  REQUIRE(cl_pos == 0);
  auto split = s.find("\r\n\r\n");
  REQUIRE(split != std::string::npos);

  std::string header = s.substr(0, split);
  std::string body_str = s.substr(split + 4);
  std::string serialized = body.dump();
  REQUIRE(body_str == serialized);

  // Header advertises matching length.
  std::string len_str = header.substr(std::string("Content-Length: ").size());
  REQUIRE(std::stoul(len_str) == serialized.size());
}

TEST_CASE("read_dap_message: round-trips a written frame", "[dap][transport]") {
  std::stringstream stream;
  json out_body = {{"seq", 7}, {"type", "response"}, {"success", true},
                   {"command", "threads"}, {"body", json::object()}};
  write_dap_message(stream, out_body);

  auto in_body = read_dap_message(stream);
  REQUIRE(in_body.has_value());
  REQUIRE(*in_body == out_body);
}

TEST_CASE("read_dap_message: handles two back-to-back frames",
          "[dap][transport]") {
  std::stringstream stream;
  json a = {{"seq", 1}, {"command", "first"}};
  json b = {{"seq", 2}, {"command", "second"}};
  write_dap_message(stream, a);
  write_dap_message(stream, b);

  auto m1 = read_dap_message(stream);
  REQUIRE(m1.has_value());
  REQUIRE((*m1)["command"] == "first");

  auto m2 = read_dap_message(stream);
  REQUIRE(m2.has_value());
  REQUIRE((*m2)["command"] == "second");

  auto m3 = read_dap_message(stream);
  REQUIRE_FALSE(m3.has_value());  // clean EOF
}

TEST_CASE("read_dap_message: clean EOF returns nullopt", "[dap][transport]") {
  std::stringstream empty;
  auto m = read_dap_message(empty);
  REQUIRE_FALSE(m.has_value());
}

TEST_CASE("read_dap_message: malformed Content-Length throws",
          "[dap][transport]") {
  std::stringstream s;
  s << "Content-Length: not-a-number\r\n\r\n{}";
  REQUIRE_THROWS_AS(read_dap_message(s), Error);
}

TEST_CASE("read_dap_message: missing Content-Length throws",
          "[dap][transport]") {
  std::stringstream s;
  s << "Content-Type: application/json\r\n\r\n{}";
  REQUIRE_THROWS_AS(read_dap_message(s), Error);
}

TEST_CASE("read_dap_message: short body read throws", "[dap][transport]") {
  std::stringstream s;
  // Advertise 100 bytes but supply only 5. Reader must NOT block forever
  // on a stringstream — it must detect EOF mid-body and throw.
  s << "Content-Length: 100\r\n\r\n{\"a\":1";
  REQUIRE_THROWS_AS(read_dap_message(s), Error);
}

TEST_CASE("read_dap_message: tolerates extra Content-Type header",
          "[dap][transport]") {
  std::stringstream s;
  std::string body = R"({"command":"x"})";
  s << "Content-Length: " << body.size() << "\r\n"
    << "Content-Type: application/vscode-jsonrpc; charset=utf-8\r\n"
    << "\r\n" << body;
  auto m = read_dap_message(s);
  REQUIRE(m.has_value());
  REQUIRE((*m)["command"] == "x");
}

TEST_CASE("read_dap_message: case-insensitive Content-Length",
          "[dap][transport]") {
  std::stringstream s;
  std::string body = R"({"k":"v"})";
  s << "content-length: " << body.size() << "\r\n\r\n" << body;
  auto m = read_dap_message(s);
  REQUIRE(m.has_value());
  REQUIRE((*m)["k"] == "v");
}

TEST_CASE("read_dap_message: tolerates bare-LF line endings on input",
          "[dap][transport]") {
  // Some sloppy clients emit only \n. Accept it on read; we still emit
  // canonical \r\n on write.
  std::stringstream s;
  std::string body = R"({"k":1})";
  s << "Content-Length: " << body.size() << "\n\n" << body;
  auto m = read_dap_message(s);
  REQUIRE(m.has_value());
  REQUIRE((*m)["k"] == 1);
}

TEST_CASE("read_dap_message: malformed JSON body throws", "[dap][transport]") {
  std::stringstream s;
  std::string body = "{not json}";
  s << "Content-Length: " << body.size() << "\r\n\r\n" << body;
  REQUIRE_THROWS_AS(read_dap_message(s), Error);
}
