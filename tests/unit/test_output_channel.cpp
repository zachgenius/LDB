// SPDX-License-Identifier: Apache-2.0
// Unit tests for the OutputChannel stream-lock layer
// (post-V1 #21 phase-2, docs/27-nonstop-listener.md §2).
//
// OutputChannel owns the stdout-side write discipline: every reply
// from the dispatcher's RPC thread and every notification from the
// listener thread funnels through this object, which serialises on a
// mutex so the JSON-RPC frames never byte-interleave on the wire.
//
// Coverage:
//   * write_response emits a single JSON line ending in \n.
//   * write_notification emits a JSON-RPC §4.1 notification shape
//     (jsonrpc, method, params; no id) followed by \n.
//   * Two threads pounding write_response + write_notification each
//     produce only complete frames — every line splits as a valid
//     JSON object with one of the two expected method/result fields.
//   * CBOR mode: write_response + write_notification emit length-
//     prefixed CBOR frames; decoding each gives back the original
//     object shape.

#include <catch_amalgamated.hpp>

#include "protocol/output_channel.h"

#include <atomic>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using ldb::protocol::OutputChannel;
using ldb::protocol::WireFormat;
using ldb::protocol::json;

TEST_CASE("OutputChannel::write_response emits a single JSON line",
          "[output_channel][json]") {
  std::ostringstream os;
  OutputChannel out(os, WireFormat::kJson);
  out.write_response(json{{"id", "1"}, {"ok", true}});
  std::string s = os.str();
  REQUIRE_FALSE(s.empty());
  CHECK(s.back() == '\n');
  // Parses back as a single JSON object.
  auto parsed = json::parse(s);
  CHECK(parsed.value("ok", false) == true);
  CHECK(parsed.value("id", std::string{}) == "1");
}

TEST_CASE("OutputChannel::write_notification emits JSON-RPC §4.1 shape",
          "[output_channel][json][notification]") {
  std::ostringstream os;
  OutputChannel out(os, WireFormat::kJson);
  out.write_notification("thread.event", json{{"tid", 42}, {"kind", "stopped"}});
  auto parsed = json::parse(os.str());
  CHECK(parsed.value("jsonrpc", std::string{}) == "2.0");
  CHECK(parsed.value("method",  std::string{}) == "thread.event");
  CHECK(parsed["params"].value("tid", 0) == 42);
  CHECK(parsed["params"].value("kind", std::string{}) == "stopped");
  // The defining property of a notification: no id field.
  CHECK_FALSE(parsed.contains("id"));
}

TEST_CASE("OutputChannel serialises concurrent writers — every line is complete",
          "[output_channel][concurrency]") {
  std::ostringstream os;
  OutputChannel out(os, WireFormat::kJson);

  constexpr int kIters = 200;
  std::atomic<bool> go{false};

  std::thread t1([&]{
    while (!go.load()) std::this_thread::yield();
    for (int i = 0; i < kIters; ++i) {
      out.write_response(json{{"id", i}, {"ok", true}, {"data", "reply"}});
    }
  });
  std::thread t2([&]{
    while (!go.load()) std::this_thread::yield();
    for (int i = 0; i < kIters; ++i) {
      out.write_notification("thread.event",
                             json{{"tid", i}, {"kind", "stopped"}});
    }
  });
  go.store(true);
  t1.join();
  t2.join();

  // Split on '\n' and parse each non-empty line. If the writers
  // interleaved bytes, json::parse would throw on at least one line.
  int replies = 0, notifications = 0;
  std::string s = os.str();
  std::size_t start = 0;
  while (start < s.size()) {
    auto nl = s.find('\n', start);
    if (nl == std::string::npos) break;
    if (nl > start) {
      auto j = json::parse(s.substr(start, nl - start));   // throws on bad shape
      if (j.contains("method")) ++notifications;
      else                       ++replies;
    }
    start = nl + 1;
  }
  CHECK(replies       == kIters);
  CHECK(notifications == kIters);
}

TEST_CASE("OutputChannel CBOR mode emits length-prefixed frames",
          "[output_channel][cbor]") {
  std::ostringstream os;
  OutputChannel out(os, WireFormat::kCbor);
  out.write_response(json{{"id", 7}, {"ok", true}});
  out.write_notification("thread.event", json{{"tid", 99}});

  // Stream is: [4-byte BE len][CBOR body][4-byte BE len][CBOR body]
  std::string s = os.str();
  REQUIRE(s.size() > 8);

  auto read_be32 = [&](std::size_t offset) -> std::uint32_t {
    auto p = reinterpret_cast<const unsigned char*>(s.data() + offset);
    return (std::uint32_t(p[0]) << 24) | (std::uint32_t(p[1]) << 16)
         | (std::uint32_t(p[2]) <<  8) |  std::uint32_t(p[3]);
  };
  std::uint32_t len1 = read_be32(0);
  REQUIRE(s.size() >= 4 + len1 + 4);
  auto body1_begin = reinterpret_cast<const std::uint8_t*>(s.data() + 4);
  std::vector<std::uint8_t> body1(body1_begin, body1_begin + len1);
  auto reply = json::from_cbor(body1);
  CHECK(reply.value("ok", false) == true);
  CHECK(reply.value("id", 0) == 7);

  std::uint32_t len2 = read_be32(4 + len1);
  auto body2_begin = reinterpret_cast<const std::uint8_t*>(s.data() + 4 + len1 + 4);
  std::vector<std::uint8_t> body2(body2_begin, body2_begin + len2);
  auto notif = json::from_cbor(body2);
  CHECK(notif.value("method", std::string{}) == "thread.event");
  CHECK_FALSE(notif.contains("id"));
}
