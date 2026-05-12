// SPDX-License-Identifier: Apache-2.0
// Unit tests for the GDB RSP packet vocabulary (post-V1 #17
// phase-1 part 2; docs/25-own-rsp-client.md §2.2).
//
// Builders are pure formatting; one golden vector each. Parsers
// cover the spec corners that bite in practice (signal-byte vs
// kv-pair stop replies, qSupported with `+`/`-`/`=value` forms,
// qXfer's m/l chunk markers, ack-mode toggle).

#include <catch_amalgamated.hpp>

#include "transport/rsp/packets.h"

#include <cstdint>
#include <string>
#include <vector>

using namespace ldb::transport::rsp;

// ----------- Request builders --------------------------------------

TEST_CASE("rsp/packets: qSupported emits feature list", "[rsp][packets]") {
  CHECK(build_qSupported({}) == "qSupported");
  CHECK(build_qSupported({"multiprocess+", "vContSupported+"})
        == "qSupported:multiprocess+;vContSupported+");
}

TEST_CASE("rsp/packets: simple one-byte builders", "[rsp][packets]") {
  CHECK(build_stop_query() == "?");
  CHECK(build_register_read_all() == "g");
  CHECK(build_qfThreadInfo() == "qfThreadInfo");
  CHECK(build_qsThreadInfo() == "qsThreadInfo");
  CHECK(build_reverse_continue() == "bc");
  CHECK(build_reverse_step() == "bs");
  CHECK(build_QStartNoAckMode() == "QStartNoAckMode");
}

TEST_CASE("rsp/packets: G hex-encodes the register block",
          "[rsp][packets]") {
  std::string bytes;
  bytes.push_back(static_cast<char>(0xde));
  bytes.push_back(static_cast<char>(0xad));
  bytes.push_back(static_cast<char>(0xbe));
  bytes.push_back(static_cast<char>(0xef));
  CHECK(build_register_write_all(bytes) == "Gdeadbeef");
}

TEST_CASE("rsp/packets: p / P single-register forms", "[rsp][packets]") {
  CHECK(build_register_read_one(0) == "p0");
  CHECK(build_register_read_one(0x10) == "p10");
  CHECK(build_register_read_one(0xff) == "pff");

  std::string val;
  val.push_back(static_cast<char>(0x01));
  val.push_back(static_cast<char>(0x02));
  CHECK(build_register_write_one(7, val) == "P7=0102");
}

TEST_CASE("rsp/packets: m / M memory addressing", "[rsp][packets]") {
  CHECK(build_memory_read(0x401000, 16) == "m401000,10");
  CHECK(build_memory_read(0, 0) == "m0,0");
  std::string b;
  b.push_back(static_cast<char>(0xaa));
  b.push_back(static_cast<char>(0xbb));
  CHECK(build_memory_write(0x1000, b) == "M1000,2:aabb");
}

TEST_CASE("rsp/packets: c / s legacy + optional resume-at",
          "[rsp][packets]") {
  CHECK(build_continue_legacy() == "c");
  CHECK(build_continue_legacy(0x401000) == "c401000");
  CHECK(build_step_legacy() == "s");
  CHECK(build_step_legacy(0x500) == "s500");
}

TEST_CASE("rsp/packets: vCont composes per-thread actions",
          "[rsp][packets]") {
  // Single action, all-threads (tid=0).
  CHECK(build_vCont({{'c', 0, 0}}) == "vCont;c");
  // Action with explicit thread.
  CHECK(build_vCont({{'c', 0, 1234}}) == "vCont;c:4d2");
  // Signal-carrying action: 'C09' = continue, deliver SIGKILL.
  CHECK(build_vCont({{'C', 0x09, 0}}) == "vCont;C09");
  // Per-thread step + continue everyone-else.
  CHECK(build_vCont({{'s', 0, 5}, {'c', 0, 0}})
        == "vCont;s:5;c");
}

TEST_CASE("rsp/packets: H thread-select forms", "[rsp][packets]") {
  CHECK(build_thread_select_general(0) == "Hg0");
  CHECK(build_thread_select_general(0x10) == "Hg10");
  CHECK(build_thread_select_general(-1) == "Hg-1");
  CHECK(build_thread_select_continue(7) == "Hc7");
}

TEST_CASE("rsp/packets: qXfer:features:read includes annex+window",
          "[rsp][packets]") {
  CHECK(build_qXfer_features_read("target.xml", 0, 0x1000)
        == "qXfer:features:read:target.xml:0,1000");
  CHECK(build_qXfer_features_read("target.xml", 0x1000, 0x800)
        == "qXfer:features:read:target.xml:1000,800");
}

// ----------- Response parsers --------------------------------------

TEST_CASE("rsp/packets: classify_response", "[rsp][packets][classify]") {
  CHECK(classify_response("") == ResponseKind::kUnsupported);
  CHECK(classify_response("OK") == ResponseKind::kOk);
  CHECK(classify_response("E03") == ResponseKind::kError);
  CHECK(classify_response("T05thread:1;") == ResponseKind::kStopReply);
  CHECK(classify_response("S05") == ResponseKind::kStopReply);
  CHECK(classify_response("W00") == ResponseKind::kStopReply);
  CHECK(classify_response("X09") == ResponseKind::kStopReply);
  CHECK(classify_response("deadbeef") == ResponseKind::kHex);
}

TEST_CASE("rsp/packets: parse_error_code", "[rsp][packets][parse]") {
  REQUIRE(parse_error_code("E03").value() == 0x03);
  REQUIRE(parse_error_code("E00").value() == 0x00);
  REQUIRE(parse_error_code("Eff").value() == 0xff);
  CHECK_FALSE(parse_error_code("OK").has_value());
  CHECK_FALSE(parse_error_code("E").has_value());     // missing digits
  CHECK_FALSE(parse_error_code("E0").has_value());    // only one digit
  CHECK_FALSE(parse_error_code("Ezz").has_value());   // non-hex
}

TEST_CASE("rsp/packets: parse_stop_reply S form (signal only)",
          "[rsp][packets][parse][stop]") {
  auto r = parse_stop_reply("S05");
  REQUIRE(r.has_value());
  CHECK(r->type == 'S');
  CHECK(r->signal == 0x05);
  CHECK(r->kv.empty());
}

TEST_CASE("rsp/packets: parse_stop_reply T with kv pairs",
          "[rsp][packets][parse][stop]") {
  auto r = parse_stop_reply("T05thread:1;reason:trace;");
  REQUIRE(r.has_value());
  CHECK(r->type == 'T');
  CHECK(r->signal == 0x05);
  REQUIRE(r->kv.size() == 2);
  CHECK(r->kv[0].first == "thread");
  CHECK(r->kv[0].second == "1");
  CHECK(r->kv[1].first == "reason");
  CHECK(r->kv[1].second == "trace");
}

TEST_CASE("rsp/packets: parse_stop_reply W form (exited)",
          "[rsp][packets][parse][stop]") {
  auto r = parse_stop_reply("W2a");
  REQUIRE(r.has_value());
  CHECK(r->type == 'W');
  CHECK(r->signal == 0x2a);
}

TEST_CASE("rsp/packets: parse_stop_reply rejects junk",
          "[rsp][packets][parse][stop]") {
  CHECK_FALSE(parse_stop_reply("").has_value());
  CHECK_FALSE(parse_stop_reply("OK").has_value());
  CHECK_FALSE(parse_stop_reply("T").has_value());    // missing signal
  CHECK_FALSE(parse_stop_reply("Tzz").has_value());  // non-hex signal
}

TEST_CASE("rsp/packets: decode_hex_bytes", "[rsp][packets][parse][hex]") {
  auto v = decode_hex_bytes("deadbeef");
  REQUIRE(v.has_value());
  REQUIRE(v->size() == 4);
  CHECK((*v)[0] == 0xde);
  CHECK((*v)[1] == 0xad);
  CHECK((*v)[2] == 0xbe);
  CHECK((*v)[3] == 0xef);
  CHECK(decode_hex_bytes("").value().empty());
  CHECK_FALSE(decode_hex_bytes("abc").has_value());      // odd length
  CHECK_FALSE(decode_hex_bytes("zz").has_value());       // non-hex
}

TEST_CASE("rsp/packets: parse_qSupported_reply parses +/-/=value",
          "[rsp][packets][parse][qSupported]") {
  // Real-world-ish qSupported reply:
  //   PacketSize=20000;qXfer:features:read+;multiprocess-;QStartNoAckMode+
  auto r = parse_qSupported_reply(
      "PacketSize=20000;qXfer:features:read+;multiprocess-;QStartNoAckMode+");
  REQUIRE(r.has_value());
  CHECK(r->packet_size == 0x20000);
  REQUIRE(r->features.size() == 4);
  CHECK(r->features[0].first == "PacketSize");
  CHECK(r->features[0].second == "20000");
  CHECK(r->features[1].first == "qXfer:features:read");
  CHECK(r->features[1].second == "+");
  CHECK(r->features[2].first == "multiprocess");
  CHECK(r->features[2].second == "-");
  CHECK(r->features[3].first == "QStartNoAckMode");
  CHECK(r->features[3].second == "+");
}

TEST_CASE("rsp/packets: parse_thread_info_reply m + l forms",
          "[rsp][packets][parse][threads]") {
  auto a = parse_thread_info_reply("m1,2,3");
  REQUIRE(a.has_value());
  CHECK_FALSE(a->end);
  REQUIRE(a->tids.size() == 3);
  CHECK(a->tids[0] == 1);
  CHECK(a->tids[1] == 2);
  CHECK(a->tids[2] == 3);

  auto b = parse_thread_info_reply("l");
  REQUIRE(b.has_value());
  CHECK(b->end);
  CHECK(b->tids.empty());

  auto c = parse_thread_info_reply("m");        // shape error
  CHECK_FALSE(c.has_value());
  auto d = parse_thread_info_reply("mxx,yy");   // non-hex tid
  CHECK_FALSE(d.has_value());
}

TEST_CASE("rsp/packets: parse_qXfer_reply m/l carries the data byte-for-byte",
          "[rsp][packets][parse][qXfer]") {
  auto a = parse_qXfer_reply("m<target>partial</target>");
  REQUIRE(a.has_value());
  CHECK_FALSE(a->end);
  CHECK(a->data == "<target>partial</target>");

  auto b = parse_qXfer_reply("l<target>final</target>");
  REQUIRE(b.has_value());
  CHECK(b->end);
  CHECK(b->data == "<target>final</target>");

  CHECK_FALSE(parse_qXfer_reply("").has_value());      // empty
  CHECK_FALSE(parse_qXfer_reply("x...").has_value());  // bad leading char
}
