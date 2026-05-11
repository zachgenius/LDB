// SPDX-License-Identifier: Apache-2.0
//
// Wire-protocol tests for the daemon - `ldb-probe-agent` channel.
//
// Why pure-protocol: libbpf is privileged + kernel-coupled; these tests
// must run on every box (no CAP_BPF, no /sys/kernel/btf/vmlinux). They
// exercise only the framing layer and command JSON shape - the same
// surface the daemon-side AgentEngine and the agent's main loop both
// depend on.
//
// See docs/21-probe-agent.md "Wire protocol" for the spec these tests
// pin.

#include <catch_amalgamated.hpp>

#include "probe_agent/protocol.h"

#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

using namespace ldb::probe_agent;
using json = nlohmann::json;

namespace {

std::string roundtrip_via_stream(const std::string& payload) {
  std::ostringstream out;
  REQUIRE(write_frame(out, payload));
  std::string buf = out.str();
  std::istringstream in(buf);
  std::string got;
  auto err = read_frame(in, &got);
  REQUIRE(err == FrameError::kOk);
  return got;
}

}  // namespace

TEST_CASE("frame: length-prefix round trip preserves bytes",
          "[probe_agent][protocol][framing]") {
  REQUIRE(roundtrip_via_stream("") == "");
  REQUIRE(roundtrip_via_stream("{}") == "{}");
  REQUIRE(roundtrip_via_stream("{\"type\":\"hello\"}") ==
          "{\"type\":\"hello\"}");

  std::string big(8192, 'x');
  REQUIRE(roundtrip_via_stream(big) == big);
}

TEST_CASE("frame: length prefix is 4-byte big-endian",
          "[probe_agent][protocol][framing]") {
  std::ostringstream out;
  REQUIRE(write_frame(out, "hi"));
  std::string s = out.str();
  REQUIRE(s.size() == 6);
  REQUIRE(static_cast<unsigned char>(s[0]) == 0x00);
  REQUIRE(static_cast<unsigned char>(s[1]) == 0x00);
  REQUIRE(static_cast<unsigned char>(s[2]) == 0x00);
  REQUIRE(static_cast<unsigned char>(s[3]) == 0x02);
  REQUIRE(s[4] == 'h');
  REQUIRE(s[5] == 'i');
}

TEST_CASE("frame: oversize frame is rejected before allocation",
          "[probe_agent][protocol][framing]") {
  std::string buf;
  buf.push_back(static_cast<char>(0x7f));
  buf.push_back(static_cast<char>(0xff));
  buf.push_back(static_cast<char>(0xff));
  buf.push_back(static_cast<char>(0xff));
  std::istringstream in(buf);
  std::string out;
  auto err = read_frame(in, &out);
  REQUIRE(err == FrameError::kTooLarge);
}

TEST_CASE("frame: truncated header returns kEof",
          "[probe_agent][protocol][framing]") {
  std::istringstream in("");
  std::string out;
  REQUIRE(read_frame(in, &out) == FrameError::kEof);
}

TEST_CASE("frame: truncated body returns kTruncated",
          "[probe_agent][protocol][framing]") {
  std::string buf;
  buf.push_back(0); buf.push_back(0); buf.push_back(0); buf.push_back(5);
  buf += "abc";
  std::istringstream in(buf);
  std::string out;
  REQUIRE(read_frame(in, &out) == FrameError::kTruncated);
}

TEST_CASE("commands: hello has a known shape",
          "[probe_agent][protocol][commands]") {
  json req = make_hello_request();
  REQUIRE(req["type"] == "hello");
}

TEST_CASE("commands: attach_uprobe carries program/path/symbol",
          "[probe_agent][protocol][commands]") {
  json req = make_attach_uprobe_request(
      "syscall_count", "/usr/bin/cat", "main", std::nullopt);
  REQUIRE(req["type"] == "attach_uprobe");
  REQUIRE(req["program"] == "syscall_count");
  REQUIRE(req["path"] == "/usr/bin/cat");
  REQUIRE(req["symbol"] == "main");
  REQUIRE_FALSE(req.contains("pid"));

  json with_pid = make_attach_uprobe_request(
      "syscall_count", "/usr/bin/cat", "main", 1234);
  REQUIRE(with_pid["pid"] == 1234);
}

TEST_CASE("commands: attach_kprobe carries program/function",
          "[probe_agent][protocol][commands]") {
  json req = make_attach_kprobe_request("syscall_count", "do_sys_open");
  REQUIRE(req["type"] == "attach_kprobe");
  REQUIRE(req["program"] == "syscall_count");
  REQUIRE(req["function"] == "do_sys_open");
}

TEST_CASE("commands: poll_events", "[probe_agent][protocol][commands]") {
  json req = make_poll_events_request("a1", 100);
  REQUIRE(req["type"] == "poll_events");
  REQUIRE(req["attach_id"] == "a1");
  REQUIRE(req["max"] == 100);
}

TEST_CASE("commands: detach + shutdown",
          "[probe_agent][protocol][commands]") {
  json d = make_detach_request("a1");
  REQUIRE(d["type"] == "detach");
  REQUIRE(d["attach_id"] == "a1");

  json s = make_shutdown_request();
  REQUIRE(s["type"] == "shutdown");
}

TEST_CASE("responses: parse_hello_ok",
          "[probe_agent][protocol][responses]") {
  json r;
  r["type"] = "hello_ok";
  r["version"] = "1";
  r["libbpf_version"] = "1.3.0";
  r["btf_present"] = true;
  r["embedded_programs"] = json::array({"syscall_count"});
  auto ok = parse_hello_ok(r);
  REQUIRE(ok.has_value());
  REQUIRE(ok->version == "1");
  REQUIRE(ok->libbpf_version == "1.3.0");
  REQUIRE(ok->btf_present == true);
  REQUIRE(ok->embedded_programs.size() == 1);
  REQUIRE(ok->embedded_programs[0] == "syscall_count");
}

TEST_CASE("responses: parse_attached",
          "[probe_agent][protocol][responses]") {
  json r;
  r["type"] = "attached";
  r["attach_id"] = "a7";
  auto a = parse_attached(r);
  REQUIRE(a.has_value());
  REQUIRE(a->attach_id == "a7");
}

TEST_CASE("responses: parse_error",
          "[probe_agent][protocol][responses]") {
  json r;
  r["type"] = "error";
  r["code"] = "no_capability";
  r["message"] = "CAP_BPF required";
  auto e = parse_error(r);
  REQUIRE(e.has_value());
  REQUIRE(e->code == "no_capability");
  REQUIRE(e->message == "CAP_BPF required");
}

TEST_CASE("responses: parse_events decodes payload_b64",
          "[probe_agent][protocol][responses]") {
  json r;
  r["type"] = "events";
  r["dropped"] = 0;
  json e0;
  e0["ts_ns"] = 1700000000000000000ULL;
  e0["pid"] = 100;
  e0["tid"] = 100;
  e0["payload_b64"] = "QUJDRA==";  // base64("ABCD")
  r["events"] = json::array({e0});

  auto p = parse_events(r);
  REQUIRE(p.has_value());
  REQUIRE(p->dropped == 0);
  REQUIRE(p->events.size() == 1);
  const auto& ev = p->events[0];
  REQUIRE(ev.ts_ns == 1700000000000000000ULL);
  REQUIRE(ev.pid == 100);
  REQUIRE(ev.tid == 100);
  REQUIRE(ev.payload.size() == 4);
  REQUIRE(ev.payload[0] == 'A');
  REQUIRE(ev.payload[3] == 'D');
}

TEST_CASE("base64: round trip handles all byte values",
          "[probe_agent][protocol][base64]") {
  std::vector<std::uint8_t> all;
  for (int i = 0; i < 256; ++i) all.push_back(static_cast<std::uint8_t>(i));
  std::string encoded = base64_encode(all.data(), all.size());
  std::vector<std::uint8_t> back;
  REQUIRE(base64_decode(encoded, &back));
  REQUIRE(back.size() == all.size());
  for (std::size_t i = 0; i < back.size(); ++i) {
    REQUIRE(back[i] == all[i]);
  }
}

TEST_CASE("base64: rejects malformed input",
          "[probe_agent][protocol][base64]") {
  std::vector<std::uint8_t> out;
  REQUIRE_FALSE(base64_decode("@@@", &out));
  REQUIRE_FALSE(base64_decode("abc", &out));  // length not multiple of 4
}

TEST_CASE("base64: rejects pad-then-data in the final group",
          "[probe_agent][protocol][base64]") {
  // RFC 4648 §3.3: once a pad character appears in a group, every
  // remaining position MUST also be a pad. The original decoder
  // accepted `AB=C` and silently emitted two garbage bytes; this case
  // pins the corrected behaviour.
  std::vector<std::uint8_t> out;
  REQUIRE_FALSE(base64_decode("AB=C", &out));
  REQUIRE(out.empty());
}

TEST_CASE("base64: RFC 4648 §10 canonical test vectors",
          "[probe_agent][protocol][base64]") {
  struct Vec { const char* plain; const char* encoded; };
  // From RFC 4648 §10. Round-trip in both directions to catch
  // simultaneously-broken encode/decode pairs that round-trip alone
  // would miss.
  const Vec vectors[] = {
      {"",       ""},
      {"f",      "Zg=="},
      {"fo",     "Zm8="},
      {"foo",    "Zm9v"},
      {"foob",   "Zm9vYg=="},
      {"fooba",  "Zm9vYmE="},
      {"foobar", "Zm9vYmFy"},
  };
  for (const auto& v : vectors) {
    auto plain_bytes = reinterpret_cast<const std::uint8_t*>(v.plain);
    std::string enc = base64_encode(plain_bytes,
                                    std::strlen(v.plain));
    REQUIRE(enc == v.encoded);
    std::vector<std::uint8_t> dec;
    REQUIRE(base64_decode(v.encoded, &dec));
    REQUIRE(std::string(dec.begin(), dec.end()) == v.plain);
  }
}
