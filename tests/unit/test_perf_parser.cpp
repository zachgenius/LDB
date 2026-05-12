// SPDX-License-Identifier: Apache-2.0
// Tests for the perf-script text parser. Pure string -> Sample[]
// transformation; no live perf needed.
//
// See docs/22-perf-integration.md for the input format spec.

#include <catch_amalgamated.hpp>

#include "perf/perf_parser.h"

#include <fstream>
#include <sstream>
#include <string>

#ifndef LDB_FIXTURE_PERF_SCRIPT_SAMPLE
#  define LDB_FIXTURE_PERF_SCRIPT_SAMPLE \
       "tests/fixtures/perf_script_sample.txt"
#endif

namespace {

std::string slurp(const std::string& path) {
  std::ifstream in(path);
  REQUIRE(in.good());
  std::stringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

}  // namespace

using ldb::perf::PerfParser;
using ldb::perf::Sample;

TEST_CASE("perf parser: fixture file parses to five samples",
          "[perf][parser]") {
  const std::string text = slurp(LDB_FIXTURE_PERF_SCRIPT_SAMPLE);
  PerfParser::Result r = PerfParser::parse(text);

  REQUIRE(r.parse_errors.empty());
  REQUIRE(r.samples.size() == 5);
}

TEST_CASE("perf parser: header lines ignored", "[perf][parser]") {
  // A standalone header block should yield zero samples and zero errors.
  std::string text =
      "# ========\n"
      "# captured on : Mon May 11 12:00:00 2026\n"
      "# event       : name = cycles\n"
      "# ========\n"
      "\n";
  PerfParser::Result r = PerfParser::parse(text);
  REQUIRE(r.samples.empty());
  REQUIRE(r.parse_errors.empty());
}

TEST_CASE("perf parser: first sample carries comm/pid/tid/cpu/event/stack",
          "[perf][parser]") {
  const std::string text = slurp(LDB_FIXTURE_PERF_SCRIPT_SAMPLE);
  PerfParser::Result r = PerfParser::parse(text);
  REQUIRE(r.samples.size() >= 1);
  const Sample& s = r.samples[0];

  REQUIRE(s.comm  == "foo");
  REQUIRE(s.pid   == 12345);
  REQUIRE(s.tid   == 12345);
  REQUIRE(s.cpu   == 3);
  REQUIRE(s.event == "cycles");
  // ts_ns from 1700000000.123456 -> 1700000000123456000
  REQUIRE(s.ts_ns == 1700000000123456000LL);

  // Stack: main, __libc_start_main, _start.
  REQUIRE(s.stack.size() == 3);
  REQUIRE(s.stack[0].addr == 0x412af0ULL);
  REQUIRE(s.stack[0].sym  == "main");
  REQUIRE(s.stack[0].mod  == "/home/zach/foo");
  REQUIRE(s.stack[1].sym  == "__libc_start_main");
  REQUIRE(s.stack[1].mod  == "/lib/x86_64-linux-gnu/libc.so.6");
  REQUIRE(s.stack[2].sym  == "_start");
}

TEST_CASE("perf parser: separate samples by blank line",
          "[perf][parser]") {
  const std::string text = slurp(LDB_FIXTURE_PERF_SCRIPT_SAMPLE);
  PerfParser::Result r = PerfParser::parse(text);
  REQUIRE(r.samples.size() == 5);
  // Second sample: do_work / main / __libc_start_main
  REQUIRE(r.samples[1].stack.size() == 3);
  REQUIRE(r.samples[1].stack[0].sym == "do_work");
  REQUIRE(r.samples[1].stack[2].sym == "__libc_start_main");
}

TEST_CASE("perf parser: [unknown] symbol passes through",
          "[perf][parser]") {
  const std::string text = slurp(LDB_FIXTURE_PERF_SCRIPT_SAMPLE);
  PerfParser::Result r = PerfParser::parse(text);
  REQUIRE(r.samples.size() >= 3);

  // Third sample: single-frame stack, sym is "[unknown]" verbatim.
  const Sample& s = r.samples[2];
  REQUIRE(s.tid == 12346);
  REQUIRE(s.stack.size() == 1);
  REQUIRE(s.stack[0].sym == "[unknown]");
  REQUIRE(s.stack[0].addr == 0x412c00ULL);
}

TEST_CASE("perf parser: missing DSO tolerated", "[perf][parser]") {
  const std::string text = slurp(LDB_FIXTURE_PERF_SCRIPT_SAMPLE);
  PerfParser::Result r = PerfParser::parse(text);
  REQUIRE(r.samples.size() == 5);
  // Fifth sample: "0 [unknown]" with no "(dso)".
  const Sample& s = r.samples[4];
  REQUIRE(s.comm == "worker");
  REQUIRE(s.tid  == 12347);
  REQUIRE(s.cpu  == 2);
  REQUIRE(s.stack.size() == 1);
  REQUIRE(s.stack[0].addr == 0ULL);
  REQUIRE(s.stack[0].sym  == "[unknown]");
  REQUIRE(s.stack[0].mod.empty());
}

TEST_CASE("perf parser: header parsing", "[perf][parser]") {
  // Verify parse picks up the trace meta off the header block.
  const std::string text = slurp(LDB_FIXTURE_PERF_SCRIPT_SAMPLE);
  PerfParser::Result r = PerfParser::parse(text);
  REQUIRE(r.os_release == "6.18.7-76061807-generic");
  REQUIRE(r.arch       == "x86_64");
  REQUIRE(r.hostname   == "devbox");
}

TEST_CASE("perf parser: handles missing event header gracefully",
          "[perf][parser]") {
  // A stack-frame line without a preceding event header line is a parse
  // error, but the parser must NOT crash — it records the error and
  // continues.
  std::string text =
      "                                412af0 main (/foo)\n"
      "\n";
  PerfParser::Result r = PerfParser::parse(text);
  REQUIRE(r.samples.empty());
  REQUIRE_FALSE(r.parse_errors.empty());
}

TEST_CASE("perf parser: tolerates samples without [CPU] token",
          "[perf][parser]") {
  // Defensive case for traces recorded without --sample-cpu (older perf
  // versions / external sources). The parser falls back to cpu=-1 and
  // continues parsing the rest of the sample shape. This pairs with
  // perf_runner.cpp passing --sample-cpu to perf record so this path
  // is rarely needed in our own traces — but a perf.data ingested from
  // a perf record run elsewhere may not have CPU info.
  std::string text =
      "foo  12345/12345  1700000000.123456: cycles: 100000: "
      "                                412af0 main (/foo)\n"
      "\n";
  PerfParser::Result r = PerfParser::parse(text);
  REQUIRE(r.parse_errors.empty());
  REQUIRE(r.samples.size() == 1);
  CHECK(r.samples[0].cpu == -1);
  CHECK(r.samples[0].tid == 12345ULL);
  CHECK(r.samples[0].event == "cycles");
  REQUIRE(r.samples[0].stack.size() == 1);
  CHECK(r.samples[0].stack[0].sym == "main");
}

TEST_CASE("perf parser: to_json shape", "[perf][parser]") {
  Sample s;
  s.ts_ns = 1700000000123456000LL;
  s.tid   = 12345;
  s.pid   = 12345;
  s.cpu   = 3;
  s.comm  = "foo";
  s.event = "cycles";
  s.stack.push_back({0x412af0, "main", "/home/zach/foo"});
  s.stack.push_back({0x7ffe1234ULL, "libc_start", "/lib/x86_64-linux-gnu/libc.so.6"});

  auto j = PerfParser::sample_to_json(s);
  REQUIRE(j["ts_ns"].get<std::int64_t>() == 1700000000123456000LL);
  REQUIRE(j["tid"].get<std::uint64_t>()  == 12345ULL);
  REQUIRE(j["cpu"].get<int>()            == 3);
  REQUIRE(j["event"].get<std::string>()  == "cycles");
  REQUIRE(j["comm"].get<std::string>()   == "foo");
  REQUIRE(j["stack"].is_array());
  REQUIRE(j["stack"].size() == 2);
  REQUIRE(j["stack"][0]["sym"].get<std::string>() == "main");
  REQUIRE(j["stack"][0]["mod"].get<std::string>() == "/home/zach/foo");
  // addr is emitted as hex string for consistency with the probe-event
  // shape ("0x412af0").
  REQUIRE(j["stack"][0]["addr"].get<std::string>() == "0x412af0");
}
