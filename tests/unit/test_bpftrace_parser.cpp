// SPDX-License-Identifier: Apache-2.0
// Tests for the bpftrace stdout JSON-line parser. Pure string → ProbeEvent
// transformation; no subprocess.

#include <catch_amalgamated.hpp>

#include "probes/bpftrace_engine.h"
#include "probes/probe_orchestrator.h"  // ProbeEvent

#include <optional>
#include <string>
#include <vector>

using ldb::probes::BpftraceParse;
using ldb::probes::ProbeEvent;

TEST_CASE("bpftrace parser: well-formed line", "[probes][bpftrace][parser]") {
  std::string line =
      R"({"ts_ns":1700000000000,"tid":4242,"pid":31415,"args":["0x7ffe","0x10","0x0"]})";
  auto pr = BpftraceParse::parse_line(line);
  REQUIRE(pr.has_value());
  REQUIRE(pr->ts_ns == 1700000000000LL);
  REQUIRE(pr->tid == 4242);
  REQUIRE(pr->memory.empty());
  REQUIRE(pr->registers.size() == 3);
  REQUIRE(pr->registers["arg0"] == 0x7ffeULL);
  REQUIRE(pr->registers["arg1"] == 0x10ULL);
  REQUIRE(pr->registers["arg2"] == 0ULL);
}

TEST_CASE("bpftrace parser: extra/missing fields tolerated",
          "[probes][bpftrace][parser]") {
  std::string line = R"({"ts_ns":42,"tid":7})";
  auto pr = BpftraceParse::parse_line(line);
  REQUIRE(pr.has_value());
  REQUIRE(pr->ts_ns == 42);
  REQUIRE(pr->tid == 7);
  REQUIRE(pr->registers.empty());
}

TEST_CASE("bpftrace parser: malformed line yields nullopt",
          "[probes][bpftrace][parser]") {
  REQUIRE_FALSE(BpftraceParse::parse_line("Attaching 1 probe...").has_value());
  REQUIRE_FALSE(BpftraceParse::parse_line("").has_value());
  REQUIRE_FALSE(BpftraceParse::parse_line("not json at all").has_value());
  // Valid JSON, but not an object → parser rejects.
  REQUIRE_FALSE(BpftraceParse::parse_line("[1,2,3]").has_value());
}

TEST_CASE("bpftrace parser: hex-string arg values",
          "[probes][bpftrace][parser]") {
  // Even though our generated programs use 0x%lx, agents may construct
  // probes that emit decimal — the parser MUST accept both shapes.
  std::string line =
      R"({"ts_ns":1,"tid":2,"args":["12345","0xdeadbeef"]})";
  auto pr = BpftraceParse::parse_line(line);
  REQUIRE(pr.has_value());
  REQUIRE(pr->registers["arg0"] == 12345ULL);
  REQUIRE(pr->registers["arg1"] == 0xdeadbeefULL);
}
