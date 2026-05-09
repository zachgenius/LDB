// SPDX-License-Identifier: Apache-2.0
// Pure-parser tests for ldb::observers IGMP (M4 §4.6 closeout).
//
// These tests feed canned text fixtures (captured live on this Pop!_OS
// box at TDD time and committed under tests/fixtures/text/) through
// the parser entry points without any filesystem or subprocess access.
// They lock down the byte-order conversion + indented-continuation
// tokenization of /proc/net/igmp and the single-line shape of
// /proc/net/igmp6.

#include <catch_amalgamated.hpp>

#include "observers/observers.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

#ifndef LDB_FIXTURE_TEXT_DIR
#error "LDB_FIXTURE_TEXT_DIR not defined — wire it from CMake"
#endif

namespace {

std::string slurp(const std::string& path) {
  std::ifstream f(path);
  REQUIRE(f.is_open());
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

std::string fixture_path(const char* leaf) {
  std::string p = LDB_FIXTURE_TEXT_DIR;
  p += "/";
  p += leaf;
  return p;
}

}  // namespace

TEST_CASE("parse_proc_net_igmp: synthetic 2-interface input",
          "[observers][net][igmp]") {
  // Hand-built mirror of the kernel's two-level format — header line
  // per interface, then indented address rows.
  std::string in =
      "Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter\n"
      "1\tlo        :     1      V3\n"
      "\t\t\t\t010000E0     1 0:00000000\t\t0\n"
      "2\teth0      :     2      V3\n"
      "\t\t\t\t010000E0     1 0:00000000\t\t0\n"
      "\t\t\t\tFB0000E0     1 0:00000000\t\t0\n";

  auto r = ldb::observers::parse_proc_net_igmp(in);
  REQUIRE(r.total == 2);
  REQUIRE(r.groups.size() == 2);

  CHECK(r.groups[0].idx == 1u);
  CHECK(r.groups[0].device == "lo");
  REQUIRE(r.groups[0].count.has_value());
  CHECK(*r.groups[0].count == 1u);
  REQUIRE(r.groups[0].querier.has_value());
  CHECK(*r.groups[0].querier == "V3");
  REQUIRE(r.groups[0].addresses.size() == 1);
  CHECK(r.groups[0].addresses[0].address == "224.0.0.1");
  CHECK(r.groups[0].addresses[0].users == 1u);

  CHECK(r.groups[1].idx == 2u);
  CHECK(r.groups[1].device == "eth0");
  REQUIRE(r.groups[1].addresses.size() == 2);
  CHECK(r.groups[1].addresses[0].address == "224.0.0.1");
  CHECK(r.groups[1].addresses[1].address == "224.0.0.251");
}

TEST_CASE("parse_proc_net_igmp: little-endian hex byte order",
          "[observers][net][igmp]") {
  // 010000E0 (kernel little-endian) ⇒ 224.0.0.1
  // FB0000E0                       ⇒ 224.0.0.251
  std::string in =
      "Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter\n"
      "9\twlan0     :     2      V3\n"
      "\t\t\t\t010000E0     1 0:00000000\t\t0\n"
      "\t\t\t\tFB0000E0     1 0:00000000\t\t0\n";
  auto r = ldb::observers::parse_proc_net_igmp(in);
  REQUIRE(r.total == 1);
  REQUIRE(r.groups[0].addresses.size() == 2);
  CHECK(r.groups[0].addresses[0].address == "224.0.0.1");
  CHECK(r.groups[0].addresses[1].address == "224.0.0.251");
}

TEST_CASE("parse_proc_net_igmp: real fixture from this host",
          "[observers][net][igmp]") {
  auto text = slurp(fixture_path("proc_net_igmp.txt"));
  auto r = ldb::observers::parse_proc_net_igmp(text);
  REQUIRE(r.total >= 1);
  // lo always has 224.0.0.1 (all-systems-multicast) on Linux.
  bool found_lo = false;
  for (const auto& g : r.groups) {
    if (g.device == "lo") {
      found_lo = true;
      bool has_all_systems = false;
      for (const auto& a : g.addresses) {
        if (a.address == "224.0.0.1") has_all_systems = true;
      }
      CHECK(has_all_systems);
    }
    CHECK(g.idx > 0u);
    CHECK(!g.device.empty());
  }
  CHECK(found_lo);
}

TEST_CASE("parse_proc_net_igmp: header-only input ⇒ empty result",
          "[observers][net][igmp]") {
  std::string in =
      "Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter\n";
  auto r = ldb::observers::parse_proc_net_igmp(in);
  CHECK(r.total == 0);
  CHECK(r.groups.empty());
}

TEST_CASE("parse_proc_net_igmp: empty input ⇒ empty result",
          "[observers][net][igmp]") {
  auto r = ldb::observers::parse_proc_net_igmp("");
  CHECK(r.total == 0);
  CHECK(r.groups.empty());
}


TEST_CASE("parse_proc_net_igmp6: synthetic input",
          "[observers][net][igmp6]") {
  std::string in =
      "1    lo              ff020000000000000000000000000001     1 0000000C 0\n"
      "2    eth0            ff0200000000000000000000000000fb     1 00000004 0\n";

  auto r = ldb::observers::parse_proc_net_igmp6(in);
  REQUIRE(r.total == 2);

  CHECK(r.groups[0].idx == 1u);
  CHECK(r.groups[0].device == "lo");
  CHECK(!r.groups[0].count.has_value());
  CHECK(!r.groups[0].querier.has_value());
  REQUIRE(r.groups[0].addresses.size() == 1);
  CHECK(r.groups[0].addresses[0].address ==
        "ff02:0000:0000:0000:0000:0000:0000:0001");
  CHECK(r.groups[0].addresses[0].users == 1u);
  CHECK(r.groups[0].addresses[0].timer == 0xCu);

  CHECK(r.groups[1].device == "eth0");
  CHECK(r.groups[1].addresses[0].address ==
        "ff02:0000:0000:0000:0000:0000:0000:00fb");
}

TEST_CASE("parse_proc_net_igmp6: real fixture from this host",
          "[observers][net][igmp6]") {
  auto text = slurp(fixture_path("proc_net_igmp6.txt"));
  auto r = ldb::observers::parse_proc_net_igmp6(text);
  REQUIRE(r.total >= 1);
  // lo always has ff02::1 (all-nodes-multicast) on Linux IPv6.
  bool found_all_nodes = false;
  for (const auto& g : r.groups) {
    CHECK(g.idx > 0u);
    CHECK(!g.device.empty());
    for (const auto& a : g.addresses) {
      // 32 hex chars + 7 colons.
      CHECK(a.address.size() == 39);
      if (g.device == "lo" &&
          a.address == "ff02:0000:0000:0000:0000:0000:0000:0001") {
        found_all_nodes = true;
      }
    }
  }
  CHECK(found_all_nodes);
}

TEST_CASE("parse_proc_net_igmp6: empty input ⇒ empty result",
          "[observers][net][igmp6]") {
  auto r = ldb::observers::parse_proc_net_igmp6("");
  CHECK(r.total == 0);
  CHECK(r.groups.empty());
}

TEST_CASE("parse_proc_net_igmp6: long no-whitespace device name",
          "[observers][net][igmp6]") {
  // Real interface names never contain whitespace; we tokenize as
  // "idx device addr users src timer".
  std::string in =
      "3    enx323e48ab03da ff0200000000000000000000000000fb     1 00000004 0\n";
  auto r = ldb::observers::parse_proc_net_igmp6(in);
  REQUIRE(r.total == 1);
  CHECK(r.groups[0].device == "enx323e48ab03da");
}
