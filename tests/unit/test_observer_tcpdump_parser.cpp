// Pure-parser tests for ldb::observers::tcpdump (M4 part 5, §4.6).
//
// `tcpdump -nn -tt -l` produces one line per packet, with a leading
// `<seconds>.<usec>` timestamp followed by a free-form summary. We
// parse the timestamp precisely (round-trip through atof) and keep
// the rest verbatim as `summary`. Best-effort src/dst/proto/len
// extraction is a separate concern documented per-test.
//
// Live capture lives in test_observer_tcpdump_live.cpp; this file
// uses canned fixture text (synthesized — see the fixture comment).

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

TEST_CASE("parse_tcpdump_line: TCP SYN on lo", "[observers][net][tcpdump]") {
  std::string in =
      "1709123456.789012 IP 127.0.0.1.34567 > 127.0.0.1.9001: "
      "Flags [S], seq 0, win 65535, length 0";
  auto p = ldb::observers::parse_tcpdump_line(in);
  REQUIRE(p.has_value());
  CHECK(p->ts_epoch == Catch::Approx(1709123456.789012).epsilon(1e-6));
  CHECK(p->summary.find("Flags [S]") != std::string::npos);
  CHECK(p->summary.find("1709123456") == std::string::npos);  // ts removed
  REQUIRE(p->proto.has_value());
  CHECK(*p->proto == "IP");
  REQUIRE(p->src.has_value());
  CHECK(*p->src == "127.0.0.1.34567");
  REQUIRE(p->dst.has_value());
  CHECK(*p->dst == "127.0.0.1.9001");
  REQUIRE(p->len.has_value());
  CHECK(*p->len == 0u);
}

TEST_CASE("parse_tcpdump_line: IPv6 P. with payload",
          "[observers][net][tcpdump]") {
  std::string in =
      "1709123457.012345 IP6 ::1.51234 > ::1.9001: "
      "Flags [P.], seq 1:6, ack 1, win 512, length 5";
  auto p = ldb::observers::parse_tcpdump_line(in);
  REQUIRE(p.has_value());
  CHECK(p->ts_epoch == Catch::Approx(1709123457.012345).epsilon(1e-6));
  REQUIRE(p->proto.has_value());
  CHECK(*p->proto == "IP6");
  REQUIRE(p->src.has_value());
  CHECK(*p->src == "::1.51234");
  REQUIRE(p->dst.has_value());
  CHECK(*p->dst == "::1.9001");
  REQUIRE(p->len.has_value());
  CHECK(*p->len == 5u);
}

TEST_CASE("parse_tcpdump_line: ARP without > separator parses ts + summary",
          "[observers][net][tcpdump]") {
  // ARP lines don't have a `src > dst` shape, so src/dst are absent
  // by design. proto is "ARP" — first whitespace-delimited token.
  std::string in =
      "1709123457.500000 ARP, Request who-has 192.168.0.1 "
      "tell 192.168.0.2, length 28";
  auto p = ldb::observers::parse_tcpdump_line(in);
  REQUIRE(p.has_value());
  CHECK(p->ts_epoch == Catch::Approx(1709123457.5).epsilon(1e-6));
  REQUIRE(p->proto.has_value());
  CHECK(*p->proto == "ARP");
  CHECK(!p->src.has_value());
  CHECK(!p->dst.has_value());
  REQUIRE(p->len.has_value());
  CHECK(*p->len == 28u);
}

TEST_CASE("parse_tcpdump_line: empty / comment / malformed",
          "[observers][net][tcpdump]") {
  CHECK(!ldb::observers::parse_tcpdump_line("").has_value());
  CHECK(!ldb::observers::parse_tcpdump_line("# just a comment").has_value());
  CHECK(!ldb::observers::parse_tcpdump_line("nothing useful here")
             .has_value());
  // No timestamp — refused.
  CHECK(!ldb::observers::parse_tcpdump_line("IP 1.2.3.4 > 5.6.7.8: ...")
             .has_value());
}

TEST_CASE("parse_tcpdump_lines: synthesized fixture",
          "[observers][net][tcpdump]") {
  auto text = slurp(fixture_path("tcpdump_lo.txt"));
  auto packets = ldb::observers::parse_tcpdump_lines(text);
  // The fixture has 5 packet lines (the rest are # comments).
  REQUIRE(packets.size() == 5);

  // First three packets are the TCP three-way handshake on 127.0.0.1.
  for (std::size_t i = 0; i < 3; ++i) {
    CHECK(packets[i].ts_epoch > 1709000000.0);
    CHECK(packets[i].ts_epoch < 1709200000.0);
    CHECK(!packets[i].summary.empty());
    REQUIRE(packets[i].proto.has_value());
    CHECK(*packets[i].proto == "IP");
    REQUIRE(packets[i].src.has_value());
    CHECK(packets[i].src->find("127.0.0.1.") == 0);
  }
  REQUIRE(packets[3].proto.has_value());
  CHECK(*packets[3].proto == "IP6");
  REQUIRE(packets[4].proto.has_value());
  CHECK(*packets[4].proto == "ARP");
}

TEST_CASE("parse_tcpdump_lines: tolerates blank + comment lines",
          "[observers][net][tcpdump]") {
  std::string in =
      "\n"
      "# comment\n"
      "1709123456.000001 IP 1.2.3.4.80 > 5.6.7.8.443: tcp\n"
      "  \n"
      "1709123456.000002 IP 5.6.7.8.443 > 1.2.3.4.80: tcp\n";
  auto packets = ldb::observers::parse_tcpdump_lines(in);
  REQUIRE(packets.size() == 2);
  CHECK(packets[0].ts_epoch == Catch::Approx(1709123456.000001).epsilon(1e-9));
  CHECK(packets[1].ts_epoch == Catch::Approx(1709123456.000002).epsilon(1e-9));
}
