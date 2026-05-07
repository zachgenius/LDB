// Tests for `transport::parse_rr_url` and `transport::find_rr_binary`.
//
// Tier 4 §13: rr integration via rr:// URL scheme. The parser is the
// bottom of the dispatch tree — every rr:// connect_remote eventually
// passes a string through here, so its edge cases are the daemon's
// edge cases.

#include <catch_amalgamated.hpp>

#include "transport/rr.h"
#include "backend/debugger_backend.h"  // backend::Error

#include <cstdlib>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

using ldb::backend::Error;
using ldb::transport::parse_rr_url;
using ldb::transport::find_rr_binary;
using ldb::transport::RrUrl;
using ldb::transport::pick_ephemeral_port_local;

TEST_CASE("parse_rr_url: absolute trace dir, no port",
          "[transport][rr][parser]") {
  auto u = parse_rr_url("rr:///path/to/trace");
  CHECK(u.trace_dir == "/path/to/trace");
  CHECK_FALSE(u.port.has_value());
}

TEST_CASE("parse_rr_url: absolute trace dir with port",
          "[transport][rr][parser]") {
  auto u = parse_rr_url("rr:///path/to/trace?port=12345");
  CHECK(u.trace_dir == "/path/to/trace");
  REQUIRE(u.port.has_value());
  CHECK(*u.port == 12345);
}

TEST_CASE("parse_rr_url: deeply nested absolute path",
          "[transport][rr][parser]") {
  auto u = parse_rr_url("rr:///home/u/.local/share/rr/true-0?port=9999");
  CHECK(u.trace_dir == "/home/u/.local/share/rr/true-0");
  REQUIRE(u.port.has_value());
  CHECK(*u.port == 9999);
}

TEST_CASE("parse_rr_url: relative path rejected",
          "[transport][rr][parser][error]") {
  // `rr://relative/path` parses authority="relative", path="/path".
  // For our purposes we want a strictly absolute trace dir, so this
  // is rejected with a sharp error.
  CHECK_THROWS_AS(parse_rr_url("rr://relative/path"), Error);
}

TEST_CASE("parse_rr_url: missing scheme rejected",
          "[transport][rr][parser][error]") {
  CHECK_THROWS_AS(parse_rr_url("/path/to/trace"), Error);
  CHECK_THROWS_AS(parse_rr_url("file:///path/to/trace"), Error);
  CHECK_THROWS_AS(parse_rr_url("connect://127.0.0.1:1234"), Error);
}

TEST_CASE("parse_rr_url: empty / whitespace-only rejected",
          "[transport][rr][parser][error]") {
  CHECK_THROWS_AS(parse_rr_url(""), Error);
  CHECK_THROWS_AS(parse_rr_url("rr://"), Error);
  CHECK_THROWS_AS(parse_rr_url("rr:///"), Error);
}

TEST_CASE("parse_rr_url: non-numeric port rejected",
          "[transport][rr][parser][error]") {
  CHECK_THROWS_AS(parse_rr_url("rr:///path?port=abc"), Error);
  CHECK_THROWS_AS(parse_rr_url("rr:///path?port="), Error);
  CHECK_THROWS_AS(parse_rr_url("rr:///path?port=12x"), Error);
}

TEST_CASE("parse_rr_url: out-of-range port rejected",
          "[transport][rr][parser][error]") {
  CHECK_THROWS_AS(parse_rr_url("rr:///path?port=0"), Error);
  CHECK_THROWS_AS(parse_rr_url("rr:///path?port=70000"), Error);
  CHECK_THROWS_AS(parse_rr_url("rr:///path?port=-1"), Error);
}

TEST_CASE("parse_rr_url: unknown query key rejected",
          "[transport][rr][parser][error]") {
  // We accept ONLY `port=N` today. Anything else is a typo or future
  // feature; refuse to swallow it silently.
  CHECK_THROWS_AS(parse_rr_url("rr:///path?bogus=1"), Error);
  CHECK_THROWS_AS(parse_rr_url("rr:///path?port=1234&bogus=1"), Error);
}

TEST_CASE("find_rr_binary: env override honored when executable",
          "[transport][rr][discovery]") {
  // Use a stand-in executable that exists on both Linux (/usr/bin/true)
  // and macOS (/usr/bin/true — macOS does not have /bin/true).
  ::setenv("LDB_RR_BIN", "/usr/bin/true", /*overwrite=*/1);
  auto got = find_rr_binary();
  CHECK(got == "/usr/bin/true");
  ::unsetenv("LDB_RR_BIN");
}

TEST_CASE("find_rr_binary: env override ignored when not executable",
          "[transport][rr][discovery]") {
  ::setenv("LDB_RR_BIN", "/this/path/does/not/exist", /*overwrite=*/1);
  auto got = find_rr_binary();
  // Falls through to /usr/bin/rr / /usr/local/bin/rr / PATH search.
  // On dev boxes without rr installed this returns "". Either way,
  // the bogus override must NOT come back.
  CHECK(got != "/this/path/does/not/exist");
  ::unsetenv("LDB_RR_BIN");
}

TEST_CASE("pick_ephemeral_port_local: returns a usable port",
          "[transport][rr][discovery]") {
  auto p1 = pick_ephemeral_port_local();
  auto p2 = pick_ephemeral_port_local();
  CHECK(p1 > 0);
  CHECK(p2 > 0);
  // The kernel may reuse the same port across two close-then-bind
  // calls (TIME_WAIT pool timing); we don't require uniqueness, only
  // that the call succeeds twice.
}
