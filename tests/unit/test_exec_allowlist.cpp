// SPDX-License-Identifier: Apache-2.0
// Pure-logic tests for the operator-configured observer.exec allowlist
// (M4 polish, plan §4.6). NO subprocess invocation — these exercise
// only the file parser + glob matcher.
//
// The matcher is fnmatch(pattern, joined_argv, FNM_PATHNAME). The tests
// pin the exact behaviour callers depend on:
//
//   • blank lines and `#` comments ignored
//   • EMPTY file rejects every command (default-deny)
//   • MISSING file → from_file returns nullopt
//   • full-line anchoring: `/bin/sh` must NOT match `/bin/sh -c rm -rf /`
//   • `*` does NOT span '/' (FNM_PATHNAME); it does span single spaces
//     between argv elements after we join them.

#include <catch_amalgamated.hpp>

#include "observers/exec_allowlist.h"

#include <filesystem>
#include <fstream>
#include <string>

namespace {

std::filesystem::path temp_allowlist_path(const std::string& tag) {
  auto p = std::filesystem::temp_directory_path()
           / ("ldb_exec_allowlist_" + tag + ".txt");
  std::filesystem::remove(p);
  return p;
}

void write_file(const std::filesystem::path& p, const std::string& body) {
  std::ofstream f(p);
  REQUIRE(f.is_open());
  f << body;
  f.close();
}

}  // namespace

TEST_CASE("ExecAllowlist::from_file: missing file returns nullopt",
          "[observers][exec][allowlist]") {
  auto p = std::filesystem::temp_directory_path()
           / "ldb_exec_allowlist_does_not_exist.txt";
  std::filesystem::remove(p);
  auto al = ldb::observers::ExecAllowlist::from_file(p);
  REQUIRE_FALSE(al.has_value());
}

TEST_CASE("ExecAllowlist::from_file: empty file → default-deny",
          "[observers][exec][allowlist]") {
  auto p = temp_allowlist_path("empty");
  write_file(p, "");
  auto al = ldb::observers::ExecAllowlist::from_file(p);
  REQUIRE(al.has_value());
  REQUIRE(al->pattern_count() == 0);
  REQUIRE_FALSE(al->allows({"/usr/bin/uptime"}));
  REQUIRE_FALSE(al->allows({"/bin/echo", "hello"}));
}

TEST_CASE("ExecAllowlist::from_file: comments and blanks ignored",
          "[observers][exec][allowlist]") {
  auto p = temp_allowlist_path("comments");
  write_file(p,
      "# operator-approved commands for observer.exec\n"
      "\n"
      "   # leading-whitespace comment\n"
      "/usr/bin/uptime\n"
      "\n"
      "/usr/bin/lsmod\n");
  auto al = ldb::observers::ExecAllowlist::from_file(p);
  REQUIRE(al.has_value());
  REQUIRE(al->pattern_count() == 2);
  REQUIRE(al->allows({"/usr/bin/uptime"}));
  REQUIRE(al->allows({"/usr/bin/lsmod"}));
  REQUIRE_FALSE(al->allows({"/usr/bin/cat"}));
}

TEST_CASE("ExecAllowlist::allows: anchoring — exact full-argv match required",
          "[observers][exec][allowlist]") {
  auto p = temp_allowlist_path("anchor");
  write_file(p, "/bin/sh\n");
  auto al = ldb::observers::ExecAllowlist::from_file(p);
  REQUIRE(al.has_value());
  // Exact match.
  REQUIRE(al->allows({"/bin/sh"}));
  // Anchored: extra args must NOT match a bare-program pattern.
  REQUIRE_FALSE(al->allows({"/bin/sh", "-c", "rm -rf /"}));
  // Substring is not enough.
  REQUIRE_FALSE(al->allows({"/usr/local/bin/sh"}));
}

TEST_CASE("ExecAllowlist::allows: glob '*' inside argv",
          "[observers][exec][allowlist]") {
  auto p = temp_allowlist_path("glob");
  write_file(p,
      "/usr/bin/systemctl status *\n"
      "ip addr show *\n");
  auto al = ldb::observers::ExecAllowlist::from_file(p);
  REQUIRE(al.has_value());
  REQUIRE(al->allows({"/usr/bin/systemctl", "status", "myunit"}));
  REQUIRE(al->allows({"/usr/bin/systemctl", "status", "another-unit.service"}));
  // Different verb → no match.
  REQUIRE_FALSE(al->allows({"/usr/bin/systemctl", "restart", "myunit"}));
  // ip addr show … OK
  REQUIRE(al->allows({"ip", "addr", "show", "eth0"}));
  REQUIRE_FALSE(al->allows({"ip", "addr", "del", "10.0.0.1/24"}));
}

TEST_CASE("ExecAllowlist::allows: FNM_PATHNAME blocks '*' from spanning '/'",
          "[observers][exec][allowlist]") {
  auto p = temp_allowlist_path("pathname");
  write_file(p, "/usr/bin/* hello\n");
  auto al = ldb::observers::ExecAllowlist::from_file(p);
  REQUIRE(al.has_value());
  REQUIRE(al->allows({"/usr/bin/echo", "hello"}));
  // '*' must not span the '/' between /usr and /bin/echo.
  REQUIRE_FALSE(al->allows({"/usr/local/bin/echo", "hello"}));
}

TEST_CASE("ExecAllowlist::allows: trailing whitespace stripped from patterns",
          "[observers][exec][allowlist]") {
  auto p = temp_allowlist_path("trailws");
  // Pattern has trailing spaces and \r — common when an operator drags
  // a file in from Windows. We strip both so the pattern matches the
  // command they typed.
  write_file(p, "/bin/echo hello   \r\n");
  auto al = ldb::observers::ExecAllowlist::from_file(p);
  REQUIRE(al.has_value());
  REQUIRE(al->allows({"/bin/echo", "hello"}));
}

TEST_CASE("ExecAllowlist::allows: empty argv never matches",
          "[observers][exec][allowlist]") {
  auto p = temp_allowlist_path("emptyargv");
  // Even a wildcard-everything pattern shouldn't allow empty-argv —
  // there's no command to run.
  write_file(p, "*\n");
  auto al = ldb::observers::ExecAllowlist::from_file(p);
  REQUIRE(al.has_value());
  REQUIRE_FALSE(al->allows({}));
}
