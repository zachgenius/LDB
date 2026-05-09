// SPDX-License-Identifier: Apache-2.0
// Pure-parser tests for ldb::observers (M4 part 3).
//
// These tests feed canned text fixtures (captured live on this Pop!_OS
// box at TDD time and committed under tests/fixtures/text/) through
// the parser entry points without any subprocess invocation. They
// guarantee the structured shape regardless of remote dispatch
// availability.
//
// Live local cases (using the current ldbd unit-test process's own
// /proc data) live in test_observers_live.cpp.

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

TEST_CASE("parse_proc_fds: well-formed find -printf output", "[observers][proc][fds]") {
  // Synthetic, mirrors the format produced by
  //   find /proc/PID/fd -mindepth 1 -maxdepth 1 -printf '%f %l\n'
  // (one entry per line, "fd target")
  std::string in =
      "0 /dev/null\n"
      "1 /tmp/ldbd.log\n"
      "2 /dev/null\n"
      "3 socket:[12345]\n"
      "4 pipe:[6789]\n"
      "5 anon_inode:[eventfd]\n"
      "10 /path with space/binary\n";

  auto r = ldb::observers::parse_proc_fds(in);
  REQUIRE(r.total == 7);
  REQUIRE(r.fds.size() == 7);

  CHECK(r.fds[0].fd == 0);
  CHECK(r.fds[0].target == "/dev/null");
  CHECK(r.fds[0].type == "file");

  CHECK(r.fds[3].fd == 3);
  CHECK(r.fds[3].target == "socket:[12345]");
  CHECK(r.fds[3].type == "socket");

  CHECK(r.fds[4].type == "pipe");
  CHECK(r.fds[5].type == "anon");

  CHECK(r.fds[6].fd == 10);
  CHECK(r.fds[6].target == "/path with space/binary");
  CHECK(r.fds[6].type == "file");
}

TEST_CASE("parse_proc_fds: real fixture from this host", "[observers][proc][fds]") {
  auto text = slurp(fixture_path("proc_fds_self.txt"));
  auto r = ldb::observers::parse_proc_fds(text);
  REQUIRE(r.total >= 1);  // at least stdout/stderr
  // Every entry should have a non-negative fd and non-empty target.
  for (const auto& e : r.fds) {
    CHECK(e.fd >= 0);
    CHECK(!e.target.empty());
    CHECK(!e.type.empty());
  }
}

TEST_CASE("parse_proc_fds: tolerates blank lines and bad entries",
          "[observers][proc][fds]") {
  // Blank lines / no-space-on-line entries should be skipped silently
  // (race: fd vanished between readdir and readlink → no target).
  std::string in =
      "\n"
      "5 /etc/hostname\n"
      "6\n"
      "  \n"
      "7 socket:[1]\n";
  auto r = ldb::observers::parse_proc_fds(in);
  REQUIRE(r.total == 2);
  CHECK(r.fds[0].fd == 5);
  CHECK(r.fds[1].fd == 7);
}


TEST_CASE("parse_proc_maps: well-formed cat /proc/PID/maps output",
          "[observers][proc][maps]") {
  std::string in =
      "5e9692cfa000-5e9692cfc000 r--p 00000000 103:03 73007242                  /usr/bin/cat\n"
      "5e96c124e000-5e96c126f000 rw-p 00000000 00:00 0                          [heap]\n"
      "7791b1a05000-7791b1a12000 rw-p 00000000 00:00 0 \n";

  auto r = ldb::observers::parse_proc_maps(in);
  REQUIRE(r.total == 3);

  const auto& a = r.regions[0];
  CHECK(a.start == 0x5e9692cfa000ULL);
  CHECK(a.end   == 0x5e9692cfc000ULL);
  CHECK(a.perm  == "r--p");
  CHECK(a.offset == 0);
  CHECK(a.dev == "103:03");
  CHECK(a.inode == 73007242ULL);
  REQUIRE(a.path.has_value());
  CHECK(*a.path == "/usr/bin/cat");

  CHECK(r.regions[1].path == std::optional<std::string>("[heap]"));
  CHECK(!r.regions[2].path.has_value());  // anonymous
}

TEST_CASE("parse_proc_maps: real fixture from this host", "[observers][proc][maps]") {
  auto text = slurp(fixture_path("proc_maps_self.txt"));
  auto r = ldb::observers::parse_proc_maps(text);
  REQUIRE(r.total > 5);
  // First region is always before the last in address order.
  CHECK(r.regions.front().start <= r.regions.back().start);
  // libc.so.6 should appear (we're on Linux x86_64).
  bool found_libc = false;
  for (const auto& reg : r.regions) {
    if (reg.path && reg.path->find("libc.so") != std::string::npos) {
      found_libc = true;
      break;
    }
  }
  CHECK(found_libc);
}

TEST_CASE("parse_proc_maps: path with whitespace survives", "[observers][proc][maps]") {
  // Rare but valid — the path field is everything after the inode column.
  std::string in =
      "00400000-00401000 r-xp 00000000 fd:01 12345                              /tmp/dir with spaces/bin\n";
  auto r = ldb::observers::parse_proc_maps(in);
  REQUIRE(r.total == 1);
  REQUIRE(r.regions[0].path.has_value());
  CHECK(*r.regions[0].path == "/tmp/dir with spaces/bin");
}


TEST_CASE("parse_proc_status: real systemd pid 1 fixture",
          "[observers][proc][status]") {
  auto text = slurp(fixture_path("proc_status_pid1.txt"));
  auto r = ldb::observers::parse_proc_status(text);

  CHECK(r.name == "systemd");
  REQUIRE(r.pid.has_value());
  CHECK(*r.pid == 1);
  REQUIRE(r.ppid.has_value());
  CHECK(*r.ppid == 0);
  CHECK(r.state.find("sleeping") != std::string::npos);
  REQUIRE(r.uid.has_value());
  CHECK(*r.uid == 0u);
  REQUIRE(r.threads.has_value());
  CHECK(*r.threads == 1u);
  REQUIRE(r.vm_rss_kb.has_value());
  CHECK(*r.vm_rss_kb > 0);
  CHECK(!r.raw_fields.empty());
}

TEST_CASE("parse_proc_status: zombie still parses", "[observers][proc][status]") {
  std::string in =
      "Name:\tdefunct\n"
      "State:\tZ (zombie)\n"
      "Tgid:\t12345\n"
      "Pid:\t12345\n"
      "PPid:\t1\n"
      "Threads:\t1\n";
  auto r = ldb::observers::parse_proc_status(in);
  CHECK(r.name == "defunct");
  CHECK(r.state.find("zombie") != std::string::npos);
  REQUIRE(r.pid.has_value());
  CHECK(*r.pid == 12345);
  CHECK(!r.vm_rss_kb.has_value());  // zombie has no rss
}


TEST_CASE("parse_ss_tunap: well-formed `ss -tunap` output",
          "[observers][net][sockets]") {
  std::string in =
      "Netid State  Recv-Q Send-Q                Local Address:Port    Peer Address:Port Process\n"
      "tcp   LISTEN 0      4096                       0.0.0.0:22           0.0.0.0:*\n"
      "tcp   LISTEN 0      1                          0.0.0.0:52301        0.0.0.0:*     users:((\"nc\",pid=287663,fd=3))\n"
      "udp   UNCONN 0      0                          127.0.0.1:323        0.0.0.0:*\n"
      "tcp   ESTAB  0      0                  192.168.0.1:22       192.168.0.2:59042\n";

  auto r = ldb::observers::parse_ss_tunap(in);
  REQUIRE(r.total == 4);

  CHECK(r.sockets[0].proto == "tcp");
  CHECK(r.sockets[0].state == "LISTEN");
  CHECK(r.sockets[0].local == "0.0.0.0:22");
  CHECK(r.sockets[0].peer  == "0.0.0.0:*");
  CHECK(!r.sockets[0].pid.has_value());

  CHECK(r.sockets[1].proto == "tcp");
  CHECK(r.sockets[1].local == "0.0.0.0:52301");
  REQUIRE(r.sockets[1].pid.has_value());
  CHECK(*r.sockets[1].pid == 287663);
  REQUIRE(r.sockets[1].comm.has_value());
  CHECK(*r.sockets[1].comm == "nc");
  REQUIRE(r.sockets[1].fd.has_value());
  CHECK(*r.sockets[1].fd == 3);

  CHECK(r.sockets[2].proto == "udp");
  CHECK(r.sockets[3].state == "ESTAB");
}

TEST_CASE("parse_ss_tunap: real fixture from this host", "[observers][net][sockets]") {
  auto text = slurp(fixture_path("ss_tunap.txt"));
  auto r = ldb::observers::parse_ss_tunap(text);
  REQUIRE(r.total > 5);
  // Every socket must have proto + local. Some won't have peer (uncommon)
  // but in `ss -tunap` they always do.
  bool any_with_users = false;
  for (const auto& s : r.sockets) {
    CHECK((s.proto == "tcp" || s.proto == "udp"));
    CHECK(!s.local.empty());
    CHECK(!s.peer.empty());
    CHECK(!s.state.empty());
    if (s.pid.has_value()) any_with_users = true;
  }
  CHECK(any_with_users);
}

TEST_CASE("parse_ss_tunap: tolerates header-only output",
          "[observers][net][sockets]") {
  // Some hosts print only the header line if there are no sockets.
  std::string in =
      "Netid State Recv-Q Send-Q   Local Address:Port    Peer Address:Port Process\n";
  auto r = ldb::observers::parse_ss_tunap(in);
  CHECK(r.total == 0);
  CHECK(r.sockets.empty());
}
