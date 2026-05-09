// SPDX-License-Identifier: Apache-2.0
// Unit tests for ldb::transport::SshTunneledCommand — single ssh
// subprocess that holds a -L port forward AND runs a remote foreground
// command (M4-2 building block for `target.connect_remote_ssh`).
//
// Architectural shape:
//
//   ldbd ──ssh──► remote: <command on $REMOTE_PORT>
//   <local_port>──ssh -L──> 127.0.0.1:<remote_port>
//
// The ssh client gets a single subprocess that does both: when we tear
// it down (RAII), the remote command dies via SIGHUP and the forward
// goes with it. Single PID, single failure surface.
//
// Test gating:
//   [transport][ssh_tun][error] — error paths that don't need a working
//                                 remote.
//   [transport][ssh_tun][live][requires_local_sshd] — needs passwordless
//                                 ssh-to-localhost. SKIP cleanly when
//                                 not configured.

#include <catch_amalgamated.hpp>

#include "transport/ssh.h"

#include "backend/debugger_backend.h"  // backend::Error

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using ldb::transport::pick_remote_free_port;
using ldb::transport::ssh_probe;
using ldb::transport::SshHost;
using ldb::transport::SshTunneledCommand;

namespace {

SshHost local_host() {
  SshHost h;
  h.host = "localhost";
  return h;
}

bool local_sshd_available() {
  return ssh_probe(local_host(), 1s).ok;
}

}  // namespace

TEST_CASE("pick_remote_free_port returns a port from a reachable host",
          "[transport][ssh_tun][live][requires_local_sshd]") {
  if (!local_sshd_available()) {
    SKIP("local sshd not configured for key-based passwordless auth");
  }
  auto p = pick_remote_free_port(local_host(), 5s);
  REQUIRE(p > 0);
  REQUIRE(p < 65536);
}

TEST_CASE("pick_remote_free_port surfaces a clear error on bad host",
          "[transport][ssh_tun][error]") {
  SshHost h;
  h.host = "nosuchhost.invalid";
  h.ssh_options = {"-o", "ConnectTimeout=1"};
  CHECK_THROWS_AS(pick_remote_free_port(h, 3s), ldb::backend::Error);
}

TEST_CASE("SshTunneledCommand exposes a usable local TCP endpoint",
          "[transport][ssh_tun][live][requires_local_sshd]") {
  if (!local_sshd_available()) {
    SKIP("local sshd not configured for key-based passwordless auth");
  }

  // Run `nc -l <port>` on the remote so we have a long-lived TCP
  // listener. nc is on every Linux distro and on macOS. Pick a remote
  // port via the helper. nc-traditional and nc-openbsd both honor the
  // form `nc -l <port>`. Use `bash -c` so we can set up a "send a
  // sentinel and exit" responder.
  std::uint16_t remote_port = pick_remote_free_port(local_host(), 5s);
  REQUIRE(remote_port > 0);

  // Multi-accept TCP echo via Python — bound to ~5 connections so we
  // don't have a fork-bomb if the test hangs. Each accept sends the
  // payload immediately. The setup probe consumes the first
  // connection; the test consumes the second.
  //
  // Why python3 over `nc`: nc-traditional and nc-openbsd diverge on
  // -l semantics; nc-openbsd's `-l <port>` exits after the first
  // accept-then-EOF, which races with our probe. Python's socket loop
  // is uniform.
  std::string py = "import socket;"
                   "s=socket.socket();"
                   "s.bind(('127.0.0.1'," + std::to_string(remote_port) + "));"
                   "s.listen(8);"
                   "[ (lambda c: (c.sendall(b'tunneled-payload\\n'),"
                   " __import__('time').sleep(0.5), c.close()))(s.accept()[0])"
                   " for _ in range(5) ]";
  std::vector<std::string> remote_cmd = {"python3", "-c", py};

  SshTunneledCommand tun(local_host(),
                         /*local_port=*/0,
                         remote_port,
                         remote_cmd,
                         /*setup_timeout=*/5s);
  REQUIRE(tun.alive());
  REQUIRE(tun.local_port() != 0);
  REQUIRE(tun.remote_port() == remote_port);

  // Connect through the tunnel to the remote nc.
  int s = ::socket(AF_INET, SOCK_STREAM, 0);
  REQUIRE(s >= 0);
  sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_port = htons(tun.local_port());
  // Connect may fail if the nc has not started listening yet — retry
  // briefly. The ssh tunnel handshake completes faster than nc binds.
  bool connected = false;
  auto deadline = std::chrono::steady_clock::now() + 3s;
  while (std::chrono::steady_clock::now() < deadline) {
    if (::connect(s, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == 0) {
      connected = true;
      break;
    }
    ::close(s);
    s = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(s >= 0);
    std::this_thread::sleep_for(50ms);
  }
  REQUIRE(connected);

  std::string buf;
  buf.resize(64);
  ssize_t got = ::recv(s, buf.data(), buf.size(), 0);
  ::close(s);
  REQUIRE(got > 0);
  buf.resize(static_cast<std::size_t>(got));
  REQUIRE(buf.find("tunneled-payload") != std::string::npos);
}

TEST_CASE("SshTunneledCommand throws when the remote command fails fast",
          "[transport][ssh_tun][live][requires_local_sshd]") {
  if (!local_sshd_available()) {
    SKIP("local sshd not configured for key-based passwordless auth");
  }

  // Pick a real free remote port, but run a command that never binds
  // it. The setup probe will keep retrying TCP connect; we want it to
  // give up at the deadline and throw rather than hanging.
  std::uint16_t remote_port = pick_remote_free_port(local_host(), 5s);
  REQUIRE(remote_port > 0);

  // sleep — keeps ssh alive but never opens the tunneled port.
  std::vector<std::string> remote_cmd = {"/bin/sleep", "10"};

  auto t0 = std::chrono::steady_clock::now();
  CHECK_THROWS_AS(
      SshTunneledCommand(local_host(), /*local_port=*/0, remote_port,
                         remote_cmd, /*setup_timeout=*/750ms),
      ldb::backend::Error);
  auto elapsed = std::chrono::steady_clock::now() - t0;
  // 750ms setup + ~250ms SIGTERM grace + slack.
  REQUIRE(elapsed < 3s);
}

TEST_CASE("SshTunneledCommand cleans up on RAII teardown",
          "[transport][ssh_tun][live][requires_local_sshd]") {
  if (!local_sshd_available()) {
    SKIP("local sshd not configured for key-based passwordless auth");
  }

  std::uint16_t remote_port = pick_remote_free_port(local_host(), 5s);
  REQUIRE(remote_port > 0);

  std::string py = "import socket,time;"
                   "s=socket.socket();"
                   "s.bind(('127.0.0.1'," + std::to_string(remote_port) + "));"
                   "s.listen(4);"
                   "time.sleep(30)";
  std::vector<std::string> remote_cmd = {"python3", "-c", py};

  std::uint16_t local_port = 0;
  {
    SshTunneledCommand tun(local_host(),
                           /*local_port=*/0,
                           remote_port,
                           remote_cmd,
                           /*setup_timeout=*/5s);
    REQUIRE(tun.alive());
    local_port = tun.local_port();
    REQUIRE(local_port != 0);
  }
  // After teardown, the local forward port should no longer accept
  // connections. Give the kernel a tick to actually close.
  std::this_thread::sleep_for(200ms);
  int s = ::socket(AF_INET, SOCK_STREAM, 0);
  REQUIRE(s >= 0);
  sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_port = htons(local_port);
  int rc = ::connect(s, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
  ::close(s);
  REQUIRE(rc != 0);
}
