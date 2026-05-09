// SPDX-License-Identifier: Apache-2.0
// Unit tests for ldb::transport::ssh — SSH transport primitive (M4-1).
//
// Surface under test (per docs/02-ldb-mvp-plan.md §9):
//
//   • ssh_exec(host, argv, opts)  → spawn ssh, run argv, capture stdio
//   • ssh_probe(host, timeout)    → cheap reachability check
//   • SshPortForward              → -N -L tunnel, RAII teardown
//
// This is an INTERNAL C++ primitive. It is NOT a JSON-RPC endpoint —
// `ssh_exec` is unbounded code execution and §4.6 puts only narrow
// allow-listed observers on the wire. Callers in M4-2 (target.connect_
// remote_ssh) and M4-3 (typed observers) consume this directly.
//
// Test gating:
//
//   [transport][ssh][error]   — error paths that don't need a working
//                               remote (binary missing, bogus host).
//   [transport][ssh][timeout] — deadline-driven cancellation.
//   [transport][ssh][probe]   — ssh_probe negative path.
//   [transport][ssh][live][requires_local_sshd]
//                             — needs passwordless ssh to localhost. We
//                               GATE on `ssh_probe(localhost, 1s)` and
//                               SKIP cleanly when not configured (do NOT
//                               weaken the assertion). Set up via
//                               `ssh-keygen -t ed25519 -f /tmp/ldb-ssh &&
//                               cat /tmp/ldb-ssh.pub >> ~/.ssh/authorized_keys`.

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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using ldb::transport::ExecOptions;
using ldb::transport::ExecResult;
using ldb::transport::ReachabilityResult;
using ldb::transport::ssh_exec;
using ldb::transport::ssh_probe;
using ldb::transport::SshHost;
using ldb::transport::SshPortForward;

namespace {

// Resolves a host that the network stack is guaranteed to reject quickly.
// We use ".invalid" (RFC 6761) — DNS will fail or NXDOMAIN immediately.
SshHost bogus_host() {
  SshHost h;
  h.host = "nosuchhost.invalid";
  // Force a tight ssh-side connect timeout so the error path returns
  // promptly even when the test's own deadline isn't exercised.
  h.ssh_options = {"-o", "ConnectTimeout=1"};
  return h;
}

SshHost local_host() {
  SshHost h;
  h.host = "localhost";
  return h;
}

// Tiny scoped TCP listener used by the port-forward end-to-end test.
// Binds 127.0.0.1:0, accepts up to N connections, sends a fixed payload
// on each, closes the conn, loops. The "up to N" matters because
// SshPortForward's setup polls with a TCP connect against the local
// forward — that probe connection gets forwarded all the way to this
// server, so we must accept it and the test connection.
//
// The worker thread polls listen_fd with a short timeout so we can stop
// it cleanly via the `stop` flag from the destructor — close() of the
// listen fd from another thread is enough on Linux to wake accept(),
// but it is not portable. The poll-based loop keeps the test boring.
struct EchoServer {
  int                 listen_fd = -1;
  std::uint16_t       port      = 0;
  std::thread         worker;
  std::string         sent;
  std::atomic<bool>   stop{false};

  explicit EchoServer(std::string payload) : sent(std::move(payload)) {
    listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(listen_fd >= 0);
    int one = 1;
    ::setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    REQUIRE(::bind(listen_fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == 0);
    socklen_t sl = sizeof(sa);
    REQUIRE(::getsockname(listen_fd, reinterpret_cast<sockaddr*>(&sa), &sl) == 0);
    port = ntohs(sa.sin_port);
    REQUIRE(::listen(listen_fd, 4) == 0);

    worker = std::thread([this]() {
      while (!stop.load(std::memory_order_relaxed)) {
        pollfd p{};
        p.fd = listen_fd;
        p.events = POLLIN;
        int pr = ::poll(&p, 1, 100);
        if (pr <= 0) continue;
        sockaddr_in peer{};
        socklen_t pl = sizeof(peer);
        int c = ::accept(listen_fd, reinterpret_cast<sockaddr*>(&peer), &pl);
        if (c < 0) continue;
        ssize_t n = ::send(c, sent.data(), sent.size(), 0);
        (void)n;
        ::shutdown(c, SHUT_RDWR);
        ::close(c);
      }
    });
  }

  ~EchoServer() {
    stop.store(true, std::memory_order_relaxed);
    if (worker.joinable()) worker.join();
    if (listen_fd >= 0) {
      ::close(listen_fd);
      listen_fd = -1;
    }
  }
};

bool local_sshd_available() {
  auto r = ssh_probe(local_host(), 1s);
  return r.ok;
}

}  // namespace

TEST_CASE("ssh_exec rejects a bogus host with a non-zero exit",
          "[transport][ssh][error]") {
  // We deliberately do NOT throw on remote-side failures (see header
  // contract). A name-resolution failure surfaces as ssh's exit_code=255
  // and a non-empty stderr. The test must NOT take more than a couple of
  // seconds — ConnectTimeout=1 in the host's ssh_options keeps it tight.
  ExecOptions opts;
  opts.timeout = 5s;
  auto r = ssh_exec(bogus_host(), {"echo", "hi"}, opts);
  REQUIRE_FALSE(r.timed_out);
  REQUIRE(r.exit_code != 0);
  REQUIRE(!r.stderr_data.empty());
}

TEST_CASE("ssh_exec honors timeout and reaps the child",
          "[transport][ssh][timeout]") {
  // We need a host that ssh won't resolve to NXDOMAIN (which would
  // return fast). 192.0.2.1 is RFC 5737 TEST-NET-1 — guaranteed
  // unroutable. ssh will sit in connect() until ConnectTimeout=10s
  // expires; we cancel after 200ms via our own deadline. Total bound:
  // ~700ms (200ms wait + 250ms SIGTERM grace + 250ms slack).
  SshHost h;
  h.host = "192.0.2.1";
  h.ssh_options = {"-o", "ConnectTimeout=10"};

  ExecOptions opts;
  opts.timeout = 200ms;

  auto t0 = std::chrono::steady_clock::now();
  auto r = ssh_exec(h, {"echo", "hi"}, opts);
  auto elapsed = std::chrono::steady_clock::now() - t0;

  REQUIRE(r.timed_out);
  REQUIRE(elapsed < 1500ms);
}

TEST_CASE("ssh_probe returns ok=false with detail for a bogus host",
          "[transport][ssh][probe]") {
  auto r = ssh_probe(bogus_host(), 1500ms);
  REQUIRE_FALSE(r.ok);
  REQUIRE_FALSE(r.detail.empty());
}

TEST_CASE("ssh_exec runs against localhost when sshd is configured",
          "[transport][ssh][live][requires_local_sshd]") {
  if (!local_sshd_available()) {
    SKIP("local sshd not configured for key-based passwordless auth — "
         "set up ssh-keygen + ~/.ssh/authorized_keys to enable");
  }

  auto r = ssh_exec(local_host(), {"/bin/echo", "hello-from-ldb"});
  REQUIRE(r.exit_code == 0);
  REQUIRE_FALSE(r.timed_out);
  // Some SSH server configs trail with \r\n; tolerate either.
  REQUIRE(r.stdout_data.find("hello-from-ldb") != std::string::npos);
}

TEST_CASE("ssh_exec stdout cap truncates without throwing",
          "[transport][ssh][live][requires_local_sshd]") {
  if (!local_sshd_available()) {
    SKIP("local sshd not configured for key-based passwordless auth — "
         "set up ssh-keygen + ~/.ssh/authorized_keys to enable");
  }

  ExecOptions opts;
  opts.stdout_cap = 1024;
  // Generate ~64 KiB of output; cap to 1 KiB.
  auto r = ssh_exec(local_host(),
                    {"/bin/sh", "-c", "yes | head -c 65536"},
                    opts);
  REQUIRE(r.exit_code == 0);
  REQUIRE(r.stdout_truncated);
  REQUIRE(r.stdout_data.size() == 1024);
}

TEST_CASE("ssh_exec captures non-zero exit code from remote command",
          "[transport][ssh][live][requires_local_sshd]") {
  if (!local_sshd_available()) {
    SKIP("local sshd not configured for key-based passwordless auth — "
         "set up ssh-keygen + ~/.ssh/authorized_keys to enable");
  }

  auto r = ssh_exec(local_host(), {"/bin/sh", "-c", "exit 7"});
  REQUIRE(r.exit_code == 7);
  REQUIRE_FALSE(r.timed_out);
}

TEST_CASE("SshPortForward tunnels bytes from local to remote",
          "[transport][ssh][live][requires_local_sshd]") {
  if (!local_sshd_available()) {
    SKIP("local sshd not configured for key-based passwordless auth — "
         "set up ssh-keygen + ~/.ssh/authorized_keys to enable");
  }

  const std::string payload = "ldb-port-forward-payload\n";
  EchoServer srv(payload);

  // Forward a kernel-assigned local port to the EchoServer running on
  // 127.0.0.1:srv.port on the "remote" (= localhost in this test).
  SshPortForward fwd(local_host(),
                     /*local_port=*/0,
                     /*remote_port=*/srv.port,
                     /*setup_timeout=*/3s);
  REQUIRE(fwd.alive());
  REQUIRE(fwd.local_port() != 0);

  // Connect to the forward.
  int s = ::socket(AF_INET, SOCK_STREAM, 0);
  REQUIRE(s >= 0);
  sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_port = htons(fwd.local_port());
  REQUIRE(::connect(s, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == 0);

  std::string buf;
  buf.resize(payload.size());
  ssize_t got = 0;
  while (got < static_cast<ssize_t>(buf.size())) {
    ssize_t n = ::recv(s, buf.data() + got, buf.size() - static_cast<std::size_t>(got), 0);
    if (n <= 0) break;
    got += n;
  }
  ::close(s);

  REQUIRE(got == static_cast<ssize_t>(payload.size()));
  REQUIRE(buf == payload);
}
