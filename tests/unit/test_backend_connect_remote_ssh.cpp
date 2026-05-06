// Tests for target.connect_remote_ssh — end-to-end remote debugging
// over an SSH-tunneled lldb-server (M4 part 2, plan §9).
//
// Strategy: a single ssh subprocess does both `-L LOCAL:127.0.0.1:RPORT`
// AND runs `lldb-server gdbserver 127.0.0.1:RPORT -- <inferior>` on the
// remote. We then drive the existing connect_remote_target against
// 127.0.0.1:LOCAL.
//
// The endpoint is registered on the dispatcher (see test_dispatcher_*),
// but the live e2e flow lives here so the backend-level resource
// bookkeeping (per-target SSH tunnel handle) is the unit under test.
//
// Negative cases run unconditionally. The live case is gated on:
//   1. ssh_probe(localhost, 1s) passing.
//   2. lldb-server discoverable at LDB_LLDB_SERVER_PATH or on PATH.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"
#include "transport/ssh.h"

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/stat.h>

using ldb::backend::ConnectRemoteSshOptions;
using ldb::backend::LldbBackend;
using ldb::backend::ProcessState;
using ldb::transport::ssh_probe;
using ldb::transport::SshHost;
using namespace std::chrono_literals;

namespace {

constexpr const char* kSleeperPath = LDB_FIXTURE_SLEEPER_PATH;

#ifndef LDB_LLDB_SERVER_PATH
#define LDB_LLDB_SERVER_PATH ""
#endif

bool local_sshd_available() {
  SshHost h;
  h.host = "localhost";
  return ssh_probe(h, 1s).ok;
}

std::string find_lldb_server() {
  if (const char* env = std::getenv("LDB_LLDB_SERVER"); env && env[0]) {
    struct stat st;
    if (::stat(env, &st) == 0 && (st.st_mode & S_IXUSR)) return env;
  }
  if (std::strlen(LDB_LLDB_SERVER_PATH) > 0) {
    struct stat st;
    if (::stat(LDB_LLDB_SERVER_PATH, &st) == 0 && (st.st_mode & S_IXUSR)) {
      return LDB_LLDB_SERVER_PATH;
    }
  }
  return {};
}

}  // namespace

TEST_CASE("target.connect_remote_ssh: bogus host throws backend::Error",
          "[backend][connect_remote_ssh][error]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->create_empty_target();
  REQUIRE(open.target_id != 0);

  ConnectRemoteSshOptions opts;
  opts.host          = "nosuchhost.invalid";
  opts.ssh_options   = {"-o", "ConnectTimeout=1"};
  opts.inferior_path = "/bin/true";  // never reached
  opts.setup_timeout = 5s;

  CHECK_THROWS_AS(
      be->connect_remote_target_ssh(open.target_id, opts),
      ldb::backend::Error);
}

TEST_CASE("target.connect_remote_ssh: empty inferior_path rejected",
          "[backend][connect_remote_ssh][error]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->create_empty_target();
  REQUIRE(open.target_id != 0);

  ConnectRemoteSshOptions opts;
  opts.host          = "localhost";
  // inferior_path intentionally empty — should be rejected fast.

  CHECK_THROWS_AS(
      be->connect_remote_target_ssh(open.target_id, opts),
      ldb::backend::Error);
}

TEST_CASE("target.connect_remote_ssh: bad target_id throws",
          "[backend][connect_remote_ssh][error]") {
  auto be = std::make_unique<LldbBackend>();
  ConnectRemoteSshOptions opts;
  opts.host          = "localhost";
  opts.inferior_path = "/bin/true";
  CHECK_THROWS_AS(
      be->connect_remote_target_ssh(/*tid=*/9999, opts),
      ldb::backend::Error);
}

TEST_CASE("target.connect_remote_ssh: end-to-end against localhost",
          "[backend][connect_remote_ssh][live][requires_local_sshd]") {
  if (!local_sshd_available()) {
    SKIP("local sshd not configured for key-based passwordless auth");
  }
  std::string server = find_lldb_server();
  if (server.empty()) {
    SKIP("lldb-server not found (set LDB_LLDB_SERVER or install Homebrew LLVM)");
  }

  auto be = std::make_unique<LldbBackend>();
  auto open = be->create_empty_target();
  REQUIRE(open.target_id != 0);

  ConnectRemoteSshOptions opts;
  opts.host                = "localhost";
  opts.remote_lldb_server  = server;
  opts.inferior_path       = kSleeperPath;
  opts.setup_timeout       = 10s;

  auto result = be->connect_remote_target_ssh(open.target_id, opts);

  CHECK((result.status.state == ProcessState::kStopped ||
         result.status.state == ProcessState::kRunning));
  CHECK(result.status.pid > 0);
  CHECK(result.local_tunnel_port > 0);

  // Detach to release the remote inferior. The tunnel handle stays
  // attached to the target until close_target / kill / detach tear
  // down — we exercise close_target via the LldbBackend dtor.
  auto det = be->detach_process(open.target_id);
  CHECK((det.state == ProcessState::kDetached ||
         det.state == ProcessState::kNone ||
         det.state == ProcessState::kExited));
}
