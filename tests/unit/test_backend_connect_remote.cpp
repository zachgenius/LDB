// SPDX-License-Identifier: Apache-2.0
// Tests for target.connect_remote — connect to a remote lldb-server (or
// gdbserver / debugserver) over its gdb-remote-protocol port.
//
// Negative cases are always exercised:
//   * bogus URL (port with nothing listening) → backend::Error promptly.
//   * malformed URL → backend::Error.
//
// The positive case spawns lldb-server gdbserver against the sleeper
// fixture on a chosen port (port 0 → kernel-allocated). The sleeper is
// long-running so we don't race with the inferior exiting before we
// finish ConnectRemote — which is what happened with the structs
// fixture (~1ms execution time) and made state=kExited the typical
// post-connect observation. It's gated on the discovery of an
// lldb-server binary at:
//   1. ${LDB_LLDB_SERVER_PATH} (CMake-baked, from LDB_LLDB_ROOT)
//   2. $LDB_LLDB_SERVER (env override)
//   3. lldb-server on PATH
// If none found, SKIP the case at runtime so the suite remains green
// on dev boxes that don't ship lldb-server.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"

#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

using ldb::backend::LldbBackend;
using ldb::backend::ProcessState;

namespace {

constexpr const char* kStructsPath  = LDB_FIXTURE_STRUCTS_PATH;
constexpr const char* kSleeperPath  = LDB_FIXTURE_SLEEPER_PATH;

#ifndef LDB_LLDB_SERVER_PATH
#define LDB_LLDB_SERVER_PATH ""
#endif

// Resolve an lldb-server binary, in priority order. Returns empty string
// if nothing is available; caller SKIPs the test in that case.
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
  // PATH lookup via popen("which") — cheap and avoids dragging in a
  // PATH-walker just for this test.
  if (FILE* p = ::popen("command -v lldb-server 2>/dev/null", "r"); p) {
    char buf[4096] = {0};
    char* got = std::fgets(buf, sizeof(buf), p);
    ::pclose(p);
    if (got) {
      std::string s(buf);
      while (!s.empty() && (s.back() == '\n' || s.back() == '\r' ||
                            s.back() == ' ')) {
        s.pop_back();
      }
      if (!s.empty()) {
        struct stat st;
        if (::stat(s.c_str(), &st) == 0 && (st.st_mode & S_IXUSR)) return s;
      }
    }
  }
  return {};
}

// A spawned lldb-server gdbserver child. Listens on 127.0.0.1:<port>
// chosen by the kernel (port 0). The chosen port is communicated back
// via a pipe (--pipe <fd>) the kernel writes the chosen port to.
struct SpawnedServer {
  pid_t       pid          = -1;
  std::uint16_t port       = 0;
  ~SpawnedServer() {
    if (pid > 0) {
      ::kill(pid, SIGTERM);
      // Best-effort wait so lldb-server cleans up its inferior; bound it.
      for (int i = 0; i < 20; ++i) {
        int st = 0;
        pid_t r = ::waitpid(pid, &st, WNOHANG);
        if (r == pid || r < 0) return;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
      }
      ::kill(pid, SIGKILL);
      int st = 0;
      ::waitpid(pid, &st, 0);
    }
  }
};

// Spawn `lldb-server gdbserver 127.0.0.1:0 -- <fixture>`. Returns nullptr
// on spawn failure. The caller asserts pid>0 before using.
//
// We use --pipe <fd> so the server writes its chosen port into a
// pipe we read here; that's the sanctioned way to get a kernel-
// allocated port.
std::unique_ptr<SpawnedServer> spawn_gdbserver(const std::string& server) {
  int port_pipe[2];
  if (::pipe(port_pipe) != 0) return nullptr;

  pid_t child = ::fork();
  if (child < 0) {
    ::close(port_pipe[0]);
    ::close(port_pipe[1]);
    return nullptr;
  }

  if (child == 0) {
    // Child: keep write end open at a known fd. Inherit it across exec
    // by clearing FD_CLOEXEC.
    ::close(port_pipe[0]);
    int wfd = port_pipe[1];
    int flags = ::fcntl(wfd, F_GETFD);
    if (flags >= 0) ::fcntl(wfd, F_SETFD, flags & ~FD_CLOEXEC);

    // Quiet diagnostics so they don't confuse other tests.
    int devnull = ::open("/dev/null", O_RDWR);
    if (devnull >= 0) {
      ::dup2(devnull, STDIN_FILENO);
      ::dup2(devnull, STDERR_FILENO);
      ::close(devnull);
    }

    char pipe_arg[16];
    std::snprintf(pipe_arg, sizeof(pipe_arg), "%d", wfd);

    std::vector<const char*> argv;
    argv.push_back(server.c_str());
    argv.push_back("gdbserver");
    argv.push_back("--pipe");
    argv.push_back(pipe_arg);
    argv.push_back("127.0.0.1:0");
    argv.push_back("--");
    argv.push_back(kSleeperPath);
    argv.push_back(nullptr);

    ::execv(server.c_str(),
            const_cast<char* const*>(
                reinterpret_cast<const char* const*>(argv.data())));
    _exit(127);
  }

  ::close(port_pipe[1]);

  // Read the port: lldb-server writes a binary little-endian uint16 on
  // some versions, an ASCII decimal on others. Accept either.
  auto out = std::make_unique<SpawnedServer>();
  out->pid = child;

  char buf[64] = {0};
  ssize_t total = 0;
  // Bound the read with a deadline so a misbehaving server can't hang
  // the test.
  auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  bool got = false;
  while (std::chrono::steady_clock::now() < deadline &&
         total < static_cast<ssize_t>(sizeof(buf) - 1)) {
    // Make the read non-blocking-ish via select.
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(port_pipe[0], &rfds);
    timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = 100 * 1000;  // 100ms
    int r = ::select(port_pipe[0] + 1, &rfds, nullptr, nullptr, &tv);
    if (r > 0) {
      ssize_t n = ::read(port_pipe[0], buf + total, sizeof(buf) - 1 - static_cast<size_t>(total));
      if (n > 0) {
        total += n;
        // ASCII decimal terminated by newline?
        if (std::memchr(buf, '\n', static_cast<size_t>(total))) { got = true; break; }
        // Or 2 bytes binary little-endian?
        if (total >= 2) { got = true; break; }
      } else if (n == 0) {
        break;  // EOF
      }
    } else if (r < 0) {
      break;
    }
  }
  ::close(port_pipe[0]);

  if (!got) return out;  // pid still set; caller checks port>0.

  // Try ASCII decimal first.
  unsigned int port_ascii = 0;
  if (std::sscanf(buf, "%u", &port_ascii) == 1 && port_ascii > 0 &&
      port_ascii < 65536) {
    out->port = static_cast<std::uint16_t>(port_ascii);
    return out;
  }
  // Fall back to binary LE uint16.
  if (total >= 2) {
    auto p = reinterpret_cast<unsigned char*>(buf);
    out->port = static_cast<std::uint16_t>(p[0] | (p[1] << 8));
  }
  return out;
}

}  // namespace

TEST_CASE("target.connect_remote: bogus URL throws promptly",
          "[backend][connect_remote][error]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->create_empty_target();
  REQUIRE(open.target_id != 0);

  // 127.0.0.1 port 1 is reserved (tcpmux) and on macOS / typical Linux
  // is unbound; ConnectRemote should fail (RST or refused) within a
  // few seconds. Bound the wall clock so a hang surfaces as a test
  // failure, not a CTest timeout.
  auto t0 = std::chrono::steady_clock::now();
  CHECK_THROWS_AS(
      be->connect_remote_target(open.target_id, "connect://127.0.0.1:1", ""),
      ldb::backend::Error);
  auto elapsed = std::chrono::steady_clock::now() - t0;
  CHECK(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() < 15);
}

TEST_CASE("target.connect_remote: malformed URL throws",
          "[backend][connect_remote][error]") {
  auto be = std::make_unique<LldbBackend>();
  auto open = be->create_empty_target();
  REQUIRE(open.target_id != 0);

  // Empty URL — invalid by construction. Must surface as backend::Error
  // (not crash, not silently succeed).
  CHECK_THROWS_AS(
      be->connect_remote_target(open.target_id, "", ""),
      ldb::backend::Error);
}

TEST_CASE("target.connect_remote: invalid target_id throws",
          "[backend][connect_remote][error]") {
  auto be = std::make_unique<LldbBackend>();
  CHECK_THROWS_AS(
      be->connect_remote_target(/*tid=*/9999, "connect://127.0.0.1:1234", ""),
      ldb::backend::Error);
}

TEST_CASE("target.connect_remote: connects to lldb-server gdbserver",
          "[backend][connect_remote][live][requires_lldb_server]") {
  std::string server = find_lldb_server();
  if (server.empty()) {
    SKIP("lldb-server not found (set LDB_LLDB_SERVER, install Homebrew LLVM, "
         "or place lldb-server on PATH)");
  }

  auto srv = spawn_gdbserver(server);
  REQUIRE(srv != nullptr);
  REQUIRE(srv->pid > 0);

  // If the server died on us (e.g. Homebrew LLVM's lldb-server crashes
  // on macOS arm64 because it can't find a debug-server underneath),
  // SKIP rather than attempt a connect to a defunct port.
  {
    int st = 0;
    pid_t r = ::waitpid(srv->pid, &st, WNOHANG);
    if (r == srv->pid) {
      srv->pid = -1;
      SKIP("lldb-server child exited before we could connect (likely "
           "crashed on this platform — see Homebrew LLVM bugs for "
           "macOS arm64 lldb-server)");
    }
  }

  if (srv->port == 0) {
    SKIP("could not parse port from lldb-server --pipe output (server "
         "probably doesn't support that mechanism on this platform)");
  }

  auto be = std::make_unique<LldbBackend>();
  auto open = be->create_empty_target();
  REQUIRE(open.target_id != 0);

  std::string url = "connect://127.0.0.1:" + std::to_string(srv->port);
  // gdb-remote plugin (default) handles lldb-server gdbserver.
  auto status = be->connect_remote_target(open.target_id, url, "");
  // After ConnectRemote against an lldb-server gdbserver that has a
  // launched-but-stopped inferior, state is typically kStopped. Some
  // servers leave it in kRunning until a continue/halt is issued.
  // The backend pumps the listener until state settles out of
  // eStateInvalid (see connect_remote_target impl), so we should see a
  // real state here.
  CHECK((status.state == ProcessState::kStopped ||
         status.state == ProcessState::kRunning));
  CHECK(status.pid >= 0);

  // Detach to release the remote inferior; the server child terminates
  // when its inferior is gone.
  auto det = be->detach_process(open.target_id);
  CHECK((det.state == ProcessState::kDetached ||
         det.state == ProcessState::kNone ||
         det.state == ProcessState::kExited));
}
