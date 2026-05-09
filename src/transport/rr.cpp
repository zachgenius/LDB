// SPDX-License-Identifier: Apache-2.0
#include "transport/rr.h"

#include "backend/debugger_backend.h"  // backend::Error

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <spawn.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

extern char** environ;

namespace ldb::backend { class Error; }  // forward — full def via header

namespace ldb::transport {

namespace {

bool is_executable(const char* path) {
  if (!path || !*path) return false;
  struct stat st;
  if (::stat(path, &st) != 0) return false;
  if (!S_ISREG(st.st_mode)) return false;
  return ::access(path, X_OK) == 0;
}

void close_safely(int& fd) {
  if (fd >= 0) {
    ::close(fd);
    fd = -1;
  }
}

bool try_connect_local(std::uint16_t port) {
  int s = ::socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) return false;
  sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_port = htons(port);
  bool ok = (::connect(s, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == 0);
  ::close(s);
  return ok;
}

// Find the first occurrence of any byte in `delims` within `s` starting
// at `start`. Returns std::string::npos if not found.
std::size_t find_any(std::string_view s, std::size_t start,
                     std::string_view delims) {
  for (std::size_t i = start; i < s.size(); ++i) {
    if (delims.find(s[i]) != std::string_view::npos) return i;
  }
  return std::string_view::npos;
}

}  // namespace

// ---------------------------------------------------------------------------
// parse_rr_url
// ---------------------------------------------------------------------------

RrUrl parse_rr_url(const std::string& url) {
  constexpr std::string_view kPrefix = "rr://";
  if (url.size() < kPrefix.size() ||
      url.compare(0, kPrefix.size(), kPrefix) != 0) {
    throw backend::Error("rr:// URL must begin with rr:// scheme");
  }

  // Everything after `rr://` is `<authority?><path>?<query>?<fragment>`.
  // We require: empty authority (host portion of URL is unused for rr://),
  // and an absolute path starting with '/'.
  std::string_view rest(url);
  rest.remove_prefix(kPrefix.size());

  if (rest.empty()) {
    throw backend::Error("rr:// URL must include an absolute trace path");
  }
  if (rest[0] != '/') {
    // e.g. `rr://relative/path` — the segment up to '/' would be parsed
    // as an authority by RFC 3986. We refuse it: trace_dir MUST be
    // absolute. Sharp error so the operator doesn't get a silent
    // "trace not found" later.
    throw backend::Error(
        "rr:// requires an absolute trace path (got `" + std::string(rest) +
        "`); use `rr:///path/to/trace`");
  }

  // Split path from query string.
  std::string trace_dir;
  std::string query;
  if (auto qpos = rest.find('?'); qpos != std::string_view::npos) {
    trace_dir.assign(rest.substr(0, qpos));
    query.assign(rest.substr(qpos + 1));
  } else {
    trace_dir.assign(rest);
  }

  // Strip a trailing '#fragment' from trace_dir or query — irrelevant.
  if (auto hp = trace_dir.find('#'); hp != std::string::npos) {
    trace_dir.resize(hp);
  }
  if (auto hp = query.find('#'); hp != std::string::npos) {
    query.resize(hp);
  }

  if (trace_dir.empty() || trace_dir == "/") {
    throw backend::Error("rr:// URL has empty trace path");
  }

  RrUrl out;
  out.trace_dir = std::move(trace_dir);

  // Parse query: only `port=N` is recognized. Anything else throws so a
  // typo doesn't get silently dropped.
  std::size_t i = 0;
  while (i < query.size()) {
    auto amp = find_any(query, i, "&");
    std::string_view kv(query.data() + i,
                        (amp == std::string_view::npos ? query.size() : amp) - i);
    auto eq = kv.find('=');
    std::string_view key = kv.substr(0, eq);
    std::string_view val = (eq == std::string_view::npos)
                               ? std::string_view{}
                               : kv.substr(eq + 1);

    if (key == "port") {
      if (val.empty()) {
        throw backend::Error("rr:// port query is empty");
      }
      // Strict numeric: every char a digit.
      for (char c : val) {
        if (c < '0' || c > '9') {
          throw backend::Error(
              "rr:// port must be a positive integer (got `" +
              std::string(val) + "`)");
        }
      }
      // strtoul to range-check.
      char* end = nullptr;
      unsigned long n = std::strtoul(std::string(val).c_str(), &end, 10);
      if (end == nullptr || *end != '\0' || n == 0 || n > 65535) {
        throw backend::Error("rr:// port out of range 1..65535 (got `" +
                             std::string(val) + "`)");
      }
      out.port = static_cast<std::uint16_t>(n);
    } else {
      throw backend::Error(
          "rr:// unknown query parameter `" + std::string(key) +
          "`; only `port=N` is supported");
    }

    if (amp == std::string_view::npos) break;
    i = amp + 1;
  }

  return out;
}

// ---------------------------------------------------------------------------
// find_rr_binary
// ---------------------------------------------------------------------------

std::string find_rr_binary() {
  // Priority 1: env override.
  if (const char* env = std::getenv("LDB_RR_BIN"); env && *env) {
    if (is_executable(env)) return std::string(env);
  }
  // Priority 2-3: well-known absolute paths.
  for (const char* p : {"/usr/bin/rr", "/usr/local/bin/rr"}) {
    if (is_executable(p)) return std::string(p);
  }
  // Priority 4: $PATH lookup via `command -v rr`. popen is acceptable
  // here — we don't read JSON-RPC stdout, only the child's stdout.
  if (FILE* f = ::popen("command -v rr 2>/dev/null", "r"); f) {
    char buf[4096] = {0};
    char* got = std::fgets(buf, sizeof(buf), f);
    ::pclose(f);
    if (got) {
      std::string s(buf);
      while (!s.empty() && (s.back() == '\n' || s.back() == '\r' ||
                            s.back() == ' ')) {
        s.pop_back();
      }
      if (!s.empty() && is_executable(s.c_str())) return s;
    }
  }
  return {};
}

// ---------------------------------------------------------------------------
// pick_ephemeral_port_local
// ---------------------------------------------------------------------------

std::uint16_t pick_ephemeral_port_local() {
  int s = ::socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    throw backend::Error(std::string("rr: socket() failed: ")
                         + std::strerror(errno));
  }
  int one = 1;
  ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_port = 0;
  if (::bind(s, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) < 0) {
    int e = errno;
    ::close(s);
    throw backend::Error(std::string("rr: bind() failed: ")
                         + std::strerror(e));
  }
  socklen_t sl = sizeof(sa);
  if (::getsockname(s, reinterpret_cast<sockaddr*>(&sa), &sl) < 0) {
    int e = errno;
    ::close(s);
    throw backend::Error(std::string("rr: getsockname() failed: ")
                         + std::strerror(e));
  }
  std::uint16_t port = ntohs(sa.sin_port);
  ::close(s);
  return port;
}

// ---------------------------------------------------------------------------
// RrReplayProcess
// ---------------------------------------------------------------------------

struct RrReplayProcess::Impl {
  std::atomic<pid_t>      pid{-1};
  std::uint16_t           port{0};
  int                     stderr_fd{-1};
  std::thread             stderr_pump;
  std::atomic<bool>       child_alive{false};
  mutable std::mutex      err_mu;
  std::string             err_buf;
  std::atomic<bool>       stop{false};

  void pump_stderr_loop() {
    char buf[4096];
    while (!stop.load()) {
      // Bounded by kStderrCap so a chatty rr can't OOM the daemon.
      ssize_t n = ::read(stderr_fd, buf, sizeof(buf));
      if (n > 0) {
        std::lock_guard<std::mutex> lk(err_mu);
        constexpr std::size_t kStderrCap = 64 * 1024;
        if (err_buf.size() < kStderrCap) {
          std::size_t take = std::min<std::size_t>(
              static_cast<std::size_t>(n), kStderrCap - err_buf.size());
          err_buf.append(buf, take);
        }
      } else if (n == 0) {
        return;
      } else {
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          std::this_thread::sleep_for(std::chrono::milliseconds(20));
          continue;
        }
        return;
      }
    }
  }
};

namespace {

void install_sigpipe_ignore_once() {
  static std::once_flag flag;
  std::call_once(flag, [] {
    struct sigaction sa{};
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    ::sigaction(SIGPIPE, &sa, nullptr);
  });
}

}  // namespace

RrReplayProcess::RrReplayProcess(std::string                rr_bin,
                                 std::string                trace_dir,
                                 std::uint16_t              port,
                                 std::chrono::milliseconds  setup_timeout)
    : impl_(std::make_unique<Impl>()) {
  install_sigpipe_ignore_once();
  impl_->port = port;

  if (rr_bin.empty()) {
    throw backend::Error("rr_bin must not be empty");
  }
  if (trace_dir.empty()) {
    throw backend::Error("trace_dir must not be empty");
  }
  if (port == 0) {
    throw backend::Error("port must be non-zero (caller picks via "
                         "pick_ephemeral_port_local)");
  }

  // Pipe stderr only — pin stdout to /dev/null so even if rr decides to
  // print something there it can't corrupt the daemon's JSON-RPC channel.
  int err_pipe[2] = {-1, -1};
  if (::pipe(err_pipe) < 0) {
    throw backend::Error(std::string("rr: pipe() failed: ")
                         + std::strerror(errno));
  }

  posix_spawn_file_actions_t actions;
  ::posix_spawn_file_actions_init(&actions);
  ::posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null",
                                     O_RDONLY, 0);
  ::posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null",
                                     O_WRONLY, 0);
  ::posix_spawn_file_actions_adddup2(&actions, err_pipe[1], STDERR_FILENO);
  ::posix_spawn_file_actions_addclose(&actions, err_pipe[0]);
  ::posix_spawn_file_actions_addclose(&actions, err_pipe[1]);

  posix_spawnattr_t attr;
  ::posix_spawnattr_init(&attr);
  sigset_t default_sigs;
  sigemptyset(&default_sigs);
  sigaddset(&default_sigs, SIGPIPE);
  ::posix_spawnattr_setsigdefault(&attr, &default_sigs);
  ::posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGDEF);

  // argv: rr replay -k --debugger-port=<port> <trace_dir>
  // -k = "keep listening" (don't exit on debugger detach). Some rr
  //      builds spell this differently; we set the port flag and trust
  //      rr to do the right thing on a clean detach (LLDB's gdb-remote
  //      client handles its own teardown).
  std::string port_flag = "--dbgport=" + std::to_string(port);
  std::vector<std::string> argv;
  argv.push_back(rr_bin);
  argv.push_back("replay");
  argv.push_back(port_flag);
  argv.push_back("-k");
  argv.push_back(trace_dir);

  std::vector<std::string> storage(argv);
  std::vector<char*> ptrs;
  ptrs.reserve(storage.size() + 1);
  for (auto& s : storage) ptrs.push_back(s.data());
  ptrs.push_back(nullptr);

  pid_t pid = -1;
  int rc = ::posix_spawnp(&pid, ptrs[0], &actions, &attr,
                          ptrs.data(), environ);

  ::posix_spawn_file_actions_destroy(&actions);
  ::posix_spawnattr_destroy(&attr);

  ::close(err_pipe[1]);  // parent only reads.
  if (rc != 0) {
    ::close(err_pipe[0]);
    throw backend::Error(std::string("rr: posix_spawnp(\"") + rr_bin +
                         "\") failed: " + std::strerror(rc));
  }
  impl_->pid.store(pid);
  impl_->child_alive.store(true);
  impl_->stderr_fd = err_pipe[0];

  // Make stderr fd non-blocking so the pump thread can poll-shutdown.
  int fl = ::fcntl(impl_->stderr_fd, F_GETFL, 0);
  if (fl >= 0) ::fcntl(impl_->stderr_fd, F_SETFL, fl | O_NONBLOCK);
  impl_->stderr_pump = std::thread([this] { impl_->pump_stderr_loop(); });

  // Wait until either (a) connect(127.0.0.1:port) succeeds — rr's
  // gdb-remote listener is up — or (b) the rr child exits — failure —
  // or (c) setup_timeout elapses.
  using clock = std::chrono::steady_clock;
  const auto deadline = clock::now() + setup_timeout;
  bool listening = false;
  while (clock::now() < deadline) {
    int status = 0;
    pid_t r = ::waitpid(pid, &status, WNOHANG);
    if (r == pid) {
      impl_->child_alive.store(false);
      break;
    }
    if (try_connect_local(port)) {
      listening = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }

  if (!listening) {
    // Pull stderr for the diagnostic and tear down the child.
    std::string err = drain_stderr();
    impl_->stop.store(true);
    if (impl_->child_alive.load() && pid > 0) {
      ::kill(pid, SIGTERM);
      for (int i = 0; i < 25; ++i) {
        int st = 0;
        pid_t rr = ::waitpid(pid, &st, WNOHANG);
        if (rr == pid) { impl_->child_alive.store(false); break; }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
      if (impl_->child_alive.load()) {
        ::kill(pid, SIGKILL);
        int st = 0;
        ::waitpid(pid, &st, 0);
        impl_->child_alive.store(false);
      }
    }
    if (impl_->stderr_pump.joinable()) impl_->stderr_pump.join();
    close_safely(impl_->stderr_fd);
    impl_->pid.store(-1);
    std::string msg = "rr replay never opened gdb-remote port " +
                      std::to_string(port);
    if (!err.empty()) {
      msg += " (stderr: ";
      // Trim noise: just first 256 bytes.
      msg.append(err, 0, std::min<std::size_t>(err.size(), 256));
      msg += ")";
    }
    throw backend::Error(msg);
  }
}

RrReplayProcess::~RrReplayProcess() {
  if (!impl_) return;
  impl_->stop.store(true);
  pid_t pid = impl_->pid.load();
  if (pid > 0 && impl_->child_alive.load()) {
    ::kill(pid, SIGTERM);
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(250);
    while (std::chrono::steady_clock::now() < deadline) {
      int st = 0;
      pid_t r = ::waitpid(pid, &st, WNOHANG);
      if (r == pid) { impl_->child_alive.store(false); break; }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (impl_->child_alive.load()) {
      ::kill(pid, SIGKILL);
      int st = 0;
      ::waitpid(pid, &st, 0);
      impl_->child_alive.store(false);
    }
  }
  if (impl_->stderr_pump.joinable()) impl_->stderr_pump.join();
  close_safely(impl_->stderr_fd);
}

std::uint16_t RrReplayProcess::port() const noexcept {
  return impl_ ? impl_->port : 0;
}

bool RrReplayProcess::alive() const noexcept {
  if (!impl_) return false;
  if (!impl_->child_alive.load()) return false;
  pid_t pid = impl_->pid.load();
  if (pid <= 0) return false;
  int st = 0;
  pid_t r = ::waitpid(pid, &st, WNOHANG);
  if (r == pid) {
    impl_->child_alive.store(false);
    return false;
  }
  return true;
}

std::string RrReplayProcess::drain_stderr() const {
  if (!impl_) return {};
  std::lock_guard<std::mutex> lk(impl_->err_mu);
  return impl_->err_buf;
}

}  // namespace ldb::transport
