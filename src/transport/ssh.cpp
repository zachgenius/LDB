#include "transport/ssh.h"

#include "backend/debugger_backend.h"  // backend::Error

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

extern char** environ;

namespace ldb::transport {

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

// POSIX shell single-quoting. Wraps each argv entry in '...' and escapes
// embedded single quotes via the standard '\'' trick.
//
// Rationale: ssh's wire protocol concatenates argv[1..] with spaces and
// the remote sshd hands the result to /bin/sh -c. Without quoting, a
// path like "/tmp/dir with space/binary" turns into three positional
// args on the remote.
std::string sh_quote(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 2);
  out.push_back('\'');
  for (char c : s) {
    if (c == '\'') {
      out += "'\\''";
    } else {
      out.push_back(c);
    }
  }
  out.push_back('\'');
  return out;
}

std::string join_argv_for_ssh(const std::vector<std::string>& argv) {
  std::string out;
  for (std::size_t i = 0; i < argv.size(); ++i) {
    if (i) out.push_back(' ');
    out += sh_quote(argv[i]);
  }
  return out;
}

// Build the ssh argv. Order matters: caller's `-o` options come BEFORE
// our defaults so caller wins on key collisions (ssh applies the first
// occurrence of any option).
std::vector<std::string> build_ssh_argv(const SshHost& host,
                                        const std::vector<std::string>& tail) {
  std::vector<std::string> argv;
  argv.reserve(host.ssh_options.size() + tail.size() + 12);
  argv.push_back("ssh");
  for (const auto& o : host.ssh_options) argv.push_back(o);
  // Defaults:
  argv.push_back("-o"); argv.push_back("BatchMode=yes");
  argv.push_back("-o"); argv.push_back("StrictHostKeyChecking=accept-new");
  argv.push_back("-o"); argv.push_back("ConnectTimeout=10");
  argv.push_back("-T");
  if (host.port) {
    argv.push_back("-p");
    argv.push_back(std::to_string(*host.port));
  }
  argv.push_back(host.host);
  for (const auto& t : tail) argv.push_back(t);
  return argv;
}

// Convert std::vector<std::string> to a NULL-terminated char*[] suitable
// for posix_spawnp. Storage stays alive in the returned pair until the
// vector destructs. Caller owns both.
struct SpawnArgv {
  std::vector<std::string>  storage;
  std::vector<char*>        ptrs;

  explicit SpawnArgv(std::vector<std::string> a) : storage(std::move(a)) {
    ptrs.reserve(storage.size() + 1);
    for (auto& s : storage) ptrs.push_back(s.data());
    ptrs.push_back(nullptr);
  }
};

void close_safely(int& fd) {
  if (fd >= 0) {
    ::close(fd);
    fd = -1;
  }
}

void set_nonblock(int fd) {
  int fl = ::fcntl(fd, F_GETFL, 0);
  if (fl >= 0) ::fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

// Reap a child with SIGTERM → 250ms grace → SIGKILL. Final waitpid is
// blocking; we have already SIGKILLed by then so it returns promptly.
int reap_child(pid_t pid) {
  ::kill(pid, SIGTERM);
  for (int i = 0; i < 25; ++i) {
    int status = 0;
    pid_t r = ::waitpid(pid, &status, WNOHANG);
    if (r == pid) return status;
    if (r < 0 && errno != EINTR) return 0;
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  ::kill(pid, SIGKILL);
  int status = 0;
  while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
  return status;
}

int decode_exit(int status) {
  if (WIFEXITED(status)) return WEXITSTATUS(status);
  if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
  return -1;
}

struct SpawnedChild {
  pid_t  pid       = -1;
  int    in_fd     = -1;   // write side -> child's stdin
  int    out_fd    = -1;   // read side  <- child's stdout
  int    err_fd    = -1;   // read side  <- child's stderr (if not merged)
};

// Spawn `argv` with pipes for stdin/stdout/stderr. If merge_stderr is
// true, the child's stderr is dup2'd onto its stdout-write end and we
// return err_fd = -1.
//
// Throws backend::Error on spawn failure.
SpawnedChild spawn_with_pipes(const std::vector<std::string>& argv,
                              bool merge_stderr) {
  install_sigpipe_ignore_once();

  int in_pipe[2]  = {-1, -1};
  int out_pipe[2] = {-1, -1};
  int err_pipe[2] = {-1, -1};

  auto cleanup_pipes = [&] {
    for (int* p : {in_pipe, out_pipe, err_pipe}) {
      if (p[0] >= 0) ::close(p[0]);
      if (p[1] >= 0) ::close(p[1]);
    }
  };

  if (::pipe(in_pipe) < 0 || ::pipe(out_pipe) < 0
      || (!merge_stderr && ::pipe(err_pipe) < 0)) {
    int e = errno;
    cleanup_pipes();
    throw backend::Error(std::string("ssh: pipe() failed: ") + std::strerror(e));
  }

  posix_spawn_file_actions_t actions;
  ::posix_spawn_file_actions_init(&actions);
  // Child: stdin <- in_pipe[0]; stdout -> out_pipe[1]; stderr -> err or out.
  ::posix_spawn_file_actions_adddup2(&actions, in_pipe[0],  STDIN_FILENO);
  ::posix_spawn_file_actions_adddup2(&actions, out_pipe[1], STDOUT_FILENO);
  if (merge_stderr) {
    ::posix_spawn_file_actions_adddup2(&actions, out_pipe[1], STDERR_FILENO);
  } else {
    ::posix_spawn_file_actions_adddup2(&actions, err_pipe[1], STDERR_FILENO);
  }
  // Close everything else from the parent set:
  ::posix_spawn_file_actions_addclose(&actions, in_pipe[0]);
  ::posix_spawn_file_actions_addclose(&actions, in_pipe[1]);
  ::posix_spawn_file_actions_addclose(&actions, out_pipe[0]);
  ::posix_spawn_file_actions_addclose(&actions, out_pipe[1]);
  if (!merge_stderr) {
    ::posix_spawn_file_actions_addclose(&actions, err_pipe[0]);
    ::posix_spawn_file_actions_addclose(&actions, err_pipe[1]);
  }

  posix_spawnattr_t attr;
  ::posix_spawnattr_init(&attr);
  // Reset SIGPIPE in the child so it inherits default behavior; we
  // ignore SIGPIPE in the parent only.
  sigset_t default_sigs;
  ::sigemptyset(&default_sigs);
  ::sigaddset(&default_sigs, SIGPIPE);
  ::posix_spawnattr_setsigdefault(&attr, &default_sigs);
  short flags = POSIX_SPAWN_SETSIGDEF;
  ::posix_spawnattr_setflags(&attr, flags);

  SpawnArgv sa(argv);

  pid_t pid = -1;
  int rc = ::posix_spawnp(&pid, sa.ptrs[0], &actions, &attr,
                          sa.ptrs.data(), environ);

  ::posix_spawn_file_actions_destroy(&actions);
  ::posix_spawnattr_destroy(&attr);

  if (rc != 0) {
    cleanup_pipes();
    throw backend::Error(std::string("ssh: posix_spawnp(\"")
                         + argv[0] + "\") failed: " + std::strerror(rc));
  }

  // Parent: close child-side ends, keep our ends.
  ::close(in_pipe[0]);
  ::close(out_pipe[1]);
  if (!merge_stderr) ::close(err_pipe[1]);

  SpawnedChild c;
  c.pid    = pid;
  c.in_fd  = in_pipe[1];
  c.out_fd = out_pipe[0];
  c.err_fd = merge_stderr ? -1 : err_pipe[0];

  set_nonblock(c.in_fd);
  set_nonblock(c.out_fd);
  if (c.err_fd >= 0) set_nonblock(c.err_fd);

  return c;
}

// Drain whatever's already buffered on a pipe before closing. Best-effort
// — we read up to a few KB to keep a final flush from being lost when
// the child has already exited.
void final_drain(int fd, std::string& sink, std::uint64_t cap, bool& truncated) {
  if (fd < 0) return;
  char buf[4096];
  while (sink.size() < cap) {
    ssize_t n = ::read(fd, buf,
                       std::min<std::size_t>(sizeof(buf), cap - sink.size()));
    if (n > 0) {
      sink.append(buf, static_cast<std::size_t>(n));
    } else if (n < 0 && errno == EINTR) {
      continue;
    } else {
      break;
    }
  }
  // If we hit cap, drop the rest but mark truncated.
  char tmp[4096];
  while (true) {
    ssize_t n = ::read(fd, tmp, sizeof(tmp));
    if (n > 0) {
      truncated = true;
      continue;
    }
    if (n < 0 && errno == EINTR) continue;
    break;
  }
}

ExecResult run_pumped(SpawnedChild               child,
                      const ExecOptions&         opts,
                      bool                       merge_stderr) {
  ExecResult result;
  const auto t0 = std::chrono::steady_clock::now();
  const auto deadline = t0 + opts.timeout;

  std::size_t stdin_written = 0;
  bool stdin_done = opts.stdin_data.empty();
  if (stdin_done) close_safely(child.in_fd);

  while (child.out_fd >= 0 || child.err_fd >= 0 || child.in_fd >= 0) {
    auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
      result.timed_out = true;
      break;
    }
    auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - now);
    int timeout_ms = static_cast<int>(std::min<std::int64_t>(
        remaining.count(), 250));

    pollfd pfds[3];
    int n = 0;
    int idx_in = -1, idx_out = -1, idx_err = -1;
    if (child.in_fd >= 0) {
      pfds[n].fd = child.in_fd;
      pfds[n].events = POLLOUT;
      pfds[n].revents = 0;
      idx_in = n++;
    }
    if (child.out_fd >= 0) {
      pfds[n].fd = child.out_fd;
      pfds[n].events = POLLIN;
      pfds[n].revents = 0;
      idx_out = n++;
    }
    if (child.err_fd >= 0) {
      pfds[n].fd = child.err_fd;
      pfds[n].events = POLLIN;
      pfds[n].revents = 0;
      idx_err = n++;
    }

    int pr = ::poll(pfds, static_cast<nfds_t>(n), timeout_ms);
    if (pr < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (pr == 0) continue;

    if (idx_in >= 0 && (pfds[idx_in].revents & (POLLOUT | POLLERR | POLLHUP))) {
      const char* p = opts.stdin_data.data() + stdin_written;
      std::size_t left = opts.stdin_data.size() - stdin_written;
      ssize_t w = ::write(child.in_fd, p, left);
      if (w > 0) {
        stdin_written += static_cast<std::size_t>(w);
        if (stdin_written >= opts.stdin_data.size()) {
          stdin_done = true;
          close_safely(child.in_fd);
        }
      } else if (w < 0 && errno != EAGAIN && errno != EINTR) {
        // Broken pipe (child closed stdin) — stop trying.
        stdin_done = true;
        close_safely(child.in_fd);
      }
    }

    auto pump_read = [&](int idx, int& fd, std::string& sink,
                         std::uint64_t cap, bool& truncated) {
      if (idx < 0) return;
      if (!(pfds[idx].revents & (POLLIN | POLLERR | POLLHUP))) return;
      char buf[4096];
      while (true) {
        std::size_t budget = (sink.size() < cap)
                                 ? std::min<std::size_t>(sizeof(buf),
                                                         cap - sink.size())
                                 : sizeof(buf);
        ssize_t r = ::read(fd, buf, budget);
        if (r > 0) {
          if (sink.size() < cap) {
            std::size_t take = std::min<std::size_t>(
                static_cast<std::size_t>(r), cap - sink.size());
            sink.append(buf, take);
            if (take < static_cast<std::size_t>(r)) {
              truncated = true;
            }
          } else {
            truncated = true;
          }
        } else if (r == 0) {
          close_safely(fd);
          break;
        } else {
          if (errno == EAGAIN || errno == EWOULDBLOCK) break;
          if (errno == EINTR) continue;
          close_safely(fd);
          break;
        }
      }
    };

    pump_read(idx_out, child.out_fd, result.stdout_data,
              opts.stdout_cap, result.stdout_truncated);
    if (!merge_stderr) {
      pump_read(idx_err, child.err_fd, result.stderr_data,
                opts.stderr_cap, result.stderr_truncated);
    }
  }

  // Close everything we still hold.
  close_safely(child.in_fd);

  if (result.timed_out) {
    final_drain(child.out_fd, result.stdout_data,
                opts.stdout_cap, result.stdout_truncated);
    if (!merge_stderr) {
      final_drain(child.err_fd, result.stderr_data,
                  opts.stderr_cap, result.stderr_truncated);
    }
    close_safely(child.out_fd);
    close_safely(child.err_fd);
    int status = reap_child(child.pid);
    result.exit_code = decode_exit(status);
  } else {
    // Drain trailing bytes after EOF / poll loop exit.
    final_drain(child.out_fd, result.stdout_data,
                opts.stdout_cap, result.stdout_truncated);
    if (!merge_stderr) {
      final_drain(child.err_fd, result.stderr_data,
                  opts.stderr_cap, result.stderr_truncated);
    }
    close_safely(child.out_fd);
    close_safely(child.err_fd);
    int status = 0;
    while (::waitpid(child.pid, &status, 0) < 0 && errno == EINTR) {}
    result.exit_code = decode_exit(status);
  }

  result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - t0);
  return result;
}

// Bind a TCP socket on 127.0.0.1:0, get the kernel-assigned port, close.
// Returns the port; throws backend::Error on failure.
std::uint16_t pick_ephemeral_port() {
  int s = ::socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    throw backend::Error(std::string("ssh: socket() failed: ")
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
    throw backend::Error(std::string("ssh: bind() failed: ")
                         + std::strerror(e));
  }
  socklen_t sl = sizeof(sa);
  if (::getsockname(s, reinterpret_cast<sockaddr*>(&sa), &sl) < 0) {
    int e = errno;
    ::close(s);
    throw backend::Error(std::string("ssh: getsockname() failed: ")
                         + std::strerror(e));
  }
  std::uint16_t port = ntohs(sa.sin_port);
  ::close(s);
  return port;
}

// Attempt a TCP connect to 127.0.0.1:port. Returns true on success.
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

// Connect through an SSH -L tunnel and check that the connection is
// "real" — i.e. the remote side is also listening, not just the ssh
// client. SSH opens the local port the moment the channel is up, and
// connect() succeeds immediately even when the remote endpoint isn't
// listening; the remote-side failure surfaces as the peer closing the
// stream within milliseconds.
//
// Returns true when:
//   - connect() succeeded AND
//   - after a short grace period, the connection is still open
//     (no EOF, no RST signaled via POLLHUP/POLLERR).
//
// IMPORTANT: this consumes one connection through the tunnel. lldb-
// server's gdbserver is multi-accept on the same listen socket, so a
// probe accept-then-close is harmless. Single-shot servers will be
// drained — same caveat documented for SshPortForward.
bool try_tunneled_connect_local(std::uint16_t port,
                                std::chrono::milliseconds grace) {
  int s = ::socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) return false;
  sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_port = htons(port);
  if (::connect(s, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0) {
    ::close(s);
    return false;
  }
  // The connect itself may have raced ssh's local-port-open. Wait
  // briefly: if the peer hangs up (POLLHUP / POLLIN with read=0), the
  // remote isn't listening. If poll times out, the connection is still
  // open — remote is listening (or at least not actively closing).
  pollfd pfd{};
  pfd.fd = s;
  pfd.events = POLLIN;
  int pr = ::poll(&pfd, 1, static_cast<int>(grace.count()));
  bool ok = true;
  if (pr > 0) {
    if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) {
      ok = false;
    } else if (pfd.revents & POLLIN) {
      // Drain — if 0, peer closed.
      char buf[1];
      ssize_t n = ::recv(s, buf, sizeof(buf), MSG_PEEK | MSG_DONTWAIT);
      if (n == 0) ok = false;
    }
  }
  ::close(s);
  return ok;
}

}  // namespace

ExecResult ssh_exec(const SshHost&                       host,
                    const std::vector<std::string>&      argv,
                    const ExecOptions&                   opts) {
  if (argv.empty()) {
    throw backend::Error("ssh_exec: empty argv");
  }

  // Build the remote command string. ssh concatenates trailing tokens
  // with spaces and re-parses on the remote shell, so we pre-quote.
  std::vector<std::string> ssh_argv = build_ssh_argv(host, {join_argv_for_ssh(argv)});

  SpawnedChild child = spawn_with_pipes(ssh_argv, opts.merge_stderr);
  return run_pumped(std::move(child), opts, opts.merge_stderr);
}

ReachabilityResult ssh_probe(const SshHost&             host,
                             std::chrono::milliseconds  timeout) {
  ExecOptions o;
  o.timeout    = timeout;
  o.stdout_cap = 4096;
  o.stderr_cap = 4096;
  // ssh's own ConnectTimeout default is 10s; tighten it for the probe
  // so we don't sit on a stuck SYN past our deadline.
  SshHost h = host;
  // Inject ConnectTimeout=ceil(timeout/1000) seconds, minimum 1.
  int ct = static_cast<int>((timeout.count() + 999) / 1000);
  if (ct < 1) ct = 1;
  h.ssh_options.insert(h.ssh_options.begin(), "ConnectTimeout=" + std::to_string(ct));
  h.ssh_options.insert(h.ssh_options.begin(), "-o");

  ReachabilityResult r;
  ExecResult er;
  try {
    er = ssh_exec(h, {"/bin/true"}, o);
  } catch (const backend::Error& e) {
    r.ok = false;
    r.detail = std::string("spawn: ") + e.what();
    return r;
  }
  if (er.timed_out) {
    r.ok = false;
    r.detail = "timed out";
    return r;
  }
  r.ok = (er.exit_code == 0);
  if (!r.ok) {
    r.detail = er.stderr_data.empty()
                   ? ("exit " + std::to_string(er.exit_code))
                   : er.stderr_data;
  }
  return r;
}

// ---- SshPortForward ------------------------------------------------------

struct SshPortForward::Impl {
  pid_t           pid        = -1;
  std::uint16_t   local_port = 0;
  // We close the dev-null fds in dtor, but we don't read from them — ssh
  // -N produces no stdout. (stderr is captured into a small ring on
  // failure; not currently surfaced — could be added if useful.)
  int             out_fd     = -1;
  int             err_fd     = -1;
};

SshPortForward::SshPortForward(const SshHost&             host,
                               std::uint16_t              local_port,
                               std::uint16_t              remote_port,
                               std::chrono::milliseconds  setup_timeout)
    : impl_(std::make_unique<Impl>()) {
  install_sigpipe_ignore_once();

  if (local_port == 0) {
    // Tiny race vs. another bind() in the same window — see header.
    local_port = pick_ephemeral_port();
  }
  impl_->local_port = local_port;

  std::string fwd_arg = "127.0.0.1:" + std::to_string(local_port)
                        + ":127.0.0.1:" + std::to_string(remote_port);

  // For -L we need the host arg + -N (no remote command). Build a custom
  // argv (NOT via build_ssh_argv's tail — that one expects a remote
  // command).
  std::vector<std::string> argv;
  argv.push_back("ssh");
  for (const auto& o : host.ssh_options) argv.push_back(o);
  argv.push_back("-o"); argv.push_back("BatchMode=yes");
  argv.push_back("-o"); argv.push_back("StrictHostKeyChecking=accept-new");
  argv.push_back("-o"); argv.push_back("ConnectTimeout=10");
  argv.push_back("-o"); argv.push_back("ExitOnForwardFailure=yes");
  argv.push_back("-N");
  argv.push_back("-T");
  argv.push_back("-L"); argv.push_back(fwd_arg);
  if (host.port) {
    argv.push_back("-p");
    argv.push_back(std::to_string(*host.port));
  }
  argv.push_back(host.host);

  SpawnedChild child = spawn_with_pipes(argv, /*merge_stderr=*/false);
  impl_->pid    = child.pid;
  impl_->out_fd = child.out_fd;
  impl_->err_fd = child.err_fd;
  // -N writes nothing to stdin, so close it.
  close_safely(child.in_fd);

  // Poll until the forward accepts a TCP connection or we time out.
  const auto deadline = std::chrono::steady_clock::now() + setup_timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    // Did ssh die already?
    int status = 0;
    pid_t r = ::waitpid(impl_->pid, &status, WNOHANG);
    if (r == impl_->pid) {
      impl_->pid = -1;
      throw backend::Error("ssh: -L forward exited during setup (exit "
                           + std::to_string(decode_exit(status)) + ")");
    }
    if (try_connect_local(local_port)) return;
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
  // Setup timed out — tear down.
  if (impl_->pid > 0) {
    reap_child(impl_->pid);
    impl_->pid = -1;
  }
  close_safely(impl_->out_fd);
  close_safely(impl_->err_fd);
  throw backend::Error("ssh: -L forward setup timed out");
}

SshPortForward::~SshPortForward() {
  if (!impl_) return;
  if (impl_->pid > 0) {
    reap_child(impl_->pid);
    impl_->pid = -1;
  }
  close_safely(impl_->out_fd);
  close_safely(impl_->err_fd);
}

std::uint16_t SshPortForward::local_port() const noexcept {
  return impl_ ? impl_->local_port : 0;
}

bool SshPortForward::alive() const noexcept {
  if (!impl_ || impl_->pid <= 0) return false;
  int status = 0;
  pid_t r = ::waitpid(impl_->pid, &status, WNOHANG);
  if (r == 0) return true;
  return false;
}

// ---- pick_remote_free_port ----------------------------------------------

std::uint16_t pick_remote_free_port(const SshHost&            host,
                                    std::chrono::milliseconds timeout) {
  ExecOptions opts;
  opts.timeout    = timeout;
  opts.stdout_cap = 64;
  opts.stderr_cap = 4096;

  // Primary: python3 (available on every modern Linux distro and macOS).
  // Bind to port 0, read kernel-assigned port via getsockname, close.
  static constexpr const char* kPythonProbe =
      "import socket;"
      "s=socket.socket();"
      "s.bind(('127.0.0.1',0));"
      "print(s.getsockname()[1]);"
      "s.close()";

  auto try_parse_port = [](const std::string& out) -> std::uint16_t {
    // Strip trailing whitespace.
    std::string s = out;
    while (!s.empty() &&
           (s.back() == '\n' || s.back() == '\r' || s.back() == ' ' ||
            s.back() == '\t')) {
      s.pop_back();
    }
    if (s.empty()) return 0;
    char* end = nullptr;
    long v = std::strtol(s.c_str(), &end, 10);
    if (end == s.c_str() || v <= 0 || v > 65535) return 0;
    return static_cast<std::uint16_t>(v);
  };

  ExecResult er;
  try {
    er = ssh_exec(host, {"python3", "-c", kPythonProbe}, opts);
  } catch (const backend::Error& e) {
    throw backend::Error(std::string("pick_remote_free_port: ssh failed: ")
                         + e.what());
  }
  if (er.exit_code == 0 && !er.stdout_data.empty()) {
    if (auto p = try_parse_port(er.stdout_data); p != 0) return p;
  }

  // Fallback: ss -tln + AWK to find the first unused ephemeral port in
  // the IANA dynamic range. Documented in the header. Some hosts run
  // sshd inside containers without python3 (Alpine `ash`-only), so
  // this matters.
  static constexpr const char* kSsProbe =
      "ss -tln 2>/dev/null | awk 'NR>1{split($4,a,\":\");"
      "used[a[length(a)]]=1} END{for(p=49152;p<60000;p++)"
      " if (!used[p]) {print p; exit}}'";

  ExecResult er2;
  try {
    er2 = ssh_exec(host, {"/bin/sh", "-c", kSsProbe}, opts);
  } catch (const backend::Error& e) {
    throw backend::Error(std::string("pick_remote_free_port: ss fallback "
                                     "failed: ") + e.what());
  }
  if (er2.exit_code == 0 && !er2.stdout_data.empty()) {
    if (auto p = try_parse_port(er2.stdout_data); p != 0) return p;
  }

  // Both probes failed. Surface what we saw.
  std::string detail = "no free-port helper succeeded on remote (";
  detail += "python3 exit=" + std::to_string(er.exit_code);
  if (!er.stderr_data.empty()) {
    detail += " stderr=";
    detail += er.stderr_data.substr(0, 160);
  }
  detail += "; ss exit=" + std::to_string(er2.exit_code);
  if (!er2.stderr_data.empty()) {
    detail += " stderr=";
    detail += er2.stderr_data.substr(0, 160);
  }
  detail += ")";
  throw backend::Error(detail);
}

// ---- SshTunneledCommand --------------------------------------------------

struct SshTunneledCommand::Impl {
  pid_t           pid          = -1;
  std::uint16_t   local_port   = 0;
  std::uint16_t   remote_port  = 0;
  int             out_fd       = -1;
  int             err_fd       = -1;
};

SshTunneledCommand::SshTunneledCommand(
    const SshHost&                  host,
    std::uint16_t                   local_port,
    std::uint16_t                   remote_port,
    const std::vector<std::string>& remote_argv,
    std::chrono::milliseconds       setup_timeout,
    ProbeKind                       probe_kind)
    : impl_(std::make_unique<Impl>()) {
  install_sigpipe_ignore_once();

  if (remote_argv.empty()) {
    throw backend::Error("SshTunneledCommand: remote_argv must not be empty");
  }
  if (remote_port == 0) {
    throw backend::Error("SshTunneledCommand: remote_port must be non-zero");
  }
  if (local_port == 0) {
    local_port = pick_ephemeral_port();
  }
  impl_->local_port  = local_port;
  impl_->remote_port = remote_port;

  std::string fwd_arg = "127.0.0.1:" + std::to_string(local_port)
                        + ":127.0.0.1:" + std::to_string(remote_port);

  // Single ssh that does -L AND runs the remote command. We can't use
  // -N (no remote command) because we need the command; we don't need
  // -f either (we want the foreground subprocess so RAII teardown
  // hangs up the remote). The remote command is shell-quoted so paths
  // with spaces survive ssh's argv-flattening.
  std::vector<std::string> argv;
  argv.push_back("ssh");
  for (const auto& o : host.ssh_options) argv.push_back(o);
  argv.push_back("-o"); argv.push_back("BatchMode=yes");
  argv.push_back("-o"); argv.push_back("StrictHostKeyChecking=accept-new");
  argv.push_back("-o"); argv.push_back("ConnectTimeout=10");
  argv.push_back("-o"); argv.push_back("ExitOnForwardFailure=yes");
  argv.push_back("-T");
  argv.push_back("-L"); argv.push_back(fwd_arg);
  if (host.port) {
    argv.push_back("-p");
    argv.push_back(std::to_string(*host.port));
  }
  argv.push_back(host.host);
  // Remote command — pre-quoted so ssh's space-flattening on the wire
  // doesn't split argv elements at embedded spaces.
  argv.push_back(join_argv_for_ssh(remote_argv));

  SpawnedChild child = spawn_with_pipes(argv, /*merge_stderr=*/false);
  impl_->pid    = child.pid;
  impl_->out_fd = child.out_fd;
  impl_->err_fd = child.err_fd;
  // We don't pipe data into the remote command via stdin in this
  // shape; close it so the child's stdin sees EOF cleanly.
  close_safely(child.in_fd);

  // Setup probe loop. Two modes:
  //   kTunneledConnect — keep retrying a TCP connect through the
  //     tunnel until the remote command is listening (or ssh dies, or
  //     we hit the deadline). Suitable for multi-accept servers.
  //   kAliveOnly — only verify ssh stayed alive past the initial
  //     spawn (a short grace check); do NOT touch the remote port.
  //     Suitable for single-accept servers (lldb-server gdbserver).
  const auto deadline = std::chrono::steady_clock::now() + setup_timeout;
  // Brief grace for ssh's auth/handshake; we want to detect "ssh exits
  // immediately because of bad host / auth failure" without sleeping
  // long when things are healthy.
  const auto alive_grace = std::min(
      setup_timeout, std::chrono::milliseconds(750));
  const auto alive_deadline = std::chrono::steady_clock::now() + alive_grace;
  while (std::chrono::steady_clock::now() < deadline) {
    int status = 0;
    pid_t r = ::waitpid(impl_->pid, &status, WNOHANG);
    if (r == impl_->pid) {
      impl_->pid = -1;
      // Drain whatever's on stderr so the error is informative.
      std::string err;
      char buf[4096];
      while (true) {
        ssize_t n = ::read(impl_->err_fd, buf, sizeof(buf));
        if (n <= 0) break;
        err.append(buf, static_cast<std::size_t>(n));
        if (err.size() > 4096) break;
      }
      close_safely(impl_->out_fd);
      close_safely(impl_->err_fd);
      throw backend::Error(
          "SshTunneledCommand: ssh exited during setup (exit "
          + std::to_string(decode_exit(status)) + ")"
          + (err.empty() ? std::string{} : ": " + err));
    }
    if (probe_kind == ProbeKind::kAliveOnly) {
      // Once the alive-grace window has passed without ssh dying, we
      // declare the tunnel ready — caller takes it from here.
      if (std::chrono::steady_clock::now() >= alive_deadline) return;
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      continue;
    }
    // 60ms grace is enough for ssh's RST to round-trip from the remote
    // when the remote endpoint isn't listening; lldb-server takes
    // ~50–200ms to bind, so a few of these probes are normal.
    if (try_tunneled_connect_local(local_port, std::chrono::milliseconds(60))) {
      return;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }

  // Setup deadline blew past — tear down and throw.
  if (impl_->pid > 0) {
    reap_child(impl_->pid);
    impl_->pid = -1;
  }
  close_safely(impl_->out_fd);
  close_safely(impl_->err_fd);
  throw backend::Error(
      "SshTunneledCommand: setup timed out before remote port "
      + std::to_string(remote_port) + " became reachable");
}

SshTunneledCommand::~SshTunneledCommand() {
  if (!impl_) return;
  if (impl_->pid > 0) {
    reap_child(impl_->pid);
    impl_->pid = -1;
  }
  close_safely(impl_->out_fd);
  close_safely(impl_->err_fd);
}

std::uint16_t SshTunneledCommand::local_port() const noexcept {
  return impl_ ? impl_->local_port : 0;
}

std::uint16_t SshTunneledCommand::remote_port() const noexcept {
  return impl_ ? impl_->remote_port : 0;
}

bool SshTunneledCommand::alive() const noexcept {
  if (!impl_ || impl_->pid <= 0) return false;
  int status = 0;
  pid_t r = ::waitpid(impl_->pid, &status, WNOHANG);
  return r == 0;
}

}  // namespace ldb::transport
