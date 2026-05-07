#include "transport/streaming_exec.h"

#include "backend/debugger_backend.h"  // backend::Error

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <thread>
#include <utility>

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

int decode_exit(int status) {
  if (WIFEXITED(status))   return WEXITSTATUS(status);
  if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
  return -1;
}

// Same shell-quoting routine as ssh.cpp uses for ssh_exec — we wrap a
// remote argv into a single 'foo' bar... command line. POSIX-portable
// single-quote escaping: every `'` becomes `'\''`.
std::string shell_quote(std::string_view s) {
  std::string out;
  out.reserve(s.size() + 2);
  out.push_back('\'');
  for (char c : s) {
    if (c == '\'') out += "'\\''";
    else out.push_back(c);
  }
  out.push_back('\'');
  return out;
}

std::string join_argv_for_ssh(const std::vector<std::string>& argv) {
  std::string out;
  for (std::size_t i = 0; i < argv.size(); ++i) {
    if (i) out += ' ';
    out += shell_quote(argv[i]);
  }
  return out;
}

std::vector<std::string> build_remote_argv(const SshHost& host,
                                           const std::vector<std::string>& argv) {
  std::vector<std::string> out;
  out.reserve(host.ssh_options.size() + 12);
  out.push_back("ssh");
  for (const auto& o : host.ssh_options) out.push_back(o);
  out.push_back("-o"); out.push_back("BatchMode=yes");
  out.push_back("-o"); out.push_back("StrictHostKeyChecking=accept-new");
  out.push_back("-o"); out.push_back("ConnectTimeout=10");
  out.push_back("-T");
  if (host.port) {
    out.push_back("-p");
    out.push_back(std::to_string(*host.port));
  }
  out.push_back(host.host);
  out.push_back(join_argv_for_ssh(argv));
  return out;
}

}  // namespace

struct StreamingExec::Impl {
  pid_t                                        pid    = -1;
  int                                          out_fd = -1;
  int                                          err_fd = -1;
  std::thread                                  reader;

  std::atomic<bool>                            alive{false};
  std::atomic<bool>                            done_called{false};
  std::atomic<bool>                            stop_requested{false};

  StreamingExec::LineCallback                  on_line;
  StreamingExec::DoneCallback                  on_done;

  // Stderr captured under mu_ for `drain_stderr`. Bounded; bytes past
  // the cap are dropped (we don't need full fidelity for diagnostics).
  mutable std::mutex                           mu;
  std::string                                  stderr_buf;

  // Signal the entire process group (we put the child into its own pg
  // at spawn time). This is critical for `sh -c 'sleep N'` and for
  // bpftrace, which fork worker children that would otherwise outlive
  // the signal and pin our stdout pipe.
  void signal_all(int sig) const {
    if (pid > 0) {
      ::kill(-pid, sig);  // pgid == pid since setpgroup(0)
      ::kill(pid, sig);   // belt + suspenders
    }
  }

  ~Impl() {
    if (alive.load()) {
      stop_requested.store(true);
      signal_all(SIGTERM);
    }
    if (reader.joinable()) reader.join();
    close_safely(out_fd);
    close_safely(err_fd);
  }
};

namespace {

// Reap a child with SIGTERM → 250 ms grace → SIGKILL. Returns the
// raw waitpid status (after WIFEXITED/WIFSIGNALED inspection by the
// caller).
int reap_child(pid_t pid) {
  for (int i = 0; i < 25; ++i) {
    int status = 0;
    pid_t r = ::waitpid(pid, &status, WNOHANG);
    if (r == pid) return status;
    if (r < 0 && errno != EINTR) return 0;
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  // Final escalation: SIGKILL the entire process group (the spawn
  // put the child as group leader; pgid == pid).
  ::kill(-pid, SIGKILL);
  ::kill(pid, SIGKILL);
  int status = 0;
  while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
  return status;
}

void deliver_lines(StreamingExec::Impl& impl,
                   std::string& accum,
                   bool& truncating) {
  // Walk accum, splitting on '\n'. Each complete line is delivered.
  // Long lines (cap exceeded before newline) are delivered as
  // "<prefix>...[truncated]" once and then we drop bytes until '\n'.
  while (true) {
    if (truncating) {
      auto nl = accum.find('\n');
      if (nl == std::string::npos) {
        accum.clear();
        return;
      }
      accum.erase(0, nl + 1);
      truncating = false;
      continue;
    }
    auto nl = accum.find('\n');
    if (nl == std::string::npos) {
      // No complete line. If we've blown past the cap, deliver the
      // truncated prefix once and switch into truncating mode.
      if (accum.size() > StreamingExec::kMaxLineBytes) {
        std::string out = accum.substr(0, StreamingExec::kMaxLineBytes);
        out += "...[truncated]";
        impl.on_line(out);
        accum.clear();
        truncating = true;
      }
      return;
    }
    if (nl > StreamingExec::kMaxLineBytes) {
      std::string out = accum.substr(0, StreamingExec::kMaxLineBytes);
      out += "...[truncated]";
      impl.on_line(out);
      accum.erase(0, nl + 1);
      continue;
    }
    impl.on_line(std::string_view(accum.data(), nl));
    accum.erase(0, nl + 1);
  }
}

void reader_loop(StreamingExec::Impl* impl) {
  std::string stdout_accum;
  bool        truncating = false;
  char        buf[4096];

  while (impl->out_fd >= 0 || impl->err_fd >= 0) {
    if (impl->stop_requested.load() && impl->pid > 0) {
      // Best-effort SIGTERM to the whole pgid (idempotent if sent).
      impl->signal_all(SIGTERM);
    }

    pollfd pfds[2];
    int n = 0;
    int idx_out = -1, idx_err = -1;
    if (impl->out_fd >= 0) {
      pfds[n] = {impl->out_fd, POLLIN, 0};
      idx_out = n++;
    }
    if (impl->err_fd >= 0) {
      pfds[n] = {impl->err_fd, POLLIN, 0};
      idx_err = n++;
    }
    if (n == 0) break;

    int pr = ::poll(pfds, static_cast<nfds_t>(n), 100);
    if (pr < 0) {
      if (errno == EINTR) continue;
      break;
    }

    if (idx_out >= 0
        && (pfds[idx_out].revents & (POLLIN | POLLERR | POLLHUP))) {
      while (true) {
        ssize_t r = ::read(impl->out_fd, buf, sizeof(buf));
        if (r > 0) {
          stdout_accum.append(buf, static_cast<std::size_t>(r));
          deliver_lines(*impl, stdout_accum, truncating);
        } else if (r == 0) {
          close_safely(impl->out_fd);
          break;
        } else {
          if (errno == EAGAIN || errno == EWOULDBLOCK) break;
          if (errno == EINTR) continue;
          close_safely(impl->out_fd);
          break;
        }
      }
    }

    if (idx_err >= 0
        && (pfds[idx_err].revents & (POLLIN | POLLERR | POLLHUP))) {
      while (true) {
        ssize_t r = ::read(impl->err_fd, buf, sizeof(buf));
        if (r > 0) {
          std::lock_guard<std::mutex> lk(impl->mu);
          if (impl->stderr_buf.size() < StreamingExec::kStderrCapBytes) {
            std::size_t take = std::min<std::size_t>(
                static_cast<std::size_t>(r),
                StreamingExec::kStderrCapBytes - impl->stderr_buf.size());
            impl->stderr_buf.append(buf, take);
          }
        } else if (r == 0) {
          close_safely(impl->err_fd);
          break;
        } else {
          if (errno == EAGAIN || errno == EWOULDBLOCK) break;
          if (errno == EINTR) continue;
          close_safely(impl->err_fd);
          break;
        }
      }
    }
  }

  // Flush any remaining bytes in the line accumulator. If there's a
  // tail without a trailing '\n', deliver it as a final partial line
  // (consistent with how shell tools tend to emit final records).
  if (!stdout_accum.empty() && !truncating) {
    if (stdout_accum.size() > StreamingExec::kMaxLineBytes) {
      stdout_accum.resize(StreamingExec::kMaxLineBytes);
      stdout_accum += "...[truncated]";
    }
    impl->on_line(stdout_accum);
  }

  // Reap. If the child is still up (we're in the destructor's path or
  // terminate() was invoked but reaping wasn't yet attempted), SIGTERM
  // → grace → SIGKILL. Otherwise the child has already exited and
  // waitpid returns immediately.
  bool       timed_out = impl->stop_requested.load();
  int        status    = 0;
  if (impl->pid > 0) {
    if (impl->stop_requested.load()) {
      impl->signal_all(SIGTERM);
    }
    status = reap_child(impl->pid);
  }
  int exit_code = decode_exit(status);

  impl->alive.store(false);
  if (!impl->done_called.exchange(true)) {
    impl->on_done(exit_code, timed_out);
  }
}

}  // namespace

StreamingExec::StreamingExec(std::optional<SshHost>          remote,
                             std::vector<std::string>        argv,
                             LineCallback                    on_line,
                             DoneCallback                    on_done)
    : impl_(std::make_unique<Impl>()) {
  if (argv.empty()) {
    throw backend::Error("StreamingExec: empty argv");
  }
  install_sigpipe_ignore_once();
  impl_->on_line = std::move(on_line);
  impl_->on_done = std::move(on_done);

  std::vector<std::string> spawn_argv =
      remote.has_value() ? build_remote_argv(*remote, argv) : argv;

  int in_pipe[2]  = {-1, -1};
  int out_pipe[2] = {-1, -1};
  int err_pipe[2] = {-1, -1};

  auto cleanup_pipes = [&] {
    for (int* p : {in_pipe, out_pipe, err_pipe}) {
      if (p[0] >= 0) ::close(p[0]);
      if (p[1] >= 0) ::close(p[1]);
    }
  };

  if (::pipe(in_pipe)  < 0 || ::pipe(out_pipe) < 0 || ::pipe(err_pipe) < 0) {
    int e = errno;
    cleanup_pipes();
    throw backend::Error(std::string("StreamingExec: pipe() failed: ")
                         + std::strerror(e));
  }

  posix_spawn_file_actions_t actions;
  ::posix_spawn_file_actions_init(&actions);
  ::posix_spawn_file_actions_adddup2(&actions, in_pipe[0],  STDIN_FILENO);
  ::posix_spawn_file_actions_adddup2(&actions, out_pipe[1], STDOUT_FILENO);
  ::posix_spawn_file_actions_adddup2(&actions, err_pipe[1], STDERR_FILENO);
  ::posix_spawn_file_actions_addclose(&actions, in_pipe[0]);
  ::posix_spawn_file_actions_addclose(&actions, in_pipe[1]);
  ::posix_spawn_file_actions_addclose(&actions, out_pipe[0]);
  ::posix_spawn_file_actions_addclose(&actions, out_pipe[1]);
  ::posix_spawn_file_actions_addclose(&actions, err_pipe[0]);
  ::posix_spawn_file_actions_addclose(&actions, err_pipe[1]);

  posix_spawnattr_t attr;
  ::posix_spawnattr_init(&attr);
  sigset_t default_sigs;
  sigemptyset(&default_sigs);
  sigaddset(&default_sigs, SIGPIPE);
  ::posix_spawnattr_setsigdefault(&attr, &default_sigs);
  // Put the child in its OWN process group so we can `kill(-pgid, ...)`
  // and reap any grand-children (sh -> sleep, bpftrace -> child workers).
  // Without this, signaling a `sh -c 'sleep 30'` parent leaves the
  // grand-child sleep reparented to init while still holding our stdout
  // pipe open, deadlocking the reader thread until sleep exits.
  ::posix_spawnattr_setpgroup(&attr, 0);
  short flags = POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETPGROUP;
  ::posix_spawnattr_setflags(&attr, flags);

  std::vector<char*> ptrs;
  std::vector<std::string> storage(spawn_argv);
  ptrs.reserve(storage.size() + 1);
  for (auto& s : storage) ptrs.push_back(s.data());
  ptrs.push_back(nullptr);

  pid_t pid = -1;
  int rc = ::posix_spawnp(&pid, ptrs[0], &actions, &attr,
                          ptrs.data(), environ);
  ::posix_spawn_file_actions_destroy(&actions);
  ::posix_spawnattr_destroy(&attr);

  if (rc != 0) {
    cleanup_pipes();
    throw backend::Error(std::string("StreamingExec: posix_spawnp(\"")
                         + spawn_argv[0] + "\") failed: "
                         + std::strerror(rc));
  }

  ::close(in_pipe[0]);
  ::close(out_pipe[1]);
  ::close(err_pipe[1]);
  // We don't write to the child's stdin in this primitive; close the
  // parent side so the child sees EOF on stdin immediately. bpftrace,
  // sleep, sh -c "..." — none consume stdin, and closing it removes
  // any chance of a deadlock on a child that does read().
  ::close(in_pipe[1]);

  impl_->pid    = pid;
  impl_->out_fd = out_pipe[0];
  impl_->err_fd = err_pipe[0];
  impl_->alive.store(true);

  set_nonblock(impl_->out_fd);
  set_nonblock(impl_->err_fd);

  impl_->reader = std::thread(reader_loop, impl_.get());
}

StreamingExec::~StreamingExec() {
  if (impl_) terminate();
}

bool StreamingExec::alive() const {
  return impl_ && impl_->alive.load();
}

std::string StreamingExec::drain_stderr() const {
  if (!impl_) return {};
  std::lock_guard<std::mutex> lk(impl_->mu);
  return impl_->stderr_buf;
}

void StreamingExec::terminate() {
  if (!impl_) return;
  if (!impl_->alive.load() && !impl_->reader.joinable()) return;

  impl_->stop_requested.store(true);
  impl_->signal_all(SIGTERM);
  // Give the reader thread up to 250 ms to drain + reap on its own.
  // After that, we SIGKILL the whole process group and re-join.
  if (impl_->reader.joinable()) {
    auto t0 = std::chrono::steady_clock::now();
    while (impl_->alive.load()
           && std::chrono::steady_clock::now() - t0
                  < std::chrono::milliseconds(250)) {
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (impl_->alive.load()) {
      impl_->signal_all(SIGKILL);
    }
    impl_->reader.join();
  }
}

}  // namespace ldb::transport
