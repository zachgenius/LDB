#include "transport/local_exec.h"

#include "backend/debugger_backend.h"  // backend::Error

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <mutex>
#include <thread>
#include <utility>

extern char** environ;

namespace ldb::transport {

namespace {

// Mirrors src/transport/ssh.cpp's SIGPIPE installation. Stdout writes
// from this child path can race the parent's pipe-close on cancellation;
// we want EPIPE on write rather than termination via SIGPIPE.
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
  pid_t pid    = -1;
  int   in_fd  = -1;
  int   out_fd = -1;
  int   err_fd = -1;
};

SpawnedChild spawn_with_pipes(const std::vector<std::string>& argv,
                              bool                            merge_stderr) {
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
    throw backend::Error(std::string("local_exec: pipe() failed: ")
                         + std::strerror(e));
  }

  posix_spawn_file_actions_t actions;
  ::posix_spawn_file_actions_init(&actions);
  ::posix_spawn_file_actions_adddup2(&actions, in_pipe[0],  STDIN_FILENO);
  ::posix_spawn_file_actions_adddup2(&actions, out_pipe[1], STDOUT_FILENO);
  if (merge_stderr) {
    ::posix_spawn_file_actions_adddup2(&actions, out_pipe[1], STDERR_FILENO);
  } else {
    ::posix_spawn_file_actions_adddup2(&actions, err_pipe[1], STDERR_FILENO);
  }
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
  sigset_t default_sigs;
  sigemptyset(&default_sigs);
  sigaddset(&default_sigs, SIGPIPE);
  ::posix_spawnattr_setsigdefault(&attr, &default_sigs);
  short flags = POSIX_SPAWN_SETSIGDEF;
  ::posix_spawnattr_setflags(&attr, flags);

  // Build argv for posix_spawnp.
  std::vector<char*> ptrs;
  ptrs.reserve(argv.size() + 1);
  // We need writable storage backing the const std::strings.
  std::vector<std::string> storage(argv);
  for (auto& s : storage) ptrs.push_back(s.data());
  ptrs.push_back(nullptr);

  pid_t pid = -1;
  int rc = ::posix_spawnp(&pid, ptrs[0], &actions, &attr,
                          ptrs.data(), environ);

  ::posix_spawn_file_actions_destroy(&actions);
  ::posix_spawnattr_destroy(&attr);

  if (rc != 0) {
    cleanup_pipes();
    throw backend::Error(std::string("local_exec: posix_spawnp(\"")
                         + argv[0] + "\") failed: " + std::strerror(rc));
  }

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

ExecResult run_pumped(SpawnedChild       child,
                      const ExecOptions& opts,
                      bool               merge_stderr) {
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

}  // namespace

ExecResult local_exec(const std::vector<std::string>& argv,
                      const ExecOptions&              opts) {
  if (argv.empty()) {
    throw backend::Error("local_exec: empty argv");
  }
  SpawnedChild child = spawn_with_pipes(argv, opts.merge_stderr);
  return run_pumped(std::move(child), opts, opts.merge_stderr);
}

}  // namespace ldb::transport
