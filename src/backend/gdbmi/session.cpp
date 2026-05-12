// SPDX-License-Identifier: Apache-2.0
#include "backend/gdbmi/session.h"

#include "util/log.h"

#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

namespace ldb::backend::gdbmi {

namespace {

// Read one line from `fd` into `out`, stripping the trailing '\n'.
// Returns false on EOF or error. Reads byte-at-a-time — slow, but
// the parent is one-line-per-iteration anyway and we want the EOF
// boundary handled cleanly without a re-fill buffer.
bool read_line(int fd, std::string& out) {
  out.clear();
  char c;
  while (true) {
    ssize_t n = ::read(fd, &c, 1);
    if (n == 0) return !out.empty();   // EOF after data is still a line
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (c == '\n') return true;
    out.push_back(c);
  }
}

bool write_all(int fd, const std::string& s) {
  const char* p = s.data();
  std::size_t left = s.size();
  while (left > 0) {
    ssize_t n = ::write(fd, p, left);
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    p += n;
    left -= static_cast<std::size_t>(n);
  }
  return true;
}

}  // namespace

GdbMiSession::GdbMiSession() = default;

GdbMiSession::~GdbMiSession() {
  shutdown();
}

bool GdbMiSession::is_running() const {
  return pid_ > 0 && !reader_eof_;
}

bool GdbMiSession::start() {
  int in_pipe[2], out_pipe[2], err_pipe[2];
  if (::pipe(in_pipe) < 0)  return false;
  if (::pipe(out_pipe) < 0) { ::close(in_pipe[0]); ::close(in_pipe[1]); return false; }
  if (::pipe(err_pipe) < 0) {
    ::close(in_pipe[0]); ::close(in_pipe[1]);
    ::close(out_pipe[0]); ::close(out_pipe[1]);
    return false;
  }

  pid_t pid = ::fork();
  if (pid < 0) return false;

  if (pid == 0) {
    // Child: wire stdin/out/err to the pipes and exec gdb.
    ::dup2(in_pipe[0], STDIN_FILENO);
    ::dup2(out_pipe[1], STDOUT_FILENO);
    ::dup2(err_pipe[1], STDERR_FILENO);
    ::close(in_pipe[0]); ::close(in_pipe[1]);
    ::close(out_pipe[0]); ::close(out_pipe[1]);
    ::close(err_pipe[0]); ::close(err_pipe[1]);
    // Suppress the banner and skip user init files so the daemon's
    // command flow is reproducible across hosts.
    ::execlp("gdb", "gdb",
             "--interpreter=mi3",
             "--quiet",
             "--silent",
             "--nx",
             nullptr);
    // exec failed; nothing useful to do — die quietly.
    ::_exit(127);
  }

  // Parent.
  ::close(in_pipe[0]);
  ::close(out_pipe[1]);
  ::close(err_pipe[1]);
  pid_       = pid;
  stdin_fd_  = in_pipe[1];
  stdout_fd_ = out_pipe[0];
  stderr_fd_ = err_pipe[0];

  reader_ = std::thread([this] { reader_loop(); });

  // Wait up to 5 s for the first (gdb) prompt — signals readiness.
  using clock = std::chrono::steady_clock;
  const auto deadline = clock::now() + std::chrono::seconds(5);
  std::unique_lock<std::mutex> lk(mu_);
  cv_.wait_until(lk, deadline, [this] { return ready_ || reader_eof_.load(); });
  return ready_;
}

void GdbMiSession::shutdown() {
  if (pid_ <= 0) return;
  if (!shutting_down_.exchange(true)) {
    // Best-effort graceful exit: send `-gdb-exit` if stdin is still
    // writable. If the subprocess already died, the write may fail —
    // that's fine, the SIGTERM path will reap it.
    (void)write_all(stdin_fd_, "-gdb-exit\n");
  }

  // Wait up to 500 ms for graceful termination.
  auto wait_ms = [this](int ms) {
    for (int i = 0; i < ms / 10; ++i) {
      int status = 0;
      pid_t r = ::waitpid(pid_, &status, WNOHANG);
      if (r == pid_) return true;
      if (r < 0 && errno != EINTR) return true;  // already reaped
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return false;
  };

  if (!wait_ms(500)) {
    ::kill(pid_, SIGTERM);
    if (!wait_ms(500)) {
      ::kill(pid_, SIGKILL);
      int status = 0;
      ::waitpid(pid_, &status, 0);
    }
  }
  pid_ = -1;

  if (stdin_fd_  >= 0) { ::close(stdin_fd_);  stdin_fd_  = -1; }
  if (stdout_fd_ >= 0) { ::close(stdout_fd_); stdout_fd_ = -1; }
  if (stderr_fd_ >= 0) { ::close(stderr_fd_); stderr_fd_ = -1; }

  if (reader_.joinable()) reader_.join();
}

void GdbMiSession::deliver_result(MiRecord r) {
  std::lock_guard<std::mutex> lk(mu_);
  if (r.token.has_value() && !pending_.empty() &&
      pending_.front().token == *r.token) {
    pending_.front().response = std::move(r);
    pending_.front().ready = true;
    cv_.notify_all();
    return;
  }
  // Untokenized result (e.g. ^done from `-gdb-exit` itself) — match
  // the oldest pending request regardless.
  if (!pending_.empty()) {
    pending_.front().response = std::move(r);
    pending_.front().ready = true;
    cv_.notify_all();
    return;
  }
  // No waiter — treat as async-equivalent.
  async_queue_.push_back(std::move(r));
}

void GdbMiSession::reader_loop() {
  std::string line;
  while (true) {
    if (!read_line(stdout_fd_, line)) {
      reader_eof_ = true;
      std::lock_guard<std::mutex> lk(mu_);
      // Unblock any pending waiter so it sees nullopt rather than
      // hang forever.
      for (auto& p : pending_) p.ready = true;
      cv_.notify_all();
      return;
    }
    auto rec = parse_line(line);
    if (!rec.has_value()) {
      log::warn(std::string("gdbmi: unparseable line: ") + line);
      continue;
    }
    switch (rec->kind) {
      case MiRecordKind::kPrompt: {
        std::lock_guard<std::mutex> lk(mu_);
        ready_ = true;
        cv_.notify_all();
        break;
      }
      case MiRecordKind::kResult:
        deliver_result(std::move(*rec));
        break;
      default: {
        // Async + stream records: queue them. drain_async lets the
        // backend retrieve them between commands.
        std::lock_guard<std::mutex> lk(mu_);
        async_queue_.push_back(std::move(*rec));
        break;
      }
    }
  }
}

std::optional<MiRecord> GdbMiSession::send_command(const std::string& cmd) {
  if (!is_running()) return std::nullopt;

  std::uint64_t token;
  {
    std::lock_guard<std::mutex> lk(mu_);
    token = next_token_++;
    pending_.push_back(PendingRequest{token, std::nullopt, false});
  }

  // Strip leading whitespace and ensure the command starts with a
  // dash; bare CLI commands aren't tokenable in MI but we still want
  // to allow them as a fall-through (rare, used for `info proc
  // mappings` etc.). For CLI fall-through we don't prepend a token —
  // gdb echoes the result on ^done without a token, and our deliver
  // path matches the oldest waiter as a fallback.
  std::string body = cmd;
  while (!body.empty() && (body.front() == ' ' || body.front() == '\t')) {
    body.erase(0, 1);
  }
  std::string line;
  if (!body.empty() && body.front() == '-') {
    line = std::to_string(token) + body + "\n";
  } else {
    line = body + "\n";
  }

  if (!write_all(stdin_fd_, line)) {
    std::lock_guard<std::mutex> lk(mu_);
    pending_.pop_back();
    return std::nullopt;
  }

  // Wait for the matching response. 30 s is a generous ceiling for
  // any individual MI command; pathological cases (huge disasm of a
  // statically-linked binary) may push toward this, and a hang here
  // would freeze the dispatcher.
  using clock = std::chrono::steady_clock;
  const auto deadline = clock::now() + std::chrono::seconds(30);
  std::optional<MiRecord> resp;
  std::unique_lock<std::mutex> lk(mu_);
  while (!pending_.front().ready && !reader_eof_.load()) {
    if (cv_.wait_until(lk, deadline) == std::cv_status::timeout) break;
  }
  if (pending_.front().ready) {
    resp = std::move(pending_.front().response);
  }
  pending_.pop_front();
  return resp;
}

std::vector<MiRecord> GdbMiSession::drain_async() {
  std::lock_guard<std::mutex> lk(mu_);
  std::vector<MiRecord> out;
  out.swap(async_queue_);
  return out;
}

}  // namespace ldb::backend::gdbmi
