// SPDX-License-Identifier: Apache-2.0
#include "daemon/socket_loop.h"

#include "daemon/stdio_loop.h"  // serve_one_connection
#include "protocol/output_channel.h"
#include "util/log.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <streambuf>
#include <string>

namespace ldb::daemon {

namespace {

// File-scope termination flag set by SIGTERM/SIGINT. The accept loop
// polls it between connections; on the main thread we block both
// signals during dispatch so a signal arriving mid-RPC can't interleave
// with the SBAPI calls. The signal handler must touch nothing the
// stdlib doesn't allow from async-signal context — std::atomic<int>
// stores are conformant.
std::atomic<int> g_shutdown{0};

void on_term_signal(int sig) {
  g_shutdown.store(sig, std::memory_order_release);
}

// Minimal fd-backed streambuf: one read buffer, one write buffer, both
// over the same blocking POSIX socket fd. Justification: we already
// have read_message/write_message that take std::istream/std::ostream;
// pulling in __gnu_cxx::stdio_filebuf is a libstdc++-specific escape
// hatch with confusing close semantics. A 200-line streambuf with
// behaviour we control is cheaper to reason about than the fd-bridge in
// the platform ABI.
class FdStreambuf : public std::streambuf {
 public:
  explicit FdStreambuf(int fd) : fd_(fd) {
    setg(read_buf_, read_buf_ + sizeof(read_buf_),
         read_buf_ + sizeof(read_buf_));
    setp(write_buf_, write_buf_ + sizeof(write_buf_));
  }
  ~FdStreambuf() override { sync(); }

  FdStreambuf(const FdStreambuf&)            = delete;
  FdStreambuf& operator=(const FdStreambuf&) = delete;

 protected:
  int_type underflow() override {
    if (gptr() < egptr()) return traits_type::to_int_type(*gptr());
    for (;;) {
      ssize_t n = ::read(fd_, read_buf_, sizeof(read_buf_));
      if (n > 0) {
        setg(read_buf_, read_buf_, read_buf_ + n);
        return traits_type::to_int_type(*gptr());
      }
      if (n == 0) return traits_type::eof();
      if (errno == EINTR) continue;
      return traits_type::eof();
    }
  }

  std::streamsize xsgetn(char_type* s, std::streamsize n) override {
    std::streamsize total = 0;
    while (total < n) {
      if (gptr() == egptr() && underflow() == traits_type::eof()) break;
      std::streamsize avail = egptr() - gptr();
      std::streamsize want = std::min(avail, n - total);
      std::memcpy(s + total, gptr(), static_cast<size_t>(want));
      gbump(static_cast<int>(want));
      total += want;
    }
    return total;
  }

  int_type overflow(int_type ch) override {
    if (sync() != 0) return traits_type::eof();
    if (!traits_type::eq_int_type(ch, traits_type::eof())) {
      *pptr() = traits_type::to_char_type(ch);
      pbump(1);
    }
    return traits_type::not_eof(ch);
  }

  std::streamsize xsputn(const char_type* s, std::streamsize n) override {
    std::streamsize total = 0;
    while (total < n) {
      std::streamsize space = epptr() - pptr();
      if (space == 0) {
        if (sync() != 0) return total;
        space = epptr() - pptr();
      }
      std::streamsize want = std::min(space, n - total);
      std::memcpy(pptr(), s + total, static_cast<size_t>(want));
      pbump(static_cast<int>(want));
      total += want;
    }
    return total;
  }

  int sync() override {
    char* p = pbase();
    while (p < pptr()) {
      ssize_t n = ::write(fd_, p, static_cast<size_t>(pptr() - p));
      if (n > 0) {
        p += n;
        continue;
      }
      if (n < 0 && errno == EINTR) continue;
      // Tear down the buffer so we don't try to re-flush garbage on
      // next sync. The caller's write_message will surface this as a
      // stream failbit; the loop drops the connection.
      setp(write_buf_, write_buf_ + sizeof(write_buf_));
      return -1;
    }
    setp(write_buf_, write_buf_ + sizeof(write_buf_));
    return 0;
  }

 private:
  int fd_;
  char read_buf_[4096];
  char write_buf_[4096];
};

class FdIstream : public std::istream {
 public:
  explicit FdIstream(int fd) : std::istream(&buf_), buf_(fd) {}
 private:
  FdStreambuf buf_;
};

class FdOstream : public std::ostream {
 public:
  explicit FdOstream(int fd) : std::ostream(&buf_), buf_(fd) {}
 private:
  FdStreambuf buf_;
};

// flock-based exclusivity. The lock file lives alongside the socket
// path so an operator running `lsof` or `ls -l` can see who owns it.
// LOCK_NB is critical — without it a stale daemon would block startup
// forever; with it, we get instant EWOULDBLOCK and a clear diagnostic.
// The descriptor is kept open for the daemon's lifetime so the kernel
// holds the lock; closing it releases the lock automatically on exit.
int acquire_lock(const std::string& lock_path) {
  int fd = ::open(lock_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  if (fd < 0) {
    std::cerr << "ldbd: cannot open lock " << lock_path
              << ": " << std::strerror(errno) << "\n";
    return -1;
  }
  if (::flock(fd, LOCK_EX | LOCK_NB) != 0) {
    // Best-effort: tell the user who's holding it. The lock file is
    // not the pid file — the pid we report is what the holder wrote
    // there (if anything). We don't fabricate one if the file is
    // empty.
    std::string holder = "(unknown pid)";
    std::ifstream pf(lock_path);
    std::string line;
    if (pf && std::getline(pf, line) && !line.empty()) {
      holder = "pid " + line;
    }
    std::cerr << "ldbd: another daemon is already listening on "
              << "this socket (" << holder << "); refusing to start\n";
    ::close(fd);
    return -1;
  }
  // Re-stamp the lock with our pid so the next collision can name us.
  // ftruncate+pwrite (rather than fopen) so flock semantics survive.
  ::ftruncate(fd, 0);
  std::string pid = std::to_string(::getpid()) + "\n";
  (void) ::pwrite(fd, pid.data(), pid.size(), 0);
  return fd;
}

bool ensure_parent_dir(const std::string& sock_path) {
  std::filesystem::path p(sock_path);
  auto parent = p.parent_path();
  if (parent.empty() || parent == ".") return true;
  if (std::filesystem::exists(parent)) {
    if (!std::filesystem::is_directory(parent)) {
      std::cerr << "ldbd: parent of socket path is not a directory: "
                << parent << "\n";
      return false;
    }
    return true;
  }
  // Create the dir 0700 atomically. mkdir() honours umask, so save and
  // restore. We only chmod when we created it ourselves — pre-existing
  // parents are the operator's concern.
  mode_t old = ::umask(0);
  int rc = ::mkdir(parent.c_str(), 0700);
  ::umask(old);
  if (rc != 0 && errno != EEXIST) {
    std::cerr << "ldbd: mkdir(" << parent << ") failed: "
              << std::strerror(errno) << "\n";
    return false;
  }
  return true;
}

// Bind a SOCK_STREAM unix socket with the inode landing at mode 0600.
// POSIX bind() honours umask, so we set umask 0077 transiently to make
// the inode 0600 atomically — there's no window where someone could
// open() the socket between bind() and an explicit fchmod().
int bind_listener(const std::string& sock_path) {
  // Refuse paths the kernel can't fit. sun_path is typically 104/108
  // bytes; truncating silently produces a socket at the wrong path,
  // which our smoke tests would catch but real users wouldn't.
  ::sockaddr_un addr{};
  if (sock_path.size() + 1 > sizeof(addr.sun_path)) {
    std::cerr << "ldbd: socket path too long (" << sock_path.size()
              << " bytes > sun_path limit "
              << (sizeof(addr.sun_path) - 1) << ")\n";
    return -1;
  }

  // macOS does not expose SOCK_CLOEXEC; portable path is socket() +
  // fcntl(FD_CLOEXEC). Linux dropped the small race years ago by adding
  // SOCK_CLOEXEC but the two-step form is functionally equivalent on a
  // single-threaded startup path where no other fork happens between
  // the two syscalls.
  int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    std::cerr << "ldbd: socket(): " << std::strerror(errno) << "\n";
    return -1;
  }
  ::fcntl(fd, F_SETFD, FD_CLOEXEC);

  // Stale socket cleanup. We hold the flock at this point, so any
  // pre-existing inode is either a leftover from a crashed daemon
  // (safe to remove) or an unrelated file (rare). Unlink is the only
  // way to make bind() succeed on a path with an existing socket
  // inode.
  ::unlink(sock_path.c_str());

  addr.sun_family = AF_UNIX;
  std::memcpy(addr.sun_path, sock_path.c_str(), sock_path.size());

  mode_t old = ::umask(0077);
  int rc = ::bind(fd, reinterpret_cast<::sockaddr*>(&addr), sizeof(addr));
  int bind_errno = errno;
  ::umask(old);
  if (rc != 0) {
    std::cerr << "ldbd: bind(" << sock_path << "): "
              << std::strerror(bind_errno) << "\n";
    ::close(fd);
    return -1;
  }

  // Defensive chmod — some filesystems (e.g. tmpfs over NFS) ignore
  // umask. Cheap, idempotent, and a wrong-perms socket is a security
  // bug we don't want to discover in production.
  if (::chmod(sock_path.c_str(), 0600) != 0) {
    std::cerr << "ldbd: chmod(" << sock_path << ", 0600): "
              << std::strerror(errno) << "\n";
    ::close(fd);
    ::unlink(sock_path.c_str());
    return -1;
  }

  if (::listen(fd, 4) != 0) {
    std::cerr << "ldbd: listen(): " << std::strerror(errno) << "\n";
    ::close(fd);
    ::unlink(sock_path.c_str());
    return -1;
  }
  return fd;
}

void install_signal_handlers() {
  struct sigaction sa{};
  sa.sa_handler = on_term_signal;
  sa.sa_flags = 0;  // No SA_RESTART — we want accept() to return EINTR.
  sigemptyset(&sa.sa_mask);
  ::sigaction(SIGTERM, &sa, nullptr);
  ::sigaction(SIGINT,  &sa, nullptr);

  // A peer closing mid-write would otherwise kill the daemon via
  // SIGPIPE. Ignoring it converts the failure into an EPIPE on
  // write(), which the streambuf surfaces as a stream failbit; the
  // connection is dropped and the loop continues.
  struct sigaction ign{};
  ign.sa_handler = SIG_IGN;
  sigemptyset(&ign.sa_mask);
  ::sigaction(SIGPIPE, &ign, nullptr);
}

}  // namespace

int run_socket_listener(Dispatcher& dispatcher,
                        const std::string& sock_path,
                        protocol::WireFormat fmt) {
  if (!ensure_parent_dir(sock_path)) return 1;

  const std::string lock_path = sock_path + ".lock";
  int lock_fd = acquire_lock(lock_path);
  if (lock_fd < 0) return 1;

  int srv = bind_listener(sock_path);
  if (srv < 0) {
    ::close(lock_fd);
    return 1;
  }

  install_signal_handlers();

  log::info("listening on unix:" + sock_path +
            " (format=" +
            (fmt == protocol::WireFormat::kCbor ? "cbor" : "json") + ")");

  while (g_shutdown.load(std::memory_order_acquire) == 0) {
    ::sockaddr_un peer{};
    socklen_t peer_len = sizeof(peer);
    int conn = ::accept(srv, reinterpret_cast<::sockaddr*>(&peer), &peer_len);
    if (conn < 0) {
      if (errno == EINTR) continue;
      log::error(std::string("accept: ") + std::strerror(errno));
      continue;
    }
    ::fcntl(conn, F_SETFD, FD_CLOEXEC);

    FdIstream  in(conn);
    FdOstream  out_stream(conn);
    protocol::OutputChannel out(out_stream, fmt);

    // The dispatcher's notification sink is shared across the daemon's
    // lifetime in stdio mode; in listen mode we re-point it at the
    // per-connection OutputChannel so async notifications go to the
    // current client. Phase 1 has at most one connection alive, so
    // this re-pointing is race-free. Phase 2 will need per-connection
    // sinks plumbed through the dispatcher.
    protocol::StreamNotificationSink sink(out);
    dispatcher.set_notification_sink(&sink);

    (void) serve_one_connection(dispatcher, out, in, fmt);

    dispatcher.set_notification_sink(nullptr);
    ::close(conn);
    log::debug("client disconnected; awaiting next");
  }

  log::info("shutdown signal received; closing listener");
  ::close(srv);
  ::unlink(sock_path.c_str());
  ::close(lock_fd);
  ::unlink(lock_path.c_str());
  return 0;
}

}  // namespace ldb::daemon
