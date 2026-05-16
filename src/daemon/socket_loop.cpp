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
//
// Failure semantics: once a write fails (closed-mid-write peer, EPIPE,
// truncated tmpfs), `write_failed_` latches true. All subsequent
// sync/overflow/xsputn calls short-circuit, returning -1 / eof / 0
// without re-attempting the syscall. FdOstream observes the latch in
// its overrides and sets `badbit` on the parent ostream so callers'
// `out.flush()` and `out << ...` reliably report failure. Without
// this latch a sync that scrubs the buffer would let the NEXT flush
// "succeed" (nothing to write), masking the original write failure
// and pinning the daemon in a write-to-dead-peer loop.
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

  bool write_failed() const noexcept { return write_failed_; }

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
    if (write_failed_) return traits_type::eof();
    if (sync() != 0) return traits_type::eof();
    if (!traits_type::eq_int_type(ch, traits_type::eof())) {
      *pptr() = traits_type::to_char_type(ch);
      pbump(1);
    }
    return traits_type::not_eof(ch);
  }

  std::streamsize xsputn(const char_type* s, std::streamsize n) override {
    if (write_failed_) return 0;
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
    if (write_failed_) return -1;
    char* p = pbase();
    while (p < pptr()) {
      ssize_t n = ::write(fd_, p, static_cast<size_t>(pptr() - p));
      if (n > 0) {
        p += n;
        continue;
      }
      if (n < 0 && errno == EINTR) continue;
      // Latch and scrub. Subsequent sync/overflow/xsputn short-
      // circuit, so write_response sees a stream failbit on the
      // NEXT attempt instead of silently retrying forever.
      write_failed_ = true;
      setp(write_buf_, write_buf_ + sizeof(write_buf_));
      return -1;
    }
    setp(write_buf_, write_buf_ + sizeof(write_buf_));
    return 0;
  }

 private:
  int fd_;
  bool write_failed_ = false;
  char read_buf_[4096];
  char write_buf_[4096];
};

class FdIstream : public std::istream {
 public:
  explicit FdIstream(int fd) : std::istream(&buf_), buf_(fd) {}
 private:
  FdStreambuf buf_;
};

// FdOstream forwards write failure from the underlying streambuf to
// the ostream's iostate so callers' `out.flush()` and `out << ...`
// observe `badbit`. The streambuf base does this for short xsputn
// returns automatically, but flush() can succeed when the buffer is
// already drained — once we've latched a write failure we re-flag it
// on every flush.
class FdOstream : public std::ostream {
 public:
  explicit FdOstream(int fd) : std::ostream(&buf_), buf_(fd) {}

  // Wrap flush so a previously-latched write failure shows up as
  // badbit even if the buffer happens to be empty.
  std::ostream& flush() {
    std::ostream::flush();
    if (buf_.write_failed()) setstate(std::ios::badbit);
    return *this;
  }

 private:
  FdStreambuf buf_;
};

// flock-based exclusivity on a sidecar lockfile. flock is the
// exclusivity mechanism (the kernel releases the lock when the holder
// dies, so stale lockfiles from crashed daemons stay reusable). The
// pid we stamp into the file is best-effort diagnostic only — used
// by the next colliding daemon to name the holder in stderr.
//
// O_NOFOLLOW: a same-uid attacker who pre-creates ${PATH}.lock as a
// symlink to e.g. ~/.ssh/authorized_keys would otherwise have our
// ftruncate+pwrite corrupt the symlink target. ELOOP is fatal —
// refuse to start rather than try to disambiguate.
int acquire_lock(const std::string& lock_path) {
  int fd = ::open(lock_path.c_str(),
                  O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0) {
    if (errno == ELOOP) {
      std::cerr << "ldbd: refusing to open lock path through symlink: "
                << lock_path << "\n";
    } else {
      std::cerr << "ldbd: cannot open lock " << lock_path
                << ": " << std::strerror(errno) << "\n";
    }
    return -1;
  }
  if (::flock(fd, LOCK_EX | LOCK_NB) != 0) {
    // Best-effort: tell the user who's holding it. We don't
    // fabricate a pid if the file is empty.
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

// Validate (or create) the socket's parent dir. The validation uses
// ::lstat() rather than std::filesystem::exists/is_directory because
// the latter follow symlinks — a same-uid attacker pre-creating the
// parent as a symlink to a sensitive directory would otherwise trick
// the daemon into bind()ing inside the symlink target. The phase-1
// trust model (docs/35-field-report-followups.md §2 "Trust model")
// assumes the uid is a single trust domain; the symlink/uid/mode
// guards here defend against accidental misconfiguration, not a
// cross-uid attacker.
bool ensure_parent_dir(const std::string& sock_path) {
  std::filesystem::path p(sock_path);
  auto parent = p.parent_path();
  if (parent.empty() || parent == ".") return true;

  struct stat st{};
  if (::lstat(parent.c_str(), &st) == 0) {
    if (S_ISLNK(st.st_mode)) {
      std::cerr << "ldbd: refusing socket parent that is a symlink: "
                << parent << "\n";
      return false;
    }
    if (!S_ISDIR(st.st_mode)) {
      std::cerr << "ldbd: parent of socket path is not a directory: "
                << parent << "\n";
      return false;
    }
    if (st.st_uid != ::geteuid()) {
      std::cerr << "ldbd: refusing socket parent owned by uid "
                << st.st_uid << " (expected " << ::geteuid() << "): "
                << parent << "\n";
      return false;
    }
    if ((st.st_mode & 0077) != 0) {
      std::cerr << "ldbd: refusing socket parent with group/other "
                << "permission bits set (mode 0"
                << std::oct << (st.st_mode & 0777) << std::dec
                << "): " << parent << "\n";
      return false;
    }
    return true;
  }
  if (errno != ENOENT) {
    std::cerr << "ldbd: lstat(" << parent << "): "
              << std::strerror(errno) << "\n";
    return false;
  }
  // Create the dir 0700 atomically. umask(0077) makes the inode land
  // at 0700 even if mkdir's mode argument is widened by an inherited
  // umask. The atomicity here only holds because daemon startup is
  // single-threaded — a sibling thread changing umask mid-call would
  // break it.
  mode_t old = ::umask(0077);
  int rc = ::mkdir(parent.c_str(), 0700);
  int mkdir_errno = errno;
  ::umask(old);
  if (rc != 0 && mkdir_errno != EEXIST) {
    std::cerr << "ldbd: mkdir(" << parent << ") failed: "
              << std::strerror(mkdir_errno) << "\n";
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
  // Copy the trailing NUL too. addr is brace-initialized to zero, so
  // sun_path[size] is already 0 — but copying size+1 makes the
  // contract explicit and impossible to silently break in a future
  // refactor.
  std::memcpy(addr.sun_path, sock_path.c_str(), sock_path.size() + 1);

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
  // umask. fchmod on the listener fd closes a tiny TOCTOU window
  // where an FS filter could replace the inode between bind() and a
  // path-based chmod, so we try it first. macOS rejects fchmod() on
  // AF_UNIX socket fds with EINVAL; on that platform we fall back to
  // path-based chmod, which is still defended by the umask(0077)
  // trick above making the bind() inode land at 0600 atomically.
  if (::fchmod(fd, 0600) != 0) {
    int fchmod_errno = errno;
    if (fchmod_errno == EINVAL || fchmod_errno == ENOTSUP) {
      if (::chmod(sock_path.c_str(), 0600) != 0) {
        std::cerr << "ldbd: chmod(" << sock_path << ", 0600): "
                  << std::strerror(errno) << "\n";
        ::close(fd);
        ::unlink(sock_path.c_str());
        return -1;
      }
    } else {
      std::cerr << "ldbd: fchmod(socket fd, 0600): "
                << std::strerror(fchmod_errno) << "\n";
      ::close(fd);
      ::unlink(sock_path.c_str());
      return -1;
    }
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

    // Phase-1 trust model is uid-only: even though the socket inode
    // is 0600, a defense-in-depth peer-cred check rejects any caller
    // whose uid differs from ours. getpeereid() is portable across
    // macOS and Linux; on Linux it wraps SO_PEERCRED, on macOS it
    // wraps LOCAL_PEERCRED.
    uid_t peer_uid = 0;
    gid_t peer_gid = 0;
    if (::getpeereid(conn, &peer_uid, &peer_gid) != 0) {
      log::error(std::string("getpeereid: ") + std::strerror(errno));
      ::close(conn);
      continue;
    }
    if (peer_uid != ::geteuid()) {
      log::error("rejecting connection from uid " +
                 std::to_string(peer_uid) +
                 " (daemon uid is " + std::to_string(::geteuid()) + ")");
      ::close(conn);
      continue;
    }

    // 5-minute receive timeout. If a peer attaches and then stalls
    // mid-message, we want the dispatcher thread back rather than
    // pinned forever. read(2) returning -1/EAGAIN is surfaced by
    // FdStreambuf::underflow as traits_type::eof(), which cleanly
    // closes the connection in serve_one_connection.
    ::timeval rcv_timeout{};
    rcv_timeout.tv_sec  = 300;
    rcv_timeout.tv_usec = 0;
    if (::setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO,
                     &rcv_timeout, sizeof(rcv_timeout)) != 0) {
      log::warn(std::string("setsockopt(SO_RCVTIMEO): ") +
                std::strerror(errno));
    }

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
