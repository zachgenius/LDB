// SPDX-License-Identifier: Apache-2.0
#include "daemon/socket_loop.h"

#include "daemon/stdio_loop.h"  // serve_one_connection
#include "protocol/output_channel.h"
#include "util/log.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

// Peer-credential retrieval is platform-specific. BSDs ship getpeereid;
// Linux glibc/musl don't, but expose SO_PEERCRED via getsockopt.
#if defined(__linux__)
#  include <sys/socket.h>  // for SO_PEERCRED + struct ucred
#endif

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <list>
#include <mutex>
#include <streambuf>
#include <string>
#include <thread>

namespace ldb::daemon {

namespace {

// File-scope termination flag set by SIGTERM/SIGINT or by the
// `daemon.shutdown` RPC. The accept loop's poll() wakes on either the
// listener fd OR the self-pipe; once g_shutdown is non-zero it exits
// the loop. The signal handler must touch nothing the stdlib doesn't
// allow from async-signal context — std::atomic<int> stores and the
// write(2) to g_shutdown_pipe_write are both conformant.
//
// Explicit `static` (alongside the surrounding anonymous namespace) so
// the file-scope intent is unambiguous to readers and to any future
// refactor that flattens the namespace.
static std::atomic<int> g_shutdown{0};

// Self-pipe pattern for signal-driven accept-loop wake-up. The write
// end is closed-on-fork (FD_CLOEXEC); the signal handler writes a
// single byte to it so poll() returns POLLIN on the read end and the
// loop notices the shutdown flag without the race that plain
// "g_shutdown.load() inside accept()" would have on a multi-second
// hung RPC. -1 sentinel means "not initialised yet" — the signal
// handler checks before calling write so an early signal during
// startup is a no-op (the loop hasn't started running anyway).
//
// Post-review N3: the write end is now `std::atomic<int>` rather
// than a plain int read directly out of the array. On aligned-int
// aarch64 the unrelaxed read is harmless in practice — but the
// signal-handler ↔ main-thread synchronisation is a relaxed atomic
// store/load by spec, so this gets us strict conformance without
// changing the observable behaviour.
static int g_shutdown_pipe[2] = {-1, -1};
static std::atomic<int> g_shutdown_pipe_write{-1};

static void on_term_signal(int sig) {
  g_shutdown.store(sig, std::memory_order_release);
  // N3: load once. Re-reading the global between the >=0 check and
  // the write() would let a concurrent teardown (main thread closing
  // the pipe in run_socket_listener's tail) sneak a -1 in between.
  int wfd = g_shutdown_pipe_write.load(std::memory_order_acquire);
  if (wfd >= 0) {
    const char byte = 'q';
    // Best-effort write; an already-full pipe (multiple signals
    // coalesced) is fine — one byte is enough to wake poll().
    // write() in a signal handler is async-signal-safe per POSIX.
    (void) ::write(wfd, &byte, 1);
  }
}

// Post-review I4: atomic single-line stderr writer. The auto-spawn
// race in §2 phase-2 produces multiple daemon processes that all
// race to bind the same socket; the losers write diagnostic lines
// to the same stderr / log file. Multiple `std::cerr << "ldbd: ..."
// << ... << "\n"` calls expand into multiple `write(2)` syscalls,
// and concurrent processes can interleave them — operators see
// "ldbd: another daemon is already lis ldbd: another daemon is alr"
// instead of two clean lines.
//
// Building the line as a single std::string and writing it with one
// fwrite gets us a single write(2) per line. POSIX guarantees a
// write of ≤PIPE_BUF bytes (typically 512) to a regular file is
// atomic w.r.t. other writers; our lines fit comfortably.
static void log_err_line(const std::string& s) {
  std::fwrite(s.data(), 1, s.size(), stderr);
  // No explicit flush — stderr is line-buffered by default; our
  // newline-terminated line flushes implicitly. Calling fflush
  // is a no-op for unbuffered streams and would add a syscall
  // for stream variants that ARE buffered.
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
      log_err_line("ldbd: refusing to open lock path through symlink: "
                   + lock_path + "\n");
    } else {
      log_err_line("ldbd: cannot open lock " + lock_path + ": "
                   + std::strerror(errno) + "\n");
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
    log_err_line("ldbd: another daemon is already listening on "
                 "this socket (" + holder + "); refusing to start\n");
    ::close(fd);
    return -1;
  }
  // Re-stamp the lock with our pid so the next collision can name us.
  // ftruncate+pwrite (rather than fopen) so flock semantics survive.
  // Both calls are best-effort — a failed pid stamp degrades the
  // collision diagnostic but is not fatal. Explicit ignore via assigning
  // to (void)-cast lvalue silences gcc's -Wunused-result (which a bare
  // cast does NOT on __attribute__((warn_unused_result)) declarations).
  if (::ftruncate(fd, 0) != 0) { /* best-effort */ }
  std::string pid = std::to_string(::getpid()) + "\n";
  if (::pwrite(fd, pid.data(), pid.size(), 0) < 0) { /* best-effort */ }
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
      log_err_line("ldbd: refusing socket parent that is a symlink: "
                   + parent.string() + "\n");
      return false;
    }
    if (!S_ISDIR(st.st_mode)) {
      log_err_line("ldbd: parent of socket path is not a directory: "
                   + parent.string() + "\n");
      return false;
    }
    if (st.st_uid != ::geteuid()) {
      log_err_line("ldbd: refusing socket parent owned by uid "
                   + std::to_string(st.st_uid) + " (expected "
                   + std::to_string(::geteuid()) + "): "
                   + parent.string() + "\n");
      return false;
    }
    if ((st.st_mode & 0077) != 0) {
      char mode_str[8];
      std::snprintf(mode_str, sizeof(mode_str), "%o", st.st_mode & 0777);
      log_err_line("ldbd: refusing socket parent with group/other "
                   "permission bits set (mode 0"
                   + std::string(mode_str) + "): "
                   + parent.string() + "\n");
      return false;
    }
    return true;
  }
  if (errno != ENOENT) {
    log_err_line("ldbd: lstat(" + parent.string() + "): "
                 + std::strerror(errno) + "\n");
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
    log_err_line("ldbd: mkdir(" + parent.string() + ") failed: "
                 + std::strerror(mkdir_errno) + "\n");
    return false;
  }
  return true;
}

// Bind a SOCK_STREAM unix socket with the inode landing at mode 0600.
// POSIX bind() honours umask. The kernel-supplied mode for AF_UNIX
// bind is 0777 (both Linux unix_bind_bsd and BSD/Darwin uipc_bind),
// so an umask of 0177 yields 0600 atomically — no window where the
// inode is more permissive than 0600 between bind() and any later
// chmod. Earlier comments here claimed umask 0077 was sufficient,
// relying on a defensive fchmod(fd, 0600) to tighten the mode. That
// doesn't work on Linux: socket fds are backed by sockfs (anonymous
// inode), so fchmod returns success but modifies the sockfs inode,
// not the on-disk inode bind() created — leaving the on-disk socket
// at 0700. The atomicity claim only holds because daemon startup is
// single-threaded; a sibling thread changing umask mid-call would
// void it.
int bind_listener(const std::string& sock_path) {
  // Refuse paths the kernel can't fit. sun_path is typically 104/108
  // bytes; truncating silently produces a socket at the wrong path,
  // which our smoke tests would catch but real users wouldn't.
  ::sockaddr_un addr{};
  if (sock_path.size() + 1 > sizeof(addr.sun_path)) {
    log_err_line("ldbd: socket path too long ("
                 + std::to_string(sock_path.size())
                 + " bytes > sun_path limit "
                 + std::to_string(sizeof(addr.sun_path) - 1)
                 + ")\n");
    return -1;
  }

  // macOS does not expose SOCK_CLOEXEC; portable path is socket() +
  // fcntl(FD_CLOEXEC). Linux dropped the small race years ago by adding
  // SOCK_CLOEXEC but the two-step form is functionally equivalent on a
  // single-threaded startup path where no other fork happens between
  // the two syscalls.
  int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    log_err_line(std::string("ldbd: socket(): ")
                 + std::strerror(errno) + "\n");
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

  mode_t old = ::umask(0177);
  int rc = ::bind(fd, reinterpret_cast<::sockaddr*>(&addr), sizeof(addr));
  int bind_errno = errno;
  ::umask(old);
  if (rc != 0) {
    log_err_line("ldbd: bind(" + sock_path + "): "
                 + std::strerror(bind_errno) + "\n");
    ::close(fd);
    return -1;
  }

  // Defensive chmod — some filesystems (e.g. tmpfs over NFS) ignore
  // umask. On Linux the listener fd refers to an anonymous sockfs
  // inode rather than the on-disk inode bind() created, so fchmod
  // here is a no-op for our purposes (it returns 0 but doesn't
  // change the on-disk mode); we still try it because on BSDs the
  // socket fd's inode is on-disk and fchmod is a smaller TOCTOU
  // window than the path-based chmod. macOS rejects fchmod() on
  // AF_UNIX socket fds with EINVAL; on that platform we fall back
  // to path-based chmod. With umask(0177) above making the bind()
  // inode land at 0600 atomically, this is pure defence in depth.
  if (::fchmod(fd, 0600) != 0) {
    int fchmod_errno = errno;
    if (fchmod_errno == EINVAL || fchmod_errno == ENOTSUP) {
      if (::chmod(sock_path.c_str(), 0600) != 0) {
        log_err_line("ldbd: chmod(" + sock_path + ", 0600): "
                     + std::strerror(errno) + "\n");
        ::close(fd);
        ::unlink(sock_path.c_str());
        return -1;
      }
    } else {
      log_err_line(std::string("ldbd: fchmod(socket fd, 0600): ")
                   + std::strerror(fchmod_errno) + "\n");
      ::close(fd);
      ::unlink(sock_path.c_str());
      return -1;
    }
  }

  if (::listen(fd, 4) != 0) {
    log_err_line(std::string("ldbd: listen(): ")
                 + std::strerror(errno) + "\n");
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

// §2 phase 2 — live worker count. Incremented on accept(), decremented
// on serve_socket_client exit. Read by the accept loop to gate the
// idle-timeout shutdown — the timeout fires only when no workers
// are alive, so a long-lived but idle connection doesn't get the
// daemon pulled out from under it.
static std::atomic<int> g_live_workers{0};

// §2 phase 2 — per-connection worker. Owns the connection fd for its
// entire lifetime: registers a per-connection notification sink with
// the dispatcher, runs serve_one_connection until the peer closes,
// deregisters the sink, closes the fd. Designed to run on its own
// std::thread so multiple connections execute concurrently. The
// dispatcher itself serialises through its internal mutex (see
// Dispatcher::dispatch); the per-connection workers contend on that
// mutex only when overlapping in actual RPC service.
void serve_socket_client(Dispatcher* dispatcher,
                         int conn,
                         protocol::WireFormat fmt) {
  FdIstream  in(conn);
  FdOstream  out_stream(conn);
  protocol::OutputChannel out(out_stream, fmt);

  // Post-review C1: heap-allocate the per-connection sink via
  // std::make_shared so a concurrent listener-thread emit_stopped_
  // can't UAF on a stack-local. The dispatcher / NonStopRuntime
  // holds a strong ref for the duration of the registration; the
  // emitter's snapshot bumps the count for the duration of the
  // delivery. When remove_notification_sink runs here, the runtime
  // drops its ref but any in-flight emit still has its snapshot's
  // ref — the sink destructs cleanly on the LAST ref drop.
  auto sink = std::make_shared<protocol::StreamNotificationSink>(out);
  auto sub = dispatcher->add_notification_sink(sink);

  // Post-review I2 — pass the shutdown gate to serve_one_connection
  // so an already-connected peer can't keep sending RPCs after
  // daemon.shutdown / SIGTERM and have them serviced. The lambda
  // closes over the file-scope g_shutdown flag; once that's set,
  // the worker emits a kBadState response on the NEXT read and
  // exits, letting the accept loop's join unblock promptly.
  auto shutdown_gate = []() {
    return g_shutdown.load(std::memory_order_acquire) != 0;
  };
  (void) serve_one_connection(*dispatcher, out, in, fmt, shutdown_gate);

  dispatcher->remove_notification_sink(sub);
  // sink (the local shared_ptr) drops its ref here; if any listener
  // still holds a snapshot ref, the sink stays alive until that
  // emit() returns and the snapshot vector destructs.
  sink.reset();
  ::close(conn);
  g_live_workers.fetch_sub(1, std::memory_order_release);
  // Wake the accept loop's poll() so it re-evaluates the idle
  // timeout. Without this, a worker that exits right after the
  // idle window starts would leave the daemon polling with the
  // (now-elapsed) timeout still in flight; on Linux this is
  // resolved by the next poll iteration, but on macOS poll's
  // timeout is preserved across spurious wakes, so without an
  // explicit wake the loop would always sit out the full window.
  int wfd = g_shutdown_pipe_write.load(std::memory_order_acquire);
  if (wfd >= 0) {
    const char byte = 'w';
    (void) ::write(wfd, &byte, 1);
  }
  log::debug("client disconnected");
}

}  // namespace

int run_socket_listener(Dispatcher& dispatcher,
                        const std::string& sock_path,
                        protocol::WireFormat fmt,
                        int idle_timeout_sec) {
  if (!ensure_parent_dir(sock_path)) return 1;

  const std::string lock_path = sock_path + ".lock";
  int lock_fd = acquire_lock(lock_path);
  if (lock_fd < 0) return 1;

  int srv = bind_listener(sock_path);
  if (srv < 0) {
    ::close(lock_fd);
    return 1;
  }

  // Self-pipe for signal-driven and daemon.shutdown-driven wake-up.
  // Both ends are CLOEXEC so a forked subprocess (we don't fork
  // today but might in the future) doesn't inherit the file
  // descriptor. The pipe is non-blocking on write because the
  // signal handler must not stall — if the pipe is full (multiple
  // signals in flight), the write fails with EAGAIN and we lose a
  // wake-up, but the EARLIER write already set g_shutdown so the
  // loop will exit on its next pass anyway.
  if (::pipe(g_shutdown_pipe) != 0) {
    log::error(std::string("pipe(): ") + std::strerror(errno));
    ::close(srv);
    ::unlink(sock_path.c_str());
    ::close(lock_fd);
    return 1;
  }
  ::fcntl(g_shutdown_pipe[0], F_SETFD, FD_CLOEXEC);
  ::fcntl(g_shutdown_pipe[1], F_SETFD, FD_CLOEXEC);
  // Both ends non-blocking. Write end so the signal handler can't
  // deadlock if the kernel pipe is full (multiple signals
  // coalesced). Read end so the drain loop's terminating read
  // returns EAGAIN instead of blocking — without that the loop
  // hangs after consuming the single wake-up byte, because the
  // pipe is now empty and the next read() would block until more
  // data arrives.
  {
    int fl0 = ::fcntl(g_shutdown_pipe[0], F_GETFL);
    if (fl0 >= 0) ::fcntl(g_shutdown_pipe[0], F_SETFL, fl0 | O_NONBLOCK);
    int fl1 = ::fcntl(g_shutdown_pipe[1], F_GETFL);
    if (fl1 >= 0) ::fcntl(g_shutdown_pipe[1], F_SETFL, fl1 | O_NONBLOCK);
  }
  // Publish the write end atomically AFTER FD_CLOEXEC + O_NONBLOCK
  // are in place. The signal handler reads this atomic and only
  // touches the fd through the snapshot it loaded — the close-then-
  // -1 teardown in the tail of this function uses release-store -1
  // so a late signal arriving during shutdown sees the sentinel and
  // skips the write. (N3.)
  g_shutdown_pipe_write.store(g_shutdown_pipe[1], std::memory_order_release);

  // `daemon.shutdown` RPC handler invokes this. We push a byte into
  // the self-pipe to wake the accept loop; g_shutdown is set in
  // both this path and the signal handler so the loop notices on
  // its next wake-up regardless of who fired.
  dispatcher.set_shutdown_callback([]() {
    g_shutdown.store(1, std::memory_order_release);
    int wfd = g_shutdown_pipe_write.load(std::memory_order_acquire);
    if (wfd >= 0) {
      const char byte = 'q';
      (void) ::write(wfd, &byte, 1);
    }
  });

  install_signal_handlers();

  log::info("listening on unix:" + sock_path +
            " (format=" +
            (fmt == protocol::WireFormat::kCbor ? "cbor" : "json") + ")");

  // §2 phase 2 — pool of detached(-after-join) worker threads, one per
  // accepted connection. The list lives on the main thread (this
  // function's stack); we sweep finished threads opportunistically
  // each time we wake up from accept(). On shutdown we join every
  // outstanding worker — workers themselves notice peer EOF or
  // hit serve_one_connection's read-side EAGAIN/SO_RCVTIMEO; the
  // shutdown signal alone doesn't reach an in-flight RPC (see the
  // "in-flight RPC interruption" follow-up).
  //
  // TODO(phase 3 / N4): reap finished workers. The list grows for the
  // daemon's lifetime; each entry is ~24 bytes plus the joinable
  // std::thread state. For realistic session counts this is
  // negligible, but a long-lived daemon servicing many short-lived
  // connections accumulates. The done-list-side-channel sketch in
  // reap_finished_workers below is the planned shape; reviewer
  // deferred it to phase 3 explicitly.
  std::list<std::thread> workers;
  auto reap_finished_workers = [&]() {
    // Joinable threads we know to have exited can't be detected
    // portably without a separate "done" flag; without that signal,
    // sweeping is best-effort. We use a try_join-by-waiting-zero
    // approximation: a thread that's exited is still joinable, but
    // joining it is non-blocking. There's no portable std::thread
    // try_join; instead, we rely on a tiny side-channel — workers
    // post their thread::id into a "done" list under done_mu before
    // returning. The main thread reads done_ids, joins those, and
    // erases.
    //
    // Initial impl uses a much simpler scheme: defer the cleanup to
    // shutdown. The list grows for the daemon's lifetime; each entry
    // is ~24 bytes plus the joinable thread state. For realistic
    // session counts this is negligible. If it ever matters, the
    // done-list scheme above is a 20-line refactor.
    (void) workers;
  };
  (void) reap_finished_workers;

  while (g_shutdown.load(std::memory_order_acquire) == 0) {
    // poll() on listener fd + self-pipe so a SIGTERM (or
    // daemon.shutdown's callback) wakes us promptly instead of
    // waiting for accept() to return naturally. Phase-1 used
    // bare accept() with EINTR handling; that worked only because
    // there was nothing else to wait for. Phase-2 adds the
    // shutdown self-pipe so a hung listener (no incoming
    // connections) still exits within ~milliseconds of the
    // shutdown signal.
    //
    // Timeout: -1 (block indefinitely) by default. When the
    // idle-timeout knob is set AND no workers are alive, we use
    // idle_timeout_sec * 1000ms; if poll returns 0 (timeout
    // elapsed) AND workers are still zero, the daemon shuts down.
    // Worker liveness recheck after the poll closes the race
    // between "worker exits, wakes us, we re-poll" and "we time
    // out exactly here".
    ::pollfd fds[2];
    fds[0].fd = srv;
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    fds[1].fd = g_shutdown_pipe[0];
    fds[1].events = POLLIN;
    fds[1].revents = 0;
    int timeout_ms = -1;
    if (idle_timeout_sec > 0 &&
        g_live_workers.load(std::memory_order_acquire) == 0) {
      timeout_ms = idle_timeout_sec * 1000;
    }
    int pr = ::poll(fds, 2, timeout_ms);
    if (pr < 0) {
      if (errno == EINTR) continue;
      log::error(std::string("poll: ") + std::strerror(errno));
      continue;
    }
    if (pr == 0) {
      // poll timed out — idle window elapsed. Confirm no worker
      // raced in during the gap; if so, this is the clean idle
      // shutdown path.
      if (g_live_workers.load(std::memory_order_acquire) == 0) {
        log::info("idle for " + std::to_string(idle_timeout_sec) +
                  "s; shutting down");
        g_shutdown.store(1, std::memory_order_release);
        break;
      }
      continue;
    }
    if (fds[1].revents & POLLIN) {
      // Drain the wake-up byte(s). Multiple signals coalesce
      // into a single drain; g_shutdown is the real signal. The
      // read end is non-blocking, so this loop terminates with
      // EAGAIN once the pipe is empty.
      char drain[64];
      while (::read(g_shutdown_pipe[0], drain, sizeof(drain)) > 0) {}
      if (g_shutdown.load(std::memory_order_acquire) != 0) break;
    }
    if (!(fds[0].revents & POLLIN)) continue;

    ::sockaddr_un peer{};
    socklen_t peer_len = sizeof(peer);
    int conn = ::accept(srv, reinterpret_cast<::sockaddr*>(&peer), &peer_len);
    if (conn < 0) {
      if (errno == EINTR || errno == EAGAIN) continue;
      log::error(std::string("accept: ") + std::strerror(errno));
      continue;
    }
    ::fcntl(conn, F_SETFD, FD_CLOEXEC);

    // Phase-1 trust model is uid-only: even though the socket inode
    // is 0600, a defense-in-depth peer-cred check rejects any caller
    // whose uid differs from ours. The retrieval API is platform-
    // specific: BSDs ship getpeereid(); glibc/musl don't, but expose
    // SO_PEERCRED via getsockopt. peer_cred_of() abstracts that.
    uid_t peer_uid = 0;
    gid_t peer_gid = 0;
#if defined(__linux__)
    {
      struct ucred uc{};
      socklen_t len = sizeof(uc);
      if (::getsockopt(conn, SOL_SOCKET, SO_PEERCRED, &uc, &len) != 0) {
        log::error(std::string("SO_PEERCRED: ") + std::strerror(errno));
        ::close(conn);
        continue;
      }
      peer_uid = uc.uid;
      peer_gid = uc.gid;
    }
#else
    if (::getpeereid(conn, &peer_uid, &peer_gid) != 0) {
      log::error(std::string("getpeereid: ") + std::strerror(errno));
      ::close(conn);
      continue;
    }
#endif
    (void)peer_gid;  // gid retrieved for parity with the BSD API but unused
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

    // 60-second send timeout (post-review I3). A connected-but-not-
    // reading peer lets the kernel send buffer fill; without this
    // setsockopt, the worker's ::write() blocks indefinitely. The
    // listener thread serving notifications also calls ::write()
    // (through OutputChannel), and an indefinite write held the
    // dispatcher's recursive_mutex via the cascade target.close →
    // map_mu_ unique. Adding SO_SNDTIMEO bounds the worst-case
    // stall: on EAGAIN the streambuf latches write_failed_,
    // write_response throws Error, and the worker exits cleanly.
    // 60s is generous (a real RPC reply round-trip is ~milliseconds)
    // but tight enough that a wedge doesn't keep the daemon
    // unresponsive for minutes.
    ::timeval snd_timeout{};
    snd_timeout.tv_sec  = 60;
    snd_timeout.tv_usec = 0;
    if (::setsockopt(conn, SOL_SOCKET, SO_SNDTIMEO,
                     &snd_timeout, sizeof(snd_timeout)) != 0) {
      log::warn(std::string("setsockopt(SO_SNDTIMEO): ") +
                std::strerror(errno));
    }

    // Spawn a worker thread; let it run for the connection's
    // lifetime. The Dispatcher is shared; its internal mutex
    // serialises overlapping RPC service. The notification sink is
    // per-connection (registered inside serve_socket_client) so
    // stop events fired from any target route to every live
    // subscriber's OutputChannel without cross-talk.
    //
    // Bump the live-workers counter BEFORE std::thread construction
    // so a poll wake-up that races with this spawn can't see zero
    // workers between accept and emplace. The worker decrements on
    // exit.
    g_live_workers.fetch_add(1, std::memory_order_release);
    workers.emplace_back(serve_socket_client, &dispatcher, conn, fmt);
  }

  log::info("shutdown signal received; closing listener");
  ::close(srv);
  ::unlink(sock_path.c_str());

  // Wait for in-flight workers to finish their current RPC and
  // notice the peer disconnect / SO_RCVTIMEO. We don't tear down
  // their fds from underneath them — that would surface as a use-
  // after-free in the underlying FdStreambuf. The §2 phase-2 docs
  // call this out: shutdown stops accepting new RPCs immediately but
  // lets the currently-executing dispatch run to completion. The
  // in-flight RPC interruption item is a finer-grained refinement
  // that requires a self-pipe + poll-based read.
  for (auto& t : workers) {
    if (t.joinable()) t.join();
  }

  ::close(lock_fd);
  ::unlink(lock_path.c_str());

  // Tear down the self-pipe. The signal handler and the dispatcher's
  // shutdown callback both read `g_shutdown_pipe_write`; we publish
  // -1 BEFORE the close so a late signal sees the sentinel and skips
  // the write entirely. (N3 — without the atomic publish-then-close
  // ordering, a signal racing the close could write to a closed fd
  // or, worse, to a recently-recycled fd of an unrelated open.)
  g_shutdown_pipe_write.store(-1, std::memory_order_release);
  if (g_shutdown_pipe[0] >= 0) {
    ::close(g_shutdown_pipe[0]);
    g_shutdown_pipe[0] = -1;
  }
  if (g_shutdown_pipe[1] >= 0) {
    ::close(g_shutdown_pipe[1]);
    g_shutdown_pipe[1] = -1;
  }
  return 0;
}

}  // namespace ldb::daemon
