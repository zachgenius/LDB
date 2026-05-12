// SPDX-License-Identifier: Apache-2.0
#include "transport/rsp/channel.h"

#include "transport/rsp/framing.h"
#include "transport/rsp/packets.h"
#include "util/log.h"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace ldb::transport::rsp {

namespace {

// Bytes-per-recv chunk. The actual server packet sizes are negotiated
// via qSupported's PacketSize; this is just the I/O slice we hand to
// recv(). 4 KiB is small enough that even tiny stop replies don't take
// two syscalls and large enough that bulk register reads land in one.
constexpr std::size_t kRecvChunkBytes = 4096;

// poll() helper: wait up to timeout for the fd to become readable or
// writable. Returns 1 on ready, 0 on timeout, -1 on error.
int poll_one(int fd, short events, std::chrono::milliseconds timeout) {
  struct pollfd p {};
  p.fd     = fd;
  p.events = events;
  int rc;
  do {
    rc = ::poll(&p, 1, static_cast<int>(timeout.count()));
  } while (rc < 0 && errno == EINTR);
  if (rc < 0) return -1;
  if (rc == 0) return 0;
  if (p.revents & (POLLERR | POLLHUP | POLLNVAL)) return -1;
  return 1;
}

int tcp_connect(const std::string& host, std::uint16_t port,
                std::chrono::milliseconds timeout, std::string* err) {
  // Resolve host. AF_INET only for phase-1; IPv6 lands when we have a
  // server to test against.
  struct addrinfo hints {};
  hints.ai_family   = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  char port_buf[16];
  std::snprintf(port_buf, sizeof(port_buf), "%u", port);

  struct addrinfo* res = nullptr;
  int gai = ::getaddrinfo(host.c_str(), port_buf, &hints, &res);
  if (gai != 0 || res == nullptr) {
    *err = std::string("getaddrinfo: ") + gai_strerror(gai);
    return -1;
  }

  int fd = -1;
  std::string last_err = "no address resolved";
  for (auto* p = res; p != nullptr; p = p->ai_next) {
    fd = ::socket(p->ai_family, p->ai_socktype | SOCK_CLOEXEC,
                  p->ai_protocol);
    if (fd < 0) { last_err = std::strerror(errno); continue; }

    // Non-blocking connect so we can enforce the timeout.
    int flags = ::fcntl(fd, F_GETFL, 0);
    ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    int rc = ::connect(fd, p->ai_addr, p->ai_addrlen);
    if (rc == 0) {
      // Immediate success (rare on TCP but happens on loopback).
      ::fcntl(fd, F_SETFL, flags);
      ::freeaddrinfo(res);
      return fd;
    }
    if (errno != EINPROGRESS) {
      last_err = std::strerror(errno);
      ::close(fd); fd = -1;
      continue;
    }

    int pr = poll_one(fd, POLLOUT, timeout);
    if (pr <= 0) {
      last_err = (pr == 0) ? std::string("connect timeout")
                           : std::string(std::strerror(errno));
      ::close(fd); fd = -1;
      continue;
    }
    int so_err = 0;
    socklen_t so_len = sizeof(so_err);
    ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &so_len);
    if (so_err != 0) {
      last_err = std::strerror(so_err);
      ::close(fd); fd = -1;
      continue;
    }

    // Restore blocking mode for the steady state — the reader thread
    // uses blocking I/O with shutdown() as the wake-up mechanism.
    ::fcntl(fd, F_SETFL, flags);
    ::freeaddrinfo(res);
    return fd;
  }

  ::freeaddrinfo(res);
  *err = last_err;
  return -1;
}

}  // namespace

RspChannel::RspChannel(std::string host, std::uint16_t port, Config cfg)
    : cfg_(cfg) {
  ack_mode_.store(cfg.ack_mode, std::memory_order_release);
  std::string err;
  fd_ = tcp_connect(host, port, cfg.connect_timeout, &err);
  if (fd_ < 0) {
    throw backend::Error(std::string("rsp: connect ") + host + ":" +
                          std::to_string(port) + ": " + err);
  }
  alive_.store(true, std::memory_order_release);
  start_reader();
  if (!cfg.skip_handshake) {
    try {
      perform_handshake();
    } catch (...) {
      // Tear down cleanly before propagating — the reader thread is
      // already running, and the destructor will never run if the
      // constructor throws.
      shutdown_.store(true, std::memory_order_release);
      ::shutdown(fd_, SHUT_RDWR);
      if (reader_.joinable()) reader_.join();
      ::close(fd_);
      fd_ = -1;
      throw;
    }
  }
}

RspChannel::RspChannel(AdoptFd adopt, Config cfg)
    : cfg_(cfg) {
  ack_mode_.store(cfg.ack_mode, std::memory_order_release);
  if (adopt.fd < 0) {
    throw backend::Error("rsp: AdoptFd given an invalid fd");
  }
  fd_ = adopt.fd;
  alive_.store(true, std::memory_order_release);
  start_reader();
  if (!cfg.skip_handshake) {
    try {
      perform_handshake();
    } catch (...) {
      shutdown_.store(true, std::memory_order_release);
      ::shutdown(fd_, SHUT_RDWR);
      if (reader_.joinable()) reader_.join();
      ::close(fd_);
      fd_ = -1;
      throw;
    }
  }
}

RspChannel::~RspChannel() {
  shutdown_.store(true, std::memory_order_release);
  if (fd_ >= 0) {
    // Unblock the reader thread's blocking recv() — shutdown(2) is the
    // portable signal that says "no more I/O, even on a thread that's
    // mid-syscall." close() alone would race the reader's fd-still-
    // valid window.
    ::shutdown(fd_, SHUT_RDWR);
  }
  // Wake any blocked recv() callers so they observe shutdown_ and
  // return nullopt.
  {
    std::lock_guard<std::mutex> g(recv_mu_);
    recv_cv_.notify_all();
  }
  {
    std::lock_guard<std::mutex> g(ack_mu_);
    ack_cv_.notify_all();
  }
  if (reader_.joinable()) reader_.join();
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
  alive_.store(false, std::memory_order_release);
}

void RspChannel::start_reader() {
  reader_ = std::thread([this]() { reader_thread_main(); });
}

bool RspChannel::alive() const noexcept {
  return alive_.load(std::memory_order_acquire);
}

void RspChannel::reader_thread_main() {
  std::string buf;
  buf.reserve(kRecvChunkBytes * 2);

  char chunk[kRecvChunkBytes];
  while (!shutdown_.load(std::memory_order_acquire)) {
    ssize_t n = ::recv(fd_, chunk, sizeof(chunk), 0);
    if (n == 0) {
      // EOF.
      alive_.store(false, std::memory_order_release);
      // Unblock recv() / send_once() waiters.
      {
        std::lock_guard<std::mutex> g(recv_mu_);
        recv_cv_.notify_all();
      }
      {
        std::lock_guard<std::mutex> g(ack_mu_);
        ack_cv_.notify_all();
      }
      return;
    }
    if (n < 0) {
      if (errno == EINTR) continue;
      // shutdown(2) trips this branch with ECONNRESET / EBADF.
      alive_.store(false, std::memory_order_release);
      {
        std::lock_guard<std::mutex> g(recv_mu_);
        recv_cv_.notify_all();
      }
      {
        std::lock_guard<std::mutex> g(ack_mu_);
        ack_cv_.notify_all();
      }
      return;
    }

    buf.append(chunk, static_cast<std::size_t>(n));

    // Drain the buffer: pull off ack/nack bytes (notify the writer)
    // and full packets (push onto recv_q_).
    for (;;) {
      if (buf.empty()) break;
      // Ack/nack: a single byte before any '$'. We can't just rely on
      // decode_packet's leading-skip because we need to *observe* the
      // byte for ack tracking.
      if (buf.front() == '+' || buf.front() == '-') {
        bool acked = (buf.front() == '+');
        buf.erase(0, 1);
        if (ack_mode_.load(std::memory_order_acquire)) {
          std::lock_guard<std::mutex> g(ack_mu_);
          if (ack_state_ == WriterAckState::kWaiting) {
            ack_state_ = acked ? WriterAckState::kAcked
                                : WriterAckState::kNacked;
            ack_cv_.notify_all();
          }
          // Stray acks (kIdle, kAcked/kNacked) are dropped silently.
        }
        continue;
      }
      auto r = decode_packet(buf);
      if (r.error == DecodeError::kIncomplete) break;
      if (r.error != DecodeError::kOk) {
        // Malformed wire. Best we can do is send a nack and drop one
        // byte to resync. Real gdb-remote clients shouldn't hit this.
        if (ack_mode_.load(std::memory_order_acquire)) {
          (void)write_all("-");
        }
        buf.erase(0, 1);
        continue;
      }
      // Successful decode. In ack-mode, send `+` so the server knows
      // we got it cleanly.
      if (ack_mode_.load(std::memory_order_acquire)) {
        (void)write_all("+");
      }
      buf.erase(0, r.consumed);
      {
        std::lock_guard<std::mutex> g(recv_mu_);
        if (recv_q_.size() < kMaxQueueDepth) {
          recv_q_.push(std::move(r.payload));
          recv_cv_.notify_all();
        }
        // Overflow path: drop the packet on the floor. The server's
        // already committed bytes; back-pressure is for a later
        // hardening pass.
      }
    }
  }
  alive_.store(false, std::memory_order_release);
}

bool RspChannel::write_all(std::string_view framed) {
  std::size_t off = 0;
  while (off < framed.size()) {
    ssize_t w = ::send(fd_, framed.data() + off,
                       framed.size() - off, MSG_NOSIGNAL);
    if (w < 0) {
      if (errno == EINTR) continue;
      alive_.store(false, std::memory_order_release);
      return false;
    }
    if (w == 0) {
      alive_.store(false, std::memory_order_release);
      return false;
    }
    off += static_cast<std::size_t>(w);
  }
  return true;
}

bool RspChannel::send_once(std::string_view payload) {
  if (!alive_.load(std::memory_order_acquire)) {
    throw backend::Error("rsp: channel not alive");
  }

  auto framed = encode_packet(payload);

  if (ack_mode_.load(std::memory_order_acquire)) {
    std::unique_lock<std::mutex> g(ack_mu_);
    ack_state_ = WriterAckState::kWaiting;
    g.unlock();

    if (!write_all(framed)) {
      throw backend::Error("rsp: write failed");
    }

    g.lock();
    bool got = ack_cv_.wait_for(g, cfg_.packet_timeout, [this]() {
      return ack_state_ != WriterAckState::kWaiting ||
             shutdown_.load(std::memory_order_acquire) ||
             !alive_.load(std::memory_order_acquire);
    });
    if (!alive_.load(std::memory_order_acquire) ||
        shutdown_.load(std::memory_order_acquire)) {
      ack_state_ = WriterAckState::kIdle;
      throw backend::Error("rsp: channel torn down during send");
    }
    if (!got) {
      // Timeout: treat as a nack to drive the retry loop.
      ack_state_ = WriterAckState::kIdle;
      return false;
    }
    bool acked = (ack_state_ == WriterAckState::kAcked);
    ack_state_ = WriterAckState::kIdle;
    return acked;
  }

  // No-ack mode: write and go.
  if (!write_all(framed)) {
    throw backend::Error("rsp: write failed");
  }
  return true;
}

bool RspChannel::send(std::string_view payload) {
  std::lock_guard<std::mutex> g(write_mu_);
  for (int attempt = 0; attempt < cfg_.retry_budget + 1; ++attempt) {
    bool ok = send_once(payload);
    if (ok) return true;
  }
  throw backend::Error("rsp: retry budget exhausted");
}

std::optional<std::string>
RspChannel::recv(std::chrono::milliseconds timeout) {
  std::unique_lock<std::mutex> g(recv_mu_);
  bool got = recv_cv_.wait_for(g, timeout, [this]() {
    return !recv_q_.empty() ||
           shutdown_.load(std::memory_order_acquire) ||
           !alive_.load(std::memory_order_acquire);
  });
  if (!got) return std::nullopt;
  if (recv_q_.empty()) return std::nullopt;  // EOF / shutdown wakeup
  std::string s = std::move(recv_q_.front());
  recv_q_.pop();
  return s;
}

std::optional<std::string>
RspChannel::request(std::string_view payload) {
  // send() throws on hard failure; we let that propagate.
  if (!send(payload)) return std::nullopt;
  return recv(cfg_.packet_timeout);
}

void RspChannel::perform_handshake() {
  // qSupported: declare what we understand and learn what the server
  // advertises. We carry the same client-side feature list LLDB uses
  // (multiprocess+, vContSupported+, ...); the server picks the
  // intersection.
  std::vector<std::string> features {
    "multiprocess+",
    "vContSupported+",
    "QStartNoAckMode+",
    "qXfer:features:read+",
    "swbreak+",
    "hwbreak+",
  };
  auto reply = request(build_qSupported(features));
  if (!reply.has_value()) {
    throw backend::Error("rsp: qSupported handshake timed out");
  }
  auto parsed = parse_qSupported_reply(*reply);
  if (!parsed.has_value()) {
    throw backend::Error("rsp: qSupported reply unparseable: " + *reply);
  }
  // Stash the raw reply for diagnostics — parsed form is paste-friendly
  // but the dispatcher exposes only the raw string for now.
  server_features_ = *reply;

  // If the server advertised QStartNoAckMode+, switch to no-ack mode.
  bool server_supports_no_ack = false;
  for (const auto& [name, val] : parsed->features) {
    if (name == "QStartNoAckMode" && val == "+") {
      server_supports_no_ack = true;
      break;
    }
  }
  if (server_supports_no_ack) {
    // Toggle: we send QStartNoAckMode under the OLD ack discipline
    // (we still ack the server's reply), then atomically flip the
    // mode after we observe their "OK". The spec allows the toggle to
    // race; the safe ordering is "ack the OK first, then stop acking
    // future packets."
    auto resp = request(build_QStartNoAckMode());
    if (resp.has_value() && *resp == "OK") {
      ack_mode_.store(false, std::memory_order_release);
    }
    // If the server doesn't reply OK, we stay in ack mode. The
    // handshake doesn't fail — ack-mode is the safer default.
  }
}

}  // namespace ldb::transport::rsp
