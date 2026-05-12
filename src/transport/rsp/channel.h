// SPDX-License-Identifier: Apache-2.0
#pragma once

// Async GDB RSP transport (post-V1 #17 phase-1; docs/25-own-rsp-client.md
// §2.1, §2.4). Composes framing + packets atop a TCP connection (or
// a pre-made fd, used by the unit tests in lieu of socketpair() faking).
//
// Threading model:
//   • One reader thread, owned by the channel, that drains the socket
//     into a per-channel mutex-protected std::queue<std::string> of
//     decoded payloads. It also observes server ack/nack bytes (+/−)
//     and signals the writer's wait-for-ack condvar.
//   • The writer side is a plain mutex held during send() — exactly one
//     framed packet is on the wire at a time. send() in ack-mode waits
//     up to packet_timeout for the reader to report an ack; on nack it
//     retransmits up to retry_budget times. On no-ack mode the writer
//     returns immediately after the OS write.
//   • recv() pops from the queue with a bounded wait. request() = send +
//     recv with the channel's packet_timeout (the common synchronous
//     path; the future #21 notification surface will call recv() alone
//     from a listener thread).
//
// Lifetime:
//   The constructor blocks on TCP connect + the qSupported handshake.
//   The destructor flips a "shutdown" flag, shutdown(fd, SHUT_RDWR) to
//   unblock the reader's blocking I/O, joins the reader thread, closes
//   the fd. Idempotent — calling shutdown() then close() twice is safe.
//
// Failure surface:
//   All construction failures and retry-budget exhaustion throw
//   backend::Error. recv() returns std::nullopt on a *bounded* timeout
//   (channel still alive); it returns an empty optional and flips
//   alive() to false on stream EOF. Network errors mid-stream mark the
//   channel dead and surface to subsequent send()/recv() calls.

#include "backend/debugger_backend.h"  // backend::Error

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <string_view>
#include <thread>

namespace ldb::transport::rsp {

struct RspChannelConfig {
  std::chrono::milliseconds connect_timeout{5000};
  std::chrono::milliseconds packet_timeout{2000};
  int                       retry_budget = 3;
  // ack_mode is the *initial* expectation; the handshake may flip it
  // off after the server advertises QStartNoAckMode+.
  bool                      ack_mode = true;
  // Skip the qSupported handshake — only the unit tests want this so
  // they can drive the wire byte-for-byte. Production callers leave it
  // false (the default) and let RspChannel negotiate.
  bool                      skip_handshake = false;
};

class RspChannel {
 public:
  using Config = RspChannelConfig;

  // Open a TCP connection to host:port and run the qSupported
  // handshake. Throws backend::Error on connect failure or handshake
  // timeout. After construction the reader thread is alive and
  // recv() / send() can be called.
  RspChannel(std::string host, std::uint16_t port, Config cfg = {});

  // Test-only ctor: take a pre-made bidirectional fd (typically one end
  // of a socketpair() set up by the unit tests). Adopts ownership; the
  // destructor closes it. The handshake still runs unless
  // cfg.skip_handshake is true, which the unit tests use to drive the
  // wire byte-for-byte without negotiating qSupported.
  struct AdoptFd { int fd; };
  RspChannel(AdoptFd adopt, Config cfg = {});

  ~RspChannel();

  RspChannel(const RspChannel&)            = delete;
  RspChannel& operator=(const RspChannel&) = delete;
  RspChannel(RspChannel&&)                 = delete;
  RspChannel& operator=(RspChannel&&)      = delete;

  // Send a payload (just the bytes between $ and # — RspChannel handles
  // framing + checksum). In ack-mode the call waits up to packet_timeout
  // for the server's + ; on - it retransmits up to retry_budget times.
  // Returns true on accepted; throws backend::Error on retry exhaustion
  // or stream error.
  bool send(std::string_view payload);

  // Wait up to `timeout` for the next decoded payload from the server.
  // Returns std::nullopt on a bounded timeout (channel still alive) or
  // on stream EOF (caller should re-check alive()).
  std::optional<std::string> recv(std::chrono::milliseconds timeout);

  // Convenience for the synchronous req/resp pattern: send then recv
  // with the configured packet_timeout.
  std::optional<std::string> request(std::string_view payload);

  // True until the reader thread observes EOF/EAGAIN/error or the
  // destructor flips shutdown_. Cheap; lock-free.
  bool alive() const noexcept;

  // Parsed qSupported features the server advertised at handshake. The
  // dispatcher peeks at "vContSupported" / "qXfer:features:read+" etc.
  // before driving subsequent endpoints.
  const std::string& server_features() const noexcept { return server_features_; }

  // Whether the channel is currently in no-ack mode (i.e. the handshake
  // negotiated QStartNoAckMode+). Useful for logging / observability.
  bool no_ack_mode() const noexcept { return !ack_mode_.load(std::memory_order_acquire); }

 private:
  enum class WriterAckState : int {
    kIdle = 0,   // no send in flight
    kWaiting,    // send in flight, awaiting +/-
    kAcked,      // server sent +
    kNacked,     // server sent -
  };

  void reader_thread_main();
  void start_reader();
  void perform_handshake();

  // Write `framed` (a full $..#cs envelope) to the socket. Loops past
  // EINTR and short writes. Returns false on a non-recoverable error;
  // sets alive_ false in that case. Caller MUST hold write_mu_ —
  // concurrent writes from reader (acks) and writer (packets) over a
  // single fd produce byte-level interleaving on real TCP.
  bool write_all(std::string_view framed);

  // Reader-thread helper: serialise an ack/nack byte against the
  // writer's packet bytes via write_mu_. The 1-byte send is cheap
  // and the lock-hold is bounded; without this gate, #21's listener-
  // thread model (which sends vCont frames asynchronously while the
  // reader acks incoming stop-events) corrupts the wire.
  void send_raw_locked(std::string_view bytes);

  // Issue one send + ack-wait pass. Returns true on accepted, false on
  // a nack we should retry. Throws on stream error or timeout (caller
  // decides whether to retry by counting throw vs return-false).
  bool send_once(std::string_view payload);

  Config       cfg_;
  int          fd_         = -1;
  std::atomic<bool> alive_{false};
  std::atomic<bool> shutdown_{false};
  // Initial expectation; flipped to false after a successful
  // QStartNoAckMode handshake. Reader + writer both consult it.
  std::atomic<bool> ack_mode_{true};

  std::thread  reader_;

  // Receive-side queue of decoded payloads.
  std::mutex                 recv_mu_;
  std::condition_variable    recv_cv_;
  std::queue<std::string>    recv_q_;
  // Bounded queue capacity — preventing a runaway server from chewing
  // through all RAM is cheap and a known gdb-remote attack surface.
  static constexpr std::size_t kMaxQueueDepth = 1024;

  // Writer-side ack tracking. Held by send_once() across the write +
  // wait window; signaled by the reader thread when it sees +/-.
  std::mutex                 ack_mu_;
  std::condition_variable    ack_cv_;
  WriterAckState             ack_state_ = WriterAckState::kIdle;

  // Two-level mutex split — the reviewer-flagged race made this
  // necessary. write_mu_ serialises send() callers (one packet in
  // flight against the ack-state machine). It is NOT held during
  // the ack-wait — that would deadlock the reader's ack-send.
  // byte_mu_ serialises raw byte writes to the fd (reader's 1-byte
  // acks vs. writer's $..#cs frames) so the two never byte-
  // interleave. Lock ordering when both are needed:
  // write_mu_ → byte_mu_.
  std::mutex                 write_mu_;
  std::mutex                 byte_mu_;

  std::string                server_features_;
};

}  // namespace ldb::transport::rsp
