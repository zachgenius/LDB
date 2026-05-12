// SPDX-License-Identifier: Apache-2.0
// Unit tests for the async RSP transport (post-V1 #17 phase-1 part 3;
// docs/25-own-rsp-client.md §2.1, §2.4).
//
// Coverage:
//   • Connect refused → backend::Error.
//   • Handshake: server sends QStartNoAckMode+ → client flips ack_mode
//     off, no_ack_mode() == true after construction.
//   • request("?") returns the server's stop-reply payload byte-for-byte.
//   • Server nacks the first 2 attempts, accepts the 3rd → request
//     succeeds within retry_budget=3.
//   • Server nacks 4 times in a row → send() throws backend::Error.
//   • Server closes the socket mid-session → next recv() returns
//     nullopt, alive() == false.
//   • Destructor races against a recv() pending on a helper thread →
//     no deadlock, no UAF (covered by the destructor unblocking recv
//     via socket shutdown).
//
// Tests use socketpair() to stand in for the TCP connection. The
// channel is built via the test-only AdoptFd ctor with
// cfg.skip_handshake set in tests that drive the wire directly; the
// handshake test exercises the real perform_handshake path.

#include <catch_amalgamated.hpp>

#include "backend/debugger_backend.h"  // backend::Error
#include "transport/rsp/channel.h"
#include "transport/rsp/framing.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace std::chrono_literals;
using ldb::transport::rsp::RspChannel;
using ldb::transport::rsp::encode_packet;
using ldb::transport::rsp::decode_packet;
using ldb::transport::rsp::DecodeError;

namespace {

// Spawn a "mock peer" thread that reads from one end of a socketpair
// and runs a script against it. The script is a sequence of
// (read_predicate, response_bytes) pairs, simulating the server's
// view of the conversation. The peer reads until a full framed packet
// is decodable, asserts the payload matches the expected, then writes
// the canned response.
//
// Kept tiny because real test value is at the channel level.
struct MockPeer {
  int fd = -1;
  std::thread t;
  std::atomic<bool> stop{false};

  ~MockPeer() {
    stop.store(true);
    if (fd >= 0) { ::shutdown(fd, SHUT_RDWR); ::close(fd); }
    if (t.joinable()) t.join();
  }

  // Blocking read of at most n bytes (or until socket closes / stop).
  static std::string read_some(int fd, std::size_t n) {
    std::string buf;
    buf.resize(n);
    ssize_t got = ::recv(fd, buf.data(), n, 0);
    if (got <= 0) return {};
    buf.resize(static_cast<std::size_t>(got));
    return buf;
  }

  // Read until decode_packet succeeds. Returns the decoded payload, or
  // empty on socket error.
  static std::string read_one_packet(int fd) {
    std::string acc;
    for (int spin = 0; spin < 1000; ++spin) {
      auto chunk = read_some(fd, 256);
      if (chunk.empty()) return {};
      acc += chunk;
      auto r = decode_packet(acc);
      if (r.error == DecodeError::kOk) return r.payload;
      if (r.error != DecodeError::kIncomplete) return {};
    }
    return {};
  }

  static void write_all(int fd, std::string_view bytes) {
    std::size_t off = 0;
    while (off < bytes.size()) {
      ssize_t w = ::send(fd, bytes.data() + off, bytes.size() - off, 0);
      if (w <= 0) return;
      off += static_cast<std::size_t>(w);
    }
  }
};

// Make a connected AF_UNIX SOCK_STREAM pair. Returns {channel_end,
// peer_end}.
std::pair<int, int> make_socketpair() {
  int sv[2] = {-1, -1};
  REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  return {sv[0], sv[1]};
}

}  // namespace

TEST_CASE("rsp/channel: connect refused throws backend::Error",
          "[rsp][channel][negative]") {
  // Pick a port we know nothing is listening on. 0 is reserved; 1 is
  // historically privileged. Either gets us a fast ECONNREFUSED on
  // Linux. The bigger constraint is that the test must finish before
  // the channel's connect_timeout (default 5s).
  ldb::transport::rsp::RspChannelConfig cfg;
  cfg.connect_timeout = 500ms;
  cfg.packet_timeout  = 200ms;
  REQUIRE_THROWS_AS(
      RspChannel(std::string("127.0.0.1"), static_cast<std::uint16_t>(1), cfg),
      ldb::backend::Error);
}

TEST_CASE("rsp/channel: handshake flips off ack-mode when server "
          "advertises QStartNoAckMode+",
          "[rsp][channel][handshake]") {
  auto [client_fd, peer_fd] = make_socketpair();

  MockPeer peer;
  peer.fd = peer_fd;
  peer.t = std::thread([peer_fd]() {
    // 1. Read the client's qSupported.
    auto req1 = MockPeer::read_one_packet(peer_fd);
    if (req1.empty()) return;
    // 2. Ack it. The client sends `+` after a successful decode, so
    //    we ack our reply first (gdb spec is symmetric).
    MockPeer::write_all(peer_fd, "+");
    // 3. Send a qSupported reply that advertises QStartNoAckMode+.
    std::string body = "PacketSize=4000;QStartNoAckMode+";
    MockPeer::write_all(peer_fd, encode_packet(body));
    // 4. Read the client's `+` ack of our reply.
    char ack;
    (void)::recv(peer_fd, &ack, 1, 0);
    // 5. Read the client's QStartNoAckMode packet.
    auto req2 = MockPeer::read_one_packet(peer_fd);
    if (req2 != "QStartNoAckMode") return;
    // 6. Ack the toggle request.
    MockPeer::write_all(peer_fd, "+");
    // 7. Reply OK. After this the wire is no-ack.
    MockPeer::write_all(peer_fd, encode_packet("OK"));
    // No more acks expected. Sit idle until the channel destructs and
    // shuts the socket.
    char buf[64];
    while (true) {
      ssize_t r = ::recv(peer_fd, buf, sizeof(buf), 0);
      if (r <= 0) break;
    }
  });

  ldb::transport::rsp::RspChannelConfig cfg;
  cfg.packet_timeout = 1s;
  RspChannel ch({client_fd}, cfg);

  CHECK(ch.alive());
  CHECK(ch.no_ack_mode() == true);
  // Server's PacketSize advertisement is exposed via server_features_.
  // We don't pin the exact format here — the dispatcher only needs the
  // string for diagnostics in phase-1.
  CHECK(ch.server_features().find("PacketSize") != std::string::npos);
}

TEST_CASE("rsp/channel: request('?') round-trips a stop-reply",
          "[rsp][channel][stop_reply]") {
  auto [client_fd, peer_fd] = make_socketpair();

  MockPeer peer;
  peer.fd = peer_fd;
  peer.t = std::thread([peer_fd]() {
    auto req = MockPeer::read_one_packet(peer_fd);
    if (req != "?") return;
    // Server ack.
    MockPeer::write_all(peer_fd, "+");
    // Stop reply: thread 1 hit SIGTRAP.
    MockPeer::write_all(peer_fd, encode_packet("T05thread:1;"));
    char ack;
    (void)::recv(peer_fd, &ack, 1, 0);
    char buf[64];
    while (::recv(peer_fd, buf, sizeof(buf), 0) > 0) {}
  });

  ldb::transport::rsp::RspChannelConfig cfg;
  cfg.skip_handshake = true;
  cfg.packet_timeout = 1s;
  RspChannel ch({client_fd}, cfg);

  auto reply = ch.request("?");
  REQUIRE(reply.has_value());
  CHECK(*reply == "T05thread:1;");
}

TEST_CASE("rsp/channel: server nacks twice, then accepts → request "
          "succeeds within retry_budget=3",
          "[rsp][channel][retry]") {
  auto [client_fd, peer_fd] = make_socketpair();

  MockPeer peer;
  peer.fd = peer_fd;
  peer.t = std::thread([peer_fd]() {
    for (int attempt = 0; attempt < 3; ++attempt) {
      auto req = MockPeer::read_one_packet(peer_fd);
      if (req != "?") return;
      if (attempt < 2) {
        // Force a retry.
        MockPeer::write_all(peer_fd, "-");
      } else {
        MockPeer::write_all(peer_fd, "+");
        MockPeer::write_all(peer_fd, encode_packet("T05"));
        char ack;
        (void)::recv(peer_fd, &ack, 1, 0);
      }
    }
    char buf[64];
    while (::recv(peer_fd, buf, sizeof(buf), 0) > 0) {}
  });

  ldb::transport::rsp::RspChannelConfig cfg;
  cfg.skip_handshake = true;
  cfg.packet_timeout = 1s;
  cfg.retry_budget   = 3;
  RspChannel ch({client_fd}, cfg);

  auto reply = ch.request("?");
  REQUIRE(reply.has_value());
  CHECK(*reply == "T05");
}

TEST_CASE("rsp/channel: retry budget exhaustion throws backend::Error",
          "[rsp][channel][retry][negative]") {
  auto [client_fd, peer_fd] = make_socketpair();

  MockPeer peer;
  peer.fd = peer_fd;
  peer.t = std::thread([peer_fd]() {
    // Nack every send forever.
    for (;;) {
      auto req = MockPeer::read_one_packet(peer_fd);
      if (req.empty()) return;
      MockPeer::write_all(peer_fd, "-");
    }
  });

  ldb::transport::rsp::RspChannelConfig cfg;
  cfg.skip_handshake = true;
  cfg.packet_timeout = 500ms;
  cfg.retry_budget   = 3;
  RspChannel ch({client_fd}, cfg);

  REQUIRE_THROWS_AS(ch.send("?"), ldb::backend::Error);
}

TEST_CASE("rsp/channel: server EOF mid-session marks channel dead",
          "[rsp][channel][eof]") {
  auto [client_fd, peer_fd] = make_socketpair();

  MockPeer peer;
  peer.fd = peer_fd;
  peer.t  = std::thread([peer_fd]() {
    // Read whatever the client sends, then close. Mimics a server
    // crash / network partition.
    char buf[64];
    (void)::recv(peer_fd, buf, sizeof(buf), 0);
    ::shutdown(peer_fd, SHUT_RDWR);
    ::close(peer_fd);
  });
  // The peer owns peer_fd inside its thread; ensure we don't double-close.
  peer.fd = -1;

  ldb::transport::rsp::RspChannelConfig cfg;
  cfg.skip_handshake = true;
  cfg.packet_timeout = 500ms;
  RspChannel ch({client_fd}, cfg);

  // After the server closes, the next recv with a bounded timeout
  // either returns nullopt (timed out, alive() also false eventually)
  // or returns nullopt immediately because the reader thread already
  // signaled EOF. Either way the channel must mark itself dead within
  // a couple of timeout windows.
  auto deadline = std::chrono::steady_clock::now() + 2s;
  bool went_dead = false;
  while (std::chrono::steady_clock::now() < deadline) {
    (void)ch.recv(200ms);
    if (!ch.alive()) { went_dead = true; break; }
    // Poke the channel — sending after EOF surfaces the error
    // through write_all() if the EOF detection on the read side
    // hasn't tripped yet.
    try { (void)ch.send("g"); } catch (...) { /* expected post-EOF */ }
  }
  CHECK(went_dead);
}

TEST_CASE("rsp/channel: destructor unblocks a recv() pending on another thread",
          "[rsp][channel][destruct]") {
  auto [client_fd, peer_fd] = make_socketpair();

  MockPeer peer;
  peer.fd = peer_fd;
  peer.t  = std::thread([peer_fd]() {
    char buf[64];
    while (::recv(peer_fd, buf, sizeof(buf), 0) > 0) {}
  });

  ldb::transport::rsp::RspChannelConfig cfg;
  cfg.skip_handshake = true;
  cfg.packet_timeout = 5s;  // intentionally generous; we want destructor to win

  auto ch = std::make_unique<RspChannel>(RspChannel::AdoptFd{client_fd}, cfg);

  std::atomic<bool> recv_returned{false};
  std::thread waiter([&]() {
    // Sit blocking on recv for ~5s; the destructor should fire first
    // and signal us via the recv_cv path.
    (void)ch->recv(5s);
    recv_returned.store(true);
  });

  // Give the waiter a moment to enter recv().
  std::this_thread::sleep_for(100ms);
  // Tear the channel down. Joining the reader + signaling recv_cv is
  // the destructor's job; if either fails, this hangs or UAFs.
  ch.reset();
  waiter.join();

  CHECK(recv_returned.load());
}
