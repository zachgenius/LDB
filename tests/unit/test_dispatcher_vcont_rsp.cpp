// SPDX-License-Identifier: Apache-2.0
// Tests for the v1.6 #17 phase-2 vCont write path
// (docs/27-nonstop-listener.md §7's "What this unblocks").
//
// Phase-1 of #17 parked an RspChannel per target but didn't route any
// operations through it — every endpoint still called LldbBackend.
// Phase-2 of #21 made the listener consume the channel's recv queue.
// This commit closes the loop: thread.continue and thread.suspend
// route through the channel via vCont packets when one is parked
// under the target_id, instead of (or in addition to) the legacy
// backend path. Non-RSP targets keep the existing LldbBackend route
// unchanged — the new path is gated on the presence of a channel.
//
// Coverage:
//   * thread.continue on an RSP-backed target emits `vCont;c:<tid>`
//     on the wire, returns kRunning, and records set_running in the
//     runtime (thread.list_state sees it).
//   * thread.suspend on an RSP-backed target emits `vCont;t:<tid>`
//     on the wire and returns ok — the -32001 kNotImplemented stub
//     is dropped for RSP-backed targets.
//   * thread.suspend on a non-RSP target still returns -32001
//     (the stub is preserved for the LldbBackend path until that
//     gets its own resume-via-listener integration).
//
// The dispatcher exposes install_rsp_channel_for_test as the seam.
// Production callers always go through target.connect_remote_rsp.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"
#include "daemon/dispatcher.h"
#include "protocol/jsonrpc.h"
#include "transport/rsp/channel.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <memory>
#include <string>
#include <thread>

using ldb::backend::LldbBackend;
using ldb::daemon::Dispatcher;
using ldb::protocol::ErrorCode;
using ldb::protocol::Request;
using ldb::protocol::Response;
using ldb::protocol::json;
using ldb::transport::rsp::RspChannel;

namespace {

Request req(const std::string& method, const json& params) {
  Request r;
  r.id     = "1";
  r.method = method;
  r.params = params;
  return r;
}

// Read everything currently sitting in the peer fd's recv buffer.
// The timeout is conservative (default 200ms) and covers the OS
// socket-buffer round-trip latency between the dispatcher's send()
// and our recv(), NOT any protocol delay — vCont is fire-and-forget.
// Do NOT trim the timeout below ~50ms even on a fast box; CI runners
// schedule unpredictably and a tighter bound would be flaky for no
// real-world gain. The function keeps draining via `continue` after
// any successful read so a packet that arrives in fragments still
// assembles before the deadline.
std::string drain_peer(int fd, std::chrono::milliseconds timeout) {
  std::string out;
  auto deadline = std::chrono::steady_clock::now() + timeout;
  char buf[256];
  while (std::chrono::steady_clock::now() < deadline) {
    // MSG_DONTWAIT — return immediately if nothing to read.
    ssize_t n = ::recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
    if (n > 0) {
      out.append(buf, static_cast<std::size_t>(n));
      // Keep draining briefly to catch the rest of the packet.
      continue;
    }
    if (n == 0) break;
    // EAGAIN — sleep a bit and retry.
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  return out;
}

// Parse a $payload#cs envelope at the start of `s`; returns the
// payload (between $ and #). Empty string if no valid frame.
std::string payload_of_frame(const std::string& s) {
  if (s.size() < 4 || s[0] != '$') return "";
  auto hash = s.find('#');
  if (hash == std::string::npos) return "";
  return s.substr(1, hash - 1);
}

// Build a Dispatcher + AdoptFd RspChannel pair. The peer fd is
// returned for the test to drain bytes off of (acting as the server
// half of the gdb-remote connection).
struct RspFixture {
  Dispatcher        disp;
  int               peer_fd = -1;

  // shared because Dispatcher takes a shared_ptr.
  std::shared_ptr<LldbBackend> backend;

  std::uint64_t target_id = 0;

  RspFixture() : disp(make_disp()), backend(std::make_shared<LldbBackend>()) {}

 private:
  static Dispatcher make_disp() {
    auto be = std::make_shared<LldbBackend>();
    return Dispatcher{be};
  }
};

// Convenience: open an empty target, install a socketpair-backed
// RspChannel under that target_id, return the peer fd + target_id.
struct InstalledRsp {
  std::uint64_t target_id = 0;
  int           peer_fd   = -1;
};
InstalledRsp install_rsp_target(Dispatcher& disp) {
  auto open = disp.dispatch(req("target.create_empty", json::object()));
  REQUIRE(open.ok);
  std::uint64_t tid = open.data["target_id"].get<std::uint64_t>();

  int sv[2] = {-1, -1};
  REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  RspChannel::Config cfg;
  cfg.skip_handshake = true;
  cfg.ack_mode       = false;
  auto chan = std::make_unique<RspChannel>(RspChannel::AdoptFd{sv[0]}, cfg);

  disp.install_rsp_channel_for_test(tid, std::move(chan));
  return {tid, sv[1]};
}

}  // namespace

TEST_CASE("vCont-RSP: thread.continue emits vCont;c:<tid> over the channel",
          "[dispatcher][rsp][vcont][thread][continue]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher disp(be);
  auto inst = install_rsp_target(disp);

  auto resp = disp.dispatch(req("thread.continue",
      json{{"target_id", inst.target_id}, {"tid", 42}}));
  REQUIRE(resp.ok);
  CHECK(resp.data.value("state", std::string{}) == "running");

  std::string bytes = drain_peer(inst.peer_fd, std::chrono::milliseconds(200));
  REQUIRE_FALSE(bytes.empty());
  // The on-wire payload is vCont;c:2a (42 = 0x2a). The framing layer
  // wraps it as $vCont;c:2a#cs8. Strip the envelope and assert on
  // the payload string.
  auto payload = payload_of_frame(bytes);
  CHECK(payload == "vCont;c:2a");

  // thread.continue records the runtime intent so thread.list_state
  // reflects the resumed thread (existing #21 phase-1 contract).
  auto ls = disp.dispatch(req("thread.list_state",
      json{{"target_id", inst.target_id}}));
  REQUIRE(ls.ok);
  REQUIRE(ls.data["threads"].size() == 1);
  CHECK(ls.data["threads"][0].value("tid",   0) == 42);
  CHECK(ls.data["threads"][0].value("state", std::string{}) == "running");

  ::close(inst.peer_fd);
}

TEST_CASE("vCont-RSP: thread.suspend emits vCont;t:<tid> + drops the -32001 stub",
          "[dispatcher][rsp][vcont][thread][suspend]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher disp(be);
  auto inst = install_rsp_target(disp);

  auto resp = disp.dispatch(req("thread.suspend",
      json{{"target_id", inst.target_id}, {"tid", 7}}));
  REQUIRE(resp.ok);   // no longer -32001 for RSP-backed targets
  // The return state is intentionally "running" — the call is
  // fire-and-forget (no synchronous server confirmation), and some
  // servers ignore vCont;t for already-stopped threads. The agent
  // gets ground truth from thread.event{kind:stopped} when the
  // listener observes the server's stop reply.
  CHECK(resp.data.value("state", std::string{}) == "running");

  std::string bytes = drain_peer(inst.peer_fd, std::chrono::milliseconds(200));
  REQUIRE_FALSE(bytes.empty());
  auto payload = payload_of_frame(bytes);
  CHECK(payload == "vCont;t:7");

  ::close(inst.peer_fd);
}

// v1.6 #21 LLDB completion: thread.suspend now forwards to
// LldbBackend::suspend_thread for non-RSP targets. The pre-#21 stub
// unconditionally returned -32001; that disappeared once the backend
// virtual landed. Against an empty target with no live process the
// backend throws "no process", surfaced as -32004 kBackendError.
// RSP-backed targets still flow through vCont;t (covered above).
TEST_CASE("vCont-RSP: thread.suspend on a non-RSP target hits LldbBackend",
          "[dispatcher][rsp][vcont][thread][suspend][legacy]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher disp(be);

  auto open = disp.dispatch(req("target.create_empty", json::object()));
  REQUIRE(open.ok);
  std::uint64_t target_id = open.data["target_id"].get<std::uint64_t>();

  // No RspChannel installed — the LldbBackend path fires. The empty
  // target has no live process, so suspend_thread throws "no process"
  // and the dispatcher surfaces it as a backend error.
  auto resp = disp.dispatch(req("thread.suspend",
      json{{"target_id", target_id}, {"tid", 1}}));
  REQUIRE_FALSE(resp.ok);
  CHECK(resp.error_code == ErrorCode::kBackendError);
  CHECK(resp.error_message.find("no process") != std::string::npos);
}
