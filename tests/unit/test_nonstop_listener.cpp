// SPDX-License-Identifier: Apache-2.0
// Unit tests for NonStopListener (post-V1 #21 phase-2,
// docs/27-nonstop-listener.md §3).
//
// The listener polls registered RspChannels for stop replies, parses
// them, and feeds them to a NonStopRuntime which fires thread.event
// notifications via the installed sink. Phase-2 ships this layer with
// the listener thread held off so its lifecycle is easy to test —
// every case here drives the parse + state-machine path via the
// `apply_stop_reply_for_test` seam, then a separate case proves the
// real listener thread comes up + shuts down cleanly.
//
// Coverage:
//   * T-reply with thread:hex;reason:trace; -> runtime kStopped,
//     sink emits thread.event with the right tid/reason/signal/pc.
//   * S-reply (signal only, no thread kv) -> tid=0 default; state
//     machine still records the stop; notification fires.
//   * W-reply (exited) -> recorded as kStopped with reason=exited.
//   * Garbled payload -> ignored, listener doesn't crash.
//   * register/unregister roundtrip — the listener thread observes
//     a registered channel's enqueued reply, fires the notification,
//     then the unregister returns without the test deadlocking on
//     the listener.

#include <catch_amalgamated.hpp>

#include "protocol/notifications.h"
#include "runtime/nonstop_listener.h"
#include "runtime/nonstop_runtime.h"
#include "transport/rsp/channel.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <memory>
#include <string>
#include <thread>

using ldb::backend::TargetId;
using ldb::backend::ThreadId;
using ldb::protocol::CapturingNotificationSink;
using ldb::runtime::NonStopListener;
using ldb::runtime::NonStopRuntime;
using ldb::runtime::ThreadState;
using ldb::transport::rsp::RspChannel;

namespace {

// Write a framed `$payload#cs8` envelope to `fd`.
void write_packet(int fd, std::string_view payload) {
  std::string framed = "$";
  framed += payload;
  framed += "#";
  unsigned sum = 0;
  for (char ch : payload) {
    sum = (sum + static_cast<unsigned char>(ch)) & 0xff;
  }
  char buf[3];
  std::snprintf(buf, sizeof(buf), "%02x", sum);
  framed.append(buf, 2);
  ::send(fd, framed.data(), framed.size(), 0);
}

}  // namespace

TEST_CASE("listener: apply T-reply records kStopped + fires thread.event",
          "[nonstop_listener][apply][T]") {
  NonStopRuntime rt;
  CapturingNotificationSink sink;
  rt.set_notification_sink(&sink);
  NonStopListener listener(rt);

  // Standard T stop reply: type=05 (SIGTRAP), thread=hex tid 0x4d2 = 1234,
  // reason=trace.
  listener.apply_stop_reply_for_test(TargetId{1},
      "T05thread:4d2;reason:trace;");

  auto state = rt.get_state(TargetId{1}, ThreadId{1234});
  REQUIRE(state.has_value());
  CHECK(*state == ThreadState::kStopped);
  CHECK(rt.stop_event_seq(TargetId{1}) == 1);

  REQUIRE(sink.events.size() == 1);
  const auto& ev = sink.events.front();
  CHECK(ev.method == "thread.event");
  CHECK(ev.params.value("kind", std::string{}) == "stopped");
  CHECK(ev.params.value("tid",  0) == 1234);
  CHECK(ev.params.value("reason", std::string{}) == "trace");
  CHECK(ev.params.value("signal", 0) == 5);
}

TEST_CASE("listener: apply S-reply with no thread kv defaults tid to 0",
          "[nonstop_listener][apply][S]") {
  // S is the legacy short stop-reply: signal byte only, no kv-pairs.
  // The listener still records a stop; tid defaults to 0 since the
  // server didn't say which thread.
  NonStopRuntime rt;
  CapturingNotificationSink sink;
  rt.set_notification_sink(&sink);
  NonStopListener listener(rt);

  listener.apply_stop_reply_for_test(TargetId{1}, "S0b");

  auto state = rt.get_state(TargetId{1}, ThreadId{0});
  REQUIRE(state.has_value());
  CHECK(*state == ThreadState::kStopped);
  REQUIRE(sink.events.size() == 1);
  CHECK(sink.events.front().params.value("signal", 0) == 0x0b);
}

TEST_CASE("listener: apply W-reply records kStopped with reason=exited",
          "[nonstop_listener][apply][W]") {
  NonStopRuntime rt;
  CapturingNotificationSink sink;
  rt.set_notification_sink(&sink);
  NonStopListener listener(rt);

  listener.apply_stop_reply_for_test(TargetId{1}, "W00");

  auto state = rt.get_state(TargetId{1}, ThreadId{0});
  REQUIRE(state.has_value());
  CHECK(*state == ThreadState::kStopped);
  REQUIRE(sink.events.size() == 1);
  CHECK(sink.events.front().params.value("reason", std::string{}) == "exited");
}

TEST_CASE("listener: garbled payload is silently dropped",
          "[nonstop_listener][apply][garbled]") {
  NonStopRuntime rt;
  CapturingNotificationSink sink;
  rt.set_notification_sink(&sink);
  NonStopListener listener(rt);

  // Random non-stop-reply payload — parse_stop_reply returns nullopt.
  listener.apply_stop_reply_for_test(TargetId{1}, "qSupported:swbreak+");

  CHECK(rt.stop_event_seq(TargetId{1}) == 0);
  CHECK(sink.events.empty());
}

TEST_CASE("listener: live thread observes register → server packet → notification",
          "[nonstop_listener][live]") {
  NonStopRuntime rt;
  CapturingNotificationSink sink;
  rt.set_notification_sink(&sink);

  // Tight poll interval so the test wakes quickly.
  NonStopListener listener(rt, std::chrono::milliseconds(5));

  int sv[2] = {-1, -1};
  REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  RspChannel::Config cfg;
  cfg.skip_handshake = true;
  cfg.ack_mode       = false;
  auto chan = std::make_unique<RspChannel>(RspChannel::AdoptFd{sv[0]}, cfg);
  int peer_fd = sv[1];

  listener.register_target(TargetId{7}, chan.get());

  // Server emits a T stop reply asynchronously; the channel's reader
  // thread enqueues it; the listener thread pops it and feeds the
  // runtime, which fires the notification.
  write_packet(peer_fd, "T05thread:1;reason:trace;");

  // Spin up to ~500 ms waiting for the notification. Real wake-time
  // should be a handful of ms; this bound is conservative.
  for (int i = 0; i < 100 && sink.events.empty(); ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  REQUIRE(sink.events.size() == 1);
  CHECK(sink.events.front().params.value("tid", 0) == 1);

  listener.unregister_target(TargetId{7});
  // After unregister returns, the channel may safely be destroyed.
  ::close(peer_fd);
}

TEST_CASE("listener: destructor joins cleanly even with no registrations",
          "[nonstop_listener][lifecycle]") {
  NonStopRuntime rt;
  NonStopListener listener(rt, std::chrono::milliseconds(5));
  // Destructor runs at end of scope — must not deadlock when no
  // channels were ever registered.
}
