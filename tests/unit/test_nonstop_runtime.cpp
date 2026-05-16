// SPDX-License-Identifier: Apache-2.0
// Unit tests for the non-stop runtime state machine
// (post-V1 #21 phase-1, docs/26-nonstop-runtime.md §2.1).
//
// Coverage:
//   * Threads start unknown; querying get_state returns nullopt.
//   * set_running / set_stopped transitions are visible to get_state +
//     snapshot, and stop_event_seq is monotonic per-target.
//   * Distinct targets have independent state — a transition on
//     target=1 doesn't bump target=2's seq.
//   * forget_thread drops one entry; forget_target drops all entries
//     for that target.
//   * Idempotent transitions: set_running on an already-running
//     thread is a no-op; set_stopped on an already-stopped thread
//     re-records the new stop info AND bumps seq (the listener may
//     deliver back-to-back stops at distinct PCs and the agent needs
//     to see each one).
//   * The runtime's NotificationSink wiring: when a sink is installed,
//     set_stopped emits a thread.event{kind:stopped, target_id, tid,
//     seq, reason, signal, pc} notification through it. No notification
//     when no sink. No notification on set_running (phase-1 ships
//     stopped events only; created/exited are phase-2).
//   * The notification carries the *new* stop_event_seq, not the
//     pre-transition value, so agents can correlate notifications
//     with snapshot() queries.

#include <catch_amalgamated.hpp>

#include "protocol/notifications.h"
#include "runtime/nonstop_runtime.h"

using ldb::backend::TargetId;
using ldb::backend::ThreadId;
using ldb::protocol::CapturingNotificationSink;
using ldb::runtime::NonStopRuntime;
using ldb::runtime::ThreadState;
using ldb::runtime::ThreadStop;

TEST_CASE("nonstop: unknown thread returns nullopt", "[nonstop][state]") {
  NonStopRuntime rt;
  CHECK_FALSE(rt.get_state(TargetId{1}, ThreadId{100}).has_value());
  CHECK(rt.snapshot(TargetId{1}).empty());
  CHECK(rt.stop_event_seq(TargetId{1}) == 0);
}

TEST_CASE("nonstop: set_running marks thread kRunning",
          "[nonstop][state]") {
  NonStopRuntime rt;
  rt.set_running(TargetId{1}, ThreadId{100});
  auto s = rt.get_state(TargetId{1}, ThreadId{100});
  REQUIRE(s.has_value());
  CHECK(*s == ThreadState::kRunning);
  // Resuming a thread isn't a stop event; seq doesn't bump.
  CHECK(rt.stop_event_seq(TargetId{1}) == 0);
}

TEST_CASE("nonstop: set_stopped marks kStopped, bumps per-target seq",
          "[nonstop][state][seq]") {
  NonStopRuntime rt;
  rt.set_stopped(TargetId{1}, ThreadId{100},
                 ThreadStop{.reason = "trace", .signal = 5, .pc = 0xdead});
  auto s = rt.get_state(TargetId{1}, ThreadId{100});
  REQUIRE(s.has_value());
  CHECK(*s == ThreadState::kStopped);
  CHECK(rt.stop_event_seq(TargetId{1}) == 1);

  rt.set_stopped(TargetId{1}, ThreadId{101},
                 ThreadStop{.reason = "breakpoint", .signal = 0, .pc = 0xbeef});
  CHECK(rt.stop_event_seq(TargetId{1}) == 2);
}

TEST_CASE("nonstop: targets are independent — seq doesn't cross",
          "[nonstop][state][seq]") {
  NonStopRuntime rt;
  rt.set_stopped(TargetId{1}, ThreadId{100},
                 ThreadStop{.reason = "trace"});
  rt.set_stopped(TargetId{2}, ThreadId{200},
                 ThreadStop{.reason = "breakpoint"});
  CHECK(rt.stop_event_seq(TargetId{1}) == 1);
  CHECK(rt.stop_event_seq(TargetId{2}) == 1);
  // A second stop on target=1 doesn't bump target=2.
  rt.set_stopped(TargetId{1}, ThreadId{100},
                 ThreadStop{.reason = "trace"});
  CHECK(rt.stop_event_seq(TargetId{1}) == 2);
  CHECK(rt.stop_event_seq(TargetId{2}) == 1);
}

TEST_CASE("nonstop: snapshot returns every thread for a target",
          "[nonstop][state][snapshot]") {
  NonStopRuntime rt;
  rt.set_stopped(TargetId{1}, ThreadId{100}, ThreadStop{.reason = "trace"});
  rt.set_running(TargetId{1}, ThreadId{101});
  rt.set_stopped(TargetId{1}, ThreadId{102}, ThreadStop{.reason = "breakpoint"});

  auto snap = rt.snapshot(TargetId{1});
  REQUIRE(snap.size() == 3);
  // Order isn't part of the contract; index by tid.
  std::map<ThreadId, ThreadState> by_tid;
  for (auto& e : snap) by_tid[e.tid] = e.state;
  CHECK(by_tid[ThreadId{100}] == ThreadState::kStopped);
  CHECK(by_tid[ThreadId{101}] == ThreadState::kRunning);
  CHECK(by_tid[ThreadId{102}] == ThreadState::kStopped);
}

TEST_CASE("nonstop: forget_thread drops one entry",
          "[nonstop][state][forget]") {
  NonStopRuntime rt;
  rt.set_stopped(TargetId{1}, ThreadId{100}, ThreadStop{});
  rt.set_stopped(TargetId{1}, ThreadId{101}, ThreadStop{});
  rt.forget_thread(TargetId{1}, ThreadId{100});
  CHECK_FALSE(rt.get_state(TargetId{1}, ThreadId{100}).has_value());
  CHECK(rt.get_state(TargetId{1}, ThreadId{101}).has_value());
  // Forgetting doesn't bump seq — it's bookkeeping, not a stop event.
  CHECK(rt.stop_event_seq(TargetId{1}) == 2);
}

TEST_CASE("nonstop: forget_target drops all entries + resets seq",
          "[nonstop][state][forget]") {
  NonStopRuntime rt;
  rt.set_stopped(TargetId{1}, ThreadId{100}, ThreadStop{});
  rt.set_stopped(TargetId{1}, ThreadId{101}, ThreadStop{});
  REQUIRE(rt.stop_event_seq(TargetId{1}) == 2);
  rt.forget_target(TargetId{1});
  CHECK(rt.snapshot(TargetId{1}).empty());
  // After target.close, an unrelated target.open could reuse the id;
  // seq must restart so the new session's notifications don't look
  // like a continuation of the prior one.
  CHECK(rt.stop_event_seq(TargetId{1}) == 0);
}

TEST_CASE("nonstop: set_stopped emits thread.event via the installed sink",
          "[nonstop][notification]") {
  NonStopRuntime rt;
  CapturingNotificationSink sink;
  rt.set_notification_sink(&sink);

  rt.set_stopped(TargetId{1}, ThreadId{100},
                 ThreadStop{.reason = "trace", .signal = 5, .pc = 0xdead});

  REQUIRE(sink.events.size() == 1);
  const auto& ev = sink.events.front();
  CHECK(ev.method == "thread.event");
  CHECK(ev.params.value("kind", std::string{}) == "stopped");
  CHECK(ev.params.value("target_id", 0) == 1);
  CHECK(ev.params.value("tid", 0) == 100);
  // The notification carries the post-transition seq, so agents can
  // correlate with a subsequent snapshot() query without an
  // off-by-one race.
  CHECK(ev.params.value("seq", 0) == 1);
  CHECK(ev.params.value("reason", std::string{}) == "trace");
  CHECK(ev.params.value("signal", 0) == 5);
  CHECK(ev.params.value("pc", 0ULL) == 0xdeadULL);
}

TEST_CASE("nonstop: set_running does not emit a notification (phase-1 scope)",
          "[nonstop][notification]") {
  NonStopRuntime rt;
  CapturingNotificationSink sink;
  rt.set_notification_sink(&sink);
  rt.set_running(TargetId{1}, ThreadId{100});
  CHECK(sink.events.empty());
}

TEST_CASE("nonstop: no sink installed → no emission, no crash",
          "[nonstop][notification]") {
  NonStopRuntime rt;
  // Just verify the call doesn't dereference a null sink.
  rt.set_stopped(TargetId{1}, ThreadId{100},
                 ThreadStop{.reason = "trace"});
  CHECK(rt.stop_event_seq(TargetId{1}) == 1);  // state machine still runs
}

// §2 phase 2 — prerequisite for multi-client. The old single-sink atomic
// pointer cannot route notifications correctly when two connections are
// attached: a stop event for target_id=1 (originating from client A)
// would arrive at whichever sink happened to be installed last. The
// fix is a subscriber SET — each connection adds its own sink, drops
// it on disconnect, and all live subscribers receive every notification.

TEST_CASE("nonstop: multi-subscriber sinks both receive a stop event",
          "[nonstop][notification][multi-client]") {
  NonStopRuntime rt;
  CapturingNotificationSink a, b;
  auto ha = rt.add_notification_sink(&a);
  auto hb = rt.add_notification_sink(&b);

  rt.set_stopped(TargetId{1}, ThreadId{100},
                 ThreadStop{.reason = "trace", .signal = 5, .pc = 0xdead});

  REQUIRE(a.events.size() == 1);
  REQUIRE(b.events.size() == 1);
  CHECK(a.events.front().method == "thread.event");
  CHECK(b.events.front().method == "thread.event");
  // Both see the same seq — there's exactly one stop event in the world.
  CHECK(a.events.front().params.value("seq", 0) == 1);
  CHECK(b.events.front().params.value("seq", 0) == 1);

  rt.remove_notification_sink(ha);
  rt.remove_notification_sink(hb);
}

TEST_CASE("nonstop: removed sink stops receiving notifications",
          "[nonstop][notification][multi-client]") {
  NonStopRuntime rt;
  CapturingNotificationSink a, b;
  auto ha = rt.add_notification_sink(&a);
  auto hb = rt.add_notification_sink(&b);

  rt.set_stopped(TargetId{1}, ThreadId{100}, ThreadStop{.reason = "trace"});
  rt.remove_notification_sink(ha);
  rt.set_stopped(TargetId{1}, ThreadId{100}, ThreadStop{.reason = "step"});

  // a got the first event but not the second; b got both.
  CHECK(a.events.size() == 1);
  CHECK(b.events.size() == 2);
  rt.remove_notification_sink(hb);
}

TEST_CASE("nonstop: set_notification_sink replaces the entire subscriber set",
          "[nonstop][notification][multi-client]") {
  // Back-compat shim for stdio mode: callers that haven't been migrated
  // to add/remove keep calling set_notification_sink. The new semantics
  // are "clear all subscribers, install this one" — so the stdio
  // daemon still wires up correctly without code changes downstream.
  NonStopRuntime rt;
  CapturingNotificationSink a, b;
  rt.add_notification_sink(&a);  // intentionally unused handle — see below
  rt.set_notification_sink(&b);

  rt.set_stopped(TargetId{1}, ThreadId{100}, ThreadStop{.reason = "trace"});
  CHECK(a.events.empty());        // replaced
  CHECK(b.events.size() == 1);    // sole subscriber now
}

TEST_CASE("nonstop: set_notification_sink(nullptr) clears all subscribers",
          "[nonstop][notification][multi-client]") {
  NonStopRuntime rt;
  CapturingNotificationSink a;
  rt.set_notification_sink(&a);
  rt.set_notification_sink(nullptr);  // legacy "clear" usage
  rt.set_stopped(TargetId{1}, ThreadId{100}, ThreadStop{.reason = "trace"});
  CHECK(a.events.empty());
}
