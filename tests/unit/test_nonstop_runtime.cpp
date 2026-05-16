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

#include <atomic>
#include <chrono>
#include <memory>
#include <thread>

using ldb::backend::TargetId;
using ldb::backend::ThreadId;
using ldb::protocol::CapturingNotificationSink;
using ldb::protocol::NotificationSink;
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
  auto sink = std::make_shared<CapturingNotificationSink>();
  rt.set_notification_sink(sink);

  rt.set_stopped(TargetId{1}, ThreadId{100},
                 ThreadStop{.reason = "trace", .signal = 5, .pc = 0xdead});

  REQUIRE(sink->events.size() == 1);
  const auto& ev = sink->events.front();
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
  auto sink = std::make_shared<CapturingNotificationSink>();
  rt.set_notification_sink(sink);
  rt.set_running(TargetId{1}, ThreadId{100});
  CHECK(sink->events.empty());
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

// Tag rename (post-review doc/I1): renamed from `[multi-client]` to
// `[broadcast]`. The code is broadcast-to-all; per-target routing is a
// phase-3 item. Naming the tests accurately matters more than tracking
// the feature name.

TEST_CASE("nonstop: multi-subscriber sinks both receive a stop event",
          "[nonstop][notification][broadcast]") {
  NonStopRuntime rt;
  auto a = std::make_shared<CapturingNotificationSink>();
  auto b = std::make_shared<CapturingNotificationSink>();
  auto ha = rt.add_notification_sink(a);
  auto hb = rt.add_notification_sink(b);

  rt.set_stopped(TargetId{1}, ThreadId{100},
                 ThreadStop{.reason = "trace", .signal = 5, .pc = 0xdead});

  REQUIRE(a->events.size() == 1);
  REQUIRE(b->events.size() == 1);
  CHECK(a->events.front().method == "thread.event");
  CHECK(b->events.front().method == "thread.event");
  // Both see the same seq — there's exactly one stop event in the world.
  CHECK(a->events.front().params.value("seq", 0) == 1);
  CHECK(b->events.front().params.value("seq", 0) == 1);

  rt.remove_notification_sink(ha);
  rt.remove_notification_sink(hb);
}

TEST_CASE("nonstop: removed sink stops receiving notifications",
          "[nonstop][notification][broadcast]") {
  NonStopRuntime rt;
  auto a = std::make_shared<CapturingNotificationSink>();
  auto b = std::make_shared<CapturingNotificationSink>();
  auto ha = rt.add_notification_sink(a);
  auto hb = rt.add_notification_sink(b);

  rt.set_stopped(TargetId{1}, ThreadId{100}, ThreadStop{.reason = "trace"});
  rt.remove_notification_sink(ha);
  rt.set_stopped(TargetId{1}, ThreadId{100}, ThreadStop{.reason = "step"});

  // a got the first event but not the second; b got both.
  CHECK(a->events.size() == 1);
  CHECK(b->events.size() == 2);
  rt.remove_notification_sink(hb);
}

TEST_CASE("nonstop: set_notification_sink replaces the entire subscriber set",
          "[nonstop][notification][broadcast]") {
  // Back-compat shim for stdio mode: callers that haven't been migrated
  // to add/remove keep calling set_notification_sink. The new semantics
  // are "clear all subscribers, install this one" — so the stdio
  // daemon still wires up correctly without code changes downstream.
  NonStopRuntime rt;
  auto a = std::make_shared<CapturingNotificationSink>();
  auto b = std::make_shared<CapturingNotificationSink>();
  rt.add_notification_sink(a);  // intentionally unused handle — see below
  rt.set_notification_sink(b);

  rt.set_stopped(TargetId{1}, ThreadId{100}, ThreadStop{.reason = "trace"});
  CHECK(a->events.empty());        // replaced
  CHECK(b->events.size() == 1);    // sole subscriber now
}

TEST_CASE("nonstop: set_notification_sink(nullptr) clears all subscribers",
          "[nonstop][notification][broadcast]") {
  NonStopRuntime rt;
  auto a = std::make_shared<CapturingNotificationSink>();
  rt.set_notification_sink(a);
  rt.set_notification_sink(std::shared_ptr<NotificationSink>{});  // legacy "clear" usage
  rt.set_stopped(TargetId{1}, ThreadId{100}, ThreadStop{.reason = "trace"});
  CHECK(a->events.empty());
}

// C1 (post-review punch list): the pre-fix design stored raw
// NotificationSink* pointers, snapshotted them into a local vector
// under a shared lock, dropped the lock, then dereferenced. A
// concurrent remove_notification_sink + sink destruction (stack-local
// sink in socket_loop's per-connection worker) could free the sink
// while the listener thread still held the raw pointer in its
// snapshot. TSan-reproduced as a vptr race + segfault.
//
// The fix is shared_ptr storage: the snapshot bumps refcounts, keeping
// every sink alive across the iteration regardless of concurrent
// remove. This test stresses the boundary — a hot adder/remover
// thread vs a hot emit thread — and asserts no crash. Without the
// fix this segv's under TSan/ASan within a fraction of a second;
// with the fix the loop completes cleanly.
namespace {
// A throwaway sink that exists only to be destructed mid-emit. emit()
// touches a member so the vptr lookup is part of the race window —
// pre-fix UAF surfaces as either a TSan vptr-race report, an ASan
// heap-use-after-free, or a SEGV depending on how the heap got reused.
class ScratchSink : public NotificationSink {
 public:
  void emit(std::string_view, ldb::protocol::json) override {
    ++delivered;
  }
  std::atomic<int> delivered{0};
};
}  // namespace

TEST_CASE("nonstop: concurrent add/remove + emit does not UAF",
          "[nonstop][notification][concurrency][uaf]") {
  // Run for a fixed wall-clock budget rather than an iteration count so
  // slow CI machines still get full coverage. 200ms is enough to
  // surface the pre-fix UAF reliably under ASan/TSan on a developer
  // Mac; pure refcounting overhead in the fixed version finishes the
  // loop without hitting the deadline. Test passes when no crash
  // occurs.
  NonStopRuntime rt;
  std::atomic<bool> stop{false};

  // Emitter: fires stop events as fast as possible. Each set_stopped
  // takes the runtime's exclusive lock briefly, then calls
  // emit_stopped_ outside the runtime lock — exactly the path where
  // the pre-fix UAF races against a concurrent remove +
  // sink-destruction.
  std::thread emitter([&] {
    std::uint64_t tid = 1;
    while (!stop.load(std::memory_order_relaxed)) {
      rt.set_stopped(TargetId{1}, ThreadId{tid++},
                     ThreadStop{.reason = "race", .signal = 0, .pc = 0});
    }
  });

  // Churn: adds a sink, immediately removes it, then drops the
  // shared_ptr. With raw pointers, the sink destructs the moment the
  // local goes out of scope — racing the emitter's dereference. With
  // shared_ptr storage the snapshot inside emit_stopped_ keeps the
  // sink alive until iteration finishes.
  std::thread churn([&] {
    while (!stop.load(std::memory_order_relaxed)) {
      auto sink = std::make_shared<ScratchSink>();
      auto h = rt.add_notification_sink(sink);
      rt.remove_notification_sink(h);
      // sink destructed here as the local shared_ptr drops. Emitter
      // may have already snapshotted us; its snapshot holds a ref so
      // we either die now or after the listener's loop completes.
    }
  });

  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  stop.store(true, std::memory_order_relaxed);
  emitter.join();
  churn.join();
  // Reaching here without crash IS the assertion. seq is the only
  // observable side-effect safe to inspect.
  CHECK(rt.stop_event_seq(TargetId{1}) > 0);
}

TEST_CASE("nonstop: runtime keeps sink alive across emit even if "
          "caller drops its ref",
          "[nonstop][notification][uaf]") {
  // Synchronous version of the race above: register a sink, drop the
  // caller's strong ref, then emit. The runtime's storage keeps the
  // sink alive across the emit_stopped_ path even though the original
  // caller has no remaining handle. With raw pointers this would have
  // been an immediate UAF the moment the local went out of scope —
  // shared_ptr storage makes the lifetime contract obvious.
  NonStopRuntime rt;
  std::weak_ptr<CapturingNotificationSink> weak;
  NonStopRuntime::SubscriptionHandle h = 0;
  {
    auto sink = std::make_shared<CapturingNotificationSink>();
    weak = sink;
    h = rt.add_notification_sink(sink);
    // Original caller drops its ref; runtime holds the only strong
    // ref now.
  }
  CHECK_FALSE(weak.expired());   // runtime keeps the sink alive
  rt.set_stopped(TargetId{1}, ThreadId{1}, ThreadStop{.reason = "x"});
  // The sink received the event — runtime's strong ref kept it alive
  // through the emit path.
  auto locked = weak.lock();
  REQUIRE(locked != nullptr);
  CHECK(locked->events.size() == 1);
  rt.remove_notification_sink(h);
  locked.reset();
  CHECK(weak.expired());          // now nothing keeps it alive
}
