// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "backend/debugger_backend.h"   // TargetId, ThreadId
#include "protocol/notifications.h"

#include <cstdint>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

// Non-stop runtime — per-target per-thread state machine + push-event
// surface (post-V1 #21 phase-1, docs/26-nonstop-runtime.md).
//
// Phase-1 ships the synchronous state contract: the dispatcher records
// transitions when it dispatches thread.continue / process.continue and
// when a stop event surfaces from the backend. Queries (snapshot,
// stop_event_seq) are served from the in-memory map. A registered
// NotificationSink receives thread.event{kind:stopped} pushes when
// set_stopped runs.
//
// Phase-2 will add a listener thread that owns the entire feeder side:
// it drains LldbBackend's SBListener / RspChannel's recv queue, calls
// set_stopped on its own, and produces the same notifications without
// the dispatcher's RPC thread synchronously synthesising them. The
// state-machine surface is identical in both phases — the listener is
// purely a different writer.
//
// Thread-safety: shared_mutex. Reads (get_state, snapshot,
// stop_event_seq) take shared locks; writes (set_running, set_stopped,
// forget_*) take exclusive locks. The sink pointer is set once at
// dispatcher construction; we don't synchronise that field.

namespace ldb::runtime {

enum class ThreadState : std::uint8_t {
  kStopped,
  kRunning,
};

// Reason / signal / pc for a stop event. Mirrors the gdb-remote
// `T` stop reply's load-bearing fields without coupling to the
// transport layer.
struct ThreadStop {
  std::string   reason;          // "trace", "breakpoint", "signal", ...
  std::uint8_t  signal = 0;
  std::uint64_t pc     = 0;
};

struct ThreadEntry {
  backend::ThreadId         tid     = 0;
  ThreadState               state   = ThreadState::kStopped;
  std::optional<ThreadStop> last_stop;
};

class NonStopRuntime {
 public:
  // Lifetime: install a sink pointer (the daemon's NotificationSink)
  // before any thread starts emitting transitions. Null sink = silent
  // mode (state machine still runs; no notifications). The pointer is
  // borrowed; the caller owns the lifetime.
  void set_notification_sink(protocol::NotificationSink* sink) {
    sink_ = sink;
  }

  // State transitions. set_running / set_stopped insert the thread if
  // we haven't seen it before, so the dispatcher can register state
  // without first asking the backend for a thread list.
  void set_running(backend::TargetId target, backend::ThreadId tid);
  void set_stopped(backend::TargetId target,
                   backend::ThreadId tid,
                   ThreadStop info);

  // Bookkeeping. forget_thread drops a single entry (used when a
  // thread exits); forget_target drops the entire per-target map and
  // resets stop_event_seq to 0 (used on target.close).
  void forget_thread(backend::TargetId target, backend::ThreadId tid);
  void forget_target(backend::TargetId target);

  // Queries.
  std::optional<ThreadState>
       get_state(backend::TargetId target, backend::ThreadId tid) const;
  std::vector<ThreadEntry>
       snapshot(backend::TargetId target) const;
  std::uint64_t
       stop_event_seq(backend::TargetId target) const;

 private:
  struct TargetState {
    std::unordered_map<backend::ThreadId, ThreadEntry> threads;
    std::uint64_t                                       stop_event_seq = 0;
  };

  // The listener-thread design (phase-2) is the second writer to
  // `by_target_`; phase-1 already takes the lock so the read/write
  // boundary is one-line to switch when that lands. Per docs/26 §2.1
  // the listener holds shared locks while *consuming* events and runs
  // its writes through this same set_stopped path — there's no
  // separate listener-only entry point.
  mutable std::shared_mutex mu_;
  std::unordered_map<backend::TargetId, TargetState> by_target_;

  protocol::NotificationSink* sink_ = nullptr;

  // Build the {jsonrpc=2.0, method=thread.event, params={...}} payload
  // and forward to sink_->emit. Holds no locks.
  void emit_stopped_(backend::TargetId target,
                     backend::ThreadId tid,
                     std::uint64_t seq,
                     const ThreadStop& info) const;
};

}  // namespace ldb::runtime
