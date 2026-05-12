// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "backend/debugger_backend.h"     // TargetId
#include "runtime/nonstop_runtime.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <shared_mutex>
#include <string_view>
#include <thread>
#include <unordered_map>

// NonStopListener — the second writer to NonStopRuntime
// (post-V1 #21 phase-2, docs/27-nonstop-listener.md §3).
//
// One thread per dispatcher (not per channel). On each iteration it
// snapshots the registered set of RspChannels under a shared lock,
// polls each with a short bounded recv timeout, parses any stop
// replies (T/S/W/X) via transport::rsp::parse_stop_reply, and feeds
// the runtime's set_stopped — which fires thread.event via the sink.
//
// register_target / unregister_target manage the channel registry.
// unregister_target blocks while the listener is mid-iteration, so by
// the time it returns the listener is guaranteed not to touch the
// channel pointer again — the dispatcher can safely destroy the
// channel afterwards.

namespace ldb::transport::rsp { class RspChannel; }

namespace ldb::runtime {

class NonStopListener {
 public:
  // Construct + start the listener thread. `runtime` is borrowed; the
  // listener stops before the runtime is destroyed (the dispatcher
  // owns both and the listener is declared after the runtime).
  // `poll_interval` is the per-channel recv timeout — small values
  // (5–50 ms) trade CPU for responsiveness.
  explicit NonStopListener(NonStopRuntime& runtime,
                            std::chrono::milliseconds poll_interval
                                = std::chrono::milliseconds(20));
  ~NonStopListener();

  NonStopListener(const NonStopListener&)            = delete;
  NonStopListener& operator=(const NonStopListener&) = delete;

  // Register a channel under target_id. The pointer is borrowed and
  // must outlive the corresponding unregister_target call. Idempotent
  // for the same target_id — re-register overwrites the prior entry.
  void register_target(backend::TargetId target,
                       transport::rsp::RspChannel* chan);

  // Drop the registration for target_id and wait for any in-flight
  // recv() on its channel to return. After this returns, the
  // dispatcher may safely destroy the channel.
  void unregister_target(backend::TargetId target);

  // Test seam — apply a single payload synchronously, bypassing the
  // listener thread. Mirrors what the listener does in production
  // (parse_stop_reply → ThreadStop → runtime.set_stopped). Used by
  // unit tests that don't want to depend on listener-thread timing.
  void apply_stop_reply_for_test(backend::TargetId target,
                                  std::string_view payload);

 private:
  void thread_main_();
  void apply_payload_(backend::TargetId target, std::string_view payload);

  NonStopRuntime&            runtime_;
  std::chrono::milliseconds  poll_interval_;

  std::atomic<bool>          shutdown_{false};
  std::thread                worker_;

  // Iteration lock: the listener thread holds shared lock for the
  // whole iteration (snapshot + recv + apply). register / unregister
  // take exclusive lock. This makes unregister wait at most one full
  // iteration before returning — bounded by poll_interval * channels.
  mutable std::shared_mutex                                       map_mu_;
  std::unordered_map<backend::TargetId, transport::rsp::RspChannel*>
                                                                  by_target_;
};

}  // namespace ldb::runtime
