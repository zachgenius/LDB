// SPDX-License-Identifier: Apache-2.0
#include "runtime/nonstop_listener.h"

#include "transport/rsp/channel.h"
#include "transport/rsp/packets.h"

#include <cstdlib>
#include <string>

namespace ldb::runtime {

namespace {

// Parse a hex string into a thread-id. Empty string / non-hex → 0.
// Tolerant by design: the gdb-remote wire occasionally hands us
// short tids and we'd rather record a stop against tid=0 than drop
// the event entirely.
backend::ThreadId parse_tid_hex(const std::string& s) {
  if (s.empty()) return 0;
  char* end = nullptr;
  auto v = std::strtoull(s.c_str(), &end, 16);
  if (end == s.c_str()) return 0;
  return static_cast<backend::ThreadId>(v);
}

// Map a parsed StopReply onto our ThreadStop. Picks load-bearing
// kv-pairs by their well-known names; unknown keys are ignored.
ThreadStop to_thread_stop(const transport::rsp::StopReply& r,
                          backend::ThreadId* tid_out) {
  ThreadStop info;
  info.signal = r.signal;
  switch (r.type) {
    case 'W':
      info.reason = "exited";
      break;
    case 'X':
      info.reason = "signalled";
      break;
    case 'S':
      // Short form — no kv-pairs to mine; reason left blank, caller
      // can derive from the signal.
      break;
    case 'T':
      // T-reply: scan the kv-pairs for thread / reason / <reg>.
      for (const auto& kv : r.kv) {
        if (kv.first == "thread") *tid_out = parse_tid_hex(kv.second);
        else if (kv.first == "reason") info.reason = kv.second;
        // Other kv entries (core, hwbreak, watch, register values …)
        // are intentionally ignored in phase-2. Phase-3 may carry the
        // register block forward into the notification.
      }
      break;
    default:
      break;
  }
  return info;
}

}  // namespace

NonStopListener::NonStopListener(NonStopRuntime& runtime,
                                  std::chrono::milliseconds poll_interval)
    : runtime_(runtime), poll_interval_(poll_interval) {
  worker_ = std::thread(&NonStopListener::thread_main_, this);
}

NonStopListener::~NonStopListener() {
  shutdown_.store(true, std::memory_order_release);
  if (worker_.joinable()) worker_.join();
}

void NonStopListener::register_target(backend::TargetId target,
                                       transport::rsp::RspChannel* chan) {
  std::unique_lock lk(map_mu_);
  by_target_[target] = chan;
}

void NonStopListener::unregister_target(backend::TargetId target) {
  // Exclusive lock blocks until the listener's current iteration (if
  // any) releases its shared lock. After this returns, no listener
  // thread call into chan->recv() can be in flight against this
  // channel — the dispatcher may safely destroy it.
  std::unique_lock lk(map_mu_);
  by_target_.erase(target);
}

void NonStopListener::apply_stop_reply_for_test(backend::TargetId target,
                                                 std::string_view payload) {
  apply_payload_(target, payload);
}

void NonStopListener::thread_main_() {
  while (!shutdown_.load(std::memory_order_acquire)) {
    // Hold shared_lock for the entire iteration (snapshot + recv +
    // apply). unregister_target waits at most one iteration; given a
    // poll_interval of ~20 ms and a handful of channels, the
    // upper bound is well under a typical RPC's response latency.
    {
      std::shared_lock lk(map_mu_);
      for (const auto& [tid, chan] : by_target_) {
        auto payload = chan->recv(poll_interval_);
        if (payload.has_value()) {
          apply_payload_(tid, *payload);
        }
      }
    }
    // If we have no registrations, recv() didn't run — burn poll
    // interval here so the busy loop doesn't spin on shutdown_.
    {
      std::shared_lock lk(map_mu_);
      if (by_target_.empty()) {
        lk.unlock();
        std::this_thread::sleep_for(poll_interval_);
      }
    }
  }
}

void NonStopListener::apply_payload_(backend::TargetId target,
                                      std::string_view payload) {
  auto parsed = transport::rsp::parse_stop_reply(payload);
  if (!parsed.has_value()) {
    // Garbled / wrong-shape — drop. The dispatcher's req/resp paths
    // don't typically share a channel with the listener (we want
    // them to one day, but that's #17-phase-2). Until then, only
    // unsolicited stop replies should land here.
    return;
  }
  backend::ThreadId tid = 0;
  ThreadStop info = to_thread_stop(*parsed, &tid);
  runtime_.set_stopped(target, tid, std::move(info));
}

}  // namespace ldb::runtime
