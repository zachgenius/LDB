// SPDX-License-Identifier: Apache-2.0
#include "runtime/nonstop_runtime.h"

namespace ldb::runtime {

void NonStopRuntime::set_running(backend::TargetId target,
                                  backend::ThreadId tid) {
  std::unique_lock lk(mu_);
  auto& ts = by_target_[target];
  auto& th = ts.threads[tid];
  th.tid   = tid;
  th.state = ThreadState::kRunning;
  // last_stop intentionally retained — agents asking "where did this
  // thread last park?" get the previous stop info until a new one
  // arrives. Future-thread.event{kind:running} (phase-2) is the
  // discoverable signal that it left that spot.
}

void NonStopRuntime::set_stopped(backend::TargetId target,
                                  backend::ThreadId tid,
                                  ThreadStop info) {
  std::uint64_t seq_after = 0;
  ThreadStop    info_copy = info;
  {
    std::unique_lock lk(mu_);
    auto& ts = by_target_[target];
    auto& th = ts.threads[tid];
    th.tid       = tid;
    th.state     = ThreadState::kStopped;
    th.last_stop = std::move(info);
    seq_after    = ++ts.stop_event_seq;
  }
  // Notification emission happens *outside* mu_. The sink may block on
  // stdout / a captor's vector mutation; we don't want to hold the
  // runtime lock across that. emit_stopped_ takes its own shared lock
  // on sinks_mu_ to iterate the subscriber set.
  emit_stopped_(target, tid, seq_after, info_copy);
}

void NonStopRuntime::forget_thread(backend::TargetId target,
                                    backend::ThreadId tid) {
  std::unique_lock lk(mu_);
  auto it = by_target_.find(target);
  if (it == by_target_.end()) return;
  it->second.threads.erase(tid);
}

void NonStopRuntime::forget_target(backend::TargetId target) {
  std::unique_lock lk(mu_);
  by_target_.erase(target);
}

std::optional<ThreadState>
NonStopRuntime::get_state(backend::TargetId target,
                           backend::ThreadId tid) const {
  std::shared_lock lk(mu_);
  auto it = by_target_.find(target);
  if (it == by_target_.end()) return std::nullopt;
  auto jt = it->second.threads.find(tid);
  if (jt == it->second.threads.end()) return std::nullopt;
  return jt->second.state;
}

std::vector<ThreadEntry>
NonStopRuntime::snapshot(backend::TargetId target) const {
  std::shared_lock lk(mu_);
  auto it = by_target_.find(target);
  if (it == by_target_.end()) return {};
  std::vector<ThreadEntry> out;
  out.reserve(it->second.threads.size());
  for (const auto& kv : it->second.threads) out.push_back(kv.second);
  return out;
}

std::uint64_t
NonStopRuntime::stop_event_seq(backend::TargetId target) const {
  std::shared_lock lk(mu_);
  auto it = by_target_.find(target);
  if (it == by_target_.end()) return 0;
  return it->second.stop_event_seq;
}

NonStopRuntime::SubscriptionHandle
NonStopRuntime::add_notification_sink(protocol::NotificationSink* sink) {
  std::unique_lock lk(sinks_mu_);
  SubscriptionHandle h = next_handle_++;
  sinks_.push_back({h, sink});
  return h;
}

void NonStopRuntime::remove_notification_sink(SubscriptionHandle h) {
  std::unique_lock lk(sinks_mu_);
  for (auto it = sinks_.begin(); it != sinks_.end(); ++it) {
    if (it->handle == h) {
      sinks_.erase(it);
      return;
    }
  }
}

void NonStopRuntime::set_notification_sink(protocol::NotificationSink* sink) {
  std::unique_lock lk(sinks_mu_);
  sinks_.clear();
  if (sink != nullptr) {
    sinks_.push_back({next_handle_++, sink});
  }
}

void NonStopRuntime::emit_stopped_(backend::TargetId target,
                                    backend::ThreadId tid,
                                    std::uint64_t seq,
                                    const ThreadStop& info) const {
  // Snapshot the subscriber list under the shared lock, then drop it
  // before calling sink->emit. Sinks can block (OutputChannel's mutex,
  // a captor's vector grow); holding sinks_mu_ across that would
  // serialise every concurrent emit through one writer's slow path.
  std::vector<protocol::NotificationSink*> snapshot;
  {
    std::shared_lock lk(sinks_mu_);
    snapshot.reserve(sinks_.size());
    for (const auto& s : sinks_) snapshot.push_back(s.sink);
  }
  if (snapshot.empty()) return;

  // params shape matches docs/26 §1 ("New notification") with phase-1
  // scope: kind/target_id/tid/seq + reason/signal/pc when available.
  protocol::json params;
  params["kind"]      = "stopped";
  params["target_id"] = static_cast<std::uint64_t>(target);
  params["tid"]       = static_cast<std::uint64_t>(tid);
  params["seq"]       = seq;
  if (!info.reason.empty()) params["reason"] = info.reason;
  if (info.signal != 0)     params["signal"] = info.signal;
  if (info.pc     != 0)     params["pc"]     = info.pc;

  // Copy params for each delivery — emit() consumes by-value. Final
  // delivery moves the original.
  for (std::size_t i = 0; i + 1 < snapshot.size(); ++i) {
    snapshot[i]->emit("thread.event", params);
  }
  snapshot.back()->emit("thread.event", std::move(params));
}

}  // namespace ldb::runtime
