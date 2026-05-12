// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <nlohmann/json.hpp>

#include <mutex>
#include <string>
#include <string_view>
#include <vector>

// JSON-RPC 2.0 §4.1 notification framing for ldbd's async push-event
// surface (post-V1 #21 phase-1, docs/26-nonstop-runtime.md).
//
// A *notification* is a request without an `id` field. The server emits
// it on the existing JSON-RPC channel; clients ignore it unless they
// opt into subscription semantics. Phase-1 uses this for thread.event /
// process.event push notifications fed by the non-stop runtime's
// listener thread; v1.5 #16-style session checkpoints / artifact events
// can reuse the same surface in later commits.

namespace ldb::protocol {

using json = nlohmann::json;

// Build the wire-shape JSON object for a notification. The result has
// the canonical fields {jsonrpc, method, params} and intentionally
// omits `id`. Caller passes `params` already-serialised; an empty
// object is preserved (we never elide it — agents that branch on
// `params` presence read a stable shape).
json make_notification(std::string_view method, json params);

// Notification sink — the dispatcher / non-stop runtime publishes
// async events through this interface so tests can capture them
// deterministically while production wiring forwards to the
// stdio stream.
class NotificationSink {
 public:
  virtual ~NotificationSink() = default;
  virtual void emit(std::string_view method, json params) = 0;
};

// Test sink — records emissions in order. Lock-free; tests are
// single-threaded by construction, and the runtime's listener
// thread is the only writer in the production path.
class CapturingNotificationSink : public NotificationSink {
 public:
  struct Event {
    std::string method;
    json        params;
  };
  std::vector<Event> events;
  void emit(std::string_view method, json params) override;
  void clear();
};

}  // namespace ldb::protocol
