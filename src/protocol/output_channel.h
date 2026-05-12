// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "protocol/notifications.h"  // make_notification
#include "protocol/transport.h"      // WireFormat, write_message

#include <iosfwd>
#include <mutex>
#include <string_view>

// OutputChannel — the daemon's stdout-side write discipline
// (post-V1 #21 phase-2, docs/27-nonstop-listener.md §2).
//
// Until phase-2, the only writer to stdout was the dispatcher's RPC
// thread (one reply per request, strictly serial). Phase-2 adds the
// NonStopListener thread as a second writer (notifications fired on
// real stop events). Without serialisation, the two writers can
// interleave raw bytes mid-frame — a corrupted JSON line on the wire
// would desynchronise every JSON-RPC client.
//
// OutputChannel wraps the std::ostream + WireFormat pair behind a
// mutex. Each write — reply or notification — acquires the mutex
// briefly, encodes the frame via the existing protocol::write_message
// (so JSON-line / length-prefixed-CBOR framing is reused as-is), and
// releases. The encode is fast enough that contention is negligible
// in realistic workloads.
//
// The class is non-copyable / non-movable; callers pass it by
// reference. stdio_loop.cpp holds the canonical instance for stdout;
// tests construct one over a std::ostringstream.

namespace ldb::protocol {

class OutputChannel {
 public:
  OutputChannel(std::ostream& out, WireFormat fmt) : out_(out), fmt_(fmt) {}

  OutputChannel(const OutputChannel&)            = delete;
  OutputChannel& operator=(const OutputChannel&) = delete;
  OutputChannel(OutputChannel&&)                 = delete;
  OutputChannel& operator=(OutputChannel&&)      = delete;

  // Write a single JSON-RPC reply frame.
  void write_response(const json& reply);

  // Write a JSON-RPC 2.0 §4.1 notification frame. Convenience over
  // make_notification + write_message — the listener thread calls
  // this on every stop event.
  void write_notification(std::string_view method, json params);

 private:
  std::ostream& out_;
  WireFormat    fmt_;
  std::mutex    mu_;
};

// Concrete NotificationSink that forwards emit() into an
// OutputChannel. The dispatcher installs one of these on its
// NonStopRuntime so the listener thread's set_stopped calls
// surface as framed JSON-RPC notifications on stdout.
class StreamNotificationSink : public NotificationSink {
 public:
  explicit StreamNotificationSink(OutputChannel& out) : out_(out) {}
  void emit(std::string_view method, json params) override {
    out_.write_notification(method, std::move(params));
  }
 private:
  OutputChannel& out_;
};

}  // namespace ldb::protocol
