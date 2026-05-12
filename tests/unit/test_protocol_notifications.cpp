// SPDX-License-Identifier: Apache-2.0
// Unit tests for JSON-RPC 2.0 §4.1 notification framing
// (post-V1 #21 phase-1).
//
// A notification is a request without an `id` field. The server emits
// these for async events (e.g. thread stopped) on the same stdio
// channel as replies. Conformance points:
//
//   * The serialised object has "jsonrpc": "2.0" and "method": <str>.
//   * The "id" field is absent — its presence would make this a Request,
//     and clients would (per spec) reply.
//   * "params" is present whenever the caller passes a non-null payload,
//     including an empty object. Phase-1 never elides params.
//   * The NotificationSink interface emits via emit(method, params).
//     A capturing sink (used by tests) records both arguments so the
//     listener-thread wiring in phase-2 has a deterministic test seam.
//
// Wire-format integration with the response stream + the byte-level
// stream lock lives in the dispatcher commit; this file pins the
// pure-shape contract.

#include <catch_amalgamated.hpp>

#include "protocol/notifications.h"

#include <string>

using ldb::protocol::CapturingNotificationSink;
using ldb::protocol::make_notification;

TEST_CASE("notifications: make_notification produces JSON-RPC 2.0 notification shape",
          "[notifications][shape]") {
  auto j = make_notification("thread.event",
                             nlohmann::json{{"tid", 1234}, {"kind", "stopped"}});
  REQUIRE(j.is_object());
  CHECK(j.value("jsonrpc", std::string{}) == "2.0");
  CHECK(j.value("method",  std::string{}) == "thread.event");
  CHECK(j.contains("params"));
  CHECK(j["params"].is_object());
  CHECK(j["params"].value("tid", -1) == 1234);
  CHECK(j["params"].value("kind", std::string{}) == "stopped");
  // The presence of "id" would make this a Request, not a Notification.
  // §4.1 of the JSON-RPC 2.0 spec is explicit: the absence of `id`
  // signals that no reply is desired.
  CHECK_FALSE(j.contains("id"));
}

TEST_CASE("notifications: make_notification preserves an empty params object",
          "[notifications][shape]") {
  auto j = make_notification("ping", nlohmann::json::object());
  CHECK(j.contains("params"));
  CHECK(j["params"].is_object());
  CHECK(j["params"].empty());
  CHECK_FALSE(j.contains("id"));
}

TEST_CASE("notifications: make_notification accepts array params",
          "[notifications][shape]") {
  // The spec allows params to be either an Object or an Array. We use
  // objects everywhere in LDB, but the serialiser doesn't get to
  // assume that.
  auto j = make_notification("batch", nlohmann::json::array({1, 2, 3}));
  REQUIRE(j["params"].is_array());
  CHECK(j["params"].size() == 3);
}

TEST_CASE("notifications: CapturingNotificationSink records every emit in order",
          "[notifications][sink]") {
  CapturingNotificationSink sink;
  sink.emit("thread.event", nlohmann::json{{"tid", 1}, {"kind", "stopped"}});
  sink.emit("thread.event", nlohmann::json{{"tid", 2}, {"kind", "exited"}});
  sink.emit("session.checkpoint", nlohmann::json{{"seq", 42}});

  REQUIRE(sink.events.size() == 3);
  CHECK(sink.events[0].method == "thread.event");
  CHECK(sink.events[0].params["tid"] == 1);
  CHECK(sink.events[1].params["kind"] == "exited");
  CHECK(sink.events[2].method == "session.checkpoint");
  CHECK(sink.events[2].params["seq"] == 42);
}

TEST_CASE("notifications: CapturingNotificationSink::clear resets the log",
          "[notifications][sink]") {
  CapturingNotificationSink sink;
  sink.emit("a", nlohmann::json::object());
  sink.emit("b", nlohmann::json::object());
  REQUIRE(sink.events.size() == 2);
  sink.clear();
  CHECK(sink.events.empty());
}
