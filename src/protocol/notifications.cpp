// SPDX-License-Identifier: Apache-2.0
#include "protocol/notifications.h"

namespace ldb::protocol {

json make_notification(std::string_view method, json params) {
  json j;
  j["jsonrpc"] = "2.0";
  j["method"]  = std::string(method);
  j["params"]  = std::move(params);
  return j;
}

void CapturingNotificationSink::emit(std::string_view method, json params) {
  events.push_back({std::string(method), std::move(params)});
}

void CapturingNotificationSink::clear() {
  events.clear();
}

}  // namespace ldb::protocol
