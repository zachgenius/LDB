#include "daemon/stdio_loop.h"

#include "protocol/jsonrpc.h"
#include "util/log.h"

#include <iostream>
#include <string>

namespace ldb::daemon {

int run_stdio_loop(Dispatcher& dispatcher) {
  // Disable stdout buffering of stdio sync — keep things flowing.
  std::ios_base::sync_with_stdio(false);
  std::cin.tie(nullptr);

  log::info("stdio loop ready");

  std::string line;
  while (std::getline(std::cin, line)) {
    if (line.empty()) continue;

    protocol::Response resp;
    try {
      auto req = protocol::parse_request(line);
      // Notifications (no id) still get dispatched, but their response is
      // suppressed on the wire.
      bool is_notification = !req.id.has_value();
      resp = dispatcher.dispatch(req);
      if (is_notification) continue;
    } catch (const protocol::json::parse_error& e) {
      resp = protocol::make_err(std::nullopt, protocol::ErrorCode::kParseError,
                                std::string("parse error: ") + e.what());
    } catch (const std::exception& e) {
      resp = protocol::make_err(std::nullopt, protocol::ErrorCode::kInvalidRequest,
                                std::string("invalid request: ") + e.what());
    }

    std::cout << protocol::serialize_response(resp) << '\n';
    std::cout.flush();
  }

  log::info("stdin closed; shutting down");
  return 0;
}

}  // namespace ldb::daemon
