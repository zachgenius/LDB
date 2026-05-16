// SPDX-License-Identifier: Apache-2.0
#include "daemon/stdio_loop.h"

#include "protocol/cost.h"
#include "protocol/jsonrpc.h"
#include "protocol/provenance.h"
#include "protocol/transport.h"
#include "util/log.h"

#include <iostream>
#include <optional>
#include <string>

namespace ldb::daemon {

namespace {

// Build a Request from an already-decoded JSON value. Mirrors
// protocol::parse_request but skips the string-parse step — the wire
// transport gave us the json object directly (CBOR mode never went
// through a JSON string at all).
protocol::Request request_from_json(const protocol::json& j) {
  if (!j.is_object()) {
    throw std::invalid_argument("request must be a JSON/CBOR object");
  }
  protocol::Request req;
  if (auto it = j.find("jsonrpc"); it != j.end()) {
    if (!it->is_string() || it->get<std::string>() != "2.0") {
      throw std::invalid_argument("jsonrpc must be \"2.0\" if present");
    }
  }
  if (auto it = j.find("id"); it != j.end()) {
    req.id = *it;
  }
  auto m = j.find("method");
  if (m == j.end() || !m->is_string()) {
    throw std::invalid_argument("missing or non-string 'method'");
  }
  req.method = m->get<std::string>();
  if (auto p = j.find("params"); p != j.end()) {
    if (!p->is_object() && !p->is_array() && !p->is_null()) {
      throw std::invalid_argument("'params' must be object, array, or null");
    }
    req.params = *p;
  }
  return req;
}

// Same shape as protocol::serialize_response but returns a json instead
// of a string — write_message handles the encode-to-wire step.
protocol::json response_to_json(const protocol::Response& r) {
  protocol::json j;
  j["jsonrpc"] = "2.0";
  if (r.id.has_value()) j["id"] = *r.id;
  else j["id"] = nullptr;
  j["ok"] = r.ok;
  if (r.ok) {
    j["data"] = r.data;
    // Cost-preview metadata (plan §3.2). Mirrors serialize_response —
    // present only on successful responses; computed against `data`.
    j["_cost"] = protocol::cost::compute_cost(r.data);
    // Provenance metadata (plan §3.5, cores-only MVP). Mirrors
    // serialize_response — alongside `_cost`, never inside it.
    j["_provenance"] =
        protocol::provenance::compute(r.provenance_snapshot);
  } else {
    protocol::json err;
    err["code"] = static_cast<int>(r.error_code);
    err["message"] = r.error_message;
    if (r.error_data.has_value()) err["data"] = *r.error_data;
    j["error"] = std::move(err);
  }
  return j;
}

}  // namespace

int serve_one_connection(Dispatcher& dispatcher,
                         protocol::OutputChannel& out,
                         std::istream& in,
                         protocol::WireFormat fmt) {
  while (true) {
    std::optional<protocol::json> incoming;
    try {
      incoming = protocol::read_message(in, fmt);
    } catch (const protocol::Error& e) {
      // Malformed framing — log to stderr and try to surface a typed
      // error to the peer if we can. With JSON we can recover (sender
      // sees one bad-frame error and continues); with CBOR a torn frame
      // means the prefix/body desync is unrecoverable, so emit a final
      // error and exit. OutputChannel serialises us against the
      // listener thread's notification writes (#21 phase-2).
      log::error(std::string("framing error: ") + e.what());
      auto err = protocol::make_err(std::nullopt,
                                    protocol::ErrorCode::kParseError,
                                    std::string("framing error: ") + e.what());
      try {
        out.write_response(response_to_json(err));
      } catch (const protocol::Error& we) {
        log::error(std::string("failed to send framing-error response: ") +
                   we.what());
      }
      if (fmt == protocol::WireFormat::kCbor) {
        // Can't continue — the byte stream is desynchronized.
        return 1;
      }
      continue;
    }
    if (!incoming.has_value()) return 0;  // clean EOF

    protocol::Response resp;
    bool is_notification = false;
    try {
      auto req = request_from_json(*incoming);
      is_notification = !req.id.has_value();
      resp = dispatcher.dispatch(req);
    } catch (const std::exception& e) {
      resp = protocol::make_err(std::nullopt,
                                protocol::ErrorCode::kInvalidRequest,
                                std::string("invalid request: ") + e.what());
    }
    if (is_notification) continue;

    try {
      out.write_response(response_to_json(resp));
    } catch (const protocol::Error& e) {
      log::error(std::string("failed to write response: ") + e.what());
      return 1;
    }
  }
}

int run_stdio_loop(Dispatcher& dispatcher,
                   protocol::OutputChannel& out,
                   protocol::WireFormat fmt) {
  // Disable stdio sync — keep things flowing.
  std::ios_base::sync_with_stdio(false);
  std::cin.tie(nullptr);

  log::info(std::string("stdio loop ready (format=") +
            (fmt == protocol::WireFormat::kCbor ? "cbor" : "json") + ")");

  int rc = serve_one_connection(dispatcher, out, std::cin, fmt);

  log::info("stdin closed; shutting down");
  return rc;
}

}  // namespace ldb::daemon
