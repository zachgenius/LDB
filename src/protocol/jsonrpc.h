#pragma once

#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>

// JSON-RPC 2.0-ish framing. Line-delimited for M0 (one message per line).
// We extend with our own response fields (_cost, _provenance) — see docs/02.

namespace ldb::protocol {

using json = nlohmann::json;

// Standard JSON-RPC 2.0 error codes plus our own (-32000 .. -32099 = server).
enum class ErrorCode : int {
  kParseError      = -32700,
  kInvalidRequest  = -32600,
  kMethodNotFound  = -32601,
  kInvalidParams   = -32602,
  kInternalError   = -32603,
  // Server-defined
  kBackendError    = -32000,
  kNotImplemented  = -32001,
  kBadState        = -32002,
};

struct Request {
  std::optional<json> id;     // string|number|null|absent (notification if absent)
  std::string method;
  json params = json::object();
  // Future: format, view, session_id — parsed but ignored in M0.
};

struct Response {
  std::optional<json> id;
  bool ok = true;
  json data = json::object();             // when ok
  ErrorCode error_code = ErrorCode::kInternalError;
  std::string error_message;              // when !ok
  std::optional<json> error_data;
};

// Parse one JSON message into a Request. Throws on malformed.
Request parse_request(std::string_view line);

// Serialize a Response to a single-line JSON string (terminator NOT included).
std::string serialize_response(const Response& r);

// Convenience constructors.
Response make_ok(std::optional<json> id, json data);
Response make_err(std::optional<json> id, ErrorCode code,
                  std::string message,
                  std::optional<json> data = std::nullopt);

}  // namespace ldb::protocol
