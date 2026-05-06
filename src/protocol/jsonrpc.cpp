#include "protocol/jsonrpc.h"

#include "protocol/cost.h"
#include "protocol/provenance.h"

#include <stdexcept>

namespace ldb::protocol {

Request parse_request(std::string_view line) {
  json j = json::parse(line);  // throws nlohmann::json::parse_error
  if (!j.is_object()) {
    throw std::invalid_argument("request must be a JSON object");
  }

  Request req;

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

std::string serialize_response(const Response& r) {
  json j;
  j["jsonrpc"] = "2.0";
  if (r.id.has_value()) {
    j["id"] = *r.id;
  } else {
    j["id"] = nullptr;
  }
  j["ok"] = r.ok;
  if (r.ok) {
    j["data"] = r.data;
    // Cost-preview metadata, plan §3.2. Only on successful responses;
    // errors are short and don't benefit. Computed against the data
    // payload — bytes is the exact serialized size of `data`.
    j["_cost"] = cost::compute_cost(r.data);
    // Provenance metadata, plan §3.5 (cores-only MVP). Same shape
    // alongside `_cost`; never inside it, so `_cost.bytes` stays the
    // exact serialized length of `data`.
    j["_provenance"] = provenance::compute(r.provenance_snapshot);
  } else {
    json err;
    err["code"] = static_cast<int>(r.error_code);
    err["message"] = r.error_message;
    if (r.error_data.has_value()) err["data"] = *r.error_data;
    j["error"] = std::move(err);
  }
  return j.dump();
}

Response make_ok(std::optional<json> id, json data) {
  Response r;
  r.id = std::move(id);
  r.ok = true;
  r.data = std::move(data);
  return r;
}

Response make_err(std::optional<json> id, ErrorCode code,
                  std::string message, std::optional<json> data) {
  Response r;
  r.id = std::move(id);
  r.ok = false;
  r.error_code = code;
  r.error_message = std::move(message);
  r.error_data = std::move(data);
  return r;
}

}  // namespace ldb::protocol
