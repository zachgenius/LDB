#include "daemon/dispatcher.h"

#include "backend/debugger_backend.h"
#include "ldb/version.h"
#include "util/log.h"

#include <utility>

namespace ldb::daemon {

using protocol::ErrorCode;
using protocol::Request;
using protocol::Response;
using protocol::json;

namespace {

json section_to_json(const backend::Section& s) {
  json j;
  j["name"] = s.name;
  j["file_addr"] = s.file_addr;
  j["load_addr"] = s.load_addr;
  j["size"] = s.size;
  j["perm"] = s.permissions;
  j["type"] = s.type;
  return j;
}

json module_to_json(const backend::Module& m) {
  json j;
  j["path"] = m.path;
  j["uuid"] = m.uuid;
  j["triple"] = m.triple;
  j["load_addr"] = m.load_address;
  json secs = json::array();
  for (const auto& s : m.sections) secs.push_back(section_to_json(s));
  j["sections"] = std::move(secs);
  return j;
}

const std::string* require_string(const json& obj, const char* key) {
  auto it = obj.find(key);
  if (it == obj.end() || !it->is_string()) return nullptr;
  return it->get_ptr<const std::string*>();
}

bool require_uint(const json& obj, const char* key, std::uint64_t* out) {
  auto it = obj.find(key);
  if (it == obj.end()) return false;
  if (it->is_number_unsigned()) { *out = it->get<std::uint64_t>(); return true; }
  if (it->is_number_integer()) {
    auto v = it->get<std::int64_t>();
    if (v < 0) return false;
    *out = static_cast<std::uint64_t>(v);
    return true;
  }
  return false;
}

}  // namespace

// ----------------------------------------------------------------------------

Dispatcher::Dispatcher(std::shared_ptr<backend::DebuggerBackend> backend)
    : backend_(std::move(backend)) {}

Dispatcher::~Dispatcher() = default;

Response Dispatcher::dispatch(const Request& req) {
  try {
    if (req.method == "hello")              return handle_hello(req);
    if (req.method == "describe.endpoints") return handle_describe_endpoints(req);
    if (req.method == "target.open")        return handle_target_open(req);
    if (req.method == "target.close")       return handle_target_close(req);
    if (req.method == "module.list")        return handle_module_list(req);

    return protocol::make_err(req.id, ErrorCode::kMethodNotFound,
                              "unknown method: " + req.method);
  } catch (const backend::Error& e) {
    return protocol::make_err(req.id, ErrorCode::kBackendError, e.what());
  } catch (const std::exception& e) {
    log::error(std::string("internal error in handler: ") + e.what());
    return protocol::make_err(req.id, ErrorCode::kInternalError, e.what());
  }
}

// ---- Handlers --------------------------------------------------------------

Response Dispatcher::handle_hello(const Request& req) {
  json data;
  data["name"] = "ldbd";
  data["version"] = kVersionString;
  data["protocol"] = {
    {"major", kProtocolMajor},
    {"minor", kProtocolMinor},
  };
  data["formats"] = json::array({"json"});  // CBOR / json-compact / tabular: post-M0
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_describe_endpoints(const Request& req) {
  // Minimal hand-written catalog for M0. Will be schema-generated in M1+.
  json eps = json::array();
  auto add = [&](const char* name, const char* summary, const json& params,
                 const json& returns) {
    json e;
    e["method"] = name;
    e["summary"] = summary;
    e["params"] = params;
    e["returns"] = returns;
    e["requires_target"] = (std::string(name) != "hello" &&
                            std::string(name) != "describe.endpoints" &&
                            std::string(name) != "target.open");
    eps.push_back(std::move(e));
  };

  add("hello", "Server identification and protocol version",
      json::object(),
      json{{"name", "string"}, {"version", "string"}, {"protocol", "object"}});

  add("describe.endpoints", "List supported methods with their schemas",
      json::object(),
      json{{"endpoints", "array"}});

  add("target.open", "Create a target from a binary on disk (no process)",
      json{{"path", "string"}},
      json{{"target_id", "uint64"}, {"triple", "string"}, {"modules", "array"}});

  add("target.close", "Drop a target",
      json{{"target_id", "uint64"}},
      json{{"closed", "bool"}});

  add("module.list", "Enumerate modules of a target",
      json{{"target_id", "uint64"}},
      json{{"modules", "array"}});

  json data;
  data["endpoints"] = std::move(eps);
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_target_open(const Request& req) {
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  const auto* path = require_string(req.params, "path");
  if (!path) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing string param 'path'");
  }

  auto res = backend_->open_executable(*path);
  json data;
  data["target_id"] = res.target_id;
  data["triple"] = res.triple;
  json mods = json::array();
  for (const auto& m : res.modules) mods.push_back(module_to_json(m));
  data["modules"] = std::move(mods);
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_target_close(const Request& req) {
  std::uint64_t tid = 0;
  if (!req.params.is_object() || !require_uint(req.params, "target_id", &tid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }
  backend_->close_target(static_cast<backend::TargetId>(tid));
  return protocol::make_ok(req.id, json{{"closed", true}});
}

Response Dispatcher::handle_module_list(const Request& req) {
  std::uint64_t tid = 0;
  if (!req.params.is_object() || !require_uint(req.params, "target_id", &tid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }
  auto mods = backend_->list_modules(static_cast<backend::TargetId>(tid));
  json arr = json::array();
  for (const auto& m : mods) arr.push_back(module_to_json(m));
  return protocol::make_ok(req.id, json{{"modules", std::move(arr)}});
}

}  // namespace ldb::daemon
