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

const char* symbol_kind_str(backend::SymbolKind k) {
  switch (k) {
    case backend::SymbolKind::kAny:      return "any";
    case backend::SymbolKind::kFunction: return "function";
    case backend::SymbolKind::kVariable: return "variable";
    case backend::SymbolKind::kOther:    return "other";
  }
  return "other";
}

bool parse_symbol_kind(const std::string& s, backend::SymbolKind* out) {
  if (s == "any" || s.empty())   { *out = backend::SymbolKind::kAny;      return true; }
  if (s == "function")           { *out = backend::SymbolKind::kFunction; return true; }
  if (s == "variable")           { *out = backend::SymbolKind::kVariable; return true; }
  if (s == "other")              { *out = backend::SymbolKind::kOther;    return true; }
  return false;
}

std::string hex_bytes(const std::vector<std::uint8_t>& bytes) {
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 3);
  for (size_t i = 0; i < bytes.size(); ++i) {
    if (i) out.push_back(' ');
    out.push_back(kHex[(bytes[i] >> 4) & 0xF]);
    out.push_back(kHex[bytes[i] & 0xF]);
  }
  return out;
}

json xref_match_to_json(const backend::XrefMatch& x) {
  json j;
  j["addr"]     = x.address;
  j["sz"]       = x.byte_size;
  j["mnemonic"] = x.mnemonic;
  j["operands"] = x.operands;
  j["function"] = x.function;
  if (!x.comment.empty()) j["comment"] = x.comment;
  return j;
}

json disasm_insn_to_json(const backend::DisasmInsn& i) {
  json j;
  j["addr"]     = i.address;
  j["sz"]       = i.byte_size;
  j["bytes"]    = hex_bytes(i.bytes);
  j["mnemonic"] = i.mnemonic;
  j["operands"] = i.operands;
  if (!i.comment.empty()) j["comment"] = i.comment;
  return j;
}

json string_match_to_json(const backend::StringMatch& s) {
  json j;
  j["text"]    = s.text;
  j["addr"]    = s.address;
  j["section"] = s.section;
  j["module"]  = s.module_path;
  return j;
}

json symbol_match_to_json(const backend::SymbolMatch& s) {
  json j;
  j["name"]    = s.name;
  j["kind"]    = symbol_kind_str(s.kind);
  j["addr"]    = s.address;
  j["sz"]      = s.byte_size;
  j["module"]  = s.module_path;
  if (!s.mangled.empty()) j["mangled"] = s.mangled;
  return j;
}

json field_to_json(const backend::Field& f) {
  json j;
  j["name"]        = f.name;
  j["type"]        = f.type_name;
  j["off"]         = f.offset;
  j["sz"]          = f.byte_size;
  j["holes_after"] = f.holes_after;
  return j;
}

json type_layout_to_json(const backend::TypeLayout& t) {
  json j;
  j["name"]        = t.name;
  j["byte_size"]   = t.byte_size;
  j["alignment"]   = t.alignment;
  j["holes_total"] = t.holes_total;
  json arr = json::array();
  for (const auto& f : t.fields) arr.push_back(field_to_json(f));
  j["fields"] = std::move(arr);
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
    if (req.method == "type.layout")        return handle_type_layout(req);
    if (req.method == "symbol.find")        return handle_symbol_find(req);
    if (req.method == "string.list")        return handle_string_list(req);
    if (req.method == "disasm.range")       return handle_disasm_range(req);
    if (req.method == "disasm.function")    return handle_disasm_function(req);
    if (req.method == "xref.addr")          return handle_xref_addr(req);
    if (req.method == "string.xref")        return handle_string_xref(req);

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

  add("type.layout",
      "Look up a struct/class/union by name and return its memory layout",
      json{{"target_id", "uint64"}, {"name", "string"}},
      json{{"found", "bool"},
           {"layout",
            "object{name,byte_size,alignment,fields[],holes_total}"}});

  add("symbol.find",
      "Find symbols by exact name; optionally filtered by kind "
      "(function|variable|other|any)",
      json{{"target_id", "uint64"}, {"name", "string"},
           {"kind", "string?"}},
      json{{"matches",
            "array of {name,kind,addr,sz,module,mangled?}"}});

  add("string.list",
      "Enumerate ASCII strings (printable runs) in the target's data "
      "sections. Default scope is the main executable.",
      json{{"target_id", "uint64"},
           {"min_len", "uint?"}, {"max_len", "uint?"},
           {"section", "string?"}, {"module", "string?"}},
      json{{"strings", "array of {text,addr,section,module}"}});

  add("disasm.range",
      "Disassemble [start_addr, end_addr) and return one entry per "
      "instruction.",
      json{{"target_id", "uint64"},
           {"start_addr", "uint64"}, {"end_addr", "uint64"}},
      json{{"instructions",
            "array of {addr,sz,bytes,mnemonic,operands,comment?}"}});

  add("disasm.function",
      "Disassemble the body of a function looked up by exact name. "
      "Equivalent to symbol.find + disasm.range.",
      json{{"target_id", "uint64"}, {"name", "string"}},
      json{{"found", "bool"},
           {"address", "uint64"}, {"byte_size", "uint64"},
           {"instructions", "array of disasm insns"}});

  add("xref.addr",
      "Find every instruction in the main executable that references "
      "an address. Detects direct branches reliably; ARM64 ADRP+ADD "
      "reconstruction is a known gap.",
      json{{"target_id", "uint64"}, {"addr", "uint64"}},
      json{{"matches",
            "array of {addr,sz,mnemonic,operands,function,comment?}"}});

  add("string.xref",
      "Find xrefs to an exact-text string. Combines address-hex "
      "detection (x86-64 direct loads) with LLDB comment-text "
      "matching (ARM64 ADRP+ADD pairs).",
      json{{"target_id", "uint64"}, {"text", "string"}},
      json{{"results",
            "array of {string:{text,addr,section,module}, "
            "xrefs:array of xref matches}"}});

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

Response Dispatcher::handle_string_xref(const Request& req) {
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::uint64_t tid = 0;
  if (!require_uint(req.params, "target_id", &tid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }
  const auto* text = require_string(req.params, "text");
  if (!text) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing string param 'text'");
  }

  auto results = backend_->find_string_xrefs(
      static_cast<backend::TargetId>(tid), *text);

  json arr = json::array();
  for (const auto& r : results) {
    json one;
    one["string"] = string_match_to_json(r.string);
    json xrefs = json::array();
    for (const auto& x : r.xrefs) xrefs.push_back(xref_match_to_json(x));
    one["xrefs"] = std::move(xrefs);
    arr.push_back(std::move(one));
  }
  return protocol::make_ok(req.id, json{{"results", std::move(arr)}});
}

Response Dispatcher::handle_xref_addr(const Request& req) {
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::uint64_t tid = 0, addr = 0;
  if (!require_uint(req.params, "target_id", &tid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }
  if (!require_uint(req.params, "addr", &addr)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'addr'");
  }
  auto refs = backend_->xref_address(
      static_cast<backend::TargetId>(tid), addr);
  json arr = json::array();
  for (const auto& r : refs) arr.push_back(xref_match_to_json(r));
  return protocol::make_ok(req.id, json{{"matches", std::move(arr)}});
}

Response Dispatcher::handle_disasm_range(const Request& req) {
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::uint64_t tid = 0, start = 0, end = 0;
  if (!require_uint(req.params, "target_id", &tid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }
  if (!require_uint(req.params, "start_addr", &start)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'start_addr'");
  }
  if (!require_uint(req.params, "end_addr", &end)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'end_addr'");
  }

  auto insns = backend_->disassemble_range(
      static_cast<backend::TargetId>(tid), start, end);
  json arr = json::array();
  for (const auto& i : insns) arr.push_back(disasm_insn_to_json(i));
  return protocol::make_ok(req.id,
                           json{{"instructions", std::move(arr)}});
}

Response Dispatcher::handle_disasm_function(const Request& req) {
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::uint64_t tid = 0;
  if (!require_uint(req.params, "target_id", &tid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }
  const auto* name = require_string(req.params, "name");
  if (!name) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing string param 'name'");
  }

  // Look up the function via the existing symbol query path so this
  // endpoint stays a thin composition.
  backend::SymbolQuery sq;
  sq.name = *name;
  sq.kind = backend::SymbolKind::kFunction;
  auto matches = backend_->find_symbols(
      static_cast<backend::TargetId>(tid), sq);

  json data;
  if (matches.empty() || matches[0].byte_size == 0) {
    data["found"] = false;
    return protocol::make_ok(req.id, std::move(data));
  }

  std::uint64_t start = matches[0].address;
  std::uint64_t end   = start + matches[0].byte_size;

  auto insns = backend_->disassemble_range(
      static_cast<backend::TargetId>(tid), start, end);

  data["found"]        = true;
  data["address"]      = start;
  data["byte_size"]    = matches[0].byte_size;
  json arr = json::array();
  for (const auto& i : insns) arr.push_back(disasm_insn_to_json(i));
  data["instructions"] = std::move(arr);
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_string_list(const Request& req) {
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::uint64_t tid = 0;
  if (!require_uint(req.params, "target_id", &tid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }

  backend::StringQuery q;
  if (auto v = req.params.find("min_len"); v != req.params.end()) {
    std::uint64_t tmp = 0;
    if (!require_uint(req.params, "min_len", &tmp)) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'min_len' must be a non-negative integer");
    }
    q.min_length = static_cast<std::uint32_t>(tmp);
  }
  if (auto v = req.params.find("max_len"); v != req.params.end()) {
    std::uint64_t tmp = 0;
    if (!require_uint(req.params, "max_len", &tmp)) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'max_len' must be a non-negative integer");
    }
    q.max_length = static_cast<std::uint32_t>(tmp);
  }
  if (const auto* s = require_string(req.params, "section")) q.section_name = *s;
  if (const auto* s = require_string(req.params, "module"))  q.module_path  = *s;

  auto strings = backend_->find_strings(
      static_cast<backend::TargetId>(tid), q);
  json arr = json::array();
  for (const auto& s : strings) arr.push_back(string_match_to_json(s));
  return protocol::make_ok(req.id, json{{"strings", std::move(arr)}});
}

Response Dispatcher::handle_symbol_find(const Request& req) {
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::uint64_t tid = 0;
  if (!require_uint(req.params, "target_id", &tid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }
  const auto* name = require_string(req.params, "name");
  if (!name) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing string param 'name'");
  }

  backend::SymbolQuery q;
  q.name = *name;
  if (auto kit = req.params.find("kind"); kit != req.params.end()) {
    if (!kit->is_string() ||
        !parse_symbol_kind(kit->get<std::string>(), &q.kind)) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'kind' must be one of: "
                                "any, function, variable, other");
    }
  }

  auto matches = backend_->find_symbols(
      static_cast<backend::TargetId>(tid), q);
  json arr = json::array();
  for (const auto& m : matches) arr.push_back(symbol_match_to_json(m));
  return protocol::make_ok(req.id, json{{"matches", std::move(arr)}});
}

Response Dispatcher::handle_type_layout(const Request& req) {
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::uint64_t tid = 0;
  if (!require_uint(req.params, "target_id", &tid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }
  const auto* name = require_string(req.params, "name");
  if (!name) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing string param 'name'");
  }

  auto layout = backend_->find_type_layout(
      static_cast<backend::TargetId>(tid), *name);

  json data;
  if (layout.has_value()) {
    data["found"]  = true;
    data["layout"] = type_layout_to_json(*layout);
  } else {
    data["found"]  = false;
  }
  return protocol::make_ok(req.id, std::move(data));
}

}  // namespace ldb::daemon
