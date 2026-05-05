#include "daemon/dispatcher.h"

#include "backend/debugger_backend.h"
#include "ldb/version.h"
#include "protocol/view.h"
#include "util/log.h"

#include <stdexcept>
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

const char* process_state_str(backend::ProcessState s) {
  switch (s) {
    case backend::ProcessState::kNone:     return "none";
    case backend::ProcessState::kRunning:  return "running";
    case backend::ProcessState::kStopped:  return "stopped";
    case backend::ProcessState::kExited:   return "exited";
    case backend::ProcessState::kCrashed:  return "crashed";
    case backend::ProcessState::kDetached: return "detached";
    case backend::ProcessState::kInvalid:  return "invalid";
  }
  return "invalid";
}

json thread_info_to_json(const backend::ThreadInfo& t) {
  json j;
  j["tid"]   = t.tid;
  j["index"] = t.index;
  j["state"] = process_state_str(t.state);
  j["pc"]    = t.pc;
  j["sp"]    = t.sp;
  if (!t.name.empty())        j["name"]        = t.name;
  if (!t.stop_reason.empty()) j["stop_reason"] = t.stop_reason;
  return j;
}

// Decode a lower-case packed-hex string into bytes. Returns nullopt on
// any non-hex character or odd length. Used by mem.search needle.
std::optional<std::vector<std::uint8_t>>
hex_decode(const std::string& s) {
  if (s.size() % 2 != 0) return std::nullopt;
  std::vector<std::uint8_t> out;
  out.reserve(s.size() / 2);
  auto val = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (std::size_t i = 0; i < s.size(); i += 2) {
    int hi = val(s[i]);
    int lo = val(s[i + 1]);
    if (hi < 0 || lo < 0) return std::nullopt;
    out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
  }
  return out;
}

json memory_region_to_json(const backend::MemoryRegion& r) {
  json j;
  j["base"] = r.base;
  j["size"] = r.size;
  j["r"]    = r.readable;
  j["w"]    = r.writable;
  j["x"]    = r.executable;
  if (r.name.has_value()) j["name"] = *r.name;
  return j;
}

std::string hex_lower(const std::vector<std::uint8_t>& bytes) {
  // Lower-case packed hex (no separators) — distinct from disasm's
  // space-separated rendering. Used by frame.* and mem.* endpoints.
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (auto b : bytes) {
    out.push_back(kHex[(b >> 4) & 0xF]);
    out.push_back(kHex[b & 0xF]);
  }
  return out;
}

json value_info_to_json(const backend::ValueInfo& v) {
  json j;
  j["name"] = v.name;
  j["type"] = v.type;
  if (v.address.has_value())  j["address"] = *v.address;
  if (!v.bytes.empty())       j["bytes"]   = hex_lower(v.bytes);
  if (v.summary.has_value())  j["summary"] = *v.summary;
  if (v.kind.has_value())     j["kind"]    = *v.kind;
  return j;
}

json frame_info_to_json(const backend::FrameInfo& f) {
  json j;
  j["index"]  = f.index;
  j["pc"]     = f.pc;
  j["fp"]     = f.fp;
  j["sp"]     = f.sp;
  if (!f.function.empty()) j["function"] = f.function;
  if (!f.module.empty())   j["module"]   = f.module;
  if (!f.file.empty())     j["file"]     = f.file;
  if (f.line > 0)          j["line"]     = f.line;
  if (f.inlined)           j["inlined"]  = true;
  return j;
}

json process_status_to_json(const backend::ProcessStatus& s) {
  json j;
  j["state"] = process_state_str(s.state);
  j["pid"]   = s.pid;
  if (s.state == backend::ProcessState::kExited) j["exit_code"] = s.exit_code;
  if (!s.stop_reason.empty()) j["stop_reason"] = s.stop_reason;
  return j;
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
  if (s.load_address.has_value()) j["load_addr"] = *s.load_address;
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
    if (req.method == "target.create_empty")return handle_target_create_empty(req);
    if (req.method == "target.attach")      return handle_target_attach(req);
    if (req.method == "target.close")       return handle_target_close(req);
    if (req.method == "module.list")        return handle_module_list(req);
    if (req.method == "type.layout")        return handle_type_layout(req);
    if (req.method == "symbol.find")        return handle_symbol_find(req);
    if (req.method == "string.list")        return handle_string_list(req);
    if (req.method == "disasm.range")       return handle_disasm_range(req);
    if (req.method == "disasm.function")    return handle_disasm_function(req);
    if (req.method == "xref.addr")          return handle_xref_addr(req);
    if (req.method == "string.xref")        return handle_string_xref(req);

    if (req.method == "process.launch")     return handle_process_launch(req);
    if (req.method == "process.state")      return handle_process_state(req);
    if (req.method == "process.continue")   return handle_process_continue(req);
    if (req.method == "process.kill")       return handle_process_kill(req);
    if (req.method == "process.detach")     return handle_process_detach(req);

    if (req.method == "thread.list")        return handle_thread_list(req);
    if (req.method == "thread.frames")      return handle_thread_frames(req);

    if (req.method == "frame.locals")       return handle_frame_locals(req);
    if (req.method == "frame.args")         return handle_frame_args(req);
    if (req.method == "frame.registers")    return handle_frame_registers(req);

    if (req.method == "mem.read")           return handle_mem_read(req);
    if (req.method == "mem.read_cstr")      return handle_mem_read_cstr(req);
    if (req.method == "mem.regions")        return handle_mem_regions(req);
    if (req.method == "mem.search")         return handle_mem_search(req);

    return protocol::make_err(req.id, ErrorCode::kMethodNotFound,
                              "unknown method: " + req.method);
  } catch (const backend::Error& e) {
    return protocol::make_err(req.id, ErrorCode::kBackendError, e.what());
  } catch (const std::invalid_argument& e) {
    // Parameter / view validation errors — agent's fault, not ours.
    return protocol::make_err(req.id, ErrorCode::kInvalidParams, e.what());
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

  add("target.create_empty",
      "Create a target with no associated executable. Used as host for "
      "target.attach by pid and (later) target.load_core.",
      json::object(),
      json{{"target_id", "uint64"}, {"triple", "string"},
           {"modules", "array"}});

  add("target.attach",
      "Attach to a running process by pid. Synchronous: blocks until "
      "the inferior is stopped on attach.",
      json{{"target_id", "uint64"}, {"pid", "int"}},
      json{{"state", "string"}, {"pid", "int"},
           {"stop_reason", "string?"}});

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

  add("process.launch",
      "Spawn the target's executable as an inferior. Synchronous: "
      "blocks until the process is stopped or has exited.",
      json{{"target_id", "uint64"}, {"stop_at_entry", "bool?"}},
      json{{"state", "string"}, {"pid", "int"},
           {"stop_reason", "string?"}, {"exit_code", "int?"}});

  add("process.state",
      "Query the current state of the target's process. Returns "
      "state=\"none\" if no process is associated.",
      json{{"target_id", "uint64"}},
      json{{"state", "string"}, {"pid", "int"}});

  add("process.continue",
      "Resume a stopped process. Blocks until next stop or exit.",
      json{{"target_id", "uint64"}},
      json{{"state", "string"}, {"pid", "int"}});

  add("process.kill",
      "Terminate the target's process. Idempotent.",
      json{{"target_id", "uint64"}},
      json{{"state", "string"}, {"pid", "int"}});

  add("process.detach",
      "Detach from the target's process, leaving it running. Preferred "
      "over process.kill for attached processes. Idempotent.",
      json{{"target_id", "uint64"}},
      json{{"state", "string"}, {"pid", "int"}});

  add("thread.list",
      "Enumerate threads of the target's process.",
      json{{"target_id", "uint64"}},
      json{{"threads",
            "array of {tid,index,state,pc,sp,name?,stop_reason?}"}});

  add("thread.frames",
      "Backtrace a thread, innermost first. max_depth=0 means no cap.",
      json{{"target_id", "uint64"}, {"tid", "uint64"},
           {"max_depth", "uint?"}},
      json{{"frames",
            "array of {index,pc,fp,sp,function?,module?,file?,line?,inlined?}"}});

  add("frame.locals",
      "Local variables in scope at a frame. Bytes capped at 64; agents "
      "follow up with mem.read for fuller dumps.",
      json{{"target_id", "uint64"}, {"tid", "uint64"},
           {"frame_index", "uint?"}},
      json{{"locals",
            "array of {name,type,address?,bytes?,summary?,kind}"}});

  add("frame.args",
      "Function arguments visible at a frame.",
      json{{"target_id", "uint64"}, {"tid", "uint64"},
           {"frame_index", "uint?"}},
      json{{"args",
            "array of {name,type,address?,bytes?,summary?,kind}"}});

  add("frame.registers",
      "All register sets at a frame, flattened.",
      json{{"target_id", "uint64"}, {"tid", "uint64"},
           {"frame_index", "uint?"}},
      json{{"registers",
            "array of {name,type,address?,bytes?,summary?,kind}"}});

  add("mem.read",
      "Read up to 1 MiB of process memory at the given runtime address. "
      "Returns lower-case packed hex.",
      json{{"target_id", "uint64"}, {"address", "uint64"},
           {"size", "uint64"}},
      json{{"address", "uint64"}, {"bytes", "string<hex>"}});

  add("mem.read_cstr",
      "Read a NUL-terminated string at a runtime address, capped at "
      "max_len bytes (default 4096).",
      json{{"target_id", "uint64"}, {"address", "uint64"},
           {"max_len", "uint?"}},
      json{{"address", "uint64"}, {"value", "string"},
           {"truncated", "bool"}});

  add("mem.regions",
      "Enumerate the inferior's mapped memory regions with permissions.",
      json{{"target_id", "uint64"}},
      json{{"regions",
            "array of {base,size,r,w,x,name?}"}});

  add("mem.search",
      "Scan process memory for a byte pattern. Needle is either a hex "
      "string or {text:'...'}. length=0 searches all readable regions "
      "(capped at 256 MiB). max_hits capped at 1024.",
      json{{"target_id", "uint64"},
           {"needle", "string<hex>|object{text}"},
           {"address", "uint64?"}, {"length", "uint64?"},
           {"max_hits", "uint?"}},
      json{{"hits", "array of {address}"}});

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

Response Dispatcher::handle_target_create_empty(const Request& req) {
  // No params required; ignore stray fields. Used as the host target
  // for target.attach by pid and target.load_core.
  auto res = backend_->create_empty_target();
  json data;
  data["target_id"] = res.target_id;
  data["triple"]    = res.triple;
  data["modules"]   = json::array();
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_target_attach(const Request& req) {
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::uint64_t tid = 0, pid_u = 0;
  if (!require_uint(req.params, "target_id", &tid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }
  if (!require_uint(req.params, "pid", &pid_u)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'pid'");
  }
  auto status = backend_->attach(static_cast<backend::TargetId>(tid),
                                 static_cast<std::int32_t>(pid_u));
  return protocol::make_ok(req.id, process_status_to_json(status));
}

Response Dispatcher::handle_process_detach(const Request& req) {
  std::uint64_t tid = 0;
  if (!req.params.is_object() || !require_uint(req.params, "target_id", &tid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }
  auto status = backend_->detach_process(static_cast<backend::TargetId>(tid));
  return protocol::make_ok(req.id, process_status_to_json(status));
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
  auto view_spec = protocol::view::parse_from_params(req.params);

  auto mods = backend_->list_modules(static_cast<backend::TargetId>(tid));
  json arr = json::array();
  for (const auto& m : mods) arr.push_back(module_to_json(m));

  return protocol::make_ok(req.id,
      protocol::view::apply_to_array(std::move(arr), view_spec, "modules"));
}

Response Dispatcher::handle_thread_list(const Request& req) {
  std::uint64_t tid = 0;
  if (!req.params.is_object() || !require_uint(req.params, "target_id", &tid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }
  auto threads = backend_->list_threads(static_cast<backend::TargetId>(tid));
  json arr = json::array();
  for (const auto& t : threads) arr.push_back(thread_info_to_json(t));
  return protocol::make_ok(req.id, json{{"threads", std::move(arr)}});
}

Response Dispatcher::handle_thread_frames(const Request& req) {
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::uint64_t target_id = 0;
  if (!require_uint(req.params, "target_id", &target_id)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }
  std::uint64_t tid = 0;
  if (!require_uint(req.params, "tid", &tid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'tid'");
  }
  std::uint64_t depth = 0;
  if (auto it = req.params.find("max_depth"); it != req.params.end()) {
    if (!require_uint(req.params, "max_depth", &depth)) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'max_depth' must be a non-negative integer");
    }
  }
  auto frames = backend_->list_frames(
      static_cast<backend::TargetId>(target_id),
      static_cast<backend::ThreadId>(tid),
      static_cast<std::uint32_t>(depth));
  json arr = json::array();
  for (const auto& f : frames) arr.push_back(frame_info_to_json(f));
  return protocol::make_ok(req.id, json{{"frames", std::move(arr)}});
}

namespace {

// Common parameter parsing for the three frame.* endpoints.
struct FrameParams {
  std::uint64_t target_id   = 0;
  std::uint64_t tid         = 0;
  std::uint32_t frame_index = 0;
};

// Returns nullopt on success; on failure returns the error response.
std::optional<Response>
parse_frame_params(const Request& req, FrameParams* out) {
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  if (!require_uint(req.params, "target_id", &out->target_id)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }
  if (!require_uint(req.params, "tid", &out->tid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'tid'");
  }
  if (auto it = req.params.find("frame_index"); it != req.params.end()) {
    std::uint64_t tmp = 0;
    if (!require_uint(req.params, "frame_index", &tmp)) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'frame_index' must be a non-negative integer");
    }
    out->frame_index = static_cast<std::uint32_t>(tmp);
  }
  return std::nullopt;
}

Response build_value_response(const Request& req,
                              const std::vector<backend::ValueInfo>& values,
                              const char* items_key) {
  auto view_spec = protocol::view::parse_from_params(req.params);
  json arr = json::array();
  for (const auto& v : values) arr.push_back(value_info_to_json(v));
  return protocol::make_ok(
      req.id, protocol::view::apply_to_array(std::move(arr), view_spec,
                                             items_key));
}

}  // namespace

Response Dispatcher::handle_frame_locals(const Request& req) {
  FrameParams p;
  if (auto err = parse_frame_params(req, &p)) return *err;
  auto values = backend_->list_locals(
      static_cast<backend::TargetId>(p.target_id),
      static_cast<backend::ThreadId>(p.tid),
      p.frame_index);
  return build_value_response(req, values, "locals");
}

Response Dispatcher::handle_frame_args(const Request& req) {
  FrameParams p;
  if (auto err = parse_frame_params(req, &p)) return *err;
  auto values = backend_->list_args(
      static_cast<backend::TargetId>(p.target_id),
      static_cast<backend::ThreadId>(p.tid),
      p.frame_index);
  return build_value_response(req, values, "args");
}

Response Dispatcher::handle_frame_registers(const Request& req) {
  FrameParams p;
  if (auto err = parse_frame_params(req, &p)) return *err;
  auto values = backend_->list_registers(
      static_cast<backend::TargetId>(p.target_id),
      static_cast<backend::ThreadId>(p.tid),
      p.frame_index);
  return build_value_response(req, values, "registers");
}

Response Dispatcher::handle_mem_read(const Request& req) {
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::uint64_t tid = 0, addr = 0, size = 0;
  if (!require_uint(req.params, "target_id", &tid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }
  if (!require_uint(req.params, "address", &addr)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'address'");
  }
  if (!require_uint(req.params, "size", &size)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'size'");
  }
  auto bytes = backend_->read_memory(
      static_cast<backend::TargetId>(tid), addr, size);
  json data;
  data["address"] = addr;
  data["bytes"]   = hex_lower(bytes);
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_mem_read_cstr(const Request& req) {
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::uint64_t tid = 0, addr = 0, max_len = 0;
  if (!require_uint(req.params, "target_id", &tid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }
  if (!require_uint(req.params, "address", &addr)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'address'");
  }
  if (auto it = req.params.find("max_len"); it != req.params.end()) {
    if (!require_uint(req.params, "max_len", &max_len)) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'max_len' must be a non-negative integer");
    }
  }
  auto value = backend_->read_cstring(
      static_cast<backend::TargetId>(tid), addr,
      static_cast<std::uint32_t>(max_len));
  json data;
  data["address"]   = addr;
  data["value"]     = value;
  // truncated == we hit max_len before NUL. The backend returns up to
  // max_len bytes; if size == max_len we may have stopped short — flag
  // it so the agent can ask for more.
  std::uint32_t cap = max_len ? static_cast<std::uint32_t>(max_len)
                              : 4096u;  // matches kMemCstrDefault
  data["truncated"] = value.size() == cap;
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_mem_regions(const Request& req) {
  std::uint64_t tid = 0;
  if (!req.params.is_object() || !require_uint(req.params, "target_id", &tid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }
  auto view_spec = protocol::view::parse_from_params(req.params);
  auto regions = backend_->list_regions(static_cast<backend::TargetId>(tid));
  json arr = json::array();
  for (const auto& r : regions) arr.push_back(memory_region_to_json(r));
  return protocol::make_ok(req.id,
      protocol::view::apply_to_array(std::move(arr), view_spec, "regions"));
}

Response Dispatcher::handle_mem_search(const Request& req) {
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::uint64_t tid = 0;
  if (!require_uint(req.params, "target_id", &tid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }

  // needle accepts either a hex string or {"text": "..."} for ASCII.
  std::vector<std::uint8_t> needle;
  auto nit = req.params.find("needle");
  if (nit == req.params.end()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing 'needle' param");
  }
  if (nit->is_string()) {
    auto decoded = hex_decode(nit->get<std::string>());
    if (!decoded) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'needle' string must be lower-case packed hex");
    }
    needle = std::move(*decoded);
  } else if (nit->is_object()) {
    auto tit = nit->find("text");
    if (tit == nit->end() || !tit->is_string()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "needle.text must be a string");
    }
    auto t = tit->get<std::string>();
    needle.assign(t.begin(), t.end());
  } else {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "'needle' must be hex string or {text:'...'}");
  }
  if (needle.empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "'needle' must be non-empty");
  }

  std::uint64_t addr = 0, length = 0, max_hits = 0;
  if (auto it = req.params.find("address"); it != req.params.end()) {
    if (!require_uint(req.params, "address", &addr)) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'address' must be a non-negative integer");
    }
  }
  if (auto it = req.params.find("length"); it != req.params.end()) {
    if (!require_uint(req.params, "length", &length)) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'length' must be a non-negative integer");
    }
  }
  if (auto it = req.params.find("max_hits"); it != req.params.end()) {
    if (!require_uint(req.params, "max_hits", &max_hits)) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'max_hits' must be a non-negative integer");
    }
  }

  auto hits = backend_->search_memory(
      static_cast<backend::TargetId>(tid), addr, length, needle,
      static_cast<std::uint32_t>(max_hits));
  json arr = json::array();
  for (const auto& h : hits) {
    json j;
    j["address"] = h.address;
    arr.push_back(std::move(j));
  }
  return protocol::make_ok(req.id, json{{"hits", std::move(arr)}});
}

Response Dispatcher::handle_process_launch(const Request& req) {
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::uint64_t tid = 0;
  if (!require_uint(req.params, "target_id", &tid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }
  backend::LaunchOptions opts;
  if (auto it = req.params.find("stop_at_entry"); it != req.params.end()) {
    if (!it->is_boolean()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'stop_at_entry' must be bool");
    }
    opts.stop_at_entry = it->get<bool>();
  }
  auto status = backend_->launch_process(
      static_cast<backend::TargetId>(tid), opts);
  return protocol::make_ok(req.id, process_status_to_json(status));
}

Response Dispatcher::handle_process_state(const Request& req) {
  std::uint64_t tid = 0;
  if (!req.params.is_object() || !require_uint(req.params, "target_id", &tid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }
  auto status = backend_->get_process_state(static_cast<backend::TargetId>(tid));
  return protocol::make_ok(req.id, process_status_to_json(status));
}

Response Dispatcher::handle_process_continue(const Request& req) {
  std::uint64_t tid = 0;
  if (!req.params.is_object() || !require_uint(req.params, "target_id", &tid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }
  auto status = backend_->continue_process(static_cast<backend::TargetId>(tid));
  return protocol::make_ok(req.id, process_status_to_json(status));
}

Response Dispatcher::handle_process_kill(const Request& req) {
  std::uint64_t tid = 0;
  if (!req.params.is_object() || !require_uint(req.params, "target_id", &tid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }
  auto status = backend_->kill_process(static_cast<backend::TargetId>(tid));
  return protocol::make_ok(req.id, process_status_to_json(status));
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
