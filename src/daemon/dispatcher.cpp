// SPDX-License-Identifier: Apache-2.0
#include "daemon/dispatcher.h"

#include <algorithm>

#include "backend/debugger_backend.h"
#include "daemon/describe_schema.h"
#include "ldb/version.h"
#include "protocol/cost.h"
#include "protocol/version.h"
#include "observers/exec_allowlist.h"
#include "observers/observers.h"
#include "perf/perf_parser.h"
#include "perf/perf_runner.h"
#include "probes/probe_orchestrator.h"
#include "python/embed.h"
#include "protocol/view.h"
#include "store/artifact_store.h"
#include "store/hypothesis.h"
#include "store/pack.h"
#include "store/pack_signing.h"
#include "store/recipe_store.h"
#include "store/session_store.h"
#include "transport/ssh.h"
#include "util/log.h"

#include <unistd.h>

#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <limits>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

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
  // `addr` is the historical short field name; `address` is an alias
  // emitted for symmetry with the rest of the surface — disasm.function
  // / disasm.range wrap their results in {address, byte_size, ...} at
  // the top level, and mem.read / watchpoint use `address`. Emitting
  // both lets `--view fields=address,...` filters work without forcing
  // callers to know which level uses which name (papercut #12).
  j["addr"]     = i.address;
  j["address"]  = i.address;
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

// Tier 3 §12 — globals-of-type wire shape. `addr` is the file (un-
// relocated) address; `load_addr` only present when the target has an
// attached process so the agent can pipe straight into mem.read.
json global_var_match_to_json(const backend::GlobalVarMatch& g) {
  json j;
  j["name"]      = g.name;
  j["type"]      = g.type;
  j["addr"]      = g.file_address;
  j["sz"]        = g.size;
  j["module"]    = g.module;
  if (g.load_address.has_value()) j["load_addr"] = *g.load_address;
  if (!g.file.empty())            j["file"]      = g.file;
  if (g.line > 0)                 j["line"]      = g.line;
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

// --- Base64 (RFC 4648, no line wrapping) ---------------------------------

constexpr const char kB64Alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const std::vector<std::uint8_t>& in) {
  std::string out;
  out.reserve(((in.size() + 2) / 3) * 4);
  std::size_t i = 0;
  for (; i + 3 <= in.size(); i += 3) {
    std::uint32_t v = (std::uint32_t{in[i]} << 16) |
                      (std::uint32_t{in[i + 1]} << 8) |
                      std::uint32_t{in[i + 2]};
    out.push_back(kB64Alphabet[(v >> 18) & 0x3Fu]);
    out.push_back(kB64Alphabet[(v >> 12) & 0x3Fu]);
    out.push_back(kB64Alphabet[(v >>  6) & 0x3Fu]);
    out.push_back(kB64Alphabet[v & 0x3Fu]);
  }
  std::size_t rem = in.size() - i;
  if (rem == 1) {
    std::uint32_t v = std::uint32_t{in[i]} << 16;
    out.push_back(kB64Alphabet[(v >> 18) & 0x3Fu]);
    out.push_back(kB64Alphabet[(v >> 12) & 0x3Fu]);
    out.push_back('=');
    out.push_back('=');
  } else if (rem == 2) {
    std::uint32_t v = (std::uint32_t{in[i]} << 16) |
                      (std::uint32_t{in[i + 1]} << 8);
    out.push_back(kB64Alphabet[(v >> 18) & 0x3Fu]);
    out.push_back(kB64Alphabet[(v >> 12) & 0x3Fu]);
    out.push_back(kB64Alphabet[(v >>  6) & 0x3Fu]);
    out.push_back('=');
  }
  return out;
}

// Returns nullopt on any non-alphabet character (excluding padding) or
// malformed length. Whitespace inside the input is rejected — the agent
// is sending JSON-RPC, not pretty-printed PEM.
std::optional<std::vector<std::uint8_t>>
base64_decode(std::string_view in) {
  if (in.size() % 4 != 0) return std::nullopt;
  auto val = [](char c) -> int {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return 26 + (c - 'a');
    if (c >= '0' && c <= '9') return 52 + (c - '0');
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
  };
  std::vector<std::uint8_t> out;
  out.reserve((in.size() / 4) * 3);
  for (std::size_t i = 0; i < in.size(); i += 4) {
    char c0 = in[i], c1 = in[i + 1], c2 = in[i + 2], c3 = in[i + 3];
    int v0 = val(c0), v1 = val(c1);
    if (v0 < 0 || v1 < 0) return std::nullopt;
    if (c2 == '=') {
      if (c3 != '=') return std::nullopt;
      out.push_back(static_cast<std::uint8_t>((v0 << 2) | (v1 >> 4)));
    } else {
      int v2 = val(c2);
      if (v2 < 0) return std::nullopt;
      if (c3 == '=') {
        out.push_back(static_cast<std::uint8_t>((v0 << 2) | (v1 >> 4)));
        out.push_back(static_cast<std::uint8_t>(((v1 & 0xF) << 4) | (v2 >> 2)));
      } else {
        int v3 = val(c3);
        if (v3 < 0) return std::nullopt;
        out.push_back(static_cast<std::uint8_t>((v0 << 2) | (v1 >> 4)));
        out.push_back(static_cast<std::uint8_t>(((v1 & 0xF) << 4) | (v2 >> 2)));
        out.push_back(static_cast<std::uint8_t>(((v2 & 0x3) << 6) | v3));
      }
    }
  }
  return out;
}

// --- Artifact row → JSON (list shape: no bytes inline) -------------------

json artifact_row_to_list_json(const ldb::store::ArtifactRow& r) {
  json j;
  j["id"]         = r.id;
  j["build_id"]   = r.build_id;
  j["name"]       = r.name;
  j["sha256"]     = r.sha256;
  j["byte_size"]  = r.byte_size;
  if (r.format.has_value())   j["format"] = *r.format;
  if (!r.tags.empty())        j["tags"]   = r.tags;
  j["created_at"] = r.created_at;
  return j;
}

json relation_to_json(const ldb::store::ArtifactRelation& r) {
  json j;
  j["id"]         = r.id;
  j["from_id"]    = r.from_id;
  j["to_id"]      = r.to_id;
  j["predicate"]  = r.predicate;
  j["meta"]       = r.meta;
  j["created_at"] = r.created_at;
  return j;
}

}  // namespace

// ----------------------------------------------------------------------------

Dispatcher::Dispatcher(std::shared_ptr<backend::DebuggerBackend> backend,
                       std::shared_ptr<store::ArtifactStore> artifacts,
                       std::shared_ptr<store::SessionStore> sessions,
                       std::shared_ptr<probes::ProbeOrchestrator> probes,
                       std::shared_ptr<observers::ExecAllowlist> exec_allowlist,
                       std::string backend_name)
    : backend_(std::move(backend)),
      artifacts_(std::move(artifacts)),
      sessions_(std::move(sessions)),
      probes_(std::move(probes)),
      exec_allowlist_(std::move(exec_allowlist)),
      backend_name_(std::move(backend_name)) {}

Dispatcher::~Dispatcher() = default;

// ── DiffCache (post-V1 plan #5) ────────────────────────────────────────

std::string Dispatcher::diff_cache_key(const std::string& method,
                                       const json& params,
                                       const std::string& snapshot) {
  // Canonicalize params: drop "view" so pagination changes don't
  // fragment the cache. nlohmann::json's default serialization sorts
  // object keys, so the dump is stable regardless of insertion order.
  json key_params = params.is_object() ? params : json::object();
  if (key_params.contains("view")) key_params.erase("view");
  return method + "|" + key_params.dump() + "|" + snapshot;
}

void Dispatcher::diff_cache_put(std::string key, json items) {
  auto it = diff_cache_index_.find(key);
  if (it != diff_cache_index_.end()) {
    // Replace existing entry; move to MRU.
    diff_cache_.erase(it->second);
    diff_cache_index_.erase(it);
  }
  diff_cache_.push_front({std::move(key), std::move(items)});
  diff_cache_index_[diff_cache_.front().cache_key] = diff_cache_.begin();

  // Bound the cache. Evict from the back (least-recently-used).
  while (diff_cache_.size() > kDiffCacheCapacity) {
    diff_cache_index_.erase(diff_cache_.back().cache_key);
    diff_cache_.pop_back();
  }
}

std::optional<json>
Dispatcher::diff_cache_get(const std::string& key) {
  auto it = diff_cache_index_.find(key);
  if (it == diff_cache_index_.end()) return std::nullopt;
  // Touch: move to MRU.
  diff_cache_.splice(diff_cache_.begin(), diff_cache_, it->second);
  return diff_cache_.front().items;
}

// ── Cost-sample recorder (post-V1 plan #4) ─────────────────────────────

void Dispatcher::record_cost_sample(const std::string& method,
                                     std::uint64_t tokens) {
  auto& ring = cost_samples_[method];
  ++ring.total;
  if (ring.recent.size() < kCostRingCapacity) {
    ring.recent.push_back(tokens);
  } else {
    ring.recent[ring.next] = tokens;
    ring.next = (ring.next + 1) % kCostRingCapacity;
  }
}

std::optional<std::uint64_t>
Dispatcher::cost_p50(const std::string& method) const {
  auto it = cost_samples_.find(method);
  if (it == cost_samples_.end() || it->second.recent.empty()) {
    return std::nullopt;
  }
  // p50 = the lower of the two middle elements in a sorted copy. For
  // odd-sized rings this is the median exactly; for even-sized rings
  // we round down, which is the conservative direction for an agent's
  // budget check (always slightly under-promise).
  std::vector<std::uint64_t> sorted = it->second.recent;
  std::sort(sorted.begin(), sorted.end());
  return sorted[(sorted.size() - 1) / 2];
}

std::uint64_t Dispatcher::cost_total(const std::string& method) const {
  auto it = cost_samples_.find(method);
  return it == cost_samples_.end() ? 0u : it->second.total;
}

namespace {

// Extract target_id from request params, when present and integer-typed.
// Returns 0 (the never-issued sentinel) if absent or wrong type — the
// backend's snapshot_for_target will then return "none".
backend::TargetId extract_target_id(const json& params) {
  if (!params.is_object()) return 0;
  auto it = params.find("target_id");
  if (it == params.end()) return 0;
  if (!it->is_number_unsigned() && !it->is_number_integer()) return 0;
  // Negative values can't be a valid TargetId — coerce via the unsigned
  // type and let snapshot_for_target return "none" for the unknown id.
  try {
    return it->get<backend::TargetId>();
  } catch (...) {
    return 0;
  }
}

// Decorate `resp` with the cores-only `_provenance.snapshot` per plan
// §3.5. Best-effort: a thrown exception inside snapshot_for_target
// degrades to "none" rather than poisoning the whole response.
void decorate_provenance(Response& resp,
                         backend::DebuggerBackend* backend,
                         const Request& req) {
  if (!resp.ok || !backend) return;
  backend::TargetId tid = extract_target_id(req.params);
  std::string snap;
  try {
    snap = backend->snapshot_for_target(tid);
  } catch (...) {
    snap = "none";
  }
  resp.provenance_snapshot = std::move(snap);
}

}  // namespace

Response Dispatcher::dispatch(const Request& req) {
  using clock = std::chrono::steady_clock;
  auto t0 = clock::now();
  Response resp = dispatch_inner(req);
  decorate_provenance(resp, backend_.get(), req);

  // Post-V1 plan #4: record measured cost. We compute tokens_est
  // here (the same formula serialize_response uses) so the recorder
  // doesn't depend on the JSON-RPC serialization path. Errors don't
  // carry _cost on the wire and aren't useful as budget signals;
  // record only successful responses.
  if (resp.ok && !req.method.empty()) {
    json cost = protocol::cost::compute_cost(resp.data);
    if (cost.contains("tokens_est") &&
        (cost["tokens_est"].is_number_unsigned() ||
         cost["tokens_est"].is_number_integer())) {
      record_cost_sample(req.method,
                         cost["tokens_est"].get<std::uint64_t>());
    }
  }
  if (active_session_writer_) {
    auto dt_us = std::chrono::duration_cast<std::chrono::microseconds>(
                     clock::now() - t0).count();
    // Reconstruct the request-as-JSON so the rpc_log row is faithful
    // to what the agent actually sent. We don't store the connection-
    // wide envelope (jsonrpc, id, format) — those are framing, not
    // semantically interesting for replay; method+params is the
    // canonical recipe shape for a future session.replay slice.
    json req_j;
    req_j["method"] = req.method;
    req_j["params"] = req.params;
    if (req.id.has_value()) req_j["id"] = *req.id;

    // Same with the response: store the data/error payload + ok bit,
    // not the JSON-RPC framing fields.
    json rsp_j;
    rsp_j["ok"] = resp.ok;
    if (resp.ok) {
      rsp_j["data"] = resp.data;
    } else {
      json err;
      err["code"] = static_cast<int>(resp.error_code);
      err["message"] = resp.error_message;
      if (resp.error_data.has_value()) err["data"] = *resp.error_data;
      rsp_j["error"] = std::move(err);
    }
    try {
      active_session_writer_->append(req.method, req_j, rsp_j, resp.ok,
                                     static_cast<std::int64_t>(dt_us));
    } catch (const std::exception& e) {
      // A failed log append must not poison the response we're about
      // to send. Log to stderr (the JSON-RPC channel is reserved for
      // stdout per CLAUDE.md) and carry on.
      log::warn(std::string("session log append failed: ") + e.what());
    }
  }
  return resp;
}

Response Dispatcher::dispatch_inner(const Request& req) {
  try {
    if (req.method == "hello")              return handle_hello(req);
    if (req.method == "describe.endpoints") return handle_describe_endpoints(req);
    if (req.method == "target.open")        return handle_target_open(req);
    if (req.method == "target.create_empty")return handle_target_create_empty(req);
    if (req.method == "target.attach")      return handle_target_attach(req);
    if (req.method == "target.connect_remote")
      return handle_target_connect_remote(req);
    if (req.method == "target.connect_remote_ssh")
      return handle_target_connect_remote_ssh(req);
    if (req.method == "target.load_core")   return handle_target_load_core(req);
    if (req.method == "target.close")       return handle_target_close(req);
    if (req.method == "target.list")        return handle_target_list(req);
    if (req.method == "target.label")       return handle_target_label(req);
    if (req.method == "module.list")        return handle_module_list(req);
    if (req.method == "type.layout")        return handle_type_layout(req);
    if (req.method == "symbol.find")        return handle_symbol_find(req);
    if (req.method == "string.list")        return handle_string_list(req);
    if (req.method == "disasm.range")       return handle_disasm_range(req);
    if (req.method == "disasm.function")    return handle_disasm_function(req);
    if (req.method == "xref.addr")          return handle_xref_addr(req);
    if (req.method == "string.xref")        return handle_string_xref(req);
    if (req.method == "static.globals_of_type")
      return handle_static_globals_of_type(req);

    if (req.method == "correlate.types")    return handle_correlate_types(req);
    if (req.method == "correlate.symbols")  return handle_correlate_symbols(req);
    if (req.method == "correlate.strings")  return handle_correlate_strings(req);

    if (req.method == "process.launch")     return handle_process_launch(req);
    if (req.method == "process.state")      return handle_process_state(req);
    if (req.method == "process.continue")   return handle_process_continue(req);
    if (req.method == "process.kill")       return handle_process_kill(req);
    if (req.method == "process.detach")     return handle_process_detach(req);
    if (req.method == "process.save_core")  return handle_process_save_core(req);
    if (req.method == "process.step")       return handle_process_step(req);
    if (req.method == "process.reverse_continue")
      return handle_process_reverse_continue(req);
    if (req.method == "process.reverse_step")
      return handle_process_reverse_step(req);

    if (req.method == "thread.list")        return handle_thread_list(req);
    if (req.method == "thread.frames")      return handle_thread_frames(req);
    if (req.method == "thread.continue")    return handle_thread_continue(req);
    if (req.method == "thread.reverse_step")
      return handle_thread_reverse_step(req);

    if (req.method == "frame.locals")       return handle_frame_locals(req);
    if (req.method == "frame.args")         return handle_frame_args(req);
    if (req.method == "frame.registers")    return handle_frame_registers(req);

    if (req.method == "value.eval")         return handle_value_eval(req);
    if (req.method == "value.read")         return handle_value_read(req);

    if (req.method == "mem.read")           return handle_mem_read(req);
    if (req.method == "mem.read_cstr")      return handle_mem_read_cstr(req);
    if (req.method == "mem.regions")        return handle_mem_regions(req);
    if (req.method == "mem.search")         return handle_mem_search(req);
    if (req.method == "mem.dump_artifact")  return handle_mem_dump_artifact(req);

    if (req.method == "artifact.put")       return handle_artifact_put(req);
    if (req.method == "artifact.hypothesis_template")
      return handle_artifact_hypothesis_template(req);
    if (req.method == "artifact.get")       return handle_artifact_get(req);
    if (req.method == "artifact.list")      return handle_artifact_list(req);
    if (req.method == "artifact.tag")       return handle_artifact_tag(req);
    if (req.method == "artifact.delete")    return handle_artifact_delete(req);
    if (req.method == "artifact.relate")    return handle_artifact_relate(req);
    if (req.method == "artifact.relations") return handle_artifact_relations(req);
    if (req.method == "artifact.unrelate")  return handle_artifact_unrelate(req);
    if (req.method == "artifact.export")    return handle_artifact_export(req);
    if (req.method == "artifact.import")    return handle_artifact_import(req);

    if (req.method == "session.create")     return handle_session_create(req);
    if (req.method == "session.attach")     return handle_session_attach(req);
    if (req.method == "session.detach")     return handle_session_detach(req);
    if (req.method == "session.list")       return handle_session_list(req);
    if (req.method == "session.info")       return handle_session_info(req);
    if (req.method == "session.export")     return handle_session_export(req);
    if (req.method == "session.import")     return handle_session_import(req);
    if (req.method == "session.diff")       return handle_session_diff(req);
    if (req.method == "session.targets")    return handle_session_targets(req);

    if (req.method == "recipe.create")       return handle_recipe_create(req);
    if (req.method == "recipe.from_session") return handle_recipe_from_session(req);
    if (req.method == "recipe.list")         return handle_recipe_list(req);
    if (req.method == "recipe.get")          return handle_recipe_get(req);
    if (req.method == "recipe.run")          return handle_recipe_run(req);
    if (req.method == "recipe.delete")       return handle_recipe_delete(req);
    if (req.method == "recipe.lint")         return handle_recipe_lint(req);
    if (req.method == "recipe.reload")       return handle_recipe_reload(req);

    if (req.method == "probe.create")       return handle_probe_create(req);
    if (req.method == "probe.events")       return handle_probe_events(req);
    if (req.method == "probe.list")         return handle_probe_list(req);
    if (req.method == "probe.disable")      return handle_probe_disable(req);
    if (req.method == "probe.enable")       return handle_probe_enable(req);
    if (req.method == "probe.delete")       return handle_probe_delete(req);

    if (req.method == "perf.record")        return handle_perf_record(req);
    if (req.method == "perf.report")        return handle_perf_report(req);
    if (req.method == "perf.cancel")        return handle_perf_cancel(req);

    if (req.method == "observer.proc.fds")    return handle_observer_proc_fds(req);
    if (req.method == "observer.proc.maps")   return handle_observer_proc_maps(req);
    if (req.method == "observer.proc.status") return handle_observer_proc_status(req);
    if (req.method == "observer.net.sockets") return handle_observer_net_sockets(req);
    if (req.method == "observer.net.tcpdump") return handle_observer_net_tcpdump(req);
    if (req.method == "observer.net.igmp")    return handle_observer_net_igmp(req);
    if (req.method == "observer.exec")        return handle_observer_exec(req);

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
  // Optional version handshake: a client that wants to fail fast on a
  // too-old daemon sends `params.protocol_min = "<major>.<minor>"`. We
  // satisfy iff our current version >= the requested floor; otherwise
  // -32011 kProtocolVersionMismatch. Malformed strings (or non-string
  // types) → -32602 kInvalidParams. See docs/05-protocol-versioning.md.
  if (req.params.is_object() && req.params.contains("protocol_min")) {
    const auto& pm = req.params["protocol_min"];
    if (!pm.is_string()) {
      return protocol::make_err(
          req.id, ErrorCode::kInvalidParams,
          "params.protocol_min must be a string of the form \"<major>.<minor>\"");
    }
    auto requested = protocol::parse_protocol_version(pm.get<std::string>());
    if (!requested.has_value()) {
      return protocol::make_err(
          req.id, ErrorCode::kInvalidParams,
          "params.protocol_min is malformed; expected \"<major>.<minor>\"");
    }
    if (*requested > protocol::kProtocolCurrent) {
      std::string msg = "client requires protocol >= " + requested->to_string()
                      + "; daemon is " + protocol::kProtocolVersionString;
      return protocol::make_err(
          req.id, ErrorCode::kProtocolVersionMismatch, std::move(msg));
    }
    // requested <= current ⇒ servable; fall through to ok.
  }

  json data;
  data["name"] = "ldbd";
  data["version"] = kVersionString;
  data["protocol"] = {
      {"version",       protocol::kProtocolVersionString},
      {"major",         protocol::kProtocolVersionMajor},
      {"minor",         protocol::kProtocolVersionMinor},
      {"min_supported", protocol::kProtocolMinSupported.to_string()},
  };
  data["capabilities"] = {
#ifdef LDB_HAVE_CAPSTONE
      {"disasm_backend", "capstone"},
      {"disasm_fallback", true},
#else
      {"disasm_backend", "lldb"},
#endif
      // v1.4 #8: echo the active DebuggerBackend so agents can
      // branch behavior. "lldb" (default) or "gdb" (GdbMiBackend).
      {"backend", backend_name_.empty() ? "lldb" : backend_name_},
  };
  data["formats"] = json::array({"json", "cbor"});
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_describe_endpoints(const Request& req) {
  // Catalog upgraded in M5 (plan §4.8). Each entry now carries proper
  // JSON Schema (draft 2020-12) for params/returns, plus
  // `requires_stopped` and `cost_hint` so a planning agent can read the
  // catalog once at session start and avoid expensive trial-and-error
  // calls.
  //
  // The informal `params: {key:"type-name"}` shape that shipped through
  // M4 is dropped: this is pre-MVP, no clients in the wild, and the
  // schema form fully supersedes it. Any client that needs the old
  // shape can derive it locally from `properties` + `required`.
  using namespace ldb::daemon::schema;

  // Post-V1 plan #4: measured cost is opt-in via view.include_cost_stats.
  // The default response stays byte-deterministic (so session.diff /
  // _provenance hashes stay clean across calls); agents who want the
  // measured numbers ask for them explicitly. Token-budget baselines
  // and the rest of the v1.0 schema are unaffected.
  bool include_cost_stats = false;
  if (req.params.is_object()) {
    if (auto vit = req.params.find("view");
        vit != req.params.end() && vit->is_object()) {
      if (auto iit = vit->find("include_cost_stats");
          iit != vit->end() && iit->is_boolean()) {
        include_cost_stats = iit->get<bool>();
      }
    }
  }

  json eps = json::array();
  auto add = [&](std::string name, const char* summary,
                 json params_schema, json returns_schema,
                 bool requires_target, bool requires_stopped,
                 std::string cost_hint) {
    json e;
    e["method"] = name;
    e["summary"] = summary;
    // The `params_schema` carries the dialect tag so clients have a
    // single anchor; nested $defs / properties inherit by virtue of
    // being in the same document. We don't repeat the tag on the
    // returns_schema to keep the payload small.
    e["params_schema"]  = with_draft(std::move(params_schema));
    e["returns_schema"] = std::move(returns_schema);
    e["requires_target"]  = requires_target;
    e["requires_stopped"] = requires_stopped;
    e["cost_hint"]        = std::move(cost_hint);
    if (include_cost_stats) {
      // cost_n_samples is always present (zero when uncalled);
      // cost_p50_tokens is absent when there are no samples so agents
      // can distinguish "this endpoint is cheap" from "we have no
      // data yet."
      e["cost_n_samples"] = static_cast<std::int64_t>(cost_total(name));
      if (auto p50 = cost_p50(name); p50.has_value()) {
        e["cost_p50_tokens"] = *p50;
      }
    }
    eps.push_back(std::move(e));
  };

  // ============== meta ==============

  add("hello",
      "Server identification and protocol version. Optionally negotiates "
      "the wire protocol via `protocol_min` — see docs/05-protocol-versioning.md.",
      obj({
          {"protocol_min", str_pattern(
              "^[0-9]+\\.[0-9]+$",
              "Optional. Minimum wire-protocol version the client will "
              "accept, as \"<major>.<minor>\". Daemon serves iff its "
              "current version >= this floor; otherwise -32011 "
              "kProtocolVersionMismatch.")},
      }),
      obj({
          {"name",     str()},
          {"version",  str("Daemon version (separate from protocol version).")},
          {"formats",  arr_of(str(), "Supported wire formats.")},
          {"capabilities", obj({
              {"disasm_backend", str(
                  "Active disassembly backend for disasm.range and "
                  "disasm.function: \"lldb\" or \"capstone\".")},
              {"disasm_fallback", bool_(
                  "Present and true when Capstone can fall back to LLDB "
                  "for unsupported arch/mode or decode/read failures.")},
          }, {"disasm_backend"})},
          {"protocol", obj({
              {"version",       str_pattern("^[0-9]+\\.[0-9]+$",
                                            "Current wire-protocol version.")},
              {"major",         uint_()},
              {"minor",         uint_()},
              {"min_supported", str_pattern(
                  "^[0-9]+\\.[0-9]+$",
                  "Oldest version the daemon would still serve; "
                  "informational, does not affect satisfy check.")},
          }, {"version", "major", "minor", "min_supported"})},
      }, {"name", "version", "protocol"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "low");

  add("describe.endpoints",
      "List supported methods with their JSON Schema params/returns, "
      "requires_target, requires_stopped, and cost_hint. Pass "
      "view.include_cost_stats=true to also receive cost_n_samples + "
      "cost_p50_tokens per entry (measured in-process; opt-in so the "
      "default response stays byte-deterministic for session.diff).",
      obj({}),
      obj({{"endpoints", arr_of(obj_open(
          "Per-method record. See plan §4.8."))}}, {"endpoints"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "low");

  // ============== target.* ==============

  add("target.open",
      "Create a target from a binary on disk (no process).",
      obj({{"path", str("Absolute path to executable on the daemon's host.")}},
          {"path"}),
      with_defs(obj({
          {"target_id", uint_min(1)},
          {"triple",    str()},
          {"modules",   arr_of(ref("Module"))},
      }, {"target_id"}),
          {{"Module", module_def()}}),
      /*requires_target=*/false, /*requires_stopped=*/false, "medium");

  add("target.create_empty",
      "Create a target with no associated executable. Used as host for "
      "target.attach by pid and target.load_core.",
      obj({}),
      obj({
          {"target_id", uint_min(1)},
          {"triple",    str()},
          {"modules",   arr_of(obj_open())},
      }, {"target_id"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "low");

  add("target.attach",
      "Attach to a running process by pid. Synchronous: blocks until "
      "the inferior is stopped on attach.",
      obj({
          {"target_id", target_id_param()},
          {"pid",       pid_param()},
      }, {"target_id", "pid"}),
      obj({
          {"state",       str()},
          {"pid",         int_()},
          {"stop_reason", str()},
      }, {"state", "pid"}),
      /*requires_target=*/true, /*requires_stopped=*/false, "medium");

  add("target.connect_remote",
      "Connect to a remote debug server (lldb-server, gdbserver, "
      "debugserver, qemu-gdbstub) over its gdb-remote-protocol "
      "endpoint. URL forms accepted: \"connect://host:port\", "
      "\"host:port\", or \"rr://<absolute-trace-dir>[?port=N]\" — "
      "the rr:// form spawns `rr replay` against the trace and "
      "tunnels to its gdb-remote port, giving the LLDB client "
      "reverse-execution semantics. plugin defaults to \"gdb-remote\".",
      obj({
          {"target_id", target_id_param()},
          {"url",       str("connect://host:port, host:port, or "
                            "rr://<trace-dir>[?port=N].")},
          {"plugin",    str("gdb-remote (default), kdp-remote, etc.")},
      }, {"target_id", "url"}),
      obj({
          {"state",       str()},
          {"pid",         int_()},
          {"stop_reason", str()},
      }, {"state", "pid"}),
      /*requires_target=*/true, /*requires_stopped=*/false, "medium");

  add("target.connect_remote_ssh",
      "End-to-end remote debugging over SSH. Spawns a single ssh "
      "subprocess that simultaneously port-forwards a kernel-assigned "
      "local port AND runs lldb-server gdbserver on the target host. "
      "Tunnel lifetime is bound to the target.",
      obj({
          {"target_id",          target_id_param()},
          {"host",               str("`[user@]hostname`.")},
          {"port",               uint_("Remote port to bind lldb-server to. "
                                       "Default 0 = kernel-assigned.")},
          {"ssh_options",        arr_of(str(),
              "Extra args passed verbatim to `ssh`.")},
          {"remote_lldb_server", str("Path to lldb-server on the remote.")},
          {"inferior_path",      str("Path to the inferior on the remote.")},
          {"inferior_argv",      arr_of(str(), "Argv tail for the inferior.")},
          {"setup_timeout_ms",   uint_("Cap for the connect handshake.")},
      }, {"target_id", "host", "inferior_path"}),
      obj({
          {"target_id",         uint_min(1)},
          {"state",             str()},
          {"pid",               int_()},
          {"stop_reason",       str()},
          {"local_tunnel_port", uint_range(1, 65535)},
      }, {"target_id", "state", "pid", "local_tunnel_port"}),
      /*requires_target=*/true, /*requires_stopped=*/false, "medium");

  add("target.load_core",
      "Load a postmortem core file as a fresh target with frozen "
      "threads. Same read-only endpoints (modules, threads, frames, "
      "memory, ...) work against the resulting target.",
      obj({{"path", str("Absolute path to the core file.")}},
          {"path"}),
      obj({
          {"target_id", uint_min(1)},
          {"triple",    str()},
          {"modules",   arr_of(obj_open())},
      }, {"target_id"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "medium");

  add("target.close", "Drop a target.",
      obj({{"target_id", target_id_param()}}, {"target_id"}),
      obj({{"closed", bool_()}}, {"closed"}),
      /*requires_target=*/true, /*requires_stopped=*/false, "low");

  add("target.list",
      "Enumerate every open target in the daemon. Each entry carries "
      "target_id, triple, executable path (when derivable), optional "
      "label (target.label), has_process bit, and snapshot string. "
      "Order is ascending by target_id (deterministic). Tier 3 §9 — "
      "the agent-side companion to target.open's opaque target_id.",
      obj({{"view", view_param()}}),
      obj({
          {"targets", arr_of(obj({
              {"target_id",   uint_min(1)},
              {"triple",      str()},
              {"path",        str("Executable path on disk; empty for "
                                  "empty / core-only targets.")},
              {"label",       str("Set by target.label; absent if "
                                  "unlabelled.")},
              {"has_process", bool_("True iff a live process is "
                                    "attached or launched.")},
              {"snapshot",    str("Same value snapshot_for_target "
                                  "produces for the dispatcher's "
                                  "_provenance.snapshot.")},
          }, {"target_id", "triple", "has_process"}))},
          {"total",       uint_()},
          {"next_offset", uint_()},
      }, {"targets", "total"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "low");

  add("target.label",
      "Set a stable, daemon-process-scoped label on a target. Labels are "
      "globally unique across open targets — relabeling another target "
      "to a label already in use returns -32602 with the conflicting "
      "owner in the message. Re-labeling the same target with a new "
      "string replaces the old name; same string is a no-op. Labels die "
      "with target.close (no cross-restart persistence — Tier 3 §9 "
      "scope).",
      obj({
          {"target_id", target_id_param()},
          {"label",     str("Non-empty string; uniqueness enforced.")},
      }, {"target_id", "label"}),
      obj({
          {"target_id", uint_min(1)},
          {"label",     str()},
      }, {"target_id", "label"}),
      /*requires_target=*/true, /*requires_stopped=*/false, "low");

  // ============== static analysis ==============

  add("module.list",
      "Enumerate modules of a target. Supports view.diff_against — pass "
      "a prior response's _provenance.snapshot to receive only the "
      "module entries added/removed since that snapshot (set-symmetric-"
      "difference; each item annotated with diff_op). Cache miss "
      "surfaces as diff_baseline_missing=true and the full array.",
      obj({{"target_id", target_id_param()}}, {"target_id"}),
with_defs(      obj({{"modules", arr_of(ref("Module"))}}, {"modules"}),
          {{"Module", module_def()}}),
      /*requires_target=*/true, /*requires_stopped=*/false, "high");

  add("type.layout",
      "Look up a struct/class/union by name and return its memory layout.",
      obj({
          {"target_id", target_id_param()},
          {"name",      str("Type name; LLDB resolves namespaces.")},
      }, {"target_id", "name"}),
      with_defs(obj({
          {"found",  bool_()},
          {"layout", obj({
              {"name",        str()},
              {"byte_size",   uint_()},
              {"alignment",   uint_()},
              {"fields",      arr_of(ref("Field"))},
              {"holes_total", uint_()},
          })},
          {"warnings", arr_of(str(
              "Optional, non-fatal advisories about the layout — e.g. a "
              "DWARF inconsistency where a field's end offset exceeds "
              "byte_size. Absent when the layout is internally "
              "consistent."))},
      }, {"found"}),
          {{"Field", field_def()}}),
      /*requires_target=*/true, /*requires_stopped=*/false, "medium");

  add("symbol.find",
      "Find symbols by exact name; optionally filtered by kind.",
      obj({
          {"target_id", target_id_param()},
          {"name",      str()},
          {"kind",      enum_str({"function", "variable", "other", "any"},
                                 "Default: any.")},
      }, {"target_id", "name"}),
with_defs(      obj({{"matches", arr_of(ref("SymbolMatch"))}}, {"matches"}),
          {{"SymbolMatch", symbol_match_def()}}),
      /*requires_target=*/true, /*requires_stopped=*/false, "medium");

  add("string.list",
      "Enumerate ASCII strings (printable runs) in the target's data "
      "sections. Default scope is the main executable.",
      obj({
          {"target_id", target_id_param()},
          {"min_len",   uint_("Minimum run length. Default 4.")},
          {"max_len",   uint_("Cap per-string emit length.")},
          {"section",   str("Limit to a named section (e.g. .rodata).")},
          {"module",    str("Limit to a named module.")},
      }, {"target_id"}),
with_defs(      obj({{"strings", arr_of(ref("StringEntry"))}}, {"strings"}),
          {{"StringEntry", string_entry_def()}}),
      /*requires_target=*/true, /*requires_stopped=*/false, "high");

  add("disasm.range",
      "Disassemble [start_addr, end_addr) and return one entry per "
      "instruction.",
      obj({
          {"target_id",  target_id_param()},
          {"start_addr", uint_()},
          {"end_addr",   uint_()},
      }, {"target_id", "start_addr", "end_addr"}),
with_defs(      obj({{"instructions", arr_of(ref("Insn"))}}, {"instructions"}),
          {{"Insn", disasm_insn_def()}}),
      /*requires_target=*/true, /*requires_stopped=*/false, "high");

  add("disasm.function",
      "Disassemble the body of a function looked up by exact name. "
      "Equivalent to symbol.find + disasm.range.",
      obj({
          {"target_id", target_id_param()},
          {"name",      str()},
      }, {"target_id", "name"}),
      with_defs(obj({
          {"found",        bool_()},
          {"address",      uint_()},
          {"byte_size",    uint_()},
          {"instructions", arr_of(ref("Insn"))},
      }, {"found"}),
          {{"Insn", disasm_insn_def()}}),
      /*requires_target=*/true, /*requires_stopped=*/false, "medium");

  add("xref.addr",
      "Find every instruction in the main executable that references "
      "an address. Detects direct branches reliably; ARM64 ADRP+ADD "
      "reconstruction is a known gap.",
      obj({
          {"target_id", target_id_param()},
          {"addr",      address_param()},
      }, {"target_id", "addr"}),
with_defs(      obj({{"matches", arr_of(ref("XrefMatch"))}}, {"matches"}),
          {{"XrefMatch", xref_match_def()}}),
      /*requires_target=*/true, /*requires_stopped=*/false, "high");

  add("string.xref",
      "Find xrefs to an exact-text string. Combines address-hex "
      "detection (x86-64 direct loads) with LLDB comment-text "
      "matching (ARM64 ADRP+ADD pairs).",
      obj({
          {"target_id", target_id_param()},
          {"text",      str("Exact string text to match.")},
      }, {"target_id", "text"}),
      with_defs(obj({{"results", arr_of(obj({
          {"string", ref("StringEntry")},
          {"xrefs",  arr_of(ref("XrefMatch"))},
      }))}}, {"results"}),
          {{"StringEntry", string_entry_def()},
           {"XrefMatch",   xref_match_def()}}),
      /*requires_target=*/true, /*requires_stopped=*/false, "high");

  add("static.globals_of_type",
      "Tier 3 §12 — semantic queries v1. Find every global variable in "
      "the target whose DWARF type matches `type_name`. Matching policy: "
      "exact match against SBValue::GetTypeName() first; if no exact "
      "hit, fall back to substring match (plain find, no regex) and "
      "surface `type_match_strict=false`. Result count is capped; "
      "`truncated=true` flags the rare case where a hostile or huge "
      "binary fills the cap. heap.objects_of_type / mutex.lock_graph / "
      "string.flow_to / thread.blockers are deferred to v0.5+ — they "
      "need glibc / pthread internals or substantial dataflow analysis. "
      "Type-name canonical form is whatever the host LLDB reports; on "
      "Linux LLVM 18+ that means bare struct/typedef names (no `struct "
      "` prefix), `const char *const`, `int[4]`.",
      obj({
          {"target_id", target_id_param()},
          {"type_name", str("DWARF type name; canonical form is "
                            "SBValue::GetTypeName() output.")},
          {"view",      view_param()},
      }, {"target_id", "type_name"}),
      with_defs(obj({
          {"globals",            arr_of(ref("GlobalVarMatch"))},
          {"total",              uint_()},
          {"next_offset",        uint_()},
          {"type_match_strict",  bool_("False iff results came from the "
                                       "substring fallback.")},
          {"truncated",          bool_("Present and true only when the "
                                       "result count hit the backend cap.")},
      }, {"globals", "type_match_strict"}),
          {{"GlobalVarMatch", global_var_match_def()}}),
      /*requires_target=*/true, /*requires_stopped=*/false, "medium");

  // ============== correlate.* (Tier 3 §10, scoped) ==============
  //
  // Composition endpoints over the per-target primitives (type.layout,
  // symbol.find, string.xref). Each takes a list of target_ids and
  // batches the same lookup across all of them, producing a per-target
  // result row the agent can compare. Full DWARF type-hash and
  // function-fingerprint correlation are deferred to Tier 5 §21.
  //
  // Validation rules (consistent across the three):
  //   • target_ids must be a non-empty array of uint target ids.
  //   • Empty array → -32602.
  //   • Unknown target_id (not currently open) → -32602 with the
  //     offender id in the message.
  //   • Duplicate target_ids → silently deduped (caller's mistake).

  add("correlate.types",
      "Look up a struct/class/union by name across N target_ids and "
      "report drift. For each target the result row carries "
      "{target_id, status, layout?, error?}. status is one of "
      "\"found\" (layout populated), \"missing\" (layout=null; type "
      "not present in that target), or \"backend_error\" (the lookup "
      "threw; error message in `error`). drift=true iff at least two "
      "found-set layouts differ; drift_reason names the FIRST kind of "
      "drift detected, with priority byte_size > alignment > "
      "fields_count > field_offsets > field_types. With fewer than two "
      "found rows there is nothing to compare across, so drift=false "
      "and drift_reason is omitted. Tier 3 §10.",
      obj({
          {"target_ids", arr_of(target_id_param(),
              "Two or more target ids to compare. Duplicates are "
              "deduped. Unknown ids → -32602.")},
          {"name",       str("Type name; LLDB resolves namespaces.")},
          {"view",       view_param()},
      }, {"target_ids", "name"}),
      with_defs(obj({
          {"results", arr_of(obj({
              {"target_id", uint_min(1)},
              {"status",    enum_str({"found", "missing", "backend_error"})},
              {"layout",    obj({
                  {"name",        str()},
                  {"byte_size",   uint_()},
                  {"alignment",   uint_()},
                  {"fields",      arr_of(ref("Field"))},
                  {"holes_total", uint_()},
              })},
              {"error",     str()},
          }, {"target_id", "status"}))},
          {"drift",        bool_()},
          {"drift_reason", enum_str({"byte_size", "alignment",
                                     "fields_count", "field_offsets",
                                     "field_types"})},
          {"total",        uint_()},
      }, {"results", "drift", "total"}),
          {{"Field", field_def()}}),
      /*requires_target=*/false, /*requires_stopped=*/false, "medium");

  add("correlate.symbols",
      "Find symbols matching `name` across N target_ids; per-target "
      "matches stand alone (no cross-target dedupe — agent compares "
      "addresses). Tier 3 §10.",
      obj({
          {"target_ids", arr_of(target_id_param())},
          {"name",       str()},
          {"view",       view_param()},
      }, {"target_ids", "name"}),
      with_defs(obj({
          {"results", arr_of(obj({
              {"target_id", uint_min(1)},
              {"matches",   arr_of(ref("SymbolMatch"))},
          }, {"target_id", "matches"}))},
          {"total",   uint_("Sum of matches across all results.")},
      }, {"results", "total"}),
          {{"SymbolMatch", symbol_match_def()}}),
      /*requires_target=*/false, /*requires_stopped=*/false, "medium");

  add("correlate.strings",
      "Find xrefs to `text` across N target_ids; per-target callsites "
      "are flattened into {addr, function?} entries. Empty callsites "
      "array means the string is absent or has no xrefs in that "
      "target. NOTE: file/line resolution per callsite is deferred — "
      "the underlying XrefMatch type doesn't carry source-line info; "
      "a backend extension is needed to populate them. Tier 3 §10.",
      obj({
          {"target_ids", arr_of(target_id_param())},
          {"text",       str("Exact string text to match.")},
          {"view",       view_param()},
      }, {"target_ids", "text"}),
      obj({
          {"results", arr_of(obj({
              {"target_id", uint_min(1)},
              {"callsites", arr_of(obj({
                  {"addr",     uint_()},
                  {"function", str()},
              }, {"addr"}))},
          }, {"target_id", "callsites"}))},
          {"total",   uint_("Sum of callsites across all results.")},
      }, {"results", "total"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "high");

  // ============== process.* ==============

  add("process.launch",
      "Spawn the target's executable as an inferior. Synchronous.",
      obj({
          {"target_id",     target_id_param()},
          {"stop_at_entry", bool_("Stop at the executable entry point.")},
      }, {"target_id"}),
      obj({
          {"state",       str()},
          {"pid",         int_()},
          {"stop_reason", str()},
          {"exit_code",   int_()},
      }, {"state", "pid"}),
      /*requires_target=*/true, /*requires_stopped=*/false, "medium");

  add("process.state",
      "Query the current state of the target's process. Returns "
      "state=\"none\" if no process is associated.",
      obj({{"target_id", target_id_param()}}, {"target_id"}),
      process_state_def(),
      /*requires_target=*/true, /*requires_stopped=*/false, "low");

  add("process.continue",
      "Resume a stopped process. Blocks until next stop or exit. "
      "Optional `tid` selects a thread for per-thread resume — in v0.3 "
      "this is SYNC PASSTHROUGH (whole-process continue regardless of "
      "tid); v0.4+ will keep sibling threads stopped (true non-stop). "
      "See docs/11-non-stop.md.",
      obj({
          {"target_id", target_id_param()},
          {"tid",       uint_min(1, "Optional. Thread id to resume "
                                    "(Tier 4 §14). v0.3: tid is logged "
                                    "but the whole process resumes — "
                                    "wire-shape parity with v0.4 async "
                                    "mode. Future per-thread keep-running "
                                    "lands when SBProcess::SetAsync(true) "
                                    "ships.")},
      }, {"target_id"}),
      process_state_def(),
      /*requires_target=*/true, /*requires_stopped=*/true, "medium");

  add("process.kill",
      "Terminate the target's process. Idempotent.",
      obj({{"target_id", target_id_param()}}, {"target_id"}),
      process_state_def(),
      /*requires_target=*/true, /*requires_stopped=*/false, "low");

  add("process.detach",
      "Detach from the target's process, leaving it running. Preferred "
      "over process.kill for attached processes. Idempotent.",
      obj({{"target_id", target_id_param()}}, {"target_id"}),
      process_state_def(),
      /*requires_target=*/true, /*requires_stopped=*/false, "low");

  add("process.save_core",
      "Save a core file of the target's stopped process to a path.",
      obj({
          {"target_id", target_id_param()},
          {"path",      str("Destination path on the daemon host.")},
      }, {"target_id", "path"}),
      obj({
          {"saved", bool_()},
          {"path",  str()},
      }, {"saved", "path"}),
      /*requires_target=*/true, /*requires_stopped=*/true, "high");

  add("process.step",
      "Single-step the given thread. kind=in|over|out|insn maps to "
      "SBThread::StepInto/StepOver/StepOut/StepInstruction.",
      obj({
          {"target_id", target_id_param()},
          {"tid",       tid_param()},
          {"kind",      enum_str({"in", "over", "out", "insn"})},
      }, {"target_id", "tid", "kind"}),
      obj({
          {"state",       str()},
          {"pid",         int_()},
          {"pc",          uint_()},
          {"stop_reason", str()},
      }, {"state", "pid"}),
      /*requires_target=*/true, /*requires_stopped=*/true, "medium");

  add("process.reverse_continue",
      "Reverse-continue: run backward until the next stop. Requires a "
      "record/replay backend (rr, reached via target.connect_remote "
      "rr://). Implemented by sending the GDB RSP 'bc' packet through "
      "LLDB's gdb-remote plugin. Non-rr targets get -32003 forbidden. "
      "See docs/16-reverse-exec.md.",
      obj({{"target_id", target_id_param()}}, {"target_id"}),
      process_state_def(),
      /*requires_target=*/true, /*requires_stopped=*/true, "high");

  add("process.reverse_step",
      "Reverse-step the given thread. v0.3 supports kind=insn only "
      "(RSP 'bs' packet, one machine instruction). kind=in/over/out "
      "are reserved-but-rejected (-32602) — their reverse semantics "
      "need client-side step-over emulation that lands later. See "
      "docs/16-reverse-exec.md.",
      obj({
          {"target_id", target_id_param()},
          {"tid",       tid_param()},
          {"kind",      enum_str({"in", "over", "out", "insn"})},
      }, {"target_id", "tid", "kind"}),
      obj({
          {"state",       str()},
          {"pid",         int_()},
          {"pc",          uint_()},
          {"stop_reason", str()},
      }, {"state", "pid"}),
      /*requires_target=*/true, /*requires_stopped=*/true, "high");

  // ============== thread.* / frame.* / value.* ==============

  add("thread.list",
      "Enumerate threads of the target's process. Supports "
      "view.diff_against in the same way as module.list — pass a "
      "prior _provenance.snapshot to receive only added/removed "
      "thread entries.",
      obj({{"target_id", target_id_param()}}, {"target_id"}),
with_defs(      obj({{"threads", arr_of(ref("Thread"))}}, {"threads"}),
          {{"Thread", thread_info_def()}}),
      /*requires_target=*/true, /*requires_stopped=*/true, "medium");

  add("thread.frames",
      "Backtrace a thread, innermost first. max_depth=0 means no cap.",
      obj({
          {"target_id", target_id_param()},
          {"tid",       tid_param()},
          {"max_depth", uint_("Default 0 (no cap).")},
      }, {"target_id", "tid"}),
with_defs(      obj({{"frames", arr_of(ref("Frame"))}}, {"frames"}),
          {{"Frame", frame_info_def()}}),
      /*requires_target=*/true, /*requires_stopped=*/true, "medium");

  add("thread.continue",
      "Resume the given thread. WARNING: in v0.3 this is SYNC — all "
      "threads resume together (passthrough into process.continue) "
      "because the daemon runs LLDB in SBProcess::SetAsync(false). The "
      "wire shape is async-ready: in v0.4+ when async mode lands this "
      "endpoint will keep sibling threads stopped (true non-stop). "
      "Agents should treat thread.continue as equivalent to "
      "process.continue under v0.3 protocol. See docs/11-non-stop.md.",
      obj({
          {"target_id", target_id_param()},
          {"tid",       tid_param()},
      }, {"target_id", "tid"}),
      process_state_def(),
      /*requires_target=*/true, /*requires_stopped=*/true, "medium");

  add("thread.reverse_step",
      "Reverse-step the given thread. Same shape as process.reverse_step; "
      "the split mirrors thread.continue / process.continue so async-aware "
      "clients can drive either entry point. v0.3 sync: kind=insn only. "
      "See docs/16-reverse-exec.md.",
      obj({
          {"target_id", target_id_param()},
          {"tid",       tid_param()},
          {"kind",      enum_str({"in", "over", "out", "insn"})},
      }, {"target_id", "tid", "kind"}),
      obj({
          {"state",       str()},
          {"pid",         int_()},
          {"pc",          uint_()},
          {"stop_reason", str()},
      }, {"state", "pid"}),
      /*requires_target=*/true, /*requires_stopped=*/true, "high");

  add("frame.locals",
      "Local variables in scope at a frame. Bytes capped at 64; agents "
      "follow up with mem.read for fuller dumps.",
      obj({
          {"target_id",   target_id_param()},
          {"tid",         tid_param()},
          {"frame_index", frame_index_param()},
      }, {"target_id", "tid"}),
with_defs(      obj({{"locals", arr_of(ref("ValueInfo"))}}, {"locals"}),
          {{"ValueInfo", value_info_def()}}),
      /*requires_target=*/true, /*requires_stopped=*/true, "medium");

  add("frame.args",
      "Function arguments visible at a frame.",
      obj({
          {"target_id",   target_id_param()},
          {"tid",         tid_param()},
          {"frame_index", frame_index_param()},
      }, {"target_id", "tid"}),
with_defs(      obj({{"args", arr_of(ref("ValueInfo"))}}, {"args"}),
          {{"ValueInfo", value_info_def()}}),
      /*requires_target=*/true, /*requires_stopped=*/true, "medium");

  add("frame.registers",
      "All register sets at a frame, flattened.",
      obj({
          {"target_id",   target_id_param()},
          {"tid",         tid_param()},
          {"frame_index", frame_index_param()},
      }, {"target_id", "tid"}),
with_defs(      obj({{"registers", arr_of(ref("ValueInfo"))}}, {"registers"}),
          {{"ValueInfo", value_info_def()}}),
      /*requires_target=*/true, /*requires_stopped=*/true, "medium");

  add("value.eval",
      "Evaluate a C/C++ expression in the context of (target, tid, "
      "frame_index). Compile/runtime/timeout failures are returned as "
      "{error:'...'} data, NOT as JSON-RPC errors.",
      obj({
          {"target_id",   target_id_param()},
          {"tid",         tid_param()},
          {"frame_index", frame_index_param()},
          {"expr",        str("C/C++ expression text.")},
          {"timeout_us",  uint_("Default 250000 (250 ms).")},
      }, {"target_id", "tid", "expr"}),
      with_defs(obj({
          {"value", ref("ValueInfo")},
          {"error", str()},
      }),
          {{"ValueInfo", value_info_def()}}),
      /*requires_target=*/true, /*requires_stopped=*/true, "medium");

  add("value.read",
      "Resolve a frame-relative dotted/bracketed path "
      "(e.g. `g_origin.x`, `arr[3].field`) to a typed value.",
      obj({
          {"target_id",   target_id_param()},
          {"tid",         tid_param()},
          {"frame_index", frame_index_param()},
          {"path",        str("Dotted/bracketed access path.")},
      }, {"target_id", "tid", "path"}),
      with_defs(obj({
          {"value",    ref("ValueInfo")},
          {"children", arr_of(ref("ValueInfo"))},
          {"error",    str()},
      }),
          {{"ValueInfo", value_info_def()}}),
      /*requires_target=*/true, /*requires_stopped=*/true, "medium");

  // ============== mem.* ==============

  add("mem.read",
      "Read up to 1 MiB of process memory at the given runtime address. "
      "Returns lower-case packed hex.",
      obj({
          {"target_id", target_id_param()},
          {"address",   address_param()},
          {"size",      size_param()},
      }, {"target_id", "address", "size"}),
      obj({
          {"address", uint_()},
          {"bytes",   hex_string()},
      }, {"address", "bytes"}),
      /*requires_target=*/true, /*requires_stopped=*/false, "high");

  add("mem.read_cstr",
      "Read a NUL-terminated string at a runtime address, capped at "
      "max_len bytes (default 4096).",
      obj({
          {"target_id", target_id_param()},
          {"address",   address_param()},
          {"max_len",   uint_("Default 4096.")},
      }, {"target_id", "address"}),
      obj({
          {"address",   uint_()},
          {"value",     str()},
          {"truncated", bool_()},
      }, {"address", "value", "truncated"}),
      /*requires_target=*/true, /*requires_stopped=*/false, "medium");

  add("mem.regions",
      "Enumerate the inferior's mapped memory regions with permissions.",
      obj({{"target_id", target_id_param()}}, {"target_id"}),
with_defs(      obj({{"regions", arr_of(ref("Region"))}}, {"regions"}),
          {{"Region", memory_region_def()}}),
      /*requires_target=*/true, /*requires_stopped=*/false, "medium");

  add("mem.search",
      "Scan process memory for a byte pattern. Needle is either a hex "
      "string or {text:'...'}. length=0 searches all readable regions "
      "(capped at 256 MiB). max_hits capped at 1024.",
      obj({
          {"target_id", target_id_param()},
          {"needle",    obj_open(
              "Hex string OR an {\"text\":\"...\"} object.")},
          {"address",   address_param()},
          {"length",    uint_("0 = scan all readable regions.")},
          {"max_hits",  uint_("Capped at 1024.")},
      }, {"target_id", "needle"}),
      obj({{"hits", arr_of(obj({{"address", uint_()}}, {"address"}))}},
          {"hits"}),
      /*requires_target=*/true, /*requires_stopped=*/false, "high");

  add("mem.dump_artifact",
      "Read [len] bytes at [addr] from the live target and store them "
      "as an artifact under (build_id, name) in one round-trip. Composes "
      "mem.read + artifact.put; same 1 MiB cap as mem.read.",
      obj({
          {"target_id", target_id_param()},
          {"addr",      address_param()},
          {"len",       size_param()},
          {"build_id",  str()},
          {"name",      str()},
          {"format",    str("Caller-supplied content tag.")},
          {"meta",      obj_open("Caller-supplied metadata.")},
      }, {"target_id", "addr", "len", "build_id", "name"}),
      obj({
          {"artifact_id", int_()},
          {"byte_size",   uint_()},
          {"sha256",      str()},
          {"name",        str()},
      }, {"artifact_id", "byte_size", "sha256", "name"}),
      /*requires_target=*/true, /*requires_stopped=*/false, "high");

  // ============== artifact.* ==============

  add("artifact.put",
      "Store a binary blob in the artifact store, keyed by "
      "(build_id, name). bytes_b64 is base64-encoded. format is a "
      "caller-supplied content tag; a few formats trigger typed "
      "validation: format=\"hypothesis-v1\" requires the bytes to "
      "parse as a JSON envelope with a numeric `confidence` in [0..1] "
      "and an `evidence_refs` array of artifact_id integers. Fetch "
      "artifact.hypothesis_template() for a starter envelope.",
      obj({
          {"build_id",  str()},
          {"name",      str()},
          {"bytes_b64", str("base64-encoded payload.")},
          {"format",    str("Caller-supplied content tag.")},
          {"meta",      obj_open("Caller-supplied metadata.")},
      }, {"build_id", "name", "bytes_b64"}),
      obj({
          {"id",          int_()},
          {"sha256",      str()},
          {"byte_size",   uint_()},
          {"stored_path", str()},
      }, {"id", "sha256", "byte_size", "stored_path"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "high");

  add("artifact.hypothesis_template",
      "Return a JSON skeleton suitable as the body of a "
      "hypothesis-v1 artifact. The template already validates; "
      "agents fill in optional fields (statement, rationale, author) "
      "and base64-encode it as artifact.put's bytes_b64. See "
      "docs/18-hypothesis.md for the schema rationale.",
      obj({}, {}),
      obj({
          {"template", obj_open("JSON envelope ready for artifact.put.")},
      }, {"template"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "low");

  add("artifact.get",
      "Fetch an artifact by (build_id, name) or by id. Cap with "
      "view.max_bytes to preview large blobs without pulling the full "
      "payload.",
      obj({
          {"build_id", str()},
          {"name",     str()},
          {"id",       int_()},
          {"view",     obj({{"max_bytes", uint_()}})},
      }),
      obj({
          {"bytes_b64",  str()},
          {"byte_size",  uint_()},
          {"sha256",     str()},
          {"format",     str()},
          {"meta",       obj_open()},
          {"build_id",   str()},
          {"name",       str()},
          {"created_at", int_()},
          {"truncated",  bool_()},
      }, {"bytes_b64", "byte_size", "sha256", "build_id", "name",
          "created_at", "truncated"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "high");

  add("artifact.list",
      "Enumerate stored artifacts, optionally filtered by build_id and/or "
      "name_pattern (sqlite LIKE — '%' multi-char, '_' single-char). Bytes "
      "are not included; use artifact.get for the payload.",
      obj({
          {"build_id",     str()},
          {"name_pattern", str()},
      }),
      obj({
          {"artifacts", arr_of(obj({
              {"id",         int_()},
              {"build_id",   str()},
              {"name",       str()},
              {"byte_size",  uint_()},
              {"sha256",     str()},
              {"format",     str()},
              {"tags",       arr_of(str())},
              {"created_at", int_()},
          }))},
          {"total", uint_()},
      }, {"artifacts", "total"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "medium");

  add("artifact.tag",
      "Add tags to an existing artifact (additive, idempotent — duplicates "
      "are no-ops). Returns the resulting full tag set.",
      obj({
          {"id",   int_()},
          {"tags", arr_of(str())},
      }, {"id", "tags"}),
      obj({{"tags", arr_of(str())}}, {"tags"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "low");

  add("artifact.delete",
      "Delete an artifact by id: drops the row, cascades its tags, and "
      "unlinks the on-disk blob. Idempotent — deleting an already-gone id "
      "returns deleted=false (not an error). The recipe.delete endpoint "
      "is the high-level wrapper for recipe-format artifacts. ON DELETE "
      "CASCADE also drops every artifact_relations row referencing this "
      "artifact (post-v0.1 §7).",
      obj({{"id", int_()}}, {"id"}),
      obj({
          {"id",      int_()},
          {"deleted", bool_()},
      }, {"id", "deleted"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "low");

  // ============== artifact.relate / .relations / .unrelate (Tier 3 §7) =====

  add("artifact.relate",
      "Insert a typed relation from one artifact to another. Predicate is "
      "a free-form short string ('parsed_by', 'extracted_from', "
      "'called_by', 'ancestor_of', ...) — see "
      "docs/09-artifact-knowledge-graph.md for common values. Both "
      "endpoints must already exist in the store; missing ids surface as "
      "-32000. Manual-attach in v0.3; auto-derivation from session logs "
      "is a v0.5 follow-up.",
      obj({
          {"from_id",   int_()},
          {"to_id",     int_()},
          {"predicate", str("Free-form non-empty string.")},
          {"meta",      obj_open("Optional small JSON object.")},
      }, {"from_id", "to_id", "predicate"}),
      obj({
          {"relation_id", int_()},
          {"from_id",     int_()},
          {"to_id",       int_()},
          {"predicate",   str()},
          {"created_at",  int_("Unix epoch nanoseconds.")},
      }, {"relation_id", "from_id", "to_id", "predicate", "created_at"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "low");

  add("artifact.relations",
      "Enumerate relations. With artifact_id set, returns only edges "
      "involving that artifact (filtered by direction: 'out' = from, "
      "'in' = to, 'both' = either). With predicate set, exact-match "
      "filter. The view spec (limit/offset/fields/summary) projects the "
      "returned array. Single-hop only — recursive graph traversal is "
      "deferred.",
      obj({
          {"artifact_id", int_("Filter to edges involving this artifact.")},
          {"predicate",   str("Exact-match filter.")},
          {"direction",   enum_str({"out", "in", "both"},
                                   "Default 'both'.")},
      }),
      obj({
          {"relations", arr_of(obj({
              {"id",         int_()},
              {"from_id",    int_()},
              {"to_id",      int_()},
              {"predicate",  str()},
              {"meta",       obj_open()},
              {"created_at", int_()},
          }))},
          {"total", uint_()},
      }, {"relations", "total"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "low");

  add("artifact.unrelate",
      "Drop one relation by id. Idempotent — deleting an already-gone "
      "id returns deleted=false (not an error). Use artifact.delete "
      "to drop every relation involving an artifact at once via "
      "ON DELETE CASCADE.",
      obj({{"relation_id", int_()}}, {"relation_id"}),
      obj({
          {"relation_id", int_()},
          {"deleted",     bool_()},
      }, {"relation_id", "deleted"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "low");

  // ============== session.* ==============

  add("session.create",
      "Create a new investigation session — a per-session sqlite db "
      "under ${LDB_STORE_ROOT}/sessions/<uuid>.db that holds the "
      "rpc_log of every call made while attached. Does NOT attach.",
      obj({
          {"name",      str()},
          {"target_id", str("Optional — may be a string handle, not the "
                            "uint64 target_id (see plan).")},
      }, {"name"}),
      obj({
          {"id",         str()},
          {"name",       str()},
          {"created_at", int_()},
          {"path",       str()},
      }, {"id", "name", "created_at", "path"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "low");

  add("session.attach",
      "Activate a session: every subsequent rpc dispatched on this "
      "connection — including this attach call — will be appended to "
      "the session's rpc_log table.",
      obj({{"id", str()}}, {"id"}),
      obj({
          {"id",       str()},
          {"name",     str()},
          {"attached", bool_()},
      }, {"id", "name", "attached"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "low");

  add("session.detach",
      "Stop logging rpcs to the active session.",
      obj({}),
      obj({{"detached", bool_()}}, {"detached"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "low");

  add("session.list",
      "Enumerate every session known to this store, sorted newest-first "
      "by created_at. Each entry includes call_count.",
      obj({}),
      obj({
          {"sessions", arr_of(obj({
              {"id",         str()},
              {"name",       str()},
              {"created_at", int_()},
              {"call_count", int_()},
              {"path",       str()},
          }))},
          {"total", uint_()},
      }, {"sessions", "total"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "medium");

  add("session.info",
      "Detailed view of one session: name, target_id (if any), "
      "created_at, current call_count, last_call_at, path.",
      obj({{"id", str()}}, {"id"}),
      obj({
          {"id",           str()},
          {"name",         str()},
          {"target_id",    str()},
          {"created_at",   int_()},
          {"call_count",   int_()},
          {"last_call_at", int_()},
          {"path",         str()},
      }, {"id", "name", "created_at", "call_count", "path"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "low");

  add("session.diff",
      "Structured diff between two sessions' rpc_logs (Tier 3 §11). "
      "Two log rows match iff their (method, canonical-params-JSON) "
      "tuples are byte-identical; an aligned pair is `common` if their "
      "canonical responses are byte-identical, else `diverged`. "
      "Unaligned A rows are `removed`, unaligned B rows are `added`. "
      "Alignment is computed via Longest Common Subsequence on the "
      "(method, params_canon) sequence — a single inserted call shows "
      "up as one `added` entry, not as a downstream cascade of "
      "diverged. Diffing across different binaries is allowed but "
      "expected to be high-divergence (no semantic match across "
      "build_ids). Use `view` for limit/offset/summary slicing — "
      "responses on long traces can be very large; cost_hint is "
      "`unbounded`.",
      obj({
          {"session_a", str("Base session id (32-hex).")},
          {"session_b", str("Compared session id (32-hex).")},
          {"view",      view_param()},
      }, {"session_a", "session_b"}),
      obj({
          {"summary", obj({
              {"total_a",  int_()},
              {"total_b",  int_()},
              {"added",    int_()},
              {"removed",  int_()},
              {"common",   int_()},
              {"diverged", int_()},
          }, {"total_a", "total_b", "added", "removed",
              "common", "diverged"})},
          {"entries",     arr_of(obj_open(
              "Diff entry. Fields by kind: "
              "common={kind, method, params_hash, seq_a, seq_b}; "
              "added={kind, method, params, response, seq_b}; "
              "removed={kind, method, params, response, seq_a}; "
              "diverged={kind, method, params, seq_a, seq_b, "
              "response_a, response_b}."))},
          {"total",       int_()},
          {"next_offset", int_()},
      }, {"summary", "entries", "total"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "unbounded");

  add("session.targets",
      "List the distinct target_ids a session has interacted with, with "
      "per-target call_count and the seq window of those calls. Mines "
      "the rpc_log; rows without params.target_id (hello, "
      "describe.endpoints, session.* themselves) are filtered out. "
      "Labels are enriched from the live backend state when the target "
      "is still open — closed targets appear without a label. Tier 3 "
      "§9.",
      obj({
          {"session_id", str("32-hex session id from session.create.")},
          {"view",       view_param()},
      }, {"session_id"}),
      obj({
          {"targets", arr_of(obj({
              {"target_id",  uint_min(1)},
              {"label",      str("Live label if the target is still "
                                 "open; absent otherwise.")},
              {"call_count", int_()},
              {"first_seq",  int_()},
              {"last_seq",   int_()},
          }, {"target_id", "call_count", "first_seq", "last_seq"}))},
          {"total",       uint_()},
          {"next_offset", uint_()},
      }, {"targets", "total"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "medium");

  // ============== session.export / .import — `.ldbpack` (M5 part 5) ====

  {
    auto pack_manifest_schema = obj({
        {"format",     str()},
        {"created_at", int_()},
        {"creator",    str()},
        {"sessions",   arr_of(obj({
            {"id",         str()},
            {"name",       str()},
            {"call_count", int_()},
            {"path",       str()},
            {"target_id",  str()},
        }))},
        {"artifacts",  arr_of(obj({
            {"build_id",  str()},
            {"name",      str()},
            {"sha256",    str()},
            {"byte_size", uint_()},
            {"path",      str()},
        }))},
        {"relations",  arr_of(obj({
            {"from_build_id", str()},
            {"from_name",     str()},
            {"to_build_id",   str()},
            {"to_name",       str()},
            {"predicate",     str()},
            {"meta",          obj_open()},
            {"created_at",    int_()},
        }))},
    }, {"format", "sessions", "artifacts"});

    auto import_entry_schema = obj({
        {"kind",   enum_str({"session", "artifact", "relation"})},
        {"key",    str()},
        {"reason", str()},
    }, {"kind", "key"});

    auto export_signature_schema = obj({
        {"key_id",    str()},
        {"algorithm", str()},
    }, {"key_id", "algorithm"});

    auto import_signature_schema = obj({
        {"key_id",   str()},
        {"verified", bool_()},
        {"signer",   str()},
    }, {"key_id", "verified"});

    add("session.export",
        "Bundle one session and every artifact in the store into a "
        "gzip+tar `.ldbpack` archive (plan §8). Path defaults to "
        "${LDB_STORE_ROOT}/packs/<id>.ldbpack. Produces a manifest the "
        "agent can introspect before extracting on the import side. "
        "Optional `sign_key` (path to an unencrypted OpenSSH ed25519 "
        "private key) emits an `ldbpack/1+sig` pack with embedded "
        "signature.json / signature.sig sidecar entries — see "
        "docs/14-pack-signing.md.",
        obj({
            {"id",       str()},
            {"path",     str("Optional output path; defaults under store root.")},
            {"sign_key", str("Optional path to an OpenSSH ed25519 private "
                             "key; when set the pack is emitted as "
                             "ldbpack/1+sig and includes signature.json + "
                             "signature.sig sidecar entries.")},
            {"signer",   str("Optional free-form signer label baked into "
                             "signature.json; defaults to the key's "
                             "comment field.")},
        }, {"id"}),
        obj({
            {"path",      str()},
            {"byte_size", uint_()},
            {"sha256",    str()},
            {"manifest",  pack_manifest_schema},
            {"signature", export_signature_schema},
        }, {"path", "byte_size", "sha256", "manifest"}),
        /*requires_target=*/false, /*requires_stopped=*/false, "high");

    add("session.import",
        "Import a `.ldbpack` archive: walk its manifest, insert every "
        "session and artifact into the local stores. conflict_policy "
        "controls duplicate handling (default 'error' aborts the whole "
        "import; 'skip' preserves local entries; 'overwrite' replaces). "
        "Optional `trust_root` (directory of `*.pub` or `authorized_keys` "
        "file) authenticates a signed pack; `require_signed=true` "
        "rejects any unsigned pack with kBadState.",
        obj({
            {"path",            str()},
            {"conflict_policy", enum_str({"error", "skip", "overwrite"})},
            {"trust_root",      str("Optional path to a directory of "
                                     "`*.pub` files or a single "
                                     "`authorized_keys`-format file. "
                                     "When set, the pack's signer key_id "
                                     "must appear in the trust root or "
                                     "the import is refused.")},
            {"require_signed",  bool_("If true, refuse unsigned packs "
                                       "with kBadState (-32002).")},
        }, {"path"}),
        obj({
            {"imported",  arr_of(import_entry_schema)},
            {"skipped",   arr_of(import_entry_schema)},
            {"policy",    str()},
            {"signature", import_signature_schema},
        }, {"imported", "skipped", "policy"}),
        /*requires_target=*/false, /*requires_stopped=*/false, "high");

    add("artifact.export",
        "Bundle artifacts (no session) into a `.ldbpack`. With "
        "build_id set, only that build's artifacts; with names set, "
        "only those names; both empty exports every artifact in the "
        "store. Optional `sign_key` emits a signed pack — see "
        "docs/14-pack-signing.md.",
        obj({
            {"build_id", str()},
            {"names",    arr_of(str())},
            {"path",     str()},
            {"sign_key", str("Optional path to an OpenSSH ed25519 "
                             "private key.")},
            {"signer",   str("Optional signer label.")},
        }),
        obj({
            {"path",      str()},
            {"byte_size", uint_()},
            {"sha256",    str()},
            {"manifest",  pack_manifest_schema},
            {"signature", export_signature_schema},
        }, {"path", "byte_size", "sha256", "manifest"}),
        /*requires_target=*/false, /*requires_stopped=*/false, "high");

    add("artifact.import",
        "Alias of session.import — both endpoints accept the same "
        "`.ldbpack` shape and import every entry inside. Conflict "
        "policy and trust-root semantics identical.",
        obj({
            {"path",            str()},
            {"conflict_policy", enum_str({"error", "skip", "overwrite"})},
            {"trust_root",      str()},
            {"require_signed",  bool_()},
        }, {"path"}),
        obj({
            {"imported",  arr_of(import_entry_schema)},
            {"skipped",   arr_of(import_entry_schema)},
            {"policy",    str()},
            {"signature", import_signature_schema},
        }, {"imported", "skipped", "policy"}),
        /*requires_target=*/false, /*requires_stopped=*/false, "high");
  }

  // ============== recipe.* (Tier 2 §6) ==============

  {
    auto recipe_param_schema = obj({
        {"name",    str()},
        {"type",    enum_str({"string", "integer"})},
        {"default", obj_open()},   // typed value or null
    }, {"name"});

    auto recipe_call_schema = obj({
        {"method", str()},
        {"params", obj_open("Params object — STRING values matching "
                            "\"{slot}\" are substituted at recipe.run.")},
    }, {"method"});

    auto recipe_summary_schema = obj({
        {"recipe_id",  int_()},
        {"name",       str()},
        {"description",str()},
        {"call_count", int_()},
        {"created_at", int_()},
    }, {"recipe_id", "name", "call_count", "created_at"});

    add("recipe.create",
        "Create a named, parameterized recipe — a reusable RPC sequence "
        "(format=\"recipe-v1\", default) OR an embedded Python module "
        "with `def run(ctx): ...` (format=\"python-v1\", post-V1 #9). "
        "Storage is a `recipe-v1` artifact under build_id \"_recipes\"; "
        "the recipe_id IS the artifact id, so artifact.delete is a "
        "valid GC path. For recipe-v1, parameter substitution is "
        "whole-string-match: a STRING value in calls[].params equal to "
        "\"{slot}\" is replaced with the caller's parameter value at "
        "recipe.run time. For python-v1, the recipe.run `args` dict is "
        "passed verbatim as the `ctx` parameter to `run(ctx)`; see "
        "docs/20-embedded-python.md.",
        obj({
            {"name",        str()},
            {"description", str()},
            {"format",      enum_str({"recipe-v1", "python-v1"})},
            {"calls",       arr_of(recipe_call_schema)},
            {"body",        str("Python module source (python-v1 only)")},
            {"parameters",  arr_of(recipe_param_schema)},
        }, {"name"}),
        obj({
            {"recipe_id",  int_()},
            {"name",       str()},
            {"format",     enum_str({"recipe-v1", "python-v1"})},
            {"call_count", int_()},
        }, {"recipe_id", "name", "call_count"}),
        /*requires_target=*/false, /*requires_stopped=*/false, "low");

    add("recipe.from_session",
        "Extract a recipe from a session's rpc_log. Filters by "
        "include_methods / exclude_methods / since_seq / until_seq; "
        "the default strip-set drops cosmetic / introspection / "
        "session-mgmt calls. Auto-detection of parameter slots is "
        "deferred to v0.5; the produced recipe has no slots — call "
        "recipe.create with parameters to templatize.",
        obj({
            {"source_session_id", str()},
            {"name",              str()},
            {"description",       str()},
            {"filter", obj({
                {"include_methods", arr_of(str())},
                {"exclude_methods", arr_of(str())},
                {"since_seq",       int_()},
                {"until_seq",       int_()},
            })},
        }, {"source_session_id", "name"}),
        obj({
            {"recipe_id",  int_()},
            {"name",       str()},
            {"call_count", int_()},
        }, {"recipe_id", "name", "call_count"}),
        /*requires_target=*/false, /*requires_stopped=*/false, "medium");

    add("recipe.list",
        "Enumerate every recipe known to this store, ascending id. "
        "Each entry is a summary — call recipe.get for the full body.",
        obj({}),
        obj({
            {"recipes", arr_of(recipe_summary_schema)},
            {"total",   int_()},
        }, {"recipes", "total"}),
        /*requires_target=*/false, /*requires_stopped=*/false, "low");

    add("recipe.get",
        "Full body of one recipe: parameters and calls, in storage "
        "order. The calls' params still carry the \"{slot}\" "
        "placeholders — substitution happens at recipe.run.",
        obj({{"recipe_id", int_()}}, {"recipe_id"}),
        obj({
            {"recipe_id",  int_()},
            {"name",       str()},
            {"description",str()},
            {"call_count", int_()},
            {"created_at", int_()},
            {"parameters", arr_of(recipe_param_schema)},
            {"calls",      arr_of(recipe_call_schema)},
        }, {"recipe_id", "name", "call_count", "parameters", "calls"}),
        /*requires_target=*/false, /*requires_stopped=*/false, "low");

    add("recipe.run",
        "Replay a recipe with caller-supplied parameter values. Each "
        "call is dispatched in storage order; on the FIRST error the "
        "run stops and returns responses up to and including the "
        "failure. responses[].seq is 1-based; responses[].method "
        "mirrors the recipe entry. A missing required parameter "
        "surfaces as ok=false with kInvalidParams BEFORE any RPC is "
        "dispatched.",
        obj({
            {"recipe_id",  int_()},
            {"parameters", obj_open(
                "Map of slot-name → value. Strings and integers are "
                "the only typed values supported in MVP.")},
        }, {"recipe_id"}),
        obj({
            {"responses", arr_of(obj({
                {"seq",    int_()},
                {"method", str()},
                {"ok",     bool_()},
                {"data",   obj_open()},
                {"error",  obj_open()},
            }, {"seq", "method", "ok"}))},
            {"total", int_()},
        }, {"responses", "total"}),
        /*requires_target=*/false, /*requires_stopped=*/false, "unbounded");

    add("recipe.delete",
        "Drop a recipe by id. Idempotent — deleting an already-gone "
        "recipe returns deleted=false (not an error). Equivalent to "
        "artifact.delete on the underlying recipe-v1 artifact, but "
        "with type-check that refuses non-recipe ids.",
        obj({{"recipe_id", int_()}}, {"recipe_id"}),
        obj({
            {"recipe_id", int_()},
            {"deleted",   bool_()},
        }, {"recipe_id", "deleted"}),
        /*requires_target=*/false, /*requires_stopped=*/false, "low");

    add("recipe.lint",
        "Validate a recipe's placeholder names against its declared parameter "
        "slots. Returns warnings for: (1) any {placeholder} string in a step's "
        "params that doesn't match any declared slot name (likely a typo — "
        "substitute_walk silently passes unknown placeholders through as "
        "literals); (2) any declared slot whose name never appears as a "
        "{placeholder} in any step (dead parameter). "
        "step_index is the 0-based call index; -1 for recipe-level warnings "
        "(unused slots). An empty warnings array means the recipe is clean.",
        obj({{"recipe_id", int_()}}, {"recipe_id"}),
        obj({
            {"recipe_id",    int_()},
            {"warning_count", int_()},
            {"warnings",     arr_of(obj({
                {"step_index", int_()},
                {"message",    str()},
            }, {}))},
        }, {"recipe_id", "warning_count", "warnings"}),
        /*requires_target=*/false, /*requires_stopped=*/false, "low");

    add("recipe.reload",
        "Re-read a recipe from its source file on disk and replace the "
        "store entry. Only valid for file-backed recipes — those imported "
        "via create_from_file or via the LDB_RECIPE_DIR startup scan. "
        "Recipes created in-band via recipe.create / recipe.from_session "
        "have no source_path and reject reload with -32003 forbidden. "
        "On a successful reload the artifact id changes (ArtifactStore's "
        "(build_id, name) collision rule replaces with a fresh id); the "
        "response surfaces both the new recipe_id and previous_recipe_id "
        "so agents can refresh their handle. Lint warnings are returned "
        "in the same shape as recipe.lint.",
        obj({{"recipe_id", int_()}}, {"recipe_id"}),
        obj({
            {"recipe_id",          int_()},
            {"previous_recipe_id", int_()},
            {"name",               str()},
            {"call_count",         int_()},
            {"warning_count",      int_()},
            {"warnings",           arr_of(obj({
                {"step_index", int_()},
                {"message",    str()},
            }, {}))},
            {"source_path",        str()},
        }, {"recipe_id", "warning_count", "warnings"}),
        /*requires_target=*/false, /*requires_stopped=*/false, "low");
  }

  // ============== probe.* ==============

  add("probe.create",
      "Create a probe — an auto-resuming probe with structured capture. "
      "kind = \"lldb_breakpoint\" (low-rate / app-level) OR \"uprobe_bpf\" "
      "(high-rate / syscall- and libc-level via bpftrace). action is one of "
      "log_and_continue (default), stop, store_artifact (lldb_breakpoint "
      "only). rate_limit is parsed but UNENFORCED.",
      obj({
          {"target_id",     optional_target_id_param()},
          {"kind",          enum_str({"lldb_breakpoint", "uprobe_bpf"})},
          {"where",         obj({
              {"function",   str()},
              {"address",    uint_()},
              {"file",       str()},
              {"line",       uint_()},
              {"uprobe",     str("PATH:SYMBOL")},
              {"tracepoint", str("CATEGORY:NAME")},
              {"kprobe",     str("FUNCTION_NAME")},
          })},
          {"capture", obj({
              {"registers", arr_of(str())},
              {"memory",    arr_of(obj({
                  {"reg", str()},
                  {"len", uint_()},
              }))},
              {"args", arr_of(str(), "bpftrace builtins like 'arg0'.")},
          })},
          {"action",        enum_str({"log_and_continue", "stop", "store_artifact"})},
          {"build_id",      str()},
          {"artifact_name", str()},
          {"rate_limit",    str("e.g. \"100/s\" — currently parsed but "
                                "UNENFORCED.")},
          {"host",          host_param()},
          {"filter_pid",    int_()},
      }, {"kind", "where"}),
      obj({
          {"probe_id", str()},
          {"kind",     str()},
      }, {"probe_id", "kind"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "medium");

  add("probe.events",
      "Pull captured events for a probe. since=N returns events with "
      "hit_seq > N (default 0 = all). max caps the page size. Events "
      "are oldest-first; next_since paginates.",
      obj({
          {"probe_id", str()},
          {"since",    uint_("Default 0 = all.")},
          {"max",      uint_("Default 0 = no cap.")},
      }, {"probe_id"}),
      obj({
          {"events", arr_of(obj({
              {"probe_id",      str()},
              {"hit_seq",       uint_()},
              {"ts_ns",         uint_()},
              {"tid",           uint_()},
              {"pc",            uint_()},
              {"registers",     obj_open()},
              {"memory",        arr_of(obj_open())},
              {"site",          obj_open()},
              {"artifact_id",   int_()},
              {"artifact_name", str()},
          }))},
          {"total",      uint_()},
          {"next_since", uint_()},
      }, {"events", "total", "next_since"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "unbounded");

  add("probe.list",
      "Enumerate every active probe with its kind, where, enabled state, "
      "and current hit_count.",
      obj({}),
      obj({
          {"probes", arr_of(obj({
              {"probe_id",   str()},
              {"kind",       str()},
              {"where_expr", str()},
              {"enabled",    bool_()},
              {"hit_count",  uint_()},
          }))},
          {"total", uint_()},
      }, {"probes", "total"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "low");

  add("probe.disable",
      "Disable a probe — the underlying breakpoint stays installed but "
      "won't fire until enabled again. hit_count is preserved.",
      obj({{"probe_id", str()}}, {"probe_id"}),
      obj({
          {"probe_id", str()},
          {"enabled",  bool_()},
      }, {"probe_id", "enabled"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "low");

  add("probe.enable",
      "Re-enable a previously-disabled probe.",
      obj({{"probe_id", str()}}, {"probe_id"}),
      obj({
          {"probe_id", str()},
          {"enabled",  bool_()},
      }, {"probe_id", "enabled"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "low");

  add("probe.delete",
      "Delete a probe entirely: removes the underlying breakpoint and drops "
      "the orchestrator's record. Captured events are lost.",
      obj({{"probe_id", str()}}, {"probe_id"}),
      obj({
          {"probe_id", str()},
          {"deleted",  bool_()},
      }, {"probe_id", "deleted"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "low");

  // ============== perf.* (post-V1 plan #13) ==============
  //
  // Sibling to probe.*; shells out to the system `perf` binary. Samples
  // are shaped to align with the BPF agent event schema #12 is landing
  // (ts_ns, tid, pid, cpu, stack: [{addr, sym, mod}]). See
  // docs/22-perf-integration.md.

  add("perf.record",
      "Spawn `perf record` against a pid or a fresh command and "
      "synchronously return the resulting perf.data artifact id plus "
      "parsed samples. Synchronous in phase 1 — duration_ms is capped "
      "at 300000 (5 min). Errors: perf missing, kernel.perf_event_paranoid "
      "too strict, target pid vanished, ArtifactStore not configured.",
      obj({
          {"pid",          int_("OS pid to sample; mutually exclusive "
                                "with `command`.")},
          {"command",      arr_of(str(), "argv to spawn + sample; "
                                          "mutually exclusive with `pid`.")},
          {"duration_ms",  uint_("Wall-clock duration. Required for pid "
                                  "mode; capped at 300000.")},
          {"frequency_hz", uint_("perf -F; default 99.")},
          {"events",       arr_of(str(), "perf -e; default [\"cycles\"].")},
          {"call_graph",   enum_str({"fp", "dwarf", "lbr"},
                                     "perf --call-graph; default \"fp\".")},
          {"build_id",     str("ArtifactStore key prefix for the perf.data "
                                "blob. Default \"_perf\".")},
      }),
      obj({
          {"artifact_id",   int_()},
          {"artifact_name", str()},
          {"sample_count",  uint_()},
          {"duration_ms",   uint_()},
          {"perf_argv",     arr_of(str())},
          {"stderr_tail",   str()},
          {"parse_errors",  arr_of(str(), "Non-fatal parse errors from "
                                           "the perf script ingestion. "
                                           "Empty on a clean trace.")},
      }, {"artifact_id", "artifact_name", "sample_count"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "high");

  add("perf.report",
      "Re-parse an existing perf.data artifact and return its samples. "
      "Lets the agent ask for a different stack depth or sample cap "
      "without re-recording.",
      obj({
          {"artifact_id",    int_()},
          {"max_samples",    uint_("Default 0 = no cap.")},
          {"max_stack_depth",uint_("Default 0 = no cap.")},
      }, {"artifact_id"}),
      obj({
          {"samples", arr_of(obj({
              {"ts_ns", int_()},
              {"tid",   uint_()},
              {"pid",   uint_()},
              {"cpu",   int_()},
              {"comm",  str()},
              {"event", str()},
              {"stack", arr_of(obj({
                  {"addr", str("Hex IP, e.g. \"0x412af0\".")},
                  {"sym",  str()},
                  {"mod",  str()},
              }))},
          }))},
          {"total",          uint_()},
          {"truncated",      bool_()},
          {"perf_data_size", uint_()},
          {"parse_errors",   arr_of(str())},
      }, {"samples", "total"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "high");

  add("perf.cancel",
      "Send SIGTERM to an in-flight perf.record subprocess. Phase 1: "
      "perf.record is synchronous so there is never an in-flight call; "
      "this endpoint exists for catalog completeness and returns "
      "-32002 kBadState until the async variant lands.",
      obj({{"record_id", str()}}, {"record_id"}),
      obj({
          {"record_id", str()},
          {"cancelled", bool_()},
      }, {"record_id", "cancelled"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "low");

  // ============== observer.* ==============

  add("observer.proc.fds",
      "Enumerate /proc/<pid>/fd of the target host. Each entry is the fd "
      "number, its readlink target, and a coarse type "
      "(socket|pipe|anon|file|other).",
      obj({
          {"pid",  pid_param()},
          {"host", host_param()},
      }, {"pid"}),
      obj({
          {"fds", arr_of(obj({
              {"fd",     uint_()},
              {"target", str()},
              {"type",   enum_str({"socket", "pipe", "anon", "file", "other"})},
          }))},
          {"total", uint_()},
      }, {"fds", "total"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "medium");

  add("observer.proc.maps",
      "Read /proc/<pid>/maps from the target host and return parsed regions.",
      obj({
          {"pid",  pid_param()},
          {"host", host_param()},
      }, {"pid"}),
      obj({
          {"regions", arr_of(obj({
              {"start",  uint_()},
              {"end",    uint_()},
              {"perm",   str()},
              {"offset", uint_()},
              {"dev",    str()},
              {"inode",  uint_()},
              {"path",   str()},
          }))},
          {"total", uint_()},
      }, {"regions", "total"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "high");

  add("observer.proc.status",
      "Read /proc/<pid>/status from the target host and return a parsed "
      "subset (name, pid, ppid, state, uid, gid, threads, vm_rss_kb?, etc).",
      obj({
          {"pid",  pid_param()},
          {"host", host_param()},
      }, {"pid"}),
      obj({
          {"name",       str()},
          {"pid",        int_()},
          {"ppid",       int_()},
          {"state",      str()},
          {"uid",        uint_()},
          {"gid",        uint_()},
          {"threads",    uint_()},
          {"vm_rss_kb",  uint_()},
          {"vm_size_kb", uint_()},
          {"vm_peak_kb", uint_()},
          {"fd_size",    uint_()},
          {"raw_fields", arr_of(obj({
              {"key",   str()},
              {"value", str()},
          }))},
      }, {"name", "state", "raw_fields"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "medium");

  add("observer.net.sockets",
      "Run `ss -tunap` on the target host and return parsed socket rows. "
      "`filter` is applied POST-PARSE — never passed to ss.",
      obj({
          {"host",   host_param()},
          {"filter", str("Substring against \"<proto> <local> <peer> "
                         "<state>\".")},
      }),
      obj({
          {"sockets", arr_of(obj({
              {"proto", str()},
              {"state", str()},
              {"local", str()},
              {"peer",  str()},
              {"pid",   int_()},
              {"comm",  str()},
              {"fd",    int_()},
          }))},
          {"total", uint_()},
      }, {"sockets", "total"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "medium");

  add("observer.net.tcpdump",
      "Bounded one-shot live capture: spawn "
      "`tcpdump -nn -tt -l -c <count> -i <iface> -s <snaplen> [bpf]`. "
      "Permission errors surface as -32000 with the underlying tcpdump "
      "stderr. count ≤ 10000, snaplen ≤ 65535.",
      obj({
          {"iface",   str("Interface name (lo, eth0, any).")},
          {"count",   uint_range(1, 10000)},
          {"bpf",     str("Optional BPF filter expression.")},
          {"snaplen", uint_range(1, 65535)},
          {"host",    host_param()},
      }, {"iface", "count"}),
      obj({
          {"packets", arr_of(obj({
              {"ts",      str()},
              {"summary", str()},
              {"iface",   str()},
              {"src",     str()},
              {"dst",     str()},
              {"proto",   str()},
              {"len",     uint_()},
          }))},
          {"total",     uint_()},
          {"truncated", bool_()},
      }, {"packets", "total", "truncated"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "unbounded");

  add("observer.net.igmp",
      "Read /proc/net/igmp (and /proc/net/igmp6 if present) on the "
      "target host and return parsed multicast memberships. V4 group hex "
      "is converted to dotted-quad; V6 is rendered as 8 colon-separated "
      "4-hex-char groups (no zero-compression).",
      obj({{"host", host_param()}}),
      obj({
          {"groups", arr_of(obj({
              {"idx",       uint_()},
              {"device",    str()},
              {"count",     uint_()},
              {"querier",   str()},
              {"addresses", arr_of(obj({
                  {"address", str()},
                  {"users",   uint_()},
                  {"timer",   uint_()},
              }))},
          }))},
          {"total", uint_()},
      }, {"groups", "total"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "low");

  add("observer.exec",
      "Operator-allowlisted exec escape hatch (plan §4.6). OFF by "
      "default: returns -32002 unless the daemon was launched with "
      "--observer-exec-allowlist <path> or LDB_OBSERVER_EXEC_ALLOWLIST. "
      "argv[0] MUST be an absolute path or a bare basename on PATH; "
      "stdin payload is capped at 64 KiB.",
      obj({
          {"argv",       arr_of(str())},
          {"host",       host_param()},
          {"timeout_ms", uint_("Default daemon-configured.")},
          {"stdin",      str("UTF-8 stdin payload, capped at 64 KiB.")},
      }, {"argv"}),
      obj({
          {"stdout",      str()},
          {"stderr",      str()},
          {"exit_code",   int_()},
          {"duration_ms", uint_()},
          {"truncated",   bool_()},
      }, {"stdout", "stderr", "exit_code", "duration_ms"}),
      /*requires_target=*/false, /*requires_stopped=*/false, "high");

  // View descriptors (M5 part 4): `params.view = {fields, limit,
  // offset, summary}` lets the agent / `ldb` CLI ask for a projected
  // and/or sliced catalog. Without a view, we still go through
  // apply_to_array — it preserves the array under the `endpoints` key
  // and adds a `total` count, which is strictly informative.
  protocol::view::Spec view_spec;
  try {
    view_spec = protocol::view::parse_from_params(req.params);
  } catch (const std::invalid_argument& e) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams, e.what());
  }
  return protocol::make_ok(req.id,
      protocol::view::apply_to_array(std::move(eps), view_spec, "endpoints"));
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

Response Dispatcher::handle_target_connect_remote(const Request& req) {
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::uint64_t tid = 0;
  if (!require_uint(req.params, "target_id", &tid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }
  const auto* url = require_string(req.params, "url");
  if (!url) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing string param 'url'");
  }
  // plugin is optional; default empty → backend uses "gdb-remote".
  std::string plugin;
  if (auto it = req.params.find("plugin");
      it != req.params.end() && it->is_string()) {
    plugin = it->get<std::string>();
  }

  try {
    auto status = backend_->connect_remote_target(
        static_cast<backend::TargetId>(tid), *url, plugin);
    return protocol::make_ok(req.id, process_status_to_json(status));
  } catch (const backend::Error& e) {
    // "does not support" → -32003 forbidden so agents can branch
    // backends cleanly (e.g. fall back to --backend=lldb on rr://
    // URLs the gdb backend rejects).
    const std::string what = e.what();
    if (what.find("does not support") != std::string::npos) {
      return protocol::make_err(req.id, ErrorCode::kForbidden, what);
    }
    return protocol::make_err(req.id, ErrorCode::kBackendError, what);
  }
}

Response Dispatcher::handle_target_connect_remote_ssh(const Request& req) {
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::uint64_t tid = 0;
  if (!require_uint(req.params, "target_id", &tid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }
  const auto* host = require_string(req.params, "host");
  if (!host || host->empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing string param 'host'");
  }
  const auto* inferior_path = require_string(req.params, "inferior_path");
  if (!inferior_path || inferior_path->empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing string param 'inferior_path'");
  }

  backend::ConnectRemoteSshOptions opts;
  opts.host          = *host;
  opts.inferior_path = *inferior_path;

  if (auto it = req.params.find("port");
      it != req.params.end() && it->is_number_integer()) {
    auto v = it->get<std::int64_t>();
    if (v < 0 || v > 65535) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "param 'port' out of range");
    }
    opts.port = static_cast<int>(v);
  }
  if (auto it = req.params.find("ssh_options");
      it != req.params.end() && it->is_array()) {
    for (const auto& e : *it) {
      if (!e.is_string()) {
        return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                  "param 'ssh_options' must be array of strings");
      }
      opts.ssh_options.push_back(e.get<std::string>());
    }
  }
  if (auto it = req.params.find("remote_lldb_server");
      it != req.params.end() && it->is_string()) {
    opts.remote_lldb_server = it->get<std::string>();
  }
  if (auto it = req.params.find("inferior_argv");
      it != req.params.end() && it->is_array()) {
    for (const auto& e : *it) {
      if (!e.is_string()) {
        return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                  "param 'inferior_argv' must be array of strings");
      }
      opts.inferior_argv.push_back(e.get<std::string>());
    }
  }
  std::uint64_t timeout_ms = 0;
  if (require_uint(req.params, "setup_timeout_ms", &timeout_ms) && timeout_ms > 0) {
    opts.setup_timeout = std::chrono::milliseconds(timeout_ms);
  }

  try {
    auto result = backend_->connect_remote_target_ssh(
        static_cast<backend::TargetId>(tid), opts);
    json data = process_status_to_json(result.status);
    data["target_id"]         = tid;
    data["local_tunnel_port"] = result.local_tunnel_port;
    return protocol::make_ok(req.id, std::move(data));
  } catch (const backend::Error& e) {
    const std::string what = e.what();
    if (what.find("does not support") != std::string::npos) {
      return protocol::make_err(req.id, ErrorCode::kForbidden, what);
    }
    return protocol::make_err(req.id, ErrorCode::kBackendError, what);
  }
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

Response Dispatcher::handle_process_save_core(const Request& req) {
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::uint64_t tid = 0;
  if (!require_uint(req.params, "target_id", &tid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }
  const auto* path = require_string(req.params, "path");
  if (!path) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing string param 'path'");
  }
  bool ok = backend_->save_core(static_cast<backend::TargetId>(tid), *path);
  return protocol::make_ok(req.id, json{{"saved", ok}, {"path", *path}});
}

Response Dispatcher::handle_target_load_core(const Request& req) {
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  const auto* path = require_string(req.params, "path");
  if (!path) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing string param 'path'");
  }
  auto res = backend_->load_core(*path);
  json data;
  data["target_id"] = res.target_id;
  data["triple"]    = res.triple;
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

Response Dispatcher::handle_target_list(const Request& req) {
  // params is optional (only carries `view`); accept null/missing as
  // empty-object equivalent. view::parse_from_params already tolerates
  // a non-object input.
  auto view_spec = protocol::view::parse_from_params(req.params);
  auto infos = backend_->list_targets();

  json arr = json::array();
  for (const auto& t : infos) {
    json j;
    j["target_id"]   = t.target_id;
    j["triple"]      = t.triple;
    if (!t.path.empty()) j["path"] = t.path;
    if (t.label.has_value()) j["label"] = *t.label;
    j["has_process"] = t.has_process;
    // Best-effort snapshot string. snapshot_for_target is documented as
    // never-throw; the dispatcher already calls it on every successful
    // response for `_provenance.snapshot`. Cheap to compute here too.
    auto snap = backend_->snapshot_for_target(t.target_id);
    if (!snap.empty()) j["snapshot"] = std::move(snap);
    arr.push_back(std::move(j));
  }
  return protocol::make_ok(req.id,
      protocol::view::apply_to_array(std::move(arr), view_spec, "targets"));
}

Response Dispatcher::handle_target_label(const Request& req) {
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::uint64_t tid = 0;
  if (!require_uint(req.params, "target_id", &tid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }
  const auto* label = require_string(req.params, "label");
  if (!label || label->empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing non-empty string param 'label'");
  }
  // Conflict (label already taken by another target) is the
  // documented -32602 path — translate the backend's typed Error into
  // kInvalidParams so the agent can branch on "label collision" without
  // string-matching the message. Truly unknown target_id stays
  // -32000 (handled by the outer catch).
  try {
    backend_->label_target(static_cast<backend::TargetId>(tid), *label);
  } catch (const backend::Error& e) {
    std::string msg = e.what();
    if (msg.find("already taken") != std::string::npos ||
        msg.find("must be non-empty") != std::string::npos) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams, msg);
    }
    throw;
  }
  json data;
  data["target_id"] = tid;
  data["label"]     = *label;
  return protocol::make_ok(req.id, std::move(data));
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

  // Post-V1 plan #5 — diff against a prior snapshot's cached array.
  std::string snapshot = backend_->snapshot_for_target(
      static_cast<backend::TargetId>(tid));
  bool diff_applied = false;
  bool baseline_missing = false;
  if (!snapshot.empty()) {
    diff_cache_put(diff_cache_key("module.list", req.params, snapshot), arr);
  }
  if (view_spec.diff_against.has_value()) {
    diff_applied = true;
    auto baseline = diff_cache_get(diff_cache_key("module.list", req.params,
                                                  *view_spec.diff_against));
    if (baseline.has_value()) {
      arr = protocol::view::compute_diff(*baseline, arr);
    } else {
      baseline_missing = true;
    }
  }

  json data = protocol::view::apply_to_array(std::move(arr), view_spec,
                                             "modules");
  if (diff_applied) {
    data["diff_against"] = *view_spec.diff_against;
    data["diff_baseline_missing"] = baseline_missing;
  }
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_thread_list(const Request& req) {
  std::uint64_t tid = 0;
  if (!req.params.is_object() || !require_uint(req.params, "target_id", &tid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }
  auto view_spec = protocol::view::parse_from_params(req.params);
  auto threads = backend_->list_threads(static_cast<backend::TargetId>(tid));
  json arr = json::array();
  for (const auto& t : threads) arr.push_back(thread_info_to_json(t));

  std::string snapshot = backend_->snapshot_for_target(
      static_cast<backend::TargetId>(tid));
  bool diff_applied = false;
  bool baseline_missing = false;
  if (!snapshot.empty()) {
    diff_cache_put(diff_cache_key("thread.list", req.params, snapshot), arr);
  }
  if (view_spec.diff_against.has_value()) {
    diff_applied = true;
    auto baseline = diff_cache_get(diff_cache_key("thread.list", req.params,
                                                  *view_spec.diff_against));
    if (baseline.has_value()) {
      arr = protocol::view::compute_diff(*baseline, arr);
    } else {
      baseline_missing = true;
    }
  }

  json data = protocol::view::apply_to_array(std::move(arr), view_spec,
                                             "threads");
  if (diff_applied) {
    data["diff_against"] = *view_spec.diff_against;
    data["diff_baseline_missing"] = baseline_missing;
  }
  return protocol::make_ok(req.id, std::move(data));
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
  auto view_spec = protocol::view::parse_from_params(req.params);
  auto frames = backend_->list_frames(
      static_cast<backend::TargetId>(target_id),
      static_cast<backend::ThreadId>(tid),
      static_cast<std::uint32_t>(depth));
  json arr = json::array();
  for (const auto& f : frames) arr.push_back(frame_info_to_json(f));
  return protocol::make_ok(req.id,
      protocol::view::apply_to_array(std::move(arr), view_spec, "frames"));
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

Response Dispatcher::handle_value_eval(const Request& req) {
  FrameParams p;
  if (auto err = parse_frame_params(req, &p)) return *err;
  const auto* expr = require_string(req.params, "expr");
  if (!expr) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing string param 'expr'");
  }
  backend::EvalOptions opts;
  if (auto it = req.params.find("timeout_us"); it != req.params.end()) {
    std::uint64_t to = 0;
    if (!require_uint(req.params, "timeout_us", &to)) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'timeout_us' must be a non-negative integer");
    }
    if (to > 0) opts.timeout_us = to;
  }

  auto result = backend_->evaluate_expression(
      static_cast<backend::TargetId>(p.target_id),
      static_cast<backend::ThreadId>(p.tid),
      p.frame_index, *expr, opts);

  json data;
  if (result.ok) {
    data["value"] = value_info_to_json(result.value);
  } else {
    data["error"] = result.error;
  }
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_value_read(const Request& req) {
  FrameParams p;
  if (auto err = parse_frame_params(req, &p)) return *err;
  const auto* path = require_string(req.params, "path");
  if (!path) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing string param 'path'");
  }

  auto result = backend_->read_value_path(
      static_cast<backend::TargetId>(p.target_id),
      static_cast<backend::ThreadId>(p.tid),
      p.frame_index, *path);

  json data;
  if (result.ok) {
    data["value"] = value_info_to_json(result.value);
    if (!result.children.empty()) {
      json arr = json::array();
      for (const auto& c : result.children) {
        arr.push_back(value_info_to_json(c));
      }
      data["children"] = std::move(arr);
    }
  } else {
    data["error"] = result.error;
  }
  return protocol::make_ok(req.id, std::move(data));
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
  // Optional `tid` (Tier 4 §14, scoped slice). When present, route to
  // the per-thread continue path. In v0.3 this is a sync passthrough
  // into continue_process — see backend::DebuggerBackend::continue_thread
  // and docs/11-non-stop.md for the runtime-vs-protocol gap.
  std::uint64_t thread_id = 0;
  bool have_tid = require_uint(req.params, "tid", &thread_id);
  backend::ProcessStatus status =
      have_tid
          ? backend_->continue_thread(static_cast<backend::TargetId>(tid),
                                      static_cast<backend::ThreadId>(thread_id))
          : backend_->continue_process(static_cast<backend::TargetId>(tid));
  return protocol::make_ok(req.id, process_status_to_json(status));
}

Response Dispatcher::handle_thread_continue(const Request& req) {
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::uint64_t target_id = 0;
  if (!require_uint(req.params, "target_id", &target_id)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }
  std::uint64_t thread_id = 0;
  if (!require_uint(req.params, "tid", &thread_id)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'tid'");
  }
  // Tier 4 §14: explicit per-thread resume. v0.3 sync passthrough —
  // resumes the whole process. See docs/11-non-stop.md.
  auto status = backend_->continue_thread(
      static_cast<backend::TargetId>(target_id),
      static_cast<backend::ThreadId>(thread_id));
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

namespace {
bool parse_step_kind(const std::string& s, backend::StepKind* out) {
  if (s == "in")   { *out = backend::StepKind::kIn;   return true; }
  if (s == "over") { *out = backend::StepKind::kOver; return true; }
  if (s == "out")  { *out = backend::StepKind::kOut;  return true; }
  if (s == "insn") { *out = backend::StepKind::kInsn; return true; }
  return false;
}
}  // namespace

Response Dispatcher::handle_process_step(const Request& req) {
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
  const auto* kind_str = require_string(req.params, "kind");
  if (!kind_str) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing string param 'kind'");
  }
  backend::StepKind kind;
  if (!parse_step_kind(*kind_str, &kind)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "'kind' must be one of: in, over, out, insn");
  }

  auto status = backend_->step_thread(
      static_cast<backend::TargetId>(target_id),
      static_cast<backend::ThreadId>(tid),
      kind);

  // Spec response: {state, stop_reason?, pc?}. We preserve pid since
  // every other process.* endpoint emits it (consistency wins for
  // agents); pc is the innermost frame's PC of the stepped thread,
  // populated only when the post-step state is stopped.
  json data = process_status_to_json(status);
  if (status.state == backend::ProcessState::kStopped) {
    auto threads = backend_->list_threads(
        static_cast<backend::TargetId>(target_id));
    for (const auto& t : threads) {
      if (t.tid == tid) {
        data["pc"] = t.pc;
        break;
      }
    }
  }
  return protocol::make_ok(req.id, std::move(data));
}

namespace {

// Reverse-step kind parser. All four kinds are accepted by the
// backend; "insn" is the RSP `bs` packet verbatim, "in"/"over"/"out"
// use a bounded `bs` loop with source-line + frame-depth checks
// (see LldbBackend::reverse_step_thread).
bool parse_reverse_step_kind(const std::string& s,
                             backend::ReverseStepKind* out) {
  if (s == "in")   { *out = backend::ReverseStepKind::kIn;   return true; }
  if (s == "over") { *out = backend::ReverseStepKind::kOver; return true; }
  if (s == "out")  { *out = backend::ReverseStepKind::kOut;  return true; }
  if (s == "insn") { *out = backend::ReverseStepKind::kInsn; return true; }
  return false;
}

// Map a backend::Error from a reverse-exec call to a JSON-RPC error
// code. Inspects the message text since backend::Error doesn't carry a
// kind enum.
Response reverse_exec_error_to_resp(const std::optional<json>& id,
                                    const ldb::backend::Error& e) {
  const std::string what = e.what();
  if (what.find("does not support reverse execution") != std::string::npos) {
    return protocol::make_err(id, ErrorCode::kForbidden, what);
  }
  if (what.find("not stopped") != std::string::npos ||
      what.find("no process") != std::string::npos) {
    return protocol::make_err(id, ErrorCode::kBadState, what);
  }
  if (what.find("kind not supported") != std::string::npos) {
    return protocol::make_err(id, ErrorCode::kInvalidParams, what);
  }
  return protocol::make_err(id, ErrorCode::kBackendError, what);
}

}  // namespace

Response Dispatcher::handle_process_reverse_continue(const Request& req) {
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::uint64_t target_id = 0;
  if (!require_uint(req.params, "target_id", &target_id)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }
  try {
    auto status = backend_->reverse_continue(
        static_cast<backend::TargetId>(target_id));
    return protocol::make_ok(req.id, process_status_to_json(status));
  } catch (const ldb::backend::Error& e) {
    return reverse_exec_error_to_resp(req.id, e);
  }
}

// Shared body for process.reverse_step and thread.reverse_step. The two
// endpoints differ only in their wire name; both take {target_id, tid,
// kind} and route to backend::reverse_step_thread. The split mirrors
// the existing process.continue / thread.continue pair (Tier 4 §14).
namespace {
Response handle_reverse_step_shared(
    std::shared_ptr<backend::DebuggerBackend> backend,
    const Request& req) {
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
  const auto* kind_str = require_string(req.params, "kind");
  if (!kind_str) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing string param 'kind'");
  }
  backend::ReverseStepKind kind;
  if (!parse_reverse_step_kind(*kind_str, &kind)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
        "'kind' must be one of: in, over, out, insn");
  }
  try {
    auto status = backend->reverse_step_thread(
        static_cast<backend::TargetId>(target_id),
        static_cast<backend::ThreadId>(tid),
        kind);
    json data = process_status_to_json(status);
    if (status.state == backend::ProcessState::kStopped) {
      auto threads = backend->list_threads(
          static_cast<backend::TargetId>(target_id));
      for (const auto& t : threads) {
        if (t.tid == tid) {
          data["pc"] = t.pc;
          break;
        }
      }
    }
    return protocol::make_ok(req.id, std::move(data));
  } catch (const ldb::backend::Error& e) {
    return reverse_exec_error_to_resp(req.id, e);
  }
}
}  // namespace

Response Dispatcher::handle_process_reverse_step(const Request& req) {
  return handle_reverse_step_shared(backend_, req);
}

Response Dispatcher::handle_thread_reverse_step(const Request& req) {
  return handle_reverse_step_shared(backend_, req);
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

  auto view_spec = protocol::view::parse_from_params(req.params);
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
  return protocol::make_ok(req.id,
      protocol::view::apply_to_array(std::move(arr), view_spec, "results"));
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
  auto view_spec = protocol::view::parse_from_params(req.params);
  auto refs = backend_->xref_address(
      static_cast<backend::TargetId>(tid), addr);
  json arr = json::array();
  for (const auto& r : refs) arr.push_back(xref_match_to_json(r));
  return protocol::make_ok(req.id,
      protocol::view::apply_to_array(std::move(arr), view_spec, "matches"));
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

  auto view_spec = protocol::view::parse_from_params(req.params);
  auto insns = backend_->disassemble_range(
      static_cast<backend::TargetId>(tid), start, end);
  json arr = json::array();
  for (const auto& i : insns) arr.push_back(disasm_insn_to_json(i));
  return protocol::make_ok(req.id,
      protocol::view::apply_to_array(std::move(arr), view_spec,
                                     "instructions"));
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
  // Apply view to the instructions array so large functions can be
  // paged or projected. The wrapping object also gets a "total" /
  // "next_offset" / "summary" — at the cost of a slightly different
  // wire shape from the bare {instructions:[]} when no view is given.
  // Empty Spec still emits "total"; agents can rely on it.
  auto view_spec = protocol::view::parse_from_params(req.params);
  json arr = json::array();
  for (const auto& i : insns) arr.push_back(disasm_insn_to_json(i));
  json paged = protocol::view::apply_to_array(
      std::move(arr), view_spec, "instructions");
  data["instructions"]      = std::move(paged["instructions"]);
  data["total"]             = paged["total"];
  if (paged.contains("next_offset")) data["next_offset"] = paged["next_offset"];
  if (paged.contains("summary"))     data["summary"]     = paged["summary"];
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

  auto view_spec = protocol::view::parse_from_params(req.params);
  auto strings = backend_->find_strings(
      static_cast<backend::TargetId>(tid), q);
  json arr = json::array();
  for (const auto& s : strings) arr.push_back(string_match_to_json(s));
  return protocol::make_ok(req.id,
      protocol::view::apply_to_array(std::move(arr), view_spec, "strings"));
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

  auto view_spec = protocol::view::parse_from_params(req.params);
  auto matches = backend_->find_symbols(
      static_cast<backend::TargetId>(tid), q);
  json arr = json::array();
  for (const auto& m : matches) arr.push_back(symbol_match_to_json(m));
  return protocol::make_ok(req.id,
      protocol::view::apply_to_array(std::move(arr), view_spec, "matches"));
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

    // DWARF-consistency check (papercut #4): some toolchains emit a
    // byte_size that is smaller than the end of one or more fields.
    // Observed on a real cffex_server core dump where g++ -O2 produced
    // a CSeatInfo whose three trailing std::vector members were
    // recorded at offsets > byte_size. Don't error — surface a
    // human-readable warning so the agent can branch on it. Computed
    // before any view/paging mutates the field array.
    json warnings = json::array();
    {
      const auto& flds = layout->fields;
      std::uint64_t max_end = 0;
      const backend::Field* worst = nullptr;
      for (const auto& f : flds) {
        std::uint64_t end = f.offset + f.byte_size;
        if (end > max_end) { max_end = end; worst = &f; }
      }
      if (worst != nullptr && max_end > layout->byte_size) {
        std::string msg = "DWARF inconsistency: field '" + worst->name +
            "' end (off=" + std::to_string(worst->offset) +
            "+sz=" + std::to_string(worst->byte_size) +
            "=" + std::to_string(max_end) +
            ") exceeds type byte_size=" + std::to_string(layout->byte_size) +
            "; layout may be unreliable, cross-check against the binary "
            "(e.g. allocator size in the ctor or member access disasm).";
        warnings.push_back(std::move(msg));
      }
    }

    json layout_j = type_layout_to_json(*layout);
    // Apply view (fields, limit, offset, summary) to the layout's
    // fields array. Useful for projecting big structs to just
    // {name, off, sz}, or for paging huge unions.
    auto view_spec = protocol::view::parse_from_params(req.params);
    json paged = protocol::view::apply_to_array(
        std::move(layout_j["fields"]), view_spec, "fields");
    layout_j["fields"]            = std::move(paged["fields"]);
    layout_j["fields_total"]      = paged["total"];
    if (paged.contains("next_offset"))
      layout_j["fields_next_offset"] = paged["next_offset"];
    if (paged.contains("summary"))
      layout_j["fields_summary"]     = paged["summary"];
    data["layout"] = std::move(layout_j);
    if (!warnings.empty()) {
      data["warnings"] = std::move(warnings);
    }
  } else {
    data["found"]  = false;
  }
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_static_globals_of_type(const Request& req) {
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::uint64_t tid = 0;
  if (!require_uint(req.params, "target_id", &tid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }
  const auto* type_name = require_string(req.params, "type_name");
  if (!type_name) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing string param 'type_name'");
  }
  if (type_name->empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "'type_name' must be non-empty");
  }

  auto view_spec = protocol::view::parse_from_params(req.params);

  bool strict = false;
  auto matches = backend_->find_globals_of_type(
      static_cast<backend::TargetId>(tid), *type_name, strict);

  // Cap-aware truncation hint. The cap value is wired through the
  // backend; matching the constant here would couple the dispatcher to
  // the backend cap, so we surface it via the result-size threshold.
  bool truncated = matches.size() >= backend::kGlobalsOfTypeMaxMatches;

  json arr = json::array();
  for (const auto& g : matches) arr.push_back(global_var_match_to_json(g));

  json data = protocol::view::apply_to_array(
      std::move(arr), view_spec, "globals");
  data["type_match_strict"] = strict;
  if (truncated) data["truncated"] = true;
  return protocol::make_ok(req.id, std::move(data));
}

// --- correlate.* (Tier 3 §10, scoped) --------------------------------------
//
// Pure dispatcher composition over per-target primitives. The shared
// preflight extracts a deduped target_ids list and validates each id
// against the live target table; we surface the offending id so the
// agent can branch without string-matching the message.

namespace {

// Parse + validate `target_ids` as a non-empty array of uint64. Stable
// dedupe: preserves first-occurrence order so per-result rows come back
// in the order the caller requested. Returns nullopt on a structural
// error and writes the wire-shaped error message into `*err_msg`.
std::optional<std::vector<std::uint64_t>>
parse_target_ids(const json& params, std::string* err_msg) {
  auto it = params.find("target_ids");
  if (it == params.end() || !it->is_array()) {
    *err_msg = "missing array param 'target_ids'";
    return std::nullopt;
  }
  if (it->empty()) {
    *err_msg = "'target_ids' must be a non-empty array";
    return std::nullopt;
  }
  std::vector<std::uint64_t> out;
  out.reserve(it->size());
  std::set<std::uint64_t> seen;
  for (const auto& el : *it) {
    std::uint64_t v = 0;
    if (el.is_number_unsigned()) {
      v = el.get<std::uint64_t>();
    } else if (el.is_number_integer()) {
      auto s = el.get<std::int64_t>();
      if (s < 0) {
        *err_msg = "'target_ids' entries must be non-negative integers";
        return std::nullopt;
      }
      v = static_cast<std::uint64_t>(s);
    } else {
      *err_msg = "'target_ids' entries must be integers";
      return std::nullopt;
    }
    if (seen.insert(v).second) out.push_back(v);
  }
  return out;
}

// Validate that every id in `ids` corresponds to an open target. On the
// first miss returns the offender; nullopt on success.
std::optional<std::uint64_t>
first_unknown_target_id(backend::DebuggerBackend& be,
                        const std::vector<std::uint64_t>& ids) {
  // Snapshot current open targets once (cheaper than O(N×M) backend
  // calls for a 2-target case but the call is trivial either way).
  auto infos = be.list_targets();
  std::set<std::uint64_t> open;
  for (const auto& t : infos) open.insert(t.target_id);
  for (auto id : ids) {
    if (open.find(id) == open.end()) return id;
  }
  return std::nullopt;
}

// drift_reason priority: byte_size > alignment > fields_count >
// field_offsets > field_types. First difference wins; ordering is
// deterministic so tests don't depend on hash iteration order.
std::optional<std::string>
detect_drift_reason(const std::vector<backend::TypeLayout>& found) {
  if (found.size() < 2) return std::nullopt;
  const auto& base = found.front();
  for (std::size_t i = 1; i < found.size(); ++i) {
    const auto& other = found[i];
    if (other.byte_size != base.byte_size) return "byte_size";
  }
  for (std::size_t i = 1; i < found.size(); ++i) {
    const auto& other = found[i];
    if (other.alignment != base.alignment) return "alignment";
  }
  for (std::size_t i = 1; i < found.size(); ++i) {
    const auto& other = found[i];
    if (other.fields.size() != base.fields.size()) return "fields_count";
  }
  for (std::size_t i = 1; i < found.size(); ++i) {
    const auto& other = found[i];
    for (std::size_t k = 0; k < base.fields.size(); ++k) {
      if (other.fields[k].offset != base.fields[k].offset ||
          other.fields[k].byte_size != base.fields[k].byte_size ||
          other.fields[k].name != base.fields[k].name) {
        return "field_offsets";
      }
    }
  }
  for (std::size_t i = 1; i < found.size(); ++i) {
    const auto& other = found[i];
    for (std::size_t k = 0; k < base.fields.size(); ++k) {
      if (other.fields[k].type_name != base.fields[k].type_name) {
        return "field_types";
      }
    }
  }
  return std::nullopt;
}

}  // namespace

Response Dispatcher::handle_correlate_types(const Request& req) {
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::string err;
  auto ids = parse_target_ids(req.params, &err);
  if (!ids.has_value()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams, err);
  }
  const auto* name = require_string(req.params, "name");
  if (!name) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing string param 'name'");
  }
  if (auto bad = first_unknown_target_id(*backend_, *ids); bad.has_value()) {
    return protocol::make_err(
        req.id, ErrorCode::kInvalidParams,
        "unknown target_id: " + std::to_string(*bad));
  }

  json results = json::array();
  std::vector<backend::TypeLayout> found_set;
  found_set.reserve(ids->size());

  for (auto tid : *ids) {
    json row;
    row["target_id"] = tid;
    try {
      auto layout = backend_->find_type_layout(
          static_cast<backend::TargetId>(tid), *name);
      if (layout.has_value()) {
        row["status"] = "found";
        row["layout"] = type_layout_to_json(*layout);
        found_set.push_back(std::move(*layout));
      } else {
        row["status"] = "missing";
        row["layout"] = nullptr;
      }
    } catch (const backend::Error& e) {
      // backend exception is data, not transport-level: per-target
      // failures shouldn't poison the whole batch.
      row["status"] = "backend_error";
      row["layout"] = nullptr;
      row["error"]  = std::string(e.what());
    }
    results.push_back(std::move(row));
  }

  auto drift_reason = detect_drift_reason(found_set);
  json data;
  auto view_spec = protocol::view::parse_from_params(req.params);
  json paged = protocol::view::apply_to_array(
      std::move(results), view_spec, "results");
  data["results"] = std::move(paged["results"]);
  data["total"]   = paged["total"];
  if (paged.contains("next_offset")) data["next_offset"] = paged["next_offset"];
  if (paged.contains("summary"))     data["summary"]     = paged["summary"];
  data["drift"]   = drift_reason.has_value();
  if (drift_reason.has_value()) data["drift_reason"] = *drift_reason;
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_correlate_symbols(const Request& req) {
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::string err;
  auto ids = parse_target_ids(req.params, &err);
  if (!ids.has_value()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams, err);
  }
  const auto* name = require_string(req.params, "name");
  if (!name) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing string param 'name'");
  }
  if (auto bad = first_unknown_target_id(*backend_, *ids); bad.has_value()) {
    return protocol::make_err(
        req.id, ErrorCode::kInvalidParams,
        "unknown target_id: " + std::to_string(*bad));
  }

  json results = json::array();
  std::int64_t total = 0;
  backend::SymbolQuery q;
  q.name = *name;
  q.kind = backend::SymbolKind::kAny;

  for (auto tid : *ids) {
    json row;
    row["target_id"] = tid;
    json arr = json::array();
    auto matches = backend_->find_symbols(
        static_cast<backend::TargetId>(tid), q);
    for (const auto& m : matches) arr.push_back(symbol_match_to_json(m));
    total += static_cast<std::int64_t>(arr.size());
    row["matches"] = std::move(arr);
    results.push_back(std::move(row));
  }

  json data;
  auto view_spec = protocol::view::parse_from_params(req.params);
  json paged = protocol::view::apply_to_array(
      std::move(results), view_spec, "results");
  data["results"] = std::move(paged["results"]);
  // Override the view's per-page total with the cross-target sum so
  // agents can size aggregates without iterating.
  data["total"]   = total;
  if (paged.contains("next_offset")) data["next_offset"] = paged["next_offset"];
  if (paged.contains("summary"))     data["summary"]     = paged["summary"];
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_correlate_strings(const Request& req) {
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::string err;
  auto ids = parse_target_ids(req.params, &err);
  if (!ids.has_value()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams, err);
  }
  const auto* text = require_string(req.params, "text");
  if (!text) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing string param 'text'");
  }
  if (auto bad = first_unknown_target_id(*backend_, *ids); bad.has_value()) {
    return protocol::make_err(
        req.id, ErrorCode::kInvalidParams,
        "unknown target_id: " + std::to_string(*bad));
  }

  json results = json::array();
  std::int64_t total = 0;

  for (auto tid : *ids) {
    json row;
    row["target_id"] = tid;
    json callsites = json::array();
    auto sxrs = backend_->find_string_xrefs(
        static_cast<backend::TargetId>(tid), *text);
    // Flatten across all matching string instances in this target.
    // XrefMatch carries function name; file/line are not in scope for
    // the v0.3 slice (XrefMatch doesn't surface them — defer to
    // future work that resolves SBLineEntry per address).
    for (const auto& r : sxrs) {
      for (const auto& x : r.xrefs) {
        json c;
        c["addr"] = x.address;
        if (!x.function.empty()) c["function"] = x.function;
        callsites.push_back(std::move(c));
      }
    }
    total += static_cast<std::int64_t>(callsites.size());
    row["callsites"] = std::move(callsites);
    results.push_back(std::move(row));
  }

  json data;
  auto view_spec = protocol::view::parse_from_params(req.params);
  json paged = protocol::view::apply_to_array(
      std::move(results), view_spec, "results");
  data["results"] = std::move(paged["results"]);
  data["total"]   = total;
  if (paged.contains("next_offset")) data["next_offset"] = paged["next_offset"];
  if (paged.contains("summary"))     data["summary"]     = paged["summary"];
  return protocol::make_ok(req.id, std::move(data));
}

// --- artifact.* ------------------------------------------------------------

namespace {
// Common preflight for all four artifact handlers: bail out cleanly if
// no store is configured (e.g. unit tests pre-dating M3, or the daemon
// somehow started without a --store-root). Returns an error response on
// missing store; nullopt to continue.
std::optional<Response>
require_artifact_store(const Request& req,
                       const std::shared_ptr<ldb::store::ArtifactStore>& s) {
  if (s) return std::nullopt;
  return protocol::make_err(req.id, ErrorCode::kBadState,
                            "artifact store not configured "
                            "(set --store-root or LDB_STORE_ROOT)");
}
}  // namespace

Response Dispatcher::handle_artifact_put(const Request& req) {
  if (auto e = require_artifact_store(req, artifacts_)) return *e;
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  const auto* build_id = require_string(req.params, "build_id");
  if (!build_id || build_id->empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing non-empty string param 'build_id'");
  }
  const auto* name = require_string(req.params, "name");
  if (!name || name->empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing non-empty string param 'name'");
  }
  const auto* b64 = require_string(req.params, "bytes_b64");
  if (!b64) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing string param 'bytes_b64'");
  }
  auto bytes = base64_decode(*b64);
  if (!bytes) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "'bytes_b64' is not valid base64");
  }

  std::optional<std::string> format;
  if (auto it = req.params.find("format"); it != req.params.end() &&
                                            !it->is_null()) {
    if (!it->is_string()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'format' must be a string");
    }
    format = it->get<std::string>();
  }

  json meta = json::object();
  if (auto it = req.params.find("meta"); it != req.params.end() &&
                                          !it->is_null()) {
    if (!it->is_object()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'meta' must be an object");
    }
    meta = *it;
  }

  // Post-V1 plan #6: when the caller declares the hypothesis-v1 format,
  // parse the bytes as JSON and validate the envelope. The artifact
  // store accepts arbitrary blobs; the dispatcher is the layer that
  // enforces typed formats so the store stays format-agnostic.
  if (format.has_value() && *format == ldb::store::kHypothesisFormat) {
    json env;
    try {
      env = json::parse(bytes->begin(), bytes->end());
    } catch (const std::exception& e) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
          std::string("hypothesis-v1 bytes must be valid JSON: ") +
          e.what());
    }
    auto v = ldb::store::validate_hypothesis_envelope(env);
    if (!v.ok) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
          std::string("hypothesis-v1: ") + v.error);
    }
  }

  auto row = artifacts_->put(*build_id, *name, *bytes, std::move(format),
                              meta);
  json data;
  data["id"]          = row.id;
  data["sha256"]      = row.sha256;
  data["byte_size"]   = row.byte_size;
  data["stored_path"] = row.stored_path;
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_artifact_hypothesis_template(const Request& req) {
  // Pure helper; no artifact store required, no params.
  json data;
  data["template"] = ldb::store::default_hypothesis_template();
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_artifact_get(const Request& req) {
  if (auto e = require_artifact_store(req, artifacts_)) return *e;
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }

  // Lookup mode: id, OR (build_id, name). id wins if both given.
  std::optional<store::ArtifactRow> row;
  if (auto it = req.params.find("id");
      it != req.params.end() && !it->is_null()) {
    std::int64_t id = 0;
    if (it->is_number_integer()) {
      id = it->get<std::int64_t>();
    } else if (it->is_number_unsigned()) {
      id = static_cast<std::int64_t>(it->get<std::uint64_t>());
    } else {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'id' must be an integer");
    }
    row = artifacts_->get_by_id(id);
  } else {
    const auto* build_id = require_string(req.params, "build_id");
    const auto* name     = require_string(req.params, "name");
    if (!build_id || !name) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "artifact.get needs either {id} or "
                                "{build_id, name}");
    }
    row = artifacts_->get_by_name(*build_id, *name);
  }

  if (!row.has_value()) {
    return protocol::make_err(req.id, ErrorCode::kBackendError,
                              "artifact not found");
  }

  // view.max_bytes caps the inline payload (preview path).
  std::uint64_t max_bytes = 0;
  if (auto vit = req.params.find("view");
      vit != req.params.end() && vit->is_object()) {
    if (auto mit = vit->find("max_bytes");
        mit != vit->end() && !mit->is_null()) {
      if (mit->is_number_unsigned()) {
        max_bytes = mit->get<std::uint64_t>();
      } else if (mit->is_number_integer()) {
        auto v = mit->get<std::int64_t>();
        if (v < 0) {
          return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                    "'view.max_bytes' must be non-negative");
        }
        max_bytes = static_cast<std::uint64_t>(v);
      } else {
        return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                  "'view.max_bytes' must be an integer");
      }
    }
  }

  auto bytes = artifacts_->read_blob(*row, max_bytes);
  bool truncated = (max_bytes != 0 &&
                    static_cast<std::uint64_t>(bytes.size()) < row->byte_size);

  json data;
  data["bytes_b64"]  = base64_encode(bytes);
  data["byte_size"]  = row->byte_size;
  data["sha256"]     = row->sha256;
  if (row->format.has_value()) data["format"] = *row->format;
  data["meta"]       = row->meta;
  data["build_id"]   = row->build_id;
  data["name"]       = row->name;
  data["created_at"] = row->created_at;
  data["truncated"]  = truncated;
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_artifact_list(const Request& req) {
  if (auto e = require_artifact_store(req, artifacts_)) return *e;
  if (!req.params.is_object() && !req.params.is_null()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::optional<std::string> build_id;
  std::optional<std::string> name_pattern;
  if (req.params.is_object()) {
    if (auto it = req.params.find("build_id");
        it != req.params.end() && !it->is_null()) {
      if (!it->is_string()) {
        return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                  "'build_id' must be a string");
      }
      build_id = it->get<std::string>();
    }
    if (auto it = req.params.find("name_pattern");
        it != req.params.end() && !it->is_null()) {
      if (!it->is_string()) {
        return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                  "'name_pattern' must be a string");
      }
      name_pattern = it->get<std::string>();
    }
  }

  auto rows = artifacts_->list(build_id, name_pattern);
  json arr = json::array();
  for (const auto& r : rows) arr.push_back(artifact_row_to_list_json(r));
  auto view_spec = protocol::view::parse_from_params(req.params);
  return protocol::make_ok(req.id,
      protocol::view::apply_to_array(std::move(arr), view_spec, "artifacts"));
}

Response Dispatcher::handle_artifact_tag(const Request& req) {
  if (auto e = require_artifact_store(req, artifacts_)) return *e;
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::int64_t id = 0;
  if (auto it = req.params.find("id");
      it != req.params.end() && !it->is_null()) {
    if (it->is_number_integer()) {
      id = it->get<std::int64_t>();
    } else if (it->is_number_unsigned()) {
      id = static_cast<std::int64_t>(it->get<std::uint64_t>());
    } else {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'id' must be an integer");
    }
  } else {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing integer param 'id'");
  }
  auto tit = req.params.find("tags");
  if (tit == req.params.end() || !tit->is_array()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing array param 'tags'");
  }
  std::vector<std::string> tags;
  for (const auto& t : *tit) {
    if (!t.is_string()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'tags' entries must be strings");
    }
    tags.push_back(t.get<std::string>());
  }

  auto out_tags = artifacts_->add_tags(id, tags);
  json data;
  data["tags"] = out_tags;
  return protocol::make_ok(req.id, std::move(data));
}

// Tier 2 §6 prep: artifact.delete is the GC sibling to artifact.put.
// Recipes will pile up — without a delete path the only way to remove
// one is editing the sqlite db by hand. Idempotent: deleting an
// already-gone id returns {deleted:false} (not an error).
Response Dispatcher::handle_artifact_delete(const Request& req) {
  if (auto e = require_artifact_store(req, artifacts_)) return *e;
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::int64_t id = 0;
  if (auto it = req.params.find("id");
      it != req.params.end() && !it->is_null()) {
    if (it->is_number_integer()) {
      id = it->get<std::int64_t>();
    } else if (it->is_number_unsigned()) {
      id = static_cast<std::int64_t>(it->get<std::uint64_t>());
    } else {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'id' must be an integer");
    }
  } else {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing integer param 'id'");
  }
  bool deleted = artifacts_->remove(id);
  json data;
  data["id"]      = id;
  data["deleted"] = deleted;
  return protocol::make_ok(req.id, std::move(data));
}

// --- artifact.relate / .relations / .unrelate (Tier 3 §7) -----------------
//
// Typed relations between artifacts form a queryable knowledge graph
// ("this XML is the schema parsed_by xml_parse called_by init_schema").
// Single-hop only in v0.3; recursive traversal is a v0.5 follow-up.
// Predicate is a free-form string — common values are documented in
// docs/09-artifact-knowledge-graph.md.
//
// Auto-derivation from session logs is deferred. This slice ships
// manual-attach only: the agent (or a higher layer) issues
// artifact.relate explicitly when it learns a fact.

namespace {
// Parse the optional [direction] param into the store enum. Defaults to
// "both" when absent or null.
bool parse_relation_dir(const json& params,
                        ldb::store::RelationDir* out,
                        std::string* err_msg) {
  *out = ldb::store::RelationDir::kBoth;
  auto it = params.find("direction");
  if (it == params.end() || it->is_null()) return true;
  if (!it->is_string()) {
    *err_msg = "'direction' must be a string ('out'|'in'|'both')";
    return false;
  }
  const auto& s = it->get_ref<const std::string&>();
  if      (s == "out")  *out = ldb::store::RelationDir::kOut;
  else if (s == "in")   *out = ldb::store::RelationDir::kIn;
  else if (s == "both") *out = ldb::store::RelationDir::kBoth;
  else {
    *err_msg = "'direction' must be one of 'out'|'in'|'both'";
    return false;
  }
  return true;
}

// Pull a signed integer id out of the params, accepting both
// number_integer and number_unsigned representations. Returns true
// only if the key was present and convertible.
bool require_int64(const json& params, const char* key, std::int64_t* out) {
  auto it = params.find(key);
  if (it == params.end() || it->is_null()) return false;
  if (it->is_number_integer())   { *out = it->get<std::int64_t>();          return true; }
  if (it->is_number_unsigned())  { *out = static_cast<std::int64_t>(
                                            it->get<std::uint64_t>());      return true; }
  return false;
}
}  // namespace

Response Dispatcher::handle_artifact_relate(const Request& req) {
  if (auto e = require_artifact_store(req, artifacts_)) return *e;
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::int64_t from_id = 0, to_id = 0;
  if (!require_int64(req.params, "from_id", &from_id)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing integer param 'from_id'");
  }
  if (!require_int64(req.params, "to_id", &to_id)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing integer param 'to_id'");
  }
  const auto* predicate = require_string(req.params, "predicate");
  if (!predicate) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing string param 'predicate'");
  }
  if (predicate->empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "'predicate' must be non-empty");
  }
  json meta = json::object();
  if (auto it = req.params.find("meta"); it != req.params.end() &&
                                          !it->is_null()) {
    if (!it->is_object()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'meta' must be an object");
    }
    meta = *it;
  }

  auto rel = artifacts_->add_relation(from_id, to_id, *predicate, meta);
  json data;
  data["relation_id"] = rel.id;
  data["from_id"]     = rel.from_id;
  data["to_id"]       = rel.to_id;
  data["predicate"]   = rel.predicate;
  data["created_at"]  = rel.created_at;
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_artifact_relations(const Request& req) {
  if (auto e = require_artifact_store(req, artifacts_)) return *e;
  if (!req.params.is_object() && !req.params.is_null()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::optional<std::int64_t> artifact_id;
  std::optional<std::string>  predicate;
  ldb::store::RelationDir     dir = ldb::store::RelationDir::kBoth;

  if (req.params.is_object()) {
    if (auto it = req.params.find("artifact_id");
        it != req.params.end() && !it->is_null()) {
      std::int64_t v = 0;
      if (!require_int64(req.params, "artifact_id", &v)) {
        return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                  "'artifact_id' must be an integer");
      }
      artifact_id = v;
    }
    if (auto it = req.params.find("predicate");
        it != req.params.end() && !it->is_null()) {
      if (!it->is_string()) {
        return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                  "'predicate' must be a string");
      }
      predicate = it->get<std::string>();
    }
    std::string err_msg;
    if (!parse_relation_dir(req.params, &dir, &err_msg)) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams, err_msg);
    }
  }

  auto rels = artifacts_->list_relations(artifact_id, predicate, dir);
  json arr = json::array();
  for (const auto& r : rels) arr.push_back(relation_to_json(r));
  auto view_spec = protocol::view::parse_from_params(req.params);
  return protocol::make_ok(req.id,
      protocol::view::apply_to_array(std::move(arr), view_spec, "relations"));
}

Response Dispatcher::handle_artifact_unrelate(const Request& req) {
  if (auto e = require_artifact_store(req, artifacts_)) return *e;
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::int64_t rid = 0;
  if (!require_int64(req.params, "relation_id", &rid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing integer param 'relation_id'");
  }
  bool deleted = artifacts_->remove_relation(rid);
  json data;
  data["relation_id"] = rid;
  data["deleted"]     = deleted;
  return protocol::make_ok(req.id, std::move(data));
}

// mem.dump_artifact — pure composition of mem.read + artifact.put.
// Reads [len] bytes at [addr] from the live target and persists them to
// the artifact store under (build_id, name). Same 1 MiB cap as mem.read
// (enforced by the backend; oversize requests surface as -32000). Errors
// mirror the constituent endpoints: bad target_id / oversize / read
// failure → -32000, missing-or-invalid params → -32602, store missing
// → -32002.
Response Dispatcher::handle_mem_dump_artifact(const Request& req) {
  if (auto e = require_artifact_store(req, artifacts_)) return *e;
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::uint64_t tid = 0, addr = 0, len = 0;
  if (!require_uint(req.params, "target_id", &tid)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }
  if (!require_uint(req.params, "addr", &addr)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'addr'");
  }
  if (!require_uint(req.params, "len", &len)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'len'");
  }
  const auto* build_id = require_string(req.params, "build_id");
  if (!build_id || build_id->empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing non-empty string param 'build_id'");
  }
  const auto* name = require_string(req.params, "name");
  if (!name || name->empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing non-empty string param 'name'");
  }

  std::optional<std::string> format;
  if (auto it = req.params.find("format"); it != req.params.end() &&
                                            !it->is_null()) {
    if (!it->is_string()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'format' must be a string");
    }
    format = it->get<std::string>();
  }

  json meta = json::object();
  if (auto it = req.params.find("meta"); it != req.params.end() &&
                                          !it->is_null()) {
    if (!it->is_object()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'meta' must be an object");
    }
    meta = *it;
  }

  // Backend enforces the 1 MiB read cap; bad target_id / read failure /
  // oversize all surface here as backend::Error → -32000.
  auto bytes = backend_->read_memory(
      static_cast<backend::TargetId>(tid), addr, len);

  auto row = artifacts_->put(*build_id, *name, bytes, std::move(format),
                              meta);
  json data;
  data["artifact_id"] = row.id;
  data["byte_size"]   = row.byte_size;
  data["sha256"]      = row.sha256;
  data["name"]        = row.name;
  return protocol::make_ok(req.id, std::move(data));
}

// ----------------------------------------------------------------------------
// session.* — investigation logging (M3 part 2)

namespace {

std::optional<Response>
require_session_store(const Request& req,
                      const std::shared_ptr<ldb::store::SessionStore>& s) {
  if (s) return std::nullopt;
  return protocol::make_err(req.id, ErrorCode::kBadState,
                            "session store not configured "
                            "(set --store-root or LDB_STORE_ROOT)");
}

json session_row_to_list_json(const ldb::store::SessionRow& r) {
  json j;
  j["id"]         = r.id;
  j["name"]       = r.name;
  if (r.target_id.has_value()) j["target_id"] = *r.target_id;
  j["created_at"] = r.created_at;
  j["call_count"] = r.call_count;
  if (r.last_call_at.has_value()) j["last_call_at"] = *r.last_call_at;
  j["path"]       = r.path;
  return j;
}

}  // namespace

Response Dispatcher::handle_session_create(const Request& req) {
  if (auto e = require_session_store(req, sessions_)) return *e;
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  const auto* name = require_string(req.params, "name");
  if (!name || name->empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing non-empty string param 'name'");
  }
  std::optional<std::string> target_id;
  if (auto it = req.params.find("target_id");
      it != req.params.end() && !it->is_null()) {
    if (!it->is_string()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'target_id' must be a string");
    }
    target_id = it->get<std::string>();
  }
  auto row = sessions_->create(*name, std::move(target_id));
  json data;
  data["id"]         = row.id;
  data["name"]       = row.name;
  if (row.target_id.has_value()) data["target_id"] = *row.target_id;
  data["created_at"] = row.created_at;
  data["path"]       = row.path;
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_session_attach(const Request& req) {
  if (auto e = require_session_store(req, sessions_)) return *e;
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  const auto* id = require_string(req.params, "id");
  if (!id || id->empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing non-empty string param 'id'");
  }
  // open_writer throws backend::Error if the id doesn't exist; the
  // outer dispatch() catch maps that to -32000.
  auto writer = sessions_->open_writer(*id);
  auto info = sessions_->info(*id);

  // Replace any previously-active writer (the dispatcher only tracks
  // one connection-wide attachment; an explicit re-attach swaps it).
  active_session_writer_ = std::move(writer);
  active_session_id_     = *id;

  json data;
  data["id"]       = *id;
  if (info.has_value()) data["name"] = info->name;
  data["attached"] = true;
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_session_detach(const Request& req) {
  // Detach is intentionally permissive: callable even when not attached
  // and even when no SessionStore is configured (no-op true→false). This
  // makes it safe for an agent to issue defensively at the end of an
  // investigation without first checking state.
  //
  // Sequencing note: dispatch() observes active_session_writer_ AFTER
  // this handler returns. To make the detach call itself appear as the
  // last row in the rpc_log (a useful "stop" bookmark for replay), we
  // append it explicitly here BEFORE clearing the writer. The
  // dispatch() wrapper's append-after-detach would be a no-op anyway.
  bool was_attached = static_cast<bool>(active_session_writer_);
  if (was_attached) {
    json req_j;
    req_j["method"] = req.method;
    req_j["params"] = req.params;
    if (req.id.has_value()) req_j["id"] = *req.id;
    json rsp_j;
    rsp_j["ok"] = true;
    rsp_j["data"] = json{{"detached", true}};
    try {
      active_session_writer_->append(req.method, req_j, rsp_j, true, 0);
    } catch (const std::exception& e) {
      log::warn(std::string("session log append (detach) failed: ") +
                e.what());
    }
  }
  active_session_writer_.reset();
  active_session_id_.clear();
  json data;
  data["detached"] = was_attached;
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_session_list(const Request& req) {
  if (auto e = require_session_store(req, sessions_)) return *e;
  auto rows = sessions_->list();
  json arr = json::array();
  for (const auto& r : rows) arr.push_back(session_row_to_list_json(r));
  json data;
  data["sessions"] = std::move(arr);
  data["total"]    = static_cast<std::int64_t>(rows.size());
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_session_info(const Request& req) {
  if (auto e = require_session_store(req, sessions_)) return *e;
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  const auto* id = require_string(req.params, "id");
  if (!id || id->empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing non-empty string param 'id'");
  }
  auto row = sessions_->info(*id);
  if (!row.has_value()) {
    return protocol::make_err(req.id, ErrorCode::kBackendError,
                              "session not found: " + *id);
  }
  json data;
  data["id"]         = row->id;
  data["name"]       = row->name;
  if (row->target_id.has_value()) data["target_id"] = *row->target_id;
  data["created_at"] = row->created_at;
  data["call_count"] = row->call_count;
  if (row->last_call_at.has_value()) {
    data["last_call_at"] = *row->last_call_at;
  }
  data["path"]       = row->path;
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_session_diff(const Request& req) {
  if (auto e = require_session_store(req, sessions_)) return *e;
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  const auto* a = require_string(req.params, "session_a");
  if (!a || a->empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing non-empty string param 'session_a'");
  }
  const auto* b = require_string(req.params, "session_b");
  if (!b || b->empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing non-empty string param 'session_b'");
  }

  // diff_logs throws backend::Error on missing id; the outer dispatch()
  // catch maps it to -32000.
  auto result = sessions_->diff_logs(*a, *b);

  // Render entries as an array; the wire shape per entry depends on
  // kind. All entries carry method + params_hash; common omits params
  // and response (they're equal — params_hash is enough to identify);
  // diverged carries both responses; added/removed carry the row's
  // params + response from the side where it lives.
  //
  // We re-parse params_canon back to an embedded JSON value (rather
  // than emitting it as a string) so the wire shape composes cleanly
  // with downstream tools — a planning agent expects `params` to be
  // an object, not a JSON-encoded string. Same for response_*.
  auto reembed = [](const std::string& canon) -> json {
    if (canon.empty()) return json::object();
    try { return json::parse(canon); }
    catch (...) { return json{{"raw", canon}}; }
  };

  json arr = json::array();
  for (const auto& e : result.entries) {
    json je;
    je["kind"]        = e.kind;
    je["method"]      = e.method;
    je["params_hash"] = e.params_hash;
    if (e.kind == "common") {
      je["seq_a"] = e.seq_a;
      je["seq_b"] = e.seq_b;
    } else if (e.kind == "diverged") {
      je["params"]     = reembed(e.params_canon);
      je["seq_a"]      = e.seq_a;
      je["seq_b"]      = e.seq_b;
      je["response_a"] = reembed(e.response_a_canon);
      je["response_b"] = reembed(e.response_b_canon);
    } else if (e.kind == "added") {
      je["params"]   = reembed(e.params_canon);
      je["seq_b"]    = e.seq_b;
      je["response"] = reembed(e.response_b_canon);
    } else if (e.kind == "removed") {
      je["params"]   = reembed(e.params_canon);
      je["seq_a"]    = e.seq_a;
      je["response"] = reembed(e.response_a_canon);
    }
    arr.push_back(std::move(je));
  }

  auto view_spec = protocol::view::parse_from_params(req.params);
  json paged = protocol::view::apply_to_array(std::move(arr), view_spec,
                                              "entries");

  // Fold the diff summary block alongside the paged entries. The view's
  // own `total` is the total number of entries (== sum of summary
  // counts); we keep both so a caller can sanity-check the shape.
  json summary;
  summary["total_a"]  = result.summary.total_a;
  summary["total_b"]  = result.summary.total_b;
  summary["added"]    = result.summary.added;
  summary["removed"]  = result.summary.removed;
  summary["common"]   = result.summary.common;
  summary["diverged"] = result.summary.diverged;
  paged["summary"]    = std::move(summary);

  return protocol::make_ok(req.id, std::move(paged));
}

Response Dispatcher::handle_session_targets(const Request& req) {
  if (auto e = require_session_store(req, sessions_)) return *e;
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  const auto* sid = require_string(req.params, "session_id");
  if (!sid || sid->empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing non-empty string param 'session_id'");
  }
  // extract_target_ids throws backend::Error on unknown id; the outer
  // dispatch() catch maps that to -32000.
  auto buckets = sessions_->extract_target_ids(*sid);

  json arr = json::array();
  for (const auto& b : buckets) {
    json j;
    j["target_id"]  = b.target_id;
    j["call_count"] = b.call_count;
    j["first_seq"]  = b.first_seq;
    j["last_seq"]   = b.last_seq;
    // Enrich with the *current* label if the target is still open.
    // Closed targets simply don't carry one — see worklog: labels are
    // daemon-process-scoped and die with close_target.
    if (auto lbl = backend_->get_target_label(
            static_cast<backend::TargetId>(b.target_id));
        lbl.has_value()) {
      j["label"] = *lbl;
    }
    arr.push_back(std::move(j));
  }
  auto view_spec = protocol::view::parse_from_params(req.params);
  return protocol::make_ok(req.id,
      protocol::view::apply_to_array(std::move(arr), view_spec, "targets"));
}

// ----------------------------------------------------------------------------
// session.export / session.import / artifact.export / artifact.import
// (M5 part 5) — `.ldbpack` round-trip across machines / restarts.

namespace {

// Default pack output dir under the store root. Created on first
// export. Returning a relative path inside the store root is the safe
// behavior — an agent that omits `path` won't accidentally drop a file
// somewhere unexpected.
std::filesystem::path default_pack_dir(
    const std::shared_ptr<ldb::store::ArtifactStore>& art,
    const std::shared_ptr<ldb::store::SessionStore>& sess) {
  // Either store has the same root by construction (main.cpp).
  std::filesystem::path root;
  if (art)       root = art->root();
  else if (sess) root = sess->root();
  return root / "packs";
}

// Validate a caller-supplied [path]. Caller can drop a pack anywhere
// they have permission to write; we only refuse the obviously hostile:
// empty string. Path-traversal of the *contents* of a pack is enforced
// during extract (in pack.cpp), not here.
bool valid_pack_path(const std::string& s, std::string* err) {
  if (s.empty()) { *err = "'path' must be non-empty"; return false; }
  return true;
}

// Pull a {path, conflict_policy?, trust_root?, require_signed?} request
// body; returns the canonical path, policy (default kError), and signing
// options (docs/14-pack-signing.md §"API Surface"). On bad input,
// returns an Err response wrapping the request id.
struct ImportArgs {
  std::filesystem::path                path;
  ldb::store::ConflictPolicy           policy = ldb::store::ConflictPolicy::kError;
  std::optional<std::filesystem::path> trust_root;
  bool                                 require_signed = false;
};

std::optional<Response>
parse_import_args(const Request& req, ImportArgs* out) {
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  const auto* path = require_string(req.params, "path");
  if (!path || path->empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing non-empty string param 'path'");
  }
  std::string err;
  if (!valid_pack_path(*path, &err)) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams, err);
  }
  out->path = *path;
  if (auto it = req.params.find("conflict_policy");
      it != req.params.end() && !it->is_null()) {
    if (!it->is_string()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'conflict_policy' must be a string");
    }
    auto s = it->get<std::string>();
    if (!ldb::store::parse_conflict_policy(s, &out->policy)) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
          "'conflict_policy' must be one of: error, skip, overwrite");
    }
  }
  if (auto it = req.params.find("trust_root");
      it != req.params.end() && !it->is_null()) {
    if (!it->is_string()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'trust_root' must be a string");
    }
    auto s = it->get<std::string>();
    if (s.empty()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'trust_root' must be a non-empty string");
    }
    out->trust_root = std::filesystem::path(s);
  }
  if (auto it = req.params.find("require_signed");
      it != req.params.end() && !it->is_null()) {
    if (!it->is_boolean()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'require_signed' must be a boolean");
    }
    out->require_signed = it->get<bool>();
  }
  return std::nullopt;
}

// Parse the export-side signing options ({sign_key, signer}) shared by
// session.export and artifact.export. `signed_key` is left empty when
// `sign_key` is not in [params]; the caller picks unsigned vs signed
// pack producer based on `signed_key.has_value()`.
//
// Per docs/14 §"Error mapping":
//   * `sign_key` path missing on export → kInvalidParams
//   * encrypted OpenSSH key             → kInvalidParams
//   * malformed key                     → kInvalidParams
struct ExportSignOpts {
  std::optional<ldb::store::Ed25519KeyPair> signed_key;
  std::optional<std::string>                signer_label;
  std::string                               key_id;  // for the response
};

std::optional<Response>
parse_export_sign_opts(const Request& req, ExportSignOpts* out) {
  if (!req.params.is_object()) return std::nullopt;
  auto sk_it = req.params.find("sign_key");
  if (sk_it == req.params.end() || sk_it->is_null()) {
    // Plain unsigned export — leave opts empty.
    return std::nullopt;
  }
  if (!sk_it->is_string()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "'sign_key' must be a string");
  }
  auto sk_path = sk_it->get<std::string>();
  if (sk_path.empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "'sign_key' must be a non-empty string");
  }
  std::ifstream in(sk_path, std::ios::binary);
  if (!in) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "sign_key file not found or unreadable: " +
                              sk_path);
  }
  in.seekg(0, std::ios::end);
  auto sz = in.tellg();
  if (sz < 0) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "sign_key: tellg failed: " + sk_path);
  }
  in.seekg(0, std::ios::beg);
  std::vector<std::uint8_t> pem(static_cast<std::size_t>(sz));
  if (sz > 0) {
    in.read(reinterpret_cast<char*>(pem.data()),
            static_cast<std::streamsize>(pem.size()));
  }
  try {
    auto kp = ldb::store::parse_openssh_secret_key(pem);
    out->signed_key = kp;
    out->key_id     = ldb::store::compute_key_id(kp.public_key);
  } catch (const backend::Error& e) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              std::string("sign_key: ") + e.what());
  }
  if (auto it = req.params.find("signer");
      it != req.params.end() && !it->is_null()) {
    if (!it->is_string()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'signer' must be a string");
    }
    out->signer_label = it->get<std::string>();
  }
  return std::nullopt;
}

json import_entry_to_json(const ldb::store::ImportEntry& e) {
  json j;
  j["kind"] = e.kind;
  j["key"]  = e.key;
  if (!e.reason.empty()) j["reason"] = e.reason;
  return j;
}

}  // namespace

Response Dispatcher::handle_session_export(const Request& req) {
  if (auto e = require_session_store(req, sessions_)) return *e;
  if (auto e = require_artifact_store(req, artifacts_)) return *e;
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  const auto* id = require_string(req.params, "id");
  if (!id || id->empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing non-empty string param 'id'");
  }

  std::filesystem::path out_path;
  if (auto it = req.params.find("path");
      it != req.params.end() && !it->is_null()) {
    if (!it->is_string()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'path' must be a string");
    }
    auto s = it->get<std::string>();
    std::string err;
    if (!valid_pack_path(s, &err)) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams, err);
    }
    out_path = s;
  } else {
    auto dir = default_pack_dir(artifacts_, sessions_);
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    out_path = dir / (*id + ".ldbpack");
  }

  ExportSignOpts sopts;
  if (auto e = parse_export_sign_opts(req, &sopts)) return *e;

  // Unsigned path: keep using `pack_session` directly so the on-disk
  // bytes stay bit-identical to today when `sign_key` isn't given —
  // smoke_agent_workflow asserts on that round-trip.
  json data;
  if (!sopts.signed_key.has_value()) {
    auto result = ldb::store::pack_session(*sessions_, *artifacts_, *id,
                                            out_path);
    data["path"]      = result.path.string();
    data["byte_size"] = result.byte_size;
    data["sha256"]    = result.sha256;
    data["manifest"]  = result.manifest;
  } else {
    auto sr = ldb::store::pack_session_signed(
        *sessions_, *artifacts_, *id, out_path,
        sopts.signed_key, sopts.signer_label);
    data["path"]      = sr.result.path.string();
    data["byte_size"] = sr.result.byte_size;
    data["sha256"]    = sr.result.sha256;
    data["manifest"]  = sr.result.manifest;
    json sig;
    sig["key_id"]    = sopts.key_id;
    sig["algorithm"] = "ed25519";
    data["signature"] = std::move(sig);
  }
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_artifact_export(const Request& req) {
  if (auto e = require_artifact_store(req, artifacts_)) return *e;
  if (!req.params.is_object() && !req.params.is_null()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::optional<std::string> build_id;
  std::optional<std::vector<std::string>> names;
  std::filesystem::path out_path;

  if (req.params.is_object()) {
    if (auto it = req.params.find("build_id");
        it != req.params.end() && !it->is_null()) {
      if (!it->is_string()) {
        return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                  "'build_id' must be a string");
      }
      build_id = it->get<std::string>();
    }
    if (auto it = req.params.find("names");
        it != req.params.end() && !it->is_null()) {
      if (!it->is_array()) {
        return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                  "'names' must be an array");
      }
      std::vector<std::string> nv;
      for (const auto& n : *it) {
        if (!n.is_string()) {
          return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                    "'names' entries must be strings");
        }
        nv.push_back(n.get<std::string>());
      }
      names = std::move(nv);
    }
    if (auto it = req.params.find("path");
        it != req.params.end() && !it->is_null()) {
      if (!it->is_string()) {
        return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                  "'path' must be a string");
      }
      auto s = it->get<std::string>();
      std::string err;
      if (!valid_pack_path(s, &err)) {
        return protocol::make_err(req.id, ErrorCode::kInvalidParams, err);
      }
      out_path = s;
    }
  }
  if (out_path.empty()) {
    auto dir = default_pack_dir(artifacts_, sessions_);
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    std::string fn = "artifacts";
    if (build_id.has_value()) { fn += "-"; fn += *build_id; }
    fn += ".ldbpack";
    out_path = dir / fn;
  }

  ExportSignOpts sopts;
  if (auto e = parse_export_sign_opts(req, &sopts)) return *e;

  json data;
  if (!sopts.signed_key.has_value()) {
    auto result = ldb::store::pack_artifacts(*artifacts_, build_id,
                                              std::move(names), out_path);
    data["path"]      = result.path.string();
    data["byte_size"] = result.byte_size;
    data["sha256"]    = result.sha256;
    data["manifest"]  = result.manifest;
  } else {
    auto sr = ldb::store::pack_artifacts_signed(
        *artifacts_, build_id, std::move(names), out_path,
        sopts.signed_key, sopts.signer_label);
    data["path"]      = sr.result.path.string();
    data["byte_size"] = sr.result.byte_size;
    data["sha256"]    = sr.result.sha256;
    data["manifest"]  = sr.result.manifest;
    json sig;
    sig["key_id"]    = sopts.key_id;
    sig["algorithm"] = "ed25519";
    data["signature"] = std::move(sig);
  }
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_session_import(const Request& req) {
  if (auto e = require_session_store(req, sessions_)) return *e;
  if (auto e = require_artifact_store(req, artifacts_)) return *e;
  ImportArgs args;
  if (auto err = parse_import_args(req, &args)) return *err;
  // If the file isn't there, surface a typed error rather than letting
  // pack::unpack's open-file failure bubble up.
  if (!std::filesystem::exists(args.path)) {
    return protocol::make_err(req.id, ErrorCode::kBackendError,
                              "session.import: no such pack file: " +
                              args.path.string());
  }

  // Verify-then-unpack pipeline. `verify_pack` is run for every import
  // (signed or not) — for unsigned packs it gives an internal-consistency
  // check at the cost of one extra parse pass; for signed packs it
  // gates the apply step on the signature outcome. Error mapping is in
  // docs/14-pack-signing.md §"Error mapping".
  ldb::store::PackVerifyReport vrep;
  try {
    vrep = ldb::store::verify_pack(args.path, args.trust_root);
  } catch (const backend::Error& e) {
    // Trust-root I/O errors and malformed signature blobs come through
    // here. Per the docs, trust-root missing/unreadable is a kBadState
    // when `require_signed=true` (the operator asked for it but the
    // environment can't fulfill it); otherwise the import is refused
    // with kForbidden (the pack carries a signature we couldn't check).
    std::string m = e.what();
    auto is_trust_io = m.find("trust_root") != std::string::npos;
    auto code = (is_trust_io && args.require_signed)
                    ? ErrorCode::kBadState
                    : ErrorCode::kBackendError;
    return protocol::make_err(req.id, code, m);
  }

  if (args.require_signed && !vrep.is_signed) {
    return protocol::make_err(req.id, ErrorCode::kBadState,
        "session.import: pack is unsigned but require_signed=true");
  }
  if (args.require_signed && !args.trust_root.has_value()) {
    return protocol::make_err(req.id, ErrorCode::kBadState,
        "session.import: require_signed=true but no trust_root provided");
  }
  if (vrep.is_signed && !vrep.verified && args.trust_root.has_value()) {
    // Three failure modes funnel here:
    //   (a) ed25519 verify failed
    //   (b) signer key_id not in trust_root
    //   (c) per-entry sha256 mismatch / entries-set mismatch
    // All three are kForbidden per docs/14 (well-formed request,
    // operation refused). The message names which check tripped.
    json edata;
    if (!vrep.key_id.empty()) edata["key_id"] = vrep.key_id;
    return protocol::make_err(req.id, ErrorCode::kForbidden,
                              vrep.error_message.empty()
                                  ? "session.import: signature verification failed"
                                  : vrep.error_message,
                              std::move(edata));
  }

  auto report = ldb::store::unpack(*sessions_, *artifacts_, args.path,
                                    args.policy);
  json imported = json::array();
  for (const auto& e : report.imported) imported.push_back(import_entry_to_json(e));
  json skipped  = json::array();
  for (const auto& e : report.skipped)  skipped.push_back(import_entry_to_json(e));
  json data;
  data["imported"] = std::move(imported);
  data["skipped"]  = std::move(skipped);
  data["policy"]   = ldb::store::conflict_policy_str(args.policy);

  if (vrep.is_signed) {
    json sig;
    sig["key_id"]   = vrep.key_id;
    sig["verified"] = vrep.verified;
    if (!vrep.signer.empty()) sig["signer"] = vrep.signer;
    data["signature"] = std::move(sig);
  }
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_artifact_import(const Request& req) {
  // Same shape as session.import but only reports the artifact rows
  // (sessions in the pack, if any, are imported too — matches the
  // simpler "import everything" semantics).
  return handle_session_import(req);
}

// ----------------------------------------------------------------------------
// recipe.* — named, parameterized RPC sequences (Tier 2 §6).
//
// Recipes promote replayable session traces to first-class objects:
// extract a useful sequence from one investigation's rpc_log, give it
// a name and parameter slots, and run it as a single call against new
// targets / addresses / paths.
//
// Storage is a `recipe-v1` artifact (see store/recipe_store.{h,cpp})
// so we get sqlite indexing, `.ldbpack` portability, and a single
// delete path (artifact.delete) for free.

namespace {

ldb::store::RecipeParameter
parse_recipe_parameter(const json& j, std::string* err) {
  ldb::store::RecipeParameter slot;
  if (!j.is_object()) {
    *err = "recipe parameter must be an object";
    return slot;
  }
  auto nit = j.find("name");
  if (nit == j.end() || !nit->is_string() ||
      nit->get<std::string>().empty()) {
    *err = "recipe parameter missing non-empty 'name'";
    return slot;
  }
  slot.name = nit->get<std::string>();

  auto tit = j.find("type");
  if (tit != j.end() && !tit->is_null()) {
    if (!tit->is_string()) {
      *err = "recipe parameter 'type' must be a string";
      return slot;
    }
    slot.type = tit->get<std::string>();
  } else {
    slot.type = "string";
  }
  if (slot.type != "string" && slot.type != "integer") {
    *err = "recipe parameter 'type' must be \"string\" or \"integer\"";
    return slot;
  }

  auto dit = j.find("default");
  if (dit != j.end() && !dit->is_null()) {
    slot.default_value = *dit;
  }
  return slot;
}

ldb::store::RecipeCall
parse_recipe_call(const json& j, std::string* err) {
  ldb::store::RecipeCall call;
  if (!j.is_object()) {
    *err = "recipe call must be an object";
    return call;
  }
  auto mit = j.find("method");
  if (mit == j.end() || !mit->is_string() ||
      mit->get<std::string>().empty()) {
    *err = "recipe call missing non-empty 'method'";
    return call;
  }
  call.method = mit->get<std::string>();
  auto pit = j.find("params");
  if (pit != j.end() && !pit->is_null()) {
    call.params = *pit;
  } else {
    call.params = json::object();
  }
  return call;
}

json recipe_to_summary_json(const ldb::store::Recipe& r) {
  json j;
  j["recipe_id"]  = r.id;
  j["name"]       = r.name;
  if (r.description.has_value()) j["description"] = *r.description;
  j["call_count"] = static_cast<std::int64_t>(r.calls.size());
  j["created_at"] = r.created_at;
  // source_path appears only on file-backed recipes; absence signals
  // the recipe was created in-band (recipe.create / recipe.from_session)
  // and cannot be reloaded.
  if (r.source_path.has_value()) j["source_path"] = *r.source_path;
  return j;
}

json recipe_to_full_json(const ldb::store::Recipe& r) {
  json j = recipe_to_summary_json(r);
  json params = json::array();
  for (const auto& p : r.parameters) {
    json one;
    one["name"] = p.name;
    one["type"] = p.type;
    if (p.default_value.has_value()) one["default"] = *p.default_value;
    params.push_back(std::move(one));
  }
  j["parameters"] = std::move(params);
  json calls = json::array();
  for (const auto& c : r.calls) {
    json one;
    one["method"] = c.method;
    one["params"] = c.params;
    calls.push_back(std::move(one));
  }
  j["calls"] = std::move(calls);
  return j;
}

}  // namespace

Response Dispatcher::handle_recipe_create(const Request& req) {
  if (auto e = require_artifact_store(req, artifacts_)) return *e;
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  const auto* name = require_string(req.params, "name");
  if (!name || name->empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing non-empty string param 'name'");
  }
  std::optional<std::string> description;
  if (auto it = req.params.find("description");
      it != req.params.end() && !it->is_null()) {
    if (!it->is_string()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'description' must be a string");
    }
    description = it->get<std::string>();
  }

  // Format dispatch. Absent / "recipe-v1" → call-sequence recipe (the
  // long-standing shape). "python-v1" → embed.h Callable; requires
  // `body`, ignores `calls`. The two formats share `parameters`.
  std::string format = "recipe-v1";
  if (auto it = req.params.find("format");
      it != req.params.end() && !it->is_null()) {
    if (!it->is_string()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'format' must be a string");
    }
    format = it->get<std::string>();
    if (format != "recipe-v1" && format != "python-v1") {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
          "'format' must be one of {\"recipe-v1\", \"python-v1\"}");
    }
  }

  std::vector<ldb::store::RecipeParameter> parameters;
  if (auto pit = req.params.find("parameters");
      pit != req.params.end() && !pit->is_null()) {
    if (!pit->is_array()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'parameters' must be an array");
    }
    parameters.reserve(pit->size());
    for (const auto& p : *pit) {
      std::string err;
      auto slot = parse_recipe_parameter(p, &err);
      if (!err.empty()) {
        return protocol::make_err(req.id, ErrorCode::kInvalidParams, err);
      }
      parameters.push_back(std::move(slot));
    }
  }

  if (format == "python-v1") {
    if (!ldb::python::Interpreter::available()) {
      return protocol::make_err(req.id, ErrorCode::kBadState,
          "python-v1 recipes require ldbd built with LDB_ENABLE_PYTHON "
          "(pkg-config python3-embed >= 3.11)");
    }
    auto bit = req.params.find("body");
    if (bit == req.params.end() || !bit->is_string()
        || bit->get<std::string>().empty()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
          "python-v1 recipes require non-empty string param 'body'");
    }
    ldb::store::RecipeStore rs(*artifacts_);
    auto r = rs.create_python_recipe(*name, std::move(description),
                                     std::move(parameters),
                                     bit->get<std::string>());
    json data;
    data["recipe_id"]  = r.id;
    data["name"]       = r.name;
    data["format"]     = "python-v1";
    data["call_count"] = 0;
    return protocol::make_ok(req.id, std::move(data));
  }

  auto cit = req.params.find("calls");
  if (cit == req.params.end() || !cit->is_array() || cit->empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing non-empty array param 'calls'");
  }
  std::vector<ldb::store::RecipeCall> calls;
  calls.reserve(cit->size());
  for (const auto& c : *cit) {
    std::string err;
    auto call = parse_recipe_call(c, &err);
    if (!err.empty()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams, err);
    }
    calls.push_back(std::move(call));
  }

  ldb::store::RecipeStore rs(*artifacts_);
  auto r = rs.create(*name, std::move(description),
                     std::move(parameters), std::move(calls));
  json data;
  data["recipe_id"]  = r.id;
  data["name"]       = r.name;
  data["format"]     = "recipe-v1";
  data["call_count"] = static_cast<std::int64_t>(r.calls.size());
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_recipe_from_session(const Request& req) {
  if (auto e = require_artifact_store(req, artifacts_)) return *e;
  if (auto e = require_session_store(req, sessions_)) return *e;
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  const auto* sid = require_string(req.params, "source_session_id");
  if (!sid || sid->empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing non-empty string param "
                              "'source_session_id'");
  }
  const auto* name = require_string(req.params, "name");
  if (!name || name->empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing non-empty string param 'name'");
  }
  std::optional<std::string> description;
  if (auto it = req.params.find("description");
      it != req.params.end() && !it->is_null()) {
    if (!it->is_string()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'description' must be a string");
    }
    description = it->get<std::string>();
  }

  // Filter parameters. include_methods + exclude_methods are mutually
  // composable; since_seq / until_seq are seq-bounds that map directly
  // to SessionStore::read_log.
  std::vector<std::string> include;
  std::vector<std::string> exclude;
  std::int64_t since_seq = 0;
  std::int64_t until_seq = 0;
  if (auto fit = req.params.find("filter");
      fit != req.params.end() && !fit->is_null()) {
    if (!fit->is_object()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'filter' must be an object");
    }
    auto str_array = [&](const char* key, std::vector<std::string>* out)
        -> std::optional<Response> {
      auto it = fit->find(key);
      if (it == fit->end() || it->is_null()) return std::nullopt;
      if (!it->is_array()) {
        return protocol::make_err(req.id, ErrorCode::kInvalidParams,
            std::string("'filter.") + key + "' must be an array");
      }
      for (const auto& el : *it) {
        if (!el.is_string()) {
          return protocol::make_err(req.id, ErrorCode::kInvalidParams,
              std::string("'filter.") + key + "' entries must be strings");
        }
        out->push_back(el.get<std::string>());
      }
      return std::nullopt;
    };
    if (auto e = str_array("include_methods", &include)) return *e;
    if (auto e = str_array("exclude_methods", &exclude)) return *e;
    if (auto it = fit->find("since_seq");
        it != fit->end() && !it->is_null()) {
      if (!it->is_number_integer() && !it->is_number_unsigned()) {
        return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                  "'filter.since_seq' must be an integer");
      }
      since_seq = it->get<std::int64_t>();
    }
    if (auto it = fit->find("until_seq");
        it != fit->end() && !it->is_null()) {
      if (!it->is_number_integer() && !it->is_number_unsigned()) {
        return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                  "'filter.until_seq' must be an integer");
      }
      until_seq = it->get<std::int64_t>();
    }
  }

  auto rows = sessions_->read_log(*sid, since_seq, until_seq);
  // Strip the cosmetic / introspection / session-mgmt calls. Anything
  // in the include list bypasses the strip; otherwise drop both
  // the default strip-set and any caller-supplied excludes.
  const auto& default_strip = ldb::store::recipe_default_strip_methods();
  std::vector<ldb::store::RecipeCall> calls;
  for (const auto& row : rows) {
    if (!row.ok) continue;  // Failed calls aren't worth replaying.
    bool in_include = include.empty() ||
        std::find(include.begin(), include.end(), row.method) != include.end();
    if (!in_include) continue;
    bool in_exclude =
        std::find(exclude.begin(), exclude.end(), row.method) != exclude.end();
    if (in_exclude) continue;
    if (include.empty()) {
      // include not specified — apply the default strip set.
      bool default_strip_hit =
          std::find(default_strip.begin(), default_strip.end(), row.method)
            != default_strip.end();
      if (default_strip_hit) continue;
    }

    ldb::store::RecipeCall call;
    call.method = row.method;
    // The persisted request_json is the {method, params, id} shape from
    // dispatch(); we only want params for replay.
    try {
      auto req_j = json::parse(row.request_json);
      if (req_j.is_object() && req_j.contains("params")) {
        call.params = req_j["params"];
      } else {
        call.params = json::object();
      }
    } catch (...) {
      call.params = json::object();
    }
    calls.push_back(std::move(call));
  }
  if (calls.empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
        "no calls remain after filtering — nothing to extract");
  }

  ldb::store::RecipeStore rs(*artifacts_);
  // No parameters auto-detected — this is an explicit v0.5 follow-up.
  // Caller can re-create the recipe with parameters via recipe.create
  // after inspecting the extracted body.
  auto r = rs.create(*name, std::move(description), {}, std::move(calls));
  json data;
  data["recipe_id"]  = r.id;
  data["name"]       = r.name;
  data["call_count"] = static_cast<std::int64_t>(r.calls.size());
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_recipe_list(const Request& req) {
  if (auto e = require_artifact_store(req, artifacts_)) return *e;
  ldb::store::RecipeStore rs(*artifacts_);
  auto recipes = rs.list();
  json arr = json::array();
  for (const auto& r : recipes) arr.push_back(recipe_to_summary_json(r));
  json data;
  data["recipes"] = std::move(arr);
  data["total"]   = static_cast<std::int64_t>(recipes.size());
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_recipe_get(const Request& req) {
  if (auto e = require_artifact_store(req, artifacts_)) return *e;
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::int64_t id = 0;
  if (auto it = req.params.find("recipe_id");
      it != req.params.end() && !it->is_null()) {
    if (it->is_number_integer()) {
      id = it->get<std::int64_t>();
    } else if (it->is_number_unsigned()) {
      id = static_cast<std::int64_t>(it->get<std::uint64_t>());
    } else {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'recipe_id' must be an integer");
    }
  } else {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing integer param 'recipe_id'");
  }

  ldb::store::RecipeStore rs(*artifacts_);
  auto r = rs.get(id);
  if (!r.has_value()) {
    return protocol::make_err(req.id, ErrorCode::kBackendError,
                              "recipe not found: " + std::to_string(id));
  }
  return protocol::make_ok(req.id, recipe_to_full_json(*r));
}

Response Dispatcher::handle_recipe_delete(const Request& req) {
  if (auto e = require_artifact_store(req, artifacts_)) return *e;
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::int64_t id = 0;
  if (auto it = req.params.find("recipe_id");
      it != req.params.end() && !it->is_null()) {
    if (it->is_number_integer()) {
      id = it->get<std::int64_t>();
    } else if (it->is_number_unsigned()) {
      id = static_cast<std::int64_t>(it->get<std::uint64_t>());
    } else {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'recipe_id' must be an integer");
    }
  } else {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing integer param 'recipe_id'");
  }

  ldb::store::RecipeStore rs(*artifacts_);
  bool deleted = rs.remove(id);
  json data;
  data["recipe_id"] = id;
  data["deleted"]   = deleted;
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_recipe_lint(const Request& req) {
  if (auto e = require_artifact_store(req, artifacts_)) return *e;
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::int64_t id = 0;
  if (auto it = req.params.find("recipe_id");
      it != req.params.end() && !it->is_null()) {
    if (it->is_number_integer()) {
      id = it->get<std::int64_t>();
    } else if (it->is_number_unsigned()) {
      id = static_cast<std::int64_t>(it->get<std::uint64_t>());
    } else {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'recipe_id' must be an integer");
    }
  } else {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing integer param 'recipe_id'");
  }

  ldb::store::RecipeStore rs(*artifacts_);
  auto r = rs.get(id);
  if (!r.has_value()) {
    return protocol::make_err(req.id, ErrorCode::kBackendError,
                              "recipe not found: " + std::to_string(id));
  }

  std::vector<ldb::store::LintWarning> warnings;
  if (r->python_body.has_value()) {
    // python-v1 recipes have no `calls` to lint; the meaningful check
    // is "does the body compile?". Attempt construction; SyntaxError
    // becomes a single LintWarning at step_index=0. Other Python
    // errors at construction time (e.g. missing run() callable) also
    // land here so the agent can fix them before a recipe.run.
    try {
      ldb::python::Callable c(*r->python_body, "<recipe:" + r->name + ">");
      (void)c;  // construction-only lint; don't invoke.
    } catch (const ldb::backend::Error& e) {
      ldb::store::LintWarning w;
      w.step_index = 0;
      w.message    = e.what();
      warnings.push_back(std::move(w));
    }
  } else {
    warnings = ldb::store::lint_recipe(*r);
  }
  json warn_arr = json::array();
  for (const auto& w : warnings) {
    warn_arr.push_back(json{{"step_index", w.step_index},
                            {"message",    w.message}});
  }
  json data;
  data["recipe_id"]    = id;
  data["warning_count"] = static_cast<int>(warnings.size());
  data["warnings"]     = std::move(warn_arr);
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_recipe_reload(const Request& req) {
  if (auto e = require_artifact_store(req, artifacts_)) return *e;
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::int64_t id = 0;
  if (auto it = req.params.find("recipe_id");
      it != req.params.end() && !it->is_null()) {
    if (it->is_number_integer()) {
      id = it->get<std::int64_t>();
    } else if (it->is_number_unsigned()) {
      id = static_cast<std::int64_t>(it->get<std::uint64_t>());
    } else {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'recipe_id' must be an integer");
    }
  } else {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing integer param 'recipe_id'");
  }

  ldb::store::RecipeStore rs(*artifacts_);
  ldb::store::Recipe reloaded;
  try {
    reloaded = rs.reload(id);
  } catch (const ldb::backend::Error& e) {
    const std::string what = e.what();
    if (what.find("no source_path") != std::string::npos) {
      return protocol::make_err(req.id, ErrorCode::kForbidden, what);
    }
    if (what.find("not found") != std::string::npos) {
      return protocol::make_err(req.id, ErrorCode::kBackendError, what);
    }
    if (what.find("no such file") != std::string::npos ||
        what.find("cannot open") != std::string::npos) {
      return protocol::make_err(req.id, ErrorCode::kBadState, what);
    }
    if (what.find("malformed") != std::string::npos ||
        what.find("missing top-level") != std::string::npos) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams, what);
    }
    return protocol::make_err(req.id, ErrorCode::kBackendError, what);
  }

  auto warnings = ldb::store::lint_recipe(reloaded);
  json warn_arr = json::array();
  for (const auto& w : warnings) {
    warn_arr.push_back(json{{"step_index", w.step_index},
                            {"message",    w.message}});
  }
  json data;
  data["recipe_id"]     = reloaded.id;
  data["name"]          = reloaded.name;
  data["call_count"]    = static_cast<int>(reloaded.calls.size());
  data["warning_count"] = static_cast<int>(warnings.size());
  data["warnings"]      = std::move(warn_arr);
  if (reloaded.source_path.has_value()) {
    data["source_path"] = *reloaded.source_path;
  }
  // recipe.reload replaces by name → fresh artifact id. Surface the
  // previous id explicitly so an agent holding `id` knows its handle
  // is now stale.
  if (reloaded.id != id) {
    data["previous_recipe_id"] = id;
  }
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_recipe_run(const Request& req) {
  if (auto e = require_artifact_store(req, artifacts_)) return *e;
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::int64_t id = 0;
  if (auto it = req.params.find("recipe_id");
      it != req.params.end() && !it->is_null()) {
    if (it->is_number_integer()) {
      id = it->get<std::int64_t>();
    } else if (it->is_number_unsigned()) {
      id = static_cast<std::int64_t>(it->get<std::uint64_t>());
    } else {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'recipe_id' must be an integer");
    }
  } else {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing integer param 'recipe_id'");
  }
  json caller_args = json::object();
  if (auto it = req.params.find("parameters");
      it != req.params.end() && !it->is_null()) {
    if (!it->is_object()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'parameters' must be an object");
    }
    caller_args = *it;
  }
  // python-v1 recipes use `args` instead of `parameters` since there is
  // no placeholder substitution — the dict is the literal `ctx` passed
  // into the recipe's `run(ctx)`. Accept both shapes; `args` wins when
  // both are present so callers can keep typed-shape predictability.
  json py_args = caller_args;
  if (auto it = req.params.find("args");
      it != req.params.end() && !it->is_null()) {
    if (!it->is_object()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'args' must be an object");
    }
    py_args = *it;
  }

  ldb::store::RecipeStore rs(*artifacts_);
  auto r = rs.get(id);
  if (!r.has_value()) {
    return protocol::make_err(req.id, ErrorCode::kBackendError,
                              "recipe not found: " + std::to_string(id));
  }

  if (r->python_body.has_value()) {
    if (!ldb::python::Interpreter::available()) {
      return protocol::make_err(req.id, ErrorCode::kBadState,
          "python-v1 recipes require ldbd built with LDB_ENABLE_PYTHON");
    }
    try {
      ldb::python::Callable c(*r->python_body,
                              "<recipe:" + r->name + ">");
      json result = c.invoke(py_args);
      json data;
      data["recipe_id"] = id;
      data["format"]    = "python-v1";
      data["result"]    = std::move(result);
      // Surface captured stdout/stderr so an agent can keep prints
      // useful for debugging without violating the JSON-RPC stdout
      // discipline. Empty strings stay in the response so the shape
      // is stable across runs.
      data["stdout"]    = c.last_stdout();
      data["stderr"]    = c.last_stderr();
      return protocol::make_ok(req.id, std::move(data));
    } catch (const ldb::backend::Error& e) {
      // The embed wrapper sets last_exception_* on the Callable but
      // we've destructed it by now — extract from the message. The
      // wrapper formats as "python: <type>: <msg>"; split on the
      // first ": " after "python:" to recover the structured shape.
      std::string what = e.what();
      json err_data = json::object();
      const std::string prefix = "python: ";
      if (what.rfind(prefix, 0) == 0) {
        std::string rest = what.substr(prefix.size());
        auto colon = rest.find(": ");
        if (colon != std::string::npos) {
          err_data["exception_type"] = rest.substr(0, colon);
          err_data["message"]        = rest.substr(colon + 2);
        } else {
          err_data["exception_type"] = rest;
        }
      }
      return protocol::make_err(req.id, ErrorCode::kBackendError,
                                what, std::move(err_data));
    }
  }

  // Stop-on-first-error policy. The brief asks for either stop or
  // continue; stop matches the typical investigation workflow (a
  // failed target.open invalidates every downstream call) and gives
  // the agent a clean truncation point. Document the policy in
  // returns: callers can examine `responses[-1]` to see what failed.
  json responses = json::array();
  std::int64_t seq = 0;
  for (const auto& call : r->calls) {
    ++seq;
    auto sub = ldb::store::substitute_params(call.params, r->parameters,
                                              caller_args);
    if (!sub.ok) {
      json entry;
      entry["seq"]    = seq;
      entry["method"] = call.method;
      entry["ok"]     = false;
      json err;
      err["code"]    = static_cast<int>(ErrorCode::kInvalidParams);
      err["message"] = sub.error;
      entry["error"] = std::move(err);
      responses.push_back(std::move(entry));
      break;
    }

    // Recursion guard: reject any recipe.* sub-call. recipe.run inside a
    // recipe segfaults the daemon via unbounded dispatch_inner recursion;
    // recipe.create / .from_session inside a recipe is operationally
    // pointless and complicates audit. The agent can compose recipes
    // out-of-band (call recipe.run, then call recipe.run again) — there
    // is no use case for nested recipe calls. Surfaced as -32003
    // kForbidden with a stop-on-first-error truncation, matching the
    // policy for substitution failures above.
    if (call.method.rfind("recipe.", 0) == 0) {
      json entry;
      entry["seq"]    = seq;
      entry["method"] = call.method;
      entry["ok"]     = false;
      json err;
      err["code"]    = static_cast<int>(ErrorCode::kForbidden);
      err["message"] = "recipe.* sub-calls are forbidden inside a recipe "
                       "(would recurse without bound); compose recipes "
                       "out-of-band by calling recipe.run from the agent";
      entry["error"] = std::move(err);
      responses.push_back(std::move(entry));
      break;
    }

    Request sub_req;
    sub_req.id     = std::nullopt;  // sub-calls don't need their own ids
    sub_req.method = call.method;
    sub_req.params = std::move(sub.params);
    Response sub_resp = dispatch_inner(sub_req);

    json entry;
    entry["seq"]    = seq;
    entry["method"] = call.method;
    entry["ok"]     = sub_resp.ok;
    if (sub_resp.ok) {
      entry["data"] = sub_resp.data;
    } else {
      json err;
      err["code"]    = static_cast<int>(sub_resp.error_code);
      err["message"] = sub_resp.error_message;
      if (sub_resp.error_data.has_value()) {
        err["data"] = *sub_resp.error_data;
      }
      entry["error"] = std::move(err);
    }
    bool failed = !sub_resp.ok;
    responses.push_back(std::move(entry));
    if (failed) break;
  }

  json data;
  data["responses"] = std::move(responses);
  data["total"]     = data["responses"].size();
  return protocol::make_ok(req.id, std::move(data));
}

// ----------------------------------------------------------------------------
// probe.* — auto-resuming breakpoints with structured capture (M3 part 3)
//
// All six handlers preflight on the orchestrator being non-null (set by
// the daemon when --store-root resolves and the backend is alive); on a
// null orchestrator they return -32002 (kBadState) so the agent gets a
// typed error instead of a crash.

namespace {

std::optional<Response>
require_probe_orchestrator(const Request& req,
                           const std::shared_ptr<probes::ProbeOrchestrator>& p) {
  if (p) return std::nullopt;
  return protocol::make_err(req.id, ErrorCode::kBadState,
                            "probe orchestrator not configured");
}

bool parse_probe_action(const std::string& s, probes::Action* out) {
  if (s == "log_and_continue" || s.empty()) {
    *out = probes::Action::kLogAndContinue; return true;
  }
  if (s == "stop")            { *out = probes::Action::kStop; return true; }
  if (s == "store_artifact")  { *out = probes::Action::kStoreArtifact; return true; }
  return false;
}

const char* probe_action_str(probes::Action a) {
  switch (a) {
    case probes::Action::kLogAndContinue: return "log_and_continue";
    case probes::Action::kStop:           return "stop";
    case probes::Action::kStoreArtifact:  return "store_artifact";
  }
  return "log_and_continue";
}

json probe_event_to_json(const probes::ProbeEvent& e,
                         const std::string& probe_id) {
  json j;
  j["probe_id"] = probe_id;
  j["hit_seq"]  = e.hit_seq;
  j["ts_ns"]    = e.ts_ns;
  j["tid"]      = e.tid;
  // PC as hex string, matching plan §7.3 ("0x412af0").
  {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx",
                  static_cast<unsigned long long>(e.pc));
    j["pc"] = buf;
  }
  // Registers as {name: "0xVAL"} hex strings.
  json regs = json::object();
  for (const auto& [name, val] : e.registers) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx",
                  static_cast<unsigned long long>(val));
    regs[name] = buf;
  }
  j["registers"] = std::move(regs);

  // Memory captures as {name, bytes_b64}. base64_encode is the
  // earlier anonymous-namespace helper in this TU; it's visible here
  // because all `namespace { ... }` blocks in one TU share the same
  // unnamed namespace.
  json mems = json::array();
  for (const auto& m : e.memory) {
    json mj;
    mj["name"]      = m.name;
    mj["bytes_b64"] = base64_encode(m.bytes);
    mems.push_back(std::move(mj));
  }
  j["memory"] = std::move(mems);

  json site = json::object();
  if (!e.site.function.empty()) site["function"] = e.site.function;
  if (!e.site.file.empty())     site["file"]     = e.site.file;
  if (e.site.line > 0)          site["line"]     = e.site.line;
  j["site"] = std::move(site);

  if (e.artifact_id.has_value())   j["artifact_id"]   = *e.artifact_id;
  if (e.artifact_name.has_value()) j["artifact_name"] = *e.artifact_name;
  return j;
}

json probe_list_entry_to_json(const probes::ProbeOrchestrator::ListEntry& e) {
  json j;
  j["probe_id"]   = e.probe_id;
  j["kind"]       = e.kind;
  j["where_expr"] = e.where_expr;
  j["enabled"]    = e.enabled;
  j["hit_count"]  = e.hit_count;
  return j;
}

}  // namespace

Response Dispatcher::handle_probe_create(const Request& req) {
  if (auto e = require_probe_orchestrator(req, probes_)) return *e;
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::uint64_t target_id = 0;
  // For uprobe_bpf, target_id is OPTIONAL — the BPF engine doesn't
  // attach to an LLDB target. Default to 0; the orchestrator ignores
  // it for that kind.
  bool have_target_id = require_uint(req.params, "target_id", &target_id);
  const auto* kind = require_string(req.params, "kind");
  if (!kind || kind->empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing non-empty string param 'kind'");
  }

  // ---- uprobe_bpf path ---------------------------------------------------
  if (*kind == "uprobe_bpf") {
    auto wit = req.params.find("where");
    if (wit == req.params.end() || !wit->is_object()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "missing object param 'where'");
    }
    probes::BpftraceWhere bw;
    int set = 0;
    if (auto it = wit->find("uprobe");
        it != wit->end() && !it->is_null()) {
      if (!it->is_string()) {
        return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                  "where.uprobe must be string");
      }
      bw.kind = probes::BpftraceWhere::Kind::kUprobe;
      bw.target = it->get<std::string>();
      ++set;
    }
    if (auto it = wit->find("tracepoint");
        it != wit->end() && !it->is_null()) {
      if (!it->is_string()) {
        return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                  "where.tracepoint must be string");
      }
      bw.kind = probes::BpftraceWhere::Kind::kTracepoint;
      bw.target = it->get<std::string>();
      ++set;
    }
    if (auto it = wit->find("kprobe");
        it != wit->end() && !it->is_null()) {
      if (!it->is_string()) {
        return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                  "where.kprobe must be string");
      }
      bw.kind = probes::BpftraceWhere::Kind::kKprobe;
      bw.target = it->get<std::string>();
      ++set;
    }
    if (set == 0 || bw.target.empty()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "where must set exactly one of "
                                "{uprobe, tracepoint, kprobe} (non-empty)");
    }
    if (set > 1) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "where must set exactly one of "
                                "{uprobe, tracepoint, kprobe}");
    }

    std::vector<std::string> bpf_args;
    if (auto cit = req.params.find("capture");
        cit != req.params.end() && cit->is_object()) {
      if (auto ait = cit->find("args");
          ait != cit->end() && !ait->is_null()) {
        if (!ait->is_array()) {
          return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                    "capture.args must be array of string");
        }
        for (const auto& a : *ait) {
          if (!a.is_string()) {
            return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                      "capture.args entries must be strings");
          }
          bpf_args.push_back(a.get<std::string>());
        }
      }
    }

    std::optional<std::int64_t> filter_pid;
    if (auto it = req.params.find("filter_pid");
        it != req.params.end() && !it->is_null()) {
      if (!it->is_number_integer() && !it->is_number_unsigned()) {
        return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                  "filter_pid must be integer");
      }
      filter_pid = it->get<std::int64_t>();
    }

    std::optional<transport::SshHost> remote;
    if (auto it = req.params.find("host");
        it != req.params.end() && !it->is_null()) {
      if (!it->is_string()) {
        return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                  "host must be string");
      }
      transport::SshHost h;
      h.host = it->get<std::string>();
      remote = std::move(h);
    }

    std::string rate_limit;
    if (const auto* rl = require_string(req.params, "rate_limit")) {
      rate_limit = *rl;
    }

    probes::ProbeSpec ps;
    ps.target_id           = static_cast<backend::TargetId>(target_id);
    ps.kind                = "uprobe_bpf";
    ps.bpftrace_where      = std::move(bw);
    ps.bpftrace_args       = std::move(bpf_args);
    ps.bpftrace_filter_pid = filter_pid;
    ps.bpftrace_host       = std::move(remote);
    ps.rate_limit_text     = std::move(rate_limit);

    std::string probe_id;
    try {
      probe_id = probes_->create(ps);
    } catch (const std::invalid_argument& e) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams, e.what());
    }
    // backend::Error from start() (bpftrace missing, attach failed, etc.)
    // propagates through dispatch_inner's catch → -32000.

    json data;
    data["probe_id"] = probe_id;
    data["kind"]     = "uprobe_bpf";
    return protocol::make_ok(req.id, std::move(data));
  }

  // ---- lldb_breakpoint path ---------------------------------------------
  if (!have_target_id) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing uint param 'target_id'");
  }

  // where = {function} | {address} | {file, line}
  auto wit = req.params.find("where");
  if (wit == req.params.end() || !wit->is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing object param 'where'");
  }
  backend::BreakpointSpec where;
  if (auto fit = wit->find("function");
      fit != wit->end() && !fit->is_null()) {
    if (!fit->is_string()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "where.function must be string");
    }
    where.function = fit->get<std::string>();
  }
  if (auto ait = wit->find("address");
      ait != wit->end() && !ait->is_null()) {
    std::uint64_t addr = 0;
    if (ait->is_number_unsigned())     addr = ait->get<std::uint64_t>();
    else if (ait->is_number_integer()) {
      auto v = ait->get<std::int64_t>();
      if (v < 0) {
        return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                  "where.address must be non-negative");
      }
      addr = static_cast<std::uint64_t>(v);
    } else if (ait->is_string()) {
      // Allow "0x..." string form.
      const std::string& s = ait->get_ref<const std::string&>();
      try { addr = std::stoull(s, nullptr, 0); }
      catch (...) {
        return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                  "where.address: invalid integer");
      }
    } else {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "where.address must be uint or hex string");
    }
    where.address = addr;
  }
  if (auto fit = wit->find("file");
      fit != wit->end() && !fit->is_null()) {
    if (!fit->is_string()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "where.file must be string");
    }
    where.file = fit->get<std::string>();
  }
  if (auto lit = wit->find("line");
      lit != wit->end() && !lit->is_null()) {
    if (!lit->is_number_integer() && !lit->is_number_unsigned()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "where.line must be integer");
    }
    where.line = lit->get<int>();
  }
  if (!where.function.has_value() && !where.address.has_value() &&
      !where.file.has_value()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "where must set function, address, or file+line");
  }

  // capture (optional)
  probes::CaptureSpec capture;
  if (auto cit = req.params.find("capture");
      cit != req.params.end() && !cit->is_null()) {
    if (!cit->is_object()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "capture must be object");
    }
    if (auto rit = cit->find("registers");
        rit != cit->end() && !rit->is_null()) {
      if (!rit->is_array()) {
        return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                  "capture.registers must be array of string");
      }
      for (const auto& r : *rit) {
        if (!r.is_string()) {
          return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                    "capture.registers entries must be strings");
        }
        capture.registers.push_back(r.get<std::string>());
      }
    }
    if (auto mit = cit->find("memory");
        mit != cit->end() && !mit->is_null()) {
      if (!mit->is_array()) {
        return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                  "capture.memory must be array");
      }
      for (const auto& m : *mit) {
        if (!m.is_object()) {
          return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                    "capture.memory entries must be objects");
        }
        probes::CaptureSpec::MemSpec ms;
        if (auto rit2 = m.find("reg"); rit2 != m.end() && rit2->is_string()) {
          ms.source   = probes::CaptureSpec::MemSpec::Source::kRegister;
          ms.reg_name = rit2->get<std::string>();
        } else if (auto ait2 = m.find("addr");
                   ait2 != m.end() && !ait2->is_null()) {
          ms.source = probes::CaptureSpec::MemSpec::Source::kAbsolute;
          if (ait2->is_number_unsigned())     ms.addr = ait2->get<std::uint64_t>();
          else if (ait2->is_number_integer()) {
            auto v = ait2->get<std::int64_t>();
            if (v < 0) {
              return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                        "capture.memory.addr must be non-negative");
            }
            ms.addr = static_cast<std::uint64_t>(v);
          } else {
            return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                      "capture.memory.addr must be uint");
          }
        } else {
          return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                    "capture.memory entry must set reg or addr");
        }
        std::uint64_t len = 0;
        if (!require_uint(m, "len", &len) || len == 0) {
          return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                    "capture.memory.len must be positive integer");
        }
        if (len > 1024 * 1024) {
          return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                    "capture.memory.len exceeds 1 MiB cap");
        }
        ms.len = static_cast<std::uint32_t>(len);
        if (auto nit = m.find("name"); nit != m.end() && nit->is_string()) {
          ms.name = nit->get<std::string>();
        }
        capture.memory.push_back(std::move(ms));
      }
    }
  }

  // action (optional, default log_and_continue)
  probes::Action action = probes::Action::kLogAndContinue;
  if (auto ait = req.params.find("action");
      ait != req.params.end() && !ait->is_null()) {
    if (!ait->is_string()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "action must be string");
    }
    if (!parse_probe_action(ait->get<std::string>(), &action)) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "action must be one of: log_and_continue, "
                                "stop, store_artifact");
    }
  }

  std::string artifact_name;
  if (const auto* a = require_string(req.params, "artifact_name")) {
    artifact_name = *a;
  }
  std::string build_id;
  if (const auto* b = require_string(req.params, "build_id")) {
    build_id = *b;
  }
  std::string rate_limit;
  if (const auto* rl = require_string(req.params, "rate_limit")) {
    rate_limit = *rl;
  }

  probes::ProbeSpec ps;
  ps.target_id              = static_cast<backend::TargetId>(target_id);
  ps.kind                   = *kind;
  ps.where                  = std::move(where);
  ps.capture                = std::move(capture);
  ps.action                 = action;
  ps.artifact_name_template = std::move(artifact_name);
  ps.build_id               = std::move(build_id);
  ps.rate_limit_text        = std::move(rate_limit);

  std::string probe_id;
  try {
    probe_id = probes_->create(ps);
  } catch (const std::invalid_argument& e) {
    // Spec problem (bad action/kind combo) — agent's fault.
    return protocol::make_err(req.id, ErrorCode::kInvalidParams, e.what());
  }
  // Backend errors propagate through the outer dispatch_inner catch.

  // Look up the bp_id via list() — the orchestrator doesn't expose it
  // directly, but list() carries probe_id and we have the freshly-
  // returned id. We need bp_id to satisfy the documented response
  // shape. Read from the orchestrator's info() — in this slice the
  // ListEntry doesn't carry bp_id; that's intentional, the agent has
  // no use for the raw id. Documented in the response shape.
  json data;
  data["probe_id"] = probe_id;
  data["action"]   = probe_action_str(action);
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_probe_events(const Request& req) {
  if (auto e = require_probe_orchestrator(req, probes_)) return *e;
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  const auto* probe_id = require_string(req.params, "probe_id");
  if (!probe_id || probe_id->empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing non-empty string param 'probe_id'");
  }
  std::uint64_t since = 0;
  if (auto it = req.params.find("since"); it != req.params.end()) {
    if (!require_uint(req.params, "since", &since)) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'since' must be a non-negative integer");
    }
  }
  std::uint64_t max = 0;
  if (auto it = req.params.find("max"); it != req.params.end()) {
    if (!require_uint(req.params, "max", &max)) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "'max' must be a non-negative integer");
    }
  }

  auto evs = probes_->events(*probe_id, since, max);
  json arr = json::array();
  std::uint64_t next_since = since;
  for (const auto& e : evs) {
    if (e.hit_seq > next_since) next_since = e.hit_seq;
    arr.push_back(probe_event_to_json(e, *probe_id));
  }
  json data;
  data["events"]     = std::move(arr);
  data["total"]      = static_cast<std::int64_t>(evs.size());
  data["next_since"] = next_since;
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_probe_list(const Request& req) {
  if (auto e = require_probe_orchestrator(req, probes_)) return *e;
  auto rows = probes_->list();
  json arr = json::array();
  for (const auto& e : rows) arr.push_back(probe_list_entry_to_json(e));
  json data;
  data["probes"] = std::move(arr);
  data["total"]  = static_cast<std::int64_t>(rows.size());
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_probe_disable(const Request& req) {
  if (auto e = require_probe_orchestrator(req, probes_)) return *e;
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  const auto* probe_id = require_string(req.params, "probe_id");
  if (!probe_id || probe_id->empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing non-empty string param 'probe_id'");
  }
  probes_->disable(*probe_id);
  json data;
  data["probe_id"] = *probe_id;
  data["enabled"]  = false;
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_probe_enable(const Request& req) {
  if (auto e = require_probe_orchestrator(req, probes_)) return *e;
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  const auto* probe_id = require_string(req.params, "probe_id");
  if (!probe_id || probe_id->empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing non-empty string param 'probe_id'");
  }
  probes_->enable(*probe_id);
  json data;
  data["probe_id"] = *probe_id;
  data["enabled"]  = true;
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_probe_delete(const Request& req) {
  if (auto e = require_probe_orchestrator(req, probes_)) return *e;
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  const auto* probe_id = require_string(req.params, "probe_id");
  if (!probe_id || probe_id->empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing non-empty string param 'probe_id'");
  }
  probes_->remove(*probe_id);
  json data;
  data["probe_id"] = *probe_id;
  data["deleted"]  = true;
  return protocol::make_ok(req.id, std::move(data));
}

// ---- perf.* handlers (post-V1 plan #13) --------------------------------
//
// See docs/22-perf-integration.md. The runner is synchronous in phase 1
// (perf.record blocks for `duration_ms`); perf.cancel is wired in
// `describe.endpoints` for catalog completeness and returns
// kBadState until the async variant lands.

namespace {

json perf_sample_to_view_json(const ldb::perf::Sample& s) {
  return ldb::perf::PerfParser::sample_to_json(s);
}

}  // namespace

Response Dispatcher::handle_perf_record(const Request& req) {
  if (auto e = require_artifact_store(req, artifacts_)) return *e;
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }

  ldb::perf::RecordSpec spec;

  // pid xor command
  bool have_pid = false;
  std::int64_t pid_v = 0;
  if (auto it = req.params.find("pid");
      it != req.params.end() && !it->is_null()) {
    if (!it->is_number_integer() && !it->is_number_unsigned()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "pid must be integer");
    }
    pid_v = it->get<std::int64_t>();
    if (pid_v <= 0) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "pid must be positive");
    }
    have_pid = true;
  }
  bool have_cmd = false;
  if (auto it = req.params.find("command");
      it != req.params.end() && !it->is_null()) {
    if (!it->is_array()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "command must be array of string");
    }
    for (const auto& a : *it) {
      if (!a.is_string()) {
        return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                  "command entries must be strings");
      }
      spec.command.push_back(a.get<std::string>());
    }
    have_cmd = !spec.command.empty();
  }
  if (have_pid == have_cmd) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "exactly one of pid|command must be set");
  }
  if (have_pid) spec.pid = pid_v;

  // perf record -- <cmd> execs <cmd> directly after the trace interval;
  // a JSON-RPC client supplying `command` is requesting arbitrary process
  // spawn. Route it through the same operator-policy allowlist as
  // observer.exec instead of trusting the wire. pid mode is fine —
  // observer-side decision about which pids the agent can sample is
  // outside this surface (it's kernel + perf_event_paranoid territory).
  if (have_cmd) {
    if (!exec_allowlist_) {
      return protocol::make_err(req.id, ErrorCode::kBadState,
          "perf.record command mode disabled — no allowlist configured. "
          "Set --observer-exec-allowlist or LDB_OBSERVER_EXEC_ALLOWLIST, "
          "or use pid mode against an already-running process.");
    }
    if (!exec_allowlist_->allows(spec.command)) {
      return protocol::make_err(req.id, ErrorCode::kForbidden,
          "perf.record: command not allowed by operator policy");
    }
  }

  // duration_ms (uint). Required for pid mode; optional for command mode
  // (the command's lifetime is the trace duration), but if supplied we
  // still cap-check.
  std::uint64_t duration_ms = 0;
  if (auto it = req.params.find("duration_ms");
      it != req.params.end() && !it->is_null()) {
    if (!require_uint(req.params, "duration_ms", &duration_ms)) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "duration_ms must be non-negative integer");
    }
    spec.duration = std::chrono::milliseconds(static_cast<long long>(duration_ms));
  } else if (have_pid) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "duration_ms required when pid is set");
  }

  // 10 kHz upper bound. Above this, sampling pressure starts producing
  // multi-GB perf.data files in a 5-minute trace and the kernel itself
  // typically throttles unprivileged perf at 1 kHz anyway. Daemon-side
  // cap is the cheap guard before disk/RAM exhaustion (see also the
  // perf.data size cap below).
  constexpr std::uint64_t kMaxFrequencyHz = 10000;
  std::uint64_t freq = 0;
  if (auto it = req.params.find("frequency_hz");
      it != req.params.end() && !it->is_null()) {
    if (!require_uint(req.params, "frequency_hz", &freq) || freq == 0) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "frequency_hz must be positive integer");
    }
    if (freq > kMaxFrequencyHz) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
          "frequency_hz exceeds " + std::to_string(kMaxFrequencyHz)
            + " Hz daemon cap");
    }
    spec.frequency_hz = static_cast<std::uint32_t>(freq);
  }

  if (auto it = req.params.find("events");
      it != req.params.end() && !it->is_null()) {
    if (!it->is_array()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "events must be array of string");
    }
    for (const auto& a : *it) {
      if (!a.is_string()) {
        return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                  "events entries must be strings");
      }
      std::string ev = a.get<std::string>();
      if (ev.empty()) {
        return protocol::make_err(req.id, ErrorCode::kInvalidParams,
            "events entries must be non-empty strings");
      }
      spec.events.push_back(std::move(ev));
    }
  }

  if (const auto* cg = require_string(req.params, "call_graph")) {
    if (!cg->empty() && *cg != "fp" && *cg != "dwarf" && *cg != "lbr") {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "call_graph must be one of {fp, dwarf, lbr}");
    }
    spec.call_graph = *cg;
  }

  std::string build_id = "_perf";
  if (const auto* bi = require_string(req.params, "build_id"); bi && !bi->empty()) {
    build_id = *bi;
  }

  // Execute. perf::PerfRunner throws backend::Error on subprocess
  // failure; the dispatcher's outer catch maps that to -32000.
  ldb::perf::RecordResult result = ldb::perf::PerfRunner::record(spec);

  // Slurp the perf.data file into the ArtifactStore. The cap exists
  // because perf record at high frequency with --call-graph dwarf can
  // emit multi-GB traces; blindly resize()-ing into RAM and copying to
  // the artifact store would put 2x that on disk plus 1x in memory.
  // 256 MiB is comfortable for typical 5-minute traces at 99 Hz fp
  // call-graph; agents who genuinely need more can chunk by time.
  constexpr std::streamsize kMaxPerfDataBytes =
      static_cast<std::streamsize>(256) * 1024 * 1024;
  std::vector<std::uint8_t> blob;
  {
    std::ifstream f(result.perf_data_path, std::ios::binary);
    if (!f) {
      ::unlink(result.perf_data_path.c_str());
      return protocol::make_err(req.id, ErrorCode::kBackendError,
                                "perf record succeeded but the perf.data "
                                "temp file is unreadable");
    }
    f.seekg(0, std::ios::end);
    std::streamsize sz = f.tellg();
    if (sz < 0) sz = 0;
    if (sz > kMaxPerfDataBytes) {
      ::unlink(result.perf_data_path.c_str());
      return protocol::make_err(req.id, ErrorCode::kBackendError,
          "perf.data exceeds daemon cap (" + std::to_string(sz)
            + " > " + std::to_string(kMaxPerfDataBytes)
            + " bytes); shorten duration_ms, lower frequency_hz, or "
              "drop --call-graph dwarf");
    }
    f.seekg(0, std::ios::beg);
    blob.resize(static_cast<std::size_t>(sz));
    if (sz > 0) f.read(reinterpret_cast<char*>(blob.data()), sz);
  }
  ::unlink(result.perf_data_path.c_str());

  // Name with a UTC timestamp suffix so multiple records on the same
  // build_id don't collide.
  std::string artifact_name;
  {
    auto t = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now());
    struct tm tm_buf{};
    gmtime_r(&t, &tm_buf);
    char buf[64];
    std::strftime(buf, sizeof(buf), "perf-%Y%m%dT%H%M%SZ.data", &tm_buf);
    artifact_name = buf;
  }

  json meta = json::object();
  meta["perf_argv"]      = result.perf_argv;
  meta["sample_count"]   = result.parsed.samples.size();
  meta["parse_errors"]   = result.parsed.parse_errors;
  if (!result.parsed.hostname.empty())   meta["hostname"]   = result.parsed.hostname;
  if (!result.parsed.os_release.empty()) meta["os_release"] = result.parsed.os_release;
  if (!result.parsed.arch.empty())       meta["arch"]       = result.parsed.arch;

  ldb::store::ArtifactRow row;
  try {
    row = artifacts_->put(build_id, artifact_name, blob,
                          std::string("perf.data"), meta);
  } catch (const backend::Error& e) {
    return protocol::make_err(req.id, ErrorCode::kBackendError,
                              std::string("artifact store put failed: ")
                                  + e.what());
  }

  json data;
  data["artifact_id"]   = row.id;
  data["artifact_name"] = row.name;
  data["sample_count"]  = result.parsed.samples.size();
  data["duration_ms"]   = result.wall_duration.count();
  data["perf_argv"]     = result.perf_argv;
  data["stderr_tail"]   = result.stderr_tail;
  data["parse_errors"]  = result.parsed.parse_errors;
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_perf_report(const Request& req) {
  if (auto e = require_artifact_store(req, artifacts_)) return *e;
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  std::uint64_t artifact_id = 0;
  if (!require_uint(req.params, "artifact_id", &artifact_id) || artifact_id == 0) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "artifact_id must be positive integer");
  }
  std::uint64_t max_samples = 0;
  if (auto it = req.params.find("max_samples");
      it != req.params.end() && !it->is_null()) {
    if (!require_uint(req.params, "max_samples", &max_samples)) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "max_samples must be non-negative integer");
    }
  }
  std::uint64_t max_stack = 0;
  if (auto it = req.params.find("max_stack_depth");
      it != req.params.end() && !it->is_null()) {
    if (!require_uint(req.params, "max_stack_depth", &max_stack)) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "max_stack_depth must be non-negative integer");
    }
  }

  auto row_opt = artifacts_->get_by_id(static_cast<std::int64_t>(artifact_id));
  if (!row_opt) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "artifact_id not found");
  }

  ldb::perf::ReportSpec rs;
  rs.perf_data_path  = row_opt->stored_path;
  rs.max_samples     = static_cast<std::int64_t>(max_samples);
  rs.max_stack_depth = static_cast<std::int64_t>(max_stack);

  ldb::perf::ReportResult result = ldb::perf::PerfRunner::report(rs);

  json arr = json::array();
  for (const auto& s : result.parsed.samples) {
    arr.push_back(perf_sample_to_view_json(s));
  }
  json data;
  data["samples"]        = std::move(arr);
  // `total` is the pre-truncation count so an agent capping with
  // max_samples can tell whether to widen the cap. Mirrors what
  // view::apply_to_array does for paginated read-path endpoints.
  data["total"]          = result.total_samples;
  data["truncated"]      = result.truncated;
  data["perf_data_size"] = row_opt->byte_size;
  data["parse_errors"]   = result.parsed.parse_errors;
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_perf_cancel(const Request& req) {
  // Phase 1: perf.record is synchronous, so there's never anything to
  // cancel. We return -32002 kBadState with a deterministic message so
  // an agent can detect "this build does not support async record".
  // Even param-malformed cases get this error preferentially — the
  // surface is intentionally trivial.
  if (!req.params.is_object() || !req.params.contains("record_id")) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "record_id required");
  }
  return protocol::make_err(req.id, ErrorCode::kBadState,
                            "perf.record is synchronous in this build; "
                            "no in-flight record to cancel");
}

// ---- observer.* handlers ------------------------------------------------
//
// All four endpoints share the same plumbing:
//   1. validate the params (pid is positive int; host is optional string),
//   2. translate `host` → optional<transport::SshHost>,
//   3. call into observers::fetch_*,
//   4. shape the result into JSON (arrays go through view::apply_to_array
//      so the standard {limit, offset, fields, summary} controls work).
//
// observers::* throws backend::Error on transport failure / non-zero
// remote exit / parse failure; the dispatcher's catch translates to
// kBackendError. Param-validation errors stay in the handler so they
// surface as kInvalidParams.

namespace {

// Convert the dispatcher's "host?" param into the optional<SshHost>
// expected by the observers. Empty string ≡ absent. host.port and
// host.ssh_options are deferred to a future slice — agents who need
// them will hit observer.* endpoints with `host` set to a config-key
// in their ~/.ssh/config.
std::optional<ldb::transport::SshHost>
observer_host_from_params(const json& params) {
  auto it = params.find("host");
  if (it == params.end() || !it->is_string()) return std::nullopt;
  std::string h = it->get<std::string>();
  if (h.empty()) return std::nullopt;
  ldb::transport::SshHost out;
  out.host = std::move(h);
  return out;
}

// Validate "pid" param. Returns nullopt + an error response on failure.
// Negative / zero pid → -32602 (caller invariant).
std::optional<protocol::Response>
require_positive_pid(const protocol::Request& req, std::int32_t* out) {
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  auto it = req.params.find("pid");
  if (it == req.params.end()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing int param 'pid'");
  }
  if (it->is_number_integer()) {
    auto v = it->get<std::int64_t>();
    if (v <= 0 || v > std::numeric_limits<std::int32_t>::max()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "param 'pid' must be a positive int32");
    }
    *out = static_cast<std::int32_t>(v);
    return std::nullopt;
  }
  if (it->is_number_unsigned()) {
    auto v = it->get<std::uint64_t>();
    if (v == 0 ||
        v > static_cast<std::uint64_t>(std::numeric_limits<std::int32_t>::max())) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "param 'pid' must be a positive int32");
    }
    *out = static_cast<std::int32_t>(v);
    return std::nullopt;
  }
  return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                            "param 'pid' must be an integer");
}

json fd_entry_to_json(const ldb::observers::FdEntry& e) {
  json j;
  j["fd"]     = e.fd;
  j["target"] = e.target;
  j["type"]   = e.type;
  return j;
}

json maps_region_to_json(const ldb::observers::MapsRegion& r) {
  json j;
  j["start"]  = r.start;
  j["end"]    = r.end;
  j["perm"]   = r.perm;
  j["offset"] = r.offset;
  j["dev"]    = r.dev;
  j["inode"]  = r.inode;
  if (r.path.has_value()) j["path"] = *r.path;
  return j;
}

json proc_status_to_json_obs(const ldb::observers::ProcStatus& s) {
  json j;
  j["name"]  = s.name;
  if (s.pid.has_value())        j["pid"]        = *s.pid;
  if (s.ppid.has_value())       j["ppid"]       = *s.ppid;
  j["state"] = s.state;
  if (s.uid.has_value())        j["uid"]        = *s.uid;
  if (s.gid.has_value())        j["gid"]        = *s.gid;
  if (s.threads.has_value())    j["threads"]    = *s.threads;
  if (s.vm_rss_kb.has_value())  j["vm_rss_kb"]  = *s.vm_rss_kb;
  if (s.vm_size_kb.has_value()) j["vm_size_kb"] = *s.vm_size_kb;
  if (s.vm_peak_kb.has_value()) j["vm_peak_kb"] = *s.vm_peak_kb;
  if (s.fd_size.has_value())    j["fd_size"]    = *s.fd_size;
  json raw = json::array();
  for (const auto& kv : s.raw_fields) {
    json e;
    e["key"]   = kv.first;
    e["value"] = kv.second;
    raw.push_back(std::move(e));
  }
  j["raw_fields"] = std::move(raw);
  return j;
}

json socket_entry_to_json(const ldb::observers::SocketEntry& s) {
  json j;
  j["proto"] = s.proto;
  j["state"] = s.state;
  j["local"] = s.local;
  j["peer"]  = s.peer;
  if (s.pid.has_value())  j["pid"]  = *s.pid;
  if (s.comm.has_value()) j["comm"] = *s.comm;
  if (s.fd.has_value())   j["fd"]   = *s.fd;
  return j;
}

json igmp_address_to_json(const ldb::observers::IgmpAddress& a) {
  json j;
  j["address"] = a.address;
  j["users"]   = a.users;
  j["timer"]   = a.timer;
  return j;
}

json igmp_group_to_json(const ldb::observers::IgmpGroup& g) {
  json j;
  j["idx"]    = g.idx;
  j["device"] = g.device;
  if (g.count.has_value())   j["count"]   = *g.count;
  if (g.querier.has_value()) j["querier"] = *g.querier;
  json arr = json::array();
  for (const auto& a : g.addresses) arr.push_back(igmp_address_to_json(a));
  j["addresses"] = std::move(arr);
  return j;
}

}  // namespace

Response Dispatcher::handle_observer_proc_fds(const Request& req) {
  std::int32_t pid = 0;
  if (auto e = require_positive_pid(req, &pid)) return *e;
  auto remote = observer_host_from_params(req.params);
  auto view_spec = protocol::view::parse_from_params(req.params);

  auto r = ldb::observers::fetch_proc_fds(remote, pid);
  json arr = json::array();
  for (const auto& e : r.fds) arr.push_back(fd_entry_to_json(e));
  return protocol::make_ok(req.id,
      protocol::view::apply_to_array(std::move(arr), view_spec, "fds"));
}

Response Dispatcher::handle_observer_proc_maps(const Request& req) {
  std::int32_t pid = 0;
  if (auto e = require_positive_pid(req, &pid)) return *e;
  auto remote = observer_host_from_params(req.params);
  auto view_spec = protocol::view::parse_from_params(req.params);

  auto r = ldb::observers::fetch_proc_maps(remote, pid);
  json arr = json::array();
  for (const auto& reg : r.regions) arr.push_back(maps_region_to_json(reg));
  return protocol::make_ok(req.id,
      protocol::view::apply_to_array(std::move(arr), view_spec, "regions"));
}

Response Dispatcher::handle_observer_proc_status(const Request& req) {
  std::int32_t pid = 0;
  if (auto e = require_positive_pid(req, &pid)) return *e;
  auto remote = observer_host_from_params(req.params);

  auto r = ldb::observers::fetch_proc_status(remote, pid);
  return protocol::make_ok(req.id, proc_status_to_json_obs(r));
}

Response Dispatcher::handle_observer_net_sockets(const Request& req) {
  // No required params; both host and filter are optional.
  std::optional<ldb::transport::SshHost> remote;
  std::string filter;
  if (req.params.is_object()) {
    remote = observer_host_from_params(req.params);
    if (auto it = req.params.find("filter");
        it != req.params.end() && it->is_string()) {
      filter = it->get<std::string>();
    }
  }
  auto view_spec = protocol::view::parse_from_params(
      req.params.is_object() ? req.params : json::object());

  auto r = ldb::observers::fetch_net_sockets(remote, filter);
  json arr = json::array();
  for (const auto& s : r.sockets) arr.push_back(socket_entry_to_json(s));
  return protocol::make_ok(req.id,
      protocol::view::apply_to_array(std::move(arr), view_spec, "sockets"));
}

namespace {

json packet_entry_to_json(const ldb::observers::PacketEntry& p) {
  json j;
  // `ts` is the canonical wire name (epoch float seconds). `ts_epoch`
  // is the C++ struct field name; we don't expose the C++-y suffix on
  // the wire — agents reading the JSON care about "what timestamp,"
  // not "in what epoch flavor."
  j["ts"]      = p.ts_epoch;
  j["summary"] = p.summary;
  if (p.iface.has_value()) j["iface"] = *p.iface;
  if (p.src.has_value())   j["src"]   = *p.src;
  if (p.dst.has_value())   j["dst"]   = *p.dst;
  if (p.proto.has_value()) j["proto"] = *p.proto;
  if (p.len.has_value())   j["len"]   = *p.len;
  return j;
}

}  // namespace

Response Dispatcher::handle_observer_net_tcpdump(const Request& req) {
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }
  // iface (required, non-empty string)
  auto it = req.params.find("iface");
  if (it == req.params.end() || !it->is_string()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing string param 'iface'");
  }
  std::string iface = it->get<std::string>();
  if (iface.empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "param 'iface' must be non-empty");
  }
  // count (required, positive int ≤ 10000)
  auto it_c = req.params.find("count");
  if (it_c == req.params.end()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "missing int param 'count'");
  }
  std::int64_t count_signed = 0;
  if (it_c->is_number_integer()) {
    count_signed = it_c->get<std::int64_t>();
  } else if (it_c->is_number_unsigned()) {
    auto u = it_c->get<std::uint64_t>();
    if (u > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "param 'count' out of range");
    }
    count_signed = static_cast<std::int64_t>(u);
  } else {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "param 'count' must be an integer");
  }
  if (count_signed <= 0 || count_signed > 10000) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "param 'count' out of range (1..10000)");
  }
  // snaplen (optional, 1..65535)
  std::optional<std::uint32_t> snaplen;
  if (auto it_s = req.params.find("snaplen"); it_s != req.params.end()) {
    if (!it_s->is_number_integer() && !it_s->is_number_unsigned()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "param 'snaplen' must be an integer");
    }
    std::int64_t s = it_s->is_number_integer()
                       ? it_s->get<std::int64_t>()
                       : static_cast<std::int64_t>(it_s->get<std::uint64_t>());
    if (s <= 0 || s > 65535) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "param 'snaplen' out of range (1..65535)");
    }
    snaplen = static_cast<std::uint32_t>(s);
  }
  // bpf (optional string)
  std::optional<std::string> bpf;
  if (auto it_b = req.params.find("bpf");
      it_b != req.params.end() && it_b->is_string()) {
    std::string v = it_b->get<std::string>();
    if (!v.empty()) bpf = std::move(v);
  }

  auto view_spec = protocol::view::parse_from_params(req.params);

  ldb::observers::TcpdumpRequest tr;
  tr.iface   = std::move(iface);
  tr.count   = static_cast<std::uint32_t>(count_signed);
  tr.snaplen = snaplen;
  tr.bpf     = std::move(bpf);
  tr.remote  = observer_host_from_params(req.params);
  // tr.timeout stays at the default 30 s; future versions may surface
  // a `timeout_ms` param if agents want to capture longer.

  auto r = ldb::observers::tcpdump(tr);
  json arr = json::array();
  for (const auto& p : r.packets) arr.push_back(packet_entry_to_json(p));
  json data = protocol::view::apply_to_array(std::move(arr), view_spec,
                                             "packets");
  // apply_to_array sets `total` to the original (pre-view) array size,
  // which matches `r.total` — so we don't overwrite it.
  data["truncated"] = r.truncated;
  return protocol::make_ok(req.id, std::move(data));
}

Response Dispatcher::handle_observer_net_igmp(const Request& req) {
  // No required params; only optional `host`.
  std::optional<ldb::transport::SshHost> remote;
  if (req.params.is_object()) {
    remote = observer_host_from_params(req.params);
  }
  auto view_spec = protocol::view::parse_from_params(
      req.params.is_object() ? req.params : json::object());

  auto r = ldb::observers::list_igmp(remote);
  json arr = json::array();
  for (const auto& g : r.groups) arr.push_back(igmp_group_to_json(g));
  return protocol::make_ok(req.id,
      protocol::view::apply_to_array(std::move(arr), view_spec, "groups"));
}

// ---- observer.exec -----------------------------------------------------
//
// The escape-hatch endpoint from §4.6. This is the ONLY observer.* that
// runs operator-supplied argv; the others run hardcoded argv against an
// operator-supplied integer pid. The wire shape is bounded (argv array,
// not a single shell string) so we never compose a /bin/sh -c command;
// each argv element is passed verbatim through posix_spawnp (local) or
// shell-quoted by ssh_exec (remote).
//
// Off-by-default policy: if no allowlist was wired in at startup we
// return -32002 immediately. If one IS wired, we still verify the
// joined argv matches one of the operator's patterns; misses are
// -32003 (kForbidden). The dispatcher does NOT echo the allowlist
// patterns back to the agent — the contents are operator policy and
// the agent learns by attempting and seeing the typed error.

Response Dispatcher::handle_observer_exec(const Request& req) {
  if (!exec_allowlist_) {
    return protocol::make_err(req.id, ErrorCode::kBadState,
        "observer.exec disabled — no allowlist configured. Set "
        "--observer-exec-allowlist or LDB_OBSERVER_EXEC_ALLOWLIST to a "
        "file containing one allowed argv pattern per line.");
  }
  if (!req.params.is_object()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "params must be object");
  }

  // argv: required, non-empty, all-strings.
  auto it = req.params.find("argv");
  if (it == req.params.end() || !it->is_array() || it->empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
        "missing or empty array param 'argv'");
  }
  std::vector<std::string> argv;
  argv.reserve(it->size());
  for (const auto& e : *it) {
    if (!e.is_string()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
          "param 'argv' must be array of string");
    }
    argv.push_back(e.get<std::string>());
  }

  // argv[0] resolution rule: absolute path, OR a bare basename (no '/').
  // Relative paths like ./foo or ../foo are agent mistakes, not policy.
  const std::string& arg0 = argv[0];
  if (arg0.empty()) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                              "param 'argv[0]' must be non-empty");
  }
  const bool absolute = arg0.front() == '/';
  const bool basename = arg0.find('/') == std::string::npos;
  if (!absolute && !basename) {
    return protocol::make_err(req.id, ErrorCode::kInvalidParams,
        "param 'argv[0]' must be an absolute path or a bare basename "
        "on PATH (relative paths like ./foo, ../bar are rejected)");
  }

  // timeout_ms: optional, default 30s, max 300s.
  std::chrono::milliseconds timeout = std::chrono::seconds(30);
  if (auto t = req.params.find("timeout_ms");
      t != req.params.end() && !t->is_null()) {
    if (!t->is_number_unsigned() && !t->is_number_integer()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "param 'timeout_ms' must be uint");
    }
    auto v = t->get<std::int64_t>();
    if (v <= 0 || v > 300000) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "param 'timeout_ms' must be in 1..300000");
    }
    timeout = std::chrono::milliseconds(v);
  }

  // stdin: optional string, capped at 64 KiB.
  std::string stdin_data;
  if (auto s = req.params.find("stdin");
      s != req.params.end() && !s->is_null()) {
    if (!s->is_string()) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
                                "param 'stdin' must be string");
    }
    stdin_data = s->get<std::string>();
    if (stdin_data.size() > 64 * 1024) {
      return protocol::make_err(req.id, ErrorCode::kInvalidParams,
          "param 'stdin' exceeds 64 KiB cap");
    }
  }

  auto remote = observer_host_from_params(req.params);

  // Allowlist check is the last gate before transport.
  if (!exec_allowlist_->allows(argv)) {
    return protocol::make_err(req.id, ErrorCode::kForbidden,
        "observer.exec: argv not allowed by operator policy");
  }

  ldb::observers::ExecRequest ereq;
  ereq.argv       = std::move(argv);
  ereq.remote     = std::move(remote);
  ereq.timeout    = timeout;
  ereq.stdin_data = std::move(stdin_data);

  auto er = ldb::observers::run_observer_exec(*exec_allowlist_, ereq);

  json data;
  data["stdout"]      = er.stdout_data;
  data["stderr"]      = er.stderr_data;
  data["exit_code"]   = er.exit_code;
  data["duration_ms"] = static_cast<std::uint64_t>(er.duration.count());
  if (er.stdout_truncated || er.stderr_truncated || er.timed_out) {
    data["truncated"] = true;
  }
  return protocol::make_ok(req.id, std::move(data));
}

}  // namespace ldb::daemon
