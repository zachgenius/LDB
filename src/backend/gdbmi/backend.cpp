// SPDX-License-Identifier: Apache-2.0
#include "backend/gdbmi/backend.h"

#include "util/log.h"
#include "util/sha256.h"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace ldb::backend::gdbmi {

// ── Impl ──────────────────────────────────────────────────────────────
//
// Each TargetId owns its own gdb subprocess (one inferior per session).
// Multi-inferior-in-one-gdb is supported by MI but materially more
// complex (per-inferior thread namespace, target-select state); a
// session-per-target trades a small RSS hit for clean isolation.

struct TargetState {
  std::unique_ptr<GdbMiSession>                       session;
  std::optional<std::string>                          exe_path;
  std::optional<std::string>                          core_path;
  std::optional<std::string>                          label;
  std::vector<std::unique_ptr<
      DebuggerBackend::TargetResource>>               resources;
  // Cached on first launch/attach so subsequent get_process_state
  // calls can report kRunning vs kStopped without re-issuing MI.
  ProcessStatus                                       last_status;
};

struct GdbMiBackend::Impl {
  std::mutex                                                 mu;
  std::atomic<TargetId>                                      next_id{1};
  std::unordered_map<TargetId, std::unique_ptr<TargetState>> targets;
  std::unordered_map<std::string, TargetId>                  label_owners;
};

// ── Helpers ───────────────────────────────────────────────────────────

namespace {

// `not implemented yet` stub used by virtuals that will land in later
// commits. Surfaces through the dispatcher as -32000 backend error,
// which is the right shape for "this backend doesn't do that yet."
[[noreturn]] void todo(const char* method) {
  throw Error(std::string("GdbMiBackend::") + method +
              ": not implemented yet (post-V1 #8 staged work)");
}

// Pull the message out of `^error,msg="..."` payloads. Empty string
// for non-error records.
std::string error_msg_of(const MiRecord& r) {
  if (r.kind != MiRecordKind::kResult) return {};
  if (r.klass != "error") return {};
  if (!r.payload.is_tuple()) return {};
  auto it = r.payload.as_tuple().find("msg");
  if (it == r.payload.as_tuple().end()) return {};
  if (!it->second.is_string()) return {};
  return it->second.as_string();
}

// Translate a gdb error message to backend::Error's wording so the
// dispatcher's existing classifier maps it correctly to -32xxx codes.
[[noreturn]] void throw_gdb_error(const std::string& gdb_msg) {
  // Most patterns are already understood by the dispatcher's
  // existing -32002/-32003 mapping. We add a "gdbmi: " prefix
  // so logs are searchable.
  throw Error(std::string("gdbmi: ") + gdb_msg);
}

// Issue an MI command on `s` and return the result record on ^done /
// ^running. ^error → throws via throw_gdb_error. Communication
// failure (session died) → throws "gdbmi: subprocess died".
MiRecord send_or_throw(GdbMiSession& s, const std::string& cmd) {
  auto r = s.send_command(cmd);
  if (!r.has_value()) {
    throw Error("gdbmi: subprocess died waiting for: " + cmd);
  }
  if (r->klass == "error") {
    throw_gdb_error(error_msg_of(*r));
  }
  return std::move(*r);
}

// Lookup helper: returns the borrowed pointer to TargetState. Throws
// the standard "unknown target_id" message so the dispatcher's
// classifier turns it into a typed error.
TargetState& must_get_target(GdbMiBackend::Impl& impl, TargetId tid) {
  std::lock_guard<std::mutex> lk(impl.mu);
  auto it = impl.targets.find(tid);
  if (it == impl.targets.end()) throw Error("unknown target_id");
  return *it->second;
}

}  // namespace

// ── ctor / dtor ───────────────────────────────────────────────────────

GdbMiBackend::GdbMiBackend() : impl_(std::make_unique<Impl>()) {}
GdbMiBackend::~GdbMiBackend() = default;

// ── Daemon-side state (no MI calls) ───────────────────────────────────

void GdbMiBackend::label_target(TargetId tid, std::string label) {
  std::lock_guard<std::mutex> lk(impl_->mu);
  auto it = impl_->targets.find(tid);
  if (it == impl_->targets.end()) throw Error("unknown target_id");
  // Reject label collisions on a different target — same contract
  // as LldbBackend.
  auto existing = impl_->label_owners.find(label);
  if (existing != impl_->label_owners.end() && existing->second != tid) {
    throw Error("label already in use by another target: " + label);
  }
  // Clear the prior label binding for this target, if any.
  if (it->second->label.has_value()) {
    impl_->label_owners.erase(*it->second->label);
  }
  it->second->label = label;
  impl_->label_owners[std::move(label)] = tid;
}

std::optional<std::string> GdbMiBackend::get_target_label(TargetId tid) {
  std::lock_guard<std::mutex> lk(impl_->mu);
  auto it = impl_->targets.find(tid);
  if (it == impl_->targets.end()) return std::nullopt;
  return it->second->label;
}

void GdbMiBackend::attach_target_resource(
    TargetId tid,
    std::unique_ptr<DebuggerBackend::TargetResource> resource) {
  std::lock_guard<std::mutex> lk(impl_->mu);
  auto it = impl_->targets.find(tid);
  if (it == impl_->targets.end()) {
    throw Error("attach_target_resource: unknown target_id");
  }
  it->second->resources.push_back(std::move(resource));
}

// Snapshot the (exe_path | core_path) digest plus the last observed
// process state into a stable 64-hex-char token. Live-process
// snapshots include nothing volatile in v1.4 — that's the
// docs/18 "snapshot_for_target is backend-specific opaque" caveat.
std::string GdbMiBackend::snapshot_for_target(TargetId tid) {
  std::lock_guard<std::mutex> lk(impl_->mu);
  auto it = impl_->targets.find(tid);
  if (it == impl_->targets.end()) return "none";
  util::Sha256 h;
  if (it->second->exe_path.has_value()) {
    h.update("exe:");
    h.update(*it->second->exe_path);
  }
  if (it->second->core_path.has_value()) {
    h.update("core:");
    h.update(*it->second->core_path);
  }
  h.update("state:");
  switch (it->second->last_status.state) {
    case ProcessState::kRunning: h.update("running"); break;
    case ProcessState::kStopped: h.update("stopped"); break;
    case ProcessState::kExited:  h.update("exited"); break;
    case ProcessState::kDetached:h.update("detached"); break;
    case ProcessState::kCrashed: h.update("crashed"); break;
    default:                     h.update("none"); break;
  }
  return "gdb:" + util::sha256_hex(h.finalize());
}

std::vector<TargetInfo> GdbMiBackend::list_targets() {
  std::lock_guard<std::mutex> lk(impl_->mu);
  std::vector<TargetInfo> out;
  out.reserve(impl_->targets.size());
  for (const auto& [id, st] : impl_->targets) {
    TargetInfo i;
    i.target_id = id;
    if (st->exe_path.has_value()) i.path = *st->exe_path;
    if (st->label.has_value()) i.label = *st->label;
    // gdb's "configured target" line is the natural triple source
    // but expensive to fetch per target. Leave triple empty in v1.4 —
    // the abstraction-validation exercise will surface whether
    // callers actually depend on it.
    out.push_back(std::move(i));
  }
  return out;
}

// ── Target / process lifecycle ─────────────────────────────────────────

namespace {

// Quote a path for MI: wrap in double quotes, escape backslash and
// quote. MI follows C-string rules.
std::string mi_quote(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 2);
  out.push_back('"');
  for (char c : s) {
    if (c == '\\' || c == '"') out.push_back('\\');
    out.push_back(c);
  }
  out.push_back('"');
  return out;
}

}  // namespace

OpenResult GdbMiBackend::open_executable(const std::string& path) {
  auto state = std::make_unique<TargetState>();
  state->session = std::make_unique<GdbMiSession>();
  if (!state->session->start()) {
    throw Error("gdbmi: failed to start gdb subprocess");
  }
  state->exe_path = path;
  state->last_status.state = ProcessState::kNone;

  // Load symbols + executable association. -file-exec-and-symbols
  // does NOT spawn a process; the inferior is configured but idle.
  auto rec = send_or_throw(*state->session,
                            "-file-exec-and-symbols " + mi_quote(path));
  (void)rec;

  OpenResult out;
  out.target_id = impl_->next_id++;
  out.triple = "";  // see list_targets note
  // Module list is populated lazily — list_modules is its own MI call.

  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    impl_->targets.emplace(out.target_id, std::move(state));
  }
  return out;
}

OpenResult GdbMiBackend::create_empty_target() {
  auto state = std::make_unique<TargetState>();
  state->session = std::make_unique<GdbMiSession>();
  if (!state->session->start()) {
    throw Error("gdbmi: failed to start gdb subprocess");
  }
  state->last_status.state = ProcessState::kNone;
  // No -file-exec-and-symbols — gdb is idle, ready for target.attach
  // or target.connect_remote.

  OpenResult out;
  out.target_id = impl_->next_id++;
  out.triple = "";
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    impl_->targets.emplace(out.target_id, std::move(state));
  }
  return out;
}

OpenResult GdbMiBackend::load_core(const std::string& core_path) {
  auto state = std::make_unique<TargetState>();
  state->session = std::make_unique<GdbMiSession>();
  if (!state->session->start()) {
    throw Error("gdbmi: failed to start gdb subprocess");
  }
  state->core_path = core_path;
  state->last_status.state = ProcessState::kStopped;  // cores are stopped-state

  // gdb's `-target-select core PATH` is the MI form. The classic
  // CLI is `core-file PATH`. MI version stays clean.
  send_or_throw(*state->session,
                "-target-select core " + mi_quote(core_path));

  OpenResult out;
  out.target_id = impl_->next_id++;
  out.triple = "";
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    impl_->targets.emplace(out.target_id, std::move(state));
  }
  return out;
}

void GdbMiBackend::close_target(TargetId tid) {
  std::unique_ptr<TargetState> dying;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) return;
    if (it->second->label.has_value()) {
      impl_->label_owners.erase(*it->second->label);
    }
    dying = std::move(it->second);
    impl_->targets.erase(it);
  }
  // GdbMiSession's dtor shuts gdb down cleanly; resources are
  // dropped in reverse order (vector dtor).
  // (dying goes out of scope here.)
}

// Everything below this line is a staged stub. Each lands in a
// follow-up commit per the v1.4 task list (#8 implementation
// batches: static-analysis, process control, threads/frames/values,
// memory, breakpoints, reverse exec).

ProcessStatus GdbMiBackend::launch_process(TargetId, const LaunchOptions&) {
  todo("launch_process");
}
ProcessStatus GdbMiBackend::get_process_state(TargetId tid) {
  // Trivial enough to land in this commit — the cached state is
  // exactly what callers expect when no MI call has been issued
  // since the last status change.
  auto& st = must_get_target(*impl_, tid);
  return st.last_status;
}
ProcessStatus GdbMiBackend::continue_process(TargetId)       { todo("continue_process"); }
ProcessStatus GdbMiBackend::continue_thread(TargetId, ThreadId) {
  todo("continue_thread");
}
ProcessStatus GdbMiBackend::kill_process(TargetId tid) {
  // Idempotent: a target with no process should return kNone.
  auto& st = must_get_target(*impl_, tid);
  if (st.last_status.state == ProcessState::kNone) return st.last_status;
  send_or_throw(*st.session, "-exec-abort");
  st.last_status.state = ProcessState::kNone;
  return st.last_status;
}
ProcessStatus GdbMiBackend::attach(TargetId, std::int32_t) { todo("attach"); }
ProcessStatus GdbMiBackend::detach_process(TargetId)       { todo("detach_process"); }
ProcessStatus GdbMiBackend::connect_remote_target(TargetId,
    const std::string&, const std::string&) {
  todo("connect_remote_target");
}
ConnectRemoteSshResult GdbMiBackend::connect_remote_target_ssh(
    TargetId, const ConnectRemoteSshOptions&) {
  todo("connect_remote_target_ssh");
}
bool GdbMiBackend::save_core(TargetId, const std::string&) {
  todo("save_core");
}

// ── Static analysis ───────────────────────────────────────────────────

namespace {

// Parse "0x<hex>" or "0x<hex>." or "0x<hex> in <name>" → uint64.
// Returns 0 on parse failure (matches gdb's own "not found" semantic).
std::uint64_t parse_hex_addr(std::string_view s) {
  // Skip leading whitespace / quotes.
  while (!s.empty() && (s.front() == ' ' || s.front() == '"')) s.remove_prefix(1);
  if (s.size() < 3 || s[0] != '0' || (s[1] != 'x' && s[1] != 'X')) return 0;
  s.remove_prefix(2);
  std::uint64_t v = 0;
  while (!s.empty()) {
    char c = s.front();
    int d;
    if (c >= '0' && c <= '9') d = c - '0';
    else if (c >= 'a' && c <= 'f') d = 10 + (c - 'a');
    else if (c >= 'A' && c <= 'F') d = 10 + (c - 'A');
    else break;
    v = (v << 4) | static_cast<std::uint64_t>(d);
    s.remove_prefix(1);
  }
  return v;
}

// Run `info address NAME` (CLI fall-through) and pull the address
// from the resulting console-stream record. Returns 0 if gdb
// couldn't resolve the symbol — typical for forward-declared or
// extern-without-definition cases.
std::uint64_t resolve_symbol_address(GdbMiSession& s,
                                     const std::string& name) {
  // Drain stale async records so we read fresh output for this call.
  s.drain_async();
  auto r = s.send_command("info address " + name);
  if (!r.has_value() || r->klass != "done") return 0;
  // Address arrives on the console-stream that preceded this ^done.
  // drain_async picks up everything queued between commands.
  auto pending = s.drain_async();
  // Scan for "at address 0xADDR." in the most recent console-stream.
  std::string text;
  for (const auto& rec : pending) {
    if (rec.kind == MiRecordKind::kConsoleStream) {
      text += rec.stream_text;
    }
  }
  const std::string needle = "at address ";
  auto pos = text.find(needle);
  if (pos == std::string::npos) return 0;
  return parse_hex_addr(std::string_view(text).substr(pos + needle.size()));
}

}  // namespace

std::vector<Module> GdbMiBackend::list_modules(TargetId tid) {
  auto& st = must_get_target(*impl_, tid);
  std::vector<Module> out;

  // v1.4 scope: main exec only. -file-list-shared-libraries returns
  // empty for static targets (no process); shared-lib enumeration
  // needs a live inferior. Documented in docs/18 as a known v1.4
  // gap; revisit when we add launch/attach support.
  if (st.exe_path.has_value()) {
    Module m;
    m.path = *st.exe_path;
    // Load address unknown without a live process; use 0 as the
    // sentinel that matches LldbBackend's behavior on unloaded
    // modules.
    m.load_address = 0;
    // uuid (build-id) and triple deferred — both require an extra
    // CLI parse round-trip per module. Worth doing in a follow-up
    // pass but not blocking the abstraction-validation goal.
    out.push_back(std::move(m));
  }
  return out;
}

std::optional<TypeLayout>
GdbMiBackend::find_type_layout(TargetId, const std::string&) {
  todo("find_type_layout");
}

std::vector<SymbolMatch>
GdbMiBackend::find_symbols(TargetId tid, const SymbolQuery& query) {
  auto& st = must_get_target(*impl_, tid);
  std::vector<SymbolMatch> out;

  // Build the MI command. -symbol-info-functions accepts --name
  // PATTERN (regex). Empty pattern → all functions; we mirror
  // LldbBackend's behavior which treats empty queries as "match
  // anything" (rare, mostly debug use).
  auto run_kind = [&](const char* mi_verb, SymbolKind kind_enum) {
    std::string cmd = std::string(mi_verb);
    if (!query.name.empty()) {
      // gdb's --name is a regex; escape metacharacters to keep it a
      // literal substring match (LldbBackend's default).
      std::string pat;
      pat.reserve(query.name.size() * 2);
      for (char c : query.name) {
        if (std::strchr(".^$*+?()[]{}|\\", c)) pat.push_back('\\');
        pat.push_back(c);
      }
      cmd += " --name " + pat;
    }
    auto rec = st.session->send_command(cmd);
    if (!rec.has_value() || rec->klass == "error") return;
    if (!rec->payload.is_tuple()) return;
    const auto& root = rec->payload.as_tuple();
    auto sit = root.find("symbols");
    if (sit == root.end() || !sit->second.is_tuple()) return;
    const auto& syms = sit->second.as_tuple();
    auto dit = syms.find("debug");
    if (dit == syms.end() || !dit->second.is_list()) return;
    for (const auto& file_entry : dit->second.as_list()) {
      if (!file_entry.is_tuple()) continue;
      const auto& fe = file_entry.as_tuple();
      auto inner = fe.find("symbols");
      if (inner == fe.end() || !inner->second.is_list()) continue;
      for (const auto& sym_v : inner->second.as_list()) {
        if (!sym_v.is_tuple()) continue;
        const auto& sym = sym_v.as_tuple();
        SymbolMatch m;
        m.kind = kind_enum;
        if (auto it = sym.find("name");
            it != sym.end() && it->second.is_string()) {
          m.name = it->second.as_string();
        }
        m.address = 0;
        if (st.exe_path.has_value()) m.module_path = *st.exe_path;
        // byte_size, mangled, load_address left at defaults — gdb's
        // -symbol-info-functions doesn't surface them. Filling in
        // each via a separate `info symbol` round-trip would
        // dominate runtime on large result sets; agents who need
        // byte_size can follow up per-result.
        out.push_back(std::move(m));
      }
    }
  };

  if (query.kind == SymbolKind::kAny ||
      query.kind == SymbolKind::kFunction) {
    run_kind("-symbol-info-functions", SymbolKind::kFunction);
  }
  if (query.kind == SymbolKind::kAny ||
      query.kind == SymbolKind::kVariable) {
    run_kind("-symbol-info-variables", SymbolKind::kVariable);
  }

  // Resolve addresses via `info address` per symbol. Slow (one CLI
  // fall-through per result) but accurate and matches LldbBackend's
  // SymbolMatch contract. For pathological result sets (>500 hits)
  // this can take seconds — agent callers should narrow with --name.
  for (auto& m : out) {
    if (m.address == 0 && !m.name.empty()) {
      m.address = resolve_symbol_address(*st.session, m.name);
    }
  }
  return out;
}

std::vector<GlobalVarMatch> GdbMiBackend::find_globals_of_type(
    TargetId, std::string_view, bool&) {
  todo("find_globals_of_type");
}

std::vector<StringMatch>
GdbMiBackend::find_strings(TargetId, const StringQuery&) {
  todo("find_strings");
}

std::vector<DisasmInsn>
GdbMiBackend::disassemble_range(TargetId tid, std::uint64_t lo,
                                  std::uint64_t hi) {
  auto& st = must_get_target(*impl_, tid);
  std::vector<DisasmInsn> out;

  // -data-disassemble mode 0 = bare insn only; mode 1 = with src lines.
  // We use mode 0 for parity with LldbBackend's default (no line info
  // by default; agents that want source-line correlation can xref
  // via separate calls).
  char buf[160];
  std::snprintf(buf, sizeof(buf),
                "-data-disassemble -s 0x%llx -e 0x%llx -- 0",
                static_cast<unsigned long long>(lo),
                static_cast<unsigned long long>(hi));
  auto rec = st.session->send_command(buf);
  if (!rec.has_value() || rec->klass == "error") {
    if (rec.has_value()) throw_gdb_error(error_msg_of(*rec));
    throw Error("gdbmi: disassemble_range: session died");
  }
  if (!rec->payload.is_tuple()) return out;
  auto it = rec->payload.as_tuple().find("asm_insns");
  if (it == rec->payload.as_tuple().end() || !it->second.is_list()) {
    return out;
  }
  for (const auto& insn_v : it->second.as_list()) {
    if (!insn_v.is_tuple()) continue;
    const auto& t = insn_v.as_tuple();
    DisasmInsn ins;
    if (auto ait = t.find("address");
        ait != t.end() && ait->second.is_string()) {
      ins.address = parse_hex_addr(ait->second.as_string());
    }
    if (auto iit = t.find("inst");
        iit != t.end() && iit->second.is_string()) {
      // gdb emits the full insn as one string like "mov    %rsp,%rbp".
      // Split on the first whitespace block — mnemonic up front,
      // operands after. This matches the LldbBackend convention.
      const std::string& full = iit->second.as_string();
      auto space = full.find_first_of(" \t");
      if (space == std::string::npos) {
        ins.mnemonic = full;
      } else {
        ins.mnemonic = full.substr(0, space);
        auto op_start = full.find_first_not_of(" \t", space);
        if (op_start != std::string::npos) {
          ins.operands = full.substr(op_start);
        }
      }
    }
    // func-name + offset go in the optional comment; LldbBackend
    // populates similar context there.
    if (auto fit = t.find("func-name");
        fit != t.end() && fit->second.is_string() &&
        !fit->second.as_string().empty()) {
      ins.comment = fit->second.as_string();
      if (auto oit = t.find("offset");
          oit != t.end() && oit->second.is_string()) {
        ins.comment += "+" + oit->second.as_string();
      }
    }
    out.push_back(std::move(ins));
  }
  return out;
}

std::vector<XrefMatch>
GdbMiBackend::xref_address(TargetId, std::uint64_t) {
  todo("xref_address");
}

std::vector<StringXrefResult>
GdbMiBackend::find_string_xrefs(TargetId, const std::string&) {
  todo("find_string_xrefs");
}

// ── Threads / frames / values (stubbed) ───────────────────────────────

std::vector<ThreadInfo> GdbMiBackend::list_threads(TargetId)     { todo("list_threads"); }
std::vector<FrameInfo>  GdbMiBackend::list_frames(TargetId,
    ThreadId, std::uint32_t) { todo("list_frames"); }
ProcessStatus GdbMiBackend::step_thread(TargetId, ThreadId, StepKind) {
  todo("step_thread");
}
ProcessStatus GdbMiBackend::reverse_continue(TargetId) {
  todo("reverse_continue");
}
ProcessStatus GdbMiBackend::reverse_step_thread(TargetId, ThreadId,
                                                  ReverseStepKind) {
  todo("reverse_step_thread");
}
std::vector<ValueInfo> GdbMiBackend::list_locals(TargetId, ThreadId,
                                                    std::uint32_t) {
  todo("list_locals");
}
std::vector<ValueInfo> GdbMiBackend::list_args(TargetId, ThreadId,
                                                  std::uint32_t) {
  todo("list_args");
}
std::vector<ValueInfo> GdbMiBackend::list_registers(TargetId, ThreadId,
                                                       std::uint32_t) {
  todo("list_registers");
}
EvalResult GdbMiBackend::evaluate_expression(TargetId, ThreadId,
                                                std::uint32_t,
                                                const std::string&,
                                                const EvalOptions&) {
  todo("evaluate_expression");
}
ReadResult GdbMiBackend::read_value_path(TargetId, ThreadId,
                                            std::uint32_t,
                                            const std::string&) {
  todo("read_value_path");
}
std::uint64_t GdbMiBackend::read_register(TargetId, ThreadId,
                                             std::uint32_t,
                                             const std::string&) {
  todo("read_register");
}

// ── Memory (stubbed) ──────────────────────────────────────────────────

std::vector<std::uint8_t>
GdbMiBackend::read_memory(TargetId, std::uint64_t, std::uint64_t) {
  todo("read_memory");
}
std::string
GdbMiBackend::read_cstring(TargetId, std::uint64_t, std::uint32_t) {
  todo("read_cstring");
}
std::vector<MemoryRegion> GdbMiBackend::list_regions(TargetId) {
  todo("list_regions");
}
std::vector<MemorySearchHit>
GdbMiBackend::search_memory(TargetId, std::uint64_t, std::uint64_t,
                              const std::vector<std::uint8_t>&,
                              std::uint32_t) {
  todo("search_memory");
}

// ── Breakpoints (stubbed) ─────────────────────────────────────────────

BreakpointHandle
GdbMiBackend::create_breakpoint(TargetId, const BreakpointSpec&) {
  todo("create_breakpoint");
}
void GdbMiBackend::set_breakpoint_callback(TargetId, std::int32_t,
                                              BreakpointCallback, void*) {
  todo("set_breakpoint_callback");
}
void GdbMiBackend::disable_breakpoint(TargetId, std::int32_t) {
  todo("disable_breakpoint");
}
void GdbMiBackend::enable_breakpoint(TargetId, std::int32_t) {
  todo("enable_breakpoint");
}
void GdbMiBackend::delete_breakpoint(TargetId, std::int32_t) {
  todo("delete_breakpoint");
}

}  // namespace ldb::backend::gdbmi
