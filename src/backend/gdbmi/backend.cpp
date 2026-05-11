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

// ── Static analysis (stubbed) ─────────────────────────────────────────

std::vector<Module> GdbMiBackend::list_modules(TargetId)         { todo("list_modules"); }
std::optional<TypeLayout> GdbMiBackend::find_type_layout(
    TargetId, const std::string&) { todo("find_type_layout"); }
std::vector<SymbolMatch> GdbMiBackend::find_symbols(
    TargetId, const SymbolQuery&) { todo("find_symbols"); }
std::vector<GlobalVarMatch> GdbMiBackend::find_globals_of_type(
    TargetId, std::string_view, bool&) { todo("find_globals_of_type"); }
std::vector<StringMatch> GdbMiBackend::find_strings(
    TargetId, const StringQuery&) { todo("find_strings"); }
std::vector<DisasmInsn> GdbMiBackend::disassemble_range(
    TargetId, std::uint64_t, std::uint64_t) { todo("disassemble_range"); }
std::vector<XrefMatch> GdbMiBackend::xref_address(
    TargetId, std::uint64_t) { todo("xref_address"); }
std::vector<StringXrefResult> GdbMiBackend::find_string_xrefs(
    TargetId, const std::string&) { todo("find_string_xrefs"); }

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
