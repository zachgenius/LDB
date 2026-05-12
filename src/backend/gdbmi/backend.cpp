// SPDX-License-Identifier: Apache-2.0
#include "backend/gdbmi/backend.h"

#include "util/log.h"
#include "util/sha256.h"

#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <limits>
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

// Per-breakpoint callback registry entry. The LldbBackend equivalent
// is an SBBreakpoint::SetCallback baton fired from LLDB's event
// thread; the gdb-MI path has no equivalent event thread, so callbacks
// only fire on continue_process / step_thread return paths where
// wait_for_stop() observes a *stopped,reason="breakpoint-hit",bkptno=N.
// Best-effort by design; see set_breakpoint_callback for the contract.
struct GdbBreakpointCb {
  BreakpointCallback cb;
  void*              baton = nullptr;
};

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
  // Per-bp_id callback record. See GdbBreakpointCb above for the
  // best-effort firing semantics.
  std::unordered_map<std::int32_t, GdbBreakpointCb>   bp_callbacks;
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
// As of v1.4 final batch, every virtual is implemented — the helper
// is retained for future use during partial-coverage refactors so we
// don't have to re-introduce it.
[[maybe_unused, noreturn]] void todo(const char* method) {
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

namespace {

// Drain async records after an exec-style command. gdb sends
// *stopped / *running on the async channel; we look for the most
// recent terminal-state record and translate to ProcessStatus.
// Polls the session up to `deadline` for the expected record.
ProcessStatus wait_for_stop(GdbMiSession& s,
                            std::chrono::milliseconds budget) {
  using clock = std::chrono::steady_clock;
  const auto deadline = clock::now() + budget;
  ProcessStatus out;
  out.state = ProcessState::kRunning;

  while (clock::now() < deadline) {
    auto async = s.drain_async();
    for (const auto& rec : async) {
      if (rec.kind != MiRecordKind::kExecAsync) continue;
      if (rec.klass == "stopped") {
        out.state = ProcessState::kStopped;
        if (rec.payload.is_tuple()) {
          const auto& t = rec.payload.as_tuple();
          if (auto it = t.find("reason");
              it != t.end() && it->second.is_string()) {
            const std::string& reason = it->second.as_string();
            out.stop_reason = reason;
            if (reason == "exited" || reason == "exited-normally" ||
                reason == "exited-signalled") {
              out.state = ProcessState::kExited;
            } else if (reason == "signal-received") {
              // Could be crashed or signalled; keep kStopped for now.
              out.state = ProcessState::kStopped;
            }
          }
        }
        return out;
      }
      if (rec.klass == "running") {
        out.state = ProcessState::kRunning;
        // Don't return yet — exec-async may emit *running then
        // *stopped in quick succession.
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return out;
}

}  // namespace

ProcessStatus GdbMiBackend::launch_process(TargetId tid,
                                              const LaunchOptions& opts) {
  auto& st = must_get_target(*impl_, tid);

  // stop_at_entry: set a temporary breakpoint at main BEFORE exec-run
  // (gdb's --start flag would also work, but tbreak gives us a
  // matching breakpoint-hit stop reason that downstream observers
  // can pattern-match on).
  if (opts.stop_at_entry) {
    send_or_throw(*st.session, "-break-insert -t main");
  }

  // -exec-run --start triggers a transient break at main and runs;
  // without stop_at_entry, plain -exec-run runs to completion or to
  // the first inferior signal. We use -exec-run unconditionally and
  // let the tbreak above handle the stop_at_entry case.
  auto r = send_or_throw(*st.session, "-exec-run");
  // gdb returns ^running for -exec-run; the actual stop arrives
  // asynchronously.
  (void)r;
  st.last_status = wait_for_stop(*st.session,
                                  std::chrono::seconds(10));
  return st.last_status;
}

ProcessStatus GdbMiBackend::get_process_state(TargetId tid) {
  auto& st = must_get_target(*impl_, tid);
  return st.last_status;
}

ProcessStatus GdbMiBackend::continue_process(TargetId tid) {
  auto& st = must_get_target(*impl_, tid);
  if (st.last_status.state == ProcessState::kNone) {
    throw Error("no live process; cannot continue");
  }
  send_or_throw(*st.session, "-exec-continue");
  st.last_status = wait_for_stop(*st.session, std::chrono::seconds(30));
  return st.last_status;
}

ProcessStatus GdbMiBackend::continue_thread(TargetId target_id,
                                              ThreadId thread_id) {
  // v0.3 sync passthrough — mirrors LldbBackend's docstring: per-
  // thread continue is async-prep wire shape; until v1.5 async
  // runtime lands, this is process-wide continue with the thread
  // selected first.
  auto& st = must_get_target(*impl_, target_id);
  if (st.last_status.state == ProcessState::kNone) {
    throw Error("no live process; cannot continue");
  }
  // The thread_id param is a kernel tid; we ignore the per-thread
  // selection in v0.3 (matches LldbBackend's sync passthrough) and
  // just do a process-wide continue. When v1.5 async lands, this
  // will translate kernel tid → gdb id and use --thread.
  (void)thread_id;
  send_or_throw(*st.session, "-exec-continue");
  st.last_status = wait_for_stop(*st.session, std::chrono::seconds(30));
  return st.last_status;
}

// v1.6 #21: GDB/MI doesn't have a one-shot "park this thread" primitive
// matching SBThread::Suspend. The closest equivalent requires
// `-exec-continue --thread X` against an MI server in non-stop mode,
// which we don't enable. Leave the endpoint as NotImplemented for now;
// callers needing non-stop semantics use the LLDB backend.
ProcessStatus GdbMiBackend::suspend_thread(TargetId target_id,
                                            ThreadId thread_id) {
  (void)target_id;
  (void)thread_id;
  throw Error("suspend_thread: not implemented for GDB/MI backend");
}

ProcessStatus GdbMiBackend::kill_process(TargetId tid) {
  auto& st = must_get_target(*impl_, tid);
  if (st.last_status.state == ProcessState::kNone) return st.last_status;
  // -exec-abort is the documented MI form; some gdb builds map it
  // to `kill` for compatibility. The CLI fall-through `kill` is a
  // safe alternative when the MI verb isn't recognised.
  auto r = st.session->send_command("-exec-abort");
  if (!r.has_value() || r->klass == "error") {
    // Fall back to the CLI form.
    auto cli = st.session->send_command("kill");
    (void)cli;
  }
  st.last_status.state = ProcessState::kNone;
  return st.last_status;
}

ProcessStatus GdbMiBackend::attach(TargetId tid, std::int32_t pid) {
  auto& st = must_get_target(*impl_, tid);
  send_or_throw(*st.session,
                "-target-attach " + std::to_string(pid));
  // gdb stops the process on successful attach.
  st.last_status.state = ProcessState::kStopped;
  st.last_status.pid   = pid;
  return st.last_status;
}

ProcessStatus GdbMiBackend::detach_process(TargetId tid) {
  auto& st = must_get_target(*impl_, tid);
  if (st.last_status.state == ProcessState::kNone) return st.last_status;
  send_or_throw(*st.session, "-target-detach");
  st.last_status.state = ProcessState::kDetached;
  return st.last_status;
}
ProcessStatus GdbMiBackend::connect_remote_target(TargetId tid,
    const std::string& url, const std::string& plugin_name) {
  if (url.empty()) {
    throw Error("connect_remote: url must not be empty");
  }
  // rr:// URL-scheme dispatch. The LldbBackend route shells out to
  // `rr replay` and rewrites the URL to a local connect:// port; we
  // do not replicate that orchestration on the gdb side in v1.4.
  // Surface as a -32003 forbidden via the "does not support" pattern
  // so agents can branch to --backend=lldb cleanly.
  if (url.size() >= 5 && url.compare(0, 5, "rr://") == 0) {
    throw Error("gdbmi: rr:// URL via gdb backend does not support v1.4; "
                "use --backend=lldb for rr:// targets");
  }
  auto& st = must_get_target(*impl_, tid);
  // plugin_name "gdb-remote" or empty → plain remote; anything else
  // → extended-remote (gdbserver-multi, host-multi sessions).
  const bool extended = !plugin_name.empty() && plugin_name != "gdb-remote";
  const std::string verb = extended ? "-target-select extended-remote "
                                    : "-target-select remote ";
  send_or_throw(*st.session, verb + url);
  // gdb stops the inferior on a successful connect.
  st.last_status.state = ProcessState::kStopped;
  return st.last_status;
}

ConnectRemoteSshResult GdbMiBackend::connect_remote_target_ssh(
    TargetId, const ConnectRemoteSshOptions&) {
  // The LldbBackend SSH-tunnel transport is a separate Tier-2 surface
  // (post-V1 #11); landing a parallel implementation for gdb is not on
  // the v1.4 critical path. Honest punt — message includes "does not
  // support" so the dispatcher maps to -32003 forbidden.
  throw Error("gdbmi: connect_remote_target_ssh: gdb backend SSH transport "
              "does not support v1.4");
}

bool GdbMiBackend::save_core(TargetId tid, const std::string& path) {
  auto& st = must_get_target(*impl_, tid);
  if (st.last_status.state == ProcessState::kNone) {
    throw Error("no live process; cannot save_core");
  }
  // `generate-core-file PATH` CLI fall-through — no MI verb exposes
  // the same functionality on gdb 15.x. The CLI treats PATH as a
  // single token (no shell escaping); paths with embedded whitespace
  // or quotes are not supported. Refuse those up front so the failure
  // mode is clean rather than gdb writing to a mangled filename.
  for (char c : path) {
    if (c == ' ' || c == '\t' || c == '\n' || c == '"' || c == '\\') {
      throw Error(
          "gdbmi: save_core: path must not contain whitespace or quotes");
    }
  }
  st.session->drain_async();
  // The success marker arrives on the console stream as
  // "Saved corefile <path>".
  auto r = st.session->send_command("generate-core-file " + path);
  if (!r.has_value()) {
    throw Error("gdbmi: save_core: subprocess died");
  }
  if (r->klass == "error") {
    // gdb surfaces filesystem failures (no perm, no space, ...) as
    // ^error,msg=...; convert to a typed Error.
    throw_gdb_error(error_msg_of(*r));
  }
  std::string text;
  for (const auto& rec : st.session->drain_async()) {
    if (rec.kind == MiRecordKind::kConsoleStream) text += rec.stream_text;
  }
  // gdb's console wording is not a stable API — "Saved corefile" is
  // what gdb 12-15 emit; future versions may rephrase. Log loudly on
  // mismatch so the false return isn't silently misinterpreted by an
  // agent as "no permissions" when the core was actually written.
  bool ok = text.find("Saved corefile") != std::string::npos;
  if (!ok) {
    log::warn(std::string("gdbmi: save_core: success marker not found "
                          "in gdb console output (gdb version drift?); "
                          "core may still have been written to ") + path);
  }
  return ok;
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

// Estimate a function's byte size via `disassemble FUNCNAME` (CLI
// fall-through). The output lines carry `0xADDR <+OFFSET>: insn` per
// instruction; we take the highest offset + 16 (max x86 instruction
// length) as a safe upper bound. ARM64's max-insn-length is 4 so
// this over-estimates on arm64 by ~12 bytes, harmless for the
// dispatcher's disasm.function which truncates trailing junk on
// the gdb side via the asm_insns array.
//
// Returns 0 if gdb can't disassemble the symbol — same "not found"
// semantic as resolve_symbol_address.
std::uint64_t resolve_function_byte_size(GdbMiSession& s,
                                          const std::string& name) {
  s.drain_async();
  auto r = s.send_command("disassemble " + name);
  if (!r.has_value() || r->klass != "done") return 0;
  auto pending = s.drain_async();
  std::string text;
  for (const auto& rec : pending) {
    if (rec.kind == MiRecordKind::kConsoleStream) {
      text += rec.stream_text;
    }
  }
  // Find the highest `<+N>` offset across all instruction lines.
  std::uint64_t max_offset = 0;
  std::size_t i = 0;
  while (i < text.size()) {
    auto open = text.find("<+", i);
    if (open == std::string::npos) break;
    auto close = text.find(">", open);
    if (close == std::string::npos) break;
    std::uint64_t off = 0;
    for (std::size_t j = open + 2; j < close; ++j) {
      char c = text[j];
      if (c < '0' || c > '9') { off = 0; break; }
      off = off * 10 + static_cast<unsigned>(c - '0');
    }
    if (off > max_offset) max_offset = off;
    i = close + 1;
  }
  if (max_offset == 0) return 0;
  return max_offset + 16;
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

namespace {

// Parse one `ptype /o NAME` console-stream blob into TypeLayout.
//
// The output we expect (gdb 9–15 share this shape):
//
//   /* offset      |    size */  type = struct foo {
//   /*      0      |       4 */    int x;
//   /*      4      |       4 */    int y;
//   /* XXX  3-byte hole      */
//   /*      8      |       8 */    uint64_t sid;
//
//                                  /* total size (bytes):    8 */
//                                }
//
// Nested struct members emit their own opening brace + nested fields.
// We treat any line containing "type = struct" / "union" / "class"
// as the *outer* declaration only when we haven't seen one yet (the
// inner declarations don't carry "type = " on gdb 15.1). Lines with
// XXX-hole markers populate the *previous* field's holes_after.
// Returns nullopt on malformed input (defensive — ptype output varies
// across gdb versions).
std::optional<TypeLayout>
parse_ptype_offsets(const std::string& text, const std::string& name) {
  TypeLayout out;
  out.name = name;

  int depth = 0;             // nesting depth across { } pairs
  bool saw_decl = false;     // outer "type = ..." line seen
  // Index into out.fields rather than a raw pointer — push_back
  // invalidates references / pointers into a vector. Using SIZE_MAX
  // as the "no field yet" sentinel avoids accessing out.fields[-1u].
  std::size_t last_field_idx = std::numeric_limits<std::size_t>::max();

  std::size_t pos = 0;
  while (pos < text.size()) {
    auto nl = text.find('\n', pos);
    std::string line = (nl == std::string::npos)
                         ? text.substr(pos) : text.substr(pos, nl - pos);
    if (nl == std::string::npos) pos = text.size();
    else pos = nl + 1;

    // Strip trailing whitespace/CR for cleaner parsing.
    while (!line.empty() && (line.back() == ' ' || line.back() == '\t' ||
                              line.back() == '\r')) {
      line.pop_back();
    }
    if (line.empty()) continue;

    // Detect the outer type opener. We require the line to contain
    // "type = " AND a struct/union/class keyword AND an opening "{".
    if (!saw_decl) {
      const auto teq = line.find("type = ");
      if (teq != std::string::npos && line.find('{') != std::string::npos) {
        saw_decl = true;
        depth = 1;
        continue;
      }
    }

    // Detect total-size line: "/* total size (bytes):    N */".
    // Always at outer-struct close (depth becomes 0 immediately after).
    const auto tsz = line.find("total size (bytes):");
    if (tsz != std::string::npos) {
      auto colon = line.find(':', tsz);
      if (colon != std::string::npos) {
        std::string s = line.substr(colon + 1);
        // pull digits
        std::uint64_t v = 0;
        bool got = false;
        for (char c : s) {
          if (c >= '0' && c <= '9') {
            v = v * 10 + static_cast<std::uint64_t>(c - '0');
            got = true;
          } else if (got) break;
        }
        if (got && depth == 1) out.byte_size = v;
      }
      continue;
    }

    // Detect XXX hole annotation: "/* XXX  N-byte hole      */".
    if (line.find("XXX") != std::string::npos &&
        line.find("hole") != std::string::npos) {
      auto x = line.find("XXX");
      std::uint64_t v = 0;
      bool got = false;
      for (std::size_t i = x + 3; i < line.size(); ++i) {
        char c = line[i];
        if (c >= '0' && c <= '9') {
          v = v * 10 + static_cast<std::uint64_t>(c - '0');
          got = true;
        } else if (got) break;
      }
      if (got && last_field_idx < out.fields.size()) {
        out.fields[last_field_idx].holes_after = v;
      }
      continue;
    }

    // Detect a member line. The shape is:
    //   /* offset | size */   TYPENAME NAME;
    // where the comment may contain spaces / a trailing "*/" before
    // the actual member declaration. Only count *direct* members of
    // the outer type (depth == 1).
    const auto cstart = line.find("/*");
    const auto cend   = line.find("*/");
    if (cstart == std::string::npos || cend == std::string::npos ||
        cend <= cstart) {
      // Track brace depth on free-standing lines (e.g. "} origin;" or
      // a "{" continuing a nested struct).
      for (char c : line) {
        if (c == '{') ++depth;
        else if (c == '}') --depth;
      }
      continue;
    }

    // Extract offset and size from inside the comment.
    std::string inside = line.substr(cstart + 2, cend - cstart - 2);
    auto bar = inside.find('|');
    if (bar == std::string::npos) continue;
    std::uint64_t off  = 0;
    std::uint64_t bsz  = 0;
    {
      bool got = false;
      for (char c : inside.substr(0, bar)) {
        if (c >= '0' && c <= '9') {
          off = off * 10 + static_cast<std::uint64_t>(c - '0');
          got = true;
        } else if (got) break;
      }
      if (!got) continue;
    }
    {
      bool got = false;
      for (char c : inside.substr(bar + 1)) {
        if (c >= '0' && c <= '9') {
          bsz = bsz * 10 + static_cast<std::uint64_t>(c - '0');
          got = true;
        } else if (got) break;
      }
    }

    // Pull the trailing "TYPENAME NAME;" portion. Some members open a
    // nested struct ({); their declared name follows the closing brace
    // a few lines later. We only emit those as outer-struct members
    // (depth becomes 1 again at the closing-brace line), which the
    // brace counter below handles. For now, capture the simple case.
    std::string tail = line.substr(cend + 2);
    while (!tail.empty() && (tail.front() == ' ' || tail.front() == '\t')) {
      tail.erase(tail.begin());
    }

    if (depth == 1 && !tail.empty()) {
      // Simple "TYPENAME NAME;" — split at the last whitespace before
      // the semicolon, taking the trailing identifier as the field
      // name. If we see an opening "{" the field is a nested aggregate
      // and we'll handle it after the brace block.
      if (tail.find('{') != std::string::npos) {
        // Nested anonymous-typed field opens here; the field's *name*
        // appears after the matching '}'. We still want to record the
        // member with the right offset/size now and patch in the name
        // on the close line.
        Field f;
        f.offset    = off;
        f.byte_size = bsz;
        // type_name is everything up to the '{' (e.g. "struct point2 {").
        auto br = tail.find('{');
        std::string tn = tail.substr(0, br);
        while (!tn.empty() && (tn.back() == ' ' || tn.back() == '\t')) tn.pop_back();
        f.type_name = std::move(tn);
        out.fields.push_back(std::move(f));
        last_field_idx = out.fields.size() - 1;
        // Step depth for the inner block.
        ++depth;
        continue;
      }

      // Strip trailing ';'
      while (!tail.empty() &&
             (tail.back() == ';' || tail.back() == ' ' || tail.back() == '\t')) {
        tail.pop_back();
      }
      // Find last whitespace; name is after it, type is before.
      auto sp = tail.find_last_of(" \t");
      std::string ty;
      std::string nm;
      if (sp == std::string::npos) {
        nm = tail;
      } else {
        ty = tail.substr(0, sp);
        nm = tail.substr(sp + 1);
        // The name may carry a leading '*' / '[N]' decorator; pull '*'
        // back onto the type for canonical "int *" style.
        while (!nm.empty() && nm.front() == '*') {
          ty += '*';
          nm.erase(nm.begin());
        }
      }
      Field f;
      f.name      = std::move(nm);
      f.type_name = std::move(ty);
      f.offset    = off;
      f.byte_size = bsz;
      out.fields.push_back(std::move(f));
      last_field_idx = out.fields.size() - 1;
    } else if (depth > 1) {
      // Inside a nested struct; track braces on this comment line so
      // depth tracks correctly when the inner closes.
      for (char c : line) {
        if (c == '{') ++depth;
        else if (c == '}') --depth;
      }
    }
  }

  if (!saw_decl) return std::nullopt;

  // Recompute holes_total from holes_after; the XXX-hole pass populated
  // per-field. Also compute a trailing-hole for the last field if it
  // exists (e.g. struct ending with a 7-byte tail padding).
  if (!out.fields.empty() && out.byte_size > 0) {
    auto& last = out.fields.back();
    std::uint64_t end_of_last = last.offset + last.byte_size;
    if (out.byte_size > end_of_last && last.holes_after == 0) {
      last.holes_after = out.byte_size - end_of_last;
    }
  }
  out.holes_total = 0;
  for (const auto& f : out.fields) out.holes_total += f.holes_after;
  // alignment: ptype doesn't surface alignof. Leave at 0 per task spec.
  return out;
}

}  // namespace

std::optional<TypeLayout>
GdbMiBackend::find_type_layout(TargetId tid, const std::string& name) {
  auto& st = must_get_target(*impl_, tid);

  // ptype is a CLI fall-through; we never paste user input directly
  // into the shell-like parser without sanitising. Restrict to typical
  // C/C++ type-name shapes: alnum, '_', '*', '&', ':', '<', '>', ' '.
  // Refuse anything else — return nullopt rather than throw so the
  // caller treats it as "unknown type" instead of a transport error.
  for (char raw : name) {
    auto c = static_cast<unsigned char>(raw);
    if (!std::isalnum(c) && c != '_' && c != ':' && c != '<' &&
        c != '>' && c != ' ' && c != '*' && c != '&') {
      return std::nullopt;
    }
  }
  if (name.empty()) return std::nullopt;

  // Try the name verbatim first; if gdb rejects it (e.g. C tag names
  // need "struct " prefix), retry with "struct ", then "union ".
  auto attempt = [&](const std::string& q) -> std::optional<TypeLayout> {
    st.session->drain_async();
    auto r = st.session->send_command("ptype /o " + q);
    if (!r.has_value() || r->klass != "done") {
      // Drain any console-stream the failed command produced; we don't
      // want it polluting the next CLI call's parse.
      st.session->drain_async();
      return std::nullopt;
    }
    std::string text;
    for (const auto& rec : st.session->drain_async()) {
      if (rec.kind == MiRecordKind::kConsoleStream) text += rec.stream_text;
    }
    // gdb prints "No symbol \"X\" in current context." on the console
    // stream when it can't resolve the type — treat as miss.
    if (text.find("No symbol") != std::string::npos) return std::nullopt;
    return parse_ptype_offsets(text, name);
  };

  if (auto r = attempt(name); r.has_value()) return r;
  if (name.compare(0, 7, "struct ") != 0) {
    if (auto r = attempt("struct " + name); r.has_value()) return r;
  }
  if (name.compare(0, 6, "union ") != 0 &&
      name.compare(0, 7, "struct ") != 0) {
    if (auto r = attempt("union " + name); r.has_value()) return r;
  }
  return std::nullopt;
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
  //
  // For functions we ALSO resolve byte_size via `disassemble NAME`
  // so disasm.function (which keys on byte_size != 0) works
  // end-to-end against this backend.
  for (auto& m : out) {
    if (m.address == 0 && !m.name.empty()) {
      m.address = resolve_symbol_address(*st.session, m.name);
    }
    if (m.kind == SymbolKind::kFunction && m.byte_size == 0 &&
        !m.name.empty() && m.address != 0) {
      m.byte_size = resolve_function_byte_size(*st.session, m.name);
    }
  }
  return out;
}

std::vector<GlobalVarMatch> GdbMiBackend::find_globals_of_type(
    TargetId tid, std::string_view type_name, bool& truncated) {
  if (type_name.empty()) {
    throw Error("type_name must be non-empty");
  }
  auto& st = must_get_target(*impl_, tid);
  std::vector<GlobalVarMatch> out;
  // v1.4 has no enumeration cap; truncated stays false. Documented as
  // a known gap (see docs/18 — gdb's symbol enumeration is bounded by
  // the binary's debug-info size, not by our config).
  truncated = false;

  // -symbol-info-variables --type PATTERN — PATTERN is a regex on the
  // *DWARF type string*. We escape regex metacharacters in the
  // caller's string so it behaves as a literal substring match (mirrors
  // find_symbols' --name policy).
  std::string pat;
  pat.reserve(type_name.size() * 2);
  for (char c : type_name) {
    if (std::strchr(".^$*+?()[]{}|\\", c)) pat.push_back('\\');
    pat.push_back(c);
  }

  auto rec = st.session->send_command(
      "-symbol-info-variables --type " + pat);
  if (!rec.has_value() || rec->klass == "error") return out;
  if (!rec->payload.is_tuple()) return out;
  auto sit = rec->payload.as_tuple().find("symbols");
  if (sit == rec->payload.as_tuple().end() || !sit->second.is_tuple()) {
    return out;
  }
  auto dit = sit->second.as_tuple().find("debug");
  if (dit == sit->second.as_tuple().end() || !dit->second.is_list()) {
    return out;
  }
  for (const auto& file_entry : dit->second.as_list()) {
    if (!file_entry.is_tuple()) continue;
    const auto& fe = file_entry.as_tuple();
    std::string filename;
    if (auto fnit = fe.find("filename");
        fnit != fe.end() && fnit->second.is_string()) {
      filename = fnit->second.as_string();
    }
    auto inner = fe.find("symbols");
    if (inner == fe.end() || !inner->second.is_list()) continue;
    for (const auto& sym_v : inner->second.as_list()) {
      if (!sym_v.is_tuple()) continue;
      const auto& sym = sym_v.as_tuple();
      GlobalVarMatch g;
      if (auto it = sym.find("name");
          it != sym.end() && it->second.is_string()) {
        g.name = it->second.as_string();
      }
      if (auto it = sym.find("type");
          it != sym.end() && it->second.is_string()) {
        g.type = it->second.as_string();
      }
      if (auto it = sym.find("line");
          it != sym.end() && it->second.is_string()) {
        try { g.line = static_cast<std::uint32_t>(
            std::stoul(it->second.as_string()));
        } catch (...) {}
      }
      // Use the source filename verbatim (basename trim is the
      // dispatcher's concern). `module` mirrors LldbBackend's
      // basename of the owning module.
      g.file = filename;
      if (st.exe_path.has_value()) {
        // Best-effort basename of exe_path.
        auto& p = *st.exe_path;
        auto slash = p.find_last_of('/');
        g.module = (slash == std::string::npos) ? p : p.substr(slash + 1);
      }
      out.push_back(std::move(g));
    }
  }

  // Resolve file_address for each match via `info address NAME` (CLI
  // fall-through). Slow on large result sets — same trade-off as
  // find_symbols's per-result address resolution.
  for (auto& g : out) {
    if (!g.name.empty()) {
      g.file_address = resolve_symbol_address(*st.session, g.name);
    }
  }
  return out;
}

std::vector<StringMatch>
GdbMiBackend::find_strings(TargetId tid, const StringQuery&) {
  // gdb-MI has no built-in string scanner; replicating LldbBackend's
  // section-walking ASCII-run detector would require either embedding
  // a stand-alone ELF/Mach-O parser in the backend or shelling out to
  // `objdump -s -j .rodata`. Both are out of scope for v1.4 abstraction
  // validation. v1.4 contract: return empty, do not throw. The
  // dispatcher's string.list endpoint surfaces the gap; agents needing
  // string scanning switch to --backend=lldb. Re-visit in v1.5.
  //
  // We still validate target_id so callers get the same "unknown
  // target_id" semantics as every other endpoint.
  (void)must_get_target(*impl_, tid);
  return {};
}

// Bulk iteration APIs for the SymbolIndex (post-V1 #18). gdb-MI has no
// efficient module-wide enumeration primitives; replicating LldbBackend's
// SBModule walk via -interpreter-exec console "info functions" / "info
// types" would be slow and forced us to parse free-form gdb output that
// varies between versions. v1.5 contract: gdbmi backend returns empty
// iteration buckets, the dispatcher's correlate.* falls through to
// find_* per target (today's behaviour). Re-visit when --backend=gdb
// gains its own indexer.
DebuggerBackend::ModuleSymbols
GdbMiBackend::iterate_symbols(TargetId tid, std::string_view) {
  (void)must_get_target(*impl_, tid);
  return {};
}

DebuggerBackend::ModuleTypes
GdbMiBackend::iterate_types(TargetId tid, std::string_view) {
  (void)must_get_target(*impl_, tid);
  return {};
}

DebuggerBackend::ModuleStrings
GdbMiBackend::iterate_strings(TargetId tid, std::string_view) {
  (void)must_get_target(*impl_, tid);
  return {};
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
GdbMiBackend::xref_address(TargetId tid, std::uint64_t) {
  // LldbBackend's xref_address walks every instruction in .text and
  // greps each operand string for the literal address — expensive
  // even there. We could replicate via -data-disassemble across the
  // whole .text range, but the full-text scan is materially worse on
  // gdb (per-call MI tuple overhead, no SBProcess::ReadMemoryFromFileCache
  // equivalent). v1.4 punt: empty result. Agents that need xrefs on
  // a gdb-backed session switch to --backend=lldb.
  (void)must_get_target(*impl_, tid);
  return {};
}

std::vector<StringXrefResult>
GdbMiBackend::find_string_xrefs(TargetId tid, const std::string&) {
  // Same scope decision as xref_address — composed of find_strings
  // (also punted on this backend) + xref_address (also punted), so
  // the result would always be empty even if we wired it up. Keep
  // the no-op explicit so the call returns cleanly rather than
  // throwing. Documented gap in docs/18; revisit in v1.5 when a
  // shared static-analysis layer lands above the backend.
  (void)must_get_target(*impl_, tid);
  return {};
}

// ── Threads / frames / values ─────────────────────────────────────────

namespace {

// Parse the "Thread 0x7f... (LWP 12345)" target-id form gdb returns
// in -thread-info, extracting the kernel tid. The Linux pattern is
// `Thread 0xHEX (LWP TID) "name"`; on macOS gdb (rare) the format
// differs. Return 0 on parse failure — the caller falls back to
// gdb's internal numeric thread id.
std::uint64_t parse_kernel_tid(std::string_view target_id) {
  const std::string marker = "LWP ";
  auto pos = target_id.find(marker);
  if (pos == std::string::npos) return 0;
  auto start = pos + marker.size();
  std::uint64_t v = 0;
  for (auto i = start; i < target_id.size(); ++i) {
    char c = target_id[i];
    if (c < '0' || c > '9') break;
    v = v * 10 + static_cast<unsigned>(c - '0');
  }
  return v;
}

// Translate a kernel tid (LDB's ThreadId) to gdb's internal numeric
// thread id. Walks `-thread-info` once per call. Returns 0 if no
// thread matches — the caller turns that into a typed error.
std::uint32_t gdb_id_for_kernel_tid(GdbMiSession& s, ThreadId thread_id) {
  auto thr_rec = send_or_throw(s, "-thread-info");
  if (!thr_rec.payload.is_tuple()) return 0;
  auto it = thr_rec.payload.as_tuple().find("threads");
  if (it == thr_rec.payload.as_tuple().end() || !it->second.is_list()) {
    return 0;
  }
  // Two-precedence match: prefer an exact LWP hit; fall back to a
  // gdb-id match only when the thread has no LWP marker (core
  // targets, Wine). Mixing the two predicates in a single pass is
  // unsafe — a thread with kt==0 and gid==thread_id would shadow a
  // later thread whose LWP actually matches.
  std::uint32_t gid_fallback = 0;
  for (const auto& thr_v : it->second.as_list()) {
    if (!thr_v.is_tuple()) continue;
    const auto& t = thr_v.as_tuple();
    std::uint64_t kt = 0;
    if (auto tgt = t.find("target-id");
        tgt != t.end() && tgt->second.is_string()) {
      kt = parse_kernel_tid(tgt->second.as_string());
    }
    std::uint32_t gid = 0;
    if (auto idit = t.find("id");
        idit != t.end() && idit->second.is_string()) {
      try { gid = static_cast<std::uint32_t>(
          std::stoul(idit->second.as_string()));
      } catch (...) {}
    }
    if (kt == thread_id) return gid;     // exact LWP match — done
    if (kt == 0 && gid == thread_id && gid_fallback == 0) {
      gid_fallback = gid;                // remember; don't return yet
    }
  }
  return gid_fallback;
}

// Select (thread, frame) on gdb. Throws backend::Error if either
// step fails — matches LldbBackend's resolve_frame_locked contract.
void select_thread_frame(GdbMiSession& s, ThreadId thread_id,
                          std::uint32_t frame_index) {
  std::uint32_t gid = gdb_id_for_kernel_tid(s, thread_id);
  if (gid == 0) throw Error("unknown thread id");
  send_or_throw(s, "-thread-select " + std::to_string(gid));
  send_or_throw(s, "-stack-select-frame " + std::to_string(frame_index));
}

// Pull (name, type, value) out of a MI tuple shaped like
// `{name="x",type="int",value="42"}` (no-value entries also occur
// — gdb omits the value field when --simple-values rejects the
// type as too complex). Bytes/address/summary populated as far as
// MI gives us:
//   • address: parsed if value looks like a hex literal (registers,
//     pointer locals). Otherwise unset.
//   • bytes:   we leave empty — MI doesn't surface raw bytes for an
//     SBValue equivalent. Agents needing bytes follow up with
//     mem.read against `address`.
//   • summary: gdb's value string verbatim (e.g. "42", "0x7ff...",
//     `"hello"`). This is the closest analogue to LldbBackend's
//     SBValue::GetSummary || GetValue.
ValueInfo mi_tuple_to_value_info(const MiTuple& t, const char* kind) {
  ValueInfo out;
  if (auto it = t.find("name"); it != t.end() && it->second.is_string()) {
    out.name = it->second.as_string();
  }
  if (auto it = t.find("type"); it != t.end() && it->second.is_string()) {
    out.type = it->second.as_string();
  } else {
    out.type = "<unknown>";
  }
  if (auto it = t.find("value"); it != t.end() && it->second.is_string()) {
    const std::string& v = it->second.as_string();
    out.summary = v;
    if (v.size() >= 3 && v[0] == '0' && (v[1] == 'x' || v[1] == 'X')) {
      out.address = parse_hex_addr(v);
    }
  }
  if (kind) out.kind = kind;
  return out;
}

}  // namespace

std::vector<ThreadInfo> GdbMiBackend::list_threads(TargetId tid) {
  auto& st = must_get_target(*impl_, tid);
  std::vector<ThreadInfo> out;
  if (st.last_status.state == ProcessState::kNone) return out;
  auto rec = send_or_throw(*st.session, "-thread-info");
  if (!rec.payload.is_tuple()) return out;
  auto it = rec.payload.as_tuple().find("threads");
  if (it == rec.payload.as_tuple().end() || !it->second.is_list()) return out;
  for (const auto& thr_v : it->second.as_list()) {
    if (!thr_v.is_tuple()) continue;
    const auto& t = thr_v.as_tuple();
    ThreadInfo ti;
    if (auto idit = t.find("id");
        idit != t.end() && idit->second.is_string()) {
      try { ti.index = static_cast<std::uint32_t>(
          std::stoul(idit->second.as_string()));
      } catch (...) {}
    }
    if (auto tgt = t.find("target-id");
        tgt != t.end() && tgt->second.is_string()) {
      ti.tid = parse_kernel_tid(tgt->second.as_string());
    }
    if (ti.tid == 0) ti.tid = ti.index;   // fallback: gdb id
    if (auto nm = t.find("name");
        nm != t.end() && nm->second.is_string()) {
      ti.name = nm->second.as_string();
    }
    if (auto frame = t.find("frame");
        frame != t.end() && frame->second.is_tuple()) {
      auto fit = frame->second.as_tuple().find("addr");
      if (fit != frame->second.as_tuple().end() &&
          fit->second.is_string()) {
        ti.pc = parse_hex_addr(fit->second.as_string());
      }
    }
    if (auto sit = t.find("state");
        sit != t.end() && sit->second.is_string()) {
      ti.stop_reason = sit->second.as_string();
      ti.state = sit->second.as_string() == "running"
                   ? ProcessState::kRunning
                   : ProcessState::kStopped;
    }
    out.push_back(std::move(ti));
  }
  return out;
}

std::vector<FrameInfo> GdbMiBackend::list_frames(TargetId tid,
                                                    ThreadId thread_id,
                                                    std::uint32_t max_depth) {
  auto& st = must_get_target(*impl_, tid);
  std::vector<FrameInfo> out;
  if (st.last_status.state == ProcessState::kNone) return out;
  // The caller's ThreadId is a kernel tid; gdb's -thread-select wants
  // gdb's internal numeric id. Resolve once, then select the thread.
  std::uint32_t gdb_id = gdb_id_for_kernel_tid(*st.session, thread_id);
  if (gdb_id == 0) throw Error("unknown thread id");
  send_or_throw(*st.session,
                "-thread-select " + std::to_string(gdb_id));
  std::string cmd = "-stack-list-frames";
  if (max_depth > 0) {
    cmd += " 0 " + std::to_string(max_depth - 1);
  }
  auto rec = send_or_throw(*st.session, cmd);
  if (!rec.payload.is_tuple()) return out;
  auto it = rec.payload.as_tuple().find("stack");
  if (it == rec.payload.as_tuple().end() || !it->second.is_list()) return out;
  for (const auto& frame_v : it->second.as_list()) {
    if (!frame_v.is_tuple()) continue;
    const auto& f = frame_v.as_tuple();
    FrameInfo fi;
    if (auto lvit = f.find("level");
        lvit != f.end() && lvit->second.is_string()) {
      try { fi.index = static_cast<std::uint32_t>(
          std::stoul(lvit->second.as_string()));
      } catch (...) {}
    }
    if (auto ait = f.find("addr");
        ait != f.end() && ait->second.is_string()) {
      fi.pc = parse_hex_addr(ait->second.as_string());
    }
    if (auto fnit = f.find("func");
        fnit != f.end() && fnit->second.is_string()) {
      fi.function = fnit->second.as_string();
    }
    if (auto filit = f.find("file");
        filit != f.end() && filit->second.is_string()) {
      fi.file = filit->second.as_string();
    }
    if (auto liit = f.find("line");
        liit != f.end() && liit->second.is_string()) {
      try { fi.line = static_cast<std::uint32_t>(
          std::stoul(liit->second.as_string()));
      } catch (...) {}
    }
    out.push_back(std::move(fi));
  }
  return out;
}
ProcessStatus GdbMiBackend::step_thread(TargetId tid, ThreadId thread_id,
                                          StepKind kind) {
  auto& st = must_get_target(*impl_, tid);
  if (st.last_status.state == ProcessState::kNone) {
    throw Error("no live process; cannot step");
  }
  // v0.3 sync passthrough on thread selection — gdb's --thread on
  // -exec-* is supported but our tid is a kernel tid; the per-thread
  // step is process-wide for now (matches LldbBackend).
  (void)thread_id;
  const char* verb = nullptr;
  switch (kind) {
    case StepKind::kIn:   verb = "-exec-step";        break;
    case StepKind::kOver: verb = "-exec-next";        break;
    case StepKind::kOut:  verb = "-exec-finish";      break;
    case StepKind::kInsn: verb = "-exec-step-instruction"; break;
  }
  send_or_throw(*st.session, verb);
  st.last_status = wait_for_stop(*st.session, std::chrono::seconds(30));
  return st.last_status;
}

ProcessStatus GdbMiBackend::reverse_continue(TargetId tid) {
  auto& st = must_get_target(*impl_, tid);
  if (st.last_status.state == ProcessState::kNone) {
    throw Error("no live process; cannot reverse-continue");
  }
  // gdb returns ^error,msg="Target does not support this command."
  // when reverse exec isn't active (no `record` running, no rr
  // backend). The dispatcher's classifier sees "does not support"
  // and emits -32003 forbidden — that's the correct semantic for
  // "target isn't reverse-capable."
  send_or_throw(*st.session, "-exec-reverse-continue");
  st.last_status = wait_for_stop(*st.session, std::chrono::seconds(30));
  return st.last_status;
}

ProcessStatus GdbMiBackend::reverse_step_thread(TargetId tid,
                                                  ThreadId thread_id,
                                                  ReverseStepKind kind) {
  auto& st = must_get_target(*impl_, tid);
  if (st.last_status.state == ProcessState::kNone) {
    throw Error("no live process; cannot reverse-step");
  }
  (void)thread_id;
  const char* verb = nullptr;
  switch (kind) {
    case ReverseStepKind::kIn:   verb = "-exec-reverse-step";        break;
    case ReverseStepKind::kOver: verb = "-exec-reverse-next";        break;
    case ReverseStepKind::kOut:  verb = "-exec-reverse-finish";      break;
    case ReverseStepKind::kInsn: verb = "-exec-reverse-step-instruction"; break;
  }
  send_or_throw(*st.session, verb);
  st.last_status = wait_for_stop(*st.session, std::chrono::seconds(30));
  return st.last_status;
}
std::vector<ValueInfo> GdbMiBackend::list_locals(TargetId tid,
                                                    ThreadId thread_id,
                                                    std::uint32_t frame_index) {
  auto& st = must_get_target(*impl_, tid);
  std::vector<ValueInfo> out;
  if (st.last_status.state == ProcessState::kNone) {
    throw Error("no live process; cannot list locals");
  }
  select_thread_frame(*st.session, thread_id, frame_index);

  // --simple-values: emit `value` for scalar/pointer types, skip it
  // for aggregates. This keeps the response cheap and matches the
  // LLDB SBValue model where summaries are best-effort.
  auto rec = send_or_throw(*st.session,
                            "-stack-list-locals --simple-values");
  if (!rec.payload.is_tuple()) return out;
  auto it = rec.payload.as_tuple().find("locals");
  if (it == rec.payload.as_tuple().end() || !it->second.is_list()) return out;
  for (const auto& v : it->second.as_list()) {
    if (!v.is_tuple()) continue;
    out.push_back(mi_tuple_to_value_info(v.as_tuple(), "local"));
  }
  return out;
}

std::vector<ValueInfo> GdbMiBackend::list_args(TargetId tid,
                                                  ThreadId thread_id,
                                                  std::uint32_t frame_index) {
  auto& st = must_get_target(*impl_, tid);
  std::vector<ValueInfo> out;
  if (st.last_status.state == ProcessState::kNone) {
    throw Error("no live process; cannot list args");
  }
  select_thread_frame(*st.session, thread_id, frame_index);

  // `1` ≡ --simple-values; LOW HIGH bounds the frame range we want.
  // For a single frame we set both ends to frame_index.
  std::string cmd = "-stack-list-arguments 1 " +
                    std::to_string(frame_index) + " " +
                    std::to_string(frame_index);
  auto rec = send_or_throw(*st.session, cmd);
  if (!rec.payload.is_tuple()) return out;
  auto it = rec.payload.as_tuple().find("stack-args");
  if (it == rec.payload.as_tuple().end() || !it->second.is_list()) return out;
  // stack-args is a list of {level=..., args=[{name,type,value},...]}.
  for (const auto& level_v : it->second.as_list()) {
    if (!level_v.is_tuple()) continue;
    auto ait = level_v.as_tuple().find("args");
    if (ait == level_v.as_tuple().end() || !ait->second.is_list()) continue;
    for (const auto& arg_v : ait->second.as_list()) {
      if (!arg_v.is_tuple()) continue;
      out.push_back(mi_tuple_to_value_info(arg_v.as_tuple(), "arg"));
    }
  }
  return out;
}

std::vector<ValueInfo> GdbMiBackend::list_registers(TargetId tid,
                                                       ThreadId thread_id,
                                                       std::uint32_t frame_index) {
  auto& st = must_get_target(*impl_, tid);
  std::vector<ValueInfo> out;
  if (st.last_status.state == ProcessState::kNone) {
    throw Error("no live process; cannot list registers");
  }
  select_thread_frame(*st.session, thread_id, frame_index);

  // Two-call dance: names first (positional index → name), then
  // values keyed by the same indexes. We zip them into ValueInfo.
  std::vector<std::string> names;
  {
    auto rec = send_or_throw(*st.session, "-data-list-register-names");
    if (rec.payload.is_tuple()) {
      auto it = rec.payload.as_tuple().find("register-names");
      if (it != rec.payload.as_tuple().end() && it->second.is_list()) {
        names.reserve(it->second.as_list().size());
        for (const auto& n : it->second.as_list()) {
          if (n.is_string()) names.push_back(n.as_string());
          else names.emplace_back();
        }
      }
    }
  }

  // Format `x` = hex; the register-values entries are
  // {number="N",value="0x..."} pairs.
  auto rec = send_or_throw(*st.session, "-data-list-register-values x");
  if (!rec.payload.is_tuple()) return out;
  auto it = rec.payload.as_tuple().find("register-values");
  if (it == rec.payload.as_tuple().end() || !it->second.is_list()) return out;
  for (const auto& rv_v : it->second.as_list()) {
    if (!rv_v.is_tuple()) continue;
    const auto& t = rv_v.as_tuple();
    std::uint32_t num = 0;
    if (auto nit = t.find("number");
        nit != t.end() && nit->second.is_string()) {
      try { num = static_cast<std::uint32_t>(
          std::stoul(nit->second.as_string()));
      } catch (...) { continue; }
    }
    ValueInfo vi;
    vi.kind = "register";
    if (num < names.size() && !names[num].empty()) vi.name = names[num];
    // gdb doesn't expose per-register DWARF type info via MI; leave
    // type at "<unknown>" to match LldbBackend's fallback semantics.
    vi.type = "<unknown>";
    if (auto val = t.find("value");
        val != t.end() && val->second.is_string()) {
      const std::string& s = val->second.as_string();
      vi.summary = s;
      if (s.size() >= 3 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        // The value of a register IS its value; keep `address` unset
        // (matches LldbBackend, which doesn't populate load_address
        // for registers — they don't have one).
      }
    }
    out.push_back(std::move(vi));
  }
  return out;
}

EvalResult GdbMiBackend::evaluate_expression(TargetId tid,
                                                ThreadId thread_id,
                                                std::uint32_t frame_index,
                                                const std::string& expr,
                                                const EvalOptions& opts) {
  // EvalOptions has no MI analogue (no SetIgnoreBreakpoints / TryAllThreads
  // equivalents) — gdb's -data-evaluate-expression is unconditional. We
  // accept the option but ignore it; documented in docs/18.
  (void)opts;

  auto& st = must_get_target(*impl_, tid);
  EvalResult out;

  // Pure-numeric expressions (e.g. "1+2") evaluate without an
  // inferior; only do the thread/frame selection when one exists.
  if (st.last_status.state != ProcessState::kNone) {
    // Bad tid/frame_index surfaces a typed Error from
    // select_thread_frame — let it propagate per contract.
    select_thread_frame(*st.session, thread_id, frame_index);
  }

  // Build the MI command — single-line. The expression may contain
  // any C-like syntax; we wrap in quotes and escape per mi_quote
  // rules so embedded quotes/backslashes survive.
  auto rec = st.session->send_command("-data-evaluate-expression " +
                                       mi_quote(expr));
  if (!rec.has_value()) {
    throw Error("gdbmi: subprocess died during evaluate");
  }
  if (rec->klass == "error") {
    // Eval failure is *data*, not an exception — same as LldbBackend.
    out.ok    = false;
    out.error = error_msg_of(*rec);
    return out;
  }
  if (!rec->payload.is_tuple()) {
    out.ok    = false;
    out.error = "evaluate: malformed response";
    return out;
  }
  auto it = rec->payload.as_tuple().find("value");
  if (it == rec->payload.as_tuple().end() || !it->second.is_string()) {
    out.ok    = false;
    out.error = "evaluate: no value in response";
    return out;
  }
  out.ok            = true;
  out.value.name    = expr;          // gdb doesn't echo the expr; use the input
  out.value.kind    = "eval";
  out.value.summary = it->second.as_string();
  // Hex-shaped values mark pointers/addresses; lift them into
  // `address` so agents don't need to re-parse the summary string.
  const std::string& v = it->second.as_string();
  if (v.size() >= 3 && v[0] == '0' && (v[1] == 'x' || v[1] == 'X')) {
    out.value.address = parse_hex_addr(v);
  }

  // Best-effort: follow up with `ptype EXPR` for the type. gdb's
  // ptype prints `type = TYPENAME` on the console stream. Parse the
  // first such line; leave type empty on miss. This is one extra
  // round-trip per eval — acceptable for an interactive surface.
  //
  // SAFETY: `ptype` is a CLI fall-through (no MI quoting); we'd be
  // pasting `expr` directly into the shell-like CLI parser. Restrict
  // to plain identifiers / qualified names so an attacker-controlled
  // expression can't smuggle newlines, quotes, or shell metas into
  // the gdb session. Arbitrary expressions still evaluate via the
  // MI -data-evaluate-expression above; only the optional type
  // lookup is gated.
  auto is_simple_ident = [](const std::string& e) -> bool {
    if (e.empty()) return false;
    for (char raw : e) {
      auto c = static_cast<unsigned char>(raw);
      if (!std::isalnum(c) && c != '_' && c != ':') return false;
    }
    return true;
  };
  if (is_simple_ident(expr)) {
    st.session->drain_async();
    auto pt = st.session->send_command("ptype " + expr);
    if (pt.has_value() && pt->klass == "done") {
      std::string text;
      for (const auto& r : st.session->drain_async()) {
        if (r.kind == MiRecordKind::kConsoleStream) text += r.stream_text;
      }
      const std::string needle = "type = ";
      auto pos = text.find(needle);
      if (pos != std::string::npos) {
        auto start = pos + needle.size();
        auto end = text.find('\n', start);
        std::string ty = (end == std::string::npos)
                           ? text.substr(start) : text.substr(start, end - start);
        // Strip trailing whitespace/\r.
        while (!ty.empty() && (ty.back() == ' ' || ty.back() == '\t' ||
                                ty.back() == '\r')) {
          ty.pop_back();
        }
        if (!ty.empty()) out.value.type = std::move(ty);
      }
    }
  }
  if (out.value.type.empty()) out.value.type = "<unknown>";
  return out;
}

ReadResult GdbMiBackend::read_value_path(TargetId tid, ThreadId thread_id,
                                            std::uint32_t frame_index,
                                            const std::string& path) {
  // value.read accepts a frame-relative dotted/indexed path. In gdb-MI
  // there's no separate path-walker primitive — but a path like
  // "this->next" or "g_arr[2].x" is already a valid C expression that
  // gdb's evaluator understands. So delegate to evaluate_expression
  // and re-wrap the result.
  EvalOptions opts;  // defaults; eval doesn't honor options on this backend
  auto ev = evaluate_expression(tid, thread_id, frame_index, path, opts);

  ReadResult out;
  out.ok    = ev.ok;
  out.error = std::move(ev.error);
  out.value = std::move(ev.value);
  // children: gdb's MI exposes immediate children via `-var-create` /
  // `-var-list-children` (variable objects), but those carry their own
  // lifecycle (per-object IDs, manual delete on the agent's behalf).
  // Skipping in v1.4 — agents who want children re-issue value.read
  // against a deeper path. Documented in docs/18 as an MI gap.
  return out;
}

std::uint64_t GdbMiBackend::read_register(TargetId tid, ThreadId thread_id,
                                             std::uint32_t frame_index,
                                             const std::string& name) {
  auto& st = must_get_target(*impl_, tid);
  if (st.last_status.state == ProcessState::kNone) return 0;
  // Same swallow-error semantic as LldbBackend: unknown / unreadable
  // register returns 0. Bad tid/frame_index surfaces a thrown error
  // via select_thread_frame; we let it propagate.
  select_thread_frame(*st.session, thread_id, frame_index);

  // gdb's $REG syntax inside -data-evaluate-expression returns the
  // register's value as a string (hex on most regs, decimal for
  // small ones like CPU flag fields). mi_quote escapes anything in
  // `name` that could otherwise close the quoted argument early —
  // the register name is operator-controlled so we treat it as
  // untrusted by default.
  auto rec = st.session->send_command(
      "-data-evaluate-expression " + mi_quote("$" + name));
  if (!rec.has_value() || rec->klass == "error") return 0;
  if (!rec->payload.is_tuple()) return 0;
  auto it = rec->payload.as_tuple().find("value");
  if (it == rec->payload.as_tuple().end() || !it->second.is_string()) return 0;
  std::string_view v = it->second.as_string();
  while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) {
    v.remove_prefix(1);
  }
  if (v.size() >= 2 && v[0] == '0' && (v[1] == 'x' || v[1] == 'X')) {
    return parse_hex_addr(v);
  }
  // Decimal fallback. strtoull tolerates trailing junk; leftover
  // text after the digits (e.g. "12345 <symbol+0x10>") is harmless.
  std::string s(v);
  errno = 0;
  char* endp = nullptr;
  unsigned long long u = std::strtoull(s.c_str(), &endp, 10);
  if (errno != 0 || endp == s.c_str()) return 0;
  return static_cast<std::uint64_t>(u);
}

// ── Memory ────────────────────────────────────────────────────────────

namespace {

// Decode a hex byte string (e.g. "f30f1efa") into bytes. Stops at
// odd-length / non-hex-char gracefully.
std::vector<std::uint8_t> hex_decode(std::string_view s) {
  std::vector<std::uint8_t> out;
  out.reserve(s.size() / 2);
  auto val = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
  };
  for (std::size_t i = 0; i + 1 < s.size(); i += 2) {
    int hi = val(s[i]);
    int lo = val(s[i + 1]);
    if (hi < 0 || lo < 0) break;
    out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
  }
  return out;
}

}  // namespace

std::vector<std::uint8_t>
GdbMiBackend::read_memory(TargetId tid, std::uint64_t addr,
                            std::uint64_t size) {
  auto& st = must_get_target(*impl_, tid);
  std::vector<std::uint8_t> out;
  if (size == 0) return out;
  char buf[96];
  std::snprintf(buf, sizeof(buf),
                "-data-read-memory-bytes 0x%llx %llu",
                static_cast<unsigned long long>(addr),
                static_cast<unsigned long long>(size));
  auto rec = send_or_throw(*st.session, buf);
  if (!rec.payload.is_tuple()) return out;
  auto it = rec.payload.as_tuple().find("memory");
  if (it == rec.payload.as_tuple().end() || !it->second.is_list()) return out;
  for (const auto& chunk_v : it->second.as_list()) {
    if (!chunk_v.is_tuple()) continue;
    auto cit = chunk_v.as_tuple().find("contents");
    if (cit == chunk_v.as_tuple().end() || !cit->second.is_string()) continue;
    auto decoded = hex_decode(cit->second.as_string());
    out.insert(out.end(), decoded.begin(), decoded.end());
  }
  return out;
}

std::string GdbMiBackend::read_cstring(TargetId tid, std::uint64_t addr,
                                          std::uint32_t max_len) {
  if (max_len == 0) max_len = 4096;
  auto bytes = read_memory(tid, addr, max_len);
  std::string out;
  out.reserve(bytes.size());
  for (auto b : bytes) {
    if (b == 0) break;
    out.push_back(static_cast<char>(b));
  }
  return out;
}

std::vector<MemoryRegion> GdbMiBackend::list_regions(TargetId tid) {
  auto& st = must_get_target(*impl_, tid);
  std::vector<MemoryRegion> out;
  if (st.last_status.state == ProcessState::kNone) return out;
  // No MI verb for mappings — `info proc mappings` CLI fall-through.
  // Output is space-padded human text; parser extracts start/end/
  // perms/objfile per line. Linux-only in v1.4 (gdb-on-macOS produces
  // different output).
  st.session->drain_async();
  auto r = st.session->send_command("info proc mappings");
  if (!r.has_value() || r->klass != "done") return out;
  std::string text;
  for (const auto& rec : st.session->drain_async()) {
    if (rec.kind == MiRecordKind::kConsoleStream) text += rec.stream_text;
  }
  // Each row: "  0xSTART  0xEND  size  offset  perms  objfile"
  // We split on whitespace and accept rows with >= 5 columns.
  std::size_t pos = 0;
  while (pos < text.size()) {
    auto nl = text.find('\n', pos);
    std::string line = (nl == std::string::npos)
                         ? text.substr(pos) : text.substr(pos, nl - pos);
    if (nl == std::string::npos) pos = text.size();
    else pos = nl + 1;

    // Tokenize on whitespace.
    std::vector<std::string> cols;
    std::size_t i = 0;
    while (i < line.size()) {
      while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) ++i;
      if (i >= line.size()) break;
      std::size_t j = i;
      while (j < line.size() && line[j] != ' ' && line[j] != '\t') ++j;
      cols.push_back(line.substr(i, j - i));
      i = j;
    }
    if (cols.size() < 5) continue;
    if (cols[0].size() < 2 || cols[0][0] != '0' || cols[0][1] != 'x') continue;
    MemoryRegion r2;
    r2.base    = parse_hex_addr(cols[0]);
    auto end   = parse_hex_addr(cols[1]);
    r2.size    = (end > r2.base) ? (end - r2.base) : 0;
    // cols[4] is the perms string ("rwxp" or similar).
    const std::string& p = cols[4];
    r2.readable   = p.find('r') != std::string::npos;
    r2.writable   = p.find('w') != std::string::npos;
    r2.executable = p.find('x') != std::string::npos;
    if (cols.size() > 5) {
      std::string nm = cols[5];
      for (std::size_t k = 6; k < cols.size(); ++k) {
        nm += " " + cols[k];
      }
      r2.name = std::move(nm);
    }
    out.push_back(std::move(r2));
  }
  return out;
}

std::vector<MemorySearchHit>
GdbMiBackend::search_memory(TargetId tid, std::uint64_t lo,
                              std::uint64_t hi,
                              const std::vector<std::uint8_t>& needle,
                              std::uint32_t max_hits) {
  auto& st = must_get_target(*impl_, tid);
  std::vector<MemorySearchHit> out;
  if (needle.empty()) return out;
  // gdb's `find /b ADDR_LO, +SIZE, b0, b1, ...` byte-mode search.
  // We do it as CLI fall-through since MI has no equivalent.
  std::string cmd = "find /b ";
  char buf[64];
  std::snprintf(buf, sizeof(buf), "0x%llx, 0x%llx",
                static_cast<unsigned long long>(lo),
                static_cast<unsigned long long>(hi));
  cmd += buf;
  for (auto b : needle) {
    std::snprintf(buf, sizeof(buf), ", 0x%02x", b);
    cmd += buf;
  }
  st.session->drain_async();
  auto rec = st.session->send_command(cmd);
  if (!rec.has_value() || rec->klass != "done") return out;
  std::string text;
  for (const auto& r : st.session->drain_async()) {
    if (r.kind == MiRecordKind::kConsoleStream) text += r.stream_text;
  }
  // Each hit line is "0xADDR".
  std::size_t pos = 0;
  while (pos < text.size() && out.size() < max_hits) {
    auto open = text.find("0x", pos);
    if (open == std::string::npos) break;
    std::uint64_t a = parse_hex_addr(std::string_view(text).substr(open));
    if (a >= lo && a < hi) {
      MemorySearchHit h;
      h.address = a;
      out.push_back(std::move(h));
    }
    pos = open + 2;
    // Skip the hex digits we just parsed.
    while (pos < text.size() &&
           ((text[pos] >= '0' && text[pos] <= '9') ||
            (text[pos] >= 'a' && text[pos] <= 'f') ||
            (text[pos] >= 'A' && text[pos] <= 'F'))) ++pos;
  }
  return out;
}

// ── Breakpoints ───────────────────────────────────────────────────────

BreakpointHandle
GdbMiBackend::create_breakpoint(TargetId tid, const BreakpointSpec& spec) {
  if (!spec.function.has_value() && !spec.address.has_value() &&
      !spec.file.has_value()) {
    throw Error(
        "create_breakpoint: spec must set function, address, or file+line");
  }
  if (spec.file.has_value() &&
      (!spec.line.has_value() || *spec.line <= 0)) {
    throw Error("create_breakpoint: file form requires positive 'line'");
  }
  auto& st = must_get_target(*impl_, tid);

  // Compose the -break-insert LOCATION argument. The three forms gdb
  // accepts (per MI3 spec):
  //   * "--function NAME"            → resolved at insert time
  //   * "*0xADDR"                    → raw code address
  //   * "FILE:LINE"                  → source coordinate
  // We prefer --function when both function and file+line are set
  // (matches LldbBackend's precedence in BreakpointCreateByName).
  // All caller-supplied strings flow through mi_quote so MI's
  // tokenizer treats them as a single argument and spaces / quotes /
  // backslashes can't smuggle additional commands or close the
  // argument early. The function name + file path are both
  // operator-controlled and may carry C++ namespace / template
  // punctuation; assume nothing about their contents.
  std::string loc;
  if (spec.function.has_value()) {
    loc = "--function " + mi_quote(*spec.function);
  } else if (spec.address.has_value()) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "*0x%llx",
                  static_cast<unsigned long long>(*spec.address));
    loc = buf;
  } else {
    // file:line form. Quote the composed string so embedded spaces
    // in file paths can't fragment the MI argument list.
    loc = mi_quote(*spec.file + ":" + std::to_string(*spec.line));
  }

  // Drain stale async records (e.g. a stop event from a prior step)
  // so the response parser pairs the ^done correctly.
  st.session->drain_async();
  auto rec = send_or_throw(*st.session, "-break-insert " + loc);
  BreakpointHandle h;
  if (!rec.payload.is_tuple()) {
    throw Error("create_breakpoint: malformed -break-insert response");
  }
  auto bit = rec.payload.as_tuple().find("bkpt");
  if (bit == rec.payload.as_tuple().end() || !bit->second.is_tuple()) {
    throw Error("create_breakpoint: response missing bkpt tuple");
  }
  const auto& bkpt = bit->second.as_tuple();
  if (auto it = bkpt.find("number");
      it != bkpt.end() && it->second.is_string()) {
    try { h.bp_id = static_cast<std::int32_t>(
        std::stoi(it->second.as_string()));
    } catch (...) {}
  }
  // gdb's -break-insert reports a single "addr" for a non-pending
  // resolution; pending breakpoints carry addr="<PENDING>" instead
  // (we treat that as 0). LldbBackend exposes locations count via
  // BreakpointHandle::locations — gdb has no direct equivalent in the
  // single-line response, default to 1 when we got an address.
  if (auto it = bkpt.find("addr");
      it != bkpt.end() && it->second.is_string()) {
    h.locations = (parse_hex_addr(it->second.as_string()) != 0) ? 1 : 0;
  }
  if (h.bp_id == 0) {
    throw Error("create_breakpoint: gdb did not return a bp id");
  }
  return h;
}

void GdbMiBackend::set_breakpoint_callback(TargetId tid, std::int32_t bp_id,
                                              BreakpointCallback cb,
                                              void* baton) {
  // Callback semantics on this backend differ materially from LLDB:
  // gdb-MI emits *stopped,reason="breakpoint-hit",bkptno=N async records
  // when the breakpoint fires, but there is no per-callback event
  // dispatch thread analogous to LLDB's process-event thread. The
  // callback can therefore only fire on continue_process / step_thread
  // return paths where wait_for_stop() actively drains async records
  // and matches the bkptno. wait_for_stop in v1.4 does NOT route to
  // these callbacks (that would entangle process control with the
  // probe-callback contract); the registration here is store-only so
  // the orchestrator's "register a callback now, fire on hit" path
  // doesn't throw. Tracking item for v1.5: wire wait_for_stop to call
  // bp_callbacks[bkptno] when it observes a breakpoint-hit stop.
  auto& st = must_get_target(*impl_, tid);
  if (bp_id <= 0) {
    throw Error("set_breakpoint_callback: invalid bp_id");
  }
  GdbBreakpointCb rec;
  rec.cb    = std::move(cb);
  rec.baton = baton;
  st.bp_callbacks[bp_id] = std::move(rec);
}

void GdbMiBackend::disable_breakpoint(TargetId tid, std::int32_t bp_id) {
  auto& st = must_get_target(*impl_, tid);
  // gdb returns ^done even for unknown bp ids (the warning goes to the
  // console stream as "No breakpoint number N."). Mirror LldbBackend's
  // strict contract: unknown bp_id → throw "unknown bp_id".
  st.session->drain_async();
  auto r = st.session->send_command("-break-disable " + std::to_string(bp_id));
  if (!r.has_value()) {
    throw Error("gdbmi: disable_breakpoint: subprocess died");
  }
  if (r->klass == "error") {
    throw_gdb_error(error_msg_of(*r));
  }
  std::string text;
  for (const auto& rec : st.session->drain_async()) {
    if (rec.kind == MiRecordKind::kConsoleStream) text += rec.stream_text;
  }
  if (text.find("No breakpoint number") != std::string::npos) {
    throw Error("disable_breakpoint: unknown bp_id");
  }
}

void GdbMiBackend::enable_breakpoint(TargetId tid, std::int32_t bp_id) {
  auto& st = must_get_target(*impl_, tid);
  st.session->drain_async();
  auto r = st.session->send_command("-break-enable " + std::to_string(bp_id));
  if (!r.has_value()) {
    throw Error("gdbmi: enable_breakpoint: subprocess died");
  }
  if (r->klass == "error") {
    throw_gdb_error(error_msg_of(*r));
  }
  std::string text;
  for (const auto& rec : st.session->drain_async()) {
    if (rec.kind == MiRecordKind::kConsoleStream) text += rec.stream_text;
  }
  if (text.find("No breakpoint number") != std::string::npos) {
    throw Error("enable_breakpoint: unknown bp_id");
  }
}

void GdbMiBackend::delete_breakpoint(TargetId tid, std::int32_t bp_id) {
  auto& st = must_get_target(*impl_, tid);
  // Drop the callback record first so a still-firing async event
  // can't dereference a soon-to-be-deleted baton. Matches LldbBackend's
  // belt-and-braces ordering.
  st.bp_callbacks.erase(bp_id);
  st.session->drain_async();
  auto r = st.session->send_command("-break-delete " + std::to_string(bp_id));
  if (!r.has_value()) {
    throw Error("gdbmi: delete_breakpoint: subprocess died");
  }
  if (r->klass == "error") {
    throw_gdb_error(error_msg_of(*r));
  }
  std::string text;
  for (const auto& rec : st.session->drain_async()) {
    if (rec.kind == MiRecordKind::kConsoleStream) text += rec.stream_text;
  }
  if (text.find("No breakpoint number") != std::string::npos) {
    throw Error("delete_breakpoint: unknown bp_id");
  }
}

}  // namespace ldb::backend::gdbmi
