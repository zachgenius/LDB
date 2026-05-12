// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "agent_expr/bytecode.h"   // agent_expr::Program (probe predicate)
#include "backend/debugger_backend.h"
#include "transport/ssh.h"  // SshHost — for uprobe_bpf remote routing

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

// Probe orchestrator — owns the table of active probes and their
// per-probe ring buffers. Probes are auto-resuming breakpoints with
// structured data capture; this slice ships the `lldb_breakpoint`
// engine. The `uprobe_bpf` engine is M4.
//
// Module layout (per docs/02-ldb-mvp-plan.md §4.5 + §7.1):
//
//   probe.create  → ProbeOrchestrator::create
//   probe.events  → ProbeOrchestrator::events
//   probe.list    → ProbeOrchestrator::list
//   probe.disable → ProbeOrchestrator::disable
//   probe.enable  → ProbeOrchestrator::enable
//   probe.delete  → ProbeOrchestrator::remove
//
// Concurrency contract:
//
//   • The orchestrator is touched by two threads:
//     1) the dispatcher thread (single-threaded today) — issues
//        create / disable / enable / remove / list / events;
//     2) LLDB's process-event thread — invokes the breakpoint callback
//        on hit, which appends to the ring buffer.
//
//   • One std::mutex (`mu_`) guards the probe table AND every
//     per-probe state (capture spec, hit count, ring buffer). Probe
//     fire rates in the lldb_breakpoint engine are bounded by LLDB's
//     stop-and-resume cycle — we're not going to win anything by
//     sharding to per-probe locks at MVP scale.
//
//   • Lifetime: the orchestrator stores ProbeState as
//     std::shared_ptr. The breakpoint trampoline's baton is the raw
//     pointer of that ProbeState (stable: the shared_ptr lives in
//     the orchestrator's table). `remove(probe_id)` MUST first
//     disable the breakpoint, then drain any in-flight callback
//     (LLDB serializes callback invocations per-bp; once
//     disable_breakpoint returns, no further fire is possible), then
//     erase. Callers should treat this contract as load-bearing — a
//     misuse can race-free the baton.
//
// Per-probe persistence:
//
//   • For MVP, events live in an in-memory ring buffer (default cap
//     1024 events / probe). When the buffer is full we drop the
//     oldest. Sqlite-backed durability is deferred — probe events
//     are typically captured fresh per investigation, and the M3
//     session log already records the (probe.create, probe.events)
//     RPCs, so a future replay slice can recreate state without a
//     dedicated persistence layer.
//
// Action semantics (action field):
//
//   • kLogAndContinue (default): capture event → ring buffer →
//     return false (auto-continue).
//   • kStop: capture event → ring buffer → return true. Inferior
//     stays stopped; agent learns via process.state.
//   • kStoreArtifact: capture event → write all memory[] captures
//     to the ArtifactStore keyed by (build_id, name_with_{hit}).
//     Returns false (continue). Each memory capture is stored as a
//     separate artifact named "<template>" or "<template>_<idx>"
//     when there is more than one capture; the {hit} placeholder
//     in the template is substituted with the per-probe hit_seq.
//     Artifact write failures are logged to stderr and the event
//     still records, with the artifact_id/artifact_name fields
//     unset (the agent can branch on their absence).

namespace ldb::store { class ArtifactStore; }

namespace ldb::probes {

struct CaptureSpec {
  // Architecture-named registers to snapshot at hit time.
  std::vector<std::string> registers;

  // Memory regions to read at hit time. Either rooted at a register
  // (read [reg, reg+len)) or at an absolute address.
  struct MemSpec {
    enum class Source { kRegister, kAbsolute };
    Source        source = Source::kAbsolute;
    std::string   reg_name;        // when kRegister
    std::uint64_t addr   = 0;      // when kAbsolute
    std::uint32_t len    = 0;
    std::string   name;            // user-given label for the captured blob
  };
  std::vector<MemSpec> memory;
};

enum class Action {
  kLogAndContinue,
  kStop,
  kStoreArtifact,
};

// `uprobe_bpf` engine selector — only the where-form, capture.args,
// optional pid-filter, and optional remote host are meaningful for
// this engine. Memory/registers from CaptureSpec are ignored.
struct BpftraceWhere {
  enum class Kind : std::uint8_t {
    kUprobe,        // path:symbol
    kTracepoint,    // category:name
    kKprobe,        // function name
  };
  Kind          kind = Kind::kUprobe;
  std::string   target;
};

struct ProbeSpec {
  backend::TargetId  target_id = 0;
  std::string        kind;          // "lldb_breakpoint" or "uprobe_bpf"
  // Where the probe sits — exactly one of the three forms must be set.
  // The orchestrator forwards to backend::create_breakpoint.
  backend::BreakpointSpec where;
  // Human-readable rendering of `where`, used in list() output and
  // logs. Set by create() from the BreakpointSpec.
  std::string        where_expr;

  CaptureSpec        capture;
  Action             action = Action::kLogAndContinue;

  // For action == kStoreArtifact:
  std::string        artifact_name_template;  // "schema_{hit}.bin"
  std::string        build_id;                 // required when storing

  // Parsed but UNENFORCED in this slice (deferred to a later M3 slice).
  // Stored verbatim for round-trip in list() output if useful.
  std::string        rate_limit_text;

  // --- uprobe_bpf only ----------------------------------------------------
  std::optional<BpftraceWhere>      bpftrace_where;
  std::vector<std::string>          bpftrace_args;     // arg0,arg1,...
  std::optional<std::int64_t>       bpftrace_filter_pid;
  std::optional<transport::SshHost> bpftrace_host;

  // --- predicate (post-V1 #25 phase-2) ------------------------------------
  // Optional agent-expression program. When set, the orchestrator's
  // on_breakpoint_hit callback evaluates it against (target, tid,
  // frame=0) and drops the event when the result is zero. Only
  // honoured for kind=="lldb_breakpoint"; the BPF / agent paths have
  // their own filtering surface.
  std::optional<agent_expr::Program> predicate;
};

struct ProbeEvent {
  std::uint64_t                          hit_seq = 0;
  std::int64_t                           ts_ns   = 0;
  std::uint64_t                          tid     = 0;
  std::uint64_t                          pc      = 0;
  std::map<std::string, std::uint64_t>   registers;

  struct MemCapture {
    std::string                 name;
    std::vector<std::uint8_t>   bytes;
  };
  std::vector<MemCapture>                memory;

  struct Site {
    std::string  function;
    std::string  file;
    int          line = 0;
  } site;

  std::optional<std::int64_t>            artifact_id;
  std::optional<std::string>             artifact_name;
};

class ProbeOrchestrator {
 public:
  // Default ring-buffer capacity per probe. Documented in the header
  // so callers writing replay tooling know the floor.
  static constexpr std::size_t kEventBufferCap = 1024;

  // ArtifactStore is optional (nullptr) for probes that never use
  // action == kStoreArtifact.
  ProbeOrchestrator(std::shared_ptr<backend::DebuggerBackend> backend,
                    std::shared_ptr<store::ArtifactStore> artifacts);
  ~ProbeOrchestrator();

  ProbeOrchestrator(const ProbeOrchestrator&)            = delete;
  ProbeOrchestrator& operator=(const ProbeOrchestrator&) = delete;

  // Create a probe. Returns the assigned probe_id (e.g. "p1"). Throws
  // backend::Error on backend-side failure (bad target_id, bp create
  // failed) or std::invalid_argument on bad spec (kStoreArtifact
  // without build_id, unknown action/kind).
  std::string create(const ProbeSpec& spec);

  // Lifecycle. enable / disable / remove are idempotent in the sense
  // that they throw only on unknown probe_id; toggling an
  // already-enabled probe is a no-op.
  void enable(const std::string& probe_id);
  void disable(const std::string& probe_id);
  void remove(const std::string& probe_id);

  struct ListEntry {
    std::string   probe_id;
    std::string   kind;
    std::string   where_expr;
    bool          enabled            = false;
    std::uint64_t hit_count          = 0;
    // Post-V1 #25 phase-2: predicate metadata.
    //   has_predicate     — true when the probe was created with a
    //                        predicate.
    //   predicate_dropped — running count of events the predicate
    //                        filtered out by *evaluating to zero*.
    //   predicate_errored — running count of events the predicate
    //                        filtered out because eval() returned a
    //                        non-kOk error (broken bytecode, mem
    //                        read failed, etc.). Separate counter so
    //                        an agent debugging a broken predicate
    //                        can distinguish "filtered as designed"
    //                        from "predicate is faulty."
    bool          has_predicate      = false;
    std::uint64_t predicate_dropped  = 0;
    std::uint64_t predicate_errored  = 0;
  };
  std::vector<ListEntry> list();

  // Pull events with hit_seq > since (since=0 → all). Returns at most
  // `max` events, oldest first. Throws on unknown probe_id.
  std::vector<ProbeEvent> events(const std::string& probe_id,
                                  std::uint64_t since,
                                  std::uint64_t max);

  // Test/utility — returns nullopt for unknown probe_id; otherwise
  // (kind, where_expr, enabled, hit_count). Less ceremony than list()
  // when you only want one row.
  std::optional<ListEntry> info(const std::string& probe_id);

 private:
  struct ProbeState;

  std::shared_ptr<backend::DebuggerBackend>     backend_;
  std::shared_ptr<store::ArtifactStore>         artifacts_;

  std::mutex                                    mu_;
  std::map<std::string, std::shared_ptr<ProbeState>> probes_;
  std::uint64_t                                 next_probe_seq_ = 1;

  // Lazily-spawned ldb-probe-agent shared by every kind=="agent" probe
  // for the session lifetime. One subprocess per orchestrator. nullptr
  // until the first kind=="agent" probe.create.
  std::unique_ptr<class AgentEngine>            agent_engine_;

  static bool on_breakpoint_hit(void* baton,
                                const backend::BreakpointCallbackArgs& args);

  // kind=="uprobe_bpf" path.
  std::string create_uprobe_bpf(const ProbeSpec& spec_in);

  // kind=="agent" path (post-V1 plan #12 phase-3).
  std::string create_agent(const ProbeSpec& spec_in);
};

}  // namespace ldb::probes
