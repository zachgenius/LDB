// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "backend/debugger_backend.h"  // backend::TargetId
#include "protocol/jsonrpc.h"
#include "store/session_store.h"

#include <nlohmann/json.hpp>

#include <cstddef>
#include <list>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>

namespace ldb::backend { class DebuggerBackend; }
namespace ldb::store   { class ArtifactStore; }
namespace ldb::probes  { class ProbeOrchestrator; }
namespace ldb::observers { class ExecAllowlist; }
namespace ldb::python  { class Callable; }

namespace ldb::daemon {

// Routes a parsed Request to the appropriate handler and returns a Response.
// All handlers are synchronous in M0.
class Dispatcher {
 public:
  // Backend is required. The artifact store and session store are
  // optional only because the unit tests that pre-date M3 construct
  // dispatchers without them; any artifact.* / session.* call against a
  // null store returns -32002 (kBadState) with a deterministic "store
  // not configured" message.
  //
  // When a session is "attached" (after session.attach), every dispatch
  // — including the attach itself — appends a row to the session's
  // rpc_log. The dispatcher is single-threaded today; the active writer
  // is held in a plain unique_ptr without further locking.
  explicit Dispatcher(std::shared_ptr<backend::DebuggerBackend> backend,
                      std::shared_ptr<store::ArtifactStore> artifacts = {},
                      std::shared_ptr<store::SessionStore> sessions = {},
                      std::shared_ptr<probes::ProbeOrchestrator> probes = {},
                      std::shared_ptr<observers::ExecAllowlist>
                          exec_allowlist = {},
                      std::string backend_name = "lldb");
  ~Dispatcher();

  protocol::Response dispatch(const protocol::Request& req);

 private:
  std::shared_ptr<backend::DebuggerBackend>    backend_;
  std::shared_ptr<store::ArtifactStore>        artifacts_;
  std::shared_ptr<store::SessionStore>         sessions_;
  std::shared_ptr<probes::ProbeOrchestrator>   probes_;
  std::shared_ptr<observers::ExecAllowlist>    exec_allowlist_;
  // Active backend label echoed via hello.data.capabilities.backend.
  // Set by the constructor from main.cpp's --backend resolution.
  std::string                                  backend_name_;
  // Set by session.attach, cleared by session.detach. While set, every
  // dispatch result is appended to the session's rpc_log.
  std::unique_ptr<store::SessionStore::Writer> active_session_writer_;
  std::string active_session_id_;  // for info / debug

  // Diff-cache for post-V1 plan #5 (view.diff_against). Stores the
  // most recent N array responses keyed by (method, params-canonical,
  // snapshot). Endpoints that opt in record their array under the
  // current snapshot before slicing/projection; when a subsequent
  // call carries view.diff_against=<prior_snapshot>, the dispatcher
  // looks up the prior items and emits the set-symmetric-difference
  // instead of the full array. LRU-bounded so long-running sessions
  // don't grow without limit; cache misses surface as a
  // diff_baseline_missing flag in the response.
  struct DiffCacheEntry {
    std::string    cache_key;
    nlohmann::json items;
  };
  static constexpr std::size_t kDiffCacheCapacity = 64;
  std::list<DiffCacheEntry> diff_cache_;     // MRU at front
  std::unordered_map<std::string, std::list<DiffCacheEntry>::iterator>
      diff_cache_index_;
  void                diff_cache_put(std::string key, nlohmann::json items);
  std::optional<nlohmann::json>
                       diff_cache_get(const std::string& key);
  // Build a canonical key for the (method, params, snapshot) tuple.
  // The "view" sub-object is excluded from params hashing so that
  // changing pagination doesn't invalidate the cached baseline.
  static std::string  diff_cache_key(const std::string& method,
                                     const nlohmann::json& params,
                                     const std::string& snapshot);

  // Cost samples for post-V1 plan #4 (measured cost preview). Per
  // endpoint we accumulate a bounded ring of the most recent N
  // _cost.tokens_est observations plus a running total count.
  // describe.endpoints reads p50 from the ring and emits it alongside
  // the static cost_hint, so agents can budget against measured
  // numbers from the actual session rather than the original guess.
  static constexpr std::size_t kCostRingCapacity = 100;
  struct CostSampleRing {
    std::vector<std::uint64_t> recent;   // ≤ kCostRingCapacity entries
    std::size_t                next = 0; // write cursor (when full)
    std::uint64_t              total = 0; // lifetime count, not just ring size
  };
  std::unordered_map<std::string, CostSampleRing> cost_samples_;
  void                record_cost_sample(const std::string& method,
                                          std::uint64_t tokens);
  std::optional<std::uint64_t>
                       cost_p50(const std::string& method) const;
  std::uint64_t        cost_total(const std::string& method) const;

  // Post-V1 plan #14 phase-1: registered Python frame unwinders. Keyed
  // by target_id; calling process.set_python_unwinder twice on the
  // same target replaces. We hold by unique_ptr so the Callable's
  // GIL-acquire-on-destruct happens in this dispatcher's thread when
  // the entry is overwritten or the map empties at shutdown.
  std::unordered_map<backend::TargetId,
                     std::unique_ptr<python::Callable>> python_unwinders_;

  // Handlers
  protocol::Response handle_hello(const protocol::Request& req);
  protocol::Response handle_describe_endpoints(const protocol::Request& req);
  protocol::Response handle_target_open(const protocol::Request& req);
  protocol::Response handle_target_create_empty(const protocol::Request& req);
  protocol::Response handle_target_attach(const protocol::Request& req);
  protocol::Response handle_target_connect_remote(const protocol::Request& req);
  protocol::Response handle_target_connect_remote_ssh(const protocol::Request& req);
  protocol::Response handle_target_load_core(const protocol::Request& req);
  protocol::Response handle_module_list(const protocol::Request& req);
  protocol::Response handle_target_close(const protocol::Request& req);
  protocol::Response handle_target_list(const protocol::Request& req);
  protocol::Response handle_target_label(const protocol::Request& req);
  protocol::Response handle_type_layout(const protocol::Request& req);
  protocol::Response handle_symbol_find(const protocol::Request& req);
  protocol::Response handle_string_list(const protocol::Request& req);
  protocol::Response handle_disasm_range(const protocol::Request& req);
  protocol::Response handle_disasm_function(const protocol::Request& req);
  protocol::Response handle_xref_addr(const protocol::Request& req);
  protocol::Response handle_string_xref(const protocol::Request& req);
  protocol::Response handle_static_globals_of_type(
      const protocol::Request& req);

  // Cross-binary correlation (Tier 3 §10, scoped). Pure dispatcher
  // composition over existing primitives — no new backend methods.
  protocol::Response handle_correlate_types(const protocol::Request& req);
  protocol::Response handle_correlate_symbols(const protocol::Request& req);
  protocol::Response handle_correlate_strings(const protocol::Request& req);

  protocol::Response handle_process_launch(const protocol::Request& req);
  protocol::Response handle_process_state(const protocol::Request& req);
  protocol::Response handle_process_continue(const protocol::Request& req);
  protocol::Response handle_process_kill(const protocol::Request& req);
  protocol::Response handle_process_detach(const protocol::Request& req);
  protocol::Response handle_process_save_core(const protocol::Request& req);
  protocol::Response handle_process_step(const protocol::Request& req);
  protocol::Response handle_process_reverse_continue(const protocol::Request& req);
  protocol::Response handle_process_reverse_step(const protocol::Request& req);

  protocol::Response handle_thread_list(const protocol::Request& req);
  protocol::Response handle_thread_frames(const protocol::Request& req);
  protocol::Response handle_thread_continue(const protocol::Request& req);
  protocol::Response handle_thread_reverse_step(const protocol::Request& req);

  protocol::Response handle_frame_locals(const protocol::Request& req);
  protocol::Response handle_frame_args(const protocol::Request& req);
  protocol::Response handle_frame_registers(const protocol::Request& req);

  protocol::Response handle_value_eval(const protocol::Request& req);
  protocol::Response handle_value_read(const protocol::Request& req);

  protocol::Response handle_mem_read(const protocol::Request& req);
  protocol::Response handle_mem_read_cstr(const protocol::Request& req);
  protocol::Response handle_mem_regions(const protocol::Request& req);
  protocol::Response handle_mem_search(const protocol::Request& req);
  protocol::Response handle_mem_dump_artifact(const protocol::Request& req);

  protocol::Response handle_artifact_put(const protocol::Request& req);
  protocol::Response handle_artifact_hypothesis_template(
      const protocol::Request& req);
  protocol::Response handle_artifact_get(const protocol::Request& req);
  protocol::Response handle_artifact_list(const protocol::Request& req);
  protocol::Response handle_artifact_tag(const protocol::Request& req);
  protocol::Response handle_artifact_delete(const protocol::Request& req);
  protocol::Response handle_artifact_relate(const protocol::Request& req);
  protocol::Response handle_artifact_relations(const protocol::Request& req);
  protocol::Response handle_artifact_unrelate(const protocol::Request& req);

  protocol::Response handle_session_create(const protocol::Request& req);
  protocol::Response handle_session_attach(const protocol::Request& req);
  protocol::Response handle_session_detach(const protocol::Request& req);
  protocol::Response handle_session_list(const protocol::Request& req);
  protocol::Response handle_session_info(const protocol::Request& req);
  protocol::Response handle_session_export(const protocol::Request& req);
  protocol::Response handle_session_import(const protocol::Request& req);
  protocol::Response handle_session_diff(const protocol::Request& req);
  protocol::Response handle_session_targets(const protocol::Request& req);
  protocol::Response handle_artifact_export(const protocol::Request& req);
  protocol::Response handle_artifact_import(const protocol::Request& req);

  protocol::Response handle_recipe_create(const protocol::Request& req);
  protocol::Response handle_recipe_from_session(const protocol::Request& req);
  protocol::Response handle_recipe_list(const protocol::Request& req);
  protocol::Response handle_recipe_get(const protocol::Request& req);
  protocol::Response handle_recipe_run(const protocol::Request& req);
  protocol::Response handle_recipe_delete(const protocol::Request& req);
  protocol::Response handle_recipe_lint(const protocol::Request& req);
  protocol::Response handle_recipe_reload(const protocol::Request& req);

  protocol::Response handle_probe_create(const protocol::Request& req);
  protocol::Response handle_probe_events(const protocol::Request& req);
  protocol::Response handle_probe_list(const protocol::Request& req);
  protocol::Response handle_probe_disable(const protocol::Request& req);
  protocol::Response handle_probe_enable(const protocol::Request& req);
  protocol::Response handle_probe_delete(const protocol::Request& req);

  // Post-V1 plan #13: perf record/report (docs/22-perf-integration.md).
  protocol::Response handle_perf_record(const protocol::Request& req);
  protocol::Response handle_perf_report(const protocol::Request& req);
  protocol::Response handle_perf_cancel(const protocol::Request& req);

  // Post-V1 plan #12 phase-2: ldb-probe-agent wire shim
  // (docs/21-probe-agent.md). Phase-2 ships hello; attach_* + poll
  // come with the orchestrator wiring in a follow-up commit.
  protocol::Response handle_agent_hello(const protocol::Request& req);

  // Post-V1 plan #14 phase-1: Python frame unwinders. Phase-1 stores
  // the Callable per target_id and exposes process.unwind_one as a
  // test-and-observability endpoint that invokes the registered
  // unwinder synchronously against caller-supplied {ip,sp,fp}. Real
  // SBUnwinder hookup so LLDB's stack-walker calls the Callable
  // during ordinary process.list_frames is phase-2.
  protocol::Response handle_process_set_python_unwinder(const protocol::Request& req);
  protocol::Response handle_process_unwind_one(const protocol::Request& req);
  // Phase-2: iterate the unwinder until it returns null / exhausts
  // max_frames / detects a cycle. Independent of LLDB's SBUnwinder
  // (full integration deferred); useful today for offline analysis
  // and stack-walking validation against known-good traces.
  protocol::Response handle_process_list_frames_python(const protocol::Request& req);

  protocol::Response handle_observer_proc_fds(const protocol::Request& req);
  protocol::Response handle_observer_proc_maps(const protocol::Request& req);
  protocol::Response handle_observer_proc_status(const protocol::Request& req);
  protocol::Response handle_observer_net_sockets(const protocol::Request& req);
  protocol::Response handle_observer_net_tcpdump(const protocol::Request& req);
  protocol::Response handle_observer_net_igmp(const protocol::Request& req);
  protocol::Response handle_observer_exec(const protocol::Request& req);

  // The actual routing logic; dispatch() wraps this with rpc-log
  // bookkeeping when a session is attached.
  protocol::Response dispatch_inner(const protocol::Request& req);
};

}  // namespace ldb::daemon
