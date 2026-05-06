#pragma once

#include "protocol/jsonrpc.h"
#include "store/session_store.h"

#include <memory>
#include <string>

namespace ldb::backend { class DebuggerBackend; }
namespace ldb::store   { class ArtifactStore; }
namespace ldb::probes  { class ProbeOrchestrator; }
namespace ldb::observers { class ExecAllowlist; }

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
                          exec_allowlist = {});
  ~Dispatcher();

  protocol::Response dispatch(const protocol::Request& req);

 private:
  std::shared_ptr<backend::DebuggerBackend>    backend_;
  std::shared_ptr<store::ArtifactStore>        artifacts_;
  std::shared_ptr<store::SessionStore>         sessions_;
  std::shared_ptr<probes::ProbeOrchestrator>   probes_;
  std::shared_ptr<observers::ExecAllowlist>    exec_allowlist_;
  // Set by session.attach, cleared by session.detach. While set, every
  // dispatch result is appended to the session's rpc_log.
  std::unique_ptr<store::SessionStore::Writer> active_session_writer_;
  std::string active_session_id_;  // for info / debug

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

  protocol::Response handle_thread_list(const protocol::Request& req);
  protocol::Response handle_thread_frames(const protocol::Request& req);
  protocol::Response handle_thread_continue(const protocol::Request& req);

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

  protocol::Response handle_probe_create(const protocol::Request& req);
  protocol::Response handle_probe_events(const protocol::Request& req);
  protocol::Response handle_probe_list(const protocol::Request& req);
  protocol::Response handle_probe_disable(const protocol::Request& req);
  protocol::Response handle_probe_enable(const protocol::Request& req);
  protocol::Response handle_probe_delete(const protocol::Request& req);

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
