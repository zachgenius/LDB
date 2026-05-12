// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "backend/debugger_backend.h"

#include <memory>

namespace lldb {  // forward decls so header doesn't pull SBAPI
class SBDebugger;
}

namespace ldb::backend {

class LldbBackend final : public DebuggerBackend {
 public:
  LldbBackend();
  ~LldbBackend() override;

  LldbBackend(const LldbBackend&) = delete;
  LldbBackend& operator=(const LldbBackend&) = delete;

  OpenResult open_executable(const std::string& path) override;
  OpenResult create_empty_target() override;
  OpenResult load_core(const std::string& core_path) override;
  std::vector<Module> list_modules(TargetId tid) override;
  std::optional<TypeLayout>
      find_type_layout(TargetId tid, const std::string& name) override;
  std::vector<SymbolMatch>
      find_symbols(TargetId tid, const SymbolQuery& query) override;
  std::vector<GlobalVarMatch>
      find_globals_of_type(TargetId tid, std::string_view type_name,
                           bool& strict_out) override;
  std::vector<StringMatch>
      find_strings(TargetId tid, const StringQuery& query) override;
  ModuleSymbols
      iterate_symbols(TargetId tid, std::string_view build_id) override;
  ModuleTypes
      iterate_types(TargetId tid, std::string_view build_id) override;
  ModuleStrings
      iterate_strings(TargetId tid, std::string_view build_id) override;
  std::vector<DisasmInsn>
      disassemble_range(TargetId tid,
                        std::uint64_t start_addr,
                        std::uint64_t end_addr) override;
  std::vector<XrefMatch>
      xref_address(TargetId tid, std::uint64_t target_addr) override;
  std::vector<StringXrefResult>
      find_string_xrefs(TargetId tid, const std::string& text) override;

  ProcessStatus launch_process(TargetId tid,
                               const LaunchOptions& opts) override;
  ProcessStatus get_process_state(TargetId tid) override;
  ProcessStatus continue_process(TargetId tid) override;
  ProcessStatus continue_thread(TargetId target_id,
                                ThreadId thread_id) override;
  ProcessStatus kill_process(TargetId tid) override;
  ProcessStatus attach(TargetId tid, std::int32_t pid) override;
  ProcessStatus detach_process(TargetId tid) override;
  ProcessStatus connect_remote_target(TargetId tid,
                                      const std::string& url,
                                      const std::string& plugin_name) override;
  ConnectRemoteSshResult
      connect_remote_target_ssh(TargetId tid,
                                const ConnectRemoteSshOptions& opts) override;
  bool save_core(TargetId tid, const std::string& path) override;

  std::vector<ThreadInfo> list_threads(TargetId tid) override;
  std::vector<FrameInfo>  list_frames(TargetId tid, ThreadId thread_id,
                                      std::uint32_t max_depth) override;
  ProcessStatus step_thread(TargetId tid, ThreadId thread_id,
                            StepKind kind) override;

  ProcessStatus reverse_continue(TargetId tid) override;
  ProcessStatus reverse_step_thread(TargetId tid, ThreadId thread_id,
                                    ReverseStepKind kind) override;

  std::vector<ValueInfo>
      list_locals(TargetId tid, ThreadId thread_id,
                  std::uint32_t frame_index) override;
  std::vector<ValueInfo>
      list_args(TargetId tid, ThreadId thread_id,
                std::uint32_t frame_index) override;
  std::vector<ValueInfo>
      list_registers(TargetId tid, ThreadId thread_id,
                     std::uint32_t frame_index) override;
  EvalResult evaluate_expression(TargetId tid, ThreadId thread_id,
                                 std::uint32_t frame_index,
                                 const std::string& expr,
                                 const EvalOptions& opts) override;
  ReadResult read_value_path(TargetId tid, ThreadId thread_id,
                             std::uint32_t frame_index,
                             const std::string& path) override;

  std::vector<std::uint8_t>
      read_memory(TargetId tid, std::uint64_t addr,
                  std::uint64_t size) override;
  std::string
      read_cstring(TargetId tid, std::uint64_t addr,
                   std::uint32_t max_len) override;
  std::vector<MemoryRegion> list_regions(TargetId tid) override;
  std::vector<MemorySearchHit>
      search_memory(TargetId tid, std::uint64_t start, std::uint64_t length,
                    const std::vector<std::uint8_t>& needle,
                    std::uint32_t max_hits) override;

  BreakpointHandle
      create_breakpoint(TargetId tid, const BreakpointSpec& spec) override;
  void set_breakpoint_callback(TargetId tid, std::int32_t bp_id,
                               BreakpointCallback cb, void* baton) override;
  void disable_breakpoint(TargetId tid, std::int32_t bp_id) override;
  void enable_breakpoint(TargetId tid, std::int32_t bp_id) override;
  void delete_breakpoint(TargetId tid, std::int32_t bp_id) override;

  std::uint64_t read_register(TargetId tid, ThreadId thread_id,
                              std::uint32_t frame_index,
                              const std::string& name) override;

  void close_target(TargetId tid) override;

  std::vector<TargetInfo> list_targets() override;
  void label_target(TargetId tid, std::string label) override;
  std::optional<std::string> get_target_label(TargetId tid) override;

  std::string snapshot_for_target(TargetId tid) override;

  void attach_target_resource(TargetId tid,
                              std::unique_ptr<TargetResource> r) override;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;

  // Drain module-load events from impl_->module_listener and invalidate
  // the layout cache of any target whose broadcaster fired. Must be
  // called with impl_->mu held. Slice 1c — see comment in
  // lldb_backend.cpp.
  void drain_module_events_locked();
};

}  // namespace ldb::backend
