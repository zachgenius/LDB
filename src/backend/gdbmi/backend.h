// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "backend/debugger_backend.h"
#include "backend/gdbmi/session.h"

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

// GdbMiBackend — second DebuggerBackend implementation (post-V1 #8).
//
// Wraps one `gdb --interpreter=mi3` subprocess per backend instance.
// Each TargetId corresponds to a gdb "inferior" (gdb's term for what
// LDB calls a target). gdb's natural id (`i1`, `i2`, ...) is mapped
// to LDB's opaque TargetId via per-backend maps maintained by the
// open/attach/close family.
//
// Full mapping table from DebuggerBackend virtuals to MI commands
// lives in docs/18-gdbmi-backend.md.
//
// Threading: the dispatcher is single-threaded today, so this class
// is not internally synchronised beyond what GdbMiSession provides
// for the request/response pairing on its reader thread. If the
// dispatcher ever grows real parallelism, every method here needs a
// per-backend mutex; the impl_->mu_ field is already in place as a
// placeholder.

namespace ldb::backend::gdbmi {

class GdbMiBackend final : public DebuggerBackend {
 public:
  GdbMiBackend();
  ~GdbMiBackend() override;

  GdbMiBackend(const GdbMiBackend&)            = delete;
  GdbMiBackend& operator=(const GdbMiBackend&) = delete;

  // ── target / process lifecycle ──────────────────────────────────────
  OpenResult open_executable(const std::string& path,
                             const OpenOptions& opts = OpenOptions{}) override;
  OpenResult create_empty_target() override;
  OpenResult load_core(const std::string& core_path) override;
  ProcessStatus launch_process(TargetId tid,
                               const LaunchOptions& opts) override;
  ProcessStatus get_process_state(TargetId tid) override;
  ProcessStatus continue_process(TargetId tid) override;
  ProcessStatus continue_thread(TargetId target_id,
                                ThreadId thread_id) override;
  ProcessStatus suspend_thread(TargetId target_id,
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
  void close_target(TargetId tid) override;
  std::vector<TargetInfo> list_targets() override;

  // ── static analysis ────────────────────────────────────────────────
  std::vector<Module> list_modules(TargetId tid) override;
  std::optional<TypeLayout>
      find_type_layout(TargetId tid, const std::string& name) override;
  std::vector<SymbolMatch>
      find_symbols(TargetId tid, const SymbolQuery& query) override;
  std::vector<GlobalVarMatch>
      find_globals_of_type(TargetId tid, std::string_view type_name,
                           bool& truncated) override;
  std::vector<StringMatch>
      find_strings(TargetId tid, const StringQuery& query) override;
  ModuleSymbols
      iterate_symbols(TargetId tid, std::string_view build_id) override;
  ModuleTypes
      iterate_types(TargetId tid, std::string_view build_id) override;
  ModuleStrings
      iterate_strings(TargetId tid, std::string_view build_id) override;
  std::vector<DisasmInsn>
      disassemble_range(TargetId tid, std::uint64_t lo,
                        std::uint64_t hi) override;
  std::vector<XrefMatch>
      xref_address(TargetId tid, std::uint64_t addr) override;
  std::vector<StringXrefResult>
      find_string_xrefs(TargetId tid, const std::string& text) override;

  // ── threads / frames / values ──────────────────────────────────────
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
  std::uint64_t read_register(TargetId tid, ThreadId thread_id,
                              std::uint32_t frame_index,
                              const std::string& name) override;

  // ── memory ─────────────────────────────────────────────────────────
  std::vector<std::uint8_t>
      read_memory(TargetId tid, std::uint64_t addr,
                  std::uint64_t size) override;
  std::string read_cstring(TargetId tid, std::uint64_t addr,
                           std::uint32_t max_len) override;
  std::vector<MemoryRegion> list_regions(TargetId tid) override;
  std::vector<MemorySearchHit>
      search_memory(TargetId tid, std::uint64_t lo, std::uint64_t hi,
                    const std::vector<std::uint8_t>& needle,
                    std::uint32_t max_hits) override;

  // ── breakpoints ────────────────────────────────────────────────────
  BreakpointHandle
      create_breakpoint(TargetId tid, const BreakpointSpec& spec) override;
  void set_breakpoint_callback(TargetId tid, std::int32_t bp_id,
                               BreakpointCallback cb, void* ctx) override;
  void disable_breakpoint(TargetId tid, std::int32_t bp_id) override;
  void enable_breakpoint(TargetId tid, std::int32_t bp_id) override;
  void delete_breakpoint(TargetId tid, std::int32_t bp_id) override;

  // ── daemon-side state (no MI calls) ────────────────────────────────
  void label_target(TargetId tid, std::string label) override;
  std::optional<std::string> get_target_label(TargetId tid) override;
  std::string snapshot_for_target(TargetId tid) override;
  void attach_target_resource(TargetId tid,
      std::unique_ptr<DebuggerBackend::TargetResource> resource) override;

  // Public so anonymous-namespace helpers in backend.cpp can reach
  // the per-target state (must_get_target). Treat as a friend-style
  // implementation detail — callers outside the .cpp shouldn't poke
  // at this.
  struct Impl;

 private:
  std::unique_ptr<Impl> impl_;
};

}  // namespace ldb::backend::gdbmi
