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
  std::vector<StringMatch>
      find_strings(TargetId tid, const StringQuery& query) override;
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
  ProcessStatus kill_process(TargetId tid) override;
  ProcessStatus attach(TargetId tid, std::int32_t pid) override;
  ProcessStatus detach_process(TargetId tid) override;
  ProcessStatus connect_remote_target(TargetId tid,
                                      const std::string& url,
                                      const std::string& plugin_name) override;
  bool save_core(TargetId tid, const std::string& path) override;

  std::vector<ThreadInfo> list_threads(TargetId tid) override;
  std::vector<FrameInfo>  list_frames(TargetId tid, ThreadId thread_id,
                                      std::uint32_t max_depth) override;
  ProcessStatus step_thread(TargetId tid, ThreadId thread_id,
                            StepKind kind) override;

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

  void close_target(TargetId tid) override;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace ldb::backend
