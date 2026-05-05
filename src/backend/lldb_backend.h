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
  std::vector<Module> list_modules(TargetId tid) override;
  std::optional<TypeLayout>
      find_type_layout(TargetId tid, const std::string& name) override;
  std::vector<SymbolMatch>
      find_symbols(TargetId tid, const SymbolQuery& query) override;
  std::vector<StringMatch>
      find_strings(TargetId tid, const StringQuery& query) override;
  void close_target(TargetId tid) override;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace ldb::backend
