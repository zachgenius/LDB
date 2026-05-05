#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// Abstract backend interface. M0 has only the LLDB implementation, but
// the interface exists so v0.3+ GDB/MI and v1.0+ native backends can
// drop in without touching the dispatcher.
//
// The interface is intentionally narrow in M0 — it grows along with the
// RPC surface in subsequent milestones.

namespace ldb::backend {

using TargetId = std::uint64_t;

struct Section {
  std::string name;
  std::uint64_t file_addr  = 0;   // unrelocated address
  std::uint64_t load_addr  = 0;   // 0 if not loaded
  std::uint64_t size       = 0;
  std::uint32_t permissions = 0;  // bit0=R bit1=W bit2=X
  std::string  type;              // "code","data","debug","other"
};

struct Module {
  std::string path;
  std::string uuid;               // LLDB-reported UUID (build-id on ELF)
  std::string triple;             // e.g. "x86_64-apple-macosx-"
  std::uint64_t load_address = 0; // 0 if not loaded
  std::vector<Section> sections;
};

struct OpenResult {
  TargetId target_id = 0;
  std::string triple;
  std::vector<Module> modules;    // typically the executable itself
};

// Errors are reported via exceptions of type backend::Error.
struct Error : std::runtime_error {
  using std::runtime_error::runtime_error;
};

class DebuggerBackend {
 public:
  virtual ~DebuggerBackend() = default;

  // Create a target from a binary on disk; no process is spawned.
  virtual OpenResult open_executable(const std::string& path) = 0;

  // Enumerate modules associated with a target.
  virtual std::vector<Module> list_modules(TargetId tid) = 0;

  // Drop a target.
  virtual void close_target(TargetId tid) = 0;
};

}  // namespace ldb::backend
