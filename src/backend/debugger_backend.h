#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
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

struct Field {
  std::string name;
  std::string type_name;          // best-effort; whatever DWARF reports
  std::uint64_t offset = 0;       // bytes from struct start
  std::uint64_t byte_size = 0;
  std::uint64_t holes_after = 0;  // alignment gap before the next field
                                  // (or before end-of-struct for the last)
};

struct TypeLayout {
  std::string name;
  std::uint64_t byte_size = 0;
  std::uint64_t alignment = 0;
  std::vector<Field> fields;
  std::uint64_t holes_total = 0;  // sum of all internal holes (padding)
};

enum class SymbolKind {
  kAny,        // wildcard for queries; never returned in results
  kFunction,
  kVariable,
  kOther,      // anything else LLDB reports (labels, indirect, weak)
};

struct SymbolQuery {
  std::string name;            // exact name match for now; glob/regex later
  SymbolKind  kind = SymbolKind::kAny;
};

struct SymbolMatch {
  std::string name;
  std::string mangled;         // empty if same as name
  SymbolKind  kind = SymbolKind::kOther;
  std::uint64_t address = 0;   // file address (unrelocated)
  std::uint64_t byte_size = 0; // 0 if unknown
  std::string module_path;     // path of the owning module
};

struct StringQuery {
  // Restrict the scan to a single module, matched by exact path or by
  // basename. Empty (default) → main executable only. Special value
  // "*" → every loaded module.
  std::string module_path;

  // Restrict the scan to a single section (e.g. "__TEXT/__cstring",
  // ".rodata"). Empty (default) → all sections classified as "data".
  std::string section_name;

  std::uint32_t min_length = 4;
  std::uint32_t max_length = 0;  // 0 = no cap
};

struct StringMatch {
  std::string text;
  std::uint64_t address = 0;     // file address of the first byte
  std::string  section;          // owning section (e.g. "__TEXT/__cstring")
  std::string  module_path;      // owning module
};

struct DisasmInsn {
  std::uint64_t address  = 0;    // file address of this instruction
  std::uint32_t byte_size = 0;
  std::vector<std::uint8_t> bytes;
  std::string mnemonic;          // e.g. "mov", "ldr", "ret"
  std::string operands;          // e.g. "x0, [x1, #8]"
  std::string comment;           // optional disassembler annotation
};

struct XrefMatch {
  std::uint64_t address  = 0;    // referencing instruction's address
  std::uint32_t byte_size = 0;
  std::string mnemonic;
  std::string operands;
  std::string comment;
  std::string function;          // owning function name (best-effort)
};

struct StringXrefResult {
  StringMatch string;
  std::vector<XrefMatch> xrefs;
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

  // Look up a struct/class/union by unqualified or "struct foo" name and
  // produce its memory layout. Returns nullopt if the name is not found.
  // Throws backend::Error for invalid target_id.
  virtual std::optional<TypeLayout>
      find_type_layout(TargetId tid, const std::string& name) = 0;

  // Find symbols matching the query. Currently exact-name; pattern
  // support comes later. Empty result = no matches; not an error.
  // Throws backend::Error for invalid target_id.
  virtual std::vector<SymbolMatch>
      find_symbols(TargetId tid, const SymbolQuery& query) = 0;

  // Enumerate ASCII strings (printable runs) inside a target's data
  // sections. Default scope is the main executable; the query can
  // narrow by module / section and bound length. Throws backend::Error
  // for invalid target_id.
  virtual std::vector<StringMatch>
      find_strings(TargetId tid, const StringQuery& query) = 0;

  // Disassemble file-address range [start, end). Empty result for
  // empty/inverted ranges or unmapped addresses; not an error.
  // Throws backend::Error for invalid target_id.
  virtual std::vector<DisasmInsn>
      disassemble_range(TargetId tid,
                        std::uint64_t start_addr,
                        std::uint64_t end_addr) = 0;

  // Find every instruction in the main executable that references
  // `target_addr`, by scanning operand and comment strings of each
  // disassembled instruction for the address as a hex literal. Catches
  // direct branches reliably; ADRP+ADD reconstruction (for arm64
  // PC-relative loads) is not yet implemented and may miss some
  // references. Throws backend::Error for invalid target_id.
  virtual std::vector<XrefMatch>
      xref_address(TargetId tid, std::uint64_t target_addr) = 0;

  // Find xrefs to every instance of an exact-text string in the main
  // executable. Combines two detection paths to handle both x86-64
  // direct loads (operand carries the address as a hex literal) and
  // arm64 PIE ADRP+ADD pairs (LLDB annotates the second insn's
  // comment with the resolved string in quotes).
  // Returns a result per matching StringMatch; each carries the
  // string and the xrefs to its address. Empty result = string not
  // found OR no xrefs. Throws backend::Error for invalid target_id.
  virtual std::vector<StringXrefResult>
      find_string_xrefs(TargetId tid, const std::string& text) = 0;

  // Drop a target.
  virtual void close_target(TargetId tid) = 0;
};

}  // namespace ldb::backend
