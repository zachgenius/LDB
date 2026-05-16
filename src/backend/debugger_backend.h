// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
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
  std::uint64_t section_count = 0; // top-level + nested sections; always set
  std::vector<Section> sections;  // empty unless OpenOptions.include_sections
                                  // (or list_modules) explicitly asked for the
                                  // walk. section_count is the cheap proxy.
};

// Options for open_executable. Defaults are tuned for the common
// "just opened the binary, what is it" question: cheap, no eager
// SBAPI walks. Pricey enumerations are opt-in.
//
// include_sections=false skips the recursive SBSection walk in
// convert_module. For a binary with hundreds of (sub)sections this
// is a few hundred SBAPI roundtrips' worth of work — and a few MB
// of JSON on the wire — per call. Agents that need the section
// table call module.list with the appropriate view (or re-open
// with include_sections=true).
struct OpenOptions {
  bool include_sections = false;
};

struct OpenResult {
  TargetId target_id = 0;
  std::string triple;
  std::vector<Module> modules;    // typically the executable itself
};

// Per-target inventory entry — what `target.list` returns. Tier 3 §9.
//
// Daemon-process scoped: labels exist only while the target is open and
// die with `close_target`. Cross-restart persistence is explicitly out
// of scope (see worklog).
//
// `path` is the executable on disk if derivable (set for any target
// created via open_executable; empty for empty / core-only targets where
// no file backs the SBTarget). `triple` is whatever
// `SBTarget::GetTriple()` reports — best-effort string.
//
// `has_process` is the cheap "is something attached/launched here right
// now" bit; agents use it to gate process.* calls without a full
// process.state round-trip.
struct TargetInfo {
  TargetId                    target_id   = 0;
  std::string                 triple;
  std::string                 path;        // "" if not derivable
  std::optional<std::string>  label;
  bool                        has_process = false;
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

// --- Semantic queries v1 (Tier 3 §12) -----------------------------------
//
// `static.globals_of_type` answers "find every global variable whose
// DWARF type is X" — a pure-DWARF semantic query, no inferior runtime
// needed. The first tractable slice of the v0.5 roadmap entry on
// type-keyed semantic ops; heap walks / mutex graphs / dataflow defer
// to later versions because they need runtime introspection of glibc /
// pthread internals.
//
// Type-name matching policy (documented contract):
//   1. Try exact match on `SBValue::GetTypeName()`. If any global hits,
//      return them with strict_out=true.
//   2. Otherwise, fall back to substring match (plain `find`, no regex).
//      Return matches with strict_out=false so the agent can see it
//      relaxed.
//
// Canonical type form is whatever `SBValue::GetTypeName()` reports on
// the host LLDB. On Linux LLVM 18+ this is bare struct/typedef names
// (no `struct ` prefix), `const char *const` for the pointer-to-const-
// char-const idiom, `int[4]` for fixed arrays. Tests pin these forms.
struct GlobalVarMatch {
  std::string                  name;
  std::string                  type;          // SBValue::GetTypeName() verbatim
  std::uint64_t                file_address = 0;  // unrelocated
  std::optional<std::uint64_t> load_address;       // set when process attached
  std::uint32_t                size  = 0;
  std::string                  module;        // basename of the owning module
  std::string                  file;          // declaration file (basename)
  std::uint32_t                line  = 0;     // declaration line (0 if none)
};

// Cap on globals enumerated and on matches returned. Big enough that
// real binaries (~50k globals across glibc + all loaded SO) finish in
// hundreds of ms; small enough that a hostile request can't exhaust
// daemon memory. See worklog Tier 3 §12 for the back-of-envelope.
constexpr std::uint32_t kGlobalsOfTypeMaxMatches = 10000;

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

  // Runtime (relocated) address. Set when a process is loaded and the
  // symbol's section is mapped; unset for static-only inspection.
  // Memory primitives (mem.read, mem.read_cstr) expect this address.
  std::optional<std::uint64_t> load_address;
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

// Phase-3 (docs/35-field-report-followups.md §3) provenance accompanying
// an xref.address response. Populated by xref_address when the ADRP-
// pair resolver encountered situations its single-pass heuristic
// couldn't resolve. The caller surfaces this on the wire so the agent
// can branch on it (e.g. fall back to symbol-index correlate when
// the warning count is non-trivial).
struct XrefProvenance {
  // Number of times an LDR with an ADRP-tracked base register was
  // skipped because its address operand was a register-offset
  // (`[xN, xM]` or `[xN, xM, lsl #imm]`) rather than the
  // immediate-offset form the resolver models. Each such skip is one
  // potential xref the heuristic can't surface.
  std::uint32_t adrp_pair_skipped = 0;

  // Number of times a pre- or post-indexed LDR through an ADRP-
  // tracked base caused the base register to be cleared. The
  // legitimate xref against the load's effective address still fires;
  // this counter exists so the caller can see that subsequent loads
  // through the same register are no longer trackable. Post-review
  // addition (docs/35-field-report-followups.md §3 improvement 3).
  std::uint32_t adrp_pair_writeback_cleared = 0;

  // Phase 4 item 1 (docs/35-field-report-followups.md §3): conditional
  // branch (b.cond / cbz / cbnz / tbz / tbnz) whose target sat in a
  // different function caused the entire adrp_regs map to clear. This
  // counter increments per such conditional-branch reset. A non-zero
  // value signals the scanner conservatively dropped tracking; in
  // stripped binaries (where gate 1's function_name_at can't tell the
  // boundary) this is the ONLY signal the heuristic isn't authoritative.
  std::uint32_t adrp_pair_cond_branch_reset = 0;

  // Phase 4 item 3 (docs/35-field-report-followups.md §3): the scanner
  // crossed an instruction whose address was previously recorded as a
  // function start (a B / BR / BL target inside __TEXT/__text) and
  // reset adrp_regs. Catches the stripped-binary case where two
  // adjacent functions both report function_name_at = "" and gate 1
  // can't tell them apart.
  std::uint32_t adrp_pair_function_start_reset = 0;

  // Phase 4 item 4 (docs/35-field-report-followups.md §3): the
  // scanner saw a load/store it deliberately gave up on resolving
  // (pre/post-indexed LDR with untracked base, PC-relative literal
  // load, ...). Distinct from adrp_pair_skipped (which is the
  // register-offset case); together they cover the universe of
  // memops the heuristic can't statically resolve.
  std::uint32_t adrp_pair_unresolvable_load = 0;

  // Human-readable warnings — phase 3 starts with a single
  // "register-offset LDR skipped" warning when adrp_pair_skipped > 0.
  // Phase 4 extends with codes for conditional-branch resets,
  // function-start resets, and other unresolvable-load shapes.
  std::vector<std::string> warnings;
};

struct StringXrefResult {
  StringMatch string;
  std::vector<XrefMatch> xrefs;
};

enum class ProcessState {
  kNone,        // no process associated with the target
  kRunning,
  kStopped,
  kExited,
  kCrashed,
  kDetached,
  kInvalid,     // unknown / suspended state
};

struct ProcessStatus {
  ProcessState state = ProcessState::kNone;
  std::int32_t pid = 0;
  std::int32_t exit_code = 0;   // valid only when state == kExited
  std::string  stop_reason;     // human-readable when state == kStopped
};

struct LaunchOptions {
  bool stop_at_entry = true;
  std::vector<std::string> argv;   // future: forward to inferior
  std::vector<std::string> envp;   // future: env overrides
};

// What "step" means for the targeted thread. The mapping to LLDB:
//   kIn   → SBThread::StepInto         (source-line, step into calls)
//   kOver → SBThread::StepOver         (source-line, step over calls)
//   kOut  → SBThread::StepOut          (run to caller's next instr)
//   kInsn → SBThread::StepInstruction  (one machine instruction;
//                                       step_over=false → into calls)
enum class StepKind {
  kIn,
  kOver,
  kOut,
  kInsn,
};

// Reverse-execution step kinds. The wire surface accepts the same
// "in" / "over" / "out" / "insn" strings as forward step for symmetry,
// but v0.3 implements only kInsn (RSP `bs` packet). kIn / kOver / kOut
// are reserved — their reverse semantics require client-side step-over
// emulation (decode the current instruction, set internal stops, send
// reverse-continue, watch for the stop) and the dispatcher rejects them
// with -32602 today. See docs/16-reverse-exec.md.
enum class ReverseStepKind {
  kIn,
  kOver,
  kOut,
  kInsn,
};

using ThreadId = std::uint64_t;   // SBThread::GetThreadID() — kernel tid

struct ThreadInfo {
  ThreadId      tid     = 0;
  std::uint32_t index   = 0;       // 1-based LLDB index id
  std::string   name;
  ProcessState  state   = ProcessState::kInvalid;
  std::uint64_t pc      = 0;
  std::uint64_t sp      = 0;
  std::string   stop_reason;
};

struct FrameInfo {
  std::uint32_t  index   = 0;      // 0 = innermost
  std::uint64_t  pc      = 0;
  std::uint64_t  fp      = 0;
  std::uint64_t  sp      = 0;
  std::string    function;         // best-effort
  std::string    module;           // owning module path
  std::string    file;              // source file (empty if unavailable)
  std::uint32_t  line   = 0;        // source line (0 if unavailable)
  bool           inlined = false;
};

// SBValue projection — a local, an argument, or a register snapshot.
// Bytes are bounded (kValueByteCap) to keep agent context budgets sane;
// callers needing a full readout use mem.read against `address`.
struct ValueInfo {
  std::string                     name;        // empty for nameless values
  std::string                     type;        // "<unknown>" if unresolvable
  std::optional<std::uint64_t>    address;     // load addr; unset if invalid
  std::vector<std::uint8_t>       bytes;       // up to kValueByteCap bytes
  std::optional<std::string>      summary;     // SBValue::GetSummary || GetValue
  std::optional<std::string>      kind;        // "local"|"arg"|"register"
};

// Maximum number of bytes serialized per ValueInfo. Keep small; agents
// follow up with mem.read for fuller dumps.
constexpr std::size_t kValueByteCap = 64;

// --- Expression evaluation -------------------------------------------------
//
// Tunables for evaluate_expression. Defaults are chosen so a hostile
// expression can't hang the daemon: 250ms is generous for any
// arithmetic eval, tight enough to bound a runaway loop. Agents bump
// the budget for expressions that legitimately call into the inferior.

struct EvalOptions {
  std::uint64_t timeout_us = 250'000;  // 250 ms default
};

// Result envelope for evaluate_expression.
//   ok=true  → `value` is populated; `error` is empty.
//   ok=false → `error` is the LLDB compile/runtime/timeout message;
//              `value` is unspecified. This branch is *data*, not an
//              exception — the caller wants to surface "expression did
//              not compile" without a transport-level error.
struct EvalResult {
  bool        ok = false;
  std::string error;
  ValueInfo   value;
};

// --- Typed value-path read --------------------------------------------------
//
// Result envelope for read_value_path: a frame-relative dotted/indexed
// path traversal. Path resolution failure (no member, malformed token,
// unknown root identifier) returns ok=false with a non-empty error so
// the agent can branch. Bad target/tid/frame_index throws backend::Error
// (same contract as frame.locals).
//
// `children` holds the immediate children of the resolved value when
// it's a struct/array/pointer-to-aggregate. Pre-fetching one level
// saves a round-trip for the agent's "give me everything in this
// struct" pattern. Children are ValueInfo so they carry name+type+
// summary the same way; the agent then re-issues value.read with a
// deeper path if it wants to keep walking.
struct ReadResult {
  bool                    ok = false;
  std::string             error;
  ValueInfo               value;
  std::vector<ValueInfo>  children;
};

// Mapped region of the inferior's address space.
struct MemoryRegion {
  std::uint64_t base = 0;
  std::uint64_t size = 0;
  bool readable   = false;
  bool writable   = false;
  bool executable = false;
  std::optional<std::string> name;
};

// Single hit from search_memory: byte address where the needle starts.
struct MemorySearchHit {
  std::uint64_t address = 0;
};

// --- Breakpoints (M3 probes prep) -------------------------------------------
//
// `lldb_breakpoint`-engine probes (probe.create kind="lldb_breakpoint")
// install a C++ callback on a real LLDB breakpoint via
// SBBreakpoint::SetCallback. The plan §7.1 originally sketched
// SetScriptCallbackBody (Python) — we use the C++ baton path instead so
// the daemon doesn't need to embed CPython, and so probe-callback
// overhead doesn't pay Python ↔ C++ marshaling on the hot path.

struct BreakpointSpec {
  // Exactly one of the three "where" forms must be set. The backend
  // throws if all are unset, or none resolves to a code location.
  std::optional<std::string>   function;
  std::optional<std::uint64_t> address;
  std::optional<std::string>   file;
  std::optional<int>           line;
};

struct BreakpointHandle {
  std::int32_t  bp_id     = 0;   // SBBreakpoint id (1-indexed when valid)
  std::uint32_t locations = 0;   // SBBreakpoint::GetNumLocations()
};

// State the orchestrator's callback needs while the inferior is stopped
// at the breakpoint hit. The backend resolves these at hit time and
// hands them in; the callback should NOT call back into the dispatcher
// (it runs on LLDB's process-event thread).
struct BreakpointCallbackArgs {
  TargetId      target_id    = 0;
  ThreadId      tid          = 0;
  std::uint32_t frame_index  = 0;     // always 0 (innermost) at hit
  std::uint64_t pc           = 0;
  std::string   function;              // best-effort
  std::string   file;                  // empty if unavailable
  int           line         = 0;      // 0 if unavailable
};

// Returning false auto-continues the inferior (typical probe path).
// Returning true keeps it stopped — the agent picks up via process.state.
using BreakpointCallback =
    std::function<bool(void* baton, const BreakpointCallbackArgs&)>;

// Errors are reported via exceptions of type backend::Error.
struct Error : std::runtime_error {
  using std::runtime_error::runtime_error;
};

// A backend operation that is genuinely not implemented for this
// backend (as opposed to "implemented but the call failed"). The
// dispatcher maps this to -32001 kNotImplemented; the generic Error
// path maps to -32004 kBackendError.
//
// Why a typed subclass instead of a "not implemented" substring on
// Error::what(): any backend that throws a descriptive error
// containing the words "not implemented" for a legitimate runtime
// failure (e.g. "feature X is not implemented on this kernel") would
// otherwise get silently promoted to -32001 and hide a real bug. The
// type discriminator is the whole point — the dispatcher catches
// NotImplementedError BEFORE the generic Error catch.
struct NotImplementedError : Error {
  using Error::Error;
};

// Parameters for connect_remote_target_ssh — bundle them in a struct
// because there are many optional fields and call-site readability
// matters more than ABI stability for an internal interface.
struct ConnectRemoteSshOptions {
  std::string                         host;        // "user@hostname" or "hostname"
  std::optional<int>                  port;        // ssh port (defaults to 22 / ~/.ssh/config)
  std::vector<std::string>            ssh_options; // extra `-o`/etc. args, pass-through
  std::string                         remote_lldb_server;  // empty → "lldb-server" on PATH
  std::string                         inferior_path;       // absolute path on remote
  std::vector<std::string>            inferior_argv;       // optional argv tail for the inferior
  std::chrono::milliseconds           setup_timeout{10000};
};

// Result mirrors ProcessStatus but adds the local tunnel port the
// caller can use for diagnostics (e.g. `lsof -i :<port>`).
struct ConnectRemoteSshResult {
  ProcessStatus  status;
  std::uint16_t  local_tunnel_port = 0;
};

class DebuggerBackend {
 public:
  virtual ~DebuggerBackend() = default;

  // Create a target from a binary on disk; no process is spawned.
  // The default OpenOptions returns summary modules (no inline section
  // tables) — this is the cheap path. Pass include_sections=true to
  // get the full section walk in the response.
  virtual OpenResult open_executable(const std::string& path,
                                     const OpenOptions& opts = OpenOptions{}) = 0;

  // Create a target with no associated executable. Used as the host
  // for target.attach by PID (where the inferior's image is discovered
  // from the kernel) and for target.load_core. Throws backend::Error
  // on creation failure.
  virtual OpenResult create_empty_target() = 0;

  // Load a postmortem core file. Returns a fresh target whose threads
  // are frozen at the moment of capture; the same read-only endpoints
  // that work against a live process work here. Throws on missing /
  // unreadable file or unsupported format.
  virtual OpenResult load_core(const std::string& core_path) = 0;

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

  // Tier 3 §12 — semantic queries v1. Find every global variable in a
  // target whose DWARF type matches `type_name`. Empty `type_name` is
  // an Error (the caller would otherwise dump the whole catalogue
  // unintentionally). Sets `strict_out=true` when an exact-match pass
  // produced the results, false when we fell back to substring match
  // because exact returned nothing. See struct GlobalVarMatch above
  // for the matching policy contract.
  //
  // Result count is capped at kGlobalsOfTypeMaxMatches; on hitting the
  // cap the caller should treat the result as truncated. The dispatcher
  // surfaces a `truncated` bit in the wire response.
  virtual std::vector<GlobalVarMatch>
      find_globals_of_type(TargetId tid, std::string_view type_name,
                           bool& strict_out) = 0;

  // Enumerate ASCII strings (printable runs) inside a target's data
  // sections. Default scope is the main executable; the query can
  // narrow by module / section and bound length. Throws backend::Error
  // for invalid target_id.
  virtual std::vector<StringMatch>
      find_strings(TargetId tid, const StringQuery& query) = 0;

  // --- Bulk module iteration (post-V1 #18, docs/23-symbol-index.md) ----
  //
  // The dispatcher's correlate.* path needs to enumerate every symbol /
  // type / string in a module so the SymbolIndex can populate once and
  // serve subsequent calls from sqlite. Three buckets keyed by build_id:
  //
  //   ModuleSymbols  — every named symbol the backend can see in the
  //                    main executable, bucketed by classification
  //                    (function / data / other). The same SymbolMatch
  //                    shape find_symbols emits, so the index→wire
  //                    converter is the existing symbol_match_to_json.
  //   ModuleTypes    — every fully-resolved struct/class/union layout
  //                    in the target's debug info, shaped exactly like
  //                    find_type_layout returns. Type-strip / canonical-
  //                    name handling matches find_type_layout's contract
  //                    so query_type(build_id, name) returns what
  //                    find_type_layout(tid, name) would.
  //   ModuleStrings  — printable ASCII runs in the default scope of
  //                    find_strings (main executable's data sections,
  //                    min_length=4).
  //
  // Why bulk and not "find with empty query": find_symbols / find_strings
  // are query-shaped (per-target SymbolQuery / StringQuery). The cache
  // is build_id-keyed and doesn't know the caller's specific query at
  // populate time. Bulk + post-filter (in sqlite) is the inversion that
  // turns O(targets) backend walks into O(unique build_ids).
  //
  // build_id is purely a populator-side label (the caller writes it
  // into the BinaryEntry); the backend isn't expected to validate the
  // claim against the actual module UUID. Throws backend::Error for
  // invalid target_id; empty buckets are not an error.
  //
  // Hard cap on bucket size (per-bucket): kIterateBucketCap. Modules
  // that exceed it are truncated and a stderr warning logged; the
  // dispatcher's correlate.* still falls through to backend find_*
  // for specific-name queries beyond the cap. Today's biggest real-
  // world module (kernel debuginfo) hits ~1M symbols and would blow
  // sqlite WAL otherwise.
  static constexpr std::size_t kIterateBucketCap = 100000;

  // `truncated` fires when any bucket hit kIterateBucketCap. The
  // dispatcher uses this to decide whether to fall through to find_*
  // when an indexed query returns empty results — without the flag,
  // a truncated index would silently turn "this symbol was capped out"
  // into "this symbol does not exist."
  struct ModuleSymbols {
    std::vector<SymbolMatch>  functions;  // SymbolKind::kFunction
    std::vector<SymbolMatch>  data;       // SymbolKind::kVariable
    std::vector<SymbolMatch>  other;      // everything else
    bool                      truncated = false;
  };
  virtual ModuleSymbols
      iterate_symbols(TargetId tid, std::string_view build_id) = 0;

  struct ModuleTypes {
    std::vector<TypeLayout>   types;
    bool                      truncated = false;
  };
  virtual ModuleTypes
      iterate_types(TargetId tid, std::string_view build_id) = 0;

  struct ModuleStrings {
    std::vector<StringMatch>  strings;
    bool                      truncated = false;
  };
  virtual ModuleStrings
      iterate_strings(TargetId tid, std::string_view build_id) = 0;

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
  // direct branches reliably; ARM64 ADRP+ADD/LDR reconstruction lives
  // alongside (docs/35-field-report-followups.md §3) and may surface
  // warnings via `provenance` for patterns the heuristic skipped.
  // The `provenance` out-param is optional — pass nullptr if the
  // caller doesn't care to inspect skipped-ADRP-pair diagnostics.
  // Throws backend::Error for invalid target_id.
  virtual std::vector<XrefMatch>
      xref_address(TargetId tid, std::uint64_t target_addr,
                   XrefProvenance* provenance = nullptr) = 0;

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

  // --- Process lifecycle -------------------------------------------------
  //
  // M2 first slice. All operations are synchronous: launch and continue
  // block until the next stop event or terminal state. A target may have
  // at most one live process; relaunching kills any prior process first.

  // Spawn the target's executable as an inferior process. With
  // stop_at_entry=true the process is paused at the entry point; the
  // returned ProcessStatus reports state==kStopped. With
  // stop_at_entry=false the process runs until it stops or exits.
  // Throws backend::Error for invalid target_id or launch failures.
  virtual ProcessStatus
      launch_process(TargetId tid, const LaunchOptions& opts) = 0;

  // Report the current state of the target's associated process. If
  // there is none, returns ProcessStatus{state=kNone}. Throws on
  // invalid target_id.
  virtual ProcessStatus get_process_state(TargetId tid) = 0;

  // Resume a stopped process. Blocks until the next stop or terminal
  // event. Throws if there is no process to continue.
  virtual ProcessStatus continue_process(TargetId tid) = 0;

  // Resume a single thread (Tier 4 §14, scoped slice).
  //
  // v0.3 contract: SYNC PASSTHROUGH — equivalent to continue_process,
  // because LldbBackend runs in SBProcess::SetAsync(false) and the
  // whole-process Continue is the only resume path that actually works.
  // The `thread_id` argument is reserved: in v0.4+ when the daemon
  // moves to async mode this method will resume just `thread_id` while
  // the rest of the process stays stopped (true non-stop debugging).
  //
  // The protocol surface (thread.continue, process.continue+tid) is
  // wired to this method NOW so client code is async-ready and can
  // switch behavior on a daemon-version handshake bump when v0.4 lands.
  // See docs/11-non-stop.md.
  //
  // Throws backend::Error on invalid target_id, or if there is no live
  // process to resume.
  virtual ProcessStatus
      continue_thread(TargetId target_id, ThreadId thread_id) = 0;

  // Suspend a single thread — the inverse of continue_thread (v1.6 #21,
  // docs/26-nonstop-runtime.md §1). Marks `thread_id` as parked so the
  // next process-wide resume leaves it pinned at its current PC; the
  // rest of the process is unaffected by this call alone.
  //
  // LldbBackend's implementation calls `SBThread::Suspend(true)` on the
  // resolved SBThread. The process state itself doesn't change — the
  // suspend bit only matters on the NEXT SBProcess::Continue, which
  // honours suspended-ness even with SetAsync(false) (this is how LLDB
  // models per-thread stepping internally). Returns a ProcessStatus
  // snapshot for callers that want the post-call state.
  //
  // GdbMiBackend currently throws "not implemented" — GDB/MI's per-
  // thread suspend semantics differ enough from LLDB's that wiring it
  // up properly is a separate item.
  //
  // Throws backend::Error on invalid target_id, unknown thread_id, or
  // no live process.
  virtual ProcessStatus
      suspend_thread(TargetId target_id, ThreadId thread_id) = 0;

  // Terminate the target's process. Idempotent: returns
  // ProcessStatus{state=kNone} when there is no process.
  virtual ProcessStatus kill_process(TargetId tid) = 0;

  // Attach to a running process by kernel pid. The target should
  // typically be an empty target (see create_empty_target); when the
  // target has a known executable, LLDB still validates the pid maps
  // to that image.
  // Sync semantics: blocks until the inferior is stopped on attach.
  // Throws backend::Error on invalid target_id or attach failure
  // (bad pid, permissions, debugserver missing on macOS).
  virtual ProcessStatus attach(TargetId tid, std::int32_t pid) = 0;

  // Detach from the target's process. Idempotent: returns
  // ProcessStatus{state=kNone} when there is no process. Preferred
  // over kill_process for attached processes — leaves the inferior
  // running.
  virtual ProcessStatus detach_process(TargetId tid) = 0;

  // Connect to a remote debug server (lldb-server, gdbserver,
  // debugserver, qemu-gdbstub, ...) over its gdb-remote-protocol
  // endpoint. [url] is whatever SBTarget::ConnectRemote accepts:
  // "connect://host:port" or "host:port" (LLDB tolerates both).
  // [plugin_name] selects the connection plugin; empty string means
  // "gdb-remote", which covers every server we currently target.
  // Sync semantics: blocks until the server reports a stable post-
  // connect state (typically stopped) or fails. Throws backend::Error
  // on invalid target_id, malformed URL, refused connection, or
  // post-connect protocol failure.
  virtual ProcessStatus
      connect_remote_target(TargetId tid, const std::string& url,
                            const std::string& plugin_name) = 0;

  // Save a core file of the target's process to [path]. Returns true
  // on success; false if the platform doesn't implement SaveCore for
  // the current process type (e.g. some Linux configurations).
  // Throws backend::Error for invalid target_id or no live process.
  virtual bool save_core(TargetId tid, const std::string& path) = 0;

  // --- Threads & frames -------------------------------------------------

  // Enumerate threads of the target's process. Returns empty when no
  // process is associated. Throws on invalid target_id.
  virtual std::vector<ThreadInfo> list_threads(TargetId tid) = 0;

  // Backtrace a thread, innermost frame first. max_depth=0 means no
  // cap. Throws on invalid target_id or unknown thread id.
  virtual std::vector<FrameInfo>
      list_frames(TargetId tid, ThreadId thread_id,
                  std::uint32_t max_depth) = 0;

  // Single-step the given thread. Synchronous: blocks until the next
  // stop event or terminal state (sync mode is set on construction).
  // Returns the post-step process status; caller can re-query
  // list_threads / list_frames for the new PC. Throws backend::Error
  // for invalid target_id, unknown thread id, or no live process.
  virtual ProcessStatus
      step_thread(TargetId tid, ThreadId thread_id, StepKind kind) = 0;

  // Reverse-continue: run the process backward until the next stop
  // (typically a breakpoint or the beginning of the trace). Requires
  // a record/replay backend that advertises reverse-exec support —
  // currently rr, reached via `target.connect_remote rr://`. Implemented
  // by sending the GDB RSP `bc` packet through the gdb-remote plugin
  // (LLDB has no public SBProcess::ReverseContinue API), then pumping
  // the listener until the next stop event arrives.
  //
  // Throws backend::Error with a clearly worded message when:
  //   * the target_id is unknown,
  //   * no live process is attached,
  //   * the target is not reverse-capable (dispatcher maps to -32003).
  virtual ProcessStatus reverse_continue(TargetId tid) = 0;

  // Reverse-step a single thread by one machine instruction.
  // v0.3 contract: only ReverseStepKind::kInsn is implemented; kIn /
  // kOver / kOut throw a "kind not supported" backend::Error. The
  // wire surface accepts those strings so the schema doesn't change
  // when the client-side step-over emulator lands later — see
  // docs/16-reverse-exec.md.
  virtual ProcessStatus
      reverse_step_thread(TargetId tid, ThreadId thread_id,
                          ReverseStepKind kind) = 0;

  // --- Frame values ----------------------------------------------------
  //
  // Three SBValue-walking endpoints over a single frame:
  //   list_locals     — function-scope locals (DWARF DW_TAG_variable)
  //   list_args       — function arguments (DW_TAG_formal_parameter)
  //   list_registers  — every register set's registers, flattened
  //
  // All three throw backend::Error on invalid target_id, unknown thread,
  // or out-of-range frame index. Bytes are clamped to kValueByteCap.

  virtual std::vector<ValueInfo>
      list_locals(TargetId tid, ThreadId thread_id,
                  std::uint32_t frame_index) = 0;

  virtual std::vector<ValueInfo>
      list_args(TargetId tid, ThreadId thread_id,
                std::uint32_t frame_index) = 0;

  virtual std::vector<ValueInfo>
      list_registers(TargetId tid, ThreadId thread_id,
                     std::uint32_t frame_index) = 0;

  // Evaluate [expr] in the context of (target, thread, frame). Eval
  // failures (compile error, runtime trap, timeout) are returned as
  // EvalResult.error with ok=false — *not* thrown — so the agent can
  // surface "expression did not compile" without a transport-level
  // error. Throws backend::Error only for invalid target_id, unknown
  // thread, or out-of-range frame_index.
  // The expression evaluator is configured to ignore breakpoints and
  // not run other threads (no spurious side effects on sibling
  // threads). Caller-provided timeout bounds runaway expressions.
  virtual EvalResult
      evaluate_expression(TargetId tid, ThreadId thread_id,
                          std::uint32_t frame_index,
                          const std::string& expr,
                          const EvalOptions& opts) = 0;

  // Resolve a dotted/bracketed [path] relative to the given frame. The
  // leftmost ident is looked up via SBFrame::FindVariable (locals,
  // args) with a fallback to FindValue for globals; subsequent ".name"
  // and "[N]" tokens walk the SBValue tree. Path-resolution failure
  // (parser error, missing member, unknown root) returns
  // ReadResult.ok=false with a descriptive error message — *not* a
  // thrown exception. Throws backend::Error only for invalid
  // target_id, unknown thread, or out-of-range frame_index.
  virtual ReadResult
      read_value_path(TargetId tid, ThreadId thread_id,
                      std::uint32_t frame_index,
                      const std::string& path) = 0;

  // --- Memory primitives ----------------------------------------------

  // Maximum bytes returned by a single read_memory call. Beyond this
  // the caller should chunk; or use mem.search.
  static constexpr std::uint64_t kMemReadMax = 1 * 1024 * 1024;  // 1 MiB
  // Default cap for read_cstring when caller passes max_len=0.
  static constexpr std::uint32_t kMemCstrDefault = 4096;
  // Maximum bytes scanned in a single search_memory call.
  static constexpr std::uint64_t kMemSearchMax = 256ull * 1024 * 1024;
  // Hard cap on hits returned regardless of caller's max_hits.
  static constexpr std::uint32_t kMemSearchHitCap = 1024;

  // Read [size] bytes from process memory at [addr]. Throws on
  // size > kMemReadMax, invalid target_id, or read failure.
  virtual std::vector<std::uint8_t>
      read_memory(TargetId tid, std::uint64_t addr, std::uint64_t size) = 0;

  // Read a C string at [addr], up to NUL or max_len bytes (max_len=0
  // means kMemCstrDefault). Result excludes the NUL.
  virtual std::string
      read_cstring(TargetId tid, std::uint64_t addr,
                   std::uint32_t max_len) = 0;

  // Enumerate the inferior's mapped memory regions in ascending base
  // address order. Throws on invalid target_id; returns empty when
  // no process is associated.
  virtual std::vector<MemoryRegion> list_regions(TargetId tid) = 0;

  // Search [start, start+length) for [needle], returning up to
  // [max_hits] matches (capped at kMemSearchHitCap). length=0 means
  // search every readable region (intersected with kMemSearchMax).
  // Throws on length > kMemSearchMax or invalid target_id.
  virtual std::vector<MemorySearchHit>
      search_memory(TargetId tid, std::uint64_t start, std::uint64_t length,
                    const std::vector<std::uint8_t>& needle,
                    std::uint32_t max_hits) = 0;

  // --- Breakpoints (M3 probes) ---------------------------------------
  //
  // The orchestrator owns probe lifecycle and callback batons; the
  // backend just owns the raw SBBreakpoint and the bridge between
  // LLDB's SBBreakpointHitCallback signature and our typed C++
  // callback. The backend stores the callback + baton internally and
  // reaps them on delete_breakpoint or target close.
  //
  // Concurrency contract:
  //   • LLDB invokes the callback on its process-event thread, NOT on
  //     the dispatcher thread. The callback must NOT call back into
  //     the dispatcher or acquire dispatcher-side locks.
  //   • Returning false from the callback auto-continues the inferior.
  //   • Returning true keeps the inferior stopped (the agent learns
  //     via process.state).
  //   • The baton is owned by the caller; baton lifetime must extend
  //     until delete_breakpoint() returns. The orchestrator enforces
  //     "disable + drain → delete" ordering.

  virtual BreakpointHandle
      create_breakpoint(TargetId tid, const BreakpointSpec& spec) = 0;

  virtual void
      set_breakpoint_callback(TargetId tid, std::int32_t bp_id,
                              BreakpointCallback cb, void* baton) = 0;

  virtual void disable_breakpoint(TargetId tid, std::int32_t bp_id) = 0;
  virtual void enable_breakpoint(TargetId tid, std::int32_t bp_id) = 0;
  virtual void delete_breakpoint(TargetId tid, std::int32_t bp_id) = 0;

  // Read a register from a thread's frame at the moment of a stop
  // (typically called from inside a breakpoint callback). Returns 0 if
  // the register is unknown or unreadable (a real "0" register and an
  // unknown register are indistinguishable here — the orchestrator
  // documents this as captured-as-zero rather than throwing).
  virtual std::uint64_t
      read_register(TargetId tid, ThreadId thread_id,
                    std::uint32_t frame_index,
                    const std::string& name) = 0;

  // Drop a target.
  virtual void close_target(TargetId tid) = 0;

  // --- Multi-binary inventory (Tier 3 §9) -------------------------------
  //
  // `list_targets` enumerates every open target in the daemon's process,
  // best-effort decorating with executable path, triple, optional label,
  // and the `has_process` bit. Order is implementation-defined; agents
  // sort client-side if they need a stable view.
  //
  // `label_target` stores a daemon-process-scoped label for a target.
  // Constraints:
  //   • label must be non-empty.
  //   • label uniqueness is enforced across open targets — a second
  //     target trying to claim a label already owned by another target
  //     throws backend::Error. The error message includes the conflicting
  //     target_id so the dispatcher can surface it usefully.
  //   • Re-labeling the same target with a different label replaces the
  //     previous label (releases the old name) — single label per target.
  //   • Self-relabel with the same string is a no-op.
  //
  // `get_target_label` returns the current label or nullopt. Calling on
  // an unknown target_id (e.g. one that was just closed) returns nullopt
  // rather than throwing — get/list is the read path, expected to race
  // benignly with close_target.
  //
  // `close_target` drops the label (it does NOT survive). This is the
  // documented persistence boundary; cross-restart persistence is out
  // of scope for §9.
  virtual std::vector<TargetInfo> list_targets() = 0;
  virtual void label_target(TargetId tid, std::string label) = 0;
  virtual std::optional<std::string> get_target_label(TargetId tid) = 0;

  // --- Provenance ------------------------------------------------------
  //
  // Cores-only MVP per plan §3.5. The dispatcher decorates every
  // successful response with `_provenance.snapshot`; this is the
  // string it embeds, computed against the named target.
  //
  //   * core-loaded target → "core:<lowercase-hex-sha256>". The hash
  //     is computed once by load_core (against the core file on
  //     disk) and cached on the per-target state.
  //   * live target with an attached process → "live".
  //   * any other case (target not yet known, target with no process,
  //     unknown tid) → "none".
  //
  // Best-effort metadata: never throw — the dispatcher calls this on
  // every dispatch and a thrown exception would poison the response.
  virtual std::string snapshot_for_target(TargetId tid) = 0;

  // --- Out-of-band target-bound resources ------------------------------
  //
  // Some endpoints (e.g. target.connect_remote_ssh) need to keep an
  // RAII handle alive for as long as the target exists — the SSH
  // tunneled lldb-server, in that case, dies the moment we drop our
  // ssh subprocess. The target itself doesn't know about these
  // handles (they're outside SBAPI), so the backend exposes a generic
  // "attach this opaque destructor to a target" surface. Resources
  // are dropped in reverse-attach order on close_target / dtor.
  //
  // This is interface-level (not LldbBackend-specific) because future
  // backends (gdbstub, native) will also need to bind helper
  // subprocesses (probe agents, scp'd binaries, ...). Keep it generic.
  struct TargetResource {
    virtual ~TargetResource() = default;
  };
  virtual void
      attach_target_resource(TargetId tid,
                             std::unique_ptr<TargetResource> r) = 0;

  // SSH-tunneled remote connect. Spawns a single ssh subprocess that
  // simultaneously holds a `-L` port forward and runs `lldb-server
  // gdbserver` on the remote against [inferior_path]. The tunnel
  // handle's lifetime is bound to the target via attach_target_resource:
  // close_target / dtor tears it down, which kills the remote
  // lldb-server via SIGHUP.
  // Throws backend::Error on bad params, ssh failure, lldb-server
  // failure, or timeout.
  virtual ConnectRemoteSshResult
      connect_remote_target_ssh(TargetId tid,
                                const ConnectRemoteSshOptions& opts) = 0;
};

}  // namespace ldb::backend
