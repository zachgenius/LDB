// SPDX-License-Identifier: Apache-2.0
#include "backend/lldb_backend.h"

#include "backend/xref_arm64_parsers.h"
#include "ldb/backend/chained_fixups.h"
#include "transport/rr.h"
#include "transport/ssh.h"

#include <algorithm>
#include <array>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string_view>
#include <tuple>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

#ifdef LDB_HAVE_CAPSTONE
#include <capstone/capstone.h>
#endif

#include <lldb/API/LLDB.h>

#include "util/log.h"
#include "util/sha256.h"

namespace ldb::backend {

namespace {

std::uint32_t encode_perms(uint32_t lldb_perms) {
  // LLDB uses the same bit order via SBSection::GetPermissions:
  //   ePermissionsWritable = (1u << 0)
  //   ePermissionsReadable = (1u << 1)
  //   ePermissionsExecutable = (1u << 2)
  std::uint32_t out = 0;
  if (lldb_perms & static_cast<uint32_t>(lldb::ePermissionsReadable))   out |= 0b001;
  if (lldb_perms & static_cast<uint32_t>(lldb::ePermissionsWritable))   out |= 0b010;
  if (lldb_perms & static_cast<uint32_t>(lldb::ePermissionsExecutable)) out |= 0b100;
  return out;
}

const char* section_type_name(lldb::SectionType t) {
  switch (t) {
    case lldb::eSectionTypeCode:                 return "code";
    case lldb::eSectionTypeData:
    case lldb::eSectionTypeDataCString:
    case lldb::eSectionTypeDataCStringPointers:
    case lldb::eSectionTypeDataSymbolAddress:
    case lldb::eSectionTypeData4:
    case lldb::eSectionTypeData8:
    case lldb::eSectionTypeData16:
    case lldb::eSectionTypeDataPointers:         return "data";
    case lldb::eSectionTypeDebug:
    case lldb::eSectionTypeDWARFDebugAbbrev:
    case lldb::eSectionTypeDWARFDebugInfo:
    case lldb::eSectionTypeDWARFDebugLine:
    case lldb::eSectionTypeDWARFDebugStr:
    case lldb::eSectionTypeDWARFDebugRanges:
    case lldb::eSectionTypeDWARFDebugAddr:
    case lldb::eSectionTypeDWARFDebugLoc:
    case lldb::eSectionTypeDWARFDebugLocLists:
    case lldb::eSectionTypeDWARFDebugRngLists:
    case lldb::eSectionTypeDWARFDebugMacro:
    case lldb::eSectionTypeDWARFDebugMacInfo:
    case lldb::eSectionTypeDWARFDebugTypes:
    case lldb::eSectionTypeDWARFDebugPubNames:
    case lldb::eSectionTypeDWARFDebugPubTypes:
    case lldb::eSectionTypeDWARFDebugFrame:
    case lldb::eSectionTypeDWARFDebugAranges:
    case lldb::eSectionTypeDWARFDebugCuIndex:
    case lldb::eSectionTypeDWARFDebugTuIndex:
    case lldb::eSectionTypeDWARFDebugNames:
    case lldb::eSectionTypeDWARFGNUDebugAltLink: return "debug";
    default: return "other";
  }
}

// SBSection / SBModule are refcounted handles; cheap to pass by value, and
// most accessor methods are non-const (LLDB design choice).
void collect_sections(lldb::SBSection parent, std::vector<Section>& out,
                      const std::string& prefix = {}) {
  Section s;
  const char* nm = parent.GetName();
  s.name        = prefix + (nm ? nm : "");
  s.file_addr   = parent.GetFileAddress();
  s.load_addr   = 0;  // no process loaded in M0
  s.size        = parent.GetByteSize();
  s.permissions = encode_perms(parent.GetPermissions());
  s.type        = section_type_name(parent.GetSectionType());
  out.push_back(std::move(s));

  std::string child_prefix = std::string(nm ? nm : "") + "/";
  size_t n = parent.GetNumSubSections();
  for (size_t i = 0; i < n; ++i) {
    auto sub = parent.GetSubSectionAtIndex(i);
    if (sub.IsValid()) collect_sections(sub, out, child_prefix);
  }
}

// Count the top-level + nested sections in a module without
// materialising any Section records. The recursion mirrors
// collect_sections but only increments a counter — same shape, no
// allocations, no name/perm/type fetches.
std::uint64_t count_sections(lldb::SBSection parent) {
  std::uint64_t total = 1;
  size_t n = parent.GetNumSubSections();
  for (size_t i = 0; i < n; ++i) {
    auto sub = parent.GetSubSectionAtIndex(i);
    if (sub.IsValid()) total += count_sections(sub);
  }
  return total;
}

Module convert_module(lldb::SBModule m, bool include_sections) {
  Module out;
  lldb::SBFileSpec file = m.GetFileSpec();
  if (file.IsValid()) {
    char buf[4096];
    if (file.GetPath(buf, sizeof(buf)) > 0) out.path = buf;
  }

  // UUID — on ELF this is the build-id; on Mach-O the LC_UUID.
  const char* uuid = m.GetUUIDString();
  if (uuid) out.uuid = uuid;

  // Triple
  if (const char* tr = m.GetTriple()) out.triple = tr;

  size_t n = m.GetNumSections();
  if (include_sections) {
    out.sections.reserve(n);
    for (size_t i = 0; i < n; ++i) {
      auto s = m.GetSectionAtIndex(i);
      if (s.IsValid()) collect_sections(s, out.sections);
    }
    out.section_count = out.sections.size();
  } else {
    // Cheap path: just count. The recursion is bounded by the Mach-O /
    // ELF section nesting depth (typically 2), so the worst case for a
    // 587-section iOS app is one GetNumSubSections per top-level
    // section — orders of magnitude less work than the full walk.
    std::uint64_t total = 0;
    for (size_t i = 0; i < n; ++i) {
      auto s = m.GetSectionAtIndex(i);
      if (s.IsValid()) total += count_sections(s);
    }
    out.section_count = total;
  }
  return out;
}

}  // namespace

// ----------------------------------------------------------------------------

// Per-breakpoint callback record. The shim trampoline (see
// lldb_breakpoint_trampoline) is invoked by LLDB's process-event
// thread and looks the record up by (target_id, bp_id) under
// `cb_mu`. The record is destroyed by delete_breakpoint or target
// close; the orchestrator's "disable + drain → delete" contract
// ensures no in-flight callback dereferences a freed record.
struct LldbBreakpointCb {
  TargetId            target_id = 0;
  std::int32_t        bp_id     = 0;
  BreakpointCallback  cb;
  void*               baton     = nullptr;
};

// Per-target live-snapshot state for the v0.3 live-provenance model
// (audit doc §6).
//
//   live:<gen>:<reg_digest>:<layout_digest>:<bp_digest>
//
// `gen` is a session-local monotonic counter, bumped on every observed
// stopped→running→stopped transition AND on attach/launch (initial
// value 0; first stop is gen=0). reg_digest and layout_digest are
// SHA-256 over the canonicalised register state and module layout
// respectively, cached lazily per-`gen` so a hot loop of read-only
// RPCs against a paused target hashes once. bp_digest covers the
// active SW-breakpoint set (slice 1c — closes the .text-patch
// invisibility gap flagged by the 1b reviewer); it's computed fresh
// on every call rather than cached because probe.create/delete/
// enable/disable do not bump `<gen>` and a cache would need extra
// invalidation hooks. The bp set is small (typically <10), so the
// per-call hash cost is negligible.
//
// Cross-process equality in this model is
// `(reg_digest, layout_digest, bp_digest)` only — `gen` is
// session-local and explicitly excluded. The slice 1c live↔core
// determinism gate enforces this cross-process invariant.
struct LiveSnapshotState {
  std::uint64_t gen           = 0;
  std::string   reg_digest;        // 64 lowercase hex chars
  std::string   layout_digest;     // 64 lowercase hex chars
  bool          digests_valid = false;
};

namespace {

// On every observed stopped→running→stopped transition (continue,
// step, attach, launch), invalidate the digest cache so the next
// snapshot_for_target recomputes against the new state. The bump is
// what makes <gen> visible to agents without paying the digest cost
// when nothing has changed. The caller MUST hold the impl mutex
// guarding the LiveSnapshotState map.
inline void bump_live_gen_locked(LiveSnapshotState& st) {
  ++st.gen;
  st.reg_digest.clear();
  st.layout_digest.clear();
  st.digests_valid = false;
}

// Reset live-state on a fresh attach / launch — wipes the previous
// process's digest and starts gen at 0 again. mu MUST be held.
inline void reset_live_state_locked(LiveSnapshotState& st) {
  st.gen = 0;
  st.reg_digest.clear();
  st.layout_digest.clear();
  st.digests_valid = false;
}

// Subscribe the backend's module-load listener to a target's broadcaster
// (slice 1c). Called from attach/launch/connect so snapshot_for_target
// can later drain dlopen events synchronously.
inline void subscribe_modules_loaded(lldb::SBListener& listener,
                                     lldb::SBTarget target) {
  if (!listener.IsValid() || !target.IsValid()) return;
  listener.StartListeningForEvents(
      target.GetBroadcaster(),
      static_cast<std::uint32_t>(lldb::SBTarget::eBroadcastBitModulesLoaded));
}

}  // namespace

struct LldbBackend::Impl {
  lldb::SBDebugger debugger;
  std::mutex mu;
  std::unordered_map<TargetId, lldb::SBTarget> targets;
  // Out-of-band per-target RAII handles (SSH tunnels, helper
  // subprocesses, etc.). Vector preserves attach order so close_target
  // can drop them in reverse — important when one handle depends on
  // another (e.g. a future scp'd helper binary that's used by the
  // ssh-tunneled lldb-server).
  std::unordered_map<TargetId,
                     std::vector<std::unique_ptr<DebuggerBackend::TargetResource>>>
      target_resources;
  // SHA-256 of the core file backing each core-loaded target (lowercase
  // hex). Populated once by load_core; consumed by snapshot_for_target
  // to produce the cores-only `_provenance.snapshot` value per plan §3.5.
  // Absent for targets that weren't created via load_core.
  std::unordered_map<TargetId, std::string> core_sha256;
  // Per-target live-snapshot state. Reset on attach / launch_process,
  // bumped by continue_process / step_thread, invalidated by
  // detach / kill / close_target. Guarded by `mu`.
  std::unordered_map<TargetId, LiveSnapshotState> live_state;
  // Per-target reverse-execution capability flag. Set true when a
  // target connects via `rr://` (the only reverse-capable transport
  // today). Reverse-exec backend methods consult this — non-rr targets
  // get a "target does not support reverse execution" error which the
  // dispatcher maps to -32003 forbidden. Guarded by `mu`.
  std::unordered_map<TargetId, bool> reverse_capable;
  // Tier 3 §9 — per-target labels. `labels` maps target_id → label;
  // `label_owners` is the inverse (label → target_id) used to enforce
  // string uniqueness in O(1). Both protected by `mu` (no second mutex
  // — the dispatcher is single-threaded today and the maps are tiny).
  std::unordered_map<TargetId, std::string>      labels;
  std::unordered_map<std::string, TargetId>      label_owners;
  std::atomic<TargetId> next_id{1};

  // Dedicated SBListener for module-load notifications (slice 1c —
  // closes the dlopen-without-resume gap from the 1b reviewer). On
  // attach/launch we subscribe each target's broadcaster to
  // SBTarget::eBroadcastBitModulesLoaded; snapshot_for_target drains
  // any pending events synchronously before computing layout_digest,
  // so a dlopen between two snapshots invalidates the cache and the
  // second snapshot's layout_digest reflects the new module set.
  //
  // Synchronous drain (rather than a background listener thread)
  // avoids the lifetime hazards the 1b worker flagged: no thread to
  // join on dtor, no risk of receiving an event for a target that
  // was just closed. The cost is a small amount of work on each
  // snapshot_for_target call, which is dwarfed by the digest hash.
  lldb::SBListener module_listener;

  // Per-target chained-fixup map cache. Lazy-initialised on first
  // xref query against the target; in-memory only (phase 3 will add
  // on-disk caching keyed on build_id). The cached map covers only the
  // main executable (module index 0) — same scope as xref_address.
  // See docs/35-field-report-followups.md §3 phase 2.
  //
  // The optional<> distinguishes "never queried" from "queried and the
  // binary has no chained fixups": the latter caches an empty map so
  // subsequent calls don't re-read the on-disk Mach-O. Guarded by `mu`.
  std::unordered_map<TargetId, ChainedFixupMap> chained_fixup_maps;
  std::unordered_map<TargetId, bool>            chained_fixup_loaded;

  // Breakpoint callback registry. A separate mutex from `mu` so the
  // hot-path lookup from LLDB's event thread doesn't contend with
  // dispatcher-thread target operations.
  std::mutex cb_mu;
  // Keyed by (target_id, bp_id). Use shared_ptr so the trampoline can
  // hold a stable handle even if the dispatcher thread is mid-erase
  // (it can't be — the orchestrator's contract is "disable + drain
  // before delete" — but defensive shared ownership is cheap).
  std::map<std::pair<TargetId, std::int32_t>,
           std::shared_ptr<LldbBreakpointCb>> bp_callbacks;
};

namespace {

// On macOS, Homebrew LLVM's distribution does NOT ship a debugserver
// binary. SBProcess::Launch / Attach silently fail with "failed to
// launch or debug process" unless LLDB_DEBUGSERVER_PATH points at a
// signed debugserver from the Apple Command Line Tools or Xcode. We
// auto-discover one on construction so unit tests work out of the box.
void maybe_seed_apple_debugserver() {
#ifdef __APPLE__
  if (std::getenv("LLDB_DEBUGSERVER_PATH") != nullptr) return;

  static const char* kCandidates[] = {
    "/Library/Developer/CommandLineTools/Library/PrivateFrameworks/"
        "LLDB.framework/Versions/A/Resources/debugserver",
    "/Applications/Xcode.app/Contents/SharedFrameworks/"
        "LLDB.framework/Versions/A/Resources/debugserver",
  };
  for (const char* path : kCandidates) {
    struct stat st;
    if (::stat(path, &st) == 0 && (st.st_mode & S_IXUSR)) {
      ::setenv("LLDB_DEBUGSERVER_PATH", path, /*overwrite=*/0);
      log::debug(std::string("LLDB_DEBUGSERVER_PATH=") + path);
      return;
    }
  }
  log::warn(
      "could not find a signed debugserver; SBProcess::Launch may fail. "
      "Install Xcode Command Line Tools or set LLDB_DEBUGSERVER_PATH.");
#endif
}

}  // namespace

namespace {

// SBDebugger::Initialize / Terminate are process-global. Calling them
// in a per-instance ctor/dtor creates Init/Terminate cycles that
// corrupt internal state — second-and-later SBProcess::Launch calls
// then fail mysteriously. Instead, initialize on first use and let
// process exit reap everything.
void ensure_lldb_initialized() {
  static std::once_flag once;
  std::call_once(once, [] {
    maybe_seed_apple_debugserver();
    lldb::SBDebugger::Initialize();
  });
}

}  // namespace

LldbBackend::LldbBackend() : impl_(std::make_unique<Impl>()) {
  ensure_lldb_initialized();
  impl_->debugger = lldb::SBDebugger::Create();
  impl_->debugger.SetAsync(false);
  // Stop LLDB from eagerly parsing the entire symbol table + DWARF on
  // CreateTarget. For a stripped 503 MB Obj-C iOS Mach-O this single
  // knob was the difference between target.open returning in <1s and
  // never returning (RSS grew linearly at ~5 MB/s past 36 GB, building
  // an in-memory index over __objc_methname / function symbols that
  // nobody had asked for yet). Symbol queries (symbol.find,
  // disasm.function, ...) still work — they just trigger the parse
  // on demand, scoped to the module they actually need.
  if (const char* name = impl_->debugger.GetInstanceName()) {
    lldb::SBDebugger::SetInternalVariable("target.preload-symbols", "false",
                                          name);
  }
  // Module-load listener (slice 1c). Created up front and reused for
  // every target's broadcaster — synchronous drain in
  // snapshot_for_target means we never block on it.
  impl_->module_listener = lldb::SBListener("ldb.modules_loaded");
  // One-line trace per backend instance is useful for debugging client
  // setup but not for steady-state operation; demoted to debug so
  // --log-level error and the unit-test default (info) stay quiet.
  log::debug("lldb backend initialized");
}

LldbBackend::~LldbBackend() {
  if (!impl_) return;
  // Drop per-target resources (SSH tunnels, etc.) BEFORE the SBTargets
  // and the debugger — same reasoning as close_target. The bookkeeping
  // map is moved out so the unique_ptrs run their dtors with no lock
  // held.
  decltype(impl_->target_resources) resources_by_target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    resources_by_target = std::move(impl_->target_resources);
    impl_->targets.clear();
  }
  resources_by_target.clear();
  if (impl_->debugger.IsValid()) {
    lldb::SBDebugger::Destroy(impl_->debugger);
  }
  // Deliberately do NOT call SBDebugger::Terminate() here — see comment
  // on ensure_lldb_initialized.
}

OpenResult LldbBackend::open_executable(const std::string& path,
                                        const OpenOptions& opts) {
  lldb::SBError err;
  // CreateTarget(filename, triple, platform, add_dependent_modules, error)
  auto target = impl_->debugger.CreateTarget(
      path.c_str(), /*triple=*/nullptr, /*platform_name=*/nullptr,
      /*add_dependent_modules=*/true, err);

  if (err.Fail() || !target.IsValid()) {
    throw Error(std::string("CreateTarget failed: ") +
                (err.GetCString() ? err.GetCString() : "unknown"));
  }

  TargetId id = impl_->next_id.fetch_add(1);
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    impl_->targets.emplace(id, target);
  }

  OpenResult res;
  res.target_id = id;
  if (const char* tr = target.GetTriple()) res.triple = tr;

  uint32_t n = target.GetNumModules();
  res.modules.reserve(n);
  for (uint32_t i = 0; i < n; ++i) {
    auto mod = target.GetModuleAtIndex(i);
    if (mod.IsValid()) {
      res.modules.push_back(convert_module(mod, opts.include_sections));
    }
  }
  return res;
}

OpenResult LldbBackend::create_empty_target() {
  // Empty path → SBTarget with no associated executable. Required so
  // target.attach by pid has a target to attach against; the inferior's
  // modules become available after the attach completes.
  lldb::SBError err;
  auto target = impl_->debugger.CreateTarget(
      /*filename=*/"", /*triple=*/nullptr, /*platform_name=*/nullptr,
      /*add_dependent_modules=*/false, err);
  if (err.Fail() || !target.IsValid()) {
    throw Error(std::string("CreateTarget(empty) failed: ") +
                (err.GetCString() ? err.GetCString() : "unknown"));
  }
  TargetId id = impl_->next_id.fetch_add(1);
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    impl_->targets.emplace(id, target);
  }
  OpenResult res;
  res.target_id = id;
  if (const char* tr = target.GetTriple()) res.triple = tr;
  return res;
}

OpenResult LldbBackend::load_core(const std::string& core_path) {
  // SHA-256 the core BEFORE handing it to LLDB. Two reasons:
  //   1. Hashing a fresh-on-disk file (closed by us) is more robust
  //      than racing whatever LLDB is doing with mmap / partial reads.
  //   2. If the file isn't readable we throw a focused
  //      "load_core: sha256_file_hex failed" error before LLDB has a
  //      chance to log a less-informative message.
  // Streaming hash; the file is read once in 64 KiB chunks. For multi-
  // hundred-MB cores this is the only memory cost the daemon takes on
  // load_core that wasn't already there.
  std::string core_hex;
  try {
    core_hex = ::ldb::util::sha256_file_hex(core_path);
  } catch (const std::exception& e) {
    throw Error(std::string("load_core: ") + e.what());
  }

  // Empty target hosts the load; SBTarget::LoadCore populates modules
  // and frozen threads from the core file.
  lldb::SBError err;
  auto target = impl_->debugger.CreateTarget(
      /*filename=*/"", /*triple=*/nullptr, /*platform_name=*/nullptr,
      /*add_dependent_modules=*/false, err);
  if (err.Fail() || !target.IsValid()) {
    throw Error(std::string("CreateTarget(empty) failed: ") +
                (err.GetCString() ? err.GetCString() : "unknown"));
  }

  lldb::SBProcess proc = target.LoadCore(core_path.c_str(), err);
  if (err.Fail() || !proc.IsValid()) {
    impl_->debugger.DeleteTarget(target);
    throw Error(std::string("LoadCore failed: ") +
                (err.GetCString() ? err.GetCString() : "unknown"));
  }

  TargetId id = impl_->next_id.fetch_add(1);
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    impl_->targets.emplace(id, target);
    impl_->core_sha256.emplace(id, std::move(core_hex));
  }

  OpenResult res;
  res.target_id = id;
  if (const char* tr = target.GetTriple()) res.triple = tr;
  uint32_t n = target.GetNumModules();
  res.modules.reserve(n);
  for (uint32_t i = 0; i < n; ++i) {
    auto mod = target.GetModuleAtIndex(i);
    // load_core is the postmortem-analysis entry point; the caller has
    // already paid the cost of opening a core file and almost certainly
    // wants the module-level section detail to navigate the snapshot.
    if (mod.IsValid()) {
      res.modules.push_back(convert_module(mod, /*include_sections=*/true));
    }
  }
  return res;
}

std::vector<Module> LldbBackend::list_modules(TargetId tid) {
  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) {
      throw Error("unknown target_id");
    }
    target = it->second;
  }

  std::vector<Module> out;
  uint32_t n = target.GetNumModules();
  out.reserve(n);
  for (uint32_t i = 0; i < n; ++i) {
    auto m = target.GetModuleAtIndex(i);
    // module.list shape is unchanged: callers expect sections inline.
    // Projection out of sections is the view descriptor's job
    // (view.fields=["path","uuid",...]).
    if (m.IsValid()) out.push_back(convert_module(m, /*include_sections=*/true));
  }
  // Stable ordering (audit §3.3 / R4): sort by module path ascending.
  // LLDB's load-order iteration is per-target and stable, but two
  // attaches to the same binary can shuffle module order in the
  // presence of dlopen / lazy module discovery. Path sort is the
  // canonical key.
  std::sort(out.begin(), out.end(),
            [](const Module& a, const Module& b) { return a.path < b.path; });
  return out;
}

namespace {

// Extract a TypeLayout from an SBType. Shared by find_type_layout
// (single-name lookup) and iterate_types (bulk enumeration for the
// SymbolIndex). The two callers MUST produce byte-identical layouts
// for the same SBType, otherwise the index's query_type and the
// fall-through find_type_layout would disagree.
TypeLayout extract_type_layout(lldb::SBType sb_type,
                                const std::string& fallback_name) {
  TypeLayout out;
  if (const char* nm = sb_type.GetName()) {
    out.name = nm;
  } else {
    out.name = fallback_name;
  }

  // GetByteSize returns size in bytes; SBAPI lacks a direct alignment query,
  // so we infer alignment from the maximum field alignment requirement.
  out.byte_size = sb_type.GetByteSize();

  uint32_t nfields = sb_type.GetNumberOfFields();
  out.fields.reserve(nfields);

  std::uint64_t inferred_alignment = 1;

  for (uint32_t i = 0; i < nfields; ++i) {
    auto sb_field = sb_type.GetFieldAtIndex(i);
    if (!sb_field.IsValid()) continue;

    Field f;
    if (const char* fname = sb_field.GetName()) f.name = fname;

    auto field_type = sb_field.GetType();
    if (field_type.IsValid()) {
      if (const char* tn = field_type.GetName()) f.type_name = tn;
      f.byte_size = field_type.GetByteSize();
    }

    // GetOffsetInBytes is the offset of this member from the struct start.
    f.offset = sb_field.GetOffsetInBytes();

    // Track inferred alignment as max(field_size) for primitive-shaped fields.
    if (f.byte_size > 0 &&
        (f.byte_size & (f.byte_size - 1)) == 0 &&     // power of two
        f.byte_size <= 16) {                           // primitive-ish cap
      if (f.byte_size > inferred_alignment) {
        inferred_alignment = f.byte_size;
      }
    }

    out.fields.push_back(std::move(f));
  }

  // Compute holes_after: bytes between the end of field i and the start of
  // field i+1 (or the end of the struct for the last field).
  for (size_t i = 0; i < out.fields.size(); ++i) {
    std::uint64_t end_of_this = out.fields[i].offset + out.fields[i].byte_size;
    std::uint64_t next_start  = (i + 1 < out.fields.size())
                                  ? out.fields[i + 1].offset
                                  : out.byte_size;
    out.fields[i].holes_after = (next_start > end_of_this)
                                  ? next_start - end_of_this
                                  : 0;
    out.holes_total += out.fields[i].holes_after;
  }

  out.alignment = inferred_alignment;
  return out;
}

}  // namespace

std::optional<TypeLayout>
LldbBackend::find_type_layout(TargetId tid, const std::string& name) {
  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) {
      throw Error("unknown target_id");
    }
    target = it->second;
  }

  // FindFirstType matches "name" or "struct name" / "class name".
  auto sb_type = target.FindFirstType(name.c_str());
  if (!sb_type.IsValid()) {
    return std::nullopt;
  }

  return extract_type_layout(sb_type, name);
}

namespace {

SymbolKind classify_symbol(lldb::SymbolType t) {
  switch (t) {
    case lldb::eSymbolTypeCode:
    case lldb::eSymbolTypeResolver:
    case lldb::eSymbolTypeTrampoline:
      return SymbolKind::kFunction;
    case lldb::eSymbolTypeData:
    case lldb::eSymbolTypeObjectFile:  // some Mach-O globals show as Data/Object
    case lldb::eSymbolTypeReExported:
      return SymbolKind::kVariable;
    default:
      return SymbolKind::kOther;
  }
}

bool kind_matches(SymbolKind want, SymbolKind got) {
  return want == SymbolKind::kAny || want == got;
}

std::string module_path_of(lldb::SBSymbol /*sym*/, lldb::SBTarget target,
                           lldb::SBAddress addr) {
  // SBSymbol doesn't expose a module pointer directly in our LLDB version.
  // Resolve via the symbol's address → SBSymbolContext → SBModule.
  if (!addr.IsValid()) return {};
  auto sc = target.ResolveSymbolContextForAddress(
      addr, lldb::eSymbolContextModule);
  auto m = sc.GetModule();
  if (!m.IsValid()) return {};
  auto fs = m.GetFileSpec();
  if (!fs.IsValid()) return {};
  char buf[4096];
  if (fs.GetPath(buf, sizeof(buf)) > 0) return buf;
  return {};
}

}  // namespace

namespace {

// Build a SymbolMatch from an SBSymbol, applying the kind filter from
// the query. Returns std::nullopt if the symbol is invalid or filtered
// out. Pulled out of find_symbols so the exact-name and demangled
// fallback paths share one decorator.
std::optional<SymbolMatch> decorate_symbol(lldb::SBSymbol sym,
                                           lldb::SBTarget target,
                                           const SymbolQuery& query) {
  if (!sym.IsValid()) return std::nullopt;
  const char* name = sym.GetName();
  if (!name) return std::nullopt;

  SymbolKind kind = classify_symbol(sym.GetType());
  if (!kind_matches(query.kind, kind)) return std::nullopt;

  SymbolMatch m;
  m.name = name;
  if (const char* mn = sym.GetMangledName()) {
    if (m.name != mn) m.mangled = mn;
  }
  m.kind = kind;

  auto start_addr = sym.GetStartAddress();
  if (start_addr.IsValid()) {
    m.address = start_addr.GetFileAddress();
    lldb::addr_t la = start_addr.GetLoadAddress(target);
    if (la != LLDB_INVALID_ADDRESS) {
      m.load_address = static_cast<std::uint64_t>(la);
    }
  }
  auto end_addr = sym.GetEndAddress();
  if (end_addr.IsValid() && start_addr.IsValid()) {
    auto e = end_addr.GetFileAddress();
    auto s = start_addr.GetFileAddress();
    if (e > s) m.byte_size = e - s;
  }

  m.module_path = module_path_of(sym, target, start_addr);
  return m;
}

// Stable dedupe key for a symbol match. Symbols in different modules
// can share an address (PLT trampoline + canonical), so we key on
// (module, file_address, name).
struct SymbolDedupeKey {
  std::string module_path;
  std::uint64_t address;
  std::string name;
  bool operator<(const SymbolDedupeKey& o) const {
    if (module_path != o.module_path) return module_path < o.module_path;
    if (address     != o.address)     return address     < o.address;
    return name < o.name;
  }
};

// Strip a balanced parenthesized arg list from the end of a qualified
// C++ name, if present. "Foo::bar(int)" → "Foo::bar"; names without a
// trailing ')' are returned unchanged. Apple's libLLDB on arm64 doesn't
// parse `Class::Method(args)` in FindFunctions(eFunctionNameTypeAuto)
// the way upstream LLDB does, so the find_symbols cascade tries both
// the literal query and the arg-stripped form to stay portable.
std::string strip_trailing_arg_list(const std::string& name) {
  if (name.empty() || name.back() != ')') return name;
  int depth = 0;
  for (std::size_t i = name.size(); i-- > 0; ) {
    if (name[i] == ')') ++depth;
    else if (name[i] == '(') {
      if (--depth == 0) return name.substr(0, i);
    }
  }
  return name;
}

}  // namespace

std::vector<SymbolMatch>
LldbBackend::find_symbols(TargetId tid, const SymbolQuery& query) {
  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) {
      throw Error("unknown target_id");
    }
    target = it->second;
  }

  std::vector<SymbolMatch> out;
  std::set<SymbolDedupeKey> seen;
  auto push = [&](SymbolMatch m) {
    SymbolDedupeKey k{m.module_path, m.address, m.name};
    if (seen.insert(std::move(k)).second) {
      out.push_back(std::move(m));
    }
  };

  // Pass 1: exact-name FindSymbols. Matches when `query.name` is the
  // mangled symbol or the simple/demangled name LLDB stores on the
  // symbol. SBTarget::FindSymbols ranges over all loaded modules.
  {
    auto sblist = target.FindSymbols(query.name.c_str());
    uint32_t n = sblist.GetSize();
    for (uint32_t i = 0; i < n; ++i) {
      auto ctx = sblist.GetContextAtIndex(i);
      auto sym = ctx.GetSymbol();
      if (!sym.IsValid()) continue;
      const char* name = sym.GetName();
      if (!name || query.name != name) continue;
      if (auto m = decorate_symbol(sym, target, query)) push(std::move(*m));
    }
  }

  // Pass 2: SBTarget::FindFunctions with eFunctionNameTypeAuto. LLDB's
  // own C++ name parser handles `Class::Method`,
  // `Class::Method(args)`, and bare `Method` — on upstream LLDB.
  // Apple's libLLDB on arm64 (Homebrew / system LLVM) silently fails
  // for the parenthesized-args form, so we also try the arg-stripped
  // name to keep behavior portable. Functions only — variables do not
  // show up here, but pass 1 already covers those by name.
  // Skipped when the user explicitly asked for variables only.
  if (query.kind != SymbolKind::kVariable) {
    auto run_find_functions = [&](const std::string& nm) {
      if (nm.empty()) return;
      auto fnlist = target.FindFunctions(
          nm.c_str(),
          static_cast<std::uint32_t>(lldb::eFunctionNameTypeAuto));
      uint32_t n = fnlist.GetSize();
      for (uint32_t i = 0; i < n; ++i) {
        auto ctx = fnlist.GetContextAtIndex(i);
        auto sym = ctx.GetSymbol();
        if (!sym.IsValid()) {
          // FindFunctions sometimes returns an SBFunction without a
          // backing SBSymbol (inlined / DWARF-only). Skip — we want
          // the symbol-level match shape.
          continue;
        }
        if (auto m = decorate_symbol(sym, target, query)) push(std::move(*m));
      }
    };
    run_find_functions(query.name);
    if (auto stripped = strip_trailing_arg_list(query.name);
        stripped != query.name) {
      run_find_functions(stripped);
    }
  }

  // Pass 3: demangled-name scan. Only run when the first two passes
  // produced nothing — this is O(num_symbols) across every loaded
  // module, so we keep it as a last resort. Matches:
  //   (a) demangled name == query.name   (covers `Class::Method` when
  //       LLDB's GetName returns the simple form);
  //   (b) demangled name endsWith "::" + query.name   (covers bare
  //       `Method` lookup when only a `Class::Method` symbol exists).
  // Capped at kFallbackScanCap matches to avoid pathological responses
  // on huge binaries.
  if (out.empty()) {
    constexpr std::size_t kFallbackScanCap = 64;
    const std::string& q = query.name;
    const std::string q_stripped = strip_trailing_arg_list(q);
    const std::string suffix = "::" + q;
    const std::string suffix_stripped = "::" + q_stripped;
    const bool have_stripped_alt = (q_stripped != q);

    auto ends_with = [](std::string_view s, const std::string& suf) {
      return s.size() > suf.size() &&
             s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
    };

    uint32_t nmod = target.GetNumModules();
    for (uint32_t mi = 0; mi < nmod && out.size() < kFallbackScanCap; ++mi) {
      auto mod = target.GetModuleAtIndex(mi);
      if (!mod.IsValid()) continue;
      std::size_t nsym = mod.GetNumSymbols();
      for (std::size_t si = 0; si < nsym && out.size() < kFallbackScanCap;
           ++si) {
        auto sym = mod.GetSymbolAtIndex(si);
        if (!sym.IsValid()) continue;
        const char* nm = sym.GetName();
        if (!nm) continue;
        const std::string_view sv(nm);
        bool match = (sv == q) || ends_with(sv, suffix);
        if (!match && have_stripped_alt) {
          // Also try the arg-stripped query against both the raw symbol
          // name and the symbol name's stripped form. Covers the case
          // where the query has `(args)` but the symbol's GetName()
          // returns the bare qualified name (Apple libLLDB behavior).
          const std::string sym_stripped =
              strip_trailing_arg_list(std::string(sv));
          const std::string_view svs(sym_stripped);
          match = (sv == q_stripped) || (svs == q_stripped) ||
                  ends_with(sv, suffix_stripped) ||
                  ends_with(svs, suffix_stripped);
        }
        if (!match) continue;
        if (auto m = decorate_symbol(sym, target, query)) push(std::move(*m));
      }
    }
  }

  return out;
}

namespace {

// Build a GlobalVarMatch from an SBValue produced by FindGlobalVariables.
// Best-effort decoration: any field that LLDB can't supply stays at its
// default (empty string / 0 / nullopt) so the wire response carries the
// gap honestly rather than synthesizing a value.
GlobalVarMatch to_global_match(lldb::SBValue v) {
  GlobalVarMatch g;
  if (const char* nm = v.GetName())     g.name = nm;
  if (const char* tn = v.GetTypeName()) g.type = tn;
  g.size = static_cast<std::uint32_t>(v.GetByteSize());

  auto addr = v.GetAddress();
  if (addr.IsValid()) {
    g.file_address = addr.GetFileAddress();
    auto mod = addr.GetModule();
    if (mod.IsValid()) {
      auto fs = mod.GetFileSpec();
      if (fs.IsValid()) {
        if (const char* mn = fs.GetFilename()) g.module = mn;
      }
    }
  }
  // GetLoadAddress on an unloaded global returns LLDB_INVALID_ADDRESS.
  // Only populate load_address when a real mapping exists.
  lldb::addr_t la = v.GetLoadAddress();
  if (la != LLDB_INVALID_ADDRESS) {
    g.load_address = static_cast<std::uint64_t>(la);
  }

  auto decl = v.GetDeclaration();
  if (decl.IsValid()) {
    auto fs = decl.GetFileSpec();
    if (fs.IsValid()) {
      if (const char* fn = fs.GetFilename()) g.file = fn;
    }
    g.line = decl.GetLine();
  }
  return g;
}

}  // namespace

std::vector<GlobalVarMatch>
LldbBackend::find_globals_of_type(TargetId tid, std::string_view type_name,
                                  bool& strict_out) {
  if (type_name.empty()) {
    throw Error("type_name must be non-empty");
  }
  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) {
      throw Error("unknown target_id");
    }
    target = it->second;
  }

  // Enumerate every global with a wildcard regex. SBTarget's variant
  // that takes MatchType is the only call that gives us the whole
  // catalogue in one pass — FindGlobalVariables(name, max) treats
  // `name` as an exact ident, so ".*" without the regex flag returns
  // nothing.
  auto vlist = target.FindGlobalVariables(
      ".*", kGlobalsOfTypeMaxMatches, lldb::eMatchTypeRegex);

  // First pass: exact match. Greedy on success.
  std::vector<GlobalVarMatch> exact;
  std::vector<GlobalVarMatch> all;  // retained for substring fallback
  uint32_t n = vlist.GetSize();
  exact.reserve(n);
  all.reserve(n);
  for (uint32_t i = 0; i < n; ++i) {
    auto v = vlist.GetValueAtIndex(i);
    if (!v.IsValid()) continue;
    const char* tn = v.GetTypeName();
    if (!tn) continue;
    GlobalVarMatch g = to_global_match(v);
    if (type_name == tn) {
      exact.push_back(g);
    }
    all.push_back(std::move(g));
  }

  if (!exact.empty()) {
    strict_out = true;
    return exact;
  }

  // Substring fallback (plain `find`, no regex per scope).
  strict_out = false;
  std::vector<GlobalVarMatch> sub;
  std::string needle(type_name);
  for (auto& g : all) {
    if (g.type.find(needle) != std::string::npos) {
      sub.push_back(std::move(g));
    }
  }
  return sub;
}

namespace {

bool is_print_ascii(unsigned char c) {
  // strings(1) treats tab as printable. We accept space..~ plus tab.
  return c == 0x09 || (c >= 0x20 && c <= 0x7E);
}

// True if section's classified type is "data" (per our M0 classification).
//
// LLDB's SectionType enum is Mach-O-leaning: eSectionTypeDataCString covers
// __TEXT/__cstring and __DATA/__cstring, but ELF .rodata (and .data.rel.ro
// on glibc-style toolchains) is reported as eSectionTypeOther. Without a
// name-based fallback, string.list and string.xref find nothing on Linux.
// We accept the explicit "data"-typed cases AND named ELF read-only-data
// sections; we deliberately do NOT accept all eSectionTypeOther sections
// (that would scan .interp / .plt / .got / .eh_frame and produce noise).
bool is_data_section(lldb::SBSection sec) {
  switch (sec.GetSectionType()) {
    case lldb::eSectionTypeData:
    case lldb::eSectionTypeDataCString:
    case lldb::eSectionTypeDataCStringPointers:
    case lldb::eSectionTypeDataSymbolAddress:
    case lldb::eSectionTypeData4:
    case lldb::eSectionTypeData8:
    case lldb::eSectionTypeData16:
    case lldb::eSectionTypeDataPointers:
      return true;
    case lldb::eSectionTypeOther: {
      const char* nm = sec.GetName();
      if (!nm) return false;
      std::string_view n(nm);
      if (n == ".rodata" || n.rfind(".rodata.", 0) == 0) return true;
      if (n == ".data.rel.ro" || n.rfind(".data.rel.ro.", 0) == 0) return true;
      return false;
    }
    default:
      return false;
  }
}

std::string full_section_name(lldb::SBSection sec) {
  // Walk up the parent chain so we get e.g. "__TEXT/__cstring" not "__cstring".
  std::vector<std::string> parts;
  for (auto cur = sec; cur.IsValid(); cur = cur.GetParent()) {
    if (const char* nm = cur.GetName()) parts.emplace_back(nm);
  }
  std::string out;
  for (auto it = parts.rbegin(); it != parts.rend(); ++it) {
    if (!out.empty()) out.push_back('/');
    out += *it;
  }
  return out;
}

bool module_path_matches(lldb::SBModule mod, const std::string& want) {
  auto fs = mod.GetFileSpec();
  if (!fs.IsValid()) return false;
  char buf[4096];
  if (fs.GetPath(buf, sizeof(buf)) <= 0) return false;
  std::string path = buf;
  if (path == want) return true;
  // Allow basename match.
  if (auto slash = path.rfind('/'); slash != std::string::npos) {
    if (path.substr(slash + 1) == want) return true;
  }
  return false;
}

void scan_section_for_strings(lldb::SBSection sec, lldb::SBTarget target,
                              const StringQuery& q,
                              const std::string& module_path,
                              std::vector<StringMatch>& out) {
  if (!sec.IsValid()) return;

  auto data = sec.GetSectionData();
  if (!data.IsValid()) return;

  size_t n = data.GetByteSize();
  if (n == 0) return;

  // SBData::ReadRawData copies into a buffer. Read the whole section
  // (sections we care about are kilobytes, not gigabytes).
  std::vector<unsigned char> bytes(n);
  lldb::SBError err;
  data.ReadRawData(err, /*offset=*/0, bytes.data(), n);
  if (err.Fail()) return;

  std::uint64_t base = sec.GetFileAddress();
  std::string sec_name = full_section_name(sec);

  size_t i = 0;
  while (i < n) {
    if (!is_print_ascii(bytes[i])) {
      ++i;
      continue;
    }
    size_t start = i;
    while (i < n && is_print_ascii(bytes[i])) ++i;
    size_t len = i - start;

    if (len >= q.min_length &&
        (q.max_length == 0 || len <= q.max_length)) {
      StringMatch m;
      m.text.assign(reinterpret_cast<const char*>(&bytes[start]), len);
      m.address     = base + start;
      m.section     = sec_name;
      m.module_path = module_path;
      out.push_back(std::move(m));
    }

    // Skip the terminator (NUL or non-printable byte) and continue.
    if (i < n) ++i;
  }

  // Recurse into subsections — top-level segments (__TEXT, __DATA_CONST)
  // are containers whose subsections (__TEXT/__cstring, ...) hold the
  // actual bytes.
  size_t nsub = sec.GetNumSubSections();
  for (size_t k = 0; k < nsub; ++k) {
    auto sub = sec.GetSubSectionAtIndex(k);
    if (sub.IsValid()) {
      scan_section_for_strings(sub, target, q, module_path, out);
    }
  }
}

void scan_module_for_strings(lldb::SBModule mod, lldb::SBTarget target,
                             const StringQuery& q,
                             std::vector<StringMatch>& out) {
  if (!mod.IsValid()) return;

  // Compute module path once.
  std::string module_path;
  {
    auto fs = mod.GetFileSpec();
    if (fs.IsValid()) {
      char buf[4096];
      if (fs.GetPath(buf, sizeof(buf)) > 0) module_path = buf;
    }
  }

  size_t nsec = mod.GetNumSections();
  for (size_t i = 0; i < nsec; ++i) {
    auto sec = mod.GetSectionAtIndex(i);
    if (!sec.IsValid()) continue;

    if (!q.section_name.empty()) {
      // Match by either the full hierarchical name (e.g.
      // "__TEXT/__cstring", "PT_LOAD[2]/.rodata") or the leaf name
      // alone (".rodata", "__cstring"). The leaf form is more
      // ergonomic for callers and the only sensible cross-platform
      // option, since LLDB invents segment-style parents on ELF
      // ("PT_LOAD[N]") that callers can't reasonably know.
      std::function<bool(lldb::SBSection)> name_matches =
          [&](lldb::SBSection s) {
            if (full_section_name(s) == q.section_name) return true;
            if (const char* leaf = s.GetName();
                leaf && q.section_name == leaf) {
              return true;
            }
            return false;
          };
      std::function<void(lldb::SBSection)> visit = [&](lldb::SBSection s) {
        if (!s.IsValid()) return;
        if (name_matches(s)) {
          scan_section_for_strings(s, target, q, module_path, out);
          return;
        }
        size_t nk = s.GetNumSubSections();
        for (size_t k = 0; k < nk; ++k) visit(s.GetSubSectionAtIndex(k));
      };
      visit(sec);
      continue;
    }

    // Default: scan only "data"-classified sections (recursively).
    std::function<void(lldb::SBSection)> visit = [&](lldb::SBSection s) {
      if (!s.IsValid()) return;
      if (is_data_section(s)) {
        scan_section_for_strings(s, target, q, module_path, out);
        // scan_section_for_strings already recurses into subsections, so
        // we don't double-recurse here.
        return;
      }
      size_t nk = s.GetNumSubSections();
      for (size_t k = 0; k < nk; ++k) visit(s.GetSubSectionAtIndex(k));
    };
    visit(sec);
  }
}

}  // namespace

std::vector<StringMatch>
LldbBackend::find_strings(TargetId tid, const StringQuery& query) {
  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) {
      throw Error("unknown target_id");
    }
    target = it->second;
  }

  std::vector<StringMatch> out;

  uint32_t nmods = target.GetNumModules();
  for (uint32_t mi = 0; mi < nmods; ++mi) {
    auto mod = target.GetModuleAtIndex(mi);
    if (!mod.IsValid()) continue;

    if (query.module_path.empty()) {
      // Default scope: main executable only (module index 0).
      if (mi != 0) continue;
    } else if (query.module_path != "*") {
      if (!module_path_matches(mod, query.module_path)) continue;
    }
    // "*" matches all modules; fall through.

    scan_module_for_strings(mod, target, query, out);
  }

  return out;
}

namespace {

// Resolve the SBModule for a target whose UUID/build-id matches the
// caller's `build_id`. The dispatcher passes the build_id it sees on
// list_modules; this method's job is to bind that label back to a
// concrete SBModule so we can walk symbols/types/strings off it.
//
// Returns invalid SBModule when no module matches. Callers iterate_*
// return empty buckets in that case (the dispatcher's correlate.*
// then falls through to find_*).
lldb::SBModule resolve_module_for_build_id(lldb::SBTarget target,
                                            std::string_view build_id) {
  uint32_t n = target.GetNumModules();
  for (uint32_t i = 0; i < n; ++i) {
    auto m = target.GetModuleAtIndex(i);
    if (!m.IsValid()) continue;
    const char* uuid = m.GetUUIDString();
    if (uuid && build_id == uuid) return m;
  }
  // Fallback: empty build_id (caller didn't know) → first module is
  // the main executable on every target we open. This matches the
  // default scope of find_strings and the implicit module-0 LLDB uses
  // for find_type_layout's FindFirstType.
  if (build_id.empty() && n > 0) {
    auto m = target.GetModuleAtIndex(0);
    if (m.IsValid()) return m;
  }
  return lldb::SBModule();
}

std::string module_path_of(lldb::SBModule m) {
  if (!m.IsValid()) return {};
  auto fs = m.GetFileSpec();
  if (!fs.IsValid()) return {};
  char buf[4096];
  if (fs.GetPath(buf, sizeof(buf)) > 0) return buf;
  return {};
}

// Build a SymbolMatch from an SBSymbol unconditionally (no kind filter).
// Used by iterate_symbols where the bucket is the kind filter. Mirrors
// the decoration in find_symbols's `decorate_symbol`; intentionally
// duplicated rather than refactored because find_symbols's version
// applies a query-time kind filter we don't want here.
std::optional<SymbolMatch>
decorate_symbol_for_iterate(lldb::SBSymbol sym, lldb::SBTarget target,
                             const std::string& mod_path) {
  if (!sym.IsValid()) return std::nullopt;
  const char* name = sym.GetName();
  if (!name) return std::nullopt;

  SymbolMatch m;
  m.name = name;
  if (const char* mn = sym.GetMangledName()) {
    if (m.name != mn) m.mangled = mn;
  }
  m.kind = classify_symbol(sym.GetType());

  auto start_addr = sym.GetStartAddress();
  if (start_addr.IsValid()) {
    m.address = start_addr.GetFileAddress();
    lldb::addr_t la = start_addr.GetLoadAddress(target);
    if (la != LLDB_INVALID_ADDRESS) {
      m.load_address = static_cast<std::uint64_t>(la);
    }
  }
  auto end_addr = sym.GetEndAddress();
  if (end_addr.IsValid() && start_addr.IsValid()) {
    auto e = end_addr.GetFileAddress();
    auto s = start_addr.GetFileAddress();
    if (e > s) m.byte_size = e - s;
  }
  m.module_path = mod_path;
  return m;
}

}  // namespace

DebuggerBackend::ModuleSymbols
LldbBackend::iterate_symbols(TargetId tid, std::string_view build_id) {
  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) {
      throw Error("unknown target_id");
    }
    target = it->second;
  }

  ModuleSymbols out;
  auto mod = resolve_module_for_build_id(target, build_id);
  if (!mod.IsValid()) return out;
  std::string mod_path = module_path_of(mod);

  std::size_t nsym = mod.GetNumSymbols();
  std::size_t cap  = DebuggerBackend::kIterateBucketCap;
  // Reserve roughly half for functions, half for data — saves a couple
  // of reallocs on big modules without locking in a precise split.
  out.functions.reserve(nsym / 2);
  out.data.reserve(nsym / 4);

  // Dedupe by (schema PK, address) so the cache PK never rejects an
  // insert. The SymbolIndex PK is (build_id, name, address) where
  // `name` is whatever ends up in row.name — which is `m.mangled` when
  // non-empty else `m.name` (see symbol_match_to_row in dispatcher.cpp).
  // Keying the dedupe on the same expression guarantees we never drop
  // a row whose schema key would actually have been unique.
  // LLDB exposes PLT trampolines, weak aliases, and IFUNC resolvers
  // as separate SBSymbols at the same name+address; this dedupe drops
  // the duplicates the same way find_symbols's SymbolDedupeKey does.
  std::set<std::pair<std::string, std::uint64_t>> seen;

  bool truncated = false;
  for (std::size_t i = 0; i < nsym; ++i) {
    auto sym = mod.GetSymbolAtIndex(i);
    auto decorated = decorate_symbol_for_iterate(sym, target, mod_path);
    if (!decorated.has_value()) continue;
    const std::string& schema_name =
        decorated->mangled.empty() ? decorated->name : decorated->mangled;
    auto key = std::make_pair(schema_name, decorated->address);
    if (!seen.insert(std::move(key)).second) continue;
    switch (decorated->kind) {
      case SymbolKind::kFunction:
        if (out.functions.size() < cap) out.functions.push_back(std::move(*decorated));
        else truncated = true;
        break;
      case SymbolKind::kVariable:
        if (out.data.size() < cap) out.data.push_back(std::move(*decorated));
        else truncated = true;
        break;
      default:
        if (out.other.size() < cap) out.other.push_back(std::move(*decorated));
        else truncated = true;
        break;
    }
  }
  if (truncated) {
    ::ldb::log::warn(
        std::string("iterate_symbols: module ") + mod_path +
        " has >" + std::to_string(cap) + " symbols per bucket; truncated. "
        "correlate.* per-name queries beyond the cap fall through to backend.");
  }
  out.truncated = truncated;
  return out;
}

DebuggerBackend::ModuleTypes
LldbBackend::iterate_types(TargetId tid, std::string_view build_id) {
  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) {
      throw Error("unknown target_id");
    }
    target = it->second;
  }

  ModuleTypes out;
  auto mod = resolve_module_for_build_id(target, build_id);
  if (!mod.IsValid()) return out;

  // SBModule::GetTypes(eTypeClassStruct | eTypeClassClass | eTypeClassUnion)
  // gives us every aggregate the debug info knows about. We skip typedefs
  // and enums — find_type_layout only emits aggregate layouts.
  const std::uint32_t type_classes =
      static_cast<std::uint32_t>(lldb::eTypeClassStruct) |
      static_cast<std::uint32_t>(lldb::eTypeClassClass)  |
      static_cast<std::uint32_t>(lldb::eTypeClassUnion);
  auto tlist = mod.GetTypes(type_classes);
  std::uint32_t n = tlist.GetSize();
  out.types.reserve(n);

  std::size_t cap = DebuggerBackend::kIterateBucketCap;
  bool truncated = false;
  // Dedupe by canonical name — DWARF can produce multiple SBType
  // entries for the same struct across compilation units. find_type_
  // layout uses FindFirstType which returns one; we mirror by keeping
  // the first occurrence.
  std::set<std::string> seen;
  for (std::uint32_t i = 0; i < n; ++i) {
    if (out.types.size() >= cap) { truncated = true; break; }
    auto t = tlist.GetTypeAtIndex(i);
    if (!t.IsValid()) continue;
    const char* nm = t.GetName();
    if (!nm || *nm == '\0') continue;
    std::string canonical = nm;
    if (!seen.insert(canonical).second) continue;
    out.types.push_back(extract_type_layout(t, canonical));
  }
  if (truncated) {
    ::ldb::log::warn(
        std::string("iterate_types: module ") + module_path_of(mod) +
        " has >" + std::to_string(cap) + " aggregate types; truncated. "
        "correlate.types beyond the cap falls through to backend.");
  }
  out.truncated = truncated;
  return out;
}

DebuggerBackend::ModuleStrings
LldbBackend::iterate_strings(TargetId tid, std::string_view build_id) {
  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) {
      throw Error("unknown target_id");
    }
    target = it->second;
  }

  ModuleStrings out;
  auto mod = resolve_module_for_build_id(target, build_id);
  if (!mod.IsValid()) return out;

  // Match find_strings's default-scope behaviour: scan only the main
  // executable's data sections at min_length=4. The cache stores the
  // raw strings; the dispatcher's correlate.strings query path applies
  // any caller-supplied filter post-hoc.
  StringQuery q;
  q.module_path = "";   // default = main exec only
  q.min_length  = 4;
  q.max_length  = 0;
  scan_module_for_strings(mod, target, q, out.strings);

  if (out.strings.size() > DebuggerBackend::kIterateBucketCap) {
    ::ldb::log::warn(
        std::string("iterate_strings: module ") + module_path_of(mod) +
        " yielded " + std::to_string(out.strings.size()) +
        " strings; truncating to " +
        std::to_string(DebuggerBackend::kIterateBucketCap));
    out.strings.resize(DebuggerBackend::kIterateBucketCap);
    out.truncated = true;
  }
  return out;
}

namespace {

std::vector<DisasmInsn>
disassemble_range_lldb(lldb::SBTarget target,
                       std::uint64_t start_addr,
                       std::uint64_t end_addr);

#ifdef LDB_HAVE_CAPSTONE
std::optional<std::vector<DisasmInsn>>
disassemble_range_capstone(lldb::SBTarget target,
                           std::uint64_t start_addr,
                           std::uint64_t end_addr);
#endif

}  // namespace

std::vector<DisasmInsn>
LldbBackend::disassemble_range(TargetId tid,
                               std::uint64_t start_addr,
                               std::uint64_t end_addr) {
  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) {
      throw Error("unknown target_id");
    }
    target = it->second;
  }

#ifdef LDB_HAVE_CAPSTONE
  if (auto capstone = disassemble_range_capstone(target, start_addr, end_addr)) {
    return *capstone;
  }
#endif
  return disassemble_range_lldb(target, start_addr, end_addr);
}

namespace {

std::vector<DisasmInsn>
disassemble_range_lldb(lldb::SBTarget target,
                       std::uint64_t start_addr,
                       std::uint64_t end_addr) {
  std::vector<DisasmInsn> out;
  if (start_addr >= end_addr) return out;

  // Resolve start_addr to a section-bound SBAddress so ReadInstructions
  // can locate the bytes.
  lldb::SBAddress base = target.ResolveFileAddress(start_addr);
  if (!base.IsValid()) return out;

  // Upper bound on instruction count: assume at least 1 byte per instruction.
  // ReadInstructions returns at most this many even on fixed-width archs.
  std::uint64_t span = end_addr - start_addr;
  if (span > std::numeric_limits<std::uint32_t>::max()) {
    span = std::numeric_limits<std::uint32_t>::max();
  }
  uint32_t request = static_cast<uint32_t>(span);

  auto insns = target.ReadInstructions(base, request);
  size_t n = insns.GetSize();
  out.reserve(n);

  for (size_t i = 0; i < n; ++i) {
    auto insn = insns.GetInstructionAtIndex(static_cast<uint32_t>(i));
    if (!insn.IsValid()) continue;

    auto a = insn.GetAddress();
    std::uint64_t addr_val = a.IsValid() ? a.GetFileAddress() : 0;
    if (addr_val == 0 || addr_val >= end_addr) break;

    DisasmInsn di;
    di.address   = addr_val;
    di.byte_size = static_cast<std::uint32_t>(insn.GetByteSize());
    if (di.byte_size == 0 || di.address + di.byte_size > end_addr) break;

    if (const char* m = insn.GetMnemonic(target))  di.mnemonic = m;
    if (const char* o = insn.GetOperands(target))  di.operands = o;
    if (const char* c = insn.GetComment(target))   di.comment  = c;

    auto data = insn.GetData(target);
    if (data.IsValid()) {
      std::vector<std::uint8_t> bytes(di.byte_size);
      lldb::SBError err;
      size_t got = data.ReadRawData(err, /*offset=*/0, bytes.data(),
                                    bytes.size());
      if (!err.Fail() && got == bytes.size()) di.bytes = std::move(bytes);
    }

    out.push_back(std::move(di));
  }

  return out;
}

#ifdef LDB_HAVE_CAPSTONE

struct CapstoneHandle {
  csh handle = 0;
  CapstoneHandle() = default;
  CapstoneHandle(const CapstoneHandle&) = delete;
  CapstoneHandle& operator=(const CapstoneHandle&) = delete;
  CapstoneHandle(CapstoneHandle&& other) noexcept : handle(other.handle) {
    other.handle = 0;
  }
  CapstoneHandle& operator=(CapstoneHandle&& other) noexcept {
    if (this != &other) {
      if (handle != 0) cs_close(&handle);
      handle = other.handle;
      other.handle = 0;
    }
    return *this;
  }
  ~CapstoneHandle() {
    if (handle != 0) cs_close(&handle);
  }
};

std::optional<CapstoneHandle> open_capstone_for_target(lldb::SBTarget target) {
  const char* triple_c = target.GetTriple();
  if (triple_c == nullptr) return std::nullopt;
  std::string triple = triple_c;

  cs_arch arch;
  cs_mode mode;
  if (triple.rfind("x86_64", 0) == 0 || triple.rfind("amd64", 0) == 0) {
    arch = CS_ARCH_X86;
    mode = CS_MODE_64;
  } else if (triple.rfind("aarch64", 0) == 0 ||
             triple.rfind("arm64", 0) == 0) {
    arch = CS_ARCH_ARM64;
    mode = CS_MODE_LITTLE_ENDIAN;
  } else {
    return std::nullopt;
  }

  CapstoneHandle out;
  if (cs_open(arch, mode, &out.handle) != CS_ERR_OK) return std::nullopt;
  cs_option(out.handle, CS_OPT_DETAIL, CS_OPT_OFF);
  return out;
}

std::optional<std::vector<std::uint8_t>>
read_target_file_bytes(lldb::SBTarget target,
                       std::uint64_t start_addr,
                       std::uint64_t end_addr) {
  if (start_addr >= end_addr) return std::vector<std::uint8_t>{};
  lldb::SBAddress base = target.ResolveFileAddress(start_addr);
  if (!base.IsValid()) return std::nullopt;

  std::uint64_t span64 = end_addr - start_addr;
  if (span64 > static_cast<std::uint64_t>(std::numeric_limits<size_t>::max())) {
    return std::nullopt;
  }
  const size_t span = static_cast<size_t>(span64);
  std::vector<std::uint8_t> bytes(span);

  lldb::SBError err;
  size_t got = target.ReadMemory(base, bytes.data(), bytes.size(), err);
  if (err.Fail() || got != bytes.size()) return std::nullopt;
  return bytes;
}

std::optional<std::vector<DisasmInsn>>
disassemble_range_capstone(lldb::SBTarget target,
                           std::uint64_t start_addr,
                           std::uint64_t end_addr) {
  if (start_addr >= end_addr) return std::vector<DisasmInsn>{};

  auto handle = open_capstone_for_target(target);
  if (!handle.has_value()) return std::nullopt;
  auto bytes = read_target_file_bytes(target, start_addr, end_addr);
  if (!bytes.has_value()) return std::nullopt;

  cs_insn* raw_insns = nullptr;
  size_t n = cs_disasm(handle->handle, bytes->data(), bytes->size(),
                       start_addr, /*count=*/0, &raw_insns);
  if (n == 0 || raw_insns == nullptr) return std::nullopt;

  std::vector<DisasmInsn> out;
  out.reserve(n);
  for (size_t i = 0; i < n; ++i) {
    const cs_insn& ci = raw_insns[i];
    if (ci.address >= end_addr || ci.size == 0) break;
    if (ci.address + ci.size > end_addr) break;

    std::uint64_t offset64 = ci.address - start_addr;
    if (offset64 > static_cast<std::uint64_t>(bytes->size())) break;
    size_t offset = static_cast<size_t>(offset64);
    if (offset + ci.size > bytes->size()) break;

    DisasmInsn di;
    di.address = ci.address;
    di.byte_size = static_cast<std::uint32_t>(ci.size);
    di.bytes.assign(bytes->begin() + static_cast<std::ptrdiff_t>(offset),
                    bytes->begin() +
                        static_cast<std::ptrdiff_t>(offset + ci.size));
    di.mnemonic = ci.mnemonic;
    di.operands = ci.op_str;
    out.push_back(std::move(di));
  }
  cs_free(raw_insns, n);

  if (out.empty()) return std::nullopt;
  return out;
}

#endif  // LDB_HAVE_CAPSTONE

// Search `s` for a hex literal (0x... or 0X..., optionally preceded by '#')
// that equals `needle`. Returns true on first match.
bool string_references_address(const std::string& s, std::uint64_t needle) {
  if (s.empty()) return false;
  size_t i = 0;
  while (i < s.size()) {
    // Locate the next "0x" / "0X".
    size_t pos = s.find("0x", i);
    size_t pos2 = s.find("0X", i);
    if (pos2 != std::string::npos && (pos == std::string::npos || pos2 < pos))
      pos = pos2;
    if (pos == std::string::npos) return false;

    // Parse hex digits after the prefix.
    size_t hs = pos + 2;
    std::uint64_t value = 0;
    size_t digits = 0;
    while (hs < s.size() && digits < 16) {
      char c = s[hs];
      unsigned int d;
      if (c >= '0' && c <= '9')      d = static_cast<unsigned int>(c - '0');
      else if (c >= 'a' && c <= 'f') d = static_cast<unsigned int>(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') d = static_cast<unsigned int>(c - 'A' + 10);
      else                            break;
      value = (value << 4) | d;
      ++hs;
      ++digits;
    }
    if (digits > 0 && value == needle) return true;
    i = std::max(pos + 1, hs);
  }
  return false;
}

// On x86-64 ELF, references to .rodata strings are RIP-relative:
//   leaq 0x2e5a(%rip), %rax       (AT&T)
//   lea  rax, [rip + 0x2e5a]      (Intel)
//   lea  rax, [rip - 0x2e5a]
//
// The operand carries an offset, NOT the absolute target. The actual
// target address is `next_insn_addr + signed_offset`, where
// next_insn_addr is the address of the *following* instruction
// (= insn_addr + insn_byte_size). This is the same convention x86-64
// uses for RIP-relative addressing.
//
// We parse both AT&T and Intel forms because LLDB's disassembler can
// be configured either way and we shouldn't depend on the syntax flag.
bool rip_relative_targets(const std::string& operands,
                          std::uint64_t insn_addr,
                          std::uint32_t insn_byte_size,
                          std::uint64_t needle) {
  if (operands.empty()) return false;
  if (operands.find("rip") == std::string::npos &&
      operands.find("RIP") == std::string::npos) {
    return false;
  }

  const std::uint64_t next_addr = insn_addr + insn_byte_size;

  // Parse a hex offset starting at position `pos` (the '0x'). Returns
  // {found, value, end_pos}.
  auto parse_hex = [&](size_t pos) -> std::tuple<bool, std::uint64_t, size_t> {
    if (pos + 2 > operands.size()) return {false, 0, pos};
    if (operands[pos] != '0' ||
        (operands[pos + 1] != 'x' && operands[pos + 1] != 'X'))
      return {false, 0, pos};
    size_t hs = pos + 2;
    std::uint64_t value = 0;
    size_t digits = 0;
    while (hs < operands.size() && digits < 16) {
      char c = operands[hs];
      unsigned int d;
      if (c >= '0' && c <= '9')      d = static_cast<unsigned int>(c - '0');
      else if (c >= 'a' && c <= 'f') d = static_cast<unsigned int>(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') d = static_cast<unsigned int>(c - 'A' + 10);
      else                            break;
      value = (value << 4) | d;
      ++hs;
      ++digits;
    }
    if (digits == 0) return {false, 0, pos + 2};
    return {true, value, hs};
  };

  // AT&T:  "...0xOFFSET(%rip)..."  or  "...-0xOFFSET(%rip)..."
  // Look for "%rip" or "(rip" or "(%rip" — the rip token.
  size_t i = 0;
  while (i < operands.size()) {
    size_t hex_pos = std::string::npos;
    {
      size_t a = operands.find("0x", i);
      size_t b = operands.find("0X", i);
      if (b != std::string::npos && (a == std::string::npos || b < a)) a = b;
      hex_pos = a;
    }
    if (hex_pos == std::string::npos) break;

    bool negative = false;
    if (hex_pos > 0 && operands[hex_pos - 1] == '-') {
      negative = true;
    }

    auto [ok, value, end] = parse_hex(hex_pos);
    if (!ok) { i = hex_pos + 2; continue; }

    // Look ahead from `end` for either "(%rip)" / "(rip)" (AT&T) or
    // back to find a "[rip" / "[ rip" pattern (Intel) within reasonable
    // window. Simplest: accept if "rip" appears anywhere within ~16
    // chars after `end`, or before `hex_pos` for Intel form.
    auto window_has_rip = [&](size_t start, size_t len) {
      size_t lim = std::min(operands.size(), start + len);
      std::string_view chunk(operands.data() + start, lim - start);
      return chunk.find("rip") != std::string_view::npos ||
             chunk.find("RIP") != std::string_view::npos;
    };
    bool is_rip_relative =
        window_has_rip(end, 16) ||
        (hex_pos >= 8 && window_has_rip(hex_pos - 8, 8));

    if (is_rip_relative) {
      std::int64_t off = static_cast<std::int64_t>(value);
      if (negative) off = -off;
      std::uint64_t resolved = next_addr + static_cast<std::uint64_t>(off);
      if (resolved == needle) return true;
    }

    i = std::max(hex_pos + 1, end);
  }
  return false;
}

// ---------------------------------------------------------------------------
// ARM64 ADRP-pair target resolution (docs/35-field-report-followups.md §3
// phase 2). The existing literal-operand scan misses ADRP because LLDB
// renders the operand as a 21-bit page count (e.g. "x8, 4"), not as the
// absolute page address. We need the absolute target to match against
// (a) the caller's needle directly, and (b) chained-fixup slot
// addresses whose resolved value is the needle.
//
// We parse the small subset of ADRP / ADD-imm / LDR-imm-unsigned-offset
// operand text emitted by LLDB:
//
//   adrp x8, 4               → page = (pc & ~0xfff) + (4 << 12)
//   add  x0, x8, #0x440      → target = page + 0x440
//   add  x0, x8, 1088        → same (LLDB sometimes drops the 0x prefix)
//   ldr  x8, [x8]            → target = page + 0
//   ldr  x8, [x8, #0x440]    → target = page + 0x440
//   ldr  x8, [x8, 1088]      → same
//
// Edge cases we intentionally don't handle here:
//   - LDR with a register offset / shifted index (`[x8, x9]`, `[x8, x9, lsl #3]`)
//   - ADRP whose register is later clobbered by an unrelated insn before
//     the load/add — we'd need real liveness analysis. The common case
//     in compiler-emitted code is ADRP+LDR/ADD as adjacent or near-adjacent
//     instructions, which a single-register "last ADRP wins" map handles.
//
// Phase 3 (docs/35-field-report-followups.md §3) layers deterministic
// register-state clobber rules on top of the phase-2 single-pass scan:
//   - BL / BLR → clear x0..x18 + x30 (AAPCS64 caller-saved set)
//   - RET / B / BR / function-boundary transition → clear entire map
//   - ADD writes (any form) → clear adrp_regs[dst] AFTER emit (the dst
//     no longer holds an ADRP page once we've folded the imm in)
//   - MOV xN, xM → propagate adrp_regs[xM] into adrp_regs[xN]
//   - MOV xN, #imm / MOVZ / MOVK / MOVN / MOV xN, sp / MOV xN, lr →
//     clear adrp_regs[dst]
// These rules don't add a dataflow pass — they're per-instruction
// state mutations the loop applies inline.
struct AdrpPair {
  std::uint64_t page = 0;  // absolute target page (already << 12'd)
  std::uint64_t pc   = 0;  // pc of the ADRP that set this register
};

// The decimal/hex/signed/register parsers live in
// src/backend/xref_arm64_parsers.{h,cpp} so unit tests can exercise
// them without standing up a live LLDB target.
using xref_arm64::parse_int_at;
using xref_arm64::parse_reg_at;
using xref_arm64::parse_uint_at;

// Extract the target address an ARM64 memory operand refers to, given a
// known {adrp_page, register_name} pair. Recognised shapes:
//
//   ADD   reg, src_reg, #<imm>                  → page + imm
//   LDR   xN,  [src_reg]                        → page + 0,   slot-load
//   LDR   xN,  [src_reg, #<imm>]                → page + imm, slot-load
//   LDR   wN,  [src_reg{, #imm}]                → page + imm, NOT slot-load
//   LDRSW xN,  [src_reg{, #imm}]                → page + imm, NOT slot-load
//   LDRH/LDRB  reg, [src_reg{, #imm}]           → page + imm, NOT slot-load
//
// `mnemonic` is lower-cased by the caller. Returns std::nullopt when
// the instruction doesn't fit one of the patterns above. The
// `is_slot_load` flag is what gates the chained-fixup map lookup: it's
// only meaningful for 8-byte LDRs into x-registers, because the
// chained-fixup map keys 64-bit pointer slots. A 32-bit ldr/ldrsw or a
// halfword/byte load is consuming the same effective address as a real
// chained pointer would, so its direct ADRP target match is still
// useful, but it cannot resolve through a slot.
struct AdrpResolved {
  std::uint64_t target = 0;
  bool is_slot_load = false;
  // True iff the consumer instruction had a pre- or post-indexed
  // writeback that rewrites the base register (`[xM, #imm]!` or
  // `[xM], #imm`). The match-emit for the legitimate effective
  // address still fires, but the caller must then clear
  // adrp_regs[base_reg] so a subsequent LDR through xM doesn't
  // false-match the now-stale page.
  bool has_writeback = false;
  // The base register whose tracking should be cleared on writeback.
  // Only meaningful when has_writeback is true.
  std::string writeback_base;
};

// AAPCS64 caller-saved general-purpose register set. A BL / BLR (and
// the PAC-authenticated branch family) clears any tracked ADRP page
// held in one of these regs because the callee is free to overwrite
// them. x19..x28 are callee-saved per AAPCS64 — the callee is required
// to preserve them across the call.
//
// x29 (FP) is callee-saved per AAPCS64 — the callee is required to
// restore it before returning, so we leave it alone. x30 (LR) is the
// return-address register; BL writes the return address there, so it
// belongs in the clobber set.
//
// The classifier is a small switch on the first-character + numeric
// suffix; faster than a hash-set lookup and avoids the 20-string
// per-call construction the original implementation performed (each
// `adrp_regs.erase(std::string(reg))` allocated a temporary
// std::string for the key conversion).
bool is_aapcs64_caller_saved(std::string_view reg) {
  if (reg.size() < 2 || reg.size() > 3) return false;
  if (reg[0] != 'x') return false;
  // x0..x18: caller-saved. x30: caller-saved. Everything else: not.
  if (reg.size() == 2) {
    // x0..x9
    return reg[1] >= '0' && reg[1] <= '9';
  }
  // x10..x18 or x30
  if (reg[1] < '0' || reg[1] > '9' || reg[2] < '0' || reg[2] > '9') {
    return false;
  }
  int n = (reg[1] - '0') * 10 + (reg[2] - '0');
  return (n >= 10 && n <= 18) || n == 30;
}

void clobber_aapcs64_caller_saved(
    std::unordered_map<std::string, AdrpPair>& adrp_regs) {
  // Iterate-and-erase-by-predicate to avoid the 20-string-per-call
  // construction the kAapcs64CallerSavedGPR table loop performed.
  // Typical adrp_regs holds 1–3 entries; the inner check is a small
  // switch and erase() returns the next iterator.
  for (auto it = adrp_regs.begin(); it != adrp_regs.end(); ) {
    if (is_aapcs64_caller_saved(it->first)) {
      it = adrp_regs.erase(it);
    } else {
      ++it;
    }
  }
}

// MOV xN, xM is a register-to-register copy with no shift. LLDB
// renders it identically to ARM64 disasm: "mov  x0, x8". The phase-3
// rule (docs/35-field-report-followups.md §3) propagates ADRP
// tracking through this shape — if xM has a tracked page, so does
// xN. Any other MOV form (immediate, MOVZ/MOVK/MOVN, mov xN, sp,
// mov xN, lr, mov xN, xzr) clears adrp_regs[xN] because the result
// isn't an ADRP page. Returns true iff the instruction was a MOV
// that we handled (caller must NOT then fall through to the
// resolve_adrp_consumer path).
//
// Note: arm64 doesn't have a real MOV instruction — it's an alias
// for ORR xN, xzr, xM (reg-reg) or MOVZ/MOVN/MOVK (imm). LLDB
// canonicalises the alias back to "mov" in its disasm output, which
// is what we match against here.
//
// MOV-source classification (kZero / kImmediate / kXReg / ...) lives
// in xref_arm64_parsers.{h,cpp} so unit tests can pin its alias-name-
// first match order independently of a live LLDB target. Phase 4
// item 5 (docs/35-field-report-followups.md §3) lifted it here so the
// `mov xN, xzr` / `mov xN, #0` cases are pinned in unit tests rather
// than depending on the prefix heuristic by accident.
using xref_arm64::MovSrcKind;
using xref_arm64::classify_mov_source;

// Apply a MOV instruction's effect on the ADRP-tracking map. Returns
// true iff the mnemonic was recognised as a MOV variant — the caller
// (`resolve_adrp_consumer`) uses this to short-circuit and skip
// LDR/ADD parsing, which would never apply.
//
// Recognised shapes:
//   mov  xN, xM       — propagate xM's tracking to xN (or clear if xM
//                       isn't tracked).
//   mov  xN, <other>  — clobber xN. Covers immediate, xzr/wzr, sp,
//                       lr, wN copies, and anything we can't parse.
//   movz/movn/movk    — immediate-loading; always clobber xN.
bool apply_mov_state(
    const std::string& mnemonic, const std::string& operands,
    std::unordered_map<std::string, AdrpPair>& adrp_regs) {
  if (mnemonic != "mov" && mnemonic != "movz" && mnemonic != "movk" &&
      mnemonic != "movn") {
    return false;
  }
  auto [ok_dst, dst, p1] = parse_reg_at(operands, 0);
  if (!ok_dst) return true;  // unparseable — be conservative, ignore
  if (mnemonic == "movz" || mnemonic == "movn" || mnemonic == "movk") {
    // Immediate-loading MOVs always clobber the page.
    adrp_regs.erase(dst);
    return true;
  }
  // Skip ", " or whitespace between dst and src.
  std::size_t pos = p1;
  while (pos < operands.size() &&
         (operands[pos] == ' ' || operands[pos] == ',')) ++pos;
  // Lift the source token (up to next whitespace, comma, or end) and
  // classify by exact match against the canonical alias spellings.
  // Order of token isolation: dst is canonicalised by parse_reg_at;
  // src is matched raw because the alias spellings (xzr, wzr, sp,
  // wsp, lr) don't pass through parse_reg_at as plain xN names.
  std::size_t tok_end = pos;
  while (tok_end < operands.size() &&
         operands[tok_end] != ' ' && operands[tok_end] != ',' &&
         operands[tok_end] != '\t') {
    ++tok_end;
  }
  std::string_view tok(operands.data() + pos, tok_end - pos);
  switch (classify_mov_source(tok)) {
    case MovSrcKind::kXReg: {
      // Propagate if src is tracked; otherwise dst becomes untracked.
      // parse_reg_at canonicalises here too so the lookup hits the
      // normalised key.
      auto [ok_src, src, _p2] = parse_reg_at(operands, pos);
      if (!ok_src) {
        adrp_regs.erase(dst);
        return true;
      }
      auto it = adrp_regs.find(src);
      if (it != adrp_regs.end()) {
        adrp_regs[dst] = it->second;
      } else {
        adrp_regs.erase(dst);
      }
      return true;
    }
    case MovSrcKind::kImmediate:
    case MovSrcKind::kZero:
    case MovSrcKind::kStackPointer:
    case MovSrcKind::kLinkRegister:
    case MovSrcKind::kWReg:
    case MovSrcKind::kOther:
      // All these clobber the destination's tracked page.
      adrp_regs.erase(dst);
      return true;
  }
  return true;  // unreachable; appeases -Wreturn-type
}

// ARM64 ADD / SUB (and the flag-setting ADDS / SUBS variants) all
// write an arithmetic result, not an ADRP page, into the destination
// register. The phase-3 rule is the same in every shape: after we've
// consumed the (possibly-tracked) source for the resolve_adrp_consumer
// match, clear adrp_regs[dst] so the next instruction can't reach back
// through dst to an obsolete page.
//
// SUB joins the family because its destination-write semantics are
// identical to ADD's — `sub xN, xN, #imm` overwrites the tracked
// register exactly as `add xN, xN, #imm` does. The original phase-3
// patch only clobbered on ADD, leaving SUB as a silent false-positive
// vector (covered by xref_subclobber post-review fixture).
//
// Note on match-emit: ADD currently emits a direct-target match when
// `page + imm == target_addr` (the legitimate ADRP+ADD pattern).
// SUB+ADRP doesn't have a corresponding "compute target = page - imm"
// pattern in real compiler output (compilers emit ADD with a signed
// immediate or pre-compute via a different scheme). We only model the
// SUB clobber here, not a SUB match-emit; resolve_adrp_consumer
// remains ADD-only.
//
// Handles:
//   add/sub/adds/subs  xN, xM, #imm        — xN may equal xM
//   add/sub/adds/subs  xN, xM, xL{, shift} — register-register
void clobber_arith_destination(
    const std::string& operands,
    std::unordered_map<std::string, AdrpPair>& adrp_regs) {
  auto [ok_dst, dst, _p] = parse_reg_at(operands, 0);
  if (ok_dst) {
    adrp_regs.erase(dst);
  }
}

// Parse the `[base{, #imm}]` / `[base], #imm` / `[base, #imm]!` /
// `[base]` shapes starting at `pos` in `operands`. On success returns
// the resolved base register name, the immediate offset, and a pair of
// writeback flags (pre/post-indexed). On failure returns {false, ...}.
//
// Pre-indexed writeback: `[base, #imm]!` — base ← base+imm before load.
// Post-indexed writeback: `[base], #imm` — base ← base+imm after load.
// No-writeback: `[base]` (imm=0) or `[base, #imm]`.
//
// The effective address differs per form: pre-indexed and no-writeback
// both compute base+imm; post-indexed computes base (the writeback
// rewrites after the load). The caller fills AdrpResolved.target
// accordingly.
struct AdrpAddrOperand {
  bool ok = false;
  std::string base;
  std::uint64_t imm = 0;
  bool pre_writeback = false;
  bool post_writeback = false;
};

AdrpAddrOperand parse_adrp_addr_operand(const std::string& operands,
                                         std::size_t pos) {
  AdrpAddrOperand r;
  while (pos < operands.size() &&
         (operands[pos] == ' ' || operands[pos] == ',')) ++pos;
  if (pos >= operands.size() || operands[pos] != '[') return r;
  ++pos;
  auto [ok_src, src, p_after_src] = parse_reg_at(operands, pos);
  if (!ok_src) return r;
  r.base = src;
  pos = p_after_src;
  while (pos < operands.size() && operands[pos] == ' ') ++pos;
  if (pos < operands.size() && operands[pos] == ',') {
    // `, #imm]` or `, #imm]!`
    ++pos;
    auto [ok_imm, v, p_after_imm] = parse_uint_at(operands, pos);
    if (!ok_imm) return r;
    r.imm = v;
    pos = p_after_imm;
    while (pos < operands.size() && operands[pos] == ' ') ++pos;
    if (pos >= operands.size() || operands[pos] != ']') return r;
    ++pos;
    if (pos < operands.size() && operands[pos] == '!') {
      r.pre_writeback = true;
    }
  } else if (pos < operands.size() && operands[pos] == ']') {
    // `]` or `], #imm`
    ++pos;
    while (pos < operands.size() && operands[pos] == ' ') ++pos;
    if (pos < operands.size() && operands[pos] == ',') {
      ++pos;
      auto [ok_imm, v, _p] = parse_uint_at(operands, pos);
      if (!ok_imm) return r;
      r.imm = v;
      r.post_writeback = true;
    }
  } else {
    return r;
  }
  r.ok = true;
  return r;
}

std::optional<AdrpResolved>
resolve_adrp_consumer(const std::string& mnemonic, const std::string& operands,
                      const std::unordered_map<std::string, AdrpPair>& adrp_regs) {
  // Short-circuit on mnemonics that can never be an ADRP-pair consumer
  // (MOV variants, calls, returns, ...). The post-emit state-mutation
  // block in xref_address handles state changes for these; running
  // the operand parser below would just churn for nothing. N5 cleanup
  // — the prior apply_mov_state return value was discarded.
  if (mnemonic == "mov" || mnemonic == "movz" || mnemonic == "movk" ||
      mnemonic == "movn") {
    return std::nullopt;
  }
  if (mnemonic == "add") {
    // "add  dst, src, #imm"
    auto [ok_dst, dst, p1] = parse_reg_at(operands, 0);
    if (!ok_dst) return std::nullopt;
    auto [ok_src, src, p2] = parse_reg_at(operands, p1);
    if (!ok_src) return std::nullopt;
    auto it = adrp_regs.find(src);
    if (it == adrp_regs.end()) return std::nullopt;
    // imm
    std::size_t pos = p2;
    while (pos < operands.size() &&
           (operands[pos] == ' ' || operands[pos] == ',')) ++pos;
    auto [ok_imm, imm, _p] = parse_uint_at(operands, pos);
    if (!ok_imm) return std::nullopt;
    AdrpResolved r;
    r.target = it->second.page + imm;
    return r;
  }
  // LDR-family (load) consumer mnemonics. Phase 3 originally modelled
  // only these; the post-review spec (docs/35-field-report-followups.md
  // §3 improvement 4) extends to STR-family (stores) below, since a
  // user asking "what writes to this global?" is a real field-report
  // gap that the ADRP-pair pipeline should answer.
  const bool is_load =
      mnemonic == "ldr"   || mnemonic == "ldrsw" ||
      mnemonic == "ldrh"  || mnemonic == "ldrb"  ||
      mnemonic == "ldur";
  // STR-family. STR/STUR/STRH/STRB share the same operand shape as
  // LDR (one source register + address operand). STP pairs two
  // source registers before the address operand and needs a special
  // path. STUR is the unscaled-immediate variant; LLDB renders it as
  // a distinct mnemonic so it has to be enumerated.
  const bool is_store_one_reg =
      mnemonic == "str"   || mnemonic == "stur"  ||
      mnemonic == "strh"  || mnemonic == "strb";
  const bool is_store_pair = mnemonic == "stp";
  if (!is_load && !is_store_one_reg && !is_store_pair) {
    return std::nullopt;
  }

  // Snapshot the destination/source register's first character *before*
  // parse_reg_at canonicalises it (w8 → x8). The slot-load gate below
  // needs the original width to distinguish `ldr xN, ...` (a 64-bit
  // slot load — what the chained-fixup map indexes) from `ldr wN, ...`
  // (a 32-bit load — same effective address, but the value at that
  // address isn't a pointer). For stores this width is unused but
  // costs nothing to capture.
  std::size_t dst_start = 0;
  while (dst_start < operands.size() &&
         (operands[dst_start] == ' ' || operands[dst_start] == '\t' ||
          operands[dst_start] == ',')) ++dst_start;
  char dst_width = (dst_start < operands.size())
                       ? static_cast<char>(std::tolower(operands[dst_start]))
                       : '\0';

  // Skip the data register(s). LDR / STR / STUR / STRH / STRB have one;
  // STP / LDP have two.
  auto [ok_first, _first, p1] = parse_reg_at(operands, 0);
  if (!ok_first) return std::nullopt;
  std::size_t pos = p1;
  if (is_store_pair) {
    // Second register of the pair.
    while (pos < operands.size() &&
           (operands[pos] == ' ' || operands[pos] == ',')) ++pos;
    auto [ok_second, _second, p2] = parse_reg_at(operands, pos);
    if (!ok_second) return std::nullopt;
    pos = p2;
  }

  AdrpAddrOperand a = parse_adrp_addr_operand(operands, pos);
  if (!a.ok) return std::nullopt;
  auto it = adrp_regs.find(a.base);
  if (it == adrp_regs.end()) return std::nullopt;

  AdrpResolved r;
  // Pre-indexed: effective = page + imm (writeback BEFORE memop).
  // Post-indexed: effective = page (writeback AFTER memop).
  // No-writeback: effective = page + imm.
  if (a.post_writeback) {
    r.target = it->second.page;
  } else {
    r.target = it->second.page + a.imm;
  }
  // Slot-indirection only applies to 8-byte LDRs into x-registers.
  // Halfword/byte loads, LDRSW, and all store forms have effective
  // addresses that may match a slot but don't dereference one as a
  // chained pointer. We still emit the direct ADRP-target match so
  // the caller can resolve string-byte loads and store targets.
  r.is_slot_load = (mnemonic == "ldr" && dst_width == 'x');
  r.has_writeback = a.pre_writeback || a.post_writeback;
  if (r.has_writeback) r.writeback_base = a.base;
  return r;
}

// Read the on-disk bytes backing an SBModule. Used by the chained-
// fixup wire-up (docs/35-field-report-followups.md §3 phase 2) to feed
// LC_DYLD_CHAINED_FIXUPS / LC_SEGMENT_64 commands to
// extract_chained_fixups_from_macho(). Returns empty vector on any
// failure — caller treats that as "binary has no chained fixups."
//
// We deliberately re-read the file rather than going through SBModule's
// section-data API. The chained-fixup payload sits in LC_DYLD_CHAINED_FIXUPS,
// which is in __LINKEDIT and isn't always materialised through SBSection
// (the section walker collapses __LINKEDIT into housekeeping fields).
// File-mode is also cheaper than walking LLDB's section tree for the
// ncmds load commands.
std::vector<std::uint8_t> read_module_file_bytes(lldb::SBModule mod) {
  if (!mod.IsValid()) return {};
  auto fs = mod.GetFileSpec();
  if (!fs.IsValid()) return {};
  char path[4096];
  if (fs.GetPath(path, sizeof(path)) <= 0) return {};

  int fd = ::open(path, O_RDONLY);
  if (fd < 0) return {};

  struct stat st;
  if (::fstat(fd, &st) != 0 || st.st_size <= 0) {
    ::close(fd);
    return {};
  }

  // Reasonable upper bound: don't slurp anything above 2 GiB into a
  // single vector. Real arm64 binaries are tens-to-hundreds of MiB.
  const std::size_t size = static_cast<std::size_t>(st.st_size);
  constexpr std::size_t kMaxRead = 2ULL * 1024 * 1024 * 1024;
  if (size > kMaxRead) {
    ::close(fd);
    return {};
  }

  std::vector<std::uint8_t> buf(size);
  std::size_t off = 0;
  while (off < size) {
    ssize_t n = ::read(fd, buf.data() + off, size - off);
    if (n <= 0) {
      ::close(fd);
      return {};
    }
    off += static_cast<std::size_t>(n);
  }
  ::close(fd);
  return buf;
}

std::string function_name_at(lldb::SBTarget target, lldb::SBAddress addr) {
  if (!addr.IsValid()) return {};
  auto sc = target.ResolveSymbolContextForAddress(
      addr, lldb::eSymbolContextFunction | lldb::eSymbolContextSymbol);
  auto fn = sc.GetFunction();
  if (fn.IsValid()) {
    if (const char* n = fn.GetName()) return n;
  }
  auto sym = sc.GetSymbol();
  if (sym.IsValid()) {
    if (const char* n = sym.GetName()) return n;
  }
  return {};
}

}  // namespace

std::vector<XrefMatch>
LldbBackend::xref_address(TargetId tid, std::uint64_t target_addr,
                          XrefProvenance* provenance) {
  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) {
      throw Error("unknown target_id");
    }
    target = it->second;
  }

  std::vector<XrefMatch> out;

  // Scan only the main executable's code sections. Walking every
  // module's code on macOS would mean disassembling all of dyld and
  // libSystem — minutes of work, useless to the agent's question.
  uint32_t nmods = target.GetNumModules();
  if (nmods == 0) return out;
  auto mod = target.GetModuleAtIndex(0);
  if (!mod.IsValid()) return out;

  // Lazy-load + cache the chained-fixup map for this target. On non-
  // chained-fixup binaries (Linux ELF, older Mach-O) the map is empty
  // and the adrp-pair resolver below still runs — it falls through to
  // the direct-target match path, which subsumes the literal-operand
  // scan for ARM64 ADRP+ADD/LDR pairs that the existing
  // string_references_address heuristic misses.
  //
  // Three-phase pattern: check-flag-under-lock → read+parse-outside-lock
  // → double-check-and-publish-under-lock. The on-disk Mach-O can be
  // 500+ MiB (real iOS apps); holding impl_->mu across that read would
  // block every other RPC and the listener-thread breakpoint dispatch
  // path for the full read+parse duration. Phase-1 stdio dispatcher is
  // single-RPC so the benign race below (two callers both load, only
  // the first publishes) is forward-compatible with the upcoming
  // socket-daemon multi-client surface in §2.
  ChainedFixupMap fixup_map;
  bool need_load = false;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->chained_fixup_loaded.find(tid);
    if (it == impl_->chained_fixup_loaded.end() || !it->second) {
      need_load = true;
    }
  }
  if (need_load) {
    auto bytes = read_module_file_bytes(mod);
    ChainedFixupMap m;
    if (!bytes.empty()) {
      try {
        m = extract_chained_fixups_from_macho(bytes.data(), bytes.size());
      } catch (const Error&) {
        // Malformed payload: publish an empty map so we don't retry on
        // every call. Phase 3 will surface this as a diagnostic.
      }
    }
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto& flag = impl_->chained_fixup_loaded[tid];
    if (!flag) {
      impl_->chained_fixup_maps[tid] = std::move(m);
      flag = true;
    }
  }
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    // find() not operator[]: a concurrent close_target could in theory
    // evict our entry between the publish above and this read. The
    // operator[] default-construction would silently re-create an
    // empty entry and leak it; find() lets us simply fall through with
    // an empty local map. In the stdio dispatcher this race window is
    // empty by construction (single RPC at a time).
    auto map_it = impl_->chained_fixup_maps.find(tid);
    if (map_it != impl_->chained_fixup_maps.end()) {
      fixup_map = map_it->second;
    }
  }

  // Image base for converting slot file-addresses to chained-fixup
  // RVAs. The parser already computed this from the first chain-
  // bearing segment's (vm_addr - segment_offset); reuse it rather than
  // re-deriving from LLDB's section table. Zero when the binary has
  // no chained fixups, in which case the slot-load path below
  // short-circuits on the empty `resolved` map anyway.
  const std::uint64_t image_base = fixup_map.image_base;

  // Match an instruction's adrp-resolved target against (a) the
  // caller's needle directly, and (b) the slot-resolves-to-needle
  // case for chained-fixup binaries. Returns true if either matched.
  auto target_matches = [&](std::uint64_t adrp_target,
                            bool is_slot_load) -> bool {
    if (adrp_target == target_addr) return true;  // direct ADRP+ADD
    if (!is_slot_load) return false;
    if (fixup_map.resolved.empty()) return false;
    // For a load through a slot, adrp_target is the slot's *file
    // address*. The chained-fixup map indexes slots by RVA (file_addr
    // - image_base). Translate the file address into an RVA.
    if (adrp_target < image_base) return false;
    std::uint64_t rva = adrp_target - image_base;
    auto it = fixup_map.resolved.find(rva);
    if (it == fixup_map.resolved.end()) return false;
    return it->second == target_addr;
  };

  std::function<void(lldb::SBSection)> visit = [&](lldb::SBSection sec) {
    if (!sec.IsValid()) return;

    if (sec.GetSectionType() == lldb::eSectionTypeCode) {
      std::uint64_t start = sec.GetFileAddress();
      std::uint64_t size  = sec.GetByteSize();
      if (start != 0 && size > 0) {
        auto insns = disassemble_range_lldb(target, start, start + size);
        // Track recent ADRP results per destination register. Phase 3
        // (docs/35-field-report-followups.md §3) augments the phase-2
        // "last ADRP wins for this register" map with deterministic
        // clobber rules — BL/BLR clears caller-saved, function-boundary
        // transitions reset the map, ADD writes clear adrp_regs[dst]
        // AFTER the match emit, MOV propagates or clears.
        std::unordered_map<std::string, AdrpPair> adrp_regs;
        // Track the enclosing function for boundary detection. We only
        // resolve `function_name_at` when adrp_regs is non-empty; on
        // code with no tracked ADRPs the boundary check is free.
        std::string current_function;
        bool current_function_known = false;
        for (const auto& i : insns) {
          std::string mnem_lower = i.mnemonic;
          for (auto& c : mnem_lower) c = static_cast<char>(std::tolower(c));

          // Phase-3 gate 1 (function-boundary reset). When we have
          // tracked ADRP state, check the current instruction's
          // function against the one the state was recorded under.
          // A mismatch means we walked past RET / fell into a new
          // function via tail-call / hit an unconditional B target
          // and the prior ADRP is no longer in scope.
          if (!adrp_regs.empty()) {
            auto sa = target.ResolveFileAddress(i.address);
            std::string fn = function_name_at(target, sa);
            if (current_function_known && fn != current_function) {
              adrp_regs.clear();
            }
            current_function = std::move(fn);
            current_function_known = true;
          }

          if (mnem_lower == "adrp") {
            // "adrp xN, <imm>" — record the absolute target page. The
            // immediate is *signed* (21-bit, +/- 1 MiB pages); LLDB
            // emits e.g. `adrp x8, -2` for pages below the PC's page.
            // parse_uint_at would refuse the leading '-' and we'd
            // either miss the xref or — worse — silently bind to a
            // stale prior ADRP entry for the same register.
            auto [ok_dst, dst, p1] = parse_reg_at(i.operands, 0);
            if (ok_dst) {
              std::size_t pos = p1;
              while (pos < i.operands.size() &&
                     (i.operands[pos] == ' ' || i.operands[pos] == ','))
                ++pos;
              auto [ok_imm, imm, _e] = parse_int_at(i.operands, pos);
              if (ok_imm) {
                AdrpPair p;
                p.pc   = i.address;
                // Cast → shift → add. Two's-complement wrap on the
                // unsigned addition is exactly the page-below-PC case
                // we want; for positive imm the high bits are zero
                // and the math is identical to the old unsigned path.
                p.page = (i.address & ~static_cast<std::uint64_t>(0xfff)) +
                         (static_cast<std::uint64_t>(imm) << 12);
                adrp_regs[dst] = p;
                // First tracked ADRP in this section needs current_function
                // primed; subsequent iterations refresh on the boundary
                // check above. Cheap when an ADRP is rare; on hot ADRP-
                // emitting code the per-iteration lookup dominates anyway.
                if (!current_function_known) {
                  auto sa = target.ResolveFileAddress(i.address);
                  current_function = function_name_at(target, sa);
                  current_function_known = true;
                }
              }
            }
            // Note: ADRP itself never matches a string-pointer target
            // (its result is a page-aligned address, not the load
            // target). We don't emit an xref for it directly — the
            // paired ADD/LDR is the canonical xref site.
          }

          bool matched_literal =
              string_references_address(i.operands, target_addr) ||
              string_references_address(i.comment,  target_addr) ||
              rip_relative_targets(i.operands, i.address, i.byte_size,
                                    target_addr);

          bool matched_adrp = false;
          // Captured so the post-emit register-state mutation block can
          // apply the LDR pre/post-indexed writeback clobber AFTER the
          // match emit. resolve_adrp_consumer fires regardless of
          // whether the consumer matched the needle — we still need to
          // know "this consumer rewrites its base" so subsequent loads
          // through the same register don't false-match.
          std::optional<AdrpResolved> consumer_resolved;
          if (!matched_literal) {
            auto resolved = resolve_adrp_consumer(mnem_lower, i.operands,
                                                  adrp_regs);
            if (resolved) {
              matched_adrp = target_matches(resolved->target,
                                            resolved->is_slot_load);
              consumer_resolved = resolved;
            } else if (provenance != nullptr &&
                       (mnem_lower == "ldr"   || mnem_lower == "ldrsw" ||
                        mnem_lower == "ldrh"  || mnem_lower == "ldrb"  ||
                        mnem_lower == "ldur"  ||
                        mnem_lower == "str"   || mnem_lower == "stur"  ||
                        mnem_lower == "strh"  || mnem_lower == "strb")) {
              // Phase-3 gate 7 (docs/35-field-report-followups.md §3).
              // resolve_adrp_consumer rejected this memop — most
              // commonly because the address operand is `[xN, xM]` or
              // `[xN, xM, lsl #imm]` rather than the immediate form we
              // model. If xN was nonetheless an ADRP-tracked register,
              // the memop *might* have been the consumer for that ADRP
              // (the runtime value depends on xM, which we can't
              // statically resolve). Surface a provenance counter so
              // the caller can decide to fall back to symbol-index.
              // STP intentionally omitted: its two-register prefix
              // makes the [base] sniff more involved and the false-
              // positive cost of skipping it silently is low compared
              // to the precision loss from a false counter bump.
              std::size_t pos = 0;
              auto [ok_dst, _dst, p1] = parse_reg_at(i.operands, pos);
              if (ok_dst) {
                pos = p1;
                while (pos < i.operands.size() &&
                       (i.operands[pos] == ' ' || i.operands[pos] == ','))
                  ++pos;
                if (pos < i.operands.size() && i.operands[pos] == '[') {
                  ++pos;
                  auto [ok_src, src, _p] = parse_reg_at(i.operands, pos);
                  if (ok_src && adrp_regs.count(src)) {
                    provenance->adrp_pair_skipped++;
                  }
                }
              }
            }
          }

          if (matched_literal || matched_adrp) {
            XrefMatch m;
            m.address   = i.address;
            m.byte_size = i.byte_size;
            m.mnemonic  = i.mnemonic;
            m.operands  = i.operands;
            m.comment   = i.comment;
            auto sa = target.ResolveFileAddress(i.address);
            m.function = function_name_at(target, sa);
            out.push_back(std::move(m));
          }

          // Pre/post-indexed LDR/STR writeback (post-review
          // improvement 3, docs/35-field-report-followups.md §3). The
          // match-emit above has already captured the legitimate xref
          // against the memop's effective address; now clear the base
          // register's tracking so a subsequent memop through it can't
          // false-match the stale page. Bumping the counter + emitting
          // a warning surfaces the clobber to the caller via
          // provenance.
          if (consumer_resolved && consumer_resolved->has_writeback) {
            adrp_regs.erase(consumer_resolved->writeback_base);
            if (provenance != nullptr) {
              provenance->adrp_pair_writeback_cleared++;
              std::ostringstream w;
              w << "pre/post-indexed " << mnem_lower
                << " writeback at 0x" << std::hex << i.address
                << " cleared ADRP tracking for register "
                << consumer_resolved->writeback_base;
              provenance->warnings.push_back(w.str());
            }
          }

          // Phase-3 register-state mutations (after match emit so the
          // instruction we just resolved doesn't lose its tracking
          // mid-emit). Order matters: call clobber first because a
          // call-site has no other state-mutating effect we care about;
          // ADD/MOV are exclusive of each other and of calls.
          //
          // The PAC-authenticated branch family (BLRAA, BLRAB, BLRAAZ,
          // BLRABZ for calls; BRAA, BRAB, BRAAZ, BRABZ for indirect
          // branches; RETAA, RETAB for returns) is treated identically
          // to its plain sibling. AAPCS64 caller-saved semantics are
          // independent of PAC — a PAC call is still a call and still
          // overwrites x0..x18 + x30. The original phase-3 patch
          // matched only bare "bl"/"blr"/"br"/"ret"; the post-review
          // spec extends each clause to the full family.
          const bool is_call =
              mnem_lower == "bl"     || mnem_lower == "blr"    ||
              mnem_lower == "blraa"  || mnem_lower == "blrab"  ||
              mnem_lower == "blraaz" || mnem_lower == "blrabz";
          const bool is_indirect_branch =
              mnem_lower == "br"     ||
              mnem_lower == "braa"   || mnem_lower == "brab"   ||
              mnem_lower == "braaz"  || mnem_lower == "brabz";
          const bool is_return =
              mnem_lower == "ret"    ||
              mnem_lower == "retaa"  || mnem_lower == "retab";

          // Phase 4 item 1 (docs/35-field-report-followups.md §3):
          // conditional branches don't write registers, but a cbz / tbz
          // / b.cond whose target lands in a different function is a
          // tail-call-like control-flow handoff. Gate 1's
          // function_name_at check catches the symbolized case on the
          // NEXT iteration (when the scanner steps into the target
          // function); the new code below pre-empts gate 1 by parsing
          // the conditional's target operand inline. The pre-empt is
          // necessary for stripped binaries where function_name_at
          // returns "" for both sides and gate 1 silently misses the
          // boundary. The bump on adrp_pair_cond_branch_reset signals
          // when the new path fires.
          //
          // Conditional branch mnemonics:
          //   b.eq / b.ne / b.cs / b.cc / b.mi / b.pl / b.vs / b.vc
          //   b.hi / b.ls / b.ge / b.lt / b.gt / b.le / b.al / b.nv
          //   cbz / cbnz / tbz / tbnz
          const bool is_cond_branch =
              (mnem_lower.size() >= 4 && mnem_lower.compare(0, 2, "b.") == 0) ||
              mnem_lower == "cbz"  || mnem_lower == "cbnz" ||
              mnem_lower == "tbz"  || mnem_lower == "tbnz";

          if (is_call) {
            // Gate 2: AAPCS64 caller-saved clobber. Even a leaf-only
            // callee may overwrite x0..x18 + x30 — the scanner has
            // no way to know the callee's behaviour.
            clobber_aapcs64_caller_saved(adrp_regs);
          } else if (mnem_lower == "add" || mnem_lower == "sub" ||
                     mnem_lower == "adds" || mnem_lower == "subs") {
            // Gate 3: ADD / SUB (and the flag-setting siblings) write
            // a computed value, not an ADRP page. Clear adrp_regs[dst]
            // regardless of whether dst==src or the second operand was
            // tracked. resolve_adrp_consumer has already run; the match
            // (if any — only the ADD shape emits one) is already in
            // `out`. SUB joins per the post-review spec: same
            // destination-write semantics, same false-positive class.
            clobber_arith_destination(i.operands, adrp_regs);
          } else if (mnem_lower == "mov" || mnem_lower == "movz" ||
                     mnem_lower == "movk" || mnem_lower == "movn") {
            // Gate 4: MOV may propagate or clobber. The bool return is
            // discarded here — the mnemonic check above already
            // narrowed to MOV variants. The same return is what lets
            // resolve_adrp_consumer short-circuit on MOV without
            // running the LDR/STR operand parser (see the early-bail
            // at the top of resolve_adrp_consumer).
            (void)apply_mov_state(mnem_lower, i.operands, adrp_regs);
          } else if (is_return || is_indirect_branch || mnem_lower == "b") {
            // Gate 1 follow-up: end-of-basic-block instructions that
            // exit the current function reset the entire map. We don't
            // distinguish "B to within current function" from
            // "B to tail-call target" — both look the same in the
            // disasm and the next-iteration function-boundary check
            // will restore tracking when we re-enter the right
            // function via subsequent ADRPs. The conservative reset is
            // the phase-3 acceptance bar. Function-boundary detection
            // by symbol name would miss the two-adjacent-stripped-
            // functions case; phase 4 item 3's function_starts set
            // closes that.
            adrp_regs.clear();
            current_function_known = false;
          } else if (is_cond_branch && !adrp_regs.empty()) {
            // Phase 4 item 1: parse the conditional branch's target
            // address from the operands (LLDB renders it as
            // `0xNNNNNNN`), look up the function name at that target,
            // and reset adrp_regs when it differs from the current
            // function. The pre-empt is what closes the stripped-
            // binary case where gate 1 can't see the boundary.
            //
            // We only do the lookup when adrp_regs is non-empty —
            // when there's no tracked state, the reset is a no-op and
            // function_name_at is the dominant cost. Same optimisation
            // gate 1 uses.
            std::uint64_t branch_target = 0;
            bool have_target = false;
            const auto& ops = i.operands;
            // Walk left-to-right looking for the LAST `0x...` token.
            // LLDB renders cbz / tbz with the conditional register
            // first and the address last; `b.eq 0x100003f00` puts the
            // address first. Scanning to end-of-string and keeping
            // the last hit covers both.
            for (std::size_t scan = 0; scan + 2 <= ops.size(); ++scan) {
              if (ops[scan] == '0' &&
                  (ops[scan + 1] == 'x' || ops[scan + 1] == 'X')) {
                std::size_t hex_start = scan + 2;
                std::uint64_t v = 0;
                std::size_t end = hex_start;
                while (end < ops.size()) {
                  char c = ops[end];
                  unsigned int d;
                  if (c >= '0' && c <= '9')
                    d = static_cast<unsigned int>(c - '0');
                  else if (c >= 'a' && c <= 'f')
                    d = static_cast<unsigned int>(c - 'a' + 10);
                  else if (c >= 'A' && c <= 'F')
                    d = static_cast<unsigned int>(c - 'A' + 10);
                  else break;
                  v = (v << 4) | d;
                  ++end;
                }
                if (end > hex_start) {
                  branch_target = v;
                  have_target = true;
                  scan = end - 1;  // outer ++scan will advance past
                }
              }
            }
            if (have_target) {
              auto sa_target = target.ResolveFileAddress(branch_target);
              std::string target_fn = function_name_at(target, sa_target);
              // current_function was primed by gate 1 above (when
              // adrp_regs first became non-empty). The reset fires
              // when target_fn is non-empty AND distinct from
              // current_function — non-empty matters because stripped
              // binaries return "" on both sides and we don't want
              // to false-trigger on same-stripped-fn cbz patterns
              // (item 3 handles those via function_starts).
              if (!target_fn.empty() && target_fn != current_function) {
                adrp_regs.clear();
                if (provenance != nullptr) {
                  provenance->adrp_pair_cond_branch_reset++;
                  std::ostringstream w;
                  w << "conditional branch " << mnem_lower
                    << " at 0x" << std::hex << i.address
                    << " targets a different function ("
                    << target_fn << ") — adrp_regs cleared";
                  provenance->warnings.push_back(w.str());
                }
              }
            }
          }
        }
      }
      // Code sections may have subsections; recurse anyway in case of
      // archs that nest (rare for real binaries).
    }

    size_t nk = sec.GetNumSubSections();
    for (size_t k = 0; k < nk; ++k) visit(sec.GetSubSectionAtIndex(k));
  };

  size_t nsec = mod.GetNumSections();
  for (size_t i = 0; i < nsec; ++i) visit(mod.GetSectionAtIndex(i));

  // Dedupe by instruction address — the literal-operand path and the
  // ADRP-pair path can both match the same instruction (e.g. on x86-64
  // RIP-relative loads where the operand already carries the target
  // and we also walk the trivial ADRP-pair pattern with zero results).
  // stable_sort because std::unique below keeps the first survivor of
  // each address group; an unstable sort would let nondeterministic
  // ordering pick which of two equal-address entries wins on rebuilds.
  std::stable_sort(out.begin(), out.end(),
                   [](const XrefMatch& a, const XrefMatch& b) {
                     return a.address < b.address;
                   });
  auto last = std::unique(out.begin(), out.end(),
                          [](const XrefMatch& a, const XrefMatch& b) {
                            return a.address == b.address;
                          });
  out.erase(last, out.end());

  // Phase-3 gate 7: emit a human-readable warning when at least one
  // register-offset LDR was skipped. The agent uses this to decide
  // whether the ADRP-pair heuristic is authoritative on this binary
  // or whether it should fall back to symbol-index correlate.
  if (provenance != nullptr && provenance->adrp_pair_skipped > 0) {
    provenance->warnings.push_back(
        "adrp-pair resolver skipped " +
        std::to_string(provenance->adrp_pair_skipped) +
        " register-offset LDR(s) with tracked base "
        "(`[xN, xM]` / `[xN, xM, lsl #imm]`) — these are potential xrefs "
        "the heuristic cannot statically resolve");
  }

  return out;
}

std::vector<StringXrefResult>
LldbBackend::find_string_xrefs(TargetId tid, const std::string& text) {
  // Sanity-check the target up front (throws on invalid).
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    if (impl_->targets.find(tid) == impl_->targets.end()) {
      throw Error("unknown target_id");
    }
  }

  // Step 1: locate strings whose text matches exactly. Default scope =
  // main executable.
  StringQuery sq;
  // No min_length restriction so empty-string and short matches still
  // surface; we filter on exact text below.
  sq.min_length = static_cast<std::uint32_t>(
      text.empty() ? 1 : text.size());
  sq.max_length = static_cast<std::uint32_t>(text.size());
  auto candidates = find_strings(tid, sq);

  std::vector<StringMatch> matching;
  matching.reserve(candidates.size());
  for (auto& c : candidates) {
    if (c.text == text) matching.push_back(std::move(c));
  }
  if (matching.empty()) return {};

  // Step 2: build the LLDB-annotated needle (e.g. "btp_schema.xml" with
  // surrounding quotes — that's the form LLDB emits in instruction
  // comments).
  const std::string quoted_needle = "\"" + text + "\"";

  std::vector<StringXrefResult> out;
  out.reserve(matching.size());

  for (const auto& sm : matching) {
    StringXrefResult r;
    r.string = sm;

    // Address-based xrefs (catches x86-64 direct loads, etc.).
    auto addr_hits = xref_address(tid, sm.address);
    r.xrefs.insert(r.xrefs.end(),
                   std::make_move_iterator(addr_hits.begin()),
                   std::make_move_iterator(addr_hits.end()));

    // Comment-text xrefs: scan main exe's code for instructions whose
    // comment carries the quoted string. This is what LLDB produces
    // for ARM64 PIE ADRP+ADD pairs.
    {
      lldb::SBTarget target;
      {
        std::lock_guard<std::mutex> lk(impl_->mu);
        target = impl_->targets.at(tid);
      }
      uint32_t nmods = target.GetNumModules();
      if (nmods > 0) {
        auto mod = target.GetModuleAtIndex(0);
        if (mod.IsValid()) {
          std::function<void(lldb::SBSection)> visit =
              [&](lldb::SBSection sec) {
            if (!sec.IsValid()) return;
            if (sec.GetSectionType() == lldb::eSectionTypeCode) {
              std::uint64_t start = sec.GetFileAddress();
              std::uint64_t size  = sec.GetByteSize();
              if (start != 0 && size > 0) {
                auto insns =
                    disassemble_range_lldb(target, start, start + size);
                for (const auto& i : insns) {
                  if (i.comment.find(quoted_needle) != std::string::npos) {
                    XrefMatch m;
                    m.address   = i.address;
                    m.byte_size = i.byte_size;
                    m.mnemonic  = i.mnemonic;
                    m.operands  = i.operands;
                    m.comment   = i.comment;
                    auto sa = target.ResolveFileAddress(i.address);
                    m.function = function_name_at(target, sa);
                    r.xrefs.push_back(std::move(m));
                  }
                }
              }
            }
            size_t nk = sec.GetNumSubSections();
            for (size_t k = 0; k < nk; ++k) visit(sec.GetSubSectionAtIndex(k));
          };
          size_t nsec = mod.GetNumSections();
          for (size_t i = 0; i < nsec; ++i) visit(mod.GetSectionAtIndex(i));
        }
      }
    }

    // Dedupe by instruction address — both detection paths can hit the
    // same insn (e.g. an ADRP+ADD pair on arm64 where the operand of
    // ADD is `#0xa40` but LLDB has resolved the comment to "btp_schema").
    std::sort(r.xrefs.begin(), r.xrefs.end(),
              [](const XrefMatch& a, const XrefMatch& b) {
                return a.address < b.address;
              });
    auto last = std::unique(r.xrefs.begin(), r.xrefs.end(),
                            [](const XrefMatch& a, const XrefMatch& b) {
                              return a.address == b.address;
                            });
    r.xrefs.erase(last, r.xrefs.end());

    out.push_back(std::move(r));
  }

  return out;
}

// ---------------------------------------------------------------------------
// Process lifecycle
// ---------------------------------------------------------------------------

namespace {

ProcessState map_state(lldb::StateType s) {
  switch (s) {
    case lldb::eStateInvalid:
    case lldb::eStateUnloaded:    return ProcessState::kInvalid;
    case lldb::eStateAttaching:
    case lldb::eStateConnected:
    case lldb::eStateLaunching:
    case lldb::eStateRunning:
    case lldb::eStateStepping:    return ProcessState::kRunning;
    case lldb::eStateStopped:
    case lldb::eStateSuspended:   return ProcessState::kStopped;
    case lldb::eStateExited:      return ProcessState::kExited;
    case lldb::eStateCrashed:     return ProcessState::kCrashed;
    case lldb::eStateDetached:    return ProcessState::kDetached;
    default:                      return ProcessState::kInvalid;
  }
}

ProcessStatus snapshot(lldb::SBProcess proc) {
  ProcessStatus s;
  if (!proc.IsValid()) return s;
  s.state = map_state(proc.GetState());
  s.pid   = static_cast<std::int32_t>(proc.GetProcessID());
  if (s.state == ProcessState::kExited) {
    s.exit_code = proc.GetExitStatus();
  }
  if (s.state == ProcessState::kStopped) {
    // Best-effort stop reason via the first thread's stop reason.
    auto thr = proc.GetSelectedThread();
    if (!thr.IsValid() && proc.GetNumThreads() > 0) {
      thr = proc.GetThreadAtIndex(0);
    }
    if (thr.IsValid()) {
      char buf[256];
      size_t n = thr.GetStopDescription(buf, sizeof(buf));
      // SBThread::GetStopDescription returns a length that may include
      // the trailing NUL on some LLDB releases (audit §11.1). Use
      // strnlen so we never carry a NUL byte inside the std::string.
      if (n > 0) s.stop_reason.assign(buf, ::strnlen(buf, std::min(n, sizeof(buf))));
    }
  }
  return s;
}

}  // namespace

ProcessStatus LldbBackend::launch_process(TargetId tid,
                                          const LaunchOptions& opts) {
  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) {
      throw Error("unknown target_id");
    }
    target = it->second;
  }

  // Replace any prior process before launching a new one.
  auto existing = target.GetProcess();
  if (existing.IsValid()) {
    auto st = existing.GetState();
    if (st != lldb::eStateExited && st != lldb::eStateDetached &&
        st != lldb::eStateInvalid) {
      lldb::SBError k = existing.Kill();
      (void)k;  // best-effort
    }
  }

  lldb::SBLaunchInfo li(/*argv=*/nullptr);
  std::uint32_t flags = li.GetLaunchFlags();
  if (opts.stop_at_entry) flags |= lldb::eLaunchFlagStopAtEntry;
  li.SetLaunchFlags(flags);

  // argv / env support deferred until M2 cont.

  lldb::SBError err;
  auto proc = target.Launch(li, err);
  if (err.Fail() || !proc.IsValid()) {
    const char* dsp = std::getenv("LLDB_DEBUGSERVER_PATH");
    log::error(std::string("launch failed (LLDB_DEBUGSERVER_PATH=") +
               (dsp ? dsp : "<unset>") + "): " +
               (err.GetCString() ? err.GetCString() : "unknown"));
    throw Error(std::string("launch failed: ") +
                (err.GetCString() ? err.GetCString() : "unknown error"));
  }

  // Fresh process → reset live snapshot state (gen=0, digests cleared).
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    reset_live_state_locked(impl_->live_state[tid]);
  }
  subscribe_modules_loaded(impl_->module_listener, target);
  return snapshot(proc);
}

ProcessStatus LldbBackend::get_process_state(TargetId tid) {
  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) {
      throw Error("unknown target_id");
    }
    target = it->second;
  }
  return snapshot(target.GetProcess());
}

ProcessStatus LldbBackend::continue_process(TargetId tid) {
  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) {
      throw Error("unknown target_id");
    }
    target = it->second;
  }
  auto proc = target.GetProcess();
  if (!proc.IsValid()) {
    throw Error("no process to continue");
  }
  auto st = proc.GetState();
  if (st != lldb::eStateStopped && st != lldb::eStateSuspended) {
    throw Error(std::string("process not stopped (state=") +
                std::to_string(static_cast<int>(st)) + ")");
  }
  lldb::SBError err = proc.Continue();
  if (err.Fail()) {
    throw Error(std::string("continue failed: ") +
                (err.GetCString() ? err.GetCString() : "unknown"));
  }
  // Stopped→running→stopped (LLDB is in synchronous mode, so Continue()
  // returns only after the next stop event). Bump <gen>.
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    bump_live_gen_locked(impl_->live_state[tid]);
  }
  return snapshot(proc);
}

// Tier 4 §14, scoped slice: in v0.3 LldbBackend runs in SetAsync(false),
// so per-thread keep-running is not realizable at the LLDB layer. The
// passthrough here ships the protocol shape (thread.continue,
// process.continue+tid) for agents while the runtime stays sync. When
// v0.4 enables SBProcess::SetAsync(true), this is the expansion point:
// resolve the SBThread by `thread_id`, set thread-suspend states on the
// siblings (SBThread::Suspend()), and Continue the process with only
// `thread_id` Resumed. The wire surface won't change — that's the
// whole point of shipping the shape now.
//
// `thread_id` is logged to ease post-hoc diagnostics; we deliberately
// don't validate it against the live thread set in v0.3 because
// validation would diverge from the v0.4 contract (v0.4 must validate)
// and v0.3's whole-process resume doesn't need it.
ProcessStatus LldbBackend::continue_thread(TargetId tid, ThreadId thread_id) {
  log::info(std::string("continue_thread: target=") + std::to_string(tid) +
            " tid=" + std::to_string(thread_id) +
            " (v0.3 sync passthrough)");
  return continue_process(tid);
}

// v1.6 #21 LLDB-side completion (docs/26-nonstop-runtime.md §1). Marks
// the named thread as suspended via SBThread::Suspend(true). The process
// state is unaffected by the call itself — the suspend bit is honoured
// by the NEXT SBProcess::Continue, which LLDB already supports even
// under SetAsync(false). That's the load-bearing observation: we don't
// need the async-mode flip to deliver per-thread suspend semantics for
// the LLDB-backed `thread.suspend` endpoint; we only need to set the
// bit before the next resume.
ProcessStatus LldbBackend::suspend_thread(TargetId tid, ThreadId thread_id) {
  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) {
      throw Error("unknown target_id");
    }
    target = it->second;
  }
  auto proc = target.GetProcess();
  if (!proc.IsValid()) {
    throw Error("no process");
  }
  auto thr = proc.GetThreadByID(thread_id);
  if (!thr.IsValid()) {
    throw Error("unknown thread id");
  }
  // SBThread::Suspend returns bool; in current SBAPI it cannot fail on
  // a valid SBThread (the suspend bit is purely client-side state).
  // We treat a false return defensively in case LLDB ever grows a
  // failure mode here.
  if (!thr.Suspend()) {
    throw Error("SBThread::Suspend returned false");
  }
  return snapshot(proc);
}

ProcessStatus LldbBackend::kill_process(TargetId tid) {
  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) {
      throw Error("unknown target_id");
    }
    target = it->second;
  }
  auto proc = target.GetProcess();
  if (!proc.IsValid()) {
    return ProcessStatus{};  // kNone
  }
  auto st = proc.GetState();
  if (st == lldb::eStateExited || st == lldb::eStateDetached ||
      st == lldb::eStateInvalid) {
    return snapshot(proc);
  }
  lldb::SBError err = proc.Kill();
  if (err.Fail()) {
    throw Error(std::string("kill failed: ") +
                (err.GetCString() ? err.GetCString() : "unknown"));
  }
  // Process gone → live state is meaningless from now until a new
  // attach/launch. Erase the entry; snapshot_for_target will return
  // "none".
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    impl_->live_state.erase(tid);
  }
  // LLDB 18 on Linux delivers eStateExited asynchronously after Kill().
  // Drain the listener until the process reaches a terminal state.
  {
    auto listener = impl_->debugger.GetListener();
    using clock = std::chrono::steady_clock;
    auto deadline = clock::now() + std::chrono::seconds(5);
    while (clock::now() < deadline) {
      auto s = proc.GetState();
      if (s == lldb::eStateExited || s == lldb::eStateCrashed ||
          s == lldb::eStateDetached || s == lldb::eStateInvalid)
        break;
      lldb::SBEvent ev;
      listener.WaitForEvent(1u, ev);
      if (ev.IsValid() && lldb::SBProcess::EventIsProcessEvent(ev))
        (void)lldb::SBProcess::GetStateFromEvent(ev);
    }
  }
  return snapshot(proc);
}

ProcessStatus LldbBackend::attach(TargetId tid, std::int32_t pid) {
  // pid<=0 has special behaviour in LLDB (0 may pick the most recent
  // attached process; <0 is undefined). Reject up front so the agent
  // gets a typed error instead of silent surprising behaviour.
  if (pid <= 0) {
    throw Error("attach: pid must be a positive integer");
  }

  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) {
      throw Error("unknown target_id");
    }
    target = it->second;
  }

  // If a prior process exists, refuse to clobber it; the agent must
  // explicitly detach or kill first. Different from launch_process,
  // which is documented as auto-killing prior processes — attach is
  // typically the start of a new investigation against an existing
  // inferior, so silently nuking what's there is the wrong default.
  if (auto existing = target.GetProcess(); existing.IsValid()) {
    auto st = existing.GetState();
    if (st != lldb::eStateExited && st != lldb::eStateDetached &&
        st != lldb::eStateInvalid) {
      throw Error("target already has a live process; detach or kill first");
    }
  }

  auto listener = impl_->debugger.GetListener();
  lldb::SBError err;
  auto proc = target.AttachToProcessWithID(
      listener, static_cast<lldb::pid_t>(pid), err);
  if (err.Fail() || !proc.IsValid()) {
    const char* dsp = std::getenv("LLDB_DEBUGSERVER_PATH");
    log::error(std::string("attach failed (LLDB_DEBUGSERVER_PATH=") +
               (dsp ? dsp : "<unset>") + "): " +
               (err.GetCString() ? err.GetCString() : "unknown"));
    throw Error(std::string("attach failed: ") +
                (err.GetCString() ? err.GetCString() : "unknown"));
  }
  // Fresh attach → reset live snapshot state (gen=0).
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    reset_live_state_locked(impl_->live_state[tid]);
  }
  subscribe_modules_loaded(impl_->module_listener, target);
  return snapshot(proc);
}

ProcessStatus LldbBackend::detach_process(TargetId tid) {
  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) {
      throw Error("unknown target_id");
    }
    target = it->second;
  }
  auto proc = target.GetProcess();
  if (!proc.IsValid()) return ProcessStatus{};  // kNone
  auto st = proc.GetState();
  if (st == lldb::eStateExited || st == lldb::eStateDetached ||
      st == lldb::eStateInvalid) {
    return snapshot(proc);
  }
  // Save PID before detach; proc.GetProcessID() may return 0 afterwards.
  auto det_pid = proc.GetProcessID();
  lldb::SBError err = proc.Detach();
  if (err.Fail()) {
    throw Error(std::string("detach failed: ") +
                (err.GetCString() ? err.GetCString() : "unknown"));
  }
  // Detach terminates the live-snapshot identity. Subsequent
  // snapshot_for_target calls will return "none" until a re-attach.
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    impl_->live_state.erase(tid);
  }
#ifdef __linux__
  // LLDB 18 on Linux delivers SIGSTOP to threads before calling
  // PTRACE_DETACH.  After PTRACE_DETACH the pending SIGSTOP is received
  // by the process, leaving it stopped with no debugger watching it.
  // Send SIGCONT to ensure the inferior resumes after detach.
  if (det_pid > 0)
    ::kill(static_cast<::pid_t>(det_pid), SIGCONT);
#endif
  // Return kDetached directly — after a successful Detach() the semantic
  // state is always kDetached.  Avoid snapshot(proc) here: on LLDB 18
  // the state machine hasn't transitioned yet and proc.GetState() still
  // reports eStateStopped.
  ProcessStatus ps;
  ps.state = ProcessState::kDetached;
  ps.pid = static_cast<std::int32_t>(det_pid);
  return ps;
}

ProcessStatus LldbBackend::connect_remote_target(TargetId tid,
                                                 const std::string& url,
                                                 const std::string& plugin_name) {
  if (url.empty()) {
    throw Error("connect_remote: url must not be empty");
  }

  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) {
      throw Error("unknown target_id");
    }
    target = it->second;
  }

  // Mirror attach's policy: refuse to clobber a live process. The
  // operator must explicitly detach/kill before re-connecting.
  if (auto existing = target.GetProcess(); existing.IsValid()) {
    auto st = existing.GetState();
    if (st != lldb::eStateExited && st != lldb::eStateDetached &&
        st != lldb::eStateInvalid) {
      throw Error("target already has a live process; detach or kill first");
    }
  }

  // rr:// URL-scheme dispatch (Tier 4 §13). Per the roadmap, "Reverse
  // execution via rr is just another `target.connect_remote` URL."
  // Parse the rr:// URL, locate the rr binary, spawn `rr replay` on a
  // free port, then rewrite `url` to a local connect:// pointing at
  // the replay's gdb-remote port. The rr replay subprocess is bound
  // to the target's lifetime via attach_target_resource so close_target
  // tears it down (SIGTERM → SIGKILL after 250 ms).
  std::string effective_url = url;
  std::unique_ptr<transport::RrReplayProcess> rr_replay;
  if (url.size() >= 5 && url.compare(0, 5, "rr://") == 0) {
    transport::RrUrl parsed = transport::parse_rr_url(url);

    std::string rr_bin = transport::find_rr_binary();
    if (rr_bin.empty()) {
      throw Error(
          "rr not installed (no $LDB_RR_BIN, no /usr/bin/rr, no "
          "/usr/local/bin/rr, not on PATH); install via your distro "
          "or grab a static binary from https://rr-project.org");
    }

    std::uint16_t port = parsed.port.value_or(0);
    if (port == 0) {
      port = transport::pick_ephemeral_port_local();
    }

    // Spawn rr replay; the ctor blocks until the gdb-remote port is
    // accepting connections (or rr exits / setup_timeout elapses).
    rr_replay = std::make_unique<transport::RrReplayProcess>(
        rr_bin, parsed.trace_dir, port);

    effective_url = "connect://127.0.0.1:" + std::to_string(port);
  }

  // Default plugin is gdb-remote, which handles lldb-server, gdbserver,
  // debugserver, qemu-gdbstub, and friends. Empty plugin_name → default.
  const char* plugin = plugin_name.empty() ? "gdb-remote" : plugin_name.c_str();

  // SBTarget::ConnectRemote occasionally writes connection-failure
  // diagnostics to stdout (the gdb-remote plugin's chatty path). For
  // ldbd that would corrupt the JSON-RPC channel. dup2-over-/dev/null
  // around the call, same pattern as save_core / evaluate_expression.
  int saved_stdout = ::dup(STDOUT_FILENO);
  int devnull      = ::open("/dev/null", O_WRONLY);
  if (saved_stdout >= 0 && devnull >= 0) {
    ::dup2(devnull, STDOUT_FILENO);
    ::close(devnull);
  }

  lldb::SBListener listener = impl_->debugger.GetListener();
  lldb::SBError err;
  auto proc = target.ConnectRemote(listener, effective_url.c_str(), plugin, err);

  if (saved_stdout >= 0) {
    ::dup2(saved_stdout, STDOUT_FILENO);
    ::close(saved_stdout);
  }

  if (err.Fail() || !proc.IsValid()) {
    throw Error(std::string("connect_remote failed: ") +
                (err.GetCString() ? err.GetCString() : "unknown"));
  }

  // ConnectRemote returns with proc.GetState() == eStateInvalid on
  // gdb-remote-protocol servers (lldb-server gdbserver, gdbserver,
  // debugserver) because the initial stop notification arrives as an
  // event on the shared listener — SBProcess won't update its cached
  // state until the event is dequeued. Pump the listener until we see
  // a real state or a deadline expires. Without this every caller
  // would have to call get_process_state in a loop themselves.
  {
    using clock = std::chrono::steady_clock;
    const auto deadline = clock::now() + std::chrono::seconds(2);
    while (clock::now() < deadline) {
      auto st = proc.GetState();
      if (st != lldb::eStateInvalid &&
          st != lldb::eStateUnloaded &&
          st != lldb::eStateConnected) {
        break;
      }
      lldb::SBEvent ev;
      // 100ms blocking wait; if the server is reachable the initial
      // stop event arrives within a few ms.
      listener.WaitForEvent(/*num_seconds=*/1u, ev);
      if (ev.IsValid() && lldb::SBProcess::EventIsProcessEvent(ev)) {
        // Apply the event so SBProcess reflects it.
        (void)lldb::SBProcess::GetStateFromEvent(ev);
      }
    }
  }
  // Fresh remote attach → reset live snapshot state.
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    reset_live_state_locked(impl_->live_state[tid]);
  }
  subscribe_modules_loaded(impl_->module_listener, target);

  // Bind the rr replay subprocess (if any) to the target's lifetime.
  // Done AFTER ConnectRemote succeeds — if ConnectRemote throws, the
  // rr_replay unique_ptr's dtor SIGTERMs the child on the way out, so
  // we never leak. close_target → resource dtor on success.
  if (rr_replay) {
    struct RrReplayResource final : DebuggerBackend::TargetResource {
      explicit RrReplayResource(std::unique_ptr<transport::RrReplayProcess> p)
          : replay(std::move(p)) {}
      std::unique_ptr<transport::RrReplayProcess> replay;
    };
    attach_target_resource(
        tid, std::make_unique<RrReplayResource>(std::move(rr_replay)));
    // Mark the target as reverse-capable for reverse_continue /
    // reverse_step_thread. Today only rr satisfies this; future
    // transports (replay daemons, hardware-trace replay) will set the
    // same flag.
    {
      std::lock_guard<std::mutex> lk(impl_->mu);
      impl_->reverse_capable[tid] = true;
    }
  }

  return snapshot(proc);
}

namespace {

// RAII wrapper so the SSH tunnel can be stuffed into the backend's
// generic per-target-resource bucket. The tunnel's dtor does the real
// teardown; this just supplies the type-erasure.
struct SshTunnelResource final : DebuggerBackend::TargetResource {
  explicit SshTunnelResource(std::unique_ptr<transport::SshTunneledCommand> t)
      : tunnel(std::move(t)) {}
  std::unique_ptr<transport::SshTunneledCommand> tunnel;
};

}  // namespace

ConnectRemoteSshResult
LldbBackend::connect_remote_target_ssh(TargetId tid,
                                       const ConnectRemoteSshOptions& opts) {
  if (opts.host.empty()) {
    throw Error("connect_remote_ssh: host must not be empty");
  }
  if (opts.inferior_path.empty()) {
    throw Error("connect_remote_ssh: inferior_path must not be empty");
  }
  // Validate target_id up front so a "bad target_id" error doesn't
  // surface after we've already paid the ssh latency.
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    if (impl_->targets.find(tid) == impl_->targets.end()) {
      throw Error("connect_remote_ssh: unknown target_id");
    }
  }

  transport::SshHost ssh_host;
  ssh_host.host        = opts.host;
  ssh_host.port        = opts.port;
  ssh_host.ssh_options = opts.ssh_options;

  // Step 1: ask the remote for a free port.
  std::uint16_t remote_port = transport::pick_remote_free_port(
      ssh_host, /*timeout=*/std::chrono::seconds(10));

  // Step 2: build the remote argv. We launch lldb-server in gdbserver
  // mode listening on the chosen port. Use the absolute server path if
  // the caller supplied one — that lets the prebuilt LLVM tarball at
  // /opt/llvm-22/bin/lldb-server work via its $ORIGIN/../lib rpath
  // without us having to set LD_LIBRARY_PATH.
  std::string server_bin = opts.remote_lldb_server.empty()
                               ? std::string("lldb-server")
                               : opts.remote_lldb_server;
  std::vector<std::string> remote_argv;
  remote_argv.push_back(server_bin);
  remote_argv.push_back("gdbserver");
  remote_argv.push_back("127.0.0.1:" + std::to_string(remote_port));
  remote_argv.push_back("--");
  remote_argv.push_back(opts.inferior_path);
  for (const auto& a : opts.inferior_argv) remote_argv.push_back(a);

  // Step 3: spawn the single ssh-with-port-forward subprocess. We use
  // ProbeKind::kAliveOnly because lldb-server gdbserver is a SINGLE-
  // ACCEPT server — a destructive TCP probe through the tunnel would
  // consume its only connection and leave the inferior orphaned.
  // Instead, we spawn-and-trust, then retry ConnectRemote with
  // backoff to absorb the 50–200 ms it takes lldb-server to bind.
  auto tunnel = std::make_unique<transport::SshTunneledCommand>(
      ssh_host,
      /*local_port=*/0,
      remote_port,
      remote_argv,
      opts.setup_timeout,
      transport::ProbeKind::kAliveOnly);
  std::uint16_t local_port = tunnel->local_port();

  // Step 4: drive the existing connect_remote_target with a short
  // retry loop. lldb-server takes ~50–200ms to bind after the ssh
  // handshake; before that, ConnectRemote sees ECONNRESET / "shut
  // down by remote side". Retry-with-backoff hides the race.
  // Total budget: setup_timeout (defaults to 10s).
  std::string url = "connect://127.0.0.1:" + std::to_string(local_port);
  ProcessStatus status;
  bool connected = false;
  std::string last_err;
  const auto deadline =
      std::chrono::steady_clock::now() + opts.setup_timeout;
  for (int attempt = 0; std::chrono::steady_clock::now() < deadline; ++attempt) {
    if (!tunnel->alive()) {
      throw Error("connect_remote_ssh: ssh subprocess died before remote "
                  "lldb-server became reachable" +
                  (last_err.empty() ? std::string{} : ": " + last_err));
    }
    try {
      status = connect_remote_target(tid, url, /*plugin_name=*/"");
      connected = true;
      break;
    } catch (const Error& e) {
      last_err = e.what();
      // Cap retries at ~10 over the budget; sleep grows from 80ms.
      auto delay = std::chrono::milliseconds(80 + 50 * attempt);
      std::this_thread::sleep_for(delay);
    }
  }
  if (!connected) {
    throw Error(std::string("connect_remote_ssh: ConnectRemote retries "
                            "exhausted: ") + last_err);
  }

  // Step 5: bind the tunnel's lifetime to the target. Now the agent
  // can do anything with the target (process.continue, mem.read, ...);
  // when they finally close_target / dtor the backend, the tunnel goes
  // away which kills lldb-server via SIGHUP.
  attach_target_resource(tid,
                         std::make_unique<SshTunnelResource>(std::move(tunnel)));

  ConnectRemoteSshResult out;
  out.status            = std::move(status);
  out.local_tunnel_port = local_port;
  return out;
}

bool LldbBackend::save_core(TargetId tid, const std::string& path) {
  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) throw Error("unknown target_id");
    target = it->second;
  }
  auto proc = target.GetProcess();
  if (!proc.IsValid()) throw Error("no process to save_core");

  // SBProcess::SaveCore prints per-region progress to stdout (e.g.
  // "Saving 16384 bytes ... 0x100000000"). For ldbd that would corrupt
  // the JSON-RPC channel. Redirect stdout to /dev/null around the call
  // so the messages are dropped, then restore it.
  int saved_stdout = ::dup(STDOUT_FILENO);
  int devnull      = ::open("/dev/null", O_WRONLY);
  if (saved_stdout >= 0 && devnull >= 0) {
    ::dup2(devnull, STDOUT_FILENO);
    ::close(devnull);
  }

  // Default flavor "" lets LLDB pick the right format for the platform
  // (e.g. Mach-O on Darwin, ELF on Linux).
  lldb::SBError err = proc.SaveCore(path.c_str());

  if (saved_stdout >= 0) {
    ::dup2(saved_stdout, STDOUT_FILENO);
    ::close(saved_stdout);
  }

  if (err.Fail()) {
    log::warn(std::string("SaveCore failed: ") +
              (err.GetCString() ? err.GetCString() : "unknown"));
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Threads & frames
// ---------------------------------------------------------------------------

namespace {

ThreadInfo to_thread_info(lldb::SBThread thr) {
  ThreadInfo t;
  if (!thr.IsValid()) return t;

  t.tid    = thr.GetThreadID();
  t.index  = thr.GetIndexID();
  if (const char* nm = thr.GetName()) t.name = nm;
  t.state  = map_state(thr.GetProcess().GetState());

  if (thr.GetNumFrames() > 0) {
    auto f0 = thr.GetFrameAtIndex(0);
    if (f0.IsValid()) {
      t.pc = f0.GetPC();
      t.sp = f0.GetSP();
    }
  }

  char buf[256];
  size_t n = thr.GetStopDescription(buf, sizeof(buf));
  // Same trailing-NUL guard as ProcessStatus::stop_reason above
  // (audit §11.1). strnlen finds the real C-string length within the
  // returned byte count.
  if (n > 0) t.stop_reason.assign(buf, ::strnlen(buf, std::min(n, sizeof(buf))));

  return t;
}

FrameInfo to_frame_info(lldb::SBFrame frame, std::uint32_t index) {
  FrameInfo f;
  if (!frame.IsValid()) return f;

  f.index = index;
  f.pc    = frame.GetPC();
  f.fp    = frame.GetFP();
  f.sp    = frame.GetSP();

  // Function preferred; fall back to symbol if function-level info absent
  // (e.g. inside dyld where DWARF is sparse).
  if (auto fn = frame.GetFunction(); fn.IsValid()) {
    if (const char* nm = fn.GetName()) f.function = nm;
  }
  if (f.function.empty()) {
    if (auto sym = frame.GetSymbol(); sym.IsValid()) {
      if (const char* nm = sym.GetName()) f.function = nm;
    }
  }

  if (auto m = frame.GetModule(); m.IsValid()) {
    auto fs = m.GetFileSpec();
    if (fs.IsValid()) {
      char buf[4096];
      if (fs.GetPath(buf, sizeof(buf)) > 0) f.module = buf;
    }
  }

  if (auto le = frame.GetLineEntry(); le.IsValid()) {
    auto fs = le.GetFileSpec();
    if (fs.IsValid()) {
      char buf[4096];
      if (fs.GetPath(buf, sizeof(buf)) > 0) f.file = buf;
    }
    f.line = le.GetLine();
  }

  f.inlined = frame.IsInlined();

  return f;
}

}  // namespace

std::vector<ThreadInfo> LldbBackend::list_threads(TargetId tid) {
  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) {
      throw Error("unknown target_id");
    }
    target = it->second;
  }

  auto proc = target.GetProcess();
  if (!proc.IsValid()) return {};

  std::vector<ThreadInfo> out;
  uint32_t n = proc.GetNumThreads();
  out.reserve(n);
  for (uint32_t i = 0; i < n; ++i) {
    auto thr = proc.GetThreadAtIndex(i);
    if (thr.IsValid()) out.push_back(to_thread_info(thr));
  }
  // Stable ordering (audit §3.5 / R4): sort by ascending kernel tid.
  // The kernel hands tids out in scheduling order — that's the
  // smallest cross-LLDB-version-stable key we have. Cross-process the
  // tid drifts (N1), but identical-snapshot replay consults the
  // snapshot's reg_digest so the relative ordering remains a
  // semantically meaningful index for agents.
  std::sort(out.begin(), out.end(),
            [](const ThreadInfo& a, const ThreadInfo& b) {
              return a.tid < b.tid;
            });
  return out;
}

std::vector<FrameInfo>
LldbBackend::list_frames(TargetId tid, ThreadId thread_id,
                         std::uint32_t max_depth) {
  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) {
      throw Error("unknown target_id");
    }
    target = it->second;
  }

  auto proc = target.GetProcess();
  if (!proc.IsValid()) {
    throw Error("no process");
  }
  auto thr = proc.GetThreadByID(thread_id);
  if (!thr.IsValid()) {
    throw Error("unknown thread id");
  }

  std::vector<FrameInfo> out;
  uint32_t n = thr.GetNumFrames();
  uint32_t cap = (max_depth == 0 || max_depth > n) ? n : max_depth;
  out.reserve(cap);
  for (uint32_t i = 0; i < cap; ++i) {
    auto f = thr.GetFrameAtIndex(i);
    if (f.IsValid()) out.push_back(to_frame_info(f, i));
  }
  return out;
}

ProcessStatus LldbBackend::step_thread(TargetId tid, ThreadId thread_id,
                                       StepKind kind) {
  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) {
      throw Error("unknown target_id");
    }
    target = it->second;
  }

  auto proc = target.GetProcess();
  if (!proc.IsValid()) throw Error("no process");
  auto thr = proc.GetThreadByID(thread_id);
  if (!thr.IsValid()) throw Error("unknown thread id");

  // SBThread::Step* dispatches into the LLDB ThreadPlan stack and, with
  // SetAsync(false) (set in the ctor), blocks until the next stop or a
  // terminal state. The bool argument to StepInstruction is "step over
  // calls"; we want step-into-calls semantics for "insn", so pass false.
  switch (kind) {
    case StepKind::kIn:
      thr.StepInto();
      break;
    case StepKind::kOver:
      thr.StepOver();
      break;
    case StepKind::kOut:
      thr.StepOut();
      break;
    case StepKind::kInsn:
      thr.StepInstruction(/*step_over=*/false);
      break;
  }

  // SBThread::Step* returns void; failures surface as the post-step
  // process state (e.g. eStateInvalid) or via the thread's stop reason.
  // Snapshot the process and let the caller examine state / stop_reason.
  // Step is a stopped→running→stopped cycle just like continue — bump
  // <gen> regardless of whether the step landed at a new PC. The
  // register digest will reflect any actual state change on the next
  // snapshot_for_target call.
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    bump_live_gen_locked(impl_->live_state[tid]);
  }
  return snapshot(proc);
}

// ---------------------------------------------------------------------------
// Reverse execution (rr-backed)
// ---------------------------------------------------------------------------
//
// LLDB exposes no SBProcess::ReverseContinue / ReverseStep API and ships
// no `process reverse-continue` CLI command. The only path through SBAPI
// is the gdb-remote plugin's `process plugin packet send <packet>` CLI,
// which forwards a raw RSP packet to the active process. rr's gdbserver
// implements `bc` (reverse-continue) and `bs` (reverse-step, one
// instruction); we send those and then pump the listener for the next
// stop event, mirroring connect_remote_target's pattern.

namespace {

// Send a raw GDB RSP packet through `process plugin packet send`.
// Stdout is silenced around the call because the gdb-remote plugin
// occasionally writes diagnostics to C stdio that would corrupt the
// JSON-RPC channel (same dup2 pattern as save_core / connect_remote_target).
lldb::SBCommandReturnObject
run_packet_send(lldb::SBDebugger& debugger, lldb::SBTarget& target,
                const std::string& packet) {
  debugger.SetSelectedTarget(target);

  int saved_stdout = ::dup(STDOUT_FILENO);
  int devnull      = ::open("/dev/null", O_WRONLY);
  if (saved_stdout >= 0 && devnull >= 0) {
    ::dup2(devnull, STDOUT_FILENO);
    ::close(devnull);
  }

  std::string cmd = "process plugin packet send " + packet;
  lldb::SBCommandReturnObject ro;
  debugger.GetCommandInterpreter().HandleCommand(cmd.c_str(), ro,
                                                  /*add_to_history=*/false);

  if (saved_stdout >= 0) {
    ::dup2(saved_stdout, STDOUT_FILENO);
    ::close(saved_stdout);
  }
  return ro;
}

// After `bc`/`bs` the gdb-remote plugin returns ~immediately but rr's
// stop reply arrives asynchronously on the listener. Pump events until
// the SBProcess state reflects the stop, or `timeout` elapses.
void pump_until_stopped(lldb::SBDebugger& debugger, lldb::SBProcess& proc,
                        std::chrono::seconds timeout) {
  lldb::SBListener listener = debugger.GetListener();
  using clock = std::chrono::steady_clock;
  const auto deadline = clock::now() + timeout;
  while (clock::now() < deadline) {
    auto cur = proc.GetState();
    if (cur != lldb::eStateInvalid && cur != lldb::eStateRunning &&
        cur != lldb::eStateStepping) {
      break;
    }
    lldb::SBEvent ev;
    listener.WaitForEvent(/*num_seconds=*/1u, ev);
    if (ev.IsValid() && lldb::SBProcess::EventIsProcessEvent(ev)) {
      (void)lldb::SBProcess::GetStateFromEvent(ev);
    }
  }
}

}  // namespace

ProcessStatus LldbBackend::reverse_continue(TargetId tid) {
  lldb::SBTarget target;
  bool capable = false;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) throw Error("unknown target_id");
    target = it->second;
    auto rit = impl_->reverse_capable.find(tid);
    capable = (rit != impl_->reverse_capable.end()) && rit->second;
  }

  auto proc = target.GetProcess();
  if (!proc.IsValid()) throw Error("no process");
  auto st = proc.GetState();
  if (st != lldb::eStateStopped && st != lldb::eStateSuspended) {
    throw Error("process is not stopped; cannot reverse-continue");
  }
  if (!capable) {
    throw Error("target does not support reverse execution "
                "(connect via rr:// to a record/replay trace)");
  }

  auto ro = run_packet_send(impl_->debugger, target, "bc");
  if (!ro.Succeeded()) {
    const char* err = ro.GetError();
    throw Error(std::string("reverse-continue packet failed: ") +
                (err ? err : "unknown error"));
  }

  pump_until_stopped(impl_->debugger, proc, std::chrono::seconds(5));

  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    bump_live_gen_locked(impl_->live_state[tid]);
  }
  return snapshot(proc);
}

namespace {

// Capture the "starting position" we'll compare against in the
// reverse-step loop: source file+line and depth of the call stack.
// Stripped or JIT-only code yields empty file/line; the loop falls
// back to insn-level termination in that case.
struct StepStart {
  std::string  file;
  std::uint32_t line  = 0;
  std::uint32_t depth = 0;
};

StepStart capture_step_start(lldb::SBThread& thr) {
  StepStart s;
  s.depth = thr.GetNumFrames();
  auto frame = thr.GetFrameAtIndex(0);
  if (frame.IsValid()) {
    auto le = frame.GetLineEntry();
    if (le.IsValid()) {
      s.line = le.GetLine();
      auto fs = le.GetFileSpec();
      const char* fn = fs.GetFilename();
      if (fn) s.file = fn;
    }
  }
  return s;
}

// Termination predicate per kind. Returns true iff the current
// (thread, frame) state satisfies the reverse-step goal.
//   kIn   : any source-line change is fine (we may have descended
//           into a callee — that's exactly what "step into reversed"
//           means).
//   kOver : line changed AND we're at the same depth or shallower
//           (we don't accept landing deeper, since that would mean
//           we entered a callee).
//   kOut  : we're at a shallower depth than start (we've escaped the
//           starting frame).
//   kInsn : the caller already returned after one `bs`; not used in
//           the loop.
bool step_terminates(lldb::SBThread& thr, const StepStart& start,
                     ldb::backend::ReverseStepKind kind) {
  std::uint32_t depth = thr.GetNumFrames();
  auto frame = thr.GetFrameAtIndex(0);
  std::string file;
  std::uint32_t line = 0;
  if (frame.IsValid()) {
    auto le = frame.GetLineEntry();
    if (le.IsValid()) {
      line = le.GetLine();
      auto fs = le.GetFileSpec();
      const char* fn = fs.GetFilename();
      if (fn) file = fn;
    }
  }
  bool line_changed = (line != start.line) || (file != start.file);
  switch (kind) {
    case ldb::backend::ReverseStepKind::kIn:
      return line_changed;
    case ldb::backend::ReverseStepKind::kOver:
      return line_changed && depth <= start.depth;
    case ldb::backend::ReverseStepKind::kOut:
      return depth < start.depth;
    case ldb::backend::ReverseStepKind::kInsn:
      return true;
  }
  return true;
}

// How many `bs` packets we'll send for a single kind=in/over/out call
// before giving up. 256 is enough to cross any source line we've ever
// observed (longest single-line block in real code is rarely > 50
// instructions) while bounding the worst case to ~5s of round-trips.
constexpr int kReverseStepMaxIters = 256;

}  // namespace

ProcessStatus LldbBackend::reverse_step_thread(TargetId tid,
                                                ThreadId thread_id,
                                                ReverseStepKind kind) {
  lldb::SBTarget target;
  bool capable = false;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) throw Error("unknown target_id");
    target = it->second;
    auto rit = impl_->reverse_capable.find(tid);
    capable = (rit != impl_->reverse_capable.end()) && rit->second;
  }

  auto proc = target.GetProcess();
  if (!proc.IsValid()) throw Error("no process");
  auto st = proc.GetState();
  if (st != lldb::eStateStopped && st != lldb::eStateSuspended) {
    throw Error("process is not stopped; cannot reverse-step");
  }
  if (!capable) {
    throw Error("target does not support reverse execution "
                "(connect via rr:// to a record/replay trace)");
  }
  auto thr = proc.GetThreadByID(thread_id);
  if (!thr.IsValid()) throw Error("unknown thread id");

  // rr's gdbserver uses the selected thread for the `bs` packet; LLDB
  // tracks selection per-process.
  proc.SetSelectedThreadByID(thread_id);

  if (kind == ReverseStepKind::kInsn) {
    auto ro = run_packet_send(impl_->debugger, target, "bs");
    if (!ro.Succeeded()) {
      const char* err = ro.GetError();
      throw Error(std::string("reverse-step packet failed: ") +
                  (err ? err : "unknown error"));
    }
    pump_until_stopped(impl_->debugger, proc, std::chrono::seconds(5));
  } else {
    // Source-line-granularity emulation per docs/16-reverse-exec.md
    // §"Reverse-step-over/into": send `bs` in a bounded loop, checking
    // a kind-specific termination predicate after each step. Less
    // accurate than LLDB's forward ThreadPlan stack but adequate for
    // the most common case (single-frame reverse stepping in
    // unoptimised code).
    StepStart start = capture_step_start(thr);
    for (int i = 0; i < kReverseStepMaxIters; ++i) {
      auto ro = run_packet_send(impl_->debugger, target, "bs");
      if (!ro.Succeeded()) {
        const char* err = ro.GetError();
        throw Error(std::string("reverse-step packet failed: ") +
                    (err ? err : "unknown error"));
      }
      pump_until_stopped(impl_->debugger, proc, std::chrono::seconds(5));

      auto cur_thr = proc.GetThreadByID(thread_id);
      if (!cur_thr.IsValid()) break;  // exited / vanished
      if (step_terminates(cur_thr, start, kind)) break;
    }
    // If we hit the iteration cap, fall through: snapshot whatever
    // state we ended on. The agent can observe the still-unchanged PC
    // / line and decide to retry or escalate.
  }

  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    bump_live_gen_locked(impl_->live_state[tid]);
  }
  return snapshot(proc);
}

// ---------------------------------------------------------------------------
// Frame values: locals / args / registers
// ---------------------------------------------------------------------------

namespace {

ValueInfo to_value_info(lldb::SBValue v, const char* kind) {
  ValueInfo out;

  if (const char* nm = v.GetName()) out.name = nm;
  if (const char* tn = v.GetTypeName()) {
    out.type = tn;
  } else {
    out.type = "<unknown>";
  }

  lldb::addr_t addr = v.GetLoadAddress();
  if (addr != LLDB_INVALID_ADDRESS) {
    out.address = static_cast<std::uint64_t>(addr);
  }

  // Best-effort byte snapshot. SBValue::GetData returns a copy of the
  // value's bytes (regardless of where it lives). Cap at kValueByteCap.
  lldb::SBError err;
  auto data = v.GetData();
  if (data.IsValid()) {
    size_t avail = data.GetByteSize();
    if (avail > 0) {
      size_t want = std::min<size_t>(avail, kValueByteCap);
      std::vector<std::uint8_t> buf(want);
      size_t got = data.ReadRawData(err, /*offset=*/0, buf.data(), want);
      if (!err.Fail() && got > 0) {
        buf.resize(got);
        out.bytes = std::move(buf);
      }
    }
  }

  if (const char* sm = v.GetSummary()) {
    out.summary = sm;
  } else if (const char* val = v.GetValue()) {
    out.summary = val;
  }

  if (kind) out.kind = kind;
  return out;
}

std::vector<ValueInfo>
collect_variables(lldb::SBFrame frame, bool args, bool locals,
                  const char* kind) {
  // GetVariables(arguments, locals, statics, in_scope_only)
  auto values = frame.GetVariables(args, locals,
                                   /*statics=*/false,
                                   /*in_scope_only=*/true);
  std::vector<ValueInfo> out;
  uint32_t n = values.GetSize();
  out.reserve(n);
  for (uint32_t i = 0; i < n; ++i) {
    auto v = values.GetValueAtIndex(i);
    if (v.IsValid()) out.push_back(to_value_info(v, kind));
  }
  return out;
}

}  // namespace

namespace {

// Body shared by list_locals / list_args / list_registers: resolve
// (target, thread, frame) → SBFrame, throwing typed errors on misses.
lldb::SBFrame resolve_frame_locked(
    std::unordered_map<TargetId, lldb::SBTarget>& targets,
    std::mutex& mu, TargetId tid, ThreadId thread_id,
    std::uint32_t frame_index) {
  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(mu);
    auto it = targets.find(tid);
    if (it == targets.end()) {
      throw Error("unknown target_id");
    }
    target = it->second;
  }
  auto proc = target.GetProcess();
  if (!proc.IsValid()) throw Error("no process");
  auto thr = proc.GetThreadByID(thread_id);
  if (!thr.IsValid()) throw Error("unknown thread id");
  if (frame_index >= thr.GetNumFrames()) {
    throw Error("frame index out of range");
  }
  auto frame = thr.GetFrameAtIndex(frame_index);
  if (!frame.IsValid()) throw Error("invalid frame");
  return frame;
}

}  // namespace

std::vector<ValueInfo>
LldbBackend::list_locals(TargetId tid, ThreadId thread_id,
                         std::uint32_t frame_index) {
  auto frame = resolve_frame_locked(impl_->targets, impl_->mu,
                                    tid, thread_id, frame_index);
  return collect_variables(frame, /*args=*/false, /*locals=*/true, "local");
}

std::vector<ValueInfo>
LldbBackend::list_args(TargetId tid, ThreadId thread_id,
                       std::uint32_t frame_index) {
  auto frame = resolve_frame_locked(impl_->targets, impl_->mu,
                                    tid, thread_id, frame_index);
  return collect_variables(frame, /*args=*/true, /*locals=*/false, "arg");
}

std::vector<ValueInfo>
LldbBackend::list_registers(TargetId tid, ThreadId thread_id,
                            std::uint32_t frame_index) {
  auto frame = resolve_frame_locked(impl_->targets, impl_->mu,
                                    tid, thread_id, frame_index);

  // Registers are exposed as a list of register sets (GPR, FPR, vector,
  // exception). Flatten into one vector — agents project via view.fields.
  auto sets = frame.GetRegisters();
  std::vector<ValueInfo> out;
  uint32_t ns = sets.GetSize();
  for (uint32_t i = 0; i < ns; ++i) {
    auto set = sets.GetValueAtIndex(i);
    if (!set.IsValid()) continue;
    uint32_t nr = set.GetNumChildren();
    for (uint32_t j = 0; j < nr; ++j) {
      auto reg = set.GetChildAtIndex(j);
      if (reg.IsValid()) out.push_back(to_value_info(reg, "register"));
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Expression eval (value.eval) and typed path read (value.read)
// ---------------------------------------------------------------------------

namespace {

// Build SBExpressionOptions from our EvalOptions. The non-default flags
// matter: SetTryAllThreads(false) prevents the JIT from running other
// threads to satisfy a function call inside the expression — that's a
// silent side effect we don't want. SetIgnoreBreakpoints(true) keeps
// the eval from triggering a probe and re-entering the dispatcher.
lldb::SBExpressionOptions make_expr_options(const EvalOptions& o) {
  lldb::SBExpressionOptions sbo;
  sbo.SetTimeoutInMicroSeconds(static_cast<uint32_t>(
      std::min<std::uint64_t>(o.timeout_us,
                              std::numeric_limits<std::uint32_t>::max())));
  sbo.SetIgnoreBreakpoints(true);
  sbo.SetTryAllThreads(false);
  sbo.SetUnwindOnError(true);
  return sbo;
}

// Tokenize a value path like "g_arr[2].name.sub[0]" into its sequence
// of accessors. Returns nullopt on malformed input, with `err` filled
// in. Empty input is malformed.
struct PathToken {
  enum class Kind { kIdent, kField, kIndex };
  Kind          kind = Kind::kIdent;
  std::string   name;   // for kIdent / kField
  std::uint32_t index = 0;  // for kIndex
};

bool parse_value_path(const std::string& path,
                      std::vector<PathToken>& out, std::string& err) {
  out.clear();
  if (path.empty()) {
    err = "empty path";
    return false;
  }
  std::size_t i = 0, n = path.size();
  auto is_ident_start = [](char c) {
    return (c == '_') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
  };
  auto is_ident_cont = [&](char c) {
    return is_ident_start(c) || (c >= '0' && c <= '9');
  };

  // Leading identifier.
  if (!is_ident_start(path[i])) {
    err = "path must start with identifier";
    return false;
  }
  std::size_t j = i;
  while (j < n && is_ident_cont(path[j])) ++j;
  PathToken root;
  root.kind = PathToken::Kind::kIdent;
  root.name = path.substr(i, j - i);
  out.push_back(std::move(root));
  i = j;

  // Trailing accessors.
  while (i < n) {
    if (path[i] == '.') {
      ++i;
      if (i >= n || !is_ident_start(path[i])) {
        err = "expected field name after '.'";
        return false;
      }
      j = i;
      while (j < n && is_ident_cont(path[j])) ++j;
      PathToken t;
      t.kind = PathToken::Kind::kField;
      t.name = path.substr(i, j - i);
      out.push_back(std::move(t));
      i = j;
    } else if (path[i] == '[') {
      ++i;
      if (i >= n || path[i] < '0' || path[i] > '9') {
        err = "expected unsigned integer after '['";
        return false;
      }
      std::uint64_t v = 0;
      while (i < n && path[i] >= '0' && path[i] <= '9') {
        v = v * 10 + static_cast<std::uint64_t>(path[i] - '0');
        if (v > std::numeric_limits<std::uint32_t>::max()) {
          err = "array index too large";
          return false;
        }
        ++i;
      }
      if (i >= n || path[i] != ']') {
        err = "missing closing ']'";
        return false;
      }
      ++i;
      PathToken t;
      t.kind = PathToken::Kind::kIndex;
      t.index = static_cast<std::uint32_t>(v);
      out.push_back(std::move(t));
    } else {
      err = std::string("unexpected character '") + path[i] +
            "' in path";
      return false;
    }
  }
  return true;
}

// Resolve the leftmost identifier of a path against a frame. Tries
// frame-local lookup first (FindVariable for locals/args; FindValue
// for globals visible from the frame's CU), then falls back to a
// target-wide global search across all modules. The fallback matters
// when stop-at-entry leaves the innermost frame in `_dyld_start`,
// where the main module's globals are out of frame scope but still
// fully described by DWARF and reachable via the target.
lldb::SBValue resolve_root_identifier(lldb::SBFrame frame,
                                      const std::string& name) {
  auto v = frame.FindVariable(name.c_str());
  if (v.IsValid()) return v;
  v = frame.FindValue(name.c_str(), lldb::eValueTypeVariableGlobal);
  if (v.IsValid()) return v;
  v = frame.FindValue(name.c_str(), lldb::eValueTypeVariableStatic);
  if (v.IsValid()) return v;

  // Fallback: target-wide global search. SBTarget::FindGlobalVariables
  // walks every module's debug info; first match wins.
  auto target = frame.GetThread().GetProcess().GetTarget();
  auto vlist = target.FindGlobalVariables(name.c_str(), /*max_matches=*/1);
  if (vlist.GetSize() > 0) {
    auto g = vlist.GetValueAtIndex(0);
    if (g.IsValid()) return g;
  }
  return lldb::SBValue();
}

// Walk children for the immediate level. Skips synthetic / invalid.
std::vector<ValueInfo> collect_immediate_children(lldb::SBValue v) {
  std::vector<ValueInfo> out;
  uint32_t n = v.GetNumChildren();
  out.reserve(n);
  for (uint32_t i = 0; i < n; ++i) {
    auto c = v.GetChildAtIndex(i);
    if (c.IsValid()) out.push_back(to_value_info(c, nullptr));
  }
  return out;
}

}  // namespace

EvalResult
LldbBackend::evaluate_expression(TargetId tid, ThreadId thread_id,
                                 std::uint32_t frame_index,
                                 const std::string& expr,
                                 const EvalOptions& opts) {
  auto frame = resolve_frame_locked(impl_->targets, impl_->mu,
                                    tid, thread_id, frame_index);

  EvalResult result;
  auto sbo = make_expr_options(opts);

  // SBFrame::EvaluateExpression occasionally writes diagnostics to
  // stdout (e.g. "<expr> contained errors"); ldbd reserves stdout for
  // JSON-RPC, so redirect around the call. Same pattern as save_core.
  int saved_stdout = ::dup(STDOUT_FILENO);
  int devnull      = ::open("/dev/null", O_WRONLY);
  if (saved_stdout >= 0 && devnull >= 0) {
    ::dup2(devnull, STDOUT_FILENO);
    ::close(devnull);
  }

  lldb::SBValue v = frame.EvaluateExpression(expr.c_str(), sbo);

  if (saved_stdout >= 0) {
    ::dup2(saved_stdout, STDOUT_FILENO);
    ::close(saved_stdout);
  }

  // SBValue carries the eval error via GetError(). Note that
  // IsValid() may still be true on a soft error (e.g. timeout returns
  // an error-bearing value), so we always check the error first.
  lldb::SBError err = v.GetError();
  if (err.Fail()) {
    result.ok    = false;
    result.error = err.GetCString() ? err.GetCString() : "evaluation failed";
    return result;
  }
  if (!v.IsValid()) {
    result.ok    = false;
    result.error = "evaluation produced no value";
    return result;
  }

  result.ok    = true;
  result.value = to_value_info(v, "eval");
  return result;
}

ReadResult
LldbBackend::read_value_path(TargetId tid, ThreadId thread_id,
                             std::uint32_t frame_index,
                             const std::string& path) {
  auto frame = resolve_frame_locked(impl_->targets, impl_->mu,
                                    tid, thread_id, frame_index);

  ReadResult result;
  std::vector<PathToken> tokens;
  std::string parse_err;
  if (!parse_value_path(path, tokens, parse_err)) {
    result.ok    = false;
    result.error = "malformed path: " + parse_err;
    return result;
  }

  // Token 0 is always an identifier (parser enforces).
  lldb::SBValue cur = resolve_root_identifier(frame, tokens[0].name);
  if (!cur.IsValid()) {
    result.ok    = false;
    result.error = "unknown identifier: " + tokens[0].name;
    return result;
  }

  for (std::size_t i = 1; i < tokens.size(); ++i) {
    const auto& t = tokens[i];
    lldb::SBValue next;
    if (t.kind == PathToken::Kind::kField) {
      next = cur.GetChildMemberWithName(t.name.c_str());
      if (!next.IsValid()) {
        result.ok    = false;
        result.error = "no member '" + t.name + "' on value of type '" +
                       (cur.GetTypeName() ? cur.GetTypeName() : "<unknown>") +
                       "'";
        return result;
      }
    } else if (t.kind == PathToken::Kind::kIndex) {
      // GetChildAtIndex with synthetic_allowed=true so pointer-to-array
      // expressions and SBValueObject synthetic providers (vector<T>,
      // etc.) walk uniformly.
      next = cur.GetChildAtIndex(t.index, lldb::eDynamicCanRunTarget,
                                 /*can_create_synthetic=*/true);
      if (!next.IsValid()) {
        result.ok    = false;
        result.error = "index " + std::to_string(t.index) +
                       " out of range for value of type '" +
                       (cur.GetTypeName() ? cur.GetTypeName() : "<unknown>") +
                       "'";
        return result;
      }
    } else {
      // Defensive — parser only emits kField / kIndex after token 0.
      result.ok    = false;
      result.error = "internal: unexpected token kind";
      return result;
    }
    cur = next;
  }

  result.ok       = true;
  result.value    = to_value_info(cur, nullptr);
  result.children = collect_immediate_children(cur);
  return result;
}

// ---------------------------------------------------------------------------
// Memory primitives
// ---------------------------------------------------------------------------

namespace {

lldb::SBProcess require_process_locked(
    std::unordered_map<TargetId, lldb::SBTarget>& targets,
    std::mutex& mu, TargetId tid) {
  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(mu);
    auto it = targets.find(tid);
    if (it == targets.end()) throw Error("unknown target_id");
    target = it->second;
  }
  auto proc = target.GetProcess();
  if (!proc.IsValid()) throw Error("no process");
  return proc;
}

}  // namespace

std::vector<std::uint8_t>
LldbBackend::read_memory(TargetId tid, std::uint64_t addr,
                         std::uint64_t size) {
  if (size > DebuggerBackend::kMemReadMax) {
    throw Error("read_memory: size exceeds 1 MiB cap");
  }
  auto proc = require_process_locked(impl_->targets, impl_->mu, tid);
  std::vector<std::uint8_t> out(static_cast<std::size_t>(size));
  if (size == 0) return out;

  lldb::SBError err;
  size_t got = proc.ReadMemory(static_cast<lldb::addr_t>(addr),
                               out.data(), out.size(), err);
  if (err.Fail()) {
    throw Error(std::string("ReadMemory failed: ") +
                (err.GetCString() ? err.GetCString() : "unknown"));
  }
  out.resize(got);
  return out;
}

std::string
LldbBackend::read_cstring(TargetId tid, std::uint64_t addr,
                          std::uint32_t max_len) {
  if (max_len == 0) max_len = DebuggerBackend::kMemCstrDefault;
  auto proc = require_process_locked(impl_->targets, impl_->mu, tid);

  std::string out;
  // Chunked read so we don't pull a whole megabyte for a 16-byte string.
  constexpr std::size_t kChunk = 256;
  std::vector<std::uint8_t> buf(kChunk);
  std::uint64_t cur = addr;
  while (out.size() < max_len) {
    std::size_t want = std::min<std::size_t>(kChunk, max_len - out.size());
    lldb::SBError err;
    std::size_t got = proc.ReadMemory(static_cast<lldb::addr_t>(cur),
                                      buf.data(), want, err);
    if (err.Fail() || got == 0) break;
    for (std::size_t i = 0; i < got; ++i) {
      if (buf[i] == '\0') return out;
      out.push_back(static_cast<char>(buf[i]));
      if (out.size() >= max_len) return out;
    }
    cur += got;
  }
  return out;
}

std::vector<MemoryRegion>
LldbBackend::list_regions(TargetId tid) {
  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) throw Error("unknown target_id");
    target = it->second;
  }
  auto proc = target.GetProcess();
  if (!proc.IsValid()) return {};

  lldb::SBMemoryRegionInfoList list = proc.GetMemoryRegions();
  std::vector<MemoryRegion> out;
  uint32_t n = list.GetSize();
  out.reserve(n);
  for (uint32_t i = 0; i < n; ++i) {
    lldb::SBMemoryRegionInfo info;
    if (!list.GetMemoryRegionAtIndex(i, info)) continue;
    MemoryRegion r;
    r.base       = info.GetRegionBase();
    r.size       = info.GetRegionEnd() - info.GetRegionBase();
    r.readable   = info.IsReadable();
    r.writable   = info.IsWritable();
    r.executable = info.IsExecutable();
    if (const char* nm = info.GetName(); nm && *nm) r.name = nm;
    out.push_back(std::move(r));
  }
  // Stable ordering (audit §3.7 / R4): sort by base address ascending.
  // /proc/maps is already sorted on Linux but LLDB's enumeration on
  // remote / non-Linux backends isn't guaranteed.
  std::sort(out.begin(), out.end(),
            [](const MemoryRegion& a, const MemoryRegion& b) {
              return a.base < b.base;
            });
  return out;
}

namespace {

// Find every occurrence of [needle] within [haystack]. Naive scan; the
// inputs are bounded by kMemSearchMax / region size, so even an O(NM)
// search runs within milliseconds in practice.
void find_all(const std::uint8_t* haystack, std::size_t n,
              const std::uint8_t* needle,   std::size_t m,
              std::uint64_t base_addr,
              std::vector<MemorySearchHit>& out, std::uint32_t cap) {
  if (m == 0 || m > n) return;
  for (std::size_t i = 0; i + m <= n && out.size() < cap; ++i) {
    if (std::memcmp(haystack + i, needle, m) == 0) {
      MemorySearchHit h;
      h.address = base_addr + static_cast<std::uint64_t>(i);
      out.push_back(h);
    }
  }
}

}  // namespace

std::vector<MemorySearchHit>
LldbBackend::search_memory(TargetId tid, std::uint64_t start,
                           std::uint64_t length,
                           const std::vector<std::uint8_t>& needle,
                           std::uint32_t max_hits) {
  if (length > DebuggerBackend::kMemSearchMax) {
    throw Error("search_memory: length exceeds 256 MiB cap");
  }
  if (needle.empty()) return {};
  if (max_hits == 0 || max_hits > DebuggerBackend::kMemSearchHitCap) {
    max_hits = DebuggerBackend::kMemSearchHitCap;
  }

  // Build the list of (base, length) ranges to scan. If the caller
  // passed length>0 we use exactly that; otherwise enumerate readable
  // regions and intersect with kMemSearchMax to bound the total scan.
  struct Range { std::uint64_t base; std::uint64_t len; };
  std::vector<Range> ranges;
  if (length > 0) {
    ranges.push_back({start, length});
  } else {
    auto regions = list_regions(tid);
    std::uint64_t budget = DebuggerBackend::kMemSearchMax;
    for (const auto& r : regions) {
      if (!r.readable || r.size == 0) continue;
      if (budget == 0) break;
      std::uint64_t take = std::min<std::uint64_t>(r.size, budget);
      ranges.push_back({r.base, take});
      budget -= take;
    }
  }

  auto proc = require_process_locked(impl_->targets, impl_->mu, tid);
  std::vector<MemorySearchHit> hits;
  hits.reserve(std::min<std::uint32_t>(64, max_hits));

  // Read in 8 MiB chunks with a (needle-1)-byte overlap so a hit
  // straddling a chunk boundary still gets caught.
  constexpr std::uint64_t kChunkSize = 8 * 1024 * 1024;
  std::vector<std::uint8_t> buf;
  for (const auto& r : ranges) {
    if (hits.size() >= max_hits) break;
    std::uint64_t cur = r.base;
    std::uint64_t remaining = r.len;
    std::uint64_t overlap = (needle.size() > 0) ? needle.size() - 1 : 0;
    while (remaining > 0 && hits.size() < max_hits) {
      std::uint64_t want = std::min(remaining, kChunkSize);
      buf.assign(static_cast<std::size_t>(want), 0);
      lldb::SBError err;
      std::size_t got = proc.ReadMemory(
          static_cast<lldb::addr_t>(cur), buf.data(), buf.size(), err);
      if (err.Fail() || got == 0) {
        // Skip unreadable region tail; advance and retry.
        if (remaining <= kChunkSize) break;
        cur       += kChunkSize;
        remaining -= kChunkSize;
        continue;
      }
      find_all(buf.data(), got, needle.data(), needle.size(),
               cur, hits, max_hits);
      if (got <= overlap || got == remaining) break;
      cur       += got - overlap;
      remaining -= got - overlap;
    }
  }
  return hits;
}

// ---------------------------------------------------------------------------
// Breakpoints (M3 probes)
// ---------------------------------------------------------------------------

namespace {

// Trampoline invoked by LLDB on its process-event thread. We look up
// the registered (callback, baton) for this (target, bp_id), build the
// typed CallbackArgs, and dispatch. Returning true from this function
// keeps the inferior stopped; false auto-continues. If no callback is
// registered (e.g. mid-tear-down), default to false (auto-continue) so
// the inferior doesn't get stuck.
bool lldb_breakpoint_trampoline(void* baton,
                                lldb::SBProcess& proc,
                                lldb::SBThread& thr,
                                lldb::SBBreakpointLocation& bp_loc) {
  auto* shim = static_cast<LldbBreakpointCb*>(baton);
  if (!shim || !shim->cb) return false;

  BreakpointCallbackArgs args;
  args.target_id = shim->target_id;
  args.tid       = thr.IsValid() ? thr.GetThreadID() : 0;

  if (thr.IsValid() && thr.GetNumFrames() > 0) {
    auto frame = thr.GetFrameAtIndex(0);
    if (frame.IsValid()) {
      args.pc = frame.GetPC();
      if (auto fn = frame.GetFunction(); fn.IsValid()) {
        if (const char* nm = fn.GetName()) args.function = nm;
      }
      if (args.function.empty()) {
        if (auto sym = frame.GetSymbol(); sym.IsValid()) {
          if (const char* nm = sym.GetName()) args.function = nm;
        }
      }
      if (auto le = frame.GetLineEntry(); le.IsValid()) {
        auto fs = le.GetFileSpec();
        if (fs.IsValid()) {
          char buf[4096];
          if (fs.GetPath(buf, sizeof(buf)) > 0) args.file = buf;
        }
        args.line = static_cast<int>(le.GetLine());
      }
    }
  }

  // Defensive: if the registered callback throws, don't propagate
  // through C-linkage LLDB code (UB). Log and auto-continue.
  try {
    return shim->cb(shim->baton, args);
  } catch (const std::exception& e) {
    log::warn(std::string("breakpoint callback threw: ") + e.what());
    return false;
  } catch (...) {
    log::warn("breakpoint callback threw unknown exception");
    return false;
  }
  // Touch unused params to silence -Wunused-parameter on some toolchains.
  (void)proc; (void)bp_loc;
}

}  // namespace

BreakpointHandle
LldbBackend::create_breakpoint(TargetId tid, const BreakpointSpec& spec) {
  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) {
      throw Error("unknown target_id");
    }
    target = it->second;
  }

  if (!spec.function.has_value() && !spec.address.has_value() &&
      !spec.file.has_value()) {
    throw Error("create_breakpoint: spec must set function, address, or file+line");
  }

  lldb::SBBreakpoint bp;
  if (spec.function.has_value()) {
    bp = target.BreakpointCreateByName(spec.function->c_str());
  } else if (spec.address.has_value()) {
    bp = target.BreakpointCreateByAddress(
        static_cast<lldb::addr_t>(*spec.address));
  } else {
    if (!spec.line.has_value() || *spec.line <= 0) {
      throw Error("create_breakpoint: file form requires positive 'line'");
    }
    bp = target.BreakpointCreateByLocation(
        spec.file->c_str(), static_cast<std::uint32_t>(*spec.line));
  }

  if (!bp.IsValid() || bp.GetID() == LLDB_INVALID_BREAK_ID) {
    throw Error("create_breakpoint: LLDB rejected the spec");
  }

  BreakpointHandle h;
  h.bp_id     = static_cast<std::int32_t>(bp.GetID());
  h.locations = static_cast<std::uint32_t>(bp.GetNumLocations());
  return h;
}

void LldbBackend::set_breakpoint_callback(TargetId tid, std::int32_t bp_id,
                                          BreakpointCallback cb,
                                          void* baton) {
  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) throw Error("unknown target_id");
    target = it->second;
  }
  auto bp = target.FindBreakpointByID(bp_id);
  if (!bp.IsValid()) throw Error("set_breakpoint_callback: unknown bp_id");

  // Build / replace the registry record. We keep it in shared_ptr so
  // the trampoline's raw pointer baton stays valid even if a future
  // contract violation re-races a delete; for now the orchestrator
  // guarantees disable+drain before delete.
  auto rec = std::make_shared<LldbBreakpointCb>();
  rec->target_id = tid;
  rec->bp_id     = bp_id;
  rec->cb        = std::move(cb);
  rec->baton     = baton;

  {
    std::lock_guard<std::mutex> lk(impl_->cb_mu);
    impl_->bp_callbacks[{tid, bp_id}] = rec;
  }

  bp.SetCallback(&lldb_breakpoint_trampoline, rec.get());
}

void LldbBackend::disable_breakpoint(TargetId tid, std::int32_t bp_id) {
  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) throw Error("unknown target_id");
    target = it->second;
  }
  auto bp = target.FindBreakpointByID(bp_id);
  if (!bp.IsValid()) throw Error("disable_breakpoint: unknown bp_id");
  bp.SetEnabled(false);
}

void LldbBackend::enable_breakpoint(TargetId tid, std::int32_t bp_id) {
  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) throw Error("unknown target_id");
    target = it->second;
  }
  auto bp = target.FindBreakpointByID(bp_id);
  if (!bp.IsValid()) throw Error("enable_breakpoint: unknown bp_id");
  bp.SetEnabled(true);
}

void LldbBackend::delete_breakpoint(TargetId tid, std::int32_t bp_id) {
  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) throw Error("unknown target_id");
    target = it->second;
  }
  // Drop the callback first so any racing event can't dereference a
  // soon-to-be-deleted breakpoint's baton. SBBreakpoint::SetCallback
  // with a nullptr fn unhooks LLDB's side. The contract is "orchestrator
  // already disabled + drained" — this is belt-and-braces.
  auto bp = target.FindBreakpointByID(bp_id);
  if (bp.IsValid()) {
    bp.SetCallback(nullptr, nullptr);
  }
  {
    std::lock_guard<std::mutex> lk(impl_->cb_mu);
    impl_->bp_callbacks.erase({tid, bp_id});
  }
  if (bp.IsValid()) {
    target.BreakpointDelete(bp.GetID());
  }
}

std::uint64_t
LldbBackend::read_register(TargetId tid, ThreadId thread_id,
                           std::uint32_t frame_index,
                           const std::string& name) {
  // Reuse resolve_frame_locked for symmetry; it throws if anything's
  // off. Reads inside the breakpoint callback always pass frame_index=0
  // (innermost), but we accept arbitrary indexes for completeness.
  auto frame = resolve_frame_locked(impl_->targets, impl_->mu,
                                    tid, thread_id, frame_index);
  auto sets = frame.GetRegisters();
  uint32_t ns = sets.GetSize();
  for (uint32_t i = 0; i < ns; ++i) {
    auto set = sets.GetValueAtIndex(i);
    if (!set.IsValid()) continue;
    uint32_t nr = set.GetNumChildren();
    for (uint32_t j = 0; j < nr; ++j) {
      auto reg = set.GetChildAtIndex(j);
      if (!reg.IsValid()) continue;
      const char* rn = reg.GetName();
      if (!rn || name != rn) continue;
      lldb::SBError err;
      auto v = reg.GetValueAsUnsigned(err, /*fail_value=*/0);
      if (err.Fail()) return 0;
      return static_cast<std::uint64_t>(v);
    }
  }
  return 0;
}

// ---------------------------------------------------------------------------

void LldbBackend::close_target(TargetId tid) {
  lldb::SBTarget target;
  // Move the resources out under the lock; we'll drop them OUTSIDE the
  // lock so a long-running dtor (e.g. ssh teardown) doesn't block other
  // backend operations. Reverse-attach order matters when one handle
  // depends on another — pop_back in a loop is the cheap way.
  std::vector<std::unique_ptr<DebuggerBackend::TargetResource>> resources;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) return;
    target = it->second;
    impl_->targets.erase(it);
    if (auto rit = impl_->target_resources.find(tid);
        rit != impl_->target_resources.end()) {
      resources = std::move(rit->second);
      impl_->target_resources.erase(rit);
    }
    impl_->core_sha256.erase(tid);
    impl_->live_state.erase(tid);
    impl_->reverse_capable.erase(tid);
    impl_->chained_fixup_maps.erase(tid);
    impl_->chained_fixup_loaded.erase(tid);
    // §9 — drop the label so its string becomes available for reuse.
    if (auto lit = impl_->labels.find(tid); lit != impl_->labels.end()) {
      impl_->label_owners.erase(lit->second);
      impl_->labels.erase(lit);
    }
  }
  // Reap any breakpoint-callback records associated with this target.
  // The target's SBBreakpoints go away with DeleteTarget; the records
  // would leak otherwise. Same lock ordering as set_breakpoint_callback.
  {
    std::lock_guard<std::mutex> lk(impl_->cb_mu);
    for (auto it = impl_->bp_callbacks.begin();
         it != impl_->bp_callbacks.end(); ) {
      if (it->first.first == tid) it = impl_->bp_callbacks.erase(it);
      else ++it;
    }
  }
  impl_->debugger.DeleteTarget(target);
  // Drop resources in reverse-attach order. Tearing down LAST so the
  // SBTarget delete doesn't try to talk to a dead remote first.
  while (!resources.empty()) resources.pop_back();
}

// ---------------------------------------------------------------------------
// Tier 3 §9 — multi-binary inventory.

std::vector<TargetInfo> LldbBackend::list_targets() {
  // Snapshot the (id, target, label) tuples under the lock; query LLDB
  // for the per-target metadata (triple, executable path, has_process)
  // OUTSIDE the lock — those calls reach into LLDB and we'd rather not
  // hold `mu` across them.
  struct Pin {
    TargetId tid;
    lldb::SBTarget target;
    std::optional<std::string> label;
  };
  std::vector<Pin> pinned;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    pinned.reserve(impl_->targets.size());
    for (const auto& [tid, tgt] : impl_->targets) {
      Pin p{tid, tgt, std::nullopt};
      if (auto it = impl_->labels.find(tid); it != impl_->labels.end()) {
        p.label = it->second;
      }
      pinned.push_back(std::move(p));
    }
  }

  std::vector<TargetInfo> out;
  out.reserve(pinned.size());
  for (auto& p : pinned) {
    TargetInfo ti;
    ti.target_id = p.tid;
    ti.label     = std::move(p.label);
    if (p.target.IsValid()) {
      if (const char* tr = p.target.GetTriple()) ti.triple = tr;
      // Executable path via SBTarget::GetExecutable() → SBFileSpec.
      // Same shape as convert_module's path read; absent for empty /
      // core-only targets.
      auto file = p.target.GetExecutable();
      if (file.IsValid()) {
        char buf[4096];
        if (file.GetPath(buf, sizeof(buf)) > 0) ti.path = buf;
      }
      auto proc = p.target.GetProcess();
      if (proc.IsValid()) {
        auto state = proc.GetState();
        ti.has_process = state != lldb::eStateInvalid &&
                         state != lldb::eStateUnloaded &&
                         state != lldb::eStateExited &&
                         state != lldb::eStateDetached;
      }
    }
    out.push_back(std::move(ti));
  }
  // Stable order — sort by ascending target_id so the agent can rely on
  // a deterministic enumeration.
  std::sort(out.begin(), out.end(),
            [](const TargetInfo& a, const TargetInfo& b) {
              return a.target_id < b.target_id;
            });
  return out;
}

void LldbBackend::label_target(TargetId tid, std::string label) {
  if (label.empty()) {
    throw Error("label_target: label must be non-empty");
  }
  std::lock_guard<std::mutex> lk(impl_->mu);
  if (impl_->targets.find(tid) == impl_->targets.end()) {
    throw Error("label_target: unknown target_id");
  }
  // Conflict: label string already owned by someone else.
  if (auto own = impl_->label_owners.find(label);
      own != impl_->label_owners.end() && own->second != tid) {
    throw Error("label_target: label \"" + label +
                "\" already taken by target_id " +
                std::to_string(own->second));
  }
  // Same target re-labelling: free the old name first so the new one
  // can replace it cleanly.
  if (auto it = impl_->labels.find(tid); it != impl_->labels.end()) {
    if (it->second == label) return;  // self-relabel, no-op
    impl_->label_owners.erase(it->second);
    it->second = label;
    impl_->label_owners[label] = tid;
    return;
  }
  impl_->labels.emplace(tid, label);
  impl_->label_owners.emplace(std::move(label), tid);
}

std::optional<std::string> LldbBackend::get_target_label(TargetId tid) {
  std::lock_guard<std::mutex> lk(impl_->mu);
  if (auto it = impl_->labels.find(tid); it != impl_->labels.end()) {
    return it->second;
  }
  return std::nullopt;
}

namespace {

// Append a primitive value to the digest buffer in a fixed canonical
// form. The hash input is intentionally a contiguous byte stream — no
// separators between fields, just length-prefixed strings and
// little-endian fixed-width integers. This locks the encoding so a
// future LLDB change in iteration order or a register-name string
// can't silently shift the digest.
void hash_u64_le(util::Sha256& h, std::uint64_t v) {
  std::uint8_t buf[8];
  for (int i = 0; i < 8; ++i) buf[i] = static_cast<std::uint8_t>(v >> (8 * i));
  h.update(buf, sizeof(buf));
}

void hash_lp_string(util::Sha256& h, std::string_view s) {
  hash_u64_le(h, s.size());
  h.update(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
}

// Read a register's raw bytes via SBData. SBValue::GetData() requires a
// valid SBExecutionContext on some LLDB releases; on others the bare
// .GetData() works. We fall back to the textual GetValue() if the byte
// path is unavailable, which is what list_registers does for reporting.
std::vector<std::uint8_t> register_bytes(lldb::SBValue reg) {
  std::vector<std::uint8_t> out;
  if (!reg.IsValid()) return out;
  lldb::SBError err;
  auto data = reg.GetData();
  if (!data.IsValid()) {
    if (const char* sv = reg.GetValue()) {
      out.assign(reinterpret_cast<const std::uint8_t*>(sv),
                 reinterpret_cast<const std::uint8_t*>(sv + std::strlen(sv)));
    }
    return out;
  }
  std::size_t n = data.GetByteSize();
  if (n == 0) return out;
  // Cap per-register read at 1 KiB — far above any real GP register.
  if (n > 1024) n = 1024;
  out.resize(n);
  data.ReadRawData(err, /*offset=*/0, out.data(), n);
  if (err.Fail()) out.clear();
  return out;
}

// Compute the all-thread, all-GP-register digest. Threads are sorted
// by ascending kernel tid before hashing so the digest is invariant
// under LLDB's iteration order. Each thread contributes
//   <tid : u64 LE>
//   <num_registers : u64 LE>
//   for each register, sorted by name:
//     <name : LP string>
//     <byte length : u64 LE> <bytes>
std::string compute_reg_digest(lldb::SBProcess proc) {
  if (!proc.IsValid()) return std::string(64, '0');

  struct ThreadView {
    std::uint64_t tid = 0;
    lldb::SBThread thr;
  };
  std::vector<ThreadView> tviews;
  std::uint32_t nthreads = proc.GetNumThreads();
  tviews.reserve(nthreads);
  for (std::uint32_t i = 0; i < nthreads; ++i) {
    lldb::SBThread thr = proc.GetThreadAtIndex(i);
    if (!thr.IsValid()) continue;
    tviews.push_back({thr.GetThreadID(), thr});
  }
  std::sort(tviews.begin(), tviews.end(),
            [](const ThreadView& a, const ThreadView& b) {
              return a.tid < b.tid;
            });

  util::Sha256 h;
  hash_u64_le(h, tviews.size());
  for (auto& tv : tviews) {
    hash_u64_le(h, tv.tid);
    auto frame = tv.thr.GetFrameAtIndex(0);
    if (!frame.IsValid()) {
      hash_u64_le(h, 0);  // num_registers
      continue;
    }
    auto gpr_set = frame.GetRegisters().GetFirstValueByName(
        "General Purpose Registers");
    // Some platforms report the GPR set under a slightly different
    // name; fall back to "Generic Purpose Registers" / "Generic
    // Registers" / first set.
    if (!gpr_set.IsValid()) {
      auto sets = frame.GetRegisters();
      if (sets.GetSize() > 0) gpr_set = sets.GetValueAtIndex(0);
    }
    if (!gpr_set.IsValid()) {
      hash_u64_le(h, 0);
      continue;
    }
    // Collect regs into a name-sorted vector so the digest doesn't
    // depend on LLDB's set-internal child ordering.
    struct RegEntry {
      std::string name;
      std::vector<std::uint8_t> bytes;
    };
    std::vector<RegEntry> regs;
    std::uint32_t nr = gpr_set.GetNumChildren();
    regs.reserve(nr);
    for (std::uint32_t j = 0; j < nr; ++j) {
      auto reg = gpr_set.GetChildAtIndex(j);
      if (!reg.IsValid()) continue;
      const char* nm = reg.GetName();
      RegEntry e;
      e.name  = nm ? nm : "";
      e.bytes = register_bytes(reg);
      regs.push_back(std::move(e));
    }
    std::sort(regs.begin(), regs.end(),
              [](const RegEntry& a, const RegEntry& b) {
                return a.name < b.name;
              });
    hash_u64_le(h, regs.size());
    for (auto& r : regs) {
      hash_lp_string(h, r.name);
      hash_u64_le(h, r.bytes.size());
      h.update(r.bytes.data(), r.bytes.size());
    }
  }
  return util::sha256_hex(h.finalize());
}

// Compute the SW-breakpoint digest. Captures the set of inferior memory
// addresses currently patched with a 0xCC trap by an active
// `lldb_breakpoint`-engine probe. Sorted by address so the digest is
// invariant under LLDB's per-process bp iteration order.
//
// Each entry is
//   <load_address : u64 LE>  <patch_byte : u64 LE>
// — `patch_byte` is always 0xCC for SW breakpoints today, but we
// future-proof the canonicalisation by hashing it explicitly so a
// future hardware-watchpoint variant can extend the same digest with a
// different sentinel without colliding.
//
// Disabled breakpoints DON'T contribute (LLDB removes the patch when
// the bp is disabled — including a disabled bp would mean the digest
// doesn't match the inferior's actual .text bytes). Locations of a
// multi-location bp are each enumerated.
//
// This closes the slice-1c gap from the 1b reviewer: probe.create
// patches .text but the snapshot didn't reflect that, so two
// `mem.read` calls bracketing a probe.create would yield different
// bytes but identical snapshots.
std::string compute_bp_digest(lldb::SBTarget target) {
  if (!target.IsValid()) {
    // Empty-set sentinel: SHA-256 of u64-LE 0 (count=0). This is the
    // documented value; pinned by tests/unit/test_live_provenance_bp.cpp.
    util::Sha256 h;
    hash_u64_le(h, 0);
    return util::sha256_hex(h.finalize());
  }

  struct BpEntry {
    std::uint64_t addr  = 0;
    std::uint8_t  patch = 0xCC;  // SW-bp trap byte on x86; on arm64 it's
                                 // a different opcode, but we hash a
                                 // sentinel rather than the actual byte
                                 // because the canonical form is
                                 // arch-agnostic and the opcode-vs-trap
                                 // distinction lands on the agent side
                                 // via mem.read.
  };
  std::vector<BpEntry> entries;
  std::uint32_t n = target.GetNumBreakpoints();
  entries.reserve(n);
  for (std::uint32_t i = 0; i < n; ++i) {
    auto bp = target.GetBreakpointAtIndex(i);
    if (!bp.IsValid()) continue;
    if (!bp.IsEnabled()) continue;          // disabled → not patching
    std::size_t nloc = bp.GetNumLocations();
    for (std::size_t l = 0; l < nloc; ++l) {
      auto loc = bp.GetLocationAtIndex(static_cast<std::uint32_t>(l));
      if (!loc.IsValid() || !loc.IsEnabled()) continue;
      auto la = loc.GetLoadAddress();
      if (la == LLDB_INVALID_ADDRESS) continue;
      BpEntry e;
      e.addr  = static_cast<std::uint64_t>(la);
      e.patch = 0xCC;
      entries.push_back(e);
    }
  }
  std::sort(entries.begin(), entries.end(),
            [](const BpEntry& a, const BpEntry& b) {
              if (a.addr != b.addr) return a.addr < b.addr;
              return a.patch < b.patch;
            });

  util::Sha256 h;
  hash_u64_le(h, entries.size());
  for (const auto& e : entries) {
    hash_u64_le(h, e.addr);
    hash_u64_le(h, static_cast<std::uint64_t>(e.patch));
  }
  return util::sha256_hex(h.finalize());
}

// Compute the module layout digest. Modules are sorted by path
// ascending. Each entry is
//   <path : LP string> <load_address : u64 LE>
// where load_address captures the post-ASLR slide. dlopen invalidates
// this set; the per-`gen` cache is the right granularity for v0.3
// — this slice does not yet listen for eBroadcastBitModulesLoaded
// (deferred; see worklog).
std::string compute_layout_digest(lldb::SBTarget target) {
  if (!target.IsValid()) return std::string(64, '0');

  struct ModEntry {
    std::string path;
    std::uint64_t load_address = 0;
  };
  std::vector<ModEntry> mods;
  std::uint32_t n = target.GetNumModules();
  mods.reserve(n);
  for (std::uint32_t i = 0; i < n; ++i) {
    auto m = target.GetModuleAtIndex(i);
    if (!m.IsValid()) continue;
    auto fs = m.GetFileSpec();
    std::string path;
    if (const char* p = fs.GetDirectory(); p && *p) {
      path = std::string(p) + "/";
    }
    if (const char* fn = fs.GetFilename(); fn && *fn) {
      path += fn;
    }
    ModEntry e;
    e.path = std::move(path);
    e.load_address = 0;
    // First section's load address as the module's effective slide
    // proxy — convert_module() uses GetObjectFileHeaderAddress() but
    // that returns a file_addr+slide via SBSection lookup. For the
    // digest we want a stable function of the runtime layout, so use
    // the first non-zero section load_addr.
    std::size_t ns = m.GetNumSections();
    for (std::size_t s = 0; s < ns; ++s) {
      auto sec = m.GetSectionAtIndex(s);
      if (!sec.IsValid()) continue;
      auto la = sec.GetLoadAddress(target);
      if (la != LLDB_INVALID_ADDRESS) {
        e.load_address = la;
        break;
      }
    }
    mods.push_back(std::move(e));
  }
  std::sort(mods.begin(), mods.end(),
            [](const ModEntry& a, const ModEntry& b) {
              return a.path < b.path;
            });

  util::Sha256 h;
  hash_u64_le(h, mods.size());
  for (auto& m : mods) {
    hash_lp_string(h, m.path);
    hash_u64_le(h, m.load_address);
  }
  return util::sha256_hex(h.finalize());
}

bool process_is_live(lldb::SBProcess proc) {
  if (!proc.IsValid()) return false;
  auto state = proc.GetState();
  return state != lldb::eStateInvalid &&
         state != lldb::eStateUnloaded &&
         state != lldb::eStateExited &&
         state != lldb::eStateDetached;
}

}  // namespace

// Drain pending module-load events from `module_listener` and invalidate
// the layout cache of any target whose broadcaster fired. Called from
// snapshot_for_target before computing layout_digest so a dlopen between
// snapshots is reflected in the very next snapshot string (slice 1c —
// closes the dlopen-without-resume gap from the 1b reviewer).
//
// Synchronous drain (rather than a background thread) sidesteps the
// listener-lifetime hazards the 1b worker flagged. Cost is bounded:
// dlopen events are infrequent and we drain every snapshot call.
//
// Caller MUST hold impl_->mu (we mutate live_state).
void LldbBackend::drain_module_events_locked() {
  auto& listener = impl_->module_listener;
  if (!listener.IsValid()) return;
  lldb::SBEvent ev;
  while (listener.GetNextEvent(ev)) {
    // Find which target's broadcaster matches; invalidate that
    // target's layout cache. SBEvent::BroadcasterMatchesRef is the
    // documented matcher; we use SBTarget::EventIsTargetEvent /
    // GetTargetFromEvent first as a fast path, then fall back.
    bool matched = false;
    if (lldb::SBTarget::EventIsTargetEvent(ev)) {
      auto evt_target = lldb::SBTarget::GetTargetFromEvent(ev);
      if (evt_target.IsValid()) {
        for (auto& [tid, tgt] : impl_->targets) {
          if (tgt.IsValid() &&
              tgt.GetBroadcaster().GetName() != nullptr &&
              evt_target.GetBroadcaster().GetName() != nullptr &&
              std::string_view(tgt.GetBroadcaster().GetName()) ==
                  std::string_view(evt_target.GetBroadcaster().GetName())) {
            // Multiple targets can in principle share a broadcaster
            // name; double-check via BroadcasterMatchesRef.
            if (ev.BroadcasterMatchesRef(tgt.GetBroadcaster())) {
              auto it = impl_->live_state.find(tid);
              if (it != impl_->live_state.end()) {
                it->second.digests_valid = false;
                it->second.layout_digest.clear();
                // reg_digest stays — registers don't change on dlopen.
              }
              matched = true;
            }
          }
        }
      }
    }
    if (!matched) {
      // Generic fallback: walk targets and find a broadcaster match.
      for (auto& [tid, tgt] : impl_->targets) {
        if (!tgt.IsValid()) continue;
        if (ev.BroadcasterMatchesRef(tgt.GetBroadcaster())) {
          auto it = impl_->live_state.find(tid);
          if (it != impl_->live_state.end()) {
            it->second.digests_valid = false;
            it->second.layout_digest.clear();
          }
          break;
        }
      }
    }
  }
}

std::string LldbBackend::snapshot_for_target(TargetId tid) {
  // Best-effort metadata: if anything unusual happens (target gone
  // mid-call, SBProcess invalid) we degrade to "none" rather than
  // throw — the dispatcher calls this on every successful response and
  // a thrown exception would poison it.
  lldb::SBTarget target;
  std::string core_hex;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    if (auto it = impl_->core_sha256.find(tid);
        it != impl_->core_sha256.end()) {
      core_hex = it->second;
    }
    auto tit = impl_->targets.find(tid);
    if (tit == impl_->targets.end()) {
      // Unknown target_id (or one we already closed). The cached hash
      // would have been erased on close, so this branch always returns
      // "none".
      return "none";
    }
    target = tit->second;
  }
  if (!core_hex.empty()) {
    return "core:" + core_hex;
  }
  // Live target → "live:<gen>:<reg_digest>:<layout_digest>:<bp_digest>";
  // otherwise (target exists but no process: e.g. target.open without
  // launch/attach, or process exited) → "none".
  if (!target.IsValid()) return "none";
  auto proc = target.GetProcess();
  if (!process_is_live(proc)) return "none";

  // Compute (or reuse cached) reg+layout digests for the current `gen`.
  // The cache is invalidated by attach / launch / continue / step /
  // detach / close; see those entry points.
  //
  // bp_digest is computed FRESH on every call rather than cached: it
  // changes on probe.create / probe.delete / probe.enable / probe.disable
  // — none of which bump <gen> (they don't resume the inferior) — so a
  // cache invalidation hook would have to fire from those backend
  // entrypoints. Computing fresh is cheap (typically zero or a handful
  // of bps; SHA-256 of <100 bytes) and avoids the additional plumbing.
  std::uint64_t gen = 0;
  std::string reg_hex;
  std::string layout_hex;
  std::string bp_hex;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    // Drain pending dlopen events first — a module-load between two
    // snapshot calls must invalidate the cached layout digest for that
    // target (slice 1c).
    drain_module_events_locked();
    auto& st = impl_->live_state[tid];  // value-init on first sight
    if (!st.digests_valid) {
      st.reg_digest    = compute_reg_digest(proc);
      st.layout_digest = compute_layout_digest(target);
      st.digests_valid = true;
    }
    gen        = st.gen;
    reg_hex    = st.reg_digest;
    layout_hex = st.layout_digest;
    bp_hex     = compute_bp_digest(target);
  }
  std::string out;
  out.reserve(5 /*"live:"*/ + 20 + 1 + 64 + 1 + 64 + 1 + 64);
  out  = "live:";
  out += std::to_string(gen);
  out += ':';
  out += reg_hex;
  out += ':';
  out += layout_hex;
  out += ':';
  out += bp_hex;
  return out;
}

void LldbBackend::attach_target_resource(
    TargetId tid, std::unique_ptr<DebuggerBackend::TargetResource> r) {
  if (!r) return;
  std::lock_guard<std::mutex> lk(impl_->mu);
  auto it = impl_->targets.find(tid);
  if (it == impl_->targets.end()) {
    throw Error("attach_target_resource: unknown target_id");
  }
  impl_->target_resources[tid].push_back(std::move(r));
}

}  // namespace ldb::backend
