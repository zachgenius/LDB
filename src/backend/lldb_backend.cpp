#include "backend/lldb_backend.h"

#include <atomic>
#include <mutex>
#include <unordered_map>

#include <lldb/API/LLDB.h>

#include "util/log.h"

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

Module convert_module(lldb::SBModule m) {
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

  // Top-level sections
  size_t n = m.GetNumSections();
  out.sections.reserve(n);
  for (size_t i = 0; i < n; ++i) {
    auto s = m.GetSectionAtIndex(i);
    if (s.IsValid()) collect_sections(s, out.sections);
  }
  return out;
}

}  // namespace

// ----------------------------------------------------------------------------

struct LldbBackend::Impl {
  lldb::SBDebugger debugger;
  std::mutex mu;
  std::unordered_map<TargetId, lldb::SBTarget> targets;
  std::atomic<TargetId> next_id{1};
};

LldbBackend::LldbBackend() : impl_(std::make_unique<Impl>()) {
  lldb::SBDebugger::Initialize();
  impl_->debugger = lldb::SBDebugger::Create();
  impl_->debugger.SetAsync(false);
  log::info("lldb backend initialized");
}

LldbBackend::~LldbBackend() {
  if (impl_) {
    {
      std::lock_guard<std::mutex> lk(impl_->mu);
      impl_->targets.clear();
    }
    if (impl_->debugger.IsValid()) {
      lldb::SBDebugger::Destroy(impl_->debugger);
    }
  }
  lldb::SBDebugger::Terminate();
}

OpenResult LldbBackend::open_executable(const std::string& path) {
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
    if (mod.IsValid()) res.modules.push_back(convert_module(mod));
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
    if (m.IsValid()) out.push_back(convert_module(m));
  }
  return out;
}

void LldbBackend::close_target(TargetId tid) {
  lldb::SBTarget target;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto it = impl_->targets.find(tid);
    if (it == impl_->targets.end()) return;
    target = it->second;
    impl_->targets.erase(it);
  }
  impl_->debugger.DeleteTarget(target);
}

}  // namespace ldb::backend
