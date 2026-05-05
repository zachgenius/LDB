#include "backend/lldb_backend.h"

#include <atomic>
#include <functional>
#include <mutex>
#include <unordered_map>
#include <vector>

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

  TypeLayout out;
  if (const char* nm = sb_type.GetName()) {
    out.name = nm;
  } else {
    out.name = name;
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

  // FindSymbols searches all modules — function symbols, data symbols,
  // weak/exported, etc. We post-filter by SymbolKind.
  auto sblist = target.FindSymbols(query.name.c_str());

  std::vector<SymbolMatch> out;
  out.reserve(sblist.GetSize());

  uint32_t n = sblist.GetSize();
  for (uint32_t i = 0; i < n; ++i) {
    auto ctx = sblist.GetContextAtIndex(i);
    auto sym = ctx.GetSymbol();
    if (!sym.IsValid()) continue;

    // Match by display name. SBSymbolContextList.FindSymbols may include
    // partial / unrelated hits; reject anything where the name differs.
    const char* name = sym.GetName();
    if (!name || query.name != name) continue;

    SymbolKind kind = classify_symbol(sym.GetType());
    if (!kind_matches(query.kind, kind)) continue;

    SymbolMatch m;
    m.name = name;
    if (const char* mn = sym.GetMangledName()) {
      if (m.name != mn) m.mangled = mn;
    }
    m.kind = kind;

    auto start_addr = sym.GetStartAddress();
    if (start_addr.IsValid()) {
      m.address = start_addr.GetFileAddress();
    }
    auto end_addr = sym.GetEndAddress();
    if (end_addr.IsValid() && start_addr.IsValid()) {
      auto e = end_addr.GetFileAddress();
      auto s = start_addr.GetFileAddress();
      if (e > s) m.byte_size = e - s;
    }

    m.module_path = module_path_of(sym, target, start_addr);

    out.push_back(std::move(m));
  }

  return out;
}

namespace {

bool is_print_ascii(unsigned char c) {
  // strings(1) treats tab as printable. We accept space..~ plus tab.
  return c == 0x09 || (c >= 0x20 && c <= 0x7E);
}

// True if section's classified type is "data" (per our M0 classification).
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
      // Top-level + recursive descent finds the named section anywhere.
      // Walk the tree depth-first; only scan the matching node (no
      // siblings).
      std::function<void(lldb::SBSection)> visit = [&](lldb::SBSection s) {
        if (!s.IsValid()) return;
        if (full_section_name(s) == q.section_name) {
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
