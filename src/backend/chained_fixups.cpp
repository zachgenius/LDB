// SPDX-License-Identifier: Apache-2.0
// Parser for LC_DYLD_CHAINED_FIXUPS payloads. Phase 1 of
// docs/35-field-report-followups.md §3 — standalone parser, no
// indexer wire-up. Phase 2 wires the resolved map into xref /
// string-xref / correlate, and adds the imports table for binds.
//
// We deliberately parse the format byte-by-byte from the payload
// instead of casting to the Apple SDK structs. Two reasons:
//   1. We compile on Linux too (the daemon CI runs there); on
//      non-Apple hosts the SDK header isn't present and the layout
//      is fixed-width little-endian anyway.
//   2. The SDK bitfield structs are ABI-fragile (bit order is
//      implementation-defined in standard C++). Decoding each u64
//      via masks + shifts is portable and matches dyld source.

#include "ldb/backend/chained_fixups.h"
#include "backend/debugger_backend.h"  // backend::Error

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace ldb::backend {

namespace {

// Pointer-format enum mirrors <mach-o/fixup-chains.h>. Kept here as
// named constants so the parser is self-contained.
constexpr std::uint16_t kArm64e            =  1;
constexpr std::uint16_t kPtr64             =  2;
constexpr std::uint16_t kPtr64Offset       =  6;
constexpr std::uint16_t kArm64eUserland    =  9;
constexpr std::uint16_t kArm64eUserland24  = 12;

constexpr std::uint16_t kPageStartNone = 0xFFFF;
constexpr std::uint16_t kChainStartMulti = 0x8000;  // unsupported in phase 1

// Endian-safe little-endian reads. Mach-O is fixed LE on all
// Apple-supported architectures; we never see big-endian fixups.
std::uint16_t read_u16(const std::uint8_t* p) {
  return static_cast<std::uint16_t>(
      static_cast<std::uint16_t>(p[0]) |
      (static_cast<std::uint16_t>(p[1]) << 8));
}

std::uint32_t read_u32(const std::uint8_t* p) {
  return static_cast<std::uint32_t>(p[0]) |
         (static_cast<std::uint32_t>(p[1]) << 8) |
         (static_cast<std::uint32_t>(p[2]) << 16) |
         (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint64_t read_u64(const std::uint8_t* p) {
  std::uint64_t v = 0;
  for (int i = 0; i < 8; ++i) {
    v |= static_cast<std::uint64_t>(p[i]) << (i * 8);
  }
  return v;
}

void require_range(std::size_t off, std::size_t need,
                   std::size_t total, const char* what) {
  if (off > total || need > total - off) {
    throw Error(std::string("chained_fixups: out-of-bounds read: ") + what);
  }
}

bool is_arm64e_family(std::uint16_t fmt) {
  return fmt == kArm64e || fmt == kArm64eUserland ||
         fmt == kArm64eUserland24;
}

bool target_is_runtime_offset(std::uint16_t fmt) {
  // For unauthenticated rebases:
  //   format 1 (ARM64E)            : target is vmaddr
  //   format 2 (PTR_64)            : target is vmaddr
  //   format 6 (PTR_64_OFFSET)     : target is runtime offset
  //   format 9 (ARM64E_USERLAND)   : target is runtime offset
  //   format 12 (ARM64E_USERLAND24): target is runtime offset
  // Authenticated rebases (ARM64E*) always carry a runtime offset.
  return fmt == kPtr64Offset || fmt == kArm64eUserland ||
         fmt == kArm64eUserland24;
}

std::uint64_t stride_bytes(std::uint16_t fmt) {
  // All supported formats use 4-byte stride for PTR_64*, 8-byte for
  // ARM64E userland. (ARM64E_KERNEL is 4-byte, but unsupported here.)
  if (fmt == kPtr64 || fmt == kPtr64Offset) return 4;
  return 8;  // arm64e userland / userland24 / arm64e (format 1)
}

void unsupported_format(std::uint16_t fmt) {
  // FIXME(phase 2): docs/35-field-report-followups.md §3
  throw Error("chained_fixups: unsupported chained pointer format: " +
              std::to_string(fmt) + " — phase 2");
}

// Decode one 64-bit chained-pointer slot into:
//   - resolved logical pointer value (0 for binds — phase 1 doesn't
//     resolve them)
//   - next stride count (0 means end of chain)
//   - whether this entry was a bind
struct DecodedSlot {
  std::uint64_t resolved = 0;
  std::uint32_t next = 0;
  bool is_bind = false;
};

DecodedSlot decode_arm64e(std::uint64_t raw, std::uint64_t image_base,
                          bool target_is_offset) {
  // dyld_chained_ptr_arm64e_* layout (all variants share top bits):
  //   bit 63   : auth
  //   bit 62   : bind
  //   bits 61:51: next (11)
  // Rebase  (auth=0,bind=0): target [42:0], high8 [50:43]
  // AuthRebase (auth=1,bind=0): target [31:0] (always runtime offset),
  //                             diversity [47:32], addrDiv [48],
  //                             key [50:49]
  // Bind / AuthBind: ordinal+addend variants — phase 1 leaves at 0.
  DecodedSlot d;
  const bool auth = (raw >> 63) & 0x1;
  const bool bind = (raw >> 62) & 0x1;
  d.next = static_cast<std::uint32_t>((raw >> 51) & 0x7FFU);
  d.is_bind = bind;
  if (bind) {
    return d;
  }
  if (auth) {
    std::uint64_t target = raw & 0xFFFFFFFFULL;
    d.resolved = image_base + target;
  } else {
    std::uint64_t target = raw & 0x7FFFFFFFFFFULL;  // 43 bits
    std::uint64_t high8  = (raw >> 43) & 0xFFULL;
    std::uint64_t value  = target_is_offset ? (image_base + target) : target;
    d.resolved = value | (high8 << 56);
  }
  return d;
}

DecodedSlot decode_64(std::uint64_t raw, std::uint64_t image_base,
                      bool target_is_offset) {
  // dyld_chained_ptr_64_rebase / _bind layout:
  //   bit 63    : bind
  //   bits 62:51: next (12)
  //   Rebase: target [35:0], high8 [43:36], reserved [50:44]
  //   Bind  : ordinal [23:0], addend [31:24], reserved [50:32]
  DecodedSlot d;
  const bool bind = (raw >> 63) & 0x1;
  d.next = static_cast<std::uint32_t>((raw >> 51) & 0xFFFU);
  d.is_bind = bind;
  if (bind) {
    return d;
  }
  std::uint64_t target = raw & 0xFFFFFFFFFULL;  // 36 bits
  std::uint64_t high8  = (raw >> 36) & 0xFFULL;
  std::uint64_t value  = target_is_offset ? (image_base + target) : target;
  d.resolved = value | (high8 << 56);
  return d;
}

DecodedSlot decode_slot(std::uint16_t fmt, std::uint64_t raw,
                        std::uint64_t image_base) {
  const bool offset_target = target_is_runtime_offset(fmt);
  if (is_arm64e_family(fmt)) {
    return decode_arm64e(raw, image_base, offset_target);
  }
  return decode_64(raw, image_base, offset_target);
}

void walk_chain(const SegmentInfo& seg, std::uint16_t fmt,
                std::uint64_t seg_offset_in_image,
                std::uint64_t page_base_in_segment,
                std::uint16_t start_offset_in_page,
                std::uint64_t image_base,
                std::uint64_t stride,
                ChainedFixupMap& out) {
  if (seg.data == nullptr) {
    throw Error("chained_fixups: segment with chain data has no bytes; "
                "caller must pass segment.data for chained segments");
  }
  std::uint64_t cursor_in_seg = page_base_in_segment + start_offset_in_page;
  for (;;) {
    if (cursor_in_seg + 8 > seg.data_size) {
      throw Error("chained_fixups: chain walks past end of segment data");
    }
    std::uint64_t raw = read_u64(seg.data + cursor_in_seg);
    DecodedSlot d = decode_slot(fmt, raw, image_base);
    // rva = image-base-relative VM offset of this pointer slot. Not a
    // file offset; see ChainedFixupMap docstring.
    std::uint64_t rva = seg_offset_in_image + cursor_in_seg;
    // For binds, resolved stays 0 — but we still record the slot so
    // callers can detect chained-fixup territory by membership.
    out.resolved.emplace(rva, d.resolved);
    if (d.next == 0) {
      break;
    }
    std::uint64_t step = static_cast<std::uint64_t>(d.next) * stride;
    cursor_in_seg += step;
  }
}

}  // namespace

ChainedFixupMap parse_chained_fixups(
    const std::uint8_t* payload, std::size_t payload_size,
    const std::vector<SegmentInfo>& segments) {
  if (payload == nullptr) {
    throw Error("chained_fixups: null payload");
  }
  require_range(0, 28, payload_size, "header");
  // const std::uint32_t fixups_version = read_u32(payload + 0);
  const std::uint32_t starts_offset  = read_u32(payload +  4);
  // imports_offset / symbols_offset are phase 2 territory.
  // const std::uint32_t imports_count  = read_u32(payload + 16);
  // const std::uint32_t imports_format = read_u32(payload + 20);

  require_range(starts_offset, 4, payload_size, "starts_in_image");
  const std::uint8_t* starts = payload + starts_offset;
  const std::uint32_t seg_count = read_u32(starts);
  require_range(starts_offset + 4,
                static_cast<std::size_t>(seg_count) * 4,
                payload_size, "seg_info_offset[]");
  if (seg_count > segments.size()) {
    throw Error("chained_fixups: seg_count exceeds caller's segments[]");
  }

  ChainedFixupMap out;
  bool image_base_known = false;
  std::uint64_t image_base = 0;

  for (std::uint32_t i = 0; i < seg_count; ++i) {
    const std::uint32_t seg_info_offset =
        read_u32(starts + 4 + i * 4);
    if (seg_info_offset == 0) {
      continue;
    }
    const std::size_t sis_off =
        static_cast<std::size_t>(starts_offset) + seg_info_offset;
    // Two-phase bounds check: (1) the 22-byte fixed header must be in
    // range before we can trust the `size` field we read out of it,
    // (2) `size` itself must cover at least the header, (3) only then
    // can `size` be used to range-check the variable-length body.
    require_range(sis_off, 22, payload_size, "starts_in_segment header");
    const std::uint8_t* sis = payload + sis_off;
    const std::uint32_t size            = read_u32(sis + 0);
    if (size < 22) {
      throw Error("chained_fixups: starts_in_segment.size < 22");
    }
    require_range(sis_off, size, payload_size, "starts_in_segment body");
    const std::uint16_t page_size       = read_u16(sis + 4);
    const std::uint16_t pointer_format  = read_u16(sis + 6);
    const std::uint64_t segment_offset  = read_u64(sis + 8);
    // const std::uint32_t max_valid_ptr = read_u32(sis + 16);
    const std::uint16_t page_count      = read_u16(sis + 20);
    require_range(sis_off + 22,
                  static_cast<std::size_t>(page_count) * 2,
                  payload_size, "page_start[]");
    if (page_size == 0) {
      throw Error("chained_fixups: zero page_size");
    }

    const bool supported =
        is_arm64e_family(pointer_format) ||
        pointer_format == kPtr64 ||
        pointer_format == kPtr64Offset;
    if (!supported) {
      unsupported_format(pointer_format);
    }

    if (!image_base_known) {
      if (segments[i].vm_addr < segment_offset) {
        throw Error("chained_fixups: segment vm_addr < segment_offset");
      }
      image_base = segments[i].vm_addr - segment_offset;
      image_base_known = true;
      out.image_base = image_base;
    }

    const std::uint64_t stride = stride_bytes(pointer_format);
    const std::uint8_t* page_starts = sis + 22;
    for (std::uint16_t pi = 0; pi < page_count; ++pi) {
      const std::uint16_t ps = read_u16(page_starts + pi * 2);
      if (ps == kPageStartNone) {
        continue;
      }
      if (ps & kChainStartMulti) {
        // Multi-start pages live in chain_starts[] appended after
        // page_start[]. Real userland binaries seldom emit them
        // (clang/lld pack chains so one start per page suffices).
        // Phase 2 handles this when we encounter it in the wild.
        // FIXME(phase 2): docs/35-field-report-followups.md §3
        throw Error("chained_fixups: multi-start page — phase 2");
      }
      const std::uint64_t page_base_in_seg =
          static_cast<std::uint64_t>(pi) *
          static_cast<std::uint64_t>(page_size);
      walk_chain(segments[i], pointer_format, segment_offset,
                 page_base_in_seg, ps, image_base, stride, out);
    }
  }

  return out;
}

namespace {

// Subset of Mach-O constants we need. Kept inline to avoid pulling in
// the host SDK's <mach-o/*.h> on Linux build legs — the byte layout
// is fixed and little-endian on every Apple-supported architecture.
constexpr std::uint32_t kMagic64       = 0xFEEDFACF;

// FAT (universal) magic. The on-disk bytes are CA FE BA BE / CF
// (32-bit / 64-bit FAT). Our read_u32 is little-endian, so the FAT
// header we actually see in memory is the byte-reversed form below
// (kFatMagicLE / kFatMagic64LE). The header AND the per-arch tables
// inside the FAT preamble are big-endian on disk, so we use
// read_u32_be / read_u64_be to decode them.
constexpr std::uint32_t kFatMagicLE    = 0xBEBAFECA;
constexpr std::uint32_t kFatMagic64LE  = 0xBFBAFECA;

constexpr std::uint32_t kLCSegment64           = 0x19;
constexpr std::uint32_t kLCDyldChainedFixups   = 0x80000034;  // LC_DYLD_CHAINED_FIXUPS

// CPU types we know how to prefer in a FAT dispatch. The acceptance
// criteria in docs/35-field-report-followups.md §3 phase 3 says:
// pick the SBTarget-triple-matching slice; absent that, prefer arm64e
// over arm64 over x86_64. xref consumers today only care about ARM64;
// x86_64 has no chained fixups (LC_DYLD_INFO_ONLY) and parse_chained_
// fixups would no-op on it anyway. We only need the ARM64 constants —
// non-ARM64 slices fall through to the empty-map return.
constexpr std::uint32_t kCpuTypeArm64  = 0x0100000C;
constexpr std::uint32_t kCpuSubTypeArm64E = 2;
constexpr std::uint32_t kCpuSubTypeMask   = 0x00FFFFFFU;  // strip features

std::uint32_t read_u32_be(const std::uint8_t* p) {
  return (static_cast<std::uint32_t>(p[0]) << 24) |
         (static_cast<std::uint32_t>(p[1]) << 16) |
         (static_cast<std::uint32_t>(p[2]) << 8)  |
         (static_cast<std::uint32_t>(p[3]));
}

std::uint64_t read_u64_be(const std::uint8_t* p) {
  std::uint64_t v = 0;
  for (int i = 0; i < 8; ++i) {
    v = (v << 8) | static_cast<std::uint64_t>(p[i]);
  }
  return v;
}

// Parse a thin (non-FAT) 64-bit Mach-O at `bytes` of length `size`.
// The slice starts at offset 0 of the buffer. Returns the resolved
// chained-fixup map or empty if the binary isn't a recognised
// LE arm64 / arm64e Mach-O or doesn't carry LC_DYLD_CHAINED_FIXUPS.
ChainedFixupMap extract_chained_fixups_from_thin_macho(
    const std::uint8_t* macho_bytes, std::size_t macho_size) {
  if (macho_bytes == nullptr || macho_size < 32) {
    return {};
  }
  const std::uint32_t magic = read_u32(macho_bytes);
  if (magic != kMagic64) {
    // Byte-swapped 64-bit / 32-bit / unrecognised: not our target.
    return {};
  }

  // mach_header_64 layout (LE):
  //   magic[0..4] cputype[4..8] cpusubtype[8..12] filetype[12..16]
  //   ncmds[16..20] sizeofcmds[20..24] flags[24..28] reserved[28..32]
  const std::uint32_t ncmds      = read_u32(macho_bytes + 16);
  const std::uint32_t sizeofcmds = read_u32(macho_bytes + 20);
  if (sizeofcmds > macho_size - 32) {
    return {};
  }

  std::vector<SegmentInfo> segments;
  segments.reserve(8);
  const std::uint8_t* fixups_payload = nullptr;
  std::size_t         fixups_size    = 0;

  std::size_t cursor = 32;
  for (std::uint32_t i = 0; i < ncmds; ++i) {
    if (cursor + 8 > macho_size) return {};
    const std::uint32_t cmd     = read_u32(macho_bytes + cursor + 0);
    const std::uint32_t cmdsize = read_u32(macho_bytes + cursor + 4);
    if (cmdsize < 8 || cursor + cmdsize > macho_size) return {};

    if (cmd == kLCSegment64) {
      // segment_command_64 (72-byte fixed header):
      //   cmd[0..4] cmdsize[4..8] segname[8..24] vmaddr[24..32]
      //   vmsize[32..40] fileoff[40..48] filesize[48..56]
      //   maxprot[56..60] initprot[60..64] nsects[64..68] flags[68..72]
      // We only read up to filesize[48..56] in this branch, so a
      // cmdsize<72 input wouldn't OOB today; the tighter bound matches
      // the actual struct minimum and rejects truncated commands that
      // any later additions (nsects/flags) would dereference past.
      if (cmdsize < 72) return {};
      const std::uint64_t vmaddr   = read_u64(macho_bytes + cursor + 24);
      const std::uint64_t vmsize   = read_u64(macho_bytes + cursor + 32);
      const std::uint64_t fileoff  = read_u64(macho_bytes + cursor + 40);
      const std::uint64_t filesize = read_u64(macho_bytes + cursor + 48);

      SegmentInfo seg;
      seg.vm_addr = vmaddr;
      seg.vm_size = vmsize;
      // Bind segment bytes only if the file extent is in-range. dyld
      // tolerates filesize=0 for __PAGEZERO; parse_chained_fixups()
      // only dereferences `data` for segments with a non-zero
      // seg_info_offset, so a null/zero buffer here is safe.
      if (filesize > 0 && fileoff < macho_size &&
          filesize <= macho_size - fileoff) {
        seg.data      = macho_bytes + fileoff;
        seg.data_size = static_cast<std::size_t>(filesize);
      }
      segments.push_back(seg);
    } else if (cmd == kLCDyldChainedFixups) {
      // linkedit_data_command: cmd, cmdsize, dataoff[8..12], datasize[12..16].
      if (cmdsize < 16) return {};
      const std::uint32_t dataoff  = read_u32(macho_bytes + cursor + 8);
      const std::uint32_t datasize = read_u32(macho_bytes + cursor + 12);
      if (dataoff > macho_size || datasize > macho_size - dataoff) {
        return {};
      }
      fixups_payload = macho_bytes + dataoff;
      fixups_size    = datasize;
    }

    cursor += cmdsize;
  }

  if (fixups_payload == nullptr || fixups_size == 0) {
    return {};
  }
  return parse_chained_fixups(fixups_payload, fixups_size, segments);
}

// Phase 4 item 2 (docs/35-field-report-followups.md §3): classify a
// triple string into the (cpu_type, cpu_subtype) pair the FAT picker
// should prefer. Returns false when the triple is empty or doesn't
// name a known arch — in which case the picker falls back to the
// phase-3 preference order (arm64e > arm64).
//
// Triple substring -> (cpu_type, cpu_subtype) table:
//   "arm64e-" -> CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E (2)
//   "arm64-"  -> CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL (0)
//   "x86_64-" -> CPU_TYPE_X86_64, any subtype (x86_64 has no chained
//                fixups today; the picker still skips past it the
//                same way phase 3 did)
//
// "arm64-" matching must come AFTER "arm64e-" — the LLDB-reported
// triple for arm64e binaries contains "arm64e-", which starts with
// "arm64" without the trailing dash. The substring check is bracketed
// by the dash so we don't accidentally match "arm64-" inside
// "arm64e-apple-...".
constexpr std::uint32_t kCpuTypeX86_64 = 0x01000007;

bool triple_to_preferred_arch(std::string_view triple,
                              std::uint32_t* cpu_type,
                              std::uint32_t* cpu_subtype) {
  if (triple.empty()) return false;
  if (triple.find("arm64e-") != std::string_view::npos) {
    *cpu_type    = kCpuTypeArm64;
    *cpu_subtype = kCpuSubTypeArm64E;
    return true;
  }
  if (triple.find("arm64-") != std::string_view::npos) {
    *cpu_type    = kCpuTypeArm64;
    *cpu_subtype = 0;  // ARM64_ALL — the picker also accepts _V8 (1)
    return true;
  }
  if (triple.find("x86_64-") != std::string_view::npos) {
    *cpu_type    = kCpuTypeX86_64;
    *cpu_subtype = 0;
    return true;
  }
  // Unknown / unhandled triple — fall back to preference order.
  return false;
}

// FAT slice selection (docs/35-field-report-followups.md §3 phase 3
// gate 5; phase 4 item 2). Iterate the fat_arch[] table; if a triple
// hint is supplied, try the matching slice first. Otherwise fall back
// to the phase-3 preference order (arm64e > arm64). The phase-3
// acceptance criteria said "match the SBTarget's triple"; phase 4
// closes the loop by actually threading it through.
ChainedFixupMap extract_chained_fixups_from_fat(
    const std::uint8_t* fat_bytes, std::size_t fat_size,
    bool is_fat64, std::string_view triple) {
  if (fat_bytes == nullptr || fat_size < 8) return {};
  // fat_header: magic[0..4] nfat_arch[4..8]. Big-endian on disk.
  const std::uint32_t nfat_arch = read_u32_be(fat_bytes + 4);
  if (nfat_arch == 0 || nfat_arch > 16) {
    // Hard ceiling — Apple's universal2 binaries top out at 2
    // (arm64 + x86_64); a 64K-arch fat header is malformed.
    return {};
  }

  const std::size_t arch_entry_size = is_fat64 ? 32 : 20;
  const std::size_t table_size = arch_entry_size *
                                  static_cast<std::size_t>(nfat_arch);
  if (table_size > fat_size - 8) {
    return {};
  }

  // Three-pass selection over the arch table: arm64e first, then any
  // arm64, then bail. Anything else (x86_64, arm32) has no chained
  // fixups so we silently skip them — the empty-map return is the
  // caller's "no chained fixups" signal.
  struct ArchSlice {
    std::uint64_t offset = 0;
    std::uint64_t size   = 0;
    std::uint32_t cpu_type = 0;
    std::uint32_t cpu_subtype_masked = 0;
  };
  std::vector<ArchSlice> archs;
  archs.reserve(nfat_arch);
  for (std::uint32_t i = 0; i < nfat_arch; ++i) {
    const std::size_t entry_off = 8 + i * arch_entry_size;
    const std::uint8_t* e = fat_bytes + entry_off;
    ArchSlice a;
    a.cpu_type           = read_u32_be(e + 0);
    a.cpu_subtype_masked = read_u32_be(e + 4) & kCpuSubTypeMask;
    if (is_fat64) {
      a.offset = read_u64_be(e + 8);
      a.size   = read_u64_be(e + 16);
    } else {
      a.offset = read_u32_be(e + 8);
      a.size   = read_u32_be(e + 12);
    }
    archs.push_back(a);
  }

  auto pick_and_run = [&](const ArchSlice& a) -> ChainedFixupMap {
    if (a.offset > fat_size || a.size > fat_size - a.offset) {
      // Malformed FAT entry — out-of-bounds slice. Treat as no-op
      // rather than throwing; a malformed universal binary's other
      // slices may still be valid, but in practice this signals the
      // file is hostile and the empty-map return is the right answer.
      return {};
    }
    return extract_chained_fixups_from_thin_macho(
        fat_bytes + a.offset, static_cast<std::size_t>(a.size));
  };

  // Phase 4 item 2: if the caller provided a triple, try the exact
  // (cpu_type, cpu_subtype) match first. The image_base in the
  // returned ChainedFixupMap then matches the slice LLDB actually
  // loaded — the phase-3 hazard (arm64e wins picker; LLDB loaded
  // arm64 slice; wrong image_base, zero matches) goes away.
  std::uint32_t triple_cpu_type = 0, triple_cpu_subtype = 0;
  if (triple_to_preferred_arch(triple, &triple_cpu_type,
                                &triple_cpu_subtype)) {
    for (const auto& a : archs) {
      if (a.cpu_type == triple_cpu_type &&
          a.cpu_subtype_masked == triple_cpu_subtype) {
        auto m = pick_and_run(a);
        if (!m.resolved.empty()) return m;
      }
    }
    // ARM64_ALL match also accepts CPU_SUBTYPE_ARM64_V8 (=1). The
    // exact-match pass above would have missed a V8-tagged slice;
    // the second pass below catches it. Skip when the triple
    // demanded arm64e — V8 is not arm64e.
    if (triple_cpu_type == kCpuTypeArm64 &&
        triple_cpu_subtype == 0) {
      for (const auto& a : archs) {
        if (a.cpu_type == kCpuTypeArm64 &&
            a.cpu_subtype_masked == 1) {
          auto m = pick_and_run(a);
          if (!m.resolved.empty()) return m;
        }
      }
    }
    // Triple-specified slice missing or had no fixups — fall through
    // to the phase-3 preference order below. Better to surface SOME
    // result than nothing.
  }

  // Phase-3 preference order (also the fallback when triple is empty
  // or didn't match a known arch). arm64e first, then plain arm64.
  // A slice with an EMPTY resolved map is treated as "no chained
  // fixups in this slice; try the next" rather than "use this empty
  // result."
  for (const auto& a : archs) {
    if (a.cpu_type == kCpuTypeArm64 &&
        a.cpu_subtype_masked == kCpuSubTypeArm64E) {
      auto m = pick_and_run(a);
      if (!m.resolved.empty()) return m;
    }
  }
  for (const auto& a : archs) {
    if (a.cpu_type == kCpuTypeArm64 &&
        a.cpu_subtype_masked != kCpuSubTypeArm64E) {
      auto m = pick_and_run(a);
      if (!m.resolved.empty()) return m;
    }
  }
  // No arm64 slice with chained fixups (or x86_64-only binary).
  // Empty map — caller falls back to the literal-operand scan.
  return {};
}

}  // namespace

ChainedFixupMap extract_chained_fixups_from_macho(
    const std::uint8_t* macho_bytes, std::size_t macho_size,
    std::string_view triple) {
  if (macho_bytes == nullptr || macho_size < 8) {
    return {};
  }
  const std::uint32_t magic = read_u32(macho_bytes);
  if (magic == kFatMagicLE) {
    return extract_chained_fixups_from_fat(macho_bytes, macho_size,
                                            /*is_fat64=*/false, triple);
  }
  if (magic == kFatMagic64LE) {
    return extract_chained_fixups_from_fat(macho_bytes, macho_size,
                                            /*is_fat64=*/true, triple);
  }
  // Thin Mach-O — no slice to pick, triple is irrelevant.
  return extract_chained_fixups_from_thin_macho(macho_bytes, macho_size);
}

}  // namespace ldb::backend
