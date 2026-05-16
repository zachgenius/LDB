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
constexpr std::uint32_t kMagic64Swap   = 0xCFFAEDFE;  // big-endian header
constexpr std::uint32_t kFatMagic      = 0xCAFEBABE;
constexpr std::uint32_t kFatMagic64    = 0xCAFEBABF;
constexpr std::uint32_t kFatMagicSwap  = 0xBEBAFECA;
constexpr std::uint32_t kFatMagic64Swap= 0xBFBAFECA;

constexpr std::uint32_t kLCSegment64           = 0x19;
constexpr std::uint32_t kLCDyldChainedFixups   = 0x80000034;  // LC_DYLD_CHAINED_FIXUPS

}  // namespace

ChainedFixupMap extract_chained_fixups_from_macho(
    const std::uint8_t* macho_bytes, std::size_t macho_size) {
  if (macho_bytes == nullptr || macho_size < 32) {
    return {};
  }
  // Reject byte-swapped / 32-bit / FAT headers. FAT binaries would need
  // us to pick the right arch slice; the field report only flagged
  // single-arch arm64 binaries, so phase 2 just no-ops on FAT and the
  // caller falls back to literal-operand scanning.
  const std::uint32_t magic = read_u32(macho_bytes);
  if (magic != kMagic64) {
    if (magic == kMagic64Swap || magic == kFatMagic || magic == kFatMagic64 ||
        magic == kFatMagicSwap || magic == kFatMagic64Swap) {
      return {};
    }
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

}  // namespace ldb::backend
