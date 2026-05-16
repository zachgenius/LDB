// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <unordered_map>
#include <vector>

// Parser for Mach-O LC_DYLD_CHAINED_FIXUPS — the dyld pointer-chain
// format used by ARM64e binaries (iOS 13+ / macOS 11+) where every
// pointer-bearing slot (__objc_selrefs, __got, __auth_got, __const,
// __data, ...) stores a chained-fixup descriptor instead of a raw
// 64-bit virtual address. LDB's xref pipeline silently produces wrong
// results on these binaries unless every slot is first resolved back
// to the value dyld would have written at load time.
//
// Phase 1 (see docs/35-field-report-followups.md §3): standalone
// parser, no indexer wire-up. Phase 2 wires this into xref / string-
// xref / correlate and adds the imports table for bind resolution.
//
// Format reference: <mach-o/fixup-chains.h> from the host SDK.

namespace ldb::backend {

struct SegmentInfo {
  std::uint64_t vm_addr = 0;
  std::uint64_t vm_size = 0;

  // The on-disk bytes of this segment (length = file_size). The parser
  // reads chained-pointer slots from these bytes — the chain encoding
  // lives in segment data, not in the LC_DYLD_CHAINED_FIXUPS payload.
  // Callers may pass {nullptr, 0} for segments that don't carry chain
  // data (e.g. __PAGEZERO, __LINKEDIT); the parser only reads from
  // segments referenced by a non-zero seg_info_offset.
  const std::uint8_t* data = nullptr;
  std::size_t data_size = 0;
};

struct ChainedFixupMap {
  // rva: image-base-relative VM offset of the pointer slot. Add this
  // to the runtime image_base to get the load-time slot address; this
  // is NOT a file offset. Value is the 64-bit pointer dyld would have
  // written into that slot. For rebases, this is image_base +
  // rebase_target_offset (or the raw target VA for vmaddr-style
  // formats). For binds, this is 0 — phase 1 does not resolve binds.
  // Phase 2 wires in the imports table.
  std::unordered_map<std::uint64_t, std::uint64_t> resolved;

  // Image base derived from the first chain-bearing segment's
  // (vm_addr - segment_offset) pair. Zero when no chained fixups are
  // present (extract_chained_fixups_from_macho on a non-Mach-O / non-
  // ARM64e binary, or a Mach-O without LC_DYLD_CHAINED_FIXUPS). Callers
  // that need to translate a slot's file address to an RVA (xref's
  // ADRP-pair resolver) read this instead of re-deriving it from the
  // module's section table.
  std::uint64_t image_base = 0;
};

// Parse a raw LC_DYLD_CHAINED_FIXUPS payload. `payload` points at the
// dyld_chained_fixups_header; `payload_size` is the LC payload's
// `datasize`. `segments` mirrors the Mach-O's LC_SEGMENT_64 list in
// order — the chain data uses segment indices to find its targets.
//
// Phase 1 supports the ARM64e struct family (formats 1, 9, 12) and
// the 64-bit formats (2, 6). Other formats throw backend::Error with
// a "phase 2" message. Throws on malformed payloads (out-of-bounds
// reads, impossible struct sizes, etc.).
ChainedFixupMap parse_chained_fixups(
    const std::uint8_t* payload, std::size_t payload_size,
    const std::vector<SegmentInfo>& segments);

// High-level Mach-O wrapper used by the xref pipeline
// (docs/35-field-report-followups.md §3 phase 2). Walks the load
// commands at `macho_bytes`, locates LC_DYLD_CHAINED_FIXUPS plus the
// LC_SEGMENT_64 list, and dispatches to parse_chained_fixups().
//
// Behaviour:
//   - Non-Mach-O / 32-bit Mach-O input: returns empty map (the caller
//     treats this as "binary doesn't use chained fixups" and falls
//     back to the literal-operand scan).
//   - Mach-O without LC_DYLD_CHAINED_FIXUPS: returns empty map.
//   - Mach-O with LC_DYLD_CHAINED_FIXUPS but malformed payload:
//     propagates the backend::Error from parse_chained_fixups().
//
// `macho_bytes` must outlive this call but the map's resolved table
// owns its own storage and survives the byte buffer's destruction.
//
// `triple` is the SBTarget triple of the LOADED slice (e.g.
// "arm64e-apple-macosx14.0.0", "arm64-apple-ios13.0", "x86_64-apple-
// macosx-"). Phase 4 item 5 (docs/35-field-report-followups.md §3)
// uses it to pick the right slice from a FAT (universal) Mach-O:
//   - triple substring "arm64e-" → prefer CPU_SUBTYPE_ARM64E (= 2)
//   - triple substring "arm64-"  → prefer CPU_SUBTYPE_ARM64_ALL/_V8
//   - triple substring "x86_64-" → CPU_TYPE_X86_64 (no chained fixups
//                                   today; we still skip past it)
// Empty triple falls back to the phase-3 preference order (arm64e
// then arm64). Non-FAT inputs ignore the triple entirely.
ChainedFixupMap extract_chained_fixups_from_macho(
    const std::uint8_t* macho_bytes, std::size_t macho_size,
    std::string_view triple = {});

}  // namespace ldb::backend
