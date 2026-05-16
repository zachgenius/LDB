// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <cstdint>
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
ChainedFixupMap extract_chained_fixups_from_macho(
    const std::uint8_t* macho_bytes, std::size_t macho_size);

}  // namespace ldb::backend
