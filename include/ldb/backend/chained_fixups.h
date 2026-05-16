// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
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

// Phase 4 item 6 (docs/35-field-report-followups.md §3): per-slot
// bind information. Populated by the imports-table walk (phase 5);
// schema lives here today so callers can begin coding against it
// while the actual walk is being implemented.
//
// A bind is a chain entry that references an imported symbol from
// another module (e.g. malloc, free, _objc_msgSend). dyld resolves
// the bind at load time by looking up the symbol in the dependent
// dylib's exports table. Phase 4 only records WHICH symbol is bound
// at each slot; resolving the symbol's load address (resolved_addr)
// requires a process attached to LDB OR a cross-module symbol-index
// query, both of which are phase 5 territory.
struct BindInfo {
  // Symbol the slot is bound to, e.g. "_malloc", "_objc_msgSend".
  // Empty when the imports-table parser hasn't been wired (phase 5).
  std::string name;

  // Addend applied to the symbol's runtime address. Most binds have
  // addend = 0 (the slot holds the symbol's exact address); a non-zero
  // addend is common for re-exported aliases or field-of-imported-
  // struct patterns.
  std::int64_t addend = 0;

  // Ordinal into the imports table (DYLD_CHAINED_IMPORT,
  // _IMPORT_ADDEND, or _IMPORT_ADDEND64 record). Stored for
  // diagnostic / round-trip purposes; consumers should usually read
  // `name` and `resolved_addr` instead.
  std::uint32_t ordinal = 0;

  // Resolved load address of the bound symbol, set when a process is
  // attached and SBTarget::FindSymbols(name) returned a live mapping.
  // Empty when static-only (no process) or the symbol couldn't be
  // resolved.
  std::optional<std::uint64_t> resolved_addr;
};

struct ChainedFixupMap {
  // rva: image-base-relative VM offset of the pointer slot. Add this
  // to the runtime image_base to get the load-time slot address; this
  // is NOT a file offset. Value is the 64-bit pointer dyld would have
  // written into that slot. For rebases, this is image_base +
  // rebase_target_offset (or the raw target VA for vmaddr-style
  // formats). For binds, this is 0 — phase 4 records bind metadata in
  // `binds` (below) but doesn't synthesise a resolved value because
  // the imports-table walk is phase 5.
  std::unordered_map<std::uint64_t, std::uint64_t> resolved;

  // Phase 4 item 6: per-slot bind metadata. Keyed by the same rva as
  // `resolved`. When a slot is a bind, `resolved[rva]` stays 0 and
  // `binds[rva]` carries the symbol name + addend + (optionally)
  // resolved load address. Empty in phase 4 when the imports-table
  // walk hasn't been implemented yet; phase 5 will populate it from
  // dyld_chained_fixups_header::imports_offset.
  std::unordered_map<std::uint64_t, BindInfo> binds;

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
