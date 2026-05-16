// SPDX-License-Identifier: Apache-2.0
// Tests for ldb::backend::parse_chained_fixups — the ARM64e
// LC_DYLD_CHAINED_FIXUPS parser introduced for
// docs/35-field-report-followups.md §3 phase 1.
//
// The byte vectors below were hand-derived from the Apple SDK header
// <mach-o/fixup-chains.h> and cross-checked against the output of
// `dyld_info --fixups` on a real arm64 macOS exec built with
// `clang -Wl,-fixup_chains`. Where vectors are fully synthetic (vector
// B's two-page chain, vector C's unsupported format), the byte
// derivation is documented inline so a reviewer can verify each field
// against the SDK structs without rebuilding fixtures.

#include <catch_amalgamated.hpp>

#include "ldb/backend/chained_fixups.h"
#include "backend/debugger_backend.h"  // backend::Error

#include <array>
#include <cstdint>
#include <string>
#include <vector>

using ldb::backend::ChainedFixupMap;
using ldb::backend::Error;
using ldb::backend::parse_chained_fixups;
using ldb::backend::SegmentInfo;

namespace {

// ---------------------------------------------------------------------------
// Vector A
// ---------------------------------------------------------------------------
// Single segment, single page, two ARM64E rebases (pointer_format = 1,
// DYLD_CHAINED_PTR_ARM64E — stride 8, target is vmaddr).
//
// Image base 0x1_0000_0000. One segment at vmaddr 0x1_0000_8000 (file
// offset 0x8000, size 0x4000). Two pointer slots at file offsets
// 0x8000 and 0x8008.
//
//   slot at file 0x8000: rebase, target=0x100000500, next=1, bind=0,
//                        auth=0  (1 stride of 8 bytes = 8 bytes to next)
//   slot at file 0x8008: rebase, target=0x100000600, next=0 (end of
//                        chain), bind=0, auth=0
//
// dyld_chained_ptr_arm64e_rebase bit layout (LE):
//   target [42:0], high8 [50:43], next [61:51], bind [62], auth [63]
//
// slot 0 raw u64 = target(0x100000500) | (next=1 << 51)
//                = 0x0000_0001_0000_0500 | 0x0008_0000_0000_0000
//                = 0x0008_0001_0000_0500
// slot 1 raw u64 = target(0x100000600)
//                = 0x0000_0001_0000_0600
//
// Expected resolved map:
//   file_addr 0x8000 -> 0x100000500
//   file_addr 0x8008 -> 0x100000600
constexpr std::array<std::uint8_t, 60> kVectorA_payload = {
    // dyld_chained_fixups_header
    0x00, 0x00, 0x00, 0x00,  // fixups_version = 0
    0x1c, 0x00, 0x00, 0x00,  // starts_offset  = 0x1c
    0x3c, 0x00, 0x00, 0x00,  // imports_offset = 0x3c (end; 0 imports)
    0x3c, 0x00, 0x00, 0x00,  // symbols_offset = 0x3c (end; 0 symbols)
    0x00, 0x00, 0x00, 0x00,  // imports_count  = 0
    0x01, 0x00, 0x00, 0x00,  // imports_format = DYLD_CHAINED_IMPORT
    0x00, 0x00, 0x00, 0x00,  // symbols_format = 0 (uncompressed)

    // dyld_chained_starts_in_image @ 0x1c
    0x01, 0x00, 0x00, 0x00,  // seg_count = 1
    0x08, 0x00, 0x00, 0x00,  // seg_info_offset[0] = 8 -> starts_in_segment @ 0x24

    // dyld_chained_starts_in_segment @ 0x24
    0x18, 0x00, 0x00, 0x00,  // size = 24
    0x00, 0x40,              // page_size = 0x4000
    0x01, 0x00,              // pointer_format = DYLD_CHAINED_PTR_ARM64E
    0x00, 0x80, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,  // segment_offset = 0x8000
    0x00, 0x00, 0x00, 0x00,  // max_valid_pointer = 0
    0x01, 0x00,              // page_count = 1
    0x00, 0x00,              // page_start[0] = 0
};

constexpr std::array<std::uint8_t, 16> kVectorA_segment_bytes = {
    // file 0x8000: 0x0008_0001_0000_0500
    0x00, 0x05, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00,
    // file 0x8008: 0x0000_0001_0000_0600
    0x00, 0x06, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
};

// ---------------------------------------------------------------------------
// Vector B
// ---------------------------------------------------------------------------
// Single segment, two pages, with a chain start on each page. Exercises
// the multi-page / multi-start dispatch loop (the path Apple's dyld
// `forEachFixupChainSegment` walks via page_start[i] != START_NONE).
//
// pointer_format = 6 (DYLD_CHAINED_PTR_64_OFFSET — target is runtime
// offset relative to image base, 4-byte stride). Same struct layout as
// dyld_chained_ptr_64_rebase: target [35:0], high8 [43:36], reserved
// [50:44], next [62:51], bind [63].
//
// Image base 0x1_0000_0000. One segment at vmaddr 0x1_0000_4000 (file
// offset 0x4000, size 0x2000 — two 4 KiB pages).
//
//   Page 0:
//     file 0x4000: rebase, target_offset=0x500, next=2 (4-byte strides
//                  = 8 bytes), bind=0
//     file 0x4008: rebase, target_offset=0x600, next=0 (end), bind=0
//   Page 1:
//     file 0x5000: rebase, target_offset=0x700, next=2, bind=0
//     file 0x5008: rebase, target_offset=0x800, next=0, bind=0
//
// slot raw values:
//   0x4000: target(0x500) | (next=2 << 51) = 0x0010_0000_0000_0500
//   0x4008: target(0x600)                  = 0x0000_0000_0000_0600
//   0x5000: target(0x700) | (next=2 << 51) = 0x0010_0000_0000_0700
//   0x5008: target(0x800)                  = 0x0000_0000_0000_0800
//
// Expected resolved (image_base + target):
//   0x4000 -> 0x100000500
//   0x4008 -> 0x100000600
//   0x5000 -> 0x100000700
//   0x5008 -> 0x100000800
constexpr std::array<std::uint8_t, 64> kVectorB_payload = {
    // dyld_chained_fixups_header
    0x00, 0x00, 0x00, 0x00,  // fixups_version = 0
    0x1c, 0x00, 0x00, 0x00,  // starts_offset  = 0x1c
    0x40, 0x00, 0x00, 0x00,  // imports_offset = 0x40 (end)
    0x40, 0x00, 0x00, 0x00,  // symbols_offset = 0x40 (end)
    0x00, 0x00, 0x00, 0x00,  // imports_count  = 0
    0x01, 0x00, 0x00, 0x00,  // imports_format = DYLD_CHAINED_IMPORT
    0x00, 0x00, 0x00, 0x00,  // symbols_format = 0

    // dyld_chained_starts_in_image @ 0x1c
    0x01, 0x00, 0x00, 0x00,  // seg_count = 1
    0x08, 0x00, 0x00, 0x00,  // seg_info_offset[0] = 8 -> @ 0x24

    // dyld_chained_starts_in_segment @ 0x24, size = 28
    0x1c, 0x00, 0x00, 0x00,  // size = 28 (header 24 + 2 extra page_start bytes)
    0x00, 0x10,              // page_size = 0x1000
    0x06, 0x00,              // pointer_format = DYLD_CHAINED_PTR_64_OFFSET
    0x00, 0x40, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,  // segment_offset = 0x4000
    0x00, 0x00, 0x00, 0x00,  // max_valid_pointer = 0
    0x02, 0x00,              // page_count = 2
    0x00, 0x00,              // page_start[0] = 0
    0x00, 0x00,              // page_start[1] = 0
};

constexpr std::array<std::uint8_t, 0x1010> kVectorB_segment_bytes = []{
    std::array<std::uint8_t, 0x1010> out{};
    // file 0x4000 (offset 0 within segment): 0x0010_0000_0000_0500
    out[0x000] = 0x00; out[0x001] = 0x05; out[0x002] = 0x00; out[0x003] = 0x00;
    out[0x004] = 0x00; out[0x005] = 0x00; out[0x006] = 0x10; out[0x007] = 0x00;
    // file 0x4008 (offset 8): 0x0000_0000_0000_0600
    out[0x008] = 0x00; out[0x009] = 0x06; out[0x00a] = 0x00; out[0x00b] = 0x00;
    out[0x00c] = 0x00; out[0x00d] = 0x00; out[0x00e] = 0x00; out[0x00f] = 0x00;
    // file 0x5000 (offset 0x1000): 0x0010_0000_0000_0700
    out[0x1000] = 0x00; out[0x1001] = 0x07; out[0x1002] = 0x00; out[0x1003] = 0x00;
    out[0x1004] = 0x00; out[0x1005] = 0x00; out[0x1006] = 0x10; out[0x1007] = 0x00;
    // file 0x5008 (offset 0x1008): 0x0000_0000_0000_0800
    out[0x1008] = 0x00; out[0x1009] = 0x08; out[0x100a] = 0x00; out[0x100b] = 0x00;
    out[0x100c] = 0x00; out[0x100d] = 0x00; out[0x100e] = 0x00; out[0x100f] = 0x00;
    return out;
}();

// ---------------------------------------------------------------------------
// Vector C
// ---------------------------------------------------------------------------
// Same shape as vector A but with pointer_format = 4
// (DYLD_CHAINED_PTR_32_CACHE — 32-bit dyld-shared-cache format). Phase
// 1 does not support 32-bit pointer formats; the parser must throw
// backend::Error with a "phase 2" message instead of silently producing
// garbage.
constexpr std::array<std::uint8_t, 60> kVectorC_payload = {
    0x00, 0x00, 0x00, 0x00,
    0x1c, 0x00, 0x00, 0x00,
    0x3c, 0x00, 0x00, 0x00,
    0x3c, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,

    0x01, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00,

    0x18, 0x00, 0x00, 0x00,
    0x00, 0x40,
    0x04, 0x00,              // pointer_format = DYLD_CHAINED_PTR_32_CACHE (unsupported)
    0x00, 0x80, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x01, 0x00,
    0x00, 0x00,
};

// ---------------------------------------------------------------------------
// Vector D — ARM64E auth-rebase
// ---------------------------------------------------------------------------
// Format 1 (DYLD_CHAINED_PTR_ARM64E), single slot, auth-rebase variant.
// Closes the coverage gap on decode_arm64e()'s `auth=1, bind=0` branch
// in src/backend/chained_fixups.cpp.
//
// dyld_chained_ptr_arm64e_auth_rebase bit layout (LE):
//   target    [31:0]    — always a runtime offset for auth variants
//   diversity [47:32]   — 16-bit diversifier
//   addrDiv   [48]      — address-diversified flag
//   key       [50:49]   — PAC key (IA/IB/DA/DB)
//   next      [61:51]   — 11-bit stride count
//   bind      [62]      — 0 for auth-rebase
//   auth      [63]      — 1 for auth variant
//
// Image base 0x1_0000_0000. One segment at vmaddr 0x1_0000_8000 (file
// offset 0x8000, size 0x4000). One slot at file 0x8000.
//
//   target = 0x500
//   diversity = 0x1234
//   addrDiv = 0
//   key = 2
//   next = 0 (end of chain)
//   bind = 0
//   auth = 1
//
// raw = 0x8004_1234_0000_0500
//     = (1ULL << 63) | (2ULL << 49) | (0x1234ULL << 32) | 0x500
//
// Expected resolved: image_base + target = 0x100000500.
// (The parser drops auth metadata in phase 1 — only the resolved
// pointer value is recorded; PAC key/diversity belong to phase 2.)
constexpr std::array<std::uint8_t, 60> kVectorD_payload = {
    0x00, 0x00, 0x00, 0x00,
    0x1c, 0x00, 0x00, 0x00,
    0x3c, 0x00, 0x00, 0x00,
    0x3c, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,

    0x01, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00,

    0x18, 0x00, 0x00, 0x00,
    0x00, 0x40,
    0x01, 0x00,              // pointer_format = DYLD_CHAINED_PTR_ARM64E
    0x00, 0x80, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x01, 0x00,
    0x00, 0x00,
};

constexpr std::array<std::uint8_t, 8> kVectorD_segment_bytes = {
    // file 0x8000: 0x8004_1234_0000_0500 (LE)
    0x00, 0x05, 0x00, 0x00, 0x34, 0x12, 0x04, 0x80,
};

// ---------------------------------------------------------------------------
// Vector E — ARM64E_USERLAND (format 9) rebase
// ---------------------------------------------------------------------------
// Format 9 (DYLD_CHAINED_PTR_ARM64E_USERLAND) shares decode_arm64e()
// with format 12 (USERLAND24) but is the path used on macOS/iOS arm64
// builds without USERLAND24 (everything pre macOS 12 / iOS 15). Same
// bit layout as format 1, but rebase targets are runtime offsets
// (image-base-relative) rather than vmaddrs.
//
// dyld_chained_ptr_arm64e_rebase bit layout (LE):
//   target [42:0], high8 [50:43], next [61:51], bind [62], auth [63]
//
// Image base 0x1_0000_0000. One segment at vmaddr 0x1_0000_8000 (file
// offset 0x8000, size 0x4000). One slot at file 0x8000.
//
//   target = 0x600 (runtime offset — added to image_base)
//   high8 = 0
//   next = 0 (end of chain)
//   bind = 0
//   auth = 0
//
// raw = 0x0000_0000_0000_0600
//
// Expected resolved: image_base + target = 0x100000600.
constexpr std::array<std::uint8_t, 60> kVectorE_payload = {
    0x00, 0x00, 0x00, 0x00,
    0x1c, 0x00, 0x00, 0x00,
    0x3c, 0x00, 0x00, 0x00,
    0x3c, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,

    0x01, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00,

    0x18, 0x00, 0x00, 0x00,
    0x00, 0x40,
    0x09, 0x00,              // pointer_format = DYLD_CHAINED_PTR_ARM64E_USERLAND
    0x00, 0x80, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x01, 0x00,
    0x00, 0x00,
};

constexpr std::array<std::uint8_t, 8> kVectorE_segment_bytes = {
    // file 0x8000: 0x0000_0000_0000_0600 (LE)
    0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

}  // namespace

TEST_CASE("parse_chained_fixups: ARM64E single-page two-rebase chain",
          "[chained_fixups]") {
  std::vector<SegmentInfo> segs(1);
  segs[0].vm_addr     = 0x100008000;
  segs[0].vm_size     = 0x4000;
  segs[0].data        = kVectorA_segment_bytes.data();
  segs[0].data_size   = kVectorA_segment_bytes.size();

  ChainedFixupMap m = parse_chained_fixups(
      kVectorA_payload.data(), kVectorA_payload.size(), segs);

  REQUIRE(m.resolved.size() == 2);
  CHECK(m.resolved.at(0x8000) == 0x100000500ULL);
  CHECK(m.resolved.at(0x8008) == 0x100000600ULL);
  // image_base derived from segment[0]: vm_addr 0x100008000 -
  // segment_offset 0x8000 = 0x100000000. xref's slot-load resolver
  // reads this field rather than re-deriving from LLDB's section table.
  CHECK(m.image_base == 0x100000000ULL);
}

TEST_CASE("parse_chained_fixups: 64_OFFSET multi-page chain",
          "[chained_fixups]") {
  std::vector<SegmentInfo> segs(1);
  segs[0].vm_addr     = 0x100004000;
  segs[0].vm_size     = 0x2000;
  segs[0].data        = kVectorB_segment_bytes.data();
  segs[0].data_size   = kVectorB_segment_bytes.size();

  ChainedFixupMap m = parse_chained_fixups(
      kVectorB_payload.data(), kVectorB_payload.size(), segs);

  REQUIRE(m.resolved.size() == 4);
  CHECK(m.resolved.at(0x4000) == 0x100000500ULL);
  CHECK(m.resolved.at(0x4008) == 0x100000600ULL);
  CHECK(m.resolved.at(0x5000) == 0x100000700ULL);
  CHECK(m.resolved.at(0x5008) == 0x100000800ULL);
}

TEST_CASE("parse_chained_fixups: ARM64E auth-rebase single slot",
          "[chained_fixups]") {
  std::vector<SegmentInfo> segs(1);
  segs[0].vm_addr     = 0x100008000;
  segs[0].vm_size     = 0x4000;
  segs[0].data        = kVectorD_segment_bytes.data();
  segs[0].data_size   = kVectorD_segment_bytes.size();

  ChainedFixupMap m = parse_chained_fixups(
      kVectorD_payload.data(), kVectorD_payload.size(), segs);

  REQUIRE(m.resolved.size() == 1);
  CHECK(m.resolved.at(0x8000) == 0x100000500ULL);
}

TEST_CASE("parse_chained_fixups: ARM64E_USERLAND (format 9) rebase",
          "[chained_fixups]") {
  std::vector<SegmentInfo> segs(1);
  segs[0].vm_addr     = 0x100008000;
  segs[0].vm_size     = 0x4000;
  segs[0].data        = kVectorE_segment_bytes.data();
  segs[0].data_size   = kVectorE_segment_bytes.size();

  ChainedFixupMap m = parse_chained_fixups(
      kVectorE_payload.data(), kVectorE_payload.size(), segs);

  REQUIRE(m.resolved.size() == 1);
  CHECK(m.resolved.at(0x8000) == 0x100000600ULL);
}

TEST_CASE("parse_chained_fixups: unsupported format reports phase 2",
          "[chained_fixups][error]") {
  std::vector<SegmentInfo> segs(1);
  segs[0].vm_addr     = 0x100008000;
  segs[0].vm_size     = 0x4000;
  segs[0].data        = nullptr;
  segs[0].data_size   = 0;

  try {
    (void)parse_chained_fixups(
        kVectorC_payload.data(), kVectorC_payload.size(), segs);
    FAIL("expected backend::Error for unsupported pointer format");
  } catch (const Error& e) {
    std::string msg = e.what();
    CHECK(msg.find("phase 2") != std::string::npos);
    CHECK(msg.find("unsupported") != std::string::npos);
  }
}

// ---------------------------------------------------------------------------
// extract_chained_fixups_from_macho — Mach-O wrapper used by the xref
// wire-up (docs/35-field-report-followups.md §3 phase 2).
// ---------------------------------------------------------------------------

TEST_CASE("extract_chained_fixups_from_macho: empty/non-Mach-O is a no-op",
          "[chained_fixups][macho]") {
  using ldb::backend::extract_chained_fixups_from_macho;

  // Null / empty: empty map, no throw. image_base stays at the
  // ChainedFixupMap default (0) so the xref slot-load resolver's
  // (file_addr >= image_base) gate short-circuits to no-match.
  auto m1 = extract_chained_fixups_from_macho(nullptr, 0);
  CHECK(m1.resolved.empty());
  CHECK(m1.image_base == 0ULL);

  // ELF magic — not a Mach-O. Caller treats this as "binary doesn't
  // use chained fixups" rather than an error.
  std::array<std::uint8_t, 64> elf{};
  elf[0] = 0x7f; elf[1] = 'E'; elf[2] = 'L'; elf[3] = 'F';
  auto m2 = extract_chained_fixups_from_macho(elf.data(), elf.size());
  CHECK(m2.resolved.empty());
  CHECK(m2.image_base == 0ULL);
}

TEST_CASE("extract_chained_fixups_from_macho: minimal arm64 Mach-O round-trip",
          "[chained_fixups][macho]") {
  using ldb::backend::extract_chained_fixups_from_macho;

  // Build a minimal arm64 Mach-O image in memory:
  //   - mach_header_64 (32 bytes)
  //   - one LC_SEGMENT_64 covering the file from offset 0x100..0x110
  //     (vmaddr 0x100008000, filesize 0x10, vmsize 0x4000) — this is
  //     where the chained-pointer slot lives.
  //   - one LC_DYLD_CHAINED_FIXUPS pointing at the same payload bytes
  //     as Vector A from the parser test (ARM64E, two rebases).
  // Layout decisions are encoded in offset constants to keep the
  // hand-built header readable.
  constexpr std::size_t kHeader     = 32;
  // segment_command_64 is 72 bytes:
  //   cmd/cmdsize/segname(16)/vmaddr/vmsize/fileoff/filesize/maxprot/
  //   initprot/nsects/flags. Anything shorter would truncate the maxprot
  //   tail that the parser doesn't currently read but a future check
  //   might. Keep the test in sync with the parser's structural minimum.
  constexpr std::size_t kSegCmdSize = 72;
  constexpr std::size_t kFixCmdSize = 16;   // linkedit_data_command
  constexpr std::size_t kCmdEnd     = kHeader + kSegCmdSize + kFixCmdSize;
  constexpr std::size_t kSegOff     = 0x100;
  constexpr std::size_t kSegSize    = 0x10;
  constexpr std::size_t kFixOff     = 0x200;
  constexpr std::size_t kFileSize   = kFixOff + kVectorA_payload.size();

  std::vector<std::uint8_t> macho(kFileSize, 0);

  auto put_u32 = [&](std::size_t off, std::uint32_t v) {
    macho[off + 0] = static_cast<std::uint8_t>(v & 0xff);
    macho[off + 1] = static_cast<std::uint8_t>((v >> 8) & 0xff);
    macho[off + 2] = static_cast<std::uint8_t>((v >> 16) & 0xff);
    macho[off + 3] = static_cast<std::uint8_t>((v >> 24) & 0xff);
  };
  auto put_u64 = [&](std::size_t off, std::uint64_t v) {
    for (std::size_t i = 0; i < 8; ++i) {
      macho[off + i] = static_cast<std::uint8_t>((v >> (i * 8)) & 0xff);
    }
  };

  // mach_header_64
  put_u32(0,  0xFEEDFACF);    // magic = MH_MAGIC_64
  put_u32(4,  0x0100000C);    // cputype = CPU_TYPE_ARM64 (unused by extractor)
  put_u32(8,  0);             // cpusubtype
  put_u32(12, 2);             // filetype = MH_EXECUTE (unused)
  put_u32(16, 2);             // ncmds = 2 (LC_SEGMENT_64, LC_DYLD_CHAINED_FIXUPS)
  put_u32(20, kSegCmdSize + kFixCmdSize);  // sizeofcmds
  put_u32(24, 0);             // flags
  put_u32(28, 0);             // reserved

  // LC_SEGMENT_64
  std::size_t off = kHeader;
  put_u32(off + 0, 0x19);                  // cmd = LC_SEGMENT_64
  put_u32(off + 4, kSegCmdSize);           // cmdsize
  // segname[16] is zero-filled which is fine for the extractor.
  put_u64(off + 24, 0x100008000ULL);       // vmaddr  (matches Vector A)
  put_u64(off + 32, 0x4000ULL);            // vmsize
  put_u64(off + 40, kSegOff);              // fileoff
  put_u64(off + 48, kSegSize);             // filesize

  // LC_DYLD_CHAINED_FIXUPS
  off += kSegCmdSize;
  put_u32(off + 0, 0x80000034);            // cmd
  put_u32(off + 4, kFixCmdSize);           // cmdsize
  put_u32(off + 8, kFixOff);               // dataoff
  put_u32(off + 12, kVectorA_payload.size());  // datasize

  static_assert(kCmdEnd <= kSegOff, "load commands must fit before segment");

  // Segment payload — the chained-pointer slots Vector A expects.
  for (std::size_t i = 0; i < kVectorA_segment_bytes.size() && i < kSegSize; ++i) {
    macho[kSegOff + i] = kVectorA_segment_bytes[i];
  }

  // LC_DYLD_CHAINED_FIXUPS payload — same bytes as Vector A.
  for (std::size_t i = 0; i < kVectorA_payload.size(); ++i) {
    macho[kFixOff + i] = kVectorA_payload[i];
  }

  ChainedFixupMap m = extract_chained_fixups_from_macho(macho.data(),
                                                        macho.size());
  REQUIRE(m.resolved.size() == 2);
  CHECK(m.resolved.at(0x8000) == 0x100000500ULL);
  CHECK(m.resolved.at(0x8008) == 0x100000600ULL);
}
