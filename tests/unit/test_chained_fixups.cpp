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

// ---------------------------------------------------------------------------
// FAT (universal) Mach-O slice selection
// (docs/35-field-report-followups.md §3 phase 3 gate 5).
// ---------------------------------------------------------------------------

namespace {

// Build the same minimal arm64 Mach-O the round-trip test uses, but
// at a configurable offset within an outer buffer and with a settable
// vmaddr (so the FAT test can verify the right slice was picked by
// the image_base it produces). Returns the absolute slice size in
// bytes; the caller has reserved space at `buf[offset..offset+size]`.
std::size_t emit_thin_arm64_macho(std::vector<std::uint8_t>& buf,
                                  std::size_t offset,
                                  std::uint64_t vmaddr_base) {
  constexpr std::size_t kHeader     = 32;
  constexpr std::size_t kSegCmdSize = 72;
  constexpr std::size_t kFixCmdSize = 16;
  constexpr std::size_t kSegOff     = 0x100;
  constexpr std::size_t kSegSize    = 0x10;
  constexpr std::size_t kFixOff     = 0x200;
  const std::size_t kFileSize = kFixOff + kVectorA_payload.size();
  REQUIRE(offset + kFileSize <= buf.size());

  auto put_u32 = [&](std::size_t off, std::uint32_t v) {
    buf[offset + off + 0] = static_cast<std::uint8_t>(v & 0xff);
    buf[offset + off + 1] = static_cast<std::uint8_t>((v >> 8) & 0xff);
    buf[offset + off + 2] = static_cast<std::uint8_t>((v >> 16) & 0xff);
    buf[offset + off + 3] = static_cast<std::uint8_t>((v >> 24) & 0xff);
  };
  auto put_u64 = [&](std::size_t off, std::uint64_t v) {
    for (std::size_t i = 0; i < 8; ++i) {
      buf[offset + off + i] =
          static_cast<std::uint8_t>((v >> (i * 8)) & 0xff);
    }
  };

  put_u32(0,  0xFEEDFACF);
  put_u32(4,  0x0100000C);    // CPU_TYPE_ARM64
  put_u32(8,  0);
  put_u32(12, 2);
  put_u32(16, 2);
  put_u32(20, kSegCmdSize + kFixCmdSize);
  put_u32(24, 0);
  put_u32(28, 0);

  std::size_t off = kHeader;
  put_u32(off + 0, 0x19);                  // LC_SEGMENT_64
  put_u32(off + 4, kSegCmdSize);
  put_u64(off + 24, vmaddr_base + 0x8000);
  put_u64(off + 32, 0x4000ULL);
  put_u64(off + 40, kSegOff);
  put_u64(off + 48, kSegSize);

  off += kSegCmdSize;
  put_u32(off + 0, 0x80000034);
  put_u32(off + 4, kFixCmdSize);
  put_u32(off + 8, kFixOff);
  put_u32(off + 12, kVectorA_payload.size());

  for (std::size_t i = 0; i < kVectorA_segment_bytes.size() && i < kSegSize; ++i) {
    buf[offset + kSegOff + i] = kVectorA_segment_bytes[i];
  }
  for (std::size_t i = 0; i < kVectorA_payload.size(); ++i) {
    buf[offset + kFixOff + i] = kVectorA_payload[i];
  }

  return kFileSize;
}

// Write a 32-bit big-endian value into buf[off..off+4].
void put_u32_be(std::vector<std::uint8_t>& buf, std::size_t off,
                std::uint32_t v) {
  buf[off + 0] = static_cast<std::uint8_t>((v >> 24) & 0xff);
  buf[off + 1] = static_cast<std::uint8_t>((v >> 16) & 0xff);
  buf[off + 2] = static_cast<std::uint8_t>((v >> 8) & 0xff);
  buf[off + 3] = static_cast<std::uint8_t>(v & 0xff);
}

void put_u64_be(std::vector<std::uint8_t>& buf, std::size_t off,
                std::uint64_t v) {
  put_u32_be(buf, off + 0, static_cast<std::uint32_t>(v >> 32));
  put_u32_be(buf, off + 4, static_cast<std::uint32_t>(v & 0xffffffffULL));
}

}  // namespace

TEST_CASE("extract_chained_fixups_from_macho: FAT picks arm64 slice",
          "[chained_fixups][macho][fat]") {
  using ldb::backend::extract_chained_fixups_from_macho;

  // Layout:
  //   [0..0x10)       fat_header (magic=CAFEBABE, nfat_arch=2) +
  //                   one fat_arch entry (20 bytes).
  //   We use the 8-byte header + 2*20 = 48 bytes table = 56 bytes total
  //   of FAT preamble. Round up to a page-ish offset for clarity:
  //   the first slice lives at 0x1000.
  //
  // Slice 0 (offset 0x1000) — CPU_TYPE_X86_64, no chained fixups (we
  // leave the slice bytes zero; the thin parser will reject the
  // magic and return empty).
  //
  // Slice 1 (offset 0x2000) — CPU_TYPE_ARM64, emit_thin_arm64_macho
  // with vmaddr_base = 0x1_0000_0000 so the image_base ends up 4 GB
  // (the same as Vector A's expected image_base).
  //
  // Acceptance:
  //   - resolved is non-empty (arm64 slice picked, not x86_64).
  //   - resolved.at(0x8000) == 0x100000500 (Vector A's chain target).

  constexpr std::size_t kSlice0Off = 0x1000;
  constexpr std::size_t kSlice0Size = 0x800;  // dummy junk
  constexpr std::size_t kSlice1Off = 0x2000;
  constexpr std::size_t kSlice1Size = 0x300;  // fits the emit_thin output
  std::vector<std::uint8_t> fat(kSlice1Off + kSlice1Size, 0);

  // fat_header (big-endian)
  put_u32_be(fat, 0, 0xCAFEBABE);
  put_u32_be(fat, 4, 2);

  // fat_arch entries (big-endian, 20 bytes each)
  // Slice 0: x86_64, offset 0x1000, size 0x800
  put_u32_be(fat,  8, 0x01000007);  // cputype = CPU_TYPE_X86_64
  put_u32_be(fat, 12, 3);            // cpusubtype (irrelevant)
  put_u32_be(fat, 16, kSlice0Off);
  put_u32_be(fat, 20, kSlice0Size);
  put_u32_be(fat, 24, 12);           // align (page = 2^12)

  // Slice 1: arm64, offset 0x2000, size 0x300
  put_u32_be(fat, 28, 0x0100000C);   // cputype = CPU_TYPE_ARM64
  put_u32_be(fat, 32, 0);            // cpusubtype = ARM64_ALL (not E)
  put_u32_be(fat, 36, kSlice1Off);
  put_u32_be(fat, 40, kSlice1Size);
  put_u32_be(fat, 44, 12);

  // Emit the arm64 slice payload at offset 0x2000.
  std::size_t emitted =
      emit_thin_arm64_macho(fat, kSlice1Off, 0x100000000ULL);
  CHECK(emitted <= kSlice1Size);

  ChainedFixupMap m =
      extract_chained_fixups_from_macho(fat.data(), fat.size());
  REQUIRE(m.resolved.size() == 2);
  CHECK(m.resolved.at(0x8000) == 0x100000500ULL);
  CHECK(m.resolved.at(0x8008) == 0x100000600ULL);
  CHECK(m.image_base == 0x100000000ULL);
}

TEST_CASE("extract_chained_fixups_from_macho: FAT prefers arm64e over arm64",
          "[chained_fixups][macho][fat]") {
  using ldb::backend::extract_chained_fixups_from_macho;

  // Two slices, both arm64. Slice 0 is arm64e (cpusubtype=2),
  // Slice 1 is arm64-all (cpusubtype=0). The arm64e slice has a
  // distinct image_base so the assertion below can prove which slice
  // was picked. Phase-3 acceptance: arm64e wins.

  constexpr std::size_t kSlice0Off = 0x1000;
  constexpr std::size_t kSlice1Off = 0x2000;
  constexpr std::size_t kSliceSize = 0x300;
  std::vector<std::uint8_t> fat(kSlice1Off + kSliceSize, 0);

  put_u32_be(fat, 0, 0xCAFEBABE);
  put_u32_be(fat, 4, 2);

  // Slice 0: arm64e (subtype 2), vmaddr base 0x100000000
  put_u32_be(fat,  8, 0x0100000C);
  put_u32_be(fat, 12, 2);                 // arm64e
  put_u32_be(fat, 16, kSlice0Off);
  put_u32_be(fat, 20, kSliceSize);
  put_u32_be(fat, 24, 12);

  // Slice 1: arm64-all, vmaddr base 0x200000000 (distinct base)
  put_u32_be(fat, 28, 0x0100000C);
  put_u32_be(fat, 32, 0);
  put_u32_be(fat, 36, kSlice1Off);
  put_u32_be(fat, 40, kSliceSize);
  put_u32_be(fat, 44, 12);

  emit_thin_arm64_macho(fat, kSlice0Off, 0x100000000ULL);
  emit_thin_arm64_macho(fat, kSlice1Off, 0x200000000ULL);

  ChainedFixupMap m =
      extract_chained_fixups_from_macho(fat.data(), fat.size());
  REQUIRE(m.resolved.size() == 2);
  // image_base proves arm64e (slice 0) was picked, not arm64 (slice 1).
  CHECK(m.image_base == 0x100000000ULL);
}

TEST_CASE("extract_chained_fixups_from_macho: malformed FAT is a no-op",
          "[chained_fixups][macho][fat]") {
  using ldb::backend::extract_chained_fixups_from_macho;

  // nfat_arch too large — phase-3 guard caps at 16; 17 is rejected.
  std::vector<std::uint8_t> fat(8 + 17 * 20, 0);
  put_u32_be(fat, 0, 0xCAFEBABE);
  put_u32_be(fat, 4, 17);
  ChainedFixupMap m =
      extract_chained_fixups_from_macho(fat.data(), fat.size());
  CHECK(m.resolved.empty());

  // arch_offset + size past EOF — slice is invalid; the FAT picker
  // skips it and falls through to the (empty) "no arm64 with fixups"
  // result.
  std::vector<std::uint8_t> oob(8 + 20, 0);
  put_u32_be(oob, 0, 0xCAFEBABE);
  put_u32_be(oob, 4, 1);
  put_u32_be(oob,  8, 0x0100000C);
  put_u32_be(oob, 12, 0);
  put_u32_be(oob, 16, 0x10000);    // offset way past EOF
  put_u32_be(oob, 20, 0x1000);
  put_u32_be(oob, 24, 12);
  ChainedFixupMap m2 =
      extract_chained_fixups_from_macho(oob.data(), oob.size());
  CHECK(m2.resolved.empty());
}

TEST_CASE("extract_chained_fixups_from_macho: FAT64 (cafebabf) picks arm64 slice",
          "[chained_fixups][macho][fat][fat64]") {
  using ldb::backend::extract_chained_fixups_from_macho;

  // FAT64 layout: 8-byte header (magic=CAFEBABF, nfat_arch) plus
  // 32-byte fat_arch_64 entries (cputype, cpusubtype, offset:u64,
  // size:u64, align, reserved). The 64-bit offset/size path is
  // exercised here — N8 post-review nit: the prior FAT tests only
  // covered the 32-bit fat_arch path.
  //
  // Single arm64 slice (no preference disambiguation needed); the
  // assertion is that the picker correctly reads the 64-bit offset
  // and lands on the right Mach-O.

  constexpr std::uint64_t kSliceOff = 0x4000;
  constexpr std::uint64_t kSliceSize = 0x300;
  std::vector<std::uint8_t> fat(kSliceOff + kSliceSize, 0);

  // fat_header (big-endian)
  put_u32_be(fat, 0, 0xCAFEBABF);  // FAT64 magic
  put_u32_be(fat, 4, 1);

  // fat_arch_64 entry (big-endian, 32 bytes)
  //   off 0:  cputype     (u32)
  //   off 4:  cpusubtype  (u32)
  //   off 8:  offset      (u64)
  //   off 16: size        (u64)
  //   off 24: align       (u32)
  //   off 28: reserved    (u32)
  put_u32_be(fat,  8, 0x0100000C);   // cputype = CPU_TYPE_ARM64
  put_u32_be(fat, 12, 0);            // cpusubtype = ARM64_ALL
  put_u64_be(fat, 16, kSliceOff);
  put_u64_be(fat, 24, kSliceSize);
  put_u32_be(fat, 32, 12);
  put_u32_be(fat, 36, 0);

  emit_thin_arm64_macho(fat, kSliceOff, 0x100000000ULL);

  ChainedFixupMap m =
      extract_chained_fixups_from_macho(fat.data(), fat.size());
  REQUIRE(m.resolved.size() == 2);
  CHECK(m.resolved.at(0x8000) == 0x100000500ULL);
  CHECK(m.resolved.at(0x8008) == 0x100000600ULL);
  CHECK(m.image_base == 0x100000000ULL);
}

// ---------------------------------------------------------------------------
// FAT triple-aware slice selection
// (docs/35-field-report-followups.md §3 phase 4 item 2).
// ---------------------------------------------------------------------------

TEST_CASE("extract_chained_fixups_from_macho: FAT picks arm64 slice when "
          "triple says arm64",
          "[chained_fixups][macho][fat][triple]") {
  using ldb::backend::extract_chained_fixups_from_macho;

  // Same FAT layout as "FAT prefers arm64e over arm64" but with an
  // arm64-targeted triple. Phase 4: the triple should override the
  // phase-3 arm64e-first default and pick the plain arm64 slice.
  // image_base proves the right slice was selected.
  constexpr std::size_t kSlice0Off = 0x1000;
  constexpr std::size_t kSlice1Off = 0x2000;
  constexpr std::size_t kSliceSize = 0x300;
  std::vector<std::uint8_t> fat(kSlice1Off + kSliceSize, 0);

  put_u32_be(fat, 0, 0xCAFEBABE);
  put_u32_be(fat, 4, 2);

  // Slice 0: arm64e (subtype 2), vmaddr base 0x100000000
  put_u32_be(fat,  8, 0x0100000C);
  put_u32_be(fat, 12, 2);
  put_u32_be(fat, 16, kSlice0Off);
  put_u32_be(fat, 20, kSliceSize);
  put_u32_be(fat, 24, 12);

  // Slice 1: arm64-all, vmaddr base 0x200000000
  put_u32_be(fat, 28, 0x0100000C);
  put_u32_be(fat, 32, 0);
  put_u32_be(fat, 36, kSlice1Off);
  put_u32_be(fat, 40, kSliceSize);
  put_u32_be(fat, 44, 12);

  emit_thin_arm64_macho(fat, kSlice0Off, 0x100000000ULL);
  emit_thin_arm64_macho(fat, kSlice1Off, 0x200000000ULL);

  // Triple says arm64 (no 'e') — slice 1's image_base must come back.
  ChainedFixupMap m =
      extract_chained_fixups_from_macho(fat.data(), fat.size(),
                                         "arm64-apple-macosx14.0.0");
  REQUIRE(m.resolved.size() == 2);
  CHECK(m.image_base == 0x200000000ULL);
}

TEST_CASE("extract_chained_fixups_from_macho: FAT picks arm64e slice when "
          "triple says arm64e",
          "[chained_fixups][macho][fat][triple]") {
  using ldb::backend::extract_chained_fixups_from_macho;

  // Inverse of the test above — explicit arm64e triple still lands on
  // slice 0 (which would also be the default).
  constexpr std::size_t kSlice0Off = 0x1000;
  constexpr std::size_t kSlice1Off = 0x2000;
  constexpr std::size_t kSliceSize = 0x300;
  std::vector<std::uint8_t> fat(kSlice1Off + kSliceSize, 0);

  put_u32_be(fat, 0, 0xCAFEBABE);
  put_u32_be(fat, 4, 2);

  put_u32_be(fat,  8, 0x0100000C);
  put_u32_be(fat, 12, 2);
  put_u32_be(fat, 16, kSlice0Off);
  put_u32_be(fat, 20, kSliceSize);
  put_u32_be(fat, 24, 12);

  put_u32_be(fat, 28, 0x0100000C);
  put_u32_be(fat, 32, 0);
  put_u32_be(fat, 36, kSlice1Off);
  put_u32_be(fat, 40, kSliceSize);
  put_u32_be(fat, 44, 12);

  emit_thin_arm64_macho(fat, kSlice0Off, 0x100000000ULL);
  emit_thin_arm64_macho(fat, kSlice1Off, 0x200000000ULL);

  ChainedFixupMap m =
      extract_chained_fixups_from_macho(fat.data(), fat.size(),
                                         "arm64e-apple-macosx14.0.0");
  REQUIRE(m.resolved.size() == 2);
  CHECK(m.image_base == 0x100000000ULL);
}

TEST_CASE("extract_chained_fixups_from_macho: empty triple falls back to "
          "phase-3 preference order",
          "[chained_fixups][macho][fat][triple]") {
  using ldb::backend::extract_chained_fixups_from_macho;

  // No triple — same as phase 3's default: arm64e wins. This pins the
  // backward-compatible no-op case so existing callers (the ones that
  // don't yet plumb SBTarget::GetTriple() through) keep behaving
  // identically.
  constexpr std::size_t kSlice0Off = 0x1000;
  constexpr std::size_t kSlice1Off = 0x2000;
  constexpr std::size_t kSliceSize = 0x300;
  std::vector<std::uint8_t> fat(kSlice1Off + kSliceSize, 0);

  put_u32_be(fat, 0, 0xCAFEBABE);
  put_u32_be(fat, 4, 2);

  put_u32_be(fat,  8, 0x0100000C);
  put_u32_be(fat, 12, 2);
  put_u32_be(fat, 16, kSlice0Off);
  put_u32_be(fat, 20, kSliceSize);
  put_u32_be(fat, 24, 12);

  put_u32_be(fat, 28, 0x0100000C);
  put_u32_be(fat, 32, 0);
  put_u32_be(fat, 36, kSlice1Off);
  put_u32_be(fat, 40, kSliceSize);
  put_u32_be(fat, 44, 12);

  emit_thin_arm64_macho(fat, kSlice0Off, 0x100000000ULL);
  emit_thin_arm64_macho(fat, kSlice1Off, 0x200000000ULL);

  // Empty triple — preserves phase-3 default (arm64e first).
  ChainedFixupMap m =
      extract_chained_fixups_from_macho(fat.data(), fat.size());
  REQUIRE(m.resolved.size() == 2);
  CHECK(m.image_base == 0x100000000ULL);
}

// ---------------------------------------------------------------------------
// BindInfo schema (docs/35-field-report-followups.md §3 phase 4 item 6)
// ---------------------------------------------------------------------------

TEST_CASE("BindInfo schema is default-constructible and empty",
          "[chained_fixups][binds][schema]") {
  // Phase 4 ships the schema; phase 5 populates it. This pins the
  // default-constructed shape so callers can rely on the absent-bind
  // field semantics (empty name, addend 0, ordinal 0, no resolved_addr).
  ldb::backend::BindInfo b;
  CHECK(b.name.empty());
  CHECK(b.addend == 0);
  CHECK(b.ordinal == 0);
  CHECK_FALSE(b.resolved_addr.has_value());
}

TEST_CASE("ChainedFixupMap.binds is empty by default (phase 4)",
          "[chained_fixups][binds][schema]") {
  // The binds map is wired into ChainedFixupMap but populated only by
  // phase 5's imports-table walk. Today's parser leaves it empty.
  // This test exists so a future phase-5 commit can prove its
  // population logic fires by flipping this assertion red.
  ldb::backend::ChainedFixupMap m;
  CHECK(m.binds.empty());
}

TEST_CASE("parse_chained_fixups leaves binds empty (phase 4 schema only)",
          "[chained_fixups][binds][schema]") {
  // Use vector A — a Mach-O with two ARM64E rebases and zero binds.
  // The parser produces a non-empty resolved map and an empty binds
  // map. Phase 5 will flip the test for vectors that carry actual
  // bind entries (e.g. a synthetic vector with imports_count > 0).
  std::vector<SegmentInfo> segs(1);
  segs[0].vm_addr     = 0x100008000;
  segs[0].vm_size     = 0x4000;
  segs[0].data        = kVectorA_segment_bytes.data();
  segs[0].data_size   = kVectorA_segment_bytes.size();

  ChainedFixupMap m = parse_chained_fixups(
      kVectorA_payload.data(), kVectorA_payload.size(), segs);

  REQUIRE(m.resolved.size() == 2);
  CHECK(m.binds.empty());
}

TEST_CASE("extract_chained_fixups_from_macho: triple-matching slice missing "
          "falls back to preference order",
          "[chained_fixups][macho][fat][triple]") {
  using ldb::backend::extract_chained_fixups_from_macho;

  // FAT with only an arm64e slice. Triple says arm64. NO arm64 slice
  // exists in the FAT — fall back to phase-3 preference (arm64e).
  // This is the legitimate fallback path: when the FAT carries no
  // slice the triple matches, we'd rather surface SOMETHING than
  // nothing.
  constexpr std::size_t kSlice0Off = 0x1000;
  constexpr std::size_t kSliceSize = 0x300;
  std::vector<std::uint8_t> fat(kSlice0Off + kSliceSize, 0);

  put_u32_be(fat, 0, 0xCAFEBABE);
  put_u32_be(fat, 4, 1);

  put_u32_be(fat,  8, 0x0100000C);
  put_u32_be(fat, 12, 2);                 // arm64e
  put_u32_be(fat, 16, kSlice0Off);
  put_u32_be(fat, 20, kSliceSize);
  put_u32_be(fat, 24, 12);

  emit_thin_arm64_macho(fat, kSlice0Off, 0x100000000ULL);

  ChainedFixupMap m =
      extract_chained_fixups_from_macho(fat.data(), fat.size(),
                                         "arm64-apple-ios13.0");
  REQUIRE(m.resolved.size() == 2);
  CHECK(m.image_base == 0x100000000ULL);
}

// Emit a minimal arm64 Mach-O with one LC_SEGMENT_64 and NO chained
// fixups. The parser walks the load commands; without
// LC_DYLD_CHAINED_FIXUPS it returns ChainedFixupMap{} (empty
// resolved/binds, image_base from segments). Used to construct the
// "FAT slice exists but has no chained fixups" scenario for the C5
// regression test below.
std::size_t emit_thin_arm64_macho_no_fixups(std::vector<std::uint8_t>& buf,
                                             std::size_t offset,
                                             std::uint64_t vmaddr_base) {
  constexpr std::size_t kHeader     = 32;
  constexpr std::size_t kSegCmdSize = 72;
  constexpr std::size_t kSegOff     = 0x100;
  constexpr std::size_t kSegSize    = 0x10;
  const std::size_t kFileSize = kSegOff + kSegSize;
  REQUIRE(offset + kFileSize <= buf.size());

  auto put_u32 = [&](std::size_t off, std::uint32_t v) {
    buf[offset + off + 0] = static_cast<std::uint8_t>(v & 0xff);
    buf[offset + off + 1] = static_cast<std::uint8_t>((v >> 8) & 0xff);
    buf[offset + off + 2] = static_cast<std::uint8_t>((v >> 16) & 0xff);
    buf[offset + off + 3] = static_cast<std::uint8_t>((v >> 24) & 0xff);
  };
  auto put_u64 = [&](std::size_t off, std::uint64_t v) {
    for (std::size_t i = 0; i < 8; ++i) {
      buf[offset + off + i] =
          static_cast<std::uint8_t>((v >> (i * 8)) & 0xff);
    }
  };

  put_u32(0,  0xFEEDFACF);          // MH_MAGIC_64
  put_u32(4,  0x0100000C);          // CPU_TYPE_ARM64
  put_u32(8,  0);                   // cpu_subtype = ARM64_ALL
  put_u32(12, 2);                   // filetype = MH_EXECUTE
  put_u32(16, 1);                   // ncmds = 1 (one LC_SEGMENT_64)
  put_u32(20, kSegCmdSize);
  put_u32(24, 0);
  put_u32(28, 0);

  std::size_t off = kHeader;
  put_u32(off + 0, 0x19);            // LC_SEGMENT_64
  put_u32(off + 4, kSegCmdSize);
  put_u64(off + 24, vmaddr_base + 0x8000);
  put_u64(off + 32, 0x4000ULL);
  put_u64(off + 40, kSegOff);
  put_u64(off + 48, kSegSize);
  // No LC_DYLD_CHAINED_FIXUPS — that's the whole point.

  return kFileSize;
}

TEST_CASE("extract_chained_fixups_from_macho: triple-matched slice WITHOUT "
          "chained fixups wins (C5 silent-wrong-result fix)",
          "[chained_fixups][macho][fat][triple]") {
  using ldb::backend::extract_chained_fixups_from_macho;

  // The C5 silent-wrong-result regression
  // (docs/35-field-report-followups.md §3 phase-4 cleanup C5):
  // a FAT with both an arm64 slice (LC_DYLD_INFO_ONLY-era, no
  // chained fixups) and an arm64e slice (with chained fixups). The
  // triple says arm64 — LLDB loaded the arm64 slice and its
  // image_base is the source of truth for the xref scan. The buggy
  // phase-4 code returned the arm64 slice's empty parse only if
  // resolved was non-empty; otherwise it silently fell through to
  // the arm64e slice's parse and returned arm64e's image_base, which
  // is the wrong basis for the arm64 binary the agent is analysing.
  //
  // Post-cleanup: a triple-matched slice's parse wins UNCONDITIONALLY
  // — even when its chained-fixup map is empty. The caller then
  // gets ChainedFixupMap{} (no chained-fixup-based xref resolution)
  // and the literal-operand / ADRP-pair scan runs against the
  // CORRECT image_base.
  constexpr std::size_t kSlice0Off = 0x1000;   // arm64 (no fixups)
  constexpr std::size_t kSlice1Off = 0x2000;   // arm64e (with fixups)
  constexpr std::size_t kSliceSize = 0x300;
  std::vector<std::uint8_t> fat(kSlice1Off + kSliceSize, 0);

  put_u32_be(fat, 0, 0xCAFEBABE);
  put_u32_be(fat, 4, 2);

  // Slice 0: arm64 (cpu_type=0x0100000C, cpu_subtype=0).
  put_u32_be(fat,  8, 0x0100000C);
  put_u32_be(fat, 12, 0);
  put_u32_be(fat, 16, kSlice0Off);
  put_u32_be(fat, 20, kSliceSize);
  put_u32_be(fat, 24, 12);

  // Slice 1: arm64e (cpu_type=0x0100000C, cpu_subtype=2).
  put_u32_be(fat, 28, 0x0100000C);
  put_u32_be(fat, 32, 2);
  put_u32_be(fat, 36, kSlice1Off);
  put_u32_be(fat, 40, kSliceSize);
  put_u32_be(fat, 44, 12);

  emit_thin_arm64_macho_no_fixups(fat, kSlice0Off, 0x100000000ULL);
  emit_thin_arm64_macho        (fat, kSlice1Off, 0x200000000ULL);

  // Triple says arm64. The arm64 slice exists in the FAT — it must
  // win, even though it has no chained fixups.
  ChainedFixupMap m =
      extract_chained_fixups_from_macho(fat.data(), fat.size(),
                                         "arm64-apple-macosx14.0.0");
  // The arm64 slice has no chained fixups → resolved is empty.
  CHECK(m.resolved.empty());
  // Critically, the image_base must come from the arm64 slice
  // (image_base from its segments), NOT from the arm64e slice. If we
  // accidentally fell through to arm64e the image_base would be
  // 0x200000000.
  //
  // emit_thin_arm64_macho_no_fixups doesn't populate image_base via
  // the chained-fixup header (there isn't one), but the parser's
  // image_base derivation is "first chain-bearing segment's vm_addr
  // - segment_offset", which only applies when there ARE chained
  // fixups. With none, image_base stays at its default 0. What
  // matters for C5 is that we DON'T get arm64e's 0x200000000 (which
  // would corrupt the caller's xref slot lookup).
  CHECK(m.image_base != 0x200000000ULL);
}
