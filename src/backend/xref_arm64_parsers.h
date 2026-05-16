// SPDX-License-Identifier: Apache-2.0
#pragma once

// Internal-only parser helpers used by the ARM64 ADRP-pair resolver in
// xref_address (src/backend/lldb_backend.cpp). Lifted out of the
// translation unit's anonymous namespace so unit tests can exercise the
// signed/unsigned immediate parsing without piping disassembly through
// a live LLDB target.
//
// Not part of the public ldb::backend API — these helpers exist purely
// because LLDB's disassembler renders ADRP immediates as text we then
// have to re-tokenise. If LLDB exposes a typed operand walker later, we
// can delete this file.
//
// See docs/35-field-report-followups.md §3 phase 2 review punch-list
// item I1 — negative ADRP page counts (`adrp x8, -2`) must parse as
// signed, otherwise the page-math silently drops the entry or re-uses
// a stale prior ADRP for the same destination register.

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

namespace ldb::backend::xref_arm64 {

// Parse a decimal-or-hex non-negative integer starting at s[pos].
// Skips leading whitespace and an optional leading '#'. Returns
// {ok, value, end_pos}.
std::tuple<bool, std::uint64_t, std::size_t>
parse_uint_at(const std::string& s, std::size_t pos);

// Parse a decimal-or-hex signed integer starting at s[pos]. Skips
// leading whitespace + optional '#' + optional '-'. Magnitude
// accumulation matches parse_uint_at; the sign is applied last.
// Returns {ok, value, end_pos}.
//
// Used by the ADRP-recording block: LLDB renders negative page counts
// (compiler-emitted when ADRP targets a page below the PC's page) as
// e.g. `adrp x8, -2`. parse_uint_at would fail on the `-` and the ADRP
// would not be recorded, producing either a missed xref or — worse —
// a silent wrong xref against a stale prior ADRP entry for the same
// register.
std::tuple<bool, std::int64_t, std::size_t>
parse_int_at(const std::string& s, std::size_t pos);

// Parse an ARM64 register token starting at s[pos]. Skips leading
// whitespace and commas. Returns {ok, normalised_lowercase_token,
// end_pos}; "w8" / "X8" / "x8" all normalise to "x8". This lets us
// key the AdrpPair map on a single canonical name even though the
// underlying register pair (w/x) is the same architectural register.
std::tuple<bool, std::string, std::size_t>
parse_reg_at(const std::string& s, std::size_t pos);

// Classify the MOV source operand token (the value being moved INTO the
// destination register). The classifier exists so the ADRP-pair
// resolver in xref_address can decide whether a MOV propagates an
// ADRP-tracked page (only kXReg does) or clobbers the destination's
// tracking (every other kind).
//
// Match order is fixed: explicit alias spellings (xzr / wzr / sp / wsp
// / lr) are token-compared FIRST, before any prefix heuristic. This
// matters because `lr` and `xzr` would otherwise be misclassified by
// a first-character-check that only inspects the leading 'x' / 'w'
// nibble. See docs/35-field-report-followups.md §3 phase 4 item 5.
//
// Recognised inputs:
//   "#<n>"      → kImmediate  (covers `mov xN, #0` and friends)
//   "xzr"|"wzr" → kZero       (semantically equivalent to #0)
//   "sp"|"wsp"  → kStackPointer
//   "lr"        → kLinkRegister (alias for x30)
//   "xN"        → kXReg       (the only shape that propagates)
//   "wN"        → kWReg       (upper bits zeroed; not a page address)
//   anything else → kOther    (conservative clobber)
enum class MovSrcKind { kOther, kImmediate, kZero, kStackPointer,
                       kLinkRegister, kWReg, kXReg };

MovSrcKind classify_mov_source(std::string_view tok);

// Parse the destination register(s) an instruction writes, given its
// lower-cased mnemonic and operand string.
//
// Phase-4 cleanup C3+C4 (docs/35-field-report-followups.md §3): the
// ADRP-pair resolver's original clobber strategy was a whitelist of
// mnemonics — every instruction NOT in the list left destination
// register tracking intact, which silently bound stale ADRP pages to
// CSEL, CSET, CSINC, CSINV, CSNEG, LDP, LDPSW, LDXP, LDAR, LDAXR,
// MADD, MSUB, EXTR, BFI, BFM, UBFX, SBFX, FMOV, and dozens of other
// register-writing instructions.
//
// The cleanup pass shifts to clobber-by-default: the resolver's
// post-emit logic enumerates every instruction's destination register
// via this helper, applies any explicit propagation (e.g. MOV xN, xM),
// and then clears every remaining destination. The whitelist becomes
// a propagation-paths allowlist.
//
// Conventions:
//   - Returns canonical x-register names ("x8", not "w8"); parse_reg_at
//     does the w→x normalisation.
//   - STR/STP/STUR/STRH/STRB write to memory, not a register — they
//     return an empty vector.
//   - LDP/LDPSW/LDXP return two destinations.
//   - LDR/LDUR/LDRSW/LDRH/LDRB/LDXR/LDAR/LDAXR return one.
//   - CSEL/CSET/CSINC/CSINV/CSNEG/CINV/CINC/CNEG return one (the first
//     operand).
//   - MADD/MSUB/SMADDL/UMADDL/SMSUBL/UMSUBL return one.
//   - CMP/CMN/TST/CCMP/CCMN don't write a destination (they write
//     flags); return empty.
//   - Branches (B/BL/BR/BLR/CBZ/CBNZ/TBZ/TBNZ/RET) don't return a
//     destination in the register sense the resolver cares about; the
//     return-address writes for BL/BLR are handled separately by the
//     AAPCS64 clobber set.
//   - For instructions the helper doesn't recognise, the destination
//     register is conservatively assumed to be the first operand
//     register (matches >95% of ARM64 ISA: destination first).
//
// This intentionally over-clobbers some encodings (e.g. some FPU forms
// where the first operand is a flags-only consumer). The trade-off:
// over-clobbering loses a potential xref, under-clobbering produces
// false positives. We pick the conservative side.
std::vector<std::string> parse_destination_registers(std::string_view mnemonic,
                                                      const std::string& operands);

// Parse a branch / immediate-load target from the LAST comma-separated
// operand of `ops`. LLDB renders ARM64 branch targets as the FINAL
// operand:
//   `b 0x100003f00`               → 0x100003f00
//   `cbz x9, 0x100003f00`         → 0x100003f00
//   `tbz w0, #0x10, 0x100003f00`  → 0x100003f00  (NOT 0x10!)
//   `ldr x0, #0x40`               → 0x40
//
// Phase-4 cleanup I3 + N3 (docs/35-field-report-followups.md §3):
// the prior implementation scanned the whole operand string for any
// `0xN` substring and kept the LAST one. On `tbz w0, #0x10, _label`
// it returned 0x10 (the bit position) — a small numeric value that
// could happen to land inside __TEXT section bounds and silently
// inject a bogus function-start hint.
//
// N3: cap hex literal at 16 digits (64 bits). Anything wider
// overflows std::uint64_t and is meaningless as a code address;
// return nullopt rather than truncate silently.
//
// Returns std::nullopt when:
//   - the final operand is a textual label (LLDB sometimes renders
//     unresolved targets that way),
//   - the final operand has no `0x` prefix after optional whitespace
//     and an optional `#` immediate-prefix,
//   - the literal would overflow 64-bit (17+ hex digits).
std::optional<std::uint64_t>
parse_last_hex_in_operands(const std::string& ops);

}  // namespace ldb::backend::xref_arm64
