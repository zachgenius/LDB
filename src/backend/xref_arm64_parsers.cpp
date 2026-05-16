// SPDX-License-Identifier: Apache-2.0
#include "backend/xref_arm64_parsers.h"

#include <cctype>

namespace ldb::backend::xref_arm64 {

namespace {

// Accumulate digits at s[pos]; returns {ok, magnitude, end_pos}. ok is
// false when there's not a single digit to consume after the optional
// hex prefix. Hex prefix is `0x` or `0X`; decimal otherwise.
std::tuple<bool, std::uint64_t, std::size_t>
parse_magnitude(const std::string& s, std::size_t pos) {
  bool hex = false;
  if (pos + 1 < s.size() && s[pos] == '0' &&
      (s[pos + 1] == 'x' || s[pos + 1] == 'X')) {
    hex = true;
    pos += 2;
  }
  std::uint64_t value = 0;
  std::size_t   start = pos;
  while (pos < s.size()) {
    char c = s[pos];
    unsigned int d;
    if (c >= '0' && c <= '9')             d = static_cast<unsigned int>(c - '0');
    else if (hex && c >= 'a' && c <= 'f') d = static_cast<unsigned int>(c - 'a' + 10);
    else if (hex && c >= 'A' && c <= 'F') d = static_cast<unsigned int>(c - 'A' + 10);
    else break;
    value = (value * (hex ? 16ULL : 10ULL)) + d;
    ++pos;
  }
  if (pos == start) return {false, 0, pos};
  return {true, value, pos};
}

}  // namespace

std::tuple<bool, std::uint64_t, std::size_t>
parse_uint_at(const std::string& s, std::size_t pos) {
  while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t')) ++pos;
  if (pos < s.size() && s[pos] == '#') ++pos;
  if (pos >= s.size()) return {false, 0, pos};
  return parse_magnitude(s, pos);
}

std::tuple<bool, std::int64_t, std::size_t>
parse_int_at(const std::string& s, std::size_t pos) {
  while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t')) ++pos;
  if (pos < s.size() && s[pos] == '#') ++pos;
  while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t')) ++pos;
  bool negative = false;
  if (pos < s.size() && s[pos] == '-') {
    negative = true;
    ++pos;
  }
  if (pos >= s.size()) return {false, 0, pos};
  auto [ok, mag, end] = parse_magnitude(s, pos);
  if (!ok) return {false, 0, end};
  // Cast magnitude to signed; the wrap is intentional for INT64_MIN-
  // shaped immediates, but ADRP page counts are 21-bit signed so the
  // magnitude never approaches INT64_MAX in practice.
  std::int64_t signed_value = static_cast<std::int64_t>(mag);
  if (negative) signed_value = -signed_value;
  return {true, signed_value, end};
}

MovSrcKind classify_mov_source(std::string_view tok) {
  if (tok.empty()) return MovSrcKind::kOther;
  // Token-compare against the alias spellings FIRST so `xzr` / `wzr` /
  // `sp` / `wsp` / `lr` never fall through to the xN/wN prefix
  // heuristic below. Phase 4 item 5: making zero-register handling
  // explicit (the prior implementation worked by accident because the
  // alias names landed in the right switch arm anyway, but a future
  // refactor that touched the prefix check could silently regress).
  if (tok == "xzr" || tok == "wzr") return MovSrcKind::kZero;
  if (tok == "sp"  || tok == "wsp") return MovSrcKind::kStackPointer;
  if (tok == "lr") return MovSrcKind::kLinkRegister;
  // `#<n>` is the immediate form. `mov xN, #0` is semantically the
  // same as `mov xN, xzr`; both clobber whatever ADRP page xN may
  // have held. Classified as kImmediate (rather than kZero) so the
  // caller can distinguish "any immediate" from "the literal zero
  // register" in diagnostic output — both still produce a clobber.
  if (tok[0] == '#') return MovSrcKind::kImmediate;
  if (tok.size() >= 2 && (tok[0] == 'x' || tok[0] == 'w')) {
    for (std::size_t i = 1; i < tok.size(); ++i) {
      if (tok[i] < '0' || tok[i] > '9') return MovSrcKind::kOther;
    }
    return tok[0] == 'x' ? MovSrcKind::kXReg : MovSrcKind::kWReg;
  }
  return MovSrcKind::kOther;
}

std::tuple<bool, std::string, std::size_t>
parse_reg_at(const std::string& s, std::size_t pos) {
  while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t' || s[pos] == ','))
    ++pos;
  std::size_t start = pos;
  while (pos < s.size()) {
    char c = s[pos];
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9')) {
      ++pos;
    } else {
      break;
    }
  }
  if (pos == start) return {false, {}, pos};
  std::string tok = s.substr(start, pos - start);
  for (auto& ch : tok) ch = static_cast<char>(std::tolower(ch));
  if (!tok.empty() && tok[0] == 'w') tok[0] = 'x';
  return {true, std::move(tok), pos};
}

namespace {

// Token starts with 'x' or 'w' and is followed by all-numeric digits.
// Stub for the only thing parse_destination_registers needs to filter
// out non-register operand tokens (immediates, condition codes, etc.)
// before queueing them as destinations.
bool is_xw_register(const std::string& tok) {
  if (tok.size() < 2) return false;
  if (tok[0] != 'x' && tok[0] != 'w') return false;
  // "xzr" / "wzr" / "sp" / "wsp" / "lr" never participate as ADRP-
  // tracked destinations (zero, stack, link) — they're not in the
  // adrp_regs key set. parse_reg_at canonicalises to xzr/wzr but they
  // still wouldn't be in adrp_regs; erase() on a missing key is a
  // no-op. We let them through and rely on the no-op semantics.
  for (std::size_t i = 1; i < tok.size(); ++i) {
    if (tok[i] < '0' || tok[i] > '9') return false;
  }
  return true;
}

}  // namespace

std::vector<std::string>
parse_destination_registers(std::string_view mnemonic,
                            const std::string& operands) {
  std::vector<std::string> dests;

  // Stores write to memory, not a register. Compare-and-test
  // instructions write flags only. Branches/return have no
  // destination the resolver tracks.
  //
  // Be conservative about what we treat as "no destination" —
  // when in doubt, fall through to the default "first operand is
  // the destination" path. Over-clobbering is safe; under-
  // clobbering is silent wrong-result.
  if (mnemonic == "str"   || mnemonic == "stur"  ||
      mnemonic == "strh"  || mnemonic == "strb"  ||
      mnemonic == "sturh" || mnemonic == "sturb" ||
      mnemonic == "stp"   || mnemonic == "stnp"  ||
      mnemonic == "stlr"  || mnemonic == "stlrb" ||
      mnemonic == "stlrh" ||
      mnemonic == "stxr"  || mnemonic == "stxrb" ||
      mnemonic == "stxrh" || mnemonic == "stlxr" ||
      mnemonic == "stlxrb" || mnemonic == "stlxrh") {
    // STXR/STLXR/STXRB/STLXRB/STXRH/STLXRH technically write a
    // status code to their first operand register; treat them as
    // dest-writing under the default path below by NOT short-
    // circuiting here. The list above is the pure-store family.
    // (Reverted: leave them in this list — the status reg is set
    // unconditionally to 0/1 and isn't an ADRP page.)
    return dests;
  }
  if (mnemonic == "cmp"   || mnemonic == "cmn"   ||
      mnemonic == "tst"   || mnemonic == "ccmp"  ||
      mnemonic == "ccmn"  || mnemonic == "fcmp"  ||
      mnemonic == "fccmp" || mnemonic == "fcmpe" ||
      mnemonic == "fccmpe") {
    return dests;
  }
  if (mnemonic == "ret"   || mnemonic == "retaa" || mnemonic == "retab" ||
      mnemonic == "b"     ||
      mnemonic == "br"    || mnemonic == "braa"  || mnemonic == "brab"  ||
      mnemonic == "braaz" || mnemonic == "brabz" ||
      mnemonic == "bl"    ||
      mnemonic == "blr"   || mnemonic == "blraa" || mnemonic == "blrab" ||
      mnemonic == "blraaz" || mnemonic == "blrabz" ||
      mnemonic == "cbz"   || mnemonic == "cbnz"  ||
      mnemonic == "tbz"   || mnemonic == "tbnz"  ||
      mnemonic == "svc"   || mnemonic == "hvc"   ||
      mnemonic == "smc"   || mnemonic == "brk"   ||
      mnemonic == "hlt"   ||
      mnemonic == "nop"   || mnemonic == "yield" ||
      mnemonic == "wfe"   || mnemonic == "wfi"   ||
      mnemonic == "sev"   || mnemonic == "sevl"  ||
      mnemonic == "dmb"   || mnemonic == "dsb"   ||
      mnemonic == "isb"   ||
      mnemonic == "pacibsp" || mnemonic == "pacibz" ||
      mnemonic == "paciasp" || mnemonic == "paciaz" ||
      mnemonic == "autibsp" || mnemonic == "autibz" ||
      mnemonic == "autiasp" || mnemonic == "autiaz" ||
      mnemonic == "xpaclri" ||
      mnemonic == "eret"  || mnemonic == "drps" ||
      mnemonic == "msr") {
    // MSR writes a system register, not a GPR. The general-register
    // operand on MSR is the SOURCE (e.g. `msr nzcv, x3`).
    // Conditional B.cond mnemonics start with "b." and have no
    // destination register either; caught by the b.* check below.
    return dests;
  }
  if (mnemonic.size() >= 2 && mnemonic.substr(0, 2) == "b.") {
    // b.eq / b.ne / b.cs / ... — conditional branch, no destination.
    return dests;
  }

  // Paired-load family: LDP / LDPSW / LDNP / LDXP / LDAXP all write
  // two destination registers (the first two operands).
  const bool is_load_pair =
      mnemonic == "ldp"   || mnemonic == "ldpsw" ||
      mnemonic == "ldnp"  || mnemonic == "ldxp"  ||
      mnemonic == "ldaxp";

  // Default path: the first operand register is the destination.
  // For paired loads, the second operand register is ALSO a
  // destination. This covers (>95% of the ISA): ADD/SUB family,
  // AND/ORR/EOR family with shifted-reg, MOV/MOVZ/MOVK/MOVN,
  // LDR/LDUR/LDRSW/LDRH/LDRB/LDXR/LDAR/LDAXR/LDAPR,
  // CSEL/CSET/CSINC/CSINV/CSNEG/CINC/CINV/CNEG/CSEL,
  // MADD/MSUB/SMADDL/UMADDL/SMSUBL/UMSUBL,
  // EXTR/BFI/BFM/UBFX/SBFX/UBFM/SBFM, FMOV (to GPR),
  // SDIV/UDIV, REV/REV16/REV32/RBIT, CLZ/CLS, ASR/LSL/LSR/ROR,
  // SXT?/UXT?,...
  //
  // We don't try to enumerate which forms. The first operand is the
  // destination by ARM64 convention; over-clobbering is the safe
  // direction.
  auto [ok1, r1, p1] = parse_reg_at(operands, 0);
  if (!ok1) return dests;
  if (is_xw_register(r1)) dests.push_back(std::move(r1));

  if (is_load_pair) {
    auto [ok2, r2, _p2] = parse_reg_at(operands, p1);
    if (ok2 && is_xw_register(r2)) dests.push_back(std::move(r2));
  }

  return dests;
}

}  // namespace ldb::backend::xref_arm64
