// SPDX-License-Identifier: Apache-2.0
// Tests for the ARM64 ADRP-operand parser helpers used by xref_address.
// Drives docs/35-field-report-followups.md §3 phase 2 review punch-list
// item I1 — negative ADRP immediates (`adrp x8, -2`) must round-trip
// through parse_int_at as signed values, otherwise xref silently
// misses (or wrongly attributes) a load whose page sits below the PC.

#include <catch_amalgamated.hpp>

#include "backend/xref_arm64_parsers.h"

#include <cstdint>
#include <string>
#include <tuple>

using ldb::backend::xref_arm64::classify_mov_source;
using ldb::backend::xref_arm64::MovSrcKind;
using ldb::backend::xref_arm64::parse_int_at;
using ldb::backend::xref_arm64::parse_reg_at;
using ldb::backend::xref_arm64::parse_uint_at;

TEST_CASE("parse_int_at handles negative decimal immediates", "[xref][arm64]") {
  // LLDB renders `adrp x8, -2` like this; the caller has already
  // consumed the register and trailing comma, so we start at the
  // imm offset.
  const std::string operands = "x8, -2";
  auto [ok, value, end] = parse_int_at(operands, 4);
  REQUIRE(ok);
  REQUIRE(value == -2);
  REQUIRE(end == operands.size());
}

TEST_CASE("parse_int_at handles negative hex immediates", "[xref][arm64]") {
  const std::string operands = "x8, -0x4000";
  auto [ok, value, end] = parse_int_at(operands, 4);
  REQUIRE(ok);
  REQUIRE(value == -0x4000);
  REQUIRE(end == operands.size());
}

TEST_CASE("parse_int_at handles positive decimal immediates", "[xref][arm64]") {
  const std::string operands = "x8, 4";
  auto [ok, value, end] = parse_int_at(operands, 4);
  REQUIRE(ok);
  REQUIRE(value == 4);
  REQUIRE(end == operands.size());
}

TEST_CASE("parse_int_at skips '#' and '-' together", "[xref][arm64]") {
  // Some LLDB renderings put a literal '#' on the immediate; the
  // signed-immediate path must skip the '#' and still accept the
  // following '-'.
  const std::string operands = "# -2 ";
  auto [ok, value, end] = parse_int_at(operands, 0);
  REQUIRE(ok);
  REQUIRE(value == -2);
  // The parser stops at the trailing space (the only non-digit after
  // the magnitude); 4 = '#' + ' ' + '-' + '2'.
  REQUIRE(end == 4);
}

TEST_CASE("parse_int_at returns ok=false on missing digits", "[xref][arm64]") {
  auto [ok1, v1, e1] = parse_int_at("", 0);
  REQUIRE_FALSE(ok1);

  auto [ok2, v2, e2] = parse_int_at("x8, -", 4);
  REQUIRE_FALSE(ok2);
}

TEST_CASE("parse_uint_at still rejects negative inputs", "[xref][arm64]") {
  // The unsigned helper must not accidentally accept '-' — that's
  // parse_int_at's job. If parse_uint_at started swallowing '-', the
  // ADRP block would no longer need parse_int_at and the regression
  // would be invisible.
  const std::string operands = "x8, -2";
  auto [ok, value, end] = parse_uint_at(operands, 4);
  REQUIRE_FALSE(ok);
}

TEST_CASE("parse_reg_at canonicalises w-form to x-form", "[xref][arm64]") {
  // ADRP only produces x-registers, but the consumer may be expressed
  // as a w-register on 32-bit ops. The AdrpPair map keys on a single
  // canonical token so the resolver still finds the entry.
  auto [ok, tok, end] = parse_reg_at(" W8, ", 0);
  REQUIRE(ok);
  REQUIRE(tok == "x8");
  REQUIRE(end == 3);
}

// docs/35-field-report-followups.md §3 phase 4 item 5: classify_mov_source
// must match alias names (xzr / wzr / sp / wsp / lr) BEFORE any prefix
// heuristic. The prior implementation lived in lldb_backend.cpp and
// worked by accident — the prefix check only fired for `#` and `x`/`w`
// initial chars, so `lr` and the zero aliases happened to land in the
// right arm. Phase 4 lifts the classifier to xref_arm64_parsers so this
// test pins the match order regardless of future refactors.

TEST_CASE("classify_mov_source: xzr / wzr classified as kZero",
          "[xref][arm64]") {
  REQUIRE(classify_mov_source("xzr") == MovSrcKind::kZero);
  REQUIRE(classify_mov_source("wzr") == MovSrcKind::kZero);
}

TEST_CASE("classify_mov_source: '#0' classified as kImmediate (semantic zero)",
          "[xref][arm64]") {
  // `mov xN, #0` is semantically equivalent to `mov xN, xzr`. Both
  // clobber the destination's tracked ADRP page. We classify them
  // distinctly (kImmediate vs kZero) so a future diagnostic path can
  // report which spelling appeared; the apply_mov_state arm treats
  // both identically (clobber dst).
  REQUIRE(classify_mov_source("#0")   == MovSrcKind::kImmediate);
  REQUIRE(classify_mov_source("#-1")  == MovSrcKind::kImmediate);
  REQUIRE(classify_mov_source("#0x4000") == MovSrcKind::kImmediate);
}

TEST_CASE("classify_mov_source: sp / wsp classified as kStackPointer",
          "[xref][arm64]") {
  REQUIRE(classify_mov_source("sp")  == MovSrcKind::kStackPointer);
  REQUIRE(classify_mov_source("wsp") == MovSrcKind::kStackPointer);
}

TEST_CASE("classify_mov_source: lr classified as kLinkRegister",
          "[xref][arm64]") {
  // `mov xN, lr` is `mov xN, x30` after alias resolution. The
  // classifier reports it as kLinkRegister so apply_mov_state clobbers
  // dst — the return-address value isn't a page address. If the
  // match arm here ever changed to "propagate via x30 lookup", it
  // would silently start surfacing the most-recent ADRP into x30 as
  // an xref through every leaf-function epilogue.
  REQUIRE(classify_mov_source("lr") == MovSrcKind::kLinkRegister);
}

TEST_CASE("classify_mov_source: xN / wN classified by width",
          "[xref][arm64]") {
  // xN is the only kind that propagates ADRP tracking. wN copies zero-
  // extend, so even if the source register is ADRP-tracked, the
  // resulting 64-bit value isn't a page address (the page address has
  // bits set above bit 31).
  REQUIRE(classify_mov_source("x0")  == MovSrcKind::kXReg);
  REQUIRE(classify_mov_source("x28") == MovSrcKind::kXReg);
  REQUIRE(classify_mov_source("w0")  == MovSrcKind::kWReg);
  REQUIRE(classify_mov_source("w28") == MovSrcKind::kWReg);
}

TEST_CASE("classify_mov_source: malformed inputs classified as kOther",
          "[xref][arm64]") {
  // Empty or with non-digit suffix after x/w. Anything we can't
  // confidently model collapses to kOther → conservative clobber.
  REQUIRE(classify_mov_source("")   == MovSrcKind::kOther);
  REQUIRE(classify_mov_source("xq") == MovSrcKind::kOther);  // not a number
  REQUIRE(classify_mov_source("foo") == MovSrcKind::kOther);
}
