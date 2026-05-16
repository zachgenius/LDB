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
