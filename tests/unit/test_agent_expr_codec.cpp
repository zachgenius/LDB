// SPDX-License-Identifier: Apache-2.0
// Wire codec tests for agent-expression Programs
// (post-V1 #25 phase-1, docs/28-agent-expressions.md §2).
//
// The codec round-trips a Program through its serialised byte form:
//   u32 BE program_size
//   u8[]   opcodes
//   u16 BE reg_table_count
//   for each reg: u16 BE name_len, u8[] name
//
// Coverage:
//   * Round-trip a non-trivial program (opcodes + reg table).
//   * Empty program (no opcodes, no regs) encodes + decodes.
//   * Truncated input → decode returns nullopt at each truncation
//     point (header, opcodes, reg-count, reg-name-len, reg-name-body).
//   * Declared program_size mismatching the actual byte range is
//     rejected — silent truncation would leave the evaluator
//     running off the buffer end.
//   * Programs exceeding kMaxProgramBytes are rejected at decode
//     (anti-DoS cap).

#include <catch_amalgamated.hpp>

#include "agent_expr/bytecode.h"

#include <cstring>
#include <string>
#include <vector>

using ldb::agent_expr::Op;
using ldb::agent_expr::Program;
using ldb::agent_expr::decode;
using ldb::agent_expr::encode;
using ldb::agent_expr::kMaxProgramBytes;

namespace {

Program sample_program() {
  Program p;
  // (eq (reg "rax") (const8 42)) — pseudocode.
  // Bytecode: kReg 0x00 0x00 ; kConst8 0x2a ; kEq ; kEnd
  p.code = {
      static_cast<std::uint8_t>(Op::kReg),     0x00, 0x00,
      static_cast<std::uint8_t>(Op::kConst8),  0x2a,
      static_cast<std::uint8_t>(Op::kEq),
      static_cast<std::uint8_t>(Op::kEnd),
  };
  p.reg_table = {"rax"};
  return p;
}

}  // namespace

TEST_CASE("agent_expr/codec: round-trip preserves opcodes + reg table",
          "[agent_expr][codec]") {
  Program orig = sample_program();
  auto bytes = encode(orig);
  auto out = decode(std::string_view(
      reinterpret_cast<const char*>(bytes.data()), bytes.size()));
  REQUIRE(out.has_value());
  CHECK(out->code      == orig.code);
  CHECK(out->reg_table == orig.reg_table);
}

TEST_CASE("agent_expr/codec: empty program round-trips",
          "[agent_expr][codec][empty]") {
  Program p;  // no code, no regs
  auto bytes = encode(p);
  auto out = decode(std::string_view(
      reinterpret_cast<const char*>(bytes.data()), bytes.size()));
  REQUIRE(out.has_value());
  CHECK(out->code.empty());
  CHECK(out->reg_table.empty());
}

TEST_CASE("agent_expr/codec: truncated input returns nullopt",
          "[agent_expr][codec][error]") {
  auto bytes = encode(sample_program());

  // Walk every truncation point < full size and verify decode rejects.
  for (std::size_t cut = 0; cut < bytes.size(); ++cut) {
    auto out = decode(std::string_view(
        reinterpret_cast<const char*>(bytes.data()), cut));
    INFO("truncated at " << cut << " of " << bytes.size());
    CHECK_FALSE(out.has_value());
  }
}

TEST_CASE("agent_expr/codec: program_size mismatch is rejected",
          "[agent_expr][codec][error]") {
  Program p = sample_program();
  auto bytes = encode(p);
  // Tamper with the program_size header — claim 100 bytes of opcodes
  // when there are actually 7. The decoder must refuse rather than
  // happily consume bytes past the opcodes into the reg table.
  bytes[0] = 0x00;
  bytes[1] = 0x00;
  bytes[2] = 0x00;
  bytes[3] = 100;
  auto out = decode(std::string_view(
      reinterpret_cast<const char*>(bytes.data()), bytes.size()));
  CHECK_FALSE(out.has_value());
}

TEST_CASE("agent_expr/codec: oversize program rejected",
          "[agent_expr][codec][error][cap]") {
  // Hand-craft a header that claims kMaxProgramBytes + 1 bytes of
  // opcodes. Decoder must refuse before allocating the buffer.
  std::vector<std::uint8_t> bytes(4);
  std::uint32_t huge = static_cast<std::uint32_t>(kMaxProgramBytes + 1);
  bytes[0] = static_cast<std::uint8_t>((huge >> 24) & 0xff);
  bytes[1] = static_cast<std::uint8_t>((huge >> 16) & 0xff);
  bytes[2] = static_cast<std::uint8_t>((huge >>  8) & 0xff);
  bytes[3] = static_cast<std::uint8_t>( huge        & 0xff);
  auto out = decode(std::string_view(
      reinterpret_cast<const char*>(bytes.data()), bytes.size()));
  CHECK_FALSE(out.has_value());
}

TEST_CASE("agent_expr/codec: multi-byte reg names round-trip",
          "[agent_expr][codec]") {
  Program p;
  p.code = {static_cast<std::uint8_t>(Op::kEnd)};
  p.reg_table = {"rax", "rsp", "r15", "fs_base"};
  auto bytes = encode(p);
  auto out = decode(std::string_view(
      reinterpret_cast<const char*>(bytes.data()), bytes.size()));
  REQUIRE(out.has_value());
  REQUIRE(out->reg_table.size() == 4);
  CHECK(out->reg_table[0] == "rax");
  CHECK(out->reg_table[1] == "rsp");
  CHECK(out->reg_table[2] == "r15");
  CHECK(out->reg_table[3] == "fs_base");
}
