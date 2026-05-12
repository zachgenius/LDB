// SPDX-License-Identifier: Apache-2.0
// S-expression → bytecode compiler tests
// (post-V1 #25 phase-2, docs/29-predicate-compiler.md §2).
//
// Coverage:
//   * Trivial literal compiles to the smallest const opcode.
//   * (reg "name") compiles to kReg with name added to reg_table.
//   * Binary ops compile arguments left-to-right then emit the op.
//   * Const sizing picks the narrowest int width.
//   * Negative consts via const sizing (int8_t).
//   * (begin a b c) emits drops between forms.
//   * Compile + evaluate round-trip: parse → bytecode → eval matches
//     the hand-written expectation.
//   * Error paths: unbalanced parens, unknown op, wrong arity, bare
//     identifier, empty source compiles to a valid "false" predicate.

#include <catch_amalgamated.hpp>

#include "agent_expr/bytecode.h"
#include "agent_expr/compiler.h"

#include <string>

using ldb::agent_expr::CompileResult;
using ldb::agent_expr::EvalContext;
using ldb::agent_expr::EvalError;
using ldb::agent_expr::Op;
using ldb::agent_expr::Program;
using ldb::agent_expr::compile;
using ldb::agent_expr::eval;

namespace {

Program must_compile(std::string_view src) {
  auto r = compile(src);
  REQUIRE(r.error == std::nullopt);
  REQUIRE(r.program.has_value());
  return std::move(*r.program);
}

}  // namespace

TEST_CASE("compiler: integer literal at top level → kConst8 + kEnd",
          "[agent_expr][compiler][const]") {
  auto p = must_compile("42");
  REQUIRE(p.code.size() == 3);
  CHECK(p.code[0] == static_cast<std::uint8_t>(Op::kConst8));
  CHECK(p.code[1] == 42);
  CHECK(p.code[2] == static_cast<std::uint8_t>(Op::kEnd));
}

TEST_CASE("compiler: negative literal fits in const8",
          "[agent_expr][compiler][const]") {
  auto p = must_compile("-1");
  REQUIRE(p.code.size() == 3);
  CHECK(p.code[0] == static_cast<std::uint8_t>(Op::kConst8));
  CHECK(p.code[1] == 0xff);   // -1 as int8 sign-extended
}

TEST_CASE("compiler: literal widens to const16 / const32 / const64",
          "[agent_expr][compiler][const]") {
  CHECK(must_compile("128").code[0]
        == static_cast<std::uint8_t>(Op::kConst16));
  CHECK(must_compile("32768").code[0]
        == static_cast<std::uint8_t>(Op::kConst32));
  CHECK(must_compile("2147483648").code[0]
        == static_cast<std::uint8_t>(Op::kConst64));
}

TEST_CASE("compiler: hex literal parses",
          "[agent_expr][compiler][const]") {
  auto p = must_compile("0xdead");
  // 0xdead = 57005 — doesn't fit in signed int16 (max 32767), so
  // the compiler promotes to kConst32. (For unsigned-byte
  // comparisons, agents should mask explicitly; the VM is
  // signed-only throughout, see docs/29.)
  CHECK(p.code[0] == static_cast<std::uint8_t>(Op::kConst32));
}

TEST_CASE("compiler: (reg \"rax\") emits kReg + adds to reg_table",
          "[agent_expr][compiler][reg]") {
  auto p = must_compile("(reg \"rax\")");
  REQUIRE(p.reg_table.size() == 1);
  CHECK(p.reg_table[0] == "rax");
  // Code: kReg 0x00 0x00 kEnd
  REQUIRE(p.code.size() == 4);
  CHECK(p.code[0] == static_cast<std::uint8_t>(Op::kReg));
  CHECK(p.code[1] == 0);
  CHECK(p.code[2] == 0);
  CHECK(p.code[3] == static_cast<std::uint8_t>(Op::kEnd));
}

TEST_CASE("compiler: repeated (reg \"rax\") reuses table index",
          "[agent_expr][compiler][reg]") {
  auto p = must_compile("(add (reg \"rax\") (reg \"rax\"))");
  CHECK(p.reg_table.size() == 1);
  CHECK(p.reg_table[0] == "rax");
}

TEST_CASE("compiler: binary op emits args then op byte",
          "[agent_expr][compiler][binop]") {
  auto p = must_compile("(eq 1 2)");
  // const8 1 (2 bytes), const8 2 (2 bytes), eq (1 byte), end (1 byte) = 6.
  REQUIRE(p.code.size() == 6);
  CHECK(p.code[0] == static_cast<std::uint8_t>(Op::kConst8));
  CHECK(p.code[1] == 1);
  CHECK(p.code[2] == static_cast<std::uint8_t>(Op::kConst8));
  CHECK(p.code[3] == 2);
  CHECK(p.code[4] == static_cast<std::uint8_t>(Op::kEq));
  CHECK(p.code[5] == static_cast<std::uint8_t>(Op::kEnd));
}

TEST_CASE("compiler: round-trip — compile then eval matches expected",
          "[agent_expr][compiler][eval]") {
  EvalContext ctx;
  CHECK(eval(must_compile("42"), ctx).value == 42);
  CHECK(eval(must_compile("(add 1 2)"), ctx).value == 3);
  CHECK(eval(must_compile("(sub 10 3)"), ctx).value == 7);
  CHECK(eval(must_compile("(eq 5 5)"), ctx).value == 1);
  CHECK(eval(must_compile("(ne 5 6)"), ctx).value == 1);
  CHECK(eval(must_compile("(land 1 0)"), ctx).value == 0);
  CHECK(eval(must_compile("(lor 0 5)"), ctx).value == 1);
  CHECK(eval(must_compile("(lnot 0)"), ctx).value == 1);
  CHECK(eval(must_compile("(and 0xff 0x33)"), ctx).value == 0x33);
}

TEST_CASE("compiler: (begin a b c) drops every form but the last",
          "[agent_expr][compiler][begin]") {
  EvalContext ctx;
  // Each form pushes; begin drops all but the last.
  CHECK(eval(must_compile("(begin 1 2 3)"), ctx).value == 3);
  CHECK(eval(must_compile("(begin (add 1 2) (sub 7 2))"), ctx).value == 5);
}

TEST_CASE("compiler: empty source compiles to a kEnd-only program",
          "[agent_expr][compiler][empty]") {
  auto r = compile("");
  REQUIRE(r.error == std::nullopt);
  REQUIRE(r.program.has_value());
  REQUIRE(r.program->code.size() == 1);
  CHECK(r.program->code[0] == static_cast<std::uint8_t>(Op::kEnd));
  // Eval returns 0 (false predicate).
  EvalContext ctx;
  CHECK(eval(*r.program, ctx).value == 0);
}

TEST_CASE("compiler: whitespace + comments are ignored",
          "[agent_expr][compiler][lex]") {
  // S-expression-style ; line comments.
  auto p = must_compile(R"(
    ;; the answer
    (add 40 2)
  )");
  EvalContext ctx;
  CHECK(eval(p, ctx).value == 42);
}

TEST_CASE("compiler: unknown opcode → error with anchor",
          "[agent_expr][compiler][error]") {
  auto r = compile("(unknown 1 2)");
  REQUIRE(r.error.has_value());
  CHECK(r.error->message.find("unknown") != std::string::npos);
  CHECK(r.error->line   == 1);
  CHECK(r.error->column >= 1);
}

TEST_CASE("compiler: wrong arity → error",
          "[agent_expr][compiler][error]") {
  auto r = compile("(eq 1)");
  REQUIRE(r.error.has_value());
  CHECK(r.error->message.find("eq") != std::string::npos);
  CHECK(r.error->message.find("2")  != std::string::npos);
}

TEST_CASE("compiler: unbalanced parens → error",
          "[agent_expr][compiler][error]") {
  auto r1 = compile("(add 1 2");
  CHECK(r1.error.has_value());
  auto r2 = compile("add 1 2)");
  CHECK(r2.error.has_value());
}

TEST_CASE("compiler: bare identifier → error",
          "[agent_expr][compiler][error]") {
  // Bare 'rax' is not the same as (reg "rax") — we never silently
  // interpret identifiers as registers (avoids mistyped reg-name
  // bugs).
  auto r = compile("rax");
  REQUIRE(r.error.has_value());
  CHECK(r.error->message.find("identifier") != std::string::npos);
}

TEST_CASE("compiler: (reg \"\") rejects empty name",
          "[agent_expr][compiler][error]") {
  auto r = compile("(reg \"\")");
  REQUIRE(r.error.has_value());
  CHECK(r.error->message.find("reg") != std::string::npos);
}

TEST_CASE("compiler: line:column anchor tracks newlines",
          "[agent_expr][compiler][error]") {
  auto r = compile("\n\n(unknown)");
  REQUIRE(r.error.has_value());
  CHECK(r.error->line == 3);
}

TEST_CASE("compiler: integer overflow surfaces as compile error",
          "[agent_expr][compiler][error]") {
  // Bigger than LLONG_MAX. strtoll sets errno=ERANGE and saturates;
  // silently emitting LLONG_MAX would produce a predicate that
  // behaves nothing like what the agent wrote.
  auto r = compile("99999999999999999999");
  REQUIRE(r.error.has_value());
  CHECK(r.error->message.find("invalid integer") != std::string::npos);
}

TEST_CASE("compiler: (reg ...) emits via reg_table — round-trip against null context",
          "[agent_expr][compiler][reg]") {
  // The simpler compile-time + structural test: assert the codegen.
  // Live reg reads are exercised by the probe.create wiring tests in
  // the follow-up commit (integration covers what unit can't).
  auto p = must_compile("(eq (reg \"rax\") 0xdeadbeef)");
  REQUIRE(p.reg_table.size() == 1);
  CHECK(p.reg_table[0] == "rax");
  // 0xdeadbeef = 3735928559 — doesn't fit in signed int32_t
  // (max 2147483647), so kConst64 is selected.
  // Bytecode: kReg(1) + idx(2) + kConst64(1) + imm(8) + kEq(1) + kEnd(1) = 14
  REQUIRE(p.code.size() == 14);
  CHECK(p.code[0]  == static_cast<std::uint8_t>(Op::kReg));
  CHECK(p.code[3]  == static_cast<std::uint8_t>(Op::kConst64));
  CHECK(p.code[12] == static_cast<std::uint8_t>(Op::kEq));
  CHECK(p.code[13] == static_cast<std::uint8_t>(Op::kEnd));
}

// Live reg reads round-trip via the probe.create integration tests
// in the follow-up commit (covers what unit-level mocks can't).
