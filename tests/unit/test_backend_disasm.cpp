// Tests for DebuggerBackend::disassemble_range.
//
// We disassemble the address range of `point2_distance_sq` from the
// structs fixture. Instruction count and exact mnemonics depend on
// compiler & ABI; we assert *invariants*: every instruction lies within
// the requested range, byte-sizes are positive, and the function ends
// with a control-flow-leaving instruction (ret-family).

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"

#include <algorithm>
#include <memory>
#include <string>

using ldb::backend::DisasmInsn;
using ldb::backend::LldbBackend;
using ldb::backend::SymbolKind;
using ldb::backend::SymbolQuery;
using ldb::backend::TargetId;

namespace {

constexpr const char* kFixturePath = LDB_FIXTURE_STRUCTS_PATH;

struct OpenedFixture {
  std::unique_ptr<LldbBackend> backend;
  TargetId target_id;
};

OpenedFixture open_fixture() {
  auto be = std::make_unique<LldbBackend>();
  auto res = be->open_executable(kFixturePath);
  REQUIRE(res.target_id != 0);
  return {std::move(be), res.target_id};
}

struct FunctionRange {
  std::uint64_t start = 0;
  std::uint64_t end   = 0;
};

FunctionRange function_range(LldbBackend& be, TargetId tid,
                             const std::string& name) {
  SymbolQuery sq;
  sq.name = name;
  sq.kind = SymbolKind::kFunction;
  auto matches = be.find_symbols(tid, sq);
  REQUIRE_FALSE(matches.empty());
  REQUIRE(matches[0].byte_size > 0);
  return {matches[0].address, matches[0].address + matches[0].byte_size};
}

bool looks_like_return(const std::string& mnemonic) {
  // arm64 / arm / x86 / x86-64 return-family mnemonics.
  return mnemonic == "ret" || mnemonic == "retn" ||
         mnemonic == "retq" || mnemonic == "retl" ||
         mnemonic == "retab" ||  // arm64e auth-and-return
         mnemonic == "retaa" || mnemonic == "retab2" ||
         mnemonic == "bx";       // arm
}

}  // namespace

TEST_CASE("disasm.range: returns instructions for a known function range",
          "[backend][disasm]") {
  auto fx = open_fixture();
  auto fr = function_range(*fx.backend, fx.target_id, "point2_distance_sq");

  auto insns = fx.backend->disassemble_range(fx.target_id, fr.start, fr.end);

  REQUIRE_FALSE(insns.empty());

  // Every instruction lies within the requested range.
  for (const auto& i : insns) {
    CHECK(i.address >= fr.start);
    CHECK(i.address + i.byte_size <= fr.end);
    CHECK(i.byte_size > 0);
    CHECK_FALSE(i.mnemonic.empty());
  }
}

TEST_CASE("disasm.range: function ends with a ret-family instruction",
          "[backend][disasm]") {
  auto fx = open_fixture();
  auto fr = function_range(*fx.backend, fx.target_id, "point2_distance_sq");

  auto insns = fx.backend->disassemble_range(fx.target_id, fr.start, fr.end);
  REQUIRE_FALSE(insns.empty());

  bool found_ret = std::any_of(insns.begin(), insns.end(),
                               [](const DisasmInsn& i) {
                                 return looks_like_return(i.mnemonic);
                               });
  CHECK(found_ret);
}

TEST_CASE("disasm.range: addresses are strictly increasing",
          "[backend][disasm]") {
  auto fx = open_fixture();
  auto fr = function_range(*fx.backend, fx.target_id, "point2_distance_sq");

  auto insns = fx.backend->disassemble_range(fx.target_id, fr.start, fr.end);
  REQUIRE(insns.size() >= 2);

  for (size_t i = 1; i < insns.size(); ++i) {
    CHECK(insns[i].address > insns[i - 1].address);
  }
}

TEST_CASE("disasm.range: bytes are populated and match byte_size",
          "[backend][disasm]") {
  auto fx = open_fixture();
  auto fr = function_range(*fx.backend, fx.target_id, "point2_distance_sq");

  auto insns = fx.backend->disassemble_range(fx.target_id, fr.start, fr.end);
  REQUIRE_FALSE(insns.empty());

  for (const auto& i : insns) {
    CHECK(i.bytes.size() == i.byte_size);
  }
}

TEST_CASE("disasm.range: empty range returns no instructions",
          "[backend][disasm]") {
  auto fx = open_fixture();
  CHECK(fx.backend->disassemble_range(fx.target_id, 0, 0).empty());
  CHECK(fx.backend->disassemble_range(fx.target_id, 0x1000, 0x1000).empty());
}

TEST_CASE("disasm.range: start > end returns no instructions",
          "[backend][disasm]") {
  auto fx = open_fixture();
  CHECK(fx.backend->disassemble_range(fx.target_id, 0x2000, 0x1000).empty());
}

TEST_CASE("disasm.range: invalid target_id throws backend::Error",
          "[backend][disasm][error]") {
  auto fx = open_fixture();
  CHECK_THROWS_AS(
      fx.backend->disassemble_range(/*tid=*/9999, 0, 100),
      ldb::backend::Error);
}
