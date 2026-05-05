// Tests for DebuggerBackend::xref_address.
//
// Against the structs fixture, main contains a `bl point2_distance_sq`
// (a direct branch). Querying xref_address(addr_of_point2_distance_sq)
// must return at least that one site, with the call attributed to main.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"

#include <algorithm>
#include <memory>
#include <string>

using ldb::backend::LldbBackend;
using ldb::backend::SymbolKind;
using ldb::backend::SymbolQuery;
using ldb::backend::TargetId;
using ldb::backend::XrefMatch;

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

std::uint64_t addr_of_function(LldbBackend& be, TargetId tid,
                               const std::string& name) {
  SymbolQuery sq;
  sq.name = name;
  sq.kind = SymbolKind::kFunction;
  auto matches = be.find_symbols(tid, sq);
  REQUIRE_FALSE(matches.empty());
  return matches[0].address;
}

bool any_in_function(const std::vector<XrefMatch>& v, const std::string& fn) {
  return std::any_of(v.begin(), v.end(),
                     [&](const XrefMatch& m) { return m.function == fn; });
}

}  // namespace

TEST_CASE("xref.addr: direct branch to point2_distance_sq is detected from main",
          "[backend][xref]") {
  auto fx = open_fixture();
  std::uint64_t target = addr_of_function(*fx.backend, fx.target_id,
                                          "point2_distance_sq");

  auto refs = fx.backend->xref_address(fx.target_id, target);
  REQUIRE_FALSE(refs.empty());
  CHECK(any_in_function(refs, "main"));
}

TEST_CASE("xref.addr: each match carries instruction details",
          "[backend][xref]") {
  auto fx = open_fixture();
  std::uint64_t target = addr_of_function(*fx.backend, fx.target_id,
                                          "point2_distance_sq");

  auto refs = fx.backend->xref_address(fx.target_id, target);
  REQUIRE_FALSE(refs.empty());

  for (const auto& r : refs) {
    CHECK(r.address != 0);
    CHECK(r.byte_size > 0);
    CHECK_FALSE(r.mnemonic.empty());
  }
}

TEST_CASE("xref.addr: branch site mnemonic is in the call/branch family",
          "[backend][xref]") {
  auto fx = open_fixture();
  std::uint64_t target = addr_of_function(*fx.backend, fx.target_id,
                                          "point2_distance_sq");

  auto refs = fx.backend->xref_address(fx.target_id, target);
  REQUIRE_FALSE(refs.empty());

  // arm64: bl, blr, b, b.cond.   x86-64: call, callq, jmp.
  bool branch_seen = std::any_of(refs.begin(), refs.end(),
                                 [](const XrefMatch& m) {
                                   const std::string& mn = m.mnemonic;
                                   return mn == "bl" || mn == "blr" ||
                                          mn == "b"  || mn == "br" ||
                                          mn.rfind("b.", 0) == 0 ||
                                          mn == "call" || mn == "callq" ||
                                          mn == "jmp"  || mn == "jmpq";
                                 });
  CHECK(branch_seen);
}

TEST_CASE("xref.addr: bogus address returns no matches",
          "[backend][xref]") {
  auto fx = open_fixture();
  // 0xDEAD0000 is well outside any of the fixture's mapped addresses.
  auto refs = fx.backend->xref_address(fx.target_id, 0xDEAD0000ull);
  CHECK(refs.empty());
}

TEST_CASE("xref.addr: invalid target_id throws backend::Error",
          "[backend][xref][error]") {
  auto fx = open_fixture();
  CHECK_THROWS_AS(
      fx.backend->xref_address(/*tid=*/9999, 0x100ull),
      ldb::backend::Error);
}
