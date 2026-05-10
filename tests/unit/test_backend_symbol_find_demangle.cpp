// SPDX-License-Identifier: Apache-2.0
//
// Tests for symbol.find demangled-name and qualified-name lookup
// (papercut #3 from the cffex_server RE pass on 2026-05-10).
//
// Before the fix, find_symbols required an exact-mangled-name match;
// any of the agent-friendly forms (Class::Method, Class::Method(args),
// bare Method when only Class::Method exists) silently returned 0.
// The cascading lookup now does:
//   1. SBTarget::FindSymbols (exact name; mangled or simple).
//   2. SBTarget::FindFunctions(eFunctionNameTypeAuto)  — LLDB's own
//      qualified-name parser handles `Class::Method` and
//      `Class::Method(args)`.
//   3. Cross-module symbol-table scan with demangled-equality and
//      `endsWith("::"+name)` substring match.
//
// We use the cppsyms fixture: namespace ldb_fix, class Widget, method
// poke(long). The demangled name should be `ldb_fix::Widget::poke`.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"

#include <algorithm>
#include <memory>
#include <string>

using ldb::backend::LldbBackend;
using ldb::backend::SymbolMatch;
using ldb::backend::SymbolQuery;

namespace {

constexpr const char* kCppSymsPath = LDB_FIXTURE_CPPSYMS_PATH;

struct OpenedFixture {
  std::unique_ptr<LldbBackend> backend;
  ldb::backend::TargetId target_id;
};

OpenedFixture open_cppsyms() {
  auto be = std::make_unique<LldbBackend>();
  auto res = be->open_executable(kCppSymsPath);
  REQUIRE(res.target_id != 0);
  return {std::move(be), res.target_id};
}

bool any_demangled_contains(const std::vector<SymbolMatch>& v,
                             const std::string& needle) {
  return std::any_of(v.begin(), v.end(),
                     [&](const SymbolMatch& s) {
                       return s.name.find(needle) != std::string::npos;
                     });
}

}  // namespace

TEST_CASE("symbol.find: qualified C++ name `Class::Method` is found",
          "[backend][symbol_find][demangle]") {
  auto fx = open_cppsyms();
  SymbolQuery q;
  q.name = "ldb_fix::Widget::poke";
  auto matches = fx.backend->find_symbols(fx.target_id, q);

  // The exact-name path won't hit (LLDB's GetName for an SBSymbol
  // typically returns the demangled simple form), but pass 2's
  // FindFunctions(eFunctionNameTypeAuto) or pass 3's demangled scan
  // should resolve it.
  REQUIRE_FALSE(matches.empty());
  CHECK(any_demangled_contains(matches, "poke"));
  CHECK(matches.front().address != 0);
}

TEST_CASE("symbol.find: qualified C++ name with arg list is found",
          "[backend][symbol_find][demangle]") {
  auto fx = open_cppsyms();
  SymbolQuery q;
  q.name = "ldb_fix::Widget::poke(long)";
  auto matches = fx.backend->find_symbols(fx.target_id, q);

  REQUIRE_FALSE(matches.empty());
  CHECK(any_demangled_contains(matches, "poke"));
}

TEST_CASE("symbol.find: bare method name resolves to Class::Method via "
          "endsWith fallback",
          "[backend][symbol_find][demangle]") {
  auto fx = open_cppsyms();
  SymbolQuery q;
  q.name = "poke";
  auto matches = fx.backend->find_symbols(fx.target_id, q);

  REQUIRE_FALSE(matches.empty());
  CHECK(any_demangled_contains(matches, "poke"));
}

TEST_CASE("symbol.find: nonexistent demangled name still returns empty",
          "[backend][symbol_find][demangle]") {
  auto fx = open_cppsyms();
  SymbolQuery q;
  q.name = "ldb_fix::NoSuchClass::nope";
  auto matches = fx.backend->find_symbols(fx.target_id, q);
  CHECK(matches.empty());
}
