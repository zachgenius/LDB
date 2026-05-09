// SPDX-License-Identifier: Apache-2.0
// Tests for DebuggerBackend::find_symbols.
//
// Looks up named functions, globals, and unknown names against the
// structs fixture. Mirrors what `nm` + `ldb symbol find foo` would do.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"

#include <algorithm>
#include <memory>
#include <string>

using ldb::backend::LldbBackend;
using ldb::backend::SymbolKind;
using ldb::backend::SymbolMatch;
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

bool any_named(const std::vector<SymbolMatch>& v, const std::string& n) {
  return std::any_of(v.begin(), v.end(),
                     [&](const SymbolMatch& s) { return s.name == n; });
}

const SymbolMatch* find_named(const std::vector<SymbolMatch>& v,
                              const std::string& n) {
  for (const auto& s : v) if (s.name == n) return &s;
  return nullptr;
}

}  // namespace

TEST_CASE("symbol.find: locates a function by name", "[backend][symbol_find]") {
  auto fx = open_fixture();
  SymbolQuery q;
  q.name = "point2_distance_sq";
  auto matches = fx.backend->find_symbols(fx.target_id, q);

  REQUIRE_FALSE(matches.empty());
  const auto* m = find_named(matches, "point2_distance_sq");
  REQUIRE(m);
  CHECK(m->kind == SymbolKind::kFunction);
  CHECK(m->address != 0);
  // size > 0 — a real function body, not a null stub.
  CHECK(m->byte_size > 0);
}

TEST_CASE("symbol.find: locates a global variable by name",
          "[backend][symbol_find]") {
  auto fx = open_fixture();
  SymbolQuery q;
  q.name = "g_origin";
  auto matches = fx.backend->find_symbols(fx.target_id, q);

  REQUIRE_FALSE(matches.empty());
  const auto* m = find_named(matches, "g_origin");
  REQUIRE(m);
  CHECK(m->kind == SymbolKind::kVariable);
  CHECK(m->address != 0);
  CHECK(m->byte_size == 8);  // sizeof(struct point2)
}

TEST_CASE("symbol.find: locates main", "[backend][symbol_find]") {
  auto fx = open_fixture();
  SymbolQuery q;
  q.name = "main";
  auto matches = fx.backend->find_symbols(fx.target_id, q);

  REQUIRE_FALSE(matches.empty());
  CHECK(any_named(matches, "main"));
}

TEST_CASE("symbol.find: locates a global tagged dxp_login_frame",
          "[backend][symbol_find]") {
  auto fx = open_fixture();
  SymbolQuery q;
  q.name = "g_login_template";
  auto matches = fx.backend->find_symbols(fx.target_id, q);

  REQUIRE_FALSE(matches.empty());
  const auto* m = find_named(matches, "g_login_template");
  REQUIRE(m);
  CHECK(m->kind == SymbolKind::kVariable);
  // sizeof(struct dxp_login_frame) = 16
  CHECK(m->byte_size == 16);
}

TEST_CASE("symbol.find: kind=function filters out variables",
          "[backend][symbol_find]") {
  auto fx = open_fixture();
  SymbolQuery q;
  q.name = "g_origin";
  q.kind = SymbolKind::kFunction;
  auto matches = fx.backend->find_symbols(fx.target_id, q);
  CHECK(matches.empty());
}

TEST_CASE("symbol.find: kind=variable filters out functions",
          "[backend][symbol_find]") {
  auto fx = open_fixture();
  SymbolQuery q;
  q.name = "point2_distance_sq";
  q.kind = SymbolKind::kVariable;
  auto matches = fx.backend->find_symbols(fx.target_id, q);
  CHECK(matches.empty());
}

TEST_CASE("symbol.find: unknown name returns empty",
          "[backend][symbol_find]") {
  auto fx = open_fixture();
  SymbolQuery q;
  q.name = "this_symbol_definitely_does_not_exist_42";
  auto matches = fx.backend->find_symbols(fx.target_id, q);
  CHECK(matches.empty());
}

TEST_CASE("symbol.find: invalid target_id throws backend::Error",
          "[backend][symbol_find][error]") {
  auto fx = open_fixture();
  SymbolQuery q;
  q.name = "main";
  CHECK_THROWS_AS(
      fx.backend->find_symbols(/*tid=*/9999, q),
      ldb::backend::Error);
}
