// Tests for DebuggerBackend::find_globals_of_type — Tier 3 §12, the
// first semantic query (type-keyed global lookup). Mirrors what an
// agent would issue with `static.globals_of_type("point2")` to find
// every instance of a given DWARF type at static storage.
//
// The structs fixture (tests/fixtures/c/structs.c) declares five
// globals with known types:
//
//   g_arr            : int[4]
//   g_origin         : point2
//   k_schema_name    : const char *const
//   k_protocol_name  : const char *const
//   g_login_template : dxp_login_frame
//
// Type-name canonical form matches what `SBValue::GetTypeName()`
// reports on Linux LLVM 18+: bare struct/typedef names (no `struct`
// prefix), `const char *const` for pointer-to-const-char-const,
// `int[4]` for fixed-size arrays.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"

#include <algorithm>
#include <memory>
#include <string>

using ldb::backend::GlobalVarMatch;
using ldb::backend::LldbBackend;
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

bool any_named(const std::vector<GlobalVarMatch>& v, const std::string& n) {
  return std::any_of(v.begin(), v.end(),
                     [&](const GlobalVarMatch& g) { return g.name == n; });
}

const GlobalVarMatch* find_named(const std::vector<GlobalVarMatch>& v,
                                 const std::string& n) {
  for (const auto& g : v) if (g.name == n) return &g;
  return nullptr;
}

}  // namespace

TEST_CASE("globals_of_type: exact match on a struct type returns the lone "
          "global of that type",
          "[backend][globals_of_type]") {
  auto fx = open_fixture();
  bool strict = false;
  auto res = fx.backend->find_globals_of_type(fx.target_id, "point2", strict);

  REQUIRE(res.size() == 1);
  CHECK(strict == true);
  const auto& g = res[0];
  CHECK(g.name == "g_origin");
  CHECK(g.type == "point2");
  CHECK(g.size == 8);
  CHECK(g.file_address != 0);
  // No live process attached, so load_address should be unset.
  CHECK_FALSE(g.load_address.has_value());
  CHECK(g.module.size() > 0);
  CHECK(g.file == "structs.c");
  CHECK(g.line == 46);
}

TEST_CASE("globals_of_type: exact match on a typedef type returns multiple "
          "globals",
          "[backend][globals_of_type]") {
  auto fx = open_fixture();
  bool strict = false;
  auto res = fx.backend->find_globals_of_type(fx.target_id,
                                              "const char *const", strict);

  // Two globals of this type: k_schema_name, k_protocol_name.
  CHECK(strict == true);
  REQUIRE(res.size() == 2);
  CHECK(any_named(res, "k_schema_name"));
  CHECK(any_named(res, "k_protocol_name"));
  for (const auto& g : res) {
    CHECK(g.type == "const char *const");
    CHECK(g.size == 8);
    CHECK(g.file_address != 0);
  }
}

TEST_CASE("globals_of_type: array type matches by canonical form",
          "[backend][globals_of_type]") {
  auto fx = open_fixture();
  bool strict = false;
  auto res = fx.backend->find_globals_of_type(fx.target_id, "int[4]", strict);

  REQUIRE(res.size() == 1);
  CHECK(strict == true);
  CHECK(res[0].name == "g_arr");
  CHECK(res[0].size == 16);
}

TEST_CASE("globals_of_type: substring fallback when no exact match",
          "[backend][globals_of_type]") {
  auto fx = open_fixture();
  bool strict = false;
  // "dxp_login" is a substring of "dxp_login_frame" — no exact match
  // for the type, so we fall back to substring; should still find
  // g_login_template.
  auto res = fx.backend->find_globals_of_type(fx.target_id,
                                              "dxp_login", strict);

  REQUIRE(res.size() == 1);
  CHECK(strict == false);
  CHECK(res[0].name == "g_login_template");
  CHECK(res[0].type == "dxp_login_frame");
  CHECK(res[0].size == 16);
}

TEST_CASE("globals_of_type: completely unknown type returns empty, "
          "non-strict",
          "[backend][globals_of_type]") {
  auto fx = open_fixture();
  bool strict = false;
  auto res = fx.backend->find_globals_of_type(
      fx.target_id, "this_type_definitely_does_not_exist_42", strict);

  CHECK(res.empty());
  CHECK(strict == false);
}

TEST_CASE("globals_of_type: empty type_name throws backend::Error",
          "[backend][globals_of_type][error]") {
  auto fx = open_fixture();
  bool strict = false;
  CHECK_THROWS_AS(fx.backend->find_globals_of_type(fx.target_id, "", strict),
                  ldb::backend::Error);
}

TEST_CASE("globals_of_type: invalid target_id throws backend::Error",
          "[backend][globals_of_type][error]") {
  auto fx = open_fixture();
  bool strict = false;
  CHECK_THROWS_AS(
      fx.backend->find_globals_of_type(/*tid=*/9999, "point2", strict),
      ldb::backend::Error);
}

TEST_CASE("globals_of_type: substring match across the whole catalogue "
          "does not return false positives for an exact-existing type",
          "[backend][globals_of_type]") {
  auto fx = open_fixture();
  bool strict = false;
  // "point2" is a real exact type; we should NOT see a substring fallback
  // here because exact already returns >0.
  auto res = fx.backend->find_globals_of_type(fx.target_id, "point2", strict);
  CHECK(strict == true);
  // Just g_origin — substring would also match anything containing
  // "point2", but we shouldn't fall back since exact succeeded.
  REQUIRE(res.size() == 1);
  CHECK(res[0].name == "g_origin");
}
