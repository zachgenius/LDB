// SPDX-License-Identifier: Apache-2.0
// Unit tests for ldb::store::RecipeStore (Tier 2 §6 — probe recipes).
//
// Contract under test:
//
//   • create(name, description?, parameters, calls) round-trips through
//     get() and list() — every field is preserved verbatim.
//   • Recipes are persisted as `recipe-v1` artifacts under build_id
//     "_recipes", name "recipe:<name>". The artifact id IS the recipe
//     id (so artifact.delete is a valid recipe.delete path).
//   • create() with a duplicate name replaces the prior recipe (artifact
//     (build_id, name) uniqueness contract).
//   • substitute_params() walks the call params recursively. STRING
//     values matching "{slot}" exactly are replaced with the caller's
//     value; non-matching strings pass through verbatim. Recursion
//     covers nested objects and arrays.
//   • A missing required parameter (no caller value, no default) is
//     surfaced as an error BEFORE the recipe runs.
//   • A recipe with no parameter slots passes its calls through
//     unchanged (literal replay).
//   • remove() returns true on success, false on an unknown id.

#include <catch_amalgamated.hpp>

#include "backend/debugger_backend.h"   // backend::Error
#include "store/artifact_store.h"
#include "store/recipe_store.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <random>
#include <string>
#include <system_error>

namespace fs = std::filesystem;
using ldb::store::ArtifactStore;
using ldb::store::Recipe;
using ldb::store::RecipeCall;
using ldb::store::RecipeParameter;
using ldb::store::RecipeStore;
using ldb::store::substitute_params;
using nlohmann::json;

namespace {

struct TmpStoreRoot {
  fs::path root;
  TmpStoreRoot() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    char buf[40];
    std::snprintf(buf, sizeof(buf), "ldb_recipe_test_%016llx",
                  static_cast<unsigned long long>(gen()));
    root = fs::temp_directory_path() / buf;
    std::error_code ec;
    fs::remove_all(root, ec);
  }
  ~TmpStoreRoot() {
    std::error_code ec;
    fs::remove_all(root, ec);
  }
};

}  // namespace

TEST_CASE("recipe_store: create + get round-trip", "[store][recipe]") {
  TmpStoreRoot t;
  ArtifactStore store(t.root);
  RecipeStore rs(store);

  std::vector<RecipeCall> calls = {
      RecipeCall{"target.open", json{{"path", "{path}"}}},
      RecipeCall{"module.list", json{{"target_id", "{target_id}"}}},
      RecipeCall{"type.layout", json{
          {"target_id", "{target_id}"},
          {"name",      "btp_state"},
      }},
  };
  std::vector<RecipeParameter> params = {
      RecipeParameter{"path",      "string",  std::nullopt},
      RecipeParameter{"target_id", "integer", std::nullopt},
  };

  auto r = rs.create("btp_recovery",
                     std::optional<std::string>("BTP recovery boot pattern"),
                     params, calls);
  REQUIRE(r.id > 0);
  CHECK(r.name == "btp_recovery");
  CHECK(r.calls.size() == 3);
  REQUIRE(r.parameters.size() == 2);
  CHECK(r.parameters[0].name == "path");
  CHECK(r.parameters[1].name == "target_id");

  auto got = rs.get(r.id);
  REQUIRE(got.has_value());
  CHECK(got->id == r.id);
  CHECK(got->name == "btp_recovery");
  REQUIRE(got->description.has_value());
  CHECK(*got->description == "BTP recovery boot pattern");
  REQUIRE(got->calls.size() == 3);
  CHECK(got->calls[0].method == "target.open");
  CHECK(got->calls[0].params == json{{"path", "{path}"}});
  CHECK(got->calls[2].method == "type.layout");
  CHECK(got->calls[2].params["name"] == "btp_state");
}

TEST_CASE("recipe_store: list enumerates persisted recipes",
          "[store][recipe]") {
  TmpStoreRoot t;
  ArtifactStore store(t.root);
  RecipeStore rs(store);

  rs.create("alpha", std::nullopt, {}, {RecipeCall{"hello", json::object()}});
  rs.create("beta",  std::nullopt, {}, {
      RecipeCall{"hello", json::object()},
      RecipeCall{"describe.endpoints", json::object()},
  });

  auto all = rs.list();
  REQUIRE(all.size() == 2);
  std::vector<std::string> names;
  for (const auto& r : all) names.push_back(r.name);
  std::sort(names.begin(), names.end());
  CHECK(names == std::vector<std::string>{"alpha", "beta"});

  auto beta_iter = std::find_if(all.begin(), all.end(),
      [](const Recipe& r) { return r.name == "beta"; });
  REQUIRE(beta_iter != all.end());
  CHECK(beta_iter->calls.size() == 2);
}

TEST_CASE("recipe_store: duplicate name replaces prior recipe",
          "[store][recipe]") {
  TmpStoreRoot t;
  ArtifactStore store(t.root);
  RecipeStore rs(store);

  auto r1 = rs.create("dup", std::nullopt, {},
                      {RecipeCall{"hello", json::object()}});
  auto r2 = rs.create("dup", std::nullopt, {},
                      {RecipeCall{"describe.endpoints", json::object()},
                       RecipeCall{"hello",              json::object()}});
  CHECK(r2.id != r1.id);
  auto all = rs.list();
  REQUIRE(all.size() == 1);
  CHECK(all[0].calls.size() == 2);
}

TEST_CASE("recipe_store: remove drops the recipe",
          "[store][recipe]") {
  TmpStoreRoot t;
  ArtifactStore store(t.root);
  RecipeStore rs(store);

  auto r = rs.create("victim", std::nullopt, {},
                     {RecipeCall{"hello", json::object()}});
  REQUIRE(rs.get(r.id).has_value());

  CHECK(rs.remove(r.id) == true);
  CHECK_FALSE(rs.get(r.id).has_value());
  CHECK(rs.list().empty());

  // Idempotent on a missing id.
  CHECK(rs.remove(r.id) == false);
}

TEST_CASE("recipe_store: parameter substitution replaces placeholders",
          "[store][recipe][substitute]") {
  std::vector<RecipeParameter> slots = {
      RecipeParameter{"path",      "string",  std::nullopt},
      RecipeParameter{"target_id", "integer", std::nullopt},
  };
  json call_params = {
      {"target_id", "{target_id}"},
      {"name",      "btp_state"},
      {"nested", {
          {"path",  "{path}"},
          {"flags", json::array({"{path}", "literal"})},
      }},
  };
  json caller = {
      {"path",      "/tmp/foo"},
      {"target_id", 1},
  };
  auto out = substitute_params(call_params, slots, caller);
  REQUIRE(out.ok);
  CHECK(out.params["target_id"] == 1);
  CHECK(out.params["name"] == "btp_state");
  CHECK(out.params["nested"]["path"] == "/tmp/foo");
  CHECK(out.params["nested"]["flags"][0] == "/tmp/foo");
  CHECK(out.params["nested"]["flags"][1] == "literal");
}

TEST_CASE("recipe_store: substitution falls back to default when caller omits",
          "[store][recipe][substitute]") {
  std::vector<RecipeParameter> slots = {
      RecipeParameter{"path", "string", json("/default/path")},
  };
  json call_params = {{"path", "{path}"}};
  auto out = substitute_params(call_params, slots, json::object());
  REQUIRE(out.ok);
  CHECK(out.params["path"] == "/default/path");
}

TEST_CASE("recipe_store: substitution errors on missing required parameter",
          "[store][recipe][substitute][error]") {
  std::vector<RecipeParameter> slots = {
      RecipeParameter{"path", "string", std::nullopt},
  };
  json call_params = {{"path", "{path}"}};
  auto out = substitute_params(call_params, slots, json::object());
  CHECK_FALSE(out.ok);
  CHECK(out.error.find("path") != std::string::npos);
}

TEST_CASE("recipe_store: literal calls (no slots) pass through verbatim",
          "[store][recipe][substitute]") {
  json call_params = {
      {"target_id", 7},
      {"name", "fooStruct"},
  };
  auto out = substitute_params(call_params, {}, json::object());
  REQUIRE(out.ok);
  CHECK(out.params == call_params);
}

TEST_CASE("recipe_store: substitution leaves placeholder for unknown slot alone",
          "[store][recipe][substitute]") {
  // A "{name}" string with no matching slot is NOT a substitution
  // attempt — it's a literal that happens to look like one. Pass
  // through verbatim and let the dispatcher / backend interpret.
  std::vector<RecipeParameter> slots = {
      RecipeParameter{"path", "string", std::nullopt},
  };
  json call_params = {
      {"path",  "{path}"},
      {"other", "{not_a_slot}"},
  };
  json caller = {{"path", "/x"}};
  auto out = substitute_params(call_params, slots, caller);
  REQUIRE(out.ok);
  CHECK(out.params["path"] == "/x");
  CHECK(out.params["other"] == "{not_a_slot}");
}

TEST_CASE("recipe_store: python-v1 envelope round-trips with body, empty calls",
          "[store][recipe][envelope][python]") {
  // python-v1 recipes carry `python_body` instead of a `calls` array.
  // The envelope must preserve the body verbatim across serialisation,
  // and the absence of `calls` must not corrupt parsing of `parameters`.
  Recipe r;
  r.id = 0;
  r.name = "py-echo";
  r.description = "trivial python recipe";
  r.parameters = {RecipeParameter{"target_id", "integer", json(1)}};
  r.python_body =
      "def run(ctx):\n"
      "    return {\"echoed\": ctx.get(\"target_id\")}\n";

  auto env = RecipeStore::envelope_from_recipe(r);
  REQUIRE(env.contains("python_body"));
  CHECK(env["python_body"] == r.python_body.value());
  // calls is present-but-empty so older clients don't crash on missing key.
  REQUIRE(env.contains("calls"));
  CHECK(env["calls"].empty());

  auto back = RecipeStore::recipe_from_envelope(99, "py-echo", 0, env);
  CHECK(back.id == 99);
  REQUIRE(back.python_body.has_value());
  CHECK(*back.python_body == *r.python_body);
  CHECK(back.calls.empty());
  REQUIRE(back.parameters.size() == 1);
  CHECK(back.parameters[0].name == "target_id");
}

TEST_CASE("recipe_store: envelope round-trips through artifact bytes",
          "[store][recipe][envelope]") {
  // Pin the on-disk JSON shape: bytes_b64 should decode to a recipe-v1
  // envelope readable by recipe_from_envelope.
  Recipe r;
  r.id = 0;
  r.name = "envtest";
  r.description = "round-trip pin";
  r.parameters = {RecipeParameter{"path", "string", json("/d")}};
  r.calls = {RecipeCall{"hello", json::object()},
             RecipeCall{"target.open", json{{"path", "{path}"}}}};

  auto env = RecipeStore::envelope_from_recipe(r);
  REQUIRE(env.contains("calls"));
  REQUIRE(env.contains("parameters"));
  CHECK(env["description"] == "round-trip pin");
  CHECK(env["calls"].size() == 2);

  auto back = RecipeStore::recipe_from_envelope(42, "envtest", 0, env);
  CHECK(back.id == 42);
  CHECK(back.name == "envtest");
  REQUIRE(back.calls.size() == 2);
  CHECK(back.calls[1].method == "target.open");
  CHECK(back.calls[1].params == json{{"path", "{path}"}});
  REQUIRE(back.parameters.size() == 1);
  CHECK(back.parameters[0].name == "path");
  REQUIRE(back.parameters[0].default_value.has_value());
  CHECK(*back.parameters[0].default_value == "/d");
}
