// SPDX-License-Identifier: Apache-2.0
// Tests for lint_recipe() (recipe_store.h) and the recipe.lint dispatcher
// endpoint.  Covers the §6 reviewer finding: unknown placeholders like
// "{patH}" (wrong case) pass through substitute_walk verbatim, silently
// masking author typos.
//
// lint_recipe() surfaces:
//   - unknown placeholders — strings that look like {slot} but don't match
//     any declared parameter name
//   - unused declared slots — parameters declared but never referenced in
//     any step's params

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"
#include "daemon/dispatcher.h"
#include "protocol/jsonrpc.h"
#include "store/artifact_store.h"
#include "store/recipe_store.h"

#include <cstdio>
#include <filesystem>
#include <memory>
#include <random>
#include <string>
#include <system_error>

namespace fs = std::filesystem;
using ldb::backend::LldbBackend;
using ldb::daemon::Dispatcher;
using ldb::protocol::Request;
using ldb::store::ArtifactStore;
using ldb::store::LintWarning;
using ldb::store::Recipe;
using ldb::store::RecipeCall;
using ldb::store::RecipeParameter;
using ldb::store::RecipeStore;
using ldb::store::lint_recipe;
using nlohmann::json;

// ── helpers ────────────────────────────────────────────────────────────────

static Recipe make_recipe(
    std::vector<RecipeParameter> params,
    std::vector<RecipeCall> calls) {
  Recipe r;
  r.id   = 1;
  r.name = "test";
  r.parameters = std::move(params);
  r.calls = std::move(calls);
  return r;
}

static RecipeParameter slot(std::string name) {
  RecipeParameter p;
  p.name = std::move(name);
  p.type = "string";
  return p;
}

static RecipeCall call(std::string method, json params) {
  RecipeCall c;
  c.method = std::move(method);
  c.params = std::move(params);
  return c;
}

// ── lint_recipe() unit tests ────────────────────────────────────────────────

TEST_CASE("lint_recipe: no-param recipe with no placeholders → clean",
          "[recipe][lint]") {
  auto r = make_recipe({}, {call("target.open", {{"path", "/bin/ls"}})});
  auto w = lint_recipe(r);
  CHECK(w.empty());
}

TEST_CASE("lint_recipe: known placeholder → no warning",
          "[recipe][lint]") {
  auto r = make_recipe(
      {slot("path")},
      {call("target.open", {{"path", "{path}"}})});
  auto w = lint_recipe(r);
  CHECK(w.empty());
}

TEST_CASE("lint_recipe: wrong-case placeholder → unknown warning",
          "[recipe][lint]") {
  // Declared slot is "path" but recipe uses "{patH}" — that's a typo.
  auto r = make_recipe(
      {slot("path")},
      {call("target.open", {{"path", "{patH}"}})});
  auto w = lint_recipe(r);
  // One warning for unknown placeholder {patH}, one for unused slot {path}.
  REQUIRE_FALSE(w.empty());
  bool found_unknown = false;
  bool found_unused  = false;
  for (const auto& wi : w) {
    if (wi.message.find("patH") != std::string::npos) found_unknown = true;
    if (wi.message.find("unused") != std::string::npos) found_unused  = true;
  }
  CHECK(found_unknown);
  CHECK(found_unused);
}

TEST_CASE("lint_recipe: unused declared slot → warning",
          "[recipe][lint]") {
  // Slot "path" is declared but no step references {path}.
  auto r = make_recipe(
      {slot("path")},
      {call("target.open", {{"path", "/hardcoded/value"}})});
  auto w = lint_recipe(r);
  REQUIRE(w.size() == 1);
  CHECK(w[0].step_index == -1);  // unused slot warning has step_index -1
  CHECK(w[0].message.find("unused") != std::string::npos);
  CHECK(w[0].message.find("path") != std::string::npos);
}

TEST_CASE("lint_recipe: multiple unknown placeholders across steps",
          "[recipe][lint]") {
  auto r = make_recipe(
      {},
      {call("target.open", {{"path", "{target_path}"}}),
       call("type.layout",  {{"type_name", "{tYpe}"},
                              {"target_id", "{tid}"}})});
  auto w = lint_recipe(r);
  // Three unknowns: target_path, tYpe, tid.
  CHECK(w.size() == 3);
  std::vector<std::string> msgs;
  for (const auto& wi : w) msgs.push_back(wi.message);
  bool has_target_path = false, has_tYpe = false, has_tid = false;
  for (const auto& m : msgs) {
    if (m.find("target_path") != std::string::npos) has_target_path = true;
    if (m.find("tYpe")        != std::string::npos) has_tYpe        = true;
    if (m.find("tid")         != std::string::npos) has_tid         = true;
  }
  CHECK(has_target_path);
  CHECK(has_tYpe);
  CHECK(has_tid);
}

TEST_CASE("lint_recipe: nested object params are walked",
          "[recipe][lint]") {
  // Placeholder nested inside an array inside an object.
  auto r = make_recipe(
      {slot("name")},
      {call("some.method", {{"args", json::array({{{"x", "{name}"}}})}})});
  auto w = lint_recipe(r);
  CHECK(w.empty());
}

TEST_CASE("lint_recipe: string literal that looks like placeholder but is too short",
          "[recipe][lint]") {
  // "{}" and "{x}" (len < 3 means only "{}" which is len 2 < 3) — not a placeholder.
  // Actually "{x}" IS len 3 and has inner "x" — that IS a placeholder.
  // But "{}" is len 2 → not a placeholder.
  auto r = make_recipe(
      {},
      {call("m", {{"a", "{}"}, {"b", "not-a-placeholder"}})});
  auto w = lint_recipe(r);
  CHECK(w.empty());
}

// ── dispatcher endpoint tests ───────────────────────────────────────────────

namespace {

struct TmpStoreRoot {
  fs::path root;
  TmpStoreRoot() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    char buf[48];
    std::snprintf(buf, sizeof(buf), "ldb_recipe_lint_%016llx",
                  static_cast<unsigned long long>(gen()));
    root = fs::temp_directory_path() / buf;
    std::error_code ec;
    fs::remove_all(root, ec);
    fs::create_directories(root, ec);
  }
  ~TmpStoreRoot() {
    std::error_code ec;
    fs::remove_all(root, ec);
  }
};

Request make_req(std::string method, json params) {
  Request r;
  r.id     = json("r1");
  r.method = std::move(method);
  r.params = std::move(params);
  return r;
}

}  // namespace

TEST_CASE("recipe.lint dispatcher: missing recipe_id → -32602",
          "[recipe][lint][dispatcher]") {
  TmpStoreRoot tmp;
  auto backend = std::make_shared<LldbBackend>();
  auto store   = std::make_shared<ArtifactStore>(tmp.root);
  Dispatcher d(backend, store);

  auto resp = d.dispatch(make_req("recipe.lint", {}));
  CHECK(static_cast<int>(resp.error_code) == -32602);
}

TEST_CASE("recipe.lint dispatcher: unknown id → -32000",
          "[recipe][lint][dispatcher]") {
  TmpStoreRoot tmp;
  auto backend = std::make_shared<LldbBackend>();
  auto store   = std::make_shared<ArtifactStore>(tmp.root);
  Dispatcher d(backend, store);

  auto resp = d.dispatch(make_req("recipe.lint", {{"recipe_id", 9999}}));
  CHECK(static_cast<int>(resp.error_code) == -32000);
}

TEST_CASE("recipe.lint dispatcher: clean recipe → warnings:[]",
          "[recipe][lint][dispatcher]") {
  TmpStoreRoot tmp;
  auto backend = std::make_shared<LldbBackend>();
  auto store   = std::make_shared<ArtifactStore>(tmp.root);
  Dispatcher d(backend, store);

  // Create a recipe with a matching slot.
  auto cr = d.dispatch(make_req("recipe.create", {
      {"name", "clean"},
      {"parameters", json::array({{{"name", "path"}, {"type", "string"}}})},
      {"calls", json::array({{{"method", "target.open"},
                               {"params", {{"path", "{path}"}}}}})}
  }));
  REQUIRE(cr.ok);
  std::int64_t rid = cr.data["recipe_id"].get<std::int64_t>();

  auto resp = d.dispatch(make_req("recipe.lint", {{"recipe_id", rid}}));
  REQUIRE(resp.ok);
  CHECK(resp.data["warnings"].is_array());
  CHECK(resp.data["warnings"].empty());
  CHECK(resp.data["warning_count"] == 0);
}

TEST_CASE("recipe.lint dispatcher: typo placeholder → warning",
          "[recipe][lint][dispatcher]") {
  TmpStoreRoot tmp;
  auto backend = std::make_shared<LldbBackend>();
  auto store   = std::make_shared<ArtifactStore>(tmp.root);
  Dispatcher d(backend, store);

  auto cr = d.dispatch(make_req("recipe.create", {
      {"name", "typo"},
      {"parameters", json::array({{{"name", "path"}, {"type", "string"}}})},
      {"calls", json::array({{{"method", "target.open"},
                               {"params", {{"path", "{paTh}"}}}}})}
  }));
  REQUIRE(cr.ok);
  std::int64_t rid = cr.data["recipe_id"].get<std::int64_t>();

  auto resp = d.dispatch(make_req("recipe.lint", {{"recipe_id", rid}}));
  REQUIRE(resp.ok);
  CHECK_FALSE(resp.data["warnings"].empty());
  CHECK(resp.data["warning_count"].get<int>() > 0);
  // At least one warning mentions "paTh".
  bool found = false;
  for (const auto& w : resp.data["warnings"]) {
    if (w["message"].get<std::string>().find("paTh") != std::string::npos)
      found = true;
  }
  CHECK(found);
}
