// SPDX-License-Identifier: Apache-2.0
// Unit tests for RecipeStore file-backed recipes and reload
// (post-V1 plan #3).
//
// Contract under test:
//
//   * create_from_file(path) parses the JSON file as a recipe envelope
//     plus a top-level "name" string, inserts via the usual create()
//     path, and stores the absolute source path in artifact meta so
//     reload() can find it later.
//   * The resulting Recipe has source_path set to the absolute path.
//   * reload(recipe_id) re-reads the source file, parses the updated
//     envelope, replaces the store entry (new artifact id under the
//     ArtifactStore (build_id, name) collision rule), and returns the
//     new Recipe. The old recipe id no longer resolves via get().
//   * reload() on a recipe that was NOT created_from_file throws
//     backend::Error with a message including "source_path" so the
//     dispatcher can map to -32003 forbidden.
//   * reload() on a missing file throws backend::Error with a message
//     including "no such file" so the operator knows what happened.
//   * load_from_directory(dir) iterates *.json under dir, calls
//     create_from_file on each, and returns a per-file ScanResult.
//     Malformed files produce a non-empty error string but do not
//     fail the whole scan.

#include <catch_amalgamated.hpp>

#include "backend/debugger_backend.h"
#include "store/artifact_store.h"
#include "store/recipe_store.h"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <random>
#include <system_error>

namespace fs = std::filesystem;
using ldb::store::ArtifactStore;
using ldb::store::Recipe;
using ldb::store::RecipeStore;
using nlohmann::json;

namespace {

struct TmpDir {
  fs::path path;
  explicit TmpDir(const char* prefix) {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%s_%016llx",
                  prefix, static_cast<unsigned long long>(gen()));
    path = fs::temp_directory_path() / buf;
    std::error_code ec;
    fs::remove_all(path, ec);
    fs::create_directories(path, ec);
  }
  ~TmpDir() {
    std::error_code ec;
    fs::remove_all(path, ec);
  }
};

void write_recipe_file(const fs::path& p, const json& env) {
  std::ofstream out(p);
  out << env.dump(2);
}

json sample_envelope(const std::string& name) {
  return json{
      {"name", name},
      {"description", "test recipe"},
      {"parameters", json::array({
          json{{"name", "path"}, {"type", "string"}},
      })},
      {"calls", json::array({
          json{{"method", "target.open"},
               {"params", json{{"path", "{path}"}}}},
      })},
  };
}

}  // namespace

TEST_CASE("recipe_store: create_from_file populates source_path",
          "[store][recipe][reload]") {
  TmpDir store_root("ldb_reload_store");
  TmpDir recipes_dir("ldb_reload_recipes");
  ArtifactStore store(store_root.path);
  RecipeStore rs(store);

  fs::path file = recipes_dir.path / "demo.json";
  write_recipe_file(file, sample_envelope("demo"));

  auto r = rs.create_from_file(file);
  CHECK(r.name == "demo");
  CHECK(r.calls.size() == 1);
  REQUIRE(r.source_path.has_value());
  // Store as the absolute path so reload's filesystem lookup is robust
  // regardless of the caller's cwd at the time of reload.
  CHECK(fs::path(*r.source_path).is_absolute());
  CHECK(fs::canonical(*r.source_path) == fs::canonical(file));
}

TEST_CASE("recipe_store: reload re-reads + replaces from disk",
          "[store][recipe][reload]") {
  TmpDir store_root("ldb_reload_store");
  TmpDir recipes_dir("ldb_reload_recipes");
  ArtifactStore store(store_root.path);
  RecipeStore rs(store);

  fs::path file = recipes_dir.path / "demo.json";
  write_recipe_file(file, sample_envelope("demo"));
  auto first = rs.create_from_file(file);
  auto first_id = first.id;
  REQUIRE(first.calls.size() == 1);

  // Modify on disk: add a second call.
  json updated = sample_envelope("demo");
  updated["calls"].push_back(
      json{{"method", "module.list"},
           {"params", json{{"target_id", 1}}}});
  write_recipe_file(file, updated);

  auto reloaded = rs.reload(first_id);
  CHECK(reloaded.calls.size() == 2);
  CHECK(reloaded.name == "demo");
  REQUIRE(reloaded.source_path.has_value());
  CHECK(fs::canonical(*reloaded.source_path) == fs::canonical(file));

  // Post-replace, get() on the new id returns the updated recipe.
  auto got = rs.get(reloaded.id);
  REQUIRE(got.has_value());
  CHECK(got->calls.size() == 2);
}

TEST_CASE("recipe_store: reload on store-only recipe is forbidden",
          "[store][recipe][reload][error]") {
  TmpDir store_root("ldb_reload_store");
  ArtifactStore store(store_root.path);
  RecipeStore rs(store);

  // Normal create() — no file backing.
  auto r = rs.create("store_only",
                     std::optional<std::string>{},
                     {}, {});
  REQUIRE(r.id > 0);
  REQUIRE_FALSE(r.source_path.has_value());

  // reload() must reject — message must contain "source_path" so the
  // dispatcher can route to -32003.
  try {
    rs.reload(r.id);
    FAIL("reload of non-file-backed recipe should have thrown");
  } catch (const ldb::backend::Error& e) {
    const std::string what = e.what();
    CHECK(what.find("source_path") != std::string::npos);
  }
}

TEST_CASE("recipe_store: reload on vanished file throws clearly",
          "[store][recipe][reload][error]") {
  TmpDir store_root("ldb_reload_store");
  TmpDir recipes_dir("ldb_reload_recipes");
  ArtifactStore store(store_root.path);
  RecipeStore rs(store);

  fs::path file = recipes_dir.path / "ephemeral.json";
  write_recipe_file(file, sample_envelope("ephemeral"));
  auto r = rs.create_from_file(file);

  // Operator deletes the file.
  fs::remove(file);

  try {
    rs.reload(r.id);
    FAIL("reload of vanished file should have thrown");
  } catch (const ldb::backend::Error& e) {
    const std::string what = e.what();
    // Must surface a recognisable filesystem error so the dispatcher
    // can map it to a useful message instead of a generic -32000.
    CHECK((what.find("no such file") != std::string::npos ||
           what.find("does not exist") != std::string::npos ||
           what.find("not found") != std::string::npos ||
           what.find("cannot open") != std::string::npos));
  }
}

TEST_CASE("recipe_store: load_from_directory scans .json files",
          "[store][recipe][reload]") {
  TmpDir store_root("ldb_reload_store");
  TmpDir recipes_dir("ldb_reload_recipes");
  ArtifactStore store(store_root.path);
  RecipeStore rs(store);

  write_recipe_file(recipes_dir.path / "a.json", sample_envelope("a"));
  write_recipe_file(recipes_dir.path / "b.json", sample_envelope("b"));
  // Non-json file is ignored.
  std::ofstream(recipes_dir.path / "notes.txt") << "ignore me";
  // Malformed json must NOT block the scan — report it instead.
  std::ofstream(recipes_dir.path / "broken.json") << "{ not valid";

  auto results = rs.load_from_directory(recipes_dir.path);
  REQUIRE(results.size() == 3);  // a.json, b.json, broken.json

  int ok_count = 0;
  int err_count = 0;
  for (const auto& s : results) {
    if (s.error.empty()) {
      ++ok_count;
      CHECK(s.recipe_id.has_value());
    } else {
      ++err_count;
      CHECK_FALSE(s.recipe_id.has_value());
    }
  }
  CHECK(ok_count == 2);
  CHECK(err_count == 1);

  // The two valid recipes are now visible through list().
  auto all = rs.list();
  CHECK(all.size() == 2);
}
