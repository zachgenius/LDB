// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "store/artifact_store.h"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Recipe storage (Tier 2 §6 — probe recipes).
//
// A recipe is a named, parameterized sequence of RPC calls extracted
// from a session's rpc_log. Agents use recipes to replay common
// investigation patterns ("open this binary, layout these N structs,
// find these strings, set up this probe set") without re-issuing each
// call.
//
// Storage decision: recipes are persisted in the ArtifactStore as
// `format = "recipe-v1"` artifacts under the synthetic build_id
// "_recipes" with name "recipe:<recipe-name>". The artifact's bytes
// carry the recipe envelope as compact JSON; the artifact's meta
// mirrors {description, parameters, call_count} so list() doesn't
// have to read every blob. The artifact id IS the recipe id.
//
// Why reuse artifacts:
//   • Build-ID-keyed addressing already exists.
//   • `.ldbpack` portability comes for free — recipes round-trip
//     across machines without a new pack format.
//   • One sqlite schema, one delete path (artifact.delete).
//
// Parameter substitution (MVP):
//   • The recipe author pre-templatizes each call's params: any
//     STRING value matching the literal "{paramname}" is treated as
//     a substitution slot that recipe.run() fills with the caller's
//     parameter map.
//   • Substitution is whole-string-match only; substring substitution
//     and JSONPath targeting are deferred to v0.5.
//   • Type coercion: integer / hex-string params are accepted and
//     placed verbatim into the call's params (replacing the string
//     placeholder with the typed value the caller supplied).
//
// Error policy:
//   • A missing required parameter (no default, no caller value) is
//     surfaced via Substitute()::error before any RPC is dispatched.
//   • Recipe.run is stop-on-first-error in the dispatcher layer
//     (this header doesn't issue calls — that's the dispatcher's job).

namespace ldb::store {

constexpr const char* kRecipeBuildId   = "_recipes";
constexpr const char* kRecipeFormat    = "recipe-v1";
constexpr const char* kRecipeNamePrefix = "recipe:";

// One declared parameter slot in a recipe. `default_value` is optional;
// a recipe.run with no caller value AND no default => error.
struct RecipeParameter {
  std::string                  name;     // e.g. "path"
  std::string                  type;     // "string" | "integer"
  std::optional<nlohmann::json> default_value;
};

// One call in the recipe body — exactly the {method, params} the
// dispatcher accepts.
struct RecipeCall {
  std::string    method;
  nlohmann::json params = nlohmann::json::object();
};

// In-memory representation of a recipe.
struct Recipe {
  std::int64_t                 id = 0;       // == artifact.id
  std::string                  name;         // operator-supplied
  std::optional<std::string>   description;
  std::vector<RecipeParameter> parameters;
  std::vector<RecipeCall>      calls;
  std::int64_t                 created_at = 0;
  // Absolute path to the JSON file backing this recipe, set on recipes
  // imported via create_from_file() / load_from_directory(). Recipes
  // created in-band via create() / from_session leave this nullopt.
  // recipe.reload (post-V1 plan #3) requires source_path to be set.
  std::optional<std::string>   source_path;
};

// Methods an extract-from-session pass strips — these are protocol
// bookkeeping, not investigation steps worth replaying.
const std::vector<std::string>& recipe_default_strip_methods();

// Substitute() returns: substituted params on ok=true; `error` set on
// any missing-required / unknown-param / type-mismatch case.
struct SubstitutionResult {
  bool           ok = false;
  nlohmann::json params;        // original or substituted shape
  std::string    error;         // human-readable; empty iff ok
};

// Walk `params` recursively. For every STRING value that exactly
// matches "{name}" with a name declared in `slots`, substitute the
// value from `caller_args` (if present) or the slot's default (if
// present); otherwise emit an error referring to the missing slot.
SubstitutionResult substitute_params(const nlohmann::json&            params,
                                     const std::vector<RecipeParameter>& slots,
                                     const nlohmann::json&             caller_args);

// One lint finding from lint_recipe(). `step_index` is the 0-based index
// of the offending call, or -1 for recipe-level findings (unused slots).
struct LintWarning {
  int         step_index = 0;
  std::string message;
};

// Walk every step's params and report:
//   - any {placeholder} whose name is not in the recipe's declared slots
//   - any declared slot that appears in no step's params
std::vector<LintWarning> lint_recipe(const Recipe& r);

// Manage recipes on top of an ArtifactStore.
class RecipeStore {
 public:
  // Borrows the artifact store; the store must outlive the RecipeStore.
  explicit RecipeStore(ArtifactStore& store);

  // Insert or replace a recipe. (build_id, name) collision in the
  // ArtifactStore == replace: the new recipe inherits a fresh id.
  // Throws backend::Error on a malformed envelope (e.g. duplicate
  // parameter names) or a sqlite failure.
  Recipe create(std::string                  name,
                std::optional<std::string>   description,
                std::vector<RecipeParameter> parameters,
                std::vector<RecipeCall>      calls);

  // Look up by id; nullopt if not found.
  std::optional<Recipe> get(std::int64_t id);

  // List every recipe in the store, ascending id (matches
  // ArtifactStore::list semantics).
  std::vector<Recipe> list();

  // Delete a recipe (== ArtifactStore::remove). Returns true if found.
  bool remove(std::int64_t id);

  // Helpers exposed for testing and for from_session extraction. The
  // envelope is the bytes-payload format used in storage:
  //   {"description"?: str, "parameters": [...], "calls": [...]}
  static nlohmann::json envelope_from_recipe(const Recipe& r);
  static Recipe         recipe_from_envelope(std::int64_t   id,
                                             std::string    name,
                                             std::int64_t   created_at,
                                             const nlohmann::json& env);

  // ── Post-V1 plan #3 — file-backed recipes ────────────────────────────
  //
  // create_from_file: parse a JSON file as a recipe envelope (same
  // shape as envelope_from_recipe + a top-level "name" string) and
  // insert via create(). Stores the absolute file path in artifact
  // meta so reload() can find it. Throws backend::Error on a missing
  // file, parse error, or "name" field absent.
  Recipe create_from_file(const std::filesystem::path& path);

  // reload: look up `id`, read source_path out of artifact meta,
  // re-read the file, replace the store entry. Returns the new Recipe
  // (with a fresh id per ArtifactStore::put collision semantics).
  //
  // Throws backend::Error with:
  //   * "source_path"-mentioning message when the recipe wasn't
  //     created_from_file (dispatcher maps to -32003).
  //   * a filesystem error mentioning "no such file" / similar when
  //     the source has vanished.
  Recipe reload(std::int64_t id);

  // load_from_directory: scan dir for *.json files (one level, no
  // recursion), call create_from_file on each, accumulate results
  // including per-file error messages. Malformed files do not block
  // the scan — the caller decides whether to log or exit.
  struct ScanResult {
    std::filesystem::path             path;
    std::optional<std::int64_t>       recipe_id;
    std::string                       error;   // empty on success
  };
  std::vector<ScanResult>
      load_from_directory(const std::filesystem::path& dir);

 private:
  // Insertion variant used by create() / create_from_file(). Encodes
  // the source_path into artifact meta when present.
  Recipe create_with_source(std::string                  name,
                            std::optional<std::string>   description,
                            std::vector<RecipeParameter> parameters,
                            std::vector<RecipeCall>      calls,
                            std::optional<std::string>   source_path);

  ArtifactStore* store_;
};

}  // namespace ldb::store
