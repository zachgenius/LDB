// SPDX-License-Identifier: Apache-2.0
#include "store/recipe_store.h"

#include "backend/debugger_backend.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>

namespace ldb::store {

namespace {

[[noreturn]] void throw_recipe_error(std::string_view ctx) {
  throw backend::Error(std::string("recipe_store: ") + std::string(ctx));
}

// "{name}" wrapping rules: a substitution placeholder is a string of
// length >= 3 starting with '{', ending with '}', interior is the slot
// name (no whitespace, no nested braces). Returns the slot name on
// match, empty string on no match.
std::string match_placeholder(const std::string& s) {
  if (s.size() < 3 || s.front() != '{' || s.back() != '}') return {};
  std::string inner(s.begin() + 1, s.end() - 1);
  if (inner.empty()) return {};
  for (char c : inner) {
    if (c == '{' || c == '}' || c == ' ' || c == '\t' || c == '\n') {
      return {};
    }
  }
  return inner;
}

// Recursive substitution helper. `out_error` is set on the first
// missing-required-slot encounter; subsequent calls early-out so the
// caller sees the first failure deterministically.
nlohmann::json substitute_walk(const nlohmann::json& v,
                               const std::vector<RecipeParameter>& slots,
                               const nlohmann::json& caller_args,
                               std::string& out_error) {
  if (!out_error.empty()) return v;
  if (v.is_string()) {
    auto s = v.get<std::string>();
    auto slot_name = match_placeholder(s);
    if (slot_name.empty()) return v;
    // Look up a declared slot. Unknown slot names are LITERALS (a
    // string that happens to look like a placeholder) — pass through.
    auto it = std::find_if(slots.begin(), slots.end(),
        [&](const RecipeParameter& p) { return p.name == slot_name; });
    if (it == slots.end()) return v;

    if (caller_args.is_object() && caller_args.contains(slot_name)) {
      return caller_args.at(slot_name);
    }
    if (it->default_value.has_value()) {
      return *it->default_value;
    }
    out_error = "missing required parameter '" + slot_name + "'";
    return v;
  }
  if (v.is_object()) {
    nlohmann::json out = nlohmann::json::object();
    for (auto it = v.begin(); it != v.end(); ++it) {
      out[it.key()] = substitute_walk(it.value(), slots, caller_args,
                                      out_error);
    }
    return out;
  }
  if (v.is_array()) {
    nlohmann::json out = nlohmann::json::array();
    for (const auto& el : v) {
      out.push_back(substitute_walk(el, slots, caller_args, out_error));
    }
    return out;
  }
  return v;
}

}  // namespace

const std::vector<std::string>& recipe_default_strip_methods() {
  static const std::vector<std::string> kStripped = {
      "hello",
      "describe.endpoints",
      "session.create",
      "session.attach",
      "session.detach",
      "session.list",
      "session.info",
      // Recipe.* introspection should not be replayed inside a recipe.
      "recipe.create",
      "recipe.from_session",
      "recipe.list",
      "recipe.get",
      "recipe.run",
      "recipe.delete",
  };
  return kStripped;
}

SubstitutionResult
substitute_params(const nlohmann::json&            params,
                  const std::vector<RecipeParameter>& slots,
                  const nlohmann::json&             caller_args) {
  SubstitutionResult out;
  std::string err;
  out.params = substitute_walk(params, slots, caller_args, err);
  if (!err.empty()) {
    out.ok = false;
    out.error = err;
    return out;
  }
  out.ok = true;
  return out;
}

// ---------------------------------------------------------------------------

nlohmann::json RecipeStore::envelope_from_recipe(const Recipe& r) {
  nlohmann::json env = nlohmann::json::object();
  if (r.description.has_value()) env["description"] = *r.description;
  nlohmann::json params = nlohmann::json::array();
  for (const auto& p : r.parameters) {
    nlohmann::json one;
    one["name"] = p.name;
    one["type"] = p.type;
    if (p.default_value.has_value()) one["default"] = *p.default_value;
    params.push_back(std::move(one));
  }
  env["parameters"] = std::move(params);
  nlohmann::json calls = nlohmann::json::array();
  for (const auto& c : r.calls) {
    nlohmann::json one;
    one["method"] = c.method;
    one["params"] = c.params;
    calls.push_back(std::move(one));
  }
  env["calls"] = std::move(calls);
  if (r.python_body.has_value()) {
    env["python_body"] = *r.python_body;
  }
  return env;
}

Recipe RecipeStore::recipe_from_envelope(std::int64_t   id,
                                         std::string    name,
                                         std::int64_t   created_at,
                                         const nlohmann::json& env) {
  Recipe r;
  r.id = id;
  r.name = std::move(name);
  r.created_at = created_at;
  if (env.contains("description") && env["description"].is_string()) {
    r.description = env["description"].get<std::string>();
  }
  if (env.contains("parameters") && env["parameters"].is_array()) {
    for (const auto& p : env["parameters"]) {
      RecipeParameter slot;
      if (p.contains("name") && p["name"].is_string()) {
        slot.name = p["name"].get<std::string>();
      }
      if (p.contains("type") && p["type"].is_string()) {
        slot.type = p["type"].get<std::string>();
      } else {
        slot.type = "string";
      }
      if (p.contains("default") && !p["default"].is_null()) {
        slot.default_value = p["default"];
      }
      r.parameters.push_back(std::move(slot));
    }
  }
  if (env.contains("calls") && env["calls"].is_array()) {
    for (const auto& c : env["calls"]) {
      RecipeCall call;
      if (c.contains("method") && c["method"].is_string()) {
        call.method = c["method"].get<std::string>();
      }
      if (c.contains("params")) {
        call.params = c["params"];
      }
      r.calls.push_back(std::move(call));
    }
  }
  if (env.contains("python_body") && env["python_body"].is_string()) {
    r.python_body = env["python_body"].get<std::string>();
  }
  return r;
}

RecipeStore::RecipeStore(ArtifactStore& store) : store_(&store) {}

Recipe RecipeStore::create(std::string                  name,
                           std::optional<std::string>   description,
                           std::vector<RecipeParameter> parameters,
                           std::vector<RecipeCall>      calls) {
  return create_with_source(std::move(name), std::move(description),
                            std::move(parameters), std::move(calls),
                            /*source_path=*/std::nullopt);
}

Recipe RecipeStore::create_with_source(
    std::string                  name,
    std::optional<std::string>   description,
    std::vector<RecipeParameter> parameters,
    std::vector<RecipeCall>      calls,
    std::optional<std::string>   source_path) {
  return create_internal(std::move(name), std::move(description),
                         std::move(parameters), std::move(calls),
                         /*python_body=*/std::nullopt,
                         std::move(source_path));
}

Recipe RecipeStore::create_python_recipe(
    std::string                  name,
    std::optional<std::string>   description,
    std::vector<RecipeParameter> parameters,
    std::string                  python_body) {
  if (python_body.empty()) {
    throw_recipe_error("python_body must be non-empty for python-v1 recipes");
  }
  return create_internal(std::move(name), std::move(description),
                         std::move(parameters), /*calls=*/{},
                         std::optional<std::string>(std::move(python_body)),
                         /*source_path=*/std::nullopt);
}

Recipe RecipeStore::create_internal(
    std::string                  name,
    std::optional<std::string>   description,
    std::vector<RecipeParameter> parameters,
    std::vector<RecipeCall>      calls,
    std::optional<std::string>   python_body,
    std::optional<std::string>   source_path) {
  if (name.empty()) throw_recipe_error("recipe name must be non-empty");

  // Reject duplicate parameter slot names — they'd race in
  // substitute_params and the caller would never know which won.
  {
    std::set<std::string> seen;
    for (const auto& p : parameters) {
      if (p.name.empty()) {
        throw_recipe_error("parameter slot name must be non-empty");
      }
      if (!seen.insert(p.name).second) {
        throw_recipe_error("duplicate parameter slot name: " + p.name);
      }
    }
  }

  Recipe r;
  r.name = std::move(name);
  r.description = std::move(description);
  r.parameters = std::move(parameters);
  r.calls = std::move(calls);
  r.python_body = std::move(python_body);
  r.source_path = source_path;

  auto env = envelope_from_recipe(r);
  std::string body = env.dump();
  std::vector<std::uint8_t> bytes(body.begin(), body.end());

  // The artifact's meta carries the high-level fields so list() doesn't
  // have to read+parse every blob just for "show me a directory." When
  // source_path is set (post-V1 plan #3 file-backed recipes) it lives
  // in meta so reload() can recover it without a separate index.
  nlohmann::json meta = nlohmann::json::object();
  meta["recipe_name"] = r.name;
  if (r.description.has_value()) meta["description"] = *r.description;
  meta["call_count"] = static_cast<std::int64_t>(r.calls.size());
  meta["parameter_count"] =
      static_cast<std::int64_t>(r.parameters.size());
  if (r.source_path.has_value()) meta["source_path"] = *r.source_path;
  if (r.python_body.has_value()) meta["python_v1"] = true;

  auto row = store_->put(kRecipeBuildId,
                         std::string(kRecipeNamePrefix) + r.name,
                         bytes,
                         std::string(kRecipeFormat),
                         meta);
  r.id = row.id;
  r.created_at = row.created_at;
  return r;
}

std::optional<Recipe> RecipeStore::get(std::int64_t id) {
  auto row = store_->get_by_id(id);
  if (!row.has_value()) return std::nullopt;
  if (!row->format.has_value() || *row->format != kRecipeFormat) {
    // The artifact id exists but isn't a recipe — an agent that
    // looked up an arbitrary id shouldn't be told "you found a
    // mem.dump_artifact, here's a corrupt envelope."
    return std::nullopt;
  }
  auto bytes = store_->read_blob(*row);
  std::string text(bytes.begin(), bytes.end());
  nlohmann::json env;
  try {
    env = nlohmann::json::parse(text);
  } catch (const std::exception& e) {
    throw_recipe_error(std::string("malformed envelope on disk: ") + e.what());
  }
  // Strip the "recipe:" prefix from the artifact name to recover the
  // operator-supplied recipe name.
  std::string display_name = row->name;
  std::string prefix = kRecipeNamePrefix;
  if (display_name.rfind(prefix, 0) == 0) {
    display_name.erase(0, prefix.size());
  }
  Recipe r = recipe_from_envelope(row->id, std::move(display_name),
                                  row->created_at, env);
  // Recover the source_path written by create_with_source (plan #3).
  if (row->meta.is_object() && row->meta.contains("source_path") &&
      row->meta["source_path"].is_string()) {
    r.source_path = row->meta["source_path"].get<std::string>();
  }
  return r;
}

std::vector<Recipe> RecipeStore::list() {
  auto rows = store_->list(std::string(kRecipeBuildId), std::nullopt);
  std::vector<Recipe> out;
  out.reserve(rows.size());
  for (const auto& row : rows) {
    if (!row.format.has_value() || *row.format != kRecipeFormat) continue;
    auto r = get(row.id);
    if (r.has_value()) out.push_back(std::move(*r));
  }
  return out;
}

bool RecipeStore::remove(std::int64_t id) {
  // Verify the row IS a recipe before deleting — defends against an
  // agent calling recipe.delete on an unrelated artifact id.
  auto row = store_->get_by_id(id);
  if (!row.has_value()) return false;
  if (!row->format.has_value() || *row->format != kRecipeFormat) {
    return false;
  }
  return store_->remove(id);
}

// ── File-backed recipes (post-V1 plan #3) ──────────────────────────────

namespace {

// Parse a file as a recipe envelope plus top-level "name". Returns the
// parsed pieces ready to feed into create_with_source. Throws
// backend::Error with a filesystem-recognisable message on any
// read/parse failure — the dispatcher relies on the wording to route
// to the right JSON-RPC error code.
struct ParsedRecipeFile {
  std::string                  name;
  std::optional<std::string>   description;
  std::vector<RecipeParameter> parameters;
  std::vector<RecipeCall>      calls;
};

ParsedRecipeFile parse_recipe_file(const std::filesystem::path& path) {
  std::error_code ec;
  if (!std::filesystem::exists(path, ec) || ec) {
    throw_recipe_error("no such file: " + path.string());
  }
  std::ifstream in(path);
  if (!in) {
    throw_recipe_error("cannot open recipe file: " + path.string());
  }
  std::ostringstream buf;
  buf << in.rdbuf();
  nlohmann::json env;
  try {
    env = nlohmann::json::parse(buf.str());
  } catch (const std::exception& e) {
    throw_recipe_error("malformed recipe file " + path.string() + ": "
                       + e.what());
  }
  if (!env.is_object()) {
    throw_recipe_error("recipe file " + path.string() +
                       " top-level must be a JSON object");
  }
  if (!env.contains("name") || !env["name"].is_string()) {
    throw_recipe_error("recipe file " + path.string() +
                       " missing top-level string 'name'");
  }

  ParsedRecipeFile out;
  out.name = env["name"].get<std::string>();

  // recipe_from_envelope expects the envelope shape without "name"
  // (the artifact name carries it). Hand it a flat copy.
  auto stub = RecipeStore::recipe_from_envelope(/*id=*/0, out.name,
                                                /*created_at=*/0, env);
  out.description = stub.description;
  out.parameters = std::move(stub.parameters);
  out.calls = std::move(stub.calls);
  return out;
}

}  // namespace

Recipe RecipeStore::create_from_file(const std::filesystem::path& path) {
  auto parsed = parse_recipe_file(path);
  // Canonicalize so reload() doesn't lose the recipe when the operator
  // changes their cwd. weakly_canonical is fine — the existence check
  // already happened in parse_recipe_file.
  std::error_code ec;
  auto abs = std::filesystem::weakly_canonical(path, ec);
  if (ec) abs = std::filesystem::absolute(path);
  return create_with_source(std::move(parsed.name),
                            std::move(parsed.description),
                            std::move(parsed.parameters),
                            std::move(parsed.calls),
                            abs.string());
}

Recipe RecipeStore::reload(std::int64_t id) {
  auto existing = get(id);
  if (!existing.has_value()) {
    throw_recipe_error("recipe not found: " + std::to_string(id));
  }
  if (!existing->source_path.has_value()) {
    throw_recipe_error(
        "recipe " + std::to_string(id) +
        " has no source_path; only file-backed recipes (loaded via "
        "create_from_file or load_from_directory) can be reloaded");
  }
  return create_from_file(*existing->source_path);
}

std::vector<RecipeStore::ScanResult>
RecipeStore::load_from_directory(const std::filesystem::path& dir) {
  std::vector<ScanResult> out;
  std::error_code ec;
  if (!std::filesystem::is_directory(dir, ec) || ec) {
    return out;
  }
  // Stable order so reloads + smokes are deterministic.
  std::vector<std::filesystem::path> entries;
  for (const auto& de : std::filesystem::directory_iterator(dir, ec)) {
    if (de.is_regular_file() && de.path().extension() == ".json") {
      entries.push_back(de.path());
    }
  }
  std::sort(entries.begin(), entries.end());
  for (const auto& p : entries) {
    ScanResult sr;
    sr.path = p;
    try {
      auto r = create_from_file(p);
      sr.recipe_id = r.id;
    } catch (const ldb::backend::Error& e) {
      sr.error = e.what();
    } catch (const std::exception& e) {
      sr.error = e.what();
    }
    out.push_back(std::move(sr));
  }
  return out;
}

// ── lint_recipe ────────────────────────────────────────────────────────────

namespace {

void collect_placeholders(const nlohmann::json& v,
                          std::vector<std::string>& out) {
  if (v.is_string()) {
    auto name = match_placeholder(v.get<std::string>());
    if (!name.empty()) out.push_back(name);
  } else if (v.is_object()) {
    for (auto it = v.begin(); it != v.end(); ++it)
      collect_placeholders(it.value(), out);
  } else if (v.is_array()) {
    for (const auto& el : v) collect_placeholders(el, out);
  }
}

}  // namespace

std::vector<LintWarning> lint_recipe(const Recipe& r) {
  std::set<std::string> declared;
  for (const auto& p : r.parameters) declared.insert(p.name);

  std::set<std::string> used;
  std::vector<LintWarning> warnings;

  for (int i = 0; i < static_cast<int>(r.calls.size()); ++i) {
    std::vector<std::string> found;
    collect_placeholders(r.calls[static_cast<std::size_t>(i)].params, found);
    for (const auto& name : found) {
      if (declared.count(name) == 0) {
        warnings.push_back({i, "unknown placeholder: {" + name + "}"});
      } else {
        used.insert(name);
      }
    }
  }

  for (const auto& p : r.parameters) {
    if (used.count(p.name) == 0) {
      warnings.push_back(
          {-1, "declared slot {" + p.name + "} is unused in all steps"});
    }
  }

  return warnings;
}

}  // namespace ldb::store
