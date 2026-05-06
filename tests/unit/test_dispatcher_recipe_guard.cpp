// Recursion guard for recipe.run sub-calls (post-§6 reviewer fix).
//
// Background: §6 shipped recipes as named, replayable RPC sequences.
// The §6 reviewer surfaced a SIGSEGV path: a hand-crafted recipe whose
// `calls` array contains `recipe.run` referencing itself recurses
// through dispatch_inner without a depth bound and blows the daemon's
// stack. recipe.from_session is safe (its strip-set drops `recipe.*`),
// but recipe.create accepts arbitrary call lists.
//
// Fix: handle_recipe_run rejects any `recipe.*` sub-call with -32003
// kForbidden + stops execution. The agent can compose recipes
// out-of-band (the wrapper, not the recipe body, calls recipe.run).
//
// This test pins the contract: a recursive recipe runs to completion
// without crashing and surfaces kForbidden on the offending sub-call.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"
#include "daemon/dispatcher.h"
#include "protocol/jsonrpc.h"
#include "store/artifact_store.h"

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
using nlohmann::json;

namespace {

struct TmpStoreRoot {
  fs::path root;
  TmpStoreRoot() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    char buf[48];
    std::snprintf(buf, sizeof(buf), "ldb_recipe_guard_%016llx",
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

Request make_req(const char* method, json params = json::object(),
                 const char* id = "rX") {
  Request r;
  r.id     = id;
  r.method = method;
  r.params = std::move(params);
  return r;
}

}  // namespace

TEST_CASE("recipe.run rejects recipe.* sub-calls (no SIGSEGV)",
          "[dispatcher][recipe][guard]") {
  TmpStoreRoot tmp;
  auto backend   = std::make_shared<LldbBackend>();
  auto artifacts = std::make_shared<ArtifactStore>(tmp.root);
  Dispatcher dispatcher(backend, artifacts, nullptr, nullptr, nullptr);

  // Create a self-referential recipe: its only call is `recipe.run`
  // pointing at recipe_id 1 (which will be the recipe we're creating).
  json create_params = {
    {"name",        "loop_self"},
    {"description", "Recipe that calls recipe.run on its own id."},
    {"calls", json::array({
      json{
        {"method", "recipe.run"},
        {"params", json{{"recipe_id", 1}}},
      }
    })}
  };
  auto create_resp = dispatcher.dispatch(make_req("recipe.create", create_params));
  REQUIRE(create_resp.ok);
  std::int64_t recipe_id = create_resp.data["recipe_id"].get<std::int64_t>();
  REQUIRE(recipe_id == 1);

  // Run it. Without the guard the daemon would recurse forever and
  // SIGSEGV the test process. With the guard the wrapper succeeds and
  // responses[0] reports the offending sub-call as forbidden.
  auto run_resp = dispatcher.dispatch(
      make_req("recipe.run", json{{"recipe_id", recipe_id}}));
  REQUIRE(run_resp.ok);

  REQUIRE(run_resp.data.contains("responses"));
  const auto& responses = run_resp.data["responses"];
  REQUIRE(responses.is_array());
  REQUIRE(responses.size() == 1);

  const auto& entry = responses[0];
  CHECK(entry["seq"].get<std::int64_t>() == 1);
  CHECK(entry["method"].get<std::string>() == "recipe.run");
  CHECK_FALSE(entry["ok"].get<bool>());
  REQUIRE(entry.contains("error"));
  CHECK(entry["error"]["code"].get<int>() ==
        static_cast<int>(ldb::protocol::ErrorCode::kForbidden));
  CHECK(entry["error"]["message"].get<std::string>().find("recipe.")
        != std::string::npos);
}

TEST_CASE("recipe.run rejects any recipe.* method, not just recipe.run",
          "[dispatcher][recipe][guard]") {
  TmpStoreRoot tmp;
  auto backend   = std::make_shared<LldbBackend>();
  auto artifacts = std::make_shared<ArtifactStore>(tmp.root);
  Dispatcher dispatcher(backend, artifacts, nullptr, nullptr, nullptr);

  // recipe.create inside a recipe is also pointless and rejected.
  json create_params = {
    {"name",  "create_inside"},
    {"calls", json::array({
      json{
        {"method", "recipe.create"},
        {"params", json{{"name", "child"},
                        {"calls", json::array({
                          json{{"method", "hello"}, {"params", json::object()}}
                        })}}}
      }
    })}
  };
  auto create_resp = dispatcher.dispatch(make_req("recipe.create", create_params));
  REQUIRE(create_resp.ok);
  std::int64_t recipe_id = create_resp.data["recipe_id"].get<std::int64_t>();

  auto run_resp = dispatcher.dispatch(
      make_req("recipe.run", json{{"recipe_id", recipe_id}}));
  REQUIRE(run_resp.ok);
  const auto& responses = run_resp.data["responses"];
  REQUIRE(responses.size() == 1);
  CHECK_FALSE(responses[0]["ok"].get<bool>());
  CHECK(responses[0]["error"]["code"].get<int>() ==
        static_cast<int>(ldb::protocol::ErrorCode::kForbidden));
}
