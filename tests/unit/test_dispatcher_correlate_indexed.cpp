// SPDX-License-Identifier: Apache-2.0
// Dispatcher tests for the SymbolIndex-routed correlate.* path
// (post-V1 #18, docs/23-symbol-index.md §4 / §8).
//
// Two contracts pinned here:
//
//   1) When LDB_STORE_ROOT is configured, the first correlate.* call
//      against a (target_id, build_id) tuple populates the index
//      (stats.binary_count: 0 → 1) and subsequent calls against the
//      same build_id reuse the cached row (binary_count stays at 1).
//      The wire shape MUST match what the cold path would have
//      returned — same key set, same values for the non-cache-key
//      fields. This is the "cache survives RPC boundaries" guarantee
//      from §1 / §4.
//
//   2) When LDB_STORE_ROOT is unset, correlate.* still works —
//      falling through to the existing backend find_* path. The
//      dispatcher's SymbolIndex is constructed only when a store
//      root resolves, and `available()` gates every use of it.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"
#include "daemon/dispatcher.h"
#include "index/symbol_index.h"
#include "protocol/jsonrpc.h"
#include "store/artifact_store.h"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <random>
#include <string>
#include <thread>

using ldb::backend::LldbBackend;
using ldb::daemon::Dispatcher;
using ldb::protocol::Request;
using nlohmann::json;
namespace fs = std::filesystem;

namespace {

constexpr const char* kStructsPath = LDB_FIXTURE_STRUCTS_PATH;

Request make_req(const char* method, json params = json::object(),
                 const char* id = "rX") {
  Request r;
  r.id = id;
  r.method = method;
  r.params = std::move(params);
  return r;
}

fs::path make_tmp_root(std::string_view tag) {
  std::mt19937_64 rng(std::random_device{}());
  std::string suffix = std::to_string(rng());
  auto root = fs::temp_directory_path()
              / ("ldb_dispcorr_" + std::string(tag) + "_" + suffix);
  fs::remove_all(root);
  fs::create_directories(root);
  return root;
}

}  // namespace

TEST_CASE("correlate.symbols populates index on first call, "
          "reuses cache on second",
          "[dispatcher][correlate][indexed]") {
  auto root = make_tmp_root("populate_once");
  // Pin LDB_STORE_ROOT so Dispatcher constructs a SymbolIndex pointed
  // at our tempdir. unsetenv after the test to avoid leaking into
  // sibling unit tests.
  setenv("LDB_STORE_ROOT", root.c_str(), /*overwrite=*/1);

  auto be = std::make_shared<LldbBackend>();
  // Artifact store is wired so Dispatcher follows the production
  // construction path; symbol index pulls its own root from
  // LDB_STORE_ROOT (the dispatcher constructor reads the env).
  auto artifacts = std::make_shared<ldb::store::ArtifactStore>(root);
  Dispatcher d(be, artifacts);

  auto a = d.dispatch(make_req("target.open", json{{"path", kStructsPath}}));
  REQUIRE(a.ok);
  auto tid = a.data["target_id"].get<std::uint64_t>();

  // Pull the structs fixture's build_id (= UUID on ELF) from module.list.
  // This is the same key the dispatcher will use to write the index.
  auto modlist = d.dispatch(make_req("module.list",
      json{{"target_id", tid}}));
  REQUIRE(modlist.ok);
  std::string build_id;
  for (const auto& m : modlist.data["modules"]) {
    if (m["path"].get<std::string>() == kStructsPath) {
      build_id = m["uuid"].get<std::string>();
      break;
    }
  }
  if (build_id.empty()) {
    SKIP("fixture has no build_id (stripped binary?)");
  }

  // Direct stats peek via a fresh SymbolIndex pointed at the same
  // root. The dispatcher's index writes there; our reader sees the
  // same on-disk state. binary_count starts at 0 (no correlate.*
  // call has populated yet).
  {
    ldb::index::SymbolIndex idx(root);
    REQUIRE(idx.available());
    CHECK(idx.stats().binary_count == 0);
  }

  // First call: cold cache, dispatcher walks LLDB, writes index.
  auto first = d.dispatch(make_req("correlate.symbols",
      json{{"target_ids", json::array({tid})}, {"name", "main"}}));
  REQUIRE(first.ok);
  REQUIRE(first.data.contains("results"));
  REQUIRE(first.data["results"].size() == 1);
  const auto& first_matches = first.data["results"][0]["matches"];
  CHECK(first_matches.is_array());
  CHECK_FALSE(first_matches.empty());

  // Index now has exactly one binary indexed.
  {
    ldb::index::SymbolIndex idx(root);
    CHECK(idx.stats().binary_count == 1);
    CHECK(idx.stats().symbol_count > 0);
  }

  // Second call against the same target: cache_status should be kHot,
  // dispatcher serves from sqlite without re-walking. The observable
  // is "binary_count is still 1" — populate replaces the row, so a
  // re-population would still leave the count at 1 but reset the
  // populated_at timestamp. Take a populated_at snapshot to detect.
  std::int64_t pop_at = 0;
  {
    ldb::index::SymbolIndex idx(root);
    auto bin = idx.get_binary(build_id);
    REQUIRE(bin.has_value());
    pop_at = bin->populated_at_ns;
    REQUIRE(pop_at > 0);
  }

  // Sleep 2ms so a re-population would produce a different timestamp.
  std::this_thread::sleep_for(std::chrono::milliseconds(2));

  auto second = d.dispatch(make_req("correlate.symbols",
      json{{"target_ids", json::array({tid})}, {"name", "main"}}));
  REQUIRE(second.ok);

  // Wire shape MUST match the cold-path response. The view envelope's
  // `next_offset` is conditional; compare the parts that matter for
  // the cache contract: results, total.
  CHECK(second.data["results"] == first.data["results"]);
  CHECK(second.data["total"] == first.data["total"]);

  // Populated_at unchanged — proves we hit the cache, not re-walked.
  {
    ldb::index::SymbolIndex idx(root);
    auto bin = idx.get_binary(build_id);
    REQUIRE(bin.has_value());
    CHECK(bin->populated_at_ns == pop_at);
    CHECK(idx.stats().binary_count == 1);
  }

  unsetenv("LDB_STORE_ROOT");
  fs::remove_all(root);
}

TEST_CASE("correlate.types falls through to backend when LDB_STORE_ROOT "
          "unset",
          "[dispatcher][correlate][indexed]") {
  // Force the env var off; Dispatcher should construct without an
  // index, and correlate.* should still serve real data via the
  // backend fall-through. This is the "index is a cache, callers
  // don't care if it's missing" guarantee.
  unsetenv("LDB_STORE_ROOT");

  auto be = std::make_shared<LldbBackend>();
  // Note: no artifact store either. The dispatcher accepts a null
  // store; correlate.* doesn't depend on it.
  Dispatcher d(be);

  auto a = d.dispatch(make_req("target.open", json{{"path", kStructsPath}}));
  REQUIRE(a.ok);
  auto tid = a.data["target_id"].get<std::uint64_t>();

  auto resp = d.dispatch(make_req("correlate.types",
      json{{"target_ids", json::array({tid})}, {"name", "dxp_login_frame"}}));
  REQUIRE(resp.ok);
  REQUIRE(resp.data["results"].size() == 1);
  CHECK(resp.data["results"][0]["status"].get<std::string>() == "found");
  REQUIRE(resp.data["results"][0]["layout"].contains("byte_size"));
  CHECK(resp.data["results"][0]["layout"]["byte_size"].get<int>() == 16);
  CHECK(resp.data["drift"].get<bool>() == false);
}
