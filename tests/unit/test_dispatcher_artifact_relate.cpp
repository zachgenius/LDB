// SPDX-License-Identifier: Apache-2.0
// Dispatcher integration test for artifact.relate / artifact.relations /
// artifact.unrelate (Tier 3 §7).
//
// Pure store-only endpoints — no live target needed. We check:
//
//   • Round-trip: relate two artifacts, list, unrelate.
//   • describe.endpoints lists all three new methods.
//   • view::apply_to_array on the `relations` array (limit / offset /
//     fields / summary) — same retrofit pattern the rest of the
//     listing endpoints use.
//   • Negative paths:
//     - missing required params → -32602.
//     - relate against a non-existent artifact id → -32000.
//     - unrelate of a missing id is idempotent (deleted=false, ok).

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"
#include "daemon/dispatcher.h"
#include "protocol/jsonrpc.h"
#include "store/artifact_store.h"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <random>
#include <string>
#include <system_error>
#include <vector>

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
    std::snprintf(buf, sizeof(buf), "ldb_disp_relate_%016llx",
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

// Return the two artifact ids after putting them.
struct Pair { std::int64_t a, b; };
Pair seed_two(ArtifactStore& as) {
  auto r1 = as.put("buildA", "schema.xml",
                   std::vector<std::uint8_t>{'<','s','/','>'},
                   std::optional<std::string>("xml"),
                   nlohmann::json::object());
  auto r2 = as.put("buildA", "frame.bin",
                   std::vector<std::uint8_t>{0x01, 0x02},
                   std::nullopt, nlohmann::json::object());
  return {r1.id, r2.id};
}

}  // namespace

TEST_CASE("artifact.relate / .relations / .unrelate round-trip",
          "[dispatcher][artifact][relations]") {
  TmpStoreRoot tmp;
  auto backend   = std::make_shared<LldbBackend>();
  auto artifacts = std::make_shared<ArtifactStore>(tmp.root);
  Dispatcher d(backend, artifacts, nullptr, nullptr, nullptr);

  auto p = seed_two(*artifacts);

  // --- relate ---------------------------------------------------------
  auto rel_resp = d.dispatch(make_req("artifact.relate", json{
    {"from_id",   p.a},
    {"to_id",     p.b},
    {"predicate", "parsed_by"},
    {"meta",      json{{"function", "xml_parse"}, {"line", 42}}},
  }));
  REQUIRE(rel_resp.ok);
  REQUIRE(rel_resp.data.contains("relation_id"));
  std::int64_t rel_id = rel_resp.data["relation_id"].get<std::int64_t>();
  CHECK(rel_id > 0);
  CHECK(rel_resp.data["from_id"].get<std::int64_t>() == p.a);
  CHECK(rel_resp.data["to_id"].get<std::int64_t>()   == p.b);
  CHECK(rel_resp.data["predicate"].get<std::string>() == "parsed_by");
  CHECK(rel_resp.data["created_at"].get<std::int64_t>() > 0);

  // --- relations (no filter) ------------------------------------------
  auto list_resp = d.dispatch(make_req("artifact.relations", json::object()));
  REQUIRE(list_resp.ok);
  REQUIRE(list_resp.data.contains("relations"));
  REQUIRE(list_resp.data["relations"].is_array());
  REQUIRE(list_resp.data["relations"].size() == 1);
  CHECK(list_resp.data["total"].get<std::int64_t>() == 1);
  const auto& row = list_resp.data["relations"][0];
  CHECK(row["id"].get<std::int64_t>() == rel_id);
  CHECK(row["from_id"].get<std::int64_t>() == p.a);
  CHECK(row["to_id"].get<std::int64_t>()   == p.b);
  CHECK(row["predicate"].get<std::string>() == "parsed_by");
  REQUIRE(row.contains("meta"));
  CHECK(row["meta"]["function"].get<std::string>() == "xml_parse");

  // --- relations (filter by artifact_id + direction) ------------------
  auto out_resp = d.dispatch(make_req("artifact.relations", json{
    {"artifact_id", p.a},
    {"direction",   "out"},
  }));
  REQUIRE(out_resp.ok);
  CHECK(out_resp.data["relations"].size() == 1);

  auto in_resp = d.dispatch(make_req("artifact.relations", json{
    {"artifact_id", p.a},
    {"direction",   "in"},
  }));
  REQUIRE(in_resp.ok);
  CHECK(in_resp.data["relations"].size() == 0);

  // --- relations (filter by predicate) --------------------------------
  auto pred_hit = d.dispatch(make_req("artifact.relations", json{
    {"predicate", "parsed_by"},
  }));
  REQUIRE(pred_hit.ok);
  CHECK(pred_hit.data["relations"].size() == 1);

  auto pred_miss = d.dispatch(make_req("artifact.relations", json{
    {"predicate", "no_such_predicate"},
  }));
  REQUIRE(pred_miss.ok);
  CHECK(pred_miss.data["relations"].size() == 0);

  // --- unrelate -------------------------------------------------------
  auto un_resp = d.dispatch(make_req("artifact.unrelate", json{
    {"relation_id", rel_id},
  }));
  REQUIRE(un_resp.ok);
  CHECK(un_resp.data["relation_id"].get<std::int64_t>() == rel_id);
  CHECK(un_resp.data["deleted"].get<bool>() == true);

  // List is now empty.
  auto empty_resp = d.dispatch(make_req("artifact.relations", json::object()));
  REQUIRE(empty_resp.ok);
  CHECK(empty_resp.data["relations"].size() == 0);

  // unrelate again → still ok, deleted=false (idempotent).
  auto un_again = d.dispatch(make_req("artifact.unrelate", json{
    {"relation_id", rel_id},
  }));
  REQUIRE(un_again.ok);
  CHECK(un_again.data["deleted"].get<bool>() == false);
}

TEST_CASE("artifact.relations: view::apply_to_array on the relations array",
          "[dispatcher][artifact][relations][view]") {
  TmpStoreRoot tmp;
  auto backend   = std::make_shared<LldbBackend>();
  auto artifacts = std::make_shared<ArtifactStore>(tmp.root);
  Dispatcher d(backend, artifacts, nullptr, nullptr, nullptr);

  auto p = seed_two(*artifacts);
  for (int i = 0; i < 3; ++i) {
    d.dispatch(make_req("artifact.relate", json{
      {"from_id",   p.a},
      {"to_id",     p.b},
      {"predicate", std::string("p") + std::to_string(i)},
    }));
  }

  // limit + offset
  auto paged = d.dispatch(make_req("artifact.relations", json{
    {"view", json{{"limit", 1}, {"offset", 1}}},
  }));
  REQUIRE(paged.ok);
  CHECK(paged.data["relations"].size() == 1);
  CHECK(paged.data["total"].get<std::int64_t>() == 3);

  // fields projection — keep only id+predicate.
  auto proj = d.dispatch(make_req("artifact.relations", json{
    {"view", json{{"fields", json::array({"id", "predicate"})}}},
  }));
  REQUIRE(proj.ok);
  REQUIRE(proj.data["relations"].is_array());
  REQUIRE(proj.data["relations"].size() == 3);
  for (const auto& r : proj.data["relations"]) {
    CHECK(r.contains("id"));
    CHECK(r.contains("predicate"));
    CHECK_FALSE(r.contains("from_id"));
    CHECK_FALSE(r.contains("meta"));
  }

  // summary mode — no items, just counts.
  auto sum = d.dispatch(make_req("artifact.relations", json{
    {"view", json{{"summary", true}}},
  }));
  REQUIRE(sum.ok);
  CHECK(sum.data.contains("total"));
}

TEST_CASE("artifact.relate: missing params and bad ids",
          "[dispatcher][artifact][relations][error]") {
  TmpStoreRoot tmp;
  auto backend   = std::make_shared<LldbBackend>();
  auto artifacts = std::make_shared<ArtifactStore>(tmp.root);
  Dispatcher d(backend, artifacts, nullptr, nullptr, nullptr);

  auto p = seed_two(*artifacts);

  // Missing predicate.
  auto miss = d.dispatch(make_req("artifact.relate", json{
    {"from_id", p.a}, {"to_id", p.b},
  }));
  CHECK_FALSE(miss.ok);
  CHECK(static_cast<int>(miss.error_code) ==
        static_cast<int>(ldb::protocol::ErrorCode::kInvalidParams));

  // Bogus to_id.
  auto bad = d.dispatch(make_req("artifact.relate", json{
    {"from_id", p.a}, {"to_id", 999999}, {"predicate", "parsed_by"},
  }));
  CHECK_FALSE(bad.ok);
  CHECK(static_cast<int>(bad.error_code) ==
        static_cast<int>(ldb::protocol::ErrorCode::kBackendError));

  // Empty predicate.
  auto empty = d.dispatch(make_req("artifact.relate", json{
    {"from_id", p.a}, {"to_id", p.b}, {"predicate", ""},
  }));
  CHECK_FALSE(empty.ok);
}

TEST_CASE("describe.endpoints lists the new relation endpoints",
          "[dispatcher][artifact][relations][describe]") {
  TmpStoreRoot tmp;
  auto backend   = std::make_shared<LldbBackend>();
  auto artifacts = std::make_shared<ArtifactStore>(tmp.root);
  Dispatcher d(backend, artifacts, nullptr, nullptr, nullptr);

  auto resp = d.dispatch(make_req("describe.endpoints"));
  REQUIRE(resp.ok);
  REQUIRE(resp.data.contains("endpoints"));
  std::vector<std::string> methods;
  for (const auto& e : resp.data["endpoints"]) {
    methods.push_back(e["method"].get<std::string>());
  }
  auto has = [&](const std::string& m) {
    return std::find(methods.begin(), methods.end(), m) != methods.end();
  };
  CHECK(has("artifact.relate"));
  CHECK(has("artifact.relations"));
  CHECK(has("artifact.unrelate"));
}

TEST_CASE("artifact.unrelate: missing relation_id is -32602",
          "[dispatcher][artifact][relations][error]") {
  TmpStoreRoot tmp;
  auto backend   = std::make_shared<LldbBackend>();
  auto artifacts = std::make_shared<ArtifactStore>(tmp.root);
  Dispatcher d(backend, artifacts, nullptr, nullptr, nullptr);

  auto bad = d.dispatch(make_req("artifact.unrelate", json::object()));
  CHECK_FALSE(bad.ok);
  CHECK(static_cast<int>(bad.error_code) ==
        static_cast<int>(ldb::protocol::ErrorCode::kInvalidParams));
}
