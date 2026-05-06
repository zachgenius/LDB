// Tests for SessionStore::extract_target_ids (Tier 3 §9).
//
// extract_target_ids walks a session's rpc_log and buckets every row by
// `params.target_id` (when present and integer-typed). Per-bucket
// aggregates: count, first seq, last seq.
//
// Edge cases pinned here:
//   • Empty session → empty list.
//   • All rows on one target → one bucket, count = N.
//   • Mixed ids → distinct buckets, sorted ascending by target_id.
//   • Malformed JSON in rpc_log.request → skipped, no throw.
//   • params absent / non-object / target_id missing / non-integer →
//     row contributes to nothing.

#include <catch_amalgamated.hpp>

#include "store/session_store.h"

#include "backend/debugger_backend.h"  // backend::Error

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <random>
#include <string>
#include <system_error>

namespace fs = std::filesystem;
using ldb::store::SessionStore;
using nlohmann::json;

namespace {

struct TmpStoreRoot {
  fs::path root;
  TmpStoreRoot() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    char buf[64];
    std::snprintf(buf, sizeof(buf), "ldb_sess_extract_%016llx",
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

// Convenience — build a minimal request payload around a method + params.
json req_with(const std::string& method, json params) {
  json j;
  j["method"] = method;
  j["params"] = std::move(params);
  return j;
}

}  // namespace

TEST_CASE("extract_target_ids: empty session returns empty list",
          "[store][session][targets]") {
  TmpStoreRoot t;
  SessionStore s(t.root);
  auto row = s.create("empty", std::nullopt);
  auto out = s.extract_target_ids(row.id);
  CHECK(out.empty());
}

TEST_CASE("extract_target_ids: all rows on one target → single bucket",
          "[store][session][targets]") {
  TmpStoreRoot t;
  SessionStore s(t.root);
  auto row = s.create("solo", std::nullopt);
  auto w = s.open_writer(row.id);

  for (int i = 0; i < 3; ++i) {
    w->append("module.list",
              req_with("module.list", json{{"target_id", 1}}),
              json{{"ok", true}}, true, 100);
  }

  auto out = s.extract_target_ids(row.id);
  REQUIRE(out.size() == 1);
  CHECK(out[0].target_id == 1);
  CHECK(out[0].call_count == 3);
  CHECK(out[0].first_seq >= 1);
  CHECK(out[0].last_seq >= out[0].first_seq);
}

TEST_CASE("extract_target_ids: mixed target_ids → distinct buckets",
          "[store][session][targets]") {
  TmpStoreRoot t;
  SessionStore s(t.root);
  auto row = s.create("multi", std::nullopt);
  auto w = s.open_writer(row.id);

  // Sequence: 1, 2, 1, 3, 2 — the test verifies each bucket's count
  // and the first/last seq window per id.
  w->append("a", req_with("a", json{{"target_id", 1}}),
            json{{"ok", true}}, true, 1);  // seq 1
  w->append("b", req_with("b", json{{"target_id", 2}}),
            json{{"ok", true}}, true, 1);  // seq 2
  w->append("c", req_with("c", json{{"target_id", 1}}),
            json{{"ok", true}}, true, 1);  // seq 3
  w->append("d", req_with("d", json{{"target_id", 3}}),
            json{{"ok", true}}, true, 1);  // seq 4
  w->append("e", req_with("e", json{{"target_id", 2}}),
            json{{"ok", true}}, true, 1);  // seq 5

  auto out = s.extract_target_ids(row.id);
  REQUIRE(out.size() == 3);
  // Sorted ascending by target_id.
  CHECK(out[0].target_id == 1);
  CHECK(out[1].target_id == 2);
  CHECK(out[2].target_id == 3);

  // Counts.
  CHECK(out[0].call_count == 2);
  CHECK(out[1].call_count == 2);
  CHECK(out[2].call_count == 1);

  // first_seq / last_seq.
  CHECK(out[0].first_seq == 1);
  CHECK(out[0].last_seq  == 3);
  CHECK(out[1].first_seq == 2);
  CHECK(out[1].last_seq  == 5);
  CHECK(out[2].first_seq == 4);
  CHECK(out[2].last_seq  == 4);
}

TEST_CASE("extract_target_ids: rows without target_id are skipped",
          "[store][session][targets]") {
  TmpStoreRoot t;
  SessionStore s(t.root);
  auto row = s.create("filter", std::nullopt);
  auto w = s.open_writer(row.id);

  // hello has no target_id → skipped.
  w->append("hello", req_with("hello", json::object()),
            json{{"ok", true}}, true, 1);
  // describe.endpoints has no target_id → skipped.
  w->append("describe.endpoints",
            req_with("describe.endpoints", json::object()),
            json{{"ok", true}}, true, 1);
  // Real call against target 7.
  w->append("module.list",
            req_with("module.list", json{{"target_id", 7}}),
            json{{"ok", true}}, true, 1);

  auto out = s.extract_target_ids(row.id);
  REQUIRE(out.size() == 1);
  CHECK(out[0].target_id == 7);
  CHECK(out[0].call_count == 1);
}

TEST_CASE("extract_target_ids: non-integer target_id is skipped",
          "[store][session][targets]") {
  TmpStoreRoot t;
  SessionStore s(t.root);
  auto row = s.create("bad-types", std::nullopt);
  auto w = s.open_writer(row.id);

  // String — not the documented integer shape.
  w->append("a", req_with("a", json{{"target_id", "not-an-int"}}),
            json{{"ok", true}}, true, 1);
  // Float — not integer.
  w->append("b", req_with("b", json{{"target_id", 1.5}}),
            json{{"ok", true}}, true, 1);
  // Negative — out of TargetId domain (uint64).
  w->append("c", req_with("c", json{{"target_id", -1}}),
            json{{"ok", true}}, true, 1);
  // Valid, contributes.
  w->append("d", req_with("d", json{{"target_id", 42}}),
            json{{"ok", true}}, true, 1);

  auto out = s.extract_target_ids(row.id);
  REQUIRE(out.size() == 1);
  CHECK(out[0].target_id == 42);
}

TEST_CASE("extract_target_ids: malformed request JSON does not throw",
          "[store][session][targets]") {
  // The Writer::append path always serializes via nlohmann::json::dump,
  // so under normal operation request_json is well-formed. We can't
  // actually inject malformed text without touching sqlite directly,
  // so this test pins the *defensive* path: a row whose params field
  // is missing entirely is treated as "no target_id", not an error.
  TmpStoreRoot t;
  SessionStore s(t.root);
  auto row = s.create("missing-params", std::nullopt);
  auto w = s.open_writer(row.id);

  // Request stored with no 'params' key at all. extract_target_ids
  // should defensively skip it rather than throw.
  json req_no_params;
  req_no_params["method"] = "weird";
  w->append("weird", req_no_params, json{{"ok", true}}, true, 1);

  // Also: params present but an array, not an object. Skip it.
  json req_array_params;
  req_array_params["method"] = "a";
  req_array_params["params"] = json::array({1, 2, 3});
  w->append("a", req_array_params, json{{"ok", true}}, true, 1);

  // One valid row so the function returns a non-empty list.
  w->append("ok", req_with("ok", json{{"target_id", 5}}),
            json{{"ok", true}}, true, 1);

  REQUIRE_NOTHROW(s.extract_target_ids(row.id));
  auto out = s.extract_target_ids(row.id);
  REQUIRE(out.size() == 1);
  CHECK(out[0].target_id == 5);
}

TEST_CASE("extract_target_ids: unknown session id throws",
          "[store][session][targets][error]") {
  TmpStoreRoot t;
  SessionStore s(t.root);
  CHECK_THROWS_AS(s.extract_target_ids("nonexistent"),
                  ldb::backend::Error);
}
