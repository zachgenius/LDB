// Dispatcher integration tests for the multi-binary inventory surface
// (Tier 3 §9): target.list, target.label, session.targets.
//
// Pins the wire shape:
//
//   target.list({})
//     → {targets: [{target_id, triple, path?, label?, has_process,
//                   snapshot?}], total}
//   target.label({target_id, label}) → {target_id, label}
//   session.targets({session_id})
//     → {targets: [{target_id, label?, call_count, first_seq, last_seq}],
//        total}

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"
#include "daemon/dispatcher.h"
#include "protocol/jsonrpc.h"
#include "store/session_store.h"

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
using ldb::store::SessionStore;
using nlohmann::json;

namespace {

constexpr const char* kStructsPath = LDB_FIXTURE_STRUCTS_PATH;
constexpr const char* kSleeperPath = LDB_FIXTURE_SLEEPER_PATH;

struct TmpStoreRoot {
  fs::path root;
  TmpStoreRoot() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    char buf[64];
    std::snprintf(buf, sizeof(buf), "ldb_disp_multi_%016llx",
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
  r.id = id;
  r.method = method;
  r.params = std::move(params);
  return r;
}

}  // namespace

TEST_CASE("dispatcher: target.list with no targets returns empty",
          "[dispatcher][targets]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher d(be);

  auto resp = d.dispatch(make_req("target.list"));
  REQUIRE(resp.ok);
  REQUIRE(resp.data.contains("targets"));
  REQUIRE(resp.data.contains("total"));
  CHECK(resp.data["targets"].is_array());
  CHECK(resp.data["targets"].empty());
  CHECK(resp.data["total"].get<std::int64_t>() == 0);
}

TEST_CASE("dispatcher: target.list enumerates two open targets",
          "[dispatcher][targets]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher d(be);

  auto a = d.dispatch(make_req("target.open",
                               json{{"path", kStructsPath}}));
  REQUIRE(a.ok);
  auto b = d.dispatch(make_req("target.open",
                               json{{"path", kSleeperPath}}));
  REQUIRE(b.ok);

  auto resp = d.dispatch(make_req("target.list"));
  REQUIRE(resp.ok);
  CHECK(resp.data["total"].get<std::int64_t>() == 2);
  REQUIRE(resp.data["targets"].size() == 2);

  for (const auto& t : resp.data["targets"]) {
    REQUIRE(t.contains("target_id"));
    REQUIRE(t.contains("triple"));
    REQUIRE(t.contains("has_process"));
    CHECK(t["has_process"].get<bool>() == false);
    // path present for open_executable() targets.
    REQUIRE(t.contains("path"));
  }
}

TEST_CASE("dispatcher: target.label sets and target.list reflects it",
          "[dispatcher][targets][label]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher d(be);

  auto a = d.dispatch(make_req("target.open",
                               json{{"path", kStructsPath}}));
  REQUIRE(a.ok);
  auto tid = a.data["target_id"].get<std::uint64_t>();

  auto lab = d.dispatch(make_req("target.label",
      json{{"target_id", tid}, {"label", "structs_bin"}}));
  REQUIRE(lab.ok);
  CHECK(lab.data["target_id"].get<std::uint64_t>() == tid);
  CHECK(lab.data["label"].get<std::string>() == "structs_bin");

  auto resp = d.dispatch(make_req("target.list"));
  REQUIRE(resp.ok);
  REQUIRE(resp.data["targets"].size() == 1);
  REQUIRE(resp.data["targets"][0].contains("label"));
  CHECK(resp.data["targets"][0]["label"].get<std::string>() == "structs_bin");
}

TEST_CASE("dispatcher: target.label conflict returns -32602",
          "[dispatcher][targets][label][error]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher d(be);

  auto a = d.dispatch(make_req("target.open",
                               json{{"path", kStructsPath}}));
  REQUIRE(a.ok);
  auto tid_a = a.data["target_id"].get<std::uint64_t>();

  auto b = d.dispatch(make_req("target.open",
                               json{{"path", kSleeperPath}}));
  REQUIRE(b.ok);
  auto tid_b = b.data["target_id"].get<std::uint64_t>();

  // a takes "shared" first.
  auto la = d.dispatch(make_req("target.label",
      json{{"target_id", tid_a}, {"label", "shared"}}));
  REQUIRE(la.ok);

  // b cannot reuse it.
  auto lb = d.dispatch(make_req("target.label",
      json{{"target_id", tid_b}, {"label", "shared"}}));
  CHECK_FALSE(lb.ok);
  CHECK(static_cast<int>(lb.error_code) == -32602);
  // Error message hints at the owner.
  CHECK(lb.error_message.find("shared") != std::string::npos);
}

TEST_CASE("dispatcher: target.label rejects bogus target_id",
          "[dispatcher][targets][label][error]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher d(be);
  auto resp = d.dispatch(make_req("target.label",
      json{{"target_id", 9999}, {"label", "ghost"}}));
  CHECK_FALSE(resp.ok);
  // Backend "unknown target_id" → -32000 backend error.
  CHECK(static_cast<int>(resp.error_code) == -32000);
}

TEST_CASE("dispatcher: target.label missing params returns -32602",
          "[dispatcher][targets][label][error]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher d(be);
  auto a = d.dispatch(make_req("target.open",
                               json{{"path", kStructsPath}}));
  REQUIRE(a.ok);
  auto tid = a.data["target_id"].get<std::uint64_t>();

  // Missing label.
  auto r1 = d.dispatch(make_req("target.label",
                                json{{"target_id", tid}}));
  CHECK_FALSE(r1.ok);
  CHECK(static_cast<int>(r1.error_code) == -32602);

  // Missing target_id.
  auto r2 = d.dispatch(make_req("target.label",
                                json{{"label", "x"}}));
  CHECK_FALSE(r2.ok);
  CHECK(static_cast<int>(r2.error_code) == -32602);
}

TEST_CASE("dispatcher: session.targets with no calls returns empty",
          "[dispatcher][session][targets]") {
  TmpStoreRoot t;
  auto be = std::make_shared<LldbBackend>();
  auto sessions = std::make_shared<SessionStore>(t.root);
  Dispatcher d(be, nullptr, sessions);

  auto cr = d.dispatch(make_req("session.create", json{{"name", "z"}}));
  REQUIRE(cr.ok);
  std::string sid = cr.data["id"].get<std::string>();

  auto resp = d.dispatch(make_req("session.targets",
                                  json{{"session_id", sid}}));
  REQUIRE(resp.ok);
  REQUIRE(resp.data.contains("targets"));
  REQUIRE(resp.data.contains("total"));
  CHECK(resp.data["targets"].is_array());
  CHECK(resp.data["targets"].empty());
  CHECK(resp.data["total"].get<std::int64_t>() == 0);
}

TEST_CASE("dispatcher: session.targets buckets calls by target_id",
          "[dispatcher][session][targets]") {
  TmpStoreRoot t;
  auto be = std::make_shared<LldbBackend>();
  auto sessions = std::make_shared<SessionStore>(t.root);
  Dispatcher d(be, nullptr, sessions);

  // Open two targets, attach a session, drive a few RPCs against each.
  auto a = d.dispatch(make_req("target.open",
                               json{{"path", kStructsPath}}));
  REQUIRE(a.ok);
  auto tid_a = a.data["target_id"].get<std::uint64_t>();
  auto b = d.dispatch(make_req("target.open",
                               json{{"path", kSleeperPath}}));
  REQUIRE(b.ok);
  auto tid_b = b.data["target_id"].get<std::uint64_t>();

  // Label the targets so session.targets carries them through.
  auto la = d.dispatch(make_req("target.label",
      json{{"target_id", tid_a}, {"label", "structs"}}));
  REQUIRE(la.ok);

  auto cr = d.dispatch(make_req("session.create", json{{"name", "multi"}}));
  REQUIRE(cr.ok);
  std::string sid = cr.data["id"].get<std::string>();
  auto at = d.dispatch(make_req("session.attach", json{{"id", sid}}));
  REQUIRE(at.ok);

  // 2 calls against a, 1 against b.
  d.dispatch(make_req("module.list", json{{"target_id", tid_a}}));
  d.dispatch(make_req("module.list", json{{"target_id", tid_b}}));
  d.dispatch(make_req("module.list", json{{"target_id", tid_a}}));

  auto dt = d.dispatch(make_req("session.detach"));
  REQUIRE(dt.ok);

  auto resp = d.dispatch(make_req("session.targets",
                                  json{{"session_id", sid}}));
  REQUIRE(resp.ok);
  CHECK(resp.data["total"].get<std::int64_t>() == 2);
  REQUIRE(resp.data["targets"].size() == 2);

  // Find each bucket by target_id.
  json bucket_a, bucket_b;
  for (const auto& bk : resp.data["targets"]) {
    auto tid = bk["target_id"].get<std::uint64_t>();
    if (tid == tid_a) bucket_a = bk;
    else if (tid == tid_b) bucket_b = bk;
  }
  REQUIRE(!bucket_a.is_null());
  REQUIRE(!bucket_b.is_null());

  CHECK(bucket_a["call_count"].get<std::int64_t>() == 2);
  CHECK(bucket_b["call_count"].get<std::int64_t>() == 1);
  CHECK(bucket_a["first_seq"].get<std::int64_t>() <= bucket_a["last_seq"].get<std::int64_t>());

  // Label is enriched from the live backend state.
  REQUIRE(bucket_a.contains("label"));
  CHECK(bucket_a["label"].get<std::string>() == "structs");
  CHECK_FALSE(bucket_b.contains("label"));  // b unlabeled
}

TEST_CASE("dispatcher: session.targets unknown session returns -32000",
          "[dispatcher][session][targets][error]") {
  TmpStoreRoot t;
  auto be = std::make_shared<LldbBackend>();
  auto sessions = std::make_shared<SessionStore>(t.root);
  Dispatcher d(be, nullptr, sessions);

  auto resp = d.dispatch(make_req("session.targets",
                                  json{{"session_id", "nonexistent"}}));
  CHECK_FALSE(resp.ok);
  CHECK(static_cast<int>(resp.error_code) == -32000);
}

TEST_CASE("dispatcher: session.targets without store returns -32002",
          "[dispatcher][session][targets][error]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher d(be, nullptr, /*sessions=*/nullptr);
  auto resp = d.dispatch(make_req("session.targets",
                                  json{{"session_id", "x"}}));
  CHECK_FALSE(resp.ok);
  CHECK(static_cast<int>(resp.error_code) == -32002);
}

TEST_CASE("dispatcher: target.list / target.label / session.targets in describe.endpoints",
          "[dispatcher][targets][describe]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher d(be);
  auto resp = d.dispatch(make_req("describe.endpoints"));
  REQUIRE(resp.ok);

  bool seen_list = false, seen_label = false, seen_st = false;
  for (const auto& e : resp.data["endpoints"]) {
    auto m = e.value("method", "");
    if (m == "target.list")     seen_list = true;
    if (m == "target.label")    seen_label = true;
    if (m == "session.targets") seen_st   = true;
  }
  CHECK(seen_list);
  CHECK(seen_label);
  CHECK(seen_st);
}
