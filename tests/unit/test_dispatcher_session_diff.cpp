// Dispatcher integration tests for session.diff (Tier 3 §11).
//
// Pins the wire shape:
//
//   {
//     summary: {total_a, total_b, added, removed, common, diverged},
//     entries: [{kind, ...}, ...],
//     total: <n>,
//     next_offset?: <n>
//   }
//
// Uses a real LldbBackend so the dispatcher catch surface is exercised.

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

struct TmpStoreRoot {
  fs::path root;
  TmpStoreRoot() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    char buf[40];
    std::snprintf(buf, sizeof(buf), "ldb_disp_diff_%016llx",
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

// Drive a session via dispatch — attach, run a few rpcs, detach.
// Returns the session id.
std::string run_session(Dispatcher& d, const char* name,
                        std::vector<Request> work) {
  auto cr = d.dispatch(make_req("session.create", json{{"name", name}}));
  REQUIRE(cr.ok);
  std::string sid = cr.data["id"].get<std::string>();

  auto at = d.dispatch(make_req("session.attach", json{{"id", sid}}));
  REQUIRE(at.ok);

  for (auto& w : work) {
    d.dispatch(w);
  }

  auto dt = d.dispatch(make_req("session.detach"));
  REQUIRE(dt.ok);
  return sid;
}

}  // namespace

TEST_CASE("dispatcher: session.diff returns summary + entries + total",
          "[dispatcher][session][diff]") {
  TmpStoreRoot t;
  auto be = std::make_shared<LldbBackend>();
  auto sessions = std::make_shared<SessionStore>(t.root);
  Dispatcher d(be, nullptr, sessions);

  // Two sessions running the same canned commands. They should produce
  // mostly common rpc rows with possibly one diverging entry (ids/path
  // differ in the response of session.info — but we won't run info
  // inside the work; just hello + describe.endpoints which are
  // deterministic).
  auto a_sid = run_session(d, "alpha", {
      make_req("hello"),
      make_req("describe.endpoints"),
  });
  auto b_sid = run_session(d, "beta", {
      make_req("hello"),
      make_req("describe.endpoints"),
  });

  auto resp = d.dispatch(make_req("session.diff",
                                  json{{"session_a", a_sid},
                                        {"session_b", b_sid}}));
  REQUIRE(resp.ok);

  REQUIRE(resp.data.contains("summary"));
  REQUIRE(resp.data.contains("entries"));
  REQUIRE(resp.data.contains("total"));
  REQUIRE(resp.data["entries"].is_array());

  const auto& s = resp.data["summary"];
  REQUIRE(s.contains("total_a"));
  REQUIRE(s.contains("total_b"));
  REQUIRE(s.contains("added"));
  REQUIRE(s.contains("removed"));
  REQUIRE(s.contains("common"));
  REQUIRE(s.contains("diverged"));

  // The two work-streams are byte-identical (same RPCs in the same
  // order; hello/describe.endpoints have deterministic output). All
  // rows should be common except for any session.attach/detach rows
  // (those carry the session id in the request body, which differs).
  CHECK(s["common"].get<std::int64_t>() >= 2);
  CHECK(s["diverged"].get<std::int64_t>() == 0);

  // total_a == total_b (both ran the same number of dispatches).
  CHECK(s["total_a"].get<std::int64_t>() == s["total_b"].get<std::int64_t>());

  // Every entry has kind + method.
  for (const auto& e : resp.data["entries"]) {
    REQUIRE(e.contains("kind"));
    REQUIRE(e.contains("method"));
    auto kind = e["kind"].get<std::string>();
    REQUIRE((kind == "common" || kind == "added" ||
             kind == "removed" || kind == "diverged"));
  }
}

TEST_CASE("dispatcher: session.diff view limit + offset slices entries",
          "[dispatcher][session][diff][view]") {
  TmpStoreRoot t;
  auto be = std::make_shared<LldbBackend>();
  auto sessions = std::make_shared<SessionStore>(t.root);
  Dispatcher d(be, nullptr, sessions);

  // Build sessions with several rows each. We use unique params to
  // force divergent alignment so we get a healthy entry count.
  auto a_sid = run_session(d, "a", {
      make_req("hello", json{{"protocol_min", "1.0"}}),
      make_req("describe.endpoints"),
      make_req("hello", json{{"protocol_min", "1.1"}}),
      make_req("describe.endpoints"),
      make_req("hello", json{{"protocol_min", "1.2"}}),
  });
  auto b_sid = run_session(d, "b", {
      make_req("hello", json{{"protocol_min", "1.0"}}),
      make_req("describe.endpoints"),
      make_req("hello", json{{"protocol_min", "9.9"}}),  // diverges
      make_req("describe.endpoints"),
  });

  // Unsliced — get the full count.
  auto full = d.dispatch(make_req("session.diff",
                                  json{{"session_a", a_sid},
                                        {"session_b", b_sid}}));
  REQUIRE(full.ok);
  auto total = full.data["total"].get<std::int64_t>();
  REQUIRE(total >= 4);

  // Slice with limit=2, offset=0.
  auto sliced = d.dispatch(make_req("session.diff",
      json{{"session_a", a_sid}, {"session_b", b_sid},
            {"view", json{{"limit", 2}}}}));
  REQUIRE(sliced.ok);
  CHECK(sliced.data["entries"].size() == 2);
  CHECK(sliced.data["total"].get<std::int64_t>() == total);
  // next_offset should advertise more is available.
  if (total > 2) {
    REQUIRE(sliced.data.contains("next_offset"));
    CHECK(sliced.data["next_offset"].get<std::int64_t>() == 2);
  }

  // Slice with offset=1, limit=1 → exactly one entry, the second row.
  auto sliced2 = d.dispatch(make_req("session.diff",
      json{{"session_a", a_sid}, {"session_b", b_sid},
            {"view", json{{"offset", 1}, {"limit", 1}}}}));
  REQUIRE(sliced2.ok);
  CHECK(sliced2.data["entries"].size() == 1);
  CHECK(sliced2.data["total"].get<std::int64_t>() == total);
}

TEST_CASE("dispatcher: session.diff view summary mode caps entries",
          "[dispatcher][session][diff][view]") {
  TmpStoreRoot t;
  auto be = std::make_shared<LldbBackend>();
  auto sessions = std::make_shared<SessionStore>(t.root);
  Dispatcher d(be, nullptr, sessions);

  // Many distinct entries → summary should sample the first 5.
  std::vector<Request> work_a;
  std::vector<Request> work_b;
  for (int i = 0; i < 20; ++i) {
    work_a.push_back(make_req("hello",
        json{{"protocol_min", std::string("1.") + std::to_string(i)}}));
  }
  // B is empty — every A row becomes "removed".
  auto a_sid = run_session(d, "a", std::move(work_a));
  auto b_sid = run_session(d, "b", std::move(work_b));

  auto resp = d.dispatch(make_req("session.diff",
      json{{"session_a", a_sid}, {"session_b", b_sid},
            {"view", json{{"summary", true}}}}));
  REQUIRE(resp.ok);
  CHECK(resp.data.contains("summary"));     // diff summary block
  CHECK(resp.data.contains("entries"));
  // view summary mode caps to kSummarySampleSize (=5) entries; the diff
  // summary block (counts) is independent and stays accurate.
  CHECK(resp.data["entries"].size() <= 5);
  CHECK(resp.data["total"].get<std::int64_t>() >= 20);
}

TEST_CASE("dispatcher: session.diff with bogus id returns -32000",
          "[dispatcher][session][diff][error]") {
  TmpStoreRoot t;
  auto be = std::make_shared<LldbBackend>();
  auto sessions = std::make_shared<SessionStore>(t.root);
  Dispatcher d(be, nullptr, sessions);

  auto cr = d.dispatch(make_req("session.create", json{{"name", "z"}}));
  REQUIRE(cr.ok);
  std::string sid = cr.data["id"].get<std::string>();

  auto r = d.dispatch(make_req("session.diff",
                               json{{"session_a", sid},
                                     {"session_b", "nonexistent"}}));
  CHECK_FALSE(r.ok);
  CHECK(static_cast<int>(r.error_code) == -32000);
}

TEST_CASE("dispatcher: session.diff missing params returns -32602",
          "[dispatcher][session][diff][error]") {
  TmpStoreRoot t;
  auto be = std::make_shared<LldbBackend>();
  auto sessions = std::make_shared<SessionStore>(t.root);
  Dispatcher d(be, nullptr, sessions);

  // Missing session_b.
  auto r1 = d.dispatch(make_req("session.diff",
                                json{{"session_a", "abc"}}));
  CHECK_FALSE(r1.ok);
  CHECK(static_cast<int>(r1.error_code) == -32602);

  // Missing both.
  auto r2 = d.dispatch(make_req("session.diff", json::object()));
  CHECK_FALSE(r2.ok);
  CHECK(static_cast<int>(r2.error_code) == -32602);
}

TEST_CASE("dispatcher: session.diff without store returns -32002",
          "[dispatcher][session][diff][error]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher d(be, nullptr, /*sessions=*/nullptr);

  auto r = d.dispatch(make_req("session.diff",
                               json{{"session_a", "x"}, {"session_b", "y"}}));
  CHECK_FALSE(r.ok);
  CHECK(static_cast<int>(r.error_code) == -32002);
}

TEST_CASE("dispatcher: session.diff appears in describe.endpoints",
          "[dispatcher][session][diff][describe]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher d(be);

  auto resp = d.dispatch(make_req("describe.endpoints"));
  REQUIRE(resp.ok);
  REQUIRE(resp.data.contains("endpoints"));

  bool found = false;
  for (const auto& e : resp.data["endpoints"]) {
    if (e.value("method", "") == "session.diff") {
      found = true;
      // schema sanity — params requires session_a + session_b.
      REQUIRE(e.contains("params_schema"));
      REQUIRE(e["params_schema"].contains("required"));
      const auto& req = e["params_schema"]["required"];
      bool has_a = false, has_b = false;
      for (const auto& r : req) {
        if (r == "session_a") has_a = true;
        if (r == "session_b") has_b = true;
      }
      CHECK(has_a);
      CHECK(has_b);
      // cost_hint should be unbounded.
      CHECK(e.value("cost_hint", "") == "unbounded");
      break;
    }
  }
  CHECK(found);
}
