// Dispatcher ↔ SessionStore integration test (M3 part 2).
//
// Pins down the contract that:
//   • session.create returns an id, name, created_at, path; the call
//     itself is NOT logged (no session is attached yet).
//   • session.attach makes the session "active"; subsequent rpc traffic
//     is appended to the session's rpc_log. Per design: the attach call
//     itself IS logged (it's the first row — a natural breadcrumb that
//     "attach happened at ts X").
//   • info(id).call_count reflects appends seen so far.
//   • session.detach stops logging; subsequent calls don't bump count.
//   • session.list aggregates across sessions.
//
// We use a real LldbBackend so the full stack is exercised; we don't
// need to drive an actual debug target — `hello` is enough rpc traffic.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"
#include "daemon/dispatcher.h"
#include "protocol/jsonrpc.h"
#include "store/session_store.h"

#include <chrono>
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
    std::snprintf(buf, sizeof(buf), "ldb_disp_sess_%016llx",
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

TEST_CASE("dispatcher: session.create + attach logs subsequent rpcs",
          "[dispatcher][session]") {
  TmpStoreRoot t;
  auto be = std::make_shared<LldbBackend>();
  auto sessions = std::make_shared<SessionStore>(t.root);
  Dispatcher d(be, /*artifacts=*/nullptr, sessions);

  // Step 1: create a session — call_count must be 0 (no attach yet, the
  // create call itself isn't appended either).
  auto cr = d.dispatch(make_req("session.create",
                                json{{"name", "investigation-A"}}));
  REQUIRE(cr.ok);
  REQUIRE(cr.data.contains("id"));
  std::string sid = cr.data["id"].get<std::string>();
  REQUIRE(!sid.empty());
  CHECK(cr.data["name"] == "investigation-A");
  CHECK(cr.data.contains("path"));
  CHECK(cr.data.contains("created_at"));

  // info immediately after create: 0 calls logged.
  auto i0 = d.dispatch(make_req("session.info", json{{"id", sid}}));
  REQUIRE(i0.ok);
  CHECK(i0.data["call_count"].get<std::int64_t>() == 0);

  // Step 2: attach. The attach call IS logged (first row).
  auto at = d.dispatch(make_req("session.attach", json{{"id", sid}}));
  REQUIRE(at.ok);
  CHECK(at.data["attached"] == true);

  // Step 3: emit a few RPCs — they should all be appended.
  d.dispatch(make_req("hello"));
  d.dispatch(make_req("describe.endpoints"));
  d.dispatch(make_req("hello"));

  // Now info should report (attach + hello + describe + hello + info) = 5.
  // We allow info itself to be logged or not — we check >= 4 (attach +
  // 3 explicit calls); the implementation choice for whether
  // session.info while attached counts is documented in the impl.
  auto i1 = d.dispatch(make_req("session.info", json{{"id", sid}}));
  REQUIRE(i1.ok);
  auto count_after_attach = i1.data["call_count"].get<std::int64_t>();
  // attach + hello + describe + hello = 4; info itself may or may not
  // be counted depending on whether the *response* from info() observes
  // its own row. Either way: at least 4.
  CHECK(count_after_attach >= 4);

  // Step 4: detach. The detach call IS logged (last row before stopping).
  auto dt = d.dispatch(make_req("session.detach"));
  REQUIRE(dt.ok);
  CHECK(dt.data["detached"] == true);

  auto count_after_detach_self =
      d.dispatch(make_req("session.info", json{{"id", sid}}));
  REQUIRE(count_after_detach_self.ok);
  auto count_after_detach =
      count_after_detach_self.data["call_count"].get<std::int64_t>();

  // Step 5: emit RPCs while detached. count must NOT increase.
  d.dispatch(make_req("hello"));
  d.dispatch(make_req("hello"));
  d.dispatch(make_req("describe.endpoints"));

  auto i2 = d.dispatch(make_req("session.info", json{{"id", sid}}));
  REQUIRE(i2.ok);
  CHECK(i2.data["call_count"].get<std::int64_t>() == count_after_detach);
}

TEST_CASE("dispatcher: session.list reflects multiple sessions",
          "[dispatcher][session]") {
  TmpStoreRoot t;
  auto be = std::make_shared<LldbBackend>();
  auto sessions = std::make_shared<SessionStore>(t.root);
  Dispatcher d(be, nullptr, sessions);

  d.dispatch(make_req("session.create", json{{"name", "alpha"}}));
  d.dispatch(make_req("session.create", json{{"name", "beta"}}));
  d.dispatch(make_req("session.create", json{{"name", "gamma"}}));

  auto resp = d.dispatch(make_req("session.list"));
  REQUIRE(resp.ok);
  REQUIRE(resp.data.contains("sessions"));
  REQUIRE(resp.data["sessions"].is_array());
  CHECK(resp.data["sessions"].size() == 3);
  CHECK(resp.data["total"].get<std::int64_t>() == 3);
  // Each entry shape.
  for (const auto& s : resp.data["sessions"]) {
    CHECK(s.contains("id"));
    CHECK(s.contains("name"));
    CHECK(s.contains("created_at"));
    CHECK(s.contains("call_count"));
    CHECK(s.contains("path"));
  }
}

TEST_CASE("dispatcher: session.attach with bad id returns -32000",
          "[dispatcher][session][error]") {
  TmpStoreRoot t;
  auto be = std::make_shared<LldbBackend>();
  auto sessions = std::make_shared<SessionStore>(t.root);
  Dispatcher d(be, nullptr, sessions);

  auto resp = d.dispatch(make_req("session.attach",
                                  json{{"id", "no-such-session"}}));
  CHECK_FALSE(resp.ok);
  CHECK(static_cast<int>(resp.error_code) == -32000);
}

TEST_CASE("dispatcher: session.* without store returns -32002",
          "[dispatcher][session][error]") {
  // No SessionStore plumbed → calls fail with kBadState.
  auto be = std::make_shared<LldbBackend>();
  Dispatcher d(be, /*artifacts=*/nullptr, /*sessions=*/nullptr);

  auto cr = d.dispatch(make_req("session.create", json{{"name", "x"}}));
  CHECK_FALSE(cr.ok);
  CHECK(static_cast<int>(cr.error_code) == -32002);

  auto lst = d.dispatch(make_req("session.list"));
  CHECK_FALSE(lst.ok);
  CHECK(static_cast<int>(lst.error_code) == -32002);
}

TEST_CASE("dispatcher: session.create requires non-empty name",
          "[dispatcher][session][error]") {
  TmpStoreRoot t;
  auto be = std::make_shared<LldbBackend>();
  auto sessions = std::make_shared<SessionStore>(t.root);
  Dispatcher d(be, nullptr, sessions);

  auto resp = d.dispatch(make_req("session.create", json::object()));
  CHECK_FALSE(resp.ok);
  CHECK(static_cast<int>(resp.error_code) == -32602);

  auto resp2 = d.dispatch(make_req("session.create", json{{"name", ""}}));
  CHECK_FALSE(resp2.ok);
  CHECK(static_cast<int>(resp2.error_code) == -32602);
}
