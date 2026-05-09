// SPDX-License-Identifier: Apache-2.0
// Unit tests for ldb::store::SessionStore.
//
// Contract under test (M3 part 2, plan §3.4 + §8):
//
//   • SessionStore(root) creates ${root}/sessions/ if absent. The same
//     root is shared with the artifact store.
//   • create(name, target_id?) inserts a row, allocates a uuid (16 random
//     bytes → 32 lower-hex chars), creates ${root}/sessions/<uuid>.db
//     with the canonical meta + rpc_log schema, and returns SessionRow
//     with call_count=0 / last_call_at=nullopt.
//   • info(id) returns the row including aggregates (call_count from
//     COUNT(*), last_call_at from MAX(ts_ns)).
//   • list() returns every session (sorted by created_at DESC — newest
//     first, which is the natural order for "what was I just doing").
//   • Writer::append(method, request, response, ok, duration_us) inserts
//     one rpc_log row. Multiple appends accumulate; info(id).call_count
//     reflects N after N appends.
//   • Writer is idempotent on the same id (open_writer twice for the
//     same id is fine — both writers can append; sqlite WAL handles
//     single-process concurrent writers via its lock). The dispatcher
//     uses one writer at a time anyway.
//   • Tmpdir fixture; **never touches ~/.ldb**.

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
#include <thread>

namespace fs = std::filesystem;
using ldb::store::SessionRow;
using ldb::store::SessionStore;

namespace {

struct TmpStoreRoot {
  fs::path root;

  TmpStoreRoot() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    char buf[40];
    std::snprintf(buf, sizeof(buf), "ldb_sess_test_%016llx",
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

}  // namespace

TEST_CASE("session_store: create then info round-trip", "[store][session]") {
  TmpStoreRoot t;
  SessionStore s(t.root);

  auto row = s.create("investigation-1", std::nullopt);
  REQUIRE(!row.id.empty());
  CHECK(row.id.size() == 32);   // 16 random bytes → 32 lower-hex chars
  CHECK(row.name == "investigation-1");
  CHECK_FALSE(row.target_id.has_value());
  CHECK(row.created_at > 0);
  CHECK(row.call_count == 0);
  CHECK_FALSE(row.last_call_at.has_value());
  // The session db file lives at the documented location.
  CHECK(fs::exists(row.path));
  CHECK(fs::path(row.path).parent_path().filename() == "sessions");

  auto got = s.info(row.id);
  REQUIRE(got.has_value());
  CHECK(got->id == row.id);
  CHECK(got->name == row.name);
  CHECK(got->created_at == row.created_at);
  CHECK(got->call_count == 0);
  CHECK_FALSE(got->last_call_at.has_value());
  CHECK(got->path == row.path);
}

TEST_CASE("session_store: create with target_id", "[store][session]") {
  TmpStoreRoot t;
  SessionStore s(t.root);

  auto row = s.create("attached", std::string("target-7"));
  REQUIRE(row.target_id.has_value());
  CHECK(*row.target_id == "target-7");

  auto got = s.info(row.id);
  REQUIRE(got.has_value());
  REQUIRE(got->target_id.has_value());
  CHECK(*got->target_id == "target-7");
}

TEST_CASE("session_store: info on missing id returns nullopt",
          "[store][session]") {
  TmpStoreRoot t;
  SessionStore s(t.root);
  CHECK_FALSE(s.info("0123456789abcdef0123456789abcdef").has_value());
  CHECK_FALSE(s.info("not-a-uuid").has_value());
}

TEST_CASE("session_store: list returns all sessions, newest first",
          "[store][session]") {
  TmpStoreRoot t;
  SessionStore s(t.root);

  auto a = s.create("first", std::nullopt);
  // Force monotonic separation so the created_at timestamps differ.
  std::this_thread::sleep_for(std::chrono::milliseconds(10));
  auto b = s.create("second", std::nullopt);
  std::this_thread::sleep_for(std::chrono::milliseconds(10));
  auto c = s.create("third", std::nullopt);

  auto all = s.list();
  REQUIRE(all.size() == 3);
  // Newest first (created_at DESC), so c, b, a.
  CHECK(all[0].id == c.id);
  CHECK(all[1].id == b.id);
  CHECK(all[2].id == a.id);
  // Each is internally consistent.
  for (const auto& r : all) {
    CHECK(r.call_count == 0);
    CHECK_FALSE(r.last_call_at.has_value());
    CHECK(fs::exists(r.path));
  }
}

TEST_CASE("session_store: writer appends update info().call_count",
          "[store][session]") {
  TmpStoreRoot t;
  SessionStore s(t.root);

  auto row = s.create("logged", std::nullopt);
  auto w = s.open_writer(row.id);
  REQUIRE(w != nullptr);

  for (int i = 0; i < 5; ++i) {
    w->append("hello",
              nlohmann::json{{"params", nlohmann::json::object()}},
              nlohmann::json{{"ok", true}, {"data", nlohmann::json::object()}},
              true,
              static_cast<std::int64_t>(100 + i));
  }

  auto got = s.info(row.id);
  REQUIRE(got.has_value());
  CHECK(got->call_count == 5);
  REQUIRE(got->last_call_at.has_value());
  CHECK(*got->last_call_at > 0);
}

TEST_CASE("session_store: writer logs ok=false rows too",
          "[store][session]") {
  // A debugger session is interesting precisely *because* errors happen.
  // Make sure we record both paths.
  TmpStoreRoot t;
  SessionStore s(t.root);
  auto row = s.create("errs", std::nullopt);
  auto w = s.open_writer(row.id);

  w->append("good", nlohmann::json::object(),
            nlohmann::json{{"ok", true}}, true, 50);
  w->append("bad", nlohmann::json::object(),
            nlohmann::json{{"ok", false},
                            {"error", {{"code", -32000},
                                       {"message", "kaboom"}}}},
            false, 60);

  auto got = s.info(row.id);
  REQUIRE(got.has_value());
  CHECK(got->call_count == 2);
}

TEST_CASE("session_store: open_writer on missing id throws",
          "[store][session][error]") {
  TmpStoreRoot t;
  SessionStore s(t.root);
  CHECK_THROWS_AS(s.open_writer("nonexistent-id-string"),
                  ldb::backend::Error);
}

TEST_CASE("session_store: open_writer on same id is idempotent",
          "[store][session]") {
  // Per docstring contract: dispatcher might re-attach mid-session. Two
  // writers on the same session db should both succeed in opening (the
  // sqlite db itself handles concurrent writes with WAL+lock). The
  // dispatcher only ever holds one at a time today; this test pins the
  // contract for any future multi-attach use.
  TmpStoreRoot t;
  SessionStore s(t.root);
  auto row = s.create("multi", std::nullopt);

  auto w1 = s.open_writer(row.id);
  auto w2 = s.open_writer(row.id);
  REQUIRE(w1 != nullptr);
  REQUIRE(w2 != nullptr);

  w1->append("a", nlohmann::json::object(),
             nlohmann::json{{"ok", true}}, true, 1);
  w2->append("b", nlohmann::json::object(),
             nlohmann::json{{"ok", true}}, true, 2);

  auto got = s.info(row.id);
  REQUIRE(got.has_value());
  CHECK(got->call_count == 2);
}

TEST_CASE("session_store: persists across reopen", "[store][session]") {
  TmpStoreRoot t;
  std::string id;
  {
    SessionStore s(t.root);
    auto row = s.create("persistent", std::string("tgt-1"));
    auto w = s.open_writer(row.id);
    w->append("hello", nlohmann::json::object(),
              nlohmann::json{{"ok", true}}, true, 42);
    id = row.id;
  }
  {
    SessionStore s2(t.root);
    auto got = s2.info(id);
    REQUIRE(got.has_value());
    CHECK(got->name == "persistent");
    REQUIRE(got->target_id.has_value());
    CHECK(*got->target_id == "tgt-1");
    CHECK(got->call_count == 1);

    auto all = s2.list();
    CHECK(all.size() == 1);
    CHECK(all[0].id == id);
  }
}

TEST_CASE("session_store: list returns empty for fresh root",
          "[store][session]") {
  TmpStoreRoot t;
  SessionStore s(t.root);
  CHECK(s.list().empty());
}

TEST_CASE("session_store: many appends in tight loop don't corrupt count",
          "[store][session]") {
  // Sanity check that the writer's per-row insert isn't silently
  // dropping rows under burst load (e.g. statement reset misconfig).
  TmpStoreRoot t;
  SessionStore s(t.root);
  auto row = s.create("burst", std::nullopt);
  auto w = s.open_writer(row.id);

  constexpr int kN = 200;
  for (int i = 0; i < kN; ++i) {
    w->append("burst",
              nlohmann::json{{"i", i}},
              nlohmann::json{{"ok", true}, {"data", {{"i", i}}}},
              true, static_cast<std::int64_t>(i));
  }
  auto got = s.info(row.id);
  REQUIRE(got.has_value());
  CHECK(got->call_count == kN);
}
