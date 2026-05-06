// Unit tests for ldb::store::SessionStore::diff_logs (Tier 3 §11).
//
// Contract under test:
//
//   • diff_logs(a, b) walks each session's rpc_log in seq-ascending order,
//     canonicalizes the (method, params) tuple via re-parsed JSON dump
//     (sorted keys courtesy of nlohmann::json's std::map backing) and
//     aligns the two sequences with LCS.
//
//   • Pair shapes:
//       - aligned + same response (canon JSON byte-equal) → common
//       - aligned + different response                    → diverged
//       - in A only                                       → removed
//       - in B only                                       → added
//
//   • Returned summary has total_a, total_b, added, removed, common,
//     diverged. Counts must equal the counts of the corresponding entries
//     in the entries[] array.
//
//   • entries are emitted in a stable order: walk LCS bottom-up, emit
//     leftover-A "removed" before leftover-B "added" at each block.
//
//   • diff_logs throws backend::Error on a missing session id.
//
// Tmpdir fixture, never touches ~/.ldb.

#include <catch_amalgamated.hpp>

#include "store/session_store.h"
#include "backend/debugger_backend.h"

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
    char buf[40];
    std::snprintf(buf, sizeof(buf), "ldb_diff_test_%016llx",
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

// Append a (method, params, response, ok) row to a session's rpc_log via
// the public Writer. We always pass duration_us=0 because the diff logic
// is content-only and ignores timing fields.
void append(SessionStore& s, const std::string& id,
            const std::string& method,
            const json& params, const json& response) {
  auto w = s.open_writer(id);
  // Writer::append takes the *full request* json; for the diff key we
  // care about (method, params). The method+params content is what
  // canonicalizes; the wrapper shape is irrelevant as long as we write
  // params consistently. Pass {"params": ...} for both sessions.
  json req;
  req["params"] = params;
  w->append(method, req, response, true, 0);
}

// Count diff entries by kind in the result.
struct KindCounts {
  std::int64_t common = 0, added = 0, removed = 0, diverged = 0;
};
KindCounts count_kinds(const ldb::store::SessionStore::DiffResult& r) {
  KindCounts c;
  for (const auto& e : r.entries) {
    if      (e.kind == "common")   ++c.common;
    else if (e.kind == "added")    ++c.added;
    else if (e.kind == "removed")  ++c.removed;
    else if (e.kind == "diverged") ++c.diverged;
  }
  return c;
}

}  // namespace

TEST_CASE("session_diff: two empty sessions produce all-zero summary",
          "[store][session][diff]") {
  TmpStoreRoot t;
  SessionStore s(t.root);
  auto a = s.create("a", std::nullopt);
  auto b = s.create("b", std::nullopt);

  auto r = s.diff_logs(a.id, b.id);
  CHECK(r.summary.total_a == 0);
  CHECK(r.summary.total_b == 0);
  CHECK(r.summary.added == 0);
  CHECK(r.summary.removed == 0);
  CHECK(r.summary.common == 0);
  CHECK(r.summary.diverged == 0);
  CHECK(r.entries.empty());
}

TEST_CASE("session_diff: two identical sessions are all-common",
          "[store][session][diff]") {
  TmpStoreRoot t;
  SessionStore s(t.root);
  auto a = s.create("a", std::nullopt);
  auto b = s.create("b", std::nullopt);

  for (auto* id : {&a.id, &b.id}) {
    append(s, *id, "hello", json::object(), json{{"ok", true}});
    append(s, *id, "module.list", json{{"target_id", 1}},
           json{{"ok", true}, {"data", {{"modules", json::array()}}}});
    append(s, *id, "thread.list", json{{"target_id", 1}},
           json{{"ok", true}, {"data", {{"threads", json::array()}}}});
  }

  auto r = s.diff_logs(a.id, b.id);
  CHECK(r.summary.total_a == 3);
  CHECK(r.summary.total_b == 3);
  CHECK(r.summary.common == 3);
  CHECK(r.summary.added == 0);
  CHECK(r.summary.removed == 0);
  CHECK(r.summary.diverged == 0);
  REQUIRE(r.entries.size() == 3);
  for (const auto& e : r.entries) {
    CHECK(e.kind == "common");
    CHECK(e.seq_a > 0);
    CHECK(e.seq_b > 0);
    CHECK(!e.method.empty());
  }
}

TEST_CASE("session_diff: extra call in B yields exactly one added",
          "[store][session][diff]") {
  TmpStoreRoot t;
  SessionStore s(t.root);
  auto a = s.create("a", std::nullopt);
  auto b = s.create("b", std::nullopt);

  // Common prefix.
  append(s, a.id, "hello", json::object(), json{{"ok", true}});
  append(s, b.id, "hello", json::object(), json{{"ok", true}});
  // B has one extra call.
  append(s, b.id, "module.list", json{{"target_id", 1}},
         json{{"ok", true}});

  auto r = s.diff_logs(a.id, b.id);
  CHECK(r.summary.total_a == 1);
  CHECK(r.summary.total_b == 2);
  CHECK(r.summary.common == 1);
  CHECK(r.summary.added == 1);
  CHECK(r.summary.removed == 0);
  CHECK(r.summary.diverged == 0);

  auto kinds = count_kinds(r);
  CHECK(kinds.common == 1);
  CHECK(kinds.added == 1);
  CHECK(kinds.removed == 0);
  CHECK(kinds.diverged == 0);

  // The added entry is the "module.list" with seq_b set, no seq_a.
  for (const auto& e : r.entries) {
    if (e.kind == "added") {
      CHECK(e.method == "module.list");
      CHECK(e.seq_b > 0);
      CHECK(e.seq_a == 0);
    }
  }
}

TEST_CASE("session_diff: missing call in B yields exactly one removed",
          "[store][session][diff]") {
  TmpStoreRoot t;
  SessionStore s(t.root);
  auto a = s.create("a", std::nullopt);
  auto b = s.create("b", std::nullopt);

  append(s, a.id, "hello", json::object(), json{{"ok", true}});
  // Only present in A.
  append(s, a.id, "module.list", json{{"target_id", 1}},
         json{{"ok", true}});
  append(s, b.id, "hello", json::object(), json{{"ok", true}});

  auto r = s.diff_logs(a.id, b.id);
  CHECK(r.summary.total_a == 2);
  CHECK(r.summary.total_b == 1);
  CHECK(r.summary.common == 1);
  CHECK(r.summary.added == 0);
  CHECK(r.summary.removed == 1);
  CHECK(r.summary.diverged == 0);

  for (const auto& e : r.entries) {
    if (e.kind == "removed") {
      CHECK(e.method == "module.list");
      CHECK(e.seq_a > 0);
      CHECK(e.seq_b == 0);
    }
  }
}

TEST_CASE("session_diff: same key, different response is diverged",
          "[store][session][diff]") {
  TmpStoreRoot t;
  SessionStore s(t.root);
  auto a = s.create("a", std::nullopt);
  auto b = s.create("b", std::nullopt);

  // Same method+params, but different response payloads.
  append(s, a.id, "module.list", json{{"target_id", 1}},
         json{{"ok", true}, {"data", {{"modules",
              json::array({json{{"name", "/bin/cat"}}})}}}});
  append(s, b.id, "module.list", json{{"target_id", 1}},
         json{{"ok", true}, {"data", {{"modules",
              json::array({json{{"name", "/bin/echo"}}})}}}});

  auto r = s.diff_logs(a.id, b.id);
  CHECK(r.summary.total_a == 1);
  CHECK(r.summary.total_b == 1);
  CHECK(r.summary.common == 0);
  CHECK(r.summary.added == 0);
  CHECK(r.summary.removed == 0);
  CHECK(r.summary.diverged == 1);

  REQUIRE(r.entries.size() == 1);
  const auto& e = r.entries[0];
  CHECK(e.kind == "diverged");
  CHECK(e.method == "module.list");
  CHECK(e.seq_a > 0);
  CHECK(e.seq_b > 0);
  CHECK(!e.response_a_canon.empty());
  CHECK(!e.response_b_canon.empty());
  CHECK(e.response_a_canon != e.response_b_canon);
}

TEST_CASE("session_diff: LCS aligns A=[X,Y,Z] vs B=[X,W,Z]",
          "[store][session][diff]") {
  TmpStoreRoot t;
  SessionStore s(t.root);
  auto a = s.create("a", std::nullopt);
  auto b = s.create("b", std::nullopt);

  auto X_params = json{{"name", "X"}};
  auto Y_params = json{{"name", "Y"}};
  auto Z_params = json{{"name", "Z"}};
  auto W_params = json{{"name", "W"}};
  json ok = json{{"ok", true}};

  // A: X, Y, Z
  append(s, a.id, "symbol.find", X_params, ok);
  append(s, a.id, "symbol.find", Y_params, ok);
  append(s, a.id, "symbol.find", Z_params, ok);
  // B: X, W, Z
  append(s, b.id, "symbol.find", X_params, ok);
  append(s, b.id, "symbol.find", W_params, ok);
  append(s, b.id, "symbol.find", Z_params, ok);

  auto r = s.diff_logs(a.id, b.id);
  CHECK(r.summary.total_a == 3);
  CHECK(r.summary.total_b == 3);
  // X and Z align (LCS); Y is removed; W is added.
  CHECK(r.summary.common == 2);
  CHECK(r.summary.removed == 1);
  CHECK(r.summary.added == 1);
  CHECK(r.summary.diverged == 0);

  auto k = count_kinds(r);
  CHECK(k.common == 2);
  CHECK(k.added == 1);
  CHECK(k.removed == 1);

  // Validate the actual aligned identities — common entries' methods are
  // both symbol.find, but check the params hash matches X and Z by the
  // params_hash field.
  std::vector<std::string> common_hashes;
  for (const auto& e : r.entries) {
    if (e.kind == "common") common_hashes.push_back(e.params_hash);
  }
  REQUIRE(common_hashes.size() == 2);
  // The two common params_hashes should differ from each other (X != Z).
  CHECK(common_hashes[0] != common_hashes[1]);
}

TEST_CASE("session_diff: missing session id throws backend::Error",
          "[store][session][diff][error]") {
  TmpStoreRoot t;
  SessionStore s(t.root);
  auto a = s.create("a", std::nullopt);

  CHECK_THROWS_AS(s.diff_logs(a.id, "nonexistent"),
                  ldb::backend::Error);
  CHECK_THROWS_AS(s.diff_logs("nonexistent", a.id),
                  ldb::backend::Error);
}

TEST_CASE("session_diff: canonical params hash ignores key order in input",
          "[store][session][diff]") {
  TmpStoreRoot t;
  SessionStore s(t.root);
  auto a = s.create("a", std::nullopt);
  auto b = s.create("b", std::nullopt);

  // The two sessions log the same call — but if the agent emitted keys
  // in different orders, nlohmann::json's std::map backing already sorts
  // keys at dump time, so the canonical params_hash matches and the
  // entries align as common.
  append(s, a.id, "module.list",
         json{{"target_id", 1}, {"include_unloaded", false}},
         json{{"ok", true}});
  append(s, b.id, "module.list",
         json{{"include_unloaded", false}, {"target_id", 1}},
         json{{"ok", true}});

  auto r = s.diff_logs(a.id, b.id);
  CHECK(r.summary.common == 1);
  CHECK(r.summary.diverged == 0);
}
