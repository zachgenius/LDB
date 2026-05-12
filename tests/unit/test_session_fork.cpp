// SPDX-License-Identifier: Apache-2.0
// Unit tests for ldb::store::SessionStore::fork_session.
//
// Contract under test (docs/24-session-fork-replay.md §2.1, §8 step 2):
//
//   • fork_session(source, name, description?, until_seq=0) returns a
//     fresh SessionRow (new id, source untouched) with row-payloads
//     copied from the source's rpc_log preserving ts_ns/method/
//     request/response/ok/duration_us.
//   • until_seq=0 means "fork at the head" — every source row is
//     copied. forked_at_seq == max(source.seq).
//   • until_seq=K with K < max copies only rows where seq <= K.
//     forked_at_seq == K. Source still holds all original rows.
//   • until_seq past source.max copies every row; forked_at_seq ==
//     source.max.
//   • Empty source (zero rows) is allowed — fork yields zero rows
//     and forked_at_seq == 0.
//   • The new session's `seq` column is re-numbered from 1 (sqlite
//     AUTOINCREMENT semantics). What's preserved is the payload.
//   • Source-id-not-found raises backend::Error.
//
// Tmpdir fixture; **never touches ~/.ldb**.

#include <catch_amalgamated.hpp>

#include "store/session_store.h"

#include "backend/debugger_backend.h"  // backend::Error

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <random>
#include <string>
#include <system_error>

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
    std::snprintf(buf, sizeof(buf), "ldb_sess_fork_%016llx",
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

// Helper: append N rows to a session via Writer::append, each with
// distinct payload so we can diff cleanly post-fork.
void append_n(SessionStore& s, const std::string& sid, int n) {
  auto w = s.open_writer(sid);
  for (int i = 0; i < n; ++i) {
    w->append("method-" + std::to_string(i),
              nlohmann::json{{"params", {{"i", i}}}},
              nlohmann::json{{"ok", true}, {"data", {{"i", i}}}},
              i % 2 == 0,                            // alternate ok flag
              static_cast<std::int64_t>(100 + i));   // distinct duration
  }
}

}  // namespace

TEST_CASE("session_store: fork copies every row when until_seq=0",
          "[store][session][fork]") {
  TmpStoreRoot t;
  SessionStore s(t.root);

  auto src = s.create("parent", std::nullopt);
  append_n(s, src.id, 5);

  // Sanity: source has 5 rows.
  REQUIRE(s.info(src.id)->call_count == 5);

  auto fork = s.fork_session(src.id, "child", std::nullopt, 0);
  CHECK(fork.id.size() == 32);
  CHECK(fork.id != src.id);
  CHECK(fork.name == "child");
  CHECK(fork.forked_at_seq == 5);
  CHECK(fork.rows_copied == 5);
  CHECK(fork.source_session_id == src.id);

  // Source is untouched.
  REQUIRE(s.info(src.id).has_value());
  CHECK(s.info(src.id)->call_count == 5);

  // Child has the same N rows with byte-equal payloads.
  auto src_rows = s.read_log(src.id);
  auto child_rows = s.read_log(fork.id);
  REQUIRE(src_rows.size() == 5);
  REQUIRE(child_rows.size() == 5);

  for (std::size_t i = 0; i < src_rows.size(); ++i) {
    INFO("row index " << i);
    CHECK(child_rows[i].method == src_rows[i].method);
    CHECK(child_rows[i].request_json == src_rows[i].request_json);
    CHECK(child_rows[i].response_json == src_rows[i].response_json);
    CHECK(child_rows[i].ok == src_rows[i].ok);
    CHECK(child_rows[i].duration_us == src_rows[i].duration_us);
    CHECK(child_rows[i].ts_ns == src_rows[i].ts_ns);
  }
}

TEST_CASE("session_store: fork honors until_seq cut",
          "[store][session][fork]") {
  TmpStoreRoot t;
  SessionStore s(t.root);

  auto src = s.create("parent", std::nullopt);
  append_n(s, src.id, 10);

  // Cut at seq=4: child should have exactly the first 4 source rows.
  auto fork = s.fork_session(src.id, "cut", std::nullopt, 4);
  CHECK(fork.forked_at_seq == 4);
  CHECK(fork.rows_copied == 4);

  auto child_rows = s.read_log(fork.id);
  REQUIRE(child_rows.size() == 4);
  auto src_rows = s.read_log(src.id);
  REQUIRE(src_rows.size() == 10);

  // Payload-equality on the first 4.
  for (std::size_t i = 0; i < 4; ++i) {
    INFO("row index " << i);
    CHECK(child_rows[i].method == src_rows[i].method);
    CHECK(child_rows[i].request_json == src_rows[i].request_json);
    CHECK(child_rows[i].response_json == src_rows[i].response_json);
  }
}

TEST_CASE("session_store: fork past source max copies everything",
          "[store][session][fork]") {
  TmpStoreRoot t;
  SessionStore s(t.root);

  auto src = s.create("parent", std::nullopt);
  append_n(s, src.id, 3);

  // until_seq=999 — far past the actual max.
  auto fork = s.fork_session(src.id, "overshoot", std::nullopt, 999);
  CHECK(fork.forked_at_seq == 3);
  CHECK(fork.rows_copied == 3);
  CHECK(s.read_log(fork.id).size() == 3);
}

TEST_CASE("session_store: fork of empty source is allowed",
          "[store][session][fork]") {
  TmpStoreRoot t;
  SessionStore s(t.root);

  auto src = s.create("empty", std::nullopt);
  // No append.

  auto fork = s.fork_session(src.id, "empty-child", std::nullopt, 0);
  CHECK(fork.rows_copied == 0);
  CHECK(fork.forked_at_seq == 0);
  CHECK(s.read_log(fork.id).empty());
  // The new session's index row exists.
  auto info = s.info(fork.id);
  REQUIRE(info.has_value());
  CHECK(info->name == "empty-child");
  CHECK(info->call_count == 0);
}

TEST_CASE("session_store: fork of unknown source throws",
          "[store][session][fork][error]") {
  TmpStoreRoot t;
  SessionStore s(t.root);
  CHECK_THROWS_AS(s.fork_session("0123456789abcdef0123456789abcdef",
                                 "x", std::nullopt, 0),
                  ldb::backend::Error);
}

TEST_CASE("session_store: fork preserves target_id from source meta",
          "[store][session][fork]") {
  TmpStoreRoot t;
  SessionStore s(t.root);

  // Source created with target_id="tgt-A"; fork should inherit it.
  // Rationale: the parent's target context is part of "what we were
  // investigating"; replay-against-fork wants to reproduce that.
  auto src = s.create("parent", std::string("tgt-A"));
  auto fork = s.fork_session(src.id, "child", std::nullopt, 0);

  auto info = s.info(fork.id);
  REQUIRE(info.has_value());
  REQUIRE(info->target_id.has_value());
  CHECK(*info->target_id == "tgt-A");
}

TEST_CASE("session_store: fork is idempotent on content",
          "[store][session][fork]") {
  // Calling fork twice on the same (source, until_seq) produces two
  // different ids — but their row payloads are byte-equal. This is
  // the contract docs/24 §5 spells out.
  TmpStoreRoot t;
  SessionStore s(t.root);

  auto src = s.create("parent", std::nullopt);
  append_n(s, src.id, 4);

  auto fork_a = s.fork_session(src.id, "a", std::nullopt, 0);
  auto fork_b = s.fork_session(src.id, "b", std::nullopt, 0);
  CHECK(fork_a.id != fork_b.id);

  auto rows_a = s.read_log(fork_a.id);
  auto rows_b = s.read_log(fork_b.id);
  REQUIRE(rows_a.size() == rows_b.size());
  for (std::size_t i = 0; i < rows_a.size(); ++i) {
    CHECK(rows_a[i].method == rows_b[i].method);
    CHECK(rows_a[i].request_json == rows_b[i].request_json);
    CHECK(rows_a[i].response_json == rows_b[i].response_json);
    CHECK(rows_a[i].ok == rows_b[i].ok);
    CHECK(rows_a[i].duration_us == rows_b[i].duration_us);
  }
}

TEST_CASE("session_store: fork default name when caller passes empty",
          "[store][session][fork]") {
  // docs/24 §2.3 — when `name` is absent/empty at the *dispatcher*
  // level, the dispatcher fills in `<source.name> (fork)`. At the
  // store level we treat empty as "use the source name suffixed
  // with (fork)" so the dispatcher's default behaves uniformly even
  // if a future caller bypasses validation.
  TmpStoreRoot t;
  SessionStore s(t.root);
  auto src = s.create("investigation-A", std::nullopt);
  auto fork = s.fork_session(src.id, /*name=*/"", std::nullopt, 0);
  auto info = s.info(fork.id);
  REQUIRE(info.has_value());
  CHECK(info->name == "investigation-A (fork)");
}
