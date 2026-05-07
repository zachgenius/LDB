// Minimal sqlite3-as-build-dep smoke test.
//
// Per CLAUDE.md "harness expansion" rule: when a new test surface needs
// a new build dep (here, sqlite3 for the M3 artifact store), the *first*
// commit on the branch is the dep + a minimal test that exercises it.
// This file proves:
//
//   1. The CMake `find_package(SQLite3)` resolves a working library on
//      this host.
//   2. The Catch2 unit-test target links against it cleanly.
//   3. We can open an in-memory db, run a trivial CREATE+INSERT+SELECT,
//      and read sqlite_version() — i.e. the runtime is sane.
//
// If this fails, no other M3 artifact-store work has any chance of
// running; this is the canary.

#include <catch_amalgamated.hpp>

#include <sqlite3.h>

#include <cstring>
#include <string>

TEST_CASE("sqlite3: in-memory db open + close",
          "[harness][sqlite]") {
  sqlite3* db = nullptr;
  int rc = sqlite3_open(":memory:", &db);
  REQUIRE(rc == SQLITE_OK);
  REQUIRE(db != nullptr);
  CHECK(sqlite3_close(db) == SQLITE_OK);
}

TEST_CASE("sqlite3: round-trip a row",
          "[harness][sqlite]") {
  sqlite3* db = nullptr;
  REQUIRE(sqlite3_open(":memory:", &db) == SQLITE_OK);

  char* errmsg = nullptr;
  REQUIRE(sqlite3_exec(db,
                       "CREATE TABLE t(k TEXT PRIMARY KEY, v INTEGER);"
                       "INSERT INTO t(k, v) VALUES('hello', 42);",
                       nullptr, nullptr, &errmsg) == SQLITE_OK);

  sqlite3_stmt* stmt = nullptr;
  REQUIRE(sqlite3_prepare_v2(db, "SELECT v FROM t WHERE k = 'hello';", -1,
                             &stmt, nullptr) == SQLITE_OK);
  REQUIRE(sqlite3_step(stmt) == SQLITE_ROW);
  CHECK(sqlite3_column_int(stmt, 0) == 42);
  CHECK(sqlite3_finalize(stmt) == SQLITE_OK);

  CHECK(sqlite3_close(db) == SQLITE_OK);
}

TEST_CASE("sqlite3: library version is reachable",
          "[harness][sqlite]") {
  // Compile-time version macro must be ≥ 3.7 (WAL was introduced in
  // 3.7.0; we'll rely on it for the artifact store).
  CHECK(SQLITE_VERSION_NUMBER >= 3'007'000);

  // Runtime library must be at least as new as the headers we compiled
  // against.  On macOS the system SQLite runtime may be newer than the
  // SDK-bundled headers (Apple ships them independently), so a strict
  // string equality check fails by design. Using version numbers lets
  // us catch real ABI regressions (runtime older than headers) without
  // failing on the intentional forward-compatible discrepancy.
  const char* rv = sqlite3_libversion();
  REQUIRE(rv != nullptr);
  CHECK(sqlite3_libversion_number() >= SQLITE_VERSION_NUMBER);
}
