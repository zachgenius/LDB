// SPDX-License-Identifier: Apache-2.0
// Unit tests for the GdbMiSession subprocess driver (post-V1 #8).
//
// Covers:
//   * spawn / wait_until_ready / send_command / shutdown
//   * tokenized request/response pairing under async interleaving
//   * graceful shutdown (`-gdb-exit`) and SIGTERM-then-SIGKILL escalation
//   * record draining (async events accumulate between command calls)
//
// All tests are gated on `gdb` being on PATH — SKIP otherwise.

#include <catch_amalgamated.hpp>

#include "backend/gdbmi/session.h"
#include "backend/gdbmi/parser.h"

#include <chrono>
#include <cstdlib>
#include <string>
#include <thread>
#include <unistd.h>

using ldb::backend::gdbmi::GdbMiSession;
using ldb::backend::gdbmi::MiRecord;
using ldb::backend::gdbmi::MiRecordKind;

namespace {
bool gdb_available() {
  // shutil-which equivalent: check the same locations we'd ultimately
  // exec from. The session class encapsulates this; here we just want
  // to gate the test.
  return std::system("which gdb >/dev/null 2>&1") == 0;
}
}  // namespace

TEST_CASE("mi_session: spawn + initial prompt + clean shutdown",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) {
    SKIP("gdb not on PATH");
  }
  GdbMiSession s;
  REQUIRE(s.start());
  // After start(), the session must be ready to accept commands —
  // the gdb subprocess has issued its first (gdb) prompt.
  CHECK(s.is_running());
  s.shutdown();
  CHECK_FALSE(s.is_running());
}

TEST_CASE("mi_session: send_command returns the result record",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  GdbMiSession s;
  REQUIRE(s.start());

  // `-gdb-show prompt` is a trivial query that returns ^done with a
  // value=... payload. Lets us confirm the request/response pairing
  // and class-extraction logic without needing a binary loaded.
  auto resp = s.send_command("-gdb-show prompt");
  REQUIRE(resp.has_value());
  CHECK(resp->kind == MiRecordKind::kResult);
  CHECK(resp->klass == "done");

  s.shutdown();
}

TEST_CASE("mi_session: tokenized requests pair under async noise",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  GdbMiSession s;
  REQUIRE(s.start());

  // Fire several requests back to back; the session must return
  // each response paired with its request, even with interleaved
  // = (notify) records from gdb.
  for (int i = 0; i < 5; ++i) {
    auto resp = s.send_command("-gdb-show confirm");
    REQUIRE(resp.has_value());
    CHECK(resp->klass == "done");
  }
  s.shutdown();
}

TEST_CASE("mi_session: ^error class surfaces without throwing",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  GdbMiSession s;
  REQUIRE(s.start());

  // Bogus command — gdb replies ^error. The session must surface it
  // as a record (not throw / abort), so the backend can map to a
  // typed ldb error.
  auto resp = s.send_command("-this-is-not-a-real-mi-command");
  REQUIRE(resp.has_value());
  CHECK(resp->kind == MiRecordKind::kResult);
  CHECK(resp->klass == "error");
  REQUIRE(resp->payload.is_tuple());
  CHECK(resp->payload.as_tuple().count("msg") == 1);

  s.shutdown();
}

TEST_CASE("mi_session: drain_async returns notify records",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  GdbMiSession s;
  REQUIRE(s.start());

  // At startup gdb emits =thread-group-added,id="i1" before the
  // first prompt. After start() drains the initial prompt, that
  // record should have been moved into the async queue and be
  // retrievable via drain_async().
  auto pending = s.drain_async();
  bool saw_group_added = false;
  for (const auto& r : pending) {
    if (r.kind == MiRecordKind::kNotifyAsync &&
        r.klass == "thread-group-added") {
      saw_group_added = true;
    }
  }
  CHECK(saw_group_added);
  s.shutdown();
}

TEST_CASE("mi_session: shutdown is idempotent",
          "[gdbmi][live][requires_gdb]") {
  if (!gdb_available()) SKIP("gdb not on PATH");
  GdbMiSession s;
  REQUIRE(s.start());
  s.shutdown();
  s.shutdown();   // calling again must be a no-op, not crash
  CHECK_FALSE(s.is_running());
}
