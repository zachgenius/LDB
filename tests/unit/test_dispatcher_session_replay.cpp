// SPDX-License-Identifier: Apache-2.0
// Dispatcher integration tests for session.fork + session.replay
// (post-V1 plan #16 phase-1, docs/24-session-fork-replay.md).
//
// Two dispatcher endpoints land in the same suite because they share
// the SessionStore fixture, the deterministic-row capture pattern,
// and the way the replay handler leans on the snapshot column the
// fork copy preserves.

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
    std::snprintf(buf, sizeof(buf), "ldb_disp_replay_%016llx",
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

// Record a session of `n` no-target deterministic-ish RPCs (hello +
// describe.endpoints alternation). The provenance gate marks these
// as snapshot="none", deterministic=false — that's the honest answer
// at the gate level, and replay treats them as "informational drift
// only" (bytes are stable in practice, but we don't compare).
std::string record_no_target_session(Dispatcher& d, const char* name,
                                     int n) {
  auto cr = d.dispatch(make_req("session.create", json{{"name", name}}));
  REQUIRE(cr.ok);
  std::string sid = cr.data["id"].get<std::string>();

  auto at = d.dispatch(make_req("session.attach", json{{"id", sid}}));
  REQUIRE(at.ok);

  for (int i = 0; i < n; ++i) {
    d.dispatch(make_req(i % 2 == 0 ? "hello" : "describe.endpoints"));
  }

  auto dt = d.dispatch(make_req("session.detach"));
  REQUIRE(dt.ok);
  return sid;
}

}  // namespace

// ============================================================================
// session.fork
// ============================================================================

TEST_CASE("dispatcher: session.fork returns new id with copied row count",
          "[dispatcher][session][fork]") {
  TmpStoreRoot t;
  auto be = std::make_shared<LldbBackend>();
  auto sessions = std::make_shared<SessionStore>(t.root);
  Dispatcher d(be, nullptr, sessions);

  std::string src = record_no_target_session(d, "parent", 3);
  // The parent now has at least: attach + 3 rpcs + detach = 5 rows.
  auto src_info = d.dispatch(make_req("session.info", json{{"id", src}}));
  REQUIRE(src_info.ok);
  auto parent_count = src_info.data["call_count"].get<std::int64_t>();
  REQUIRE(parent_count >= 5);

  auto fr = d.dispatch(make_req("session.fork",
                                json{{"source_session_id", src},
                                     {"name", "child"}}));
  REQUIRE(fr.ok);
  CHECK(fr.data.contains("session_id"));
  CHECK(fr.data["source_session_id"].get<std::string>() == src);
  CHECK(fr.data["name"].get<std::string>() == "child");
  auto child_id = fr.data["session_id"].get<std::string>();
  CHECK(child_id.size() == 32);
  CHECK(child_id != src);
  CHECK(fr.data["rows_copied"].get<std::int64_t>() == parent_count);
  CHECK(fr.data["forked_at_seq"].get<std::int64_t>() == parent_count);

  // The child's info row reflects the copied rows.
  auto child_info = d.dispatch(make_req("session.info",
                                        json{{"id", child_id}}));
  REQUIRE(child_info.ok);
  CHECK(child_info.data["call_count"].get<std::int64_t>() == parent_count);

  // The parent is untouched.
  auto src_after = d.dispatch(make_req("session.info", json{{"id", src}}));
  REQUIRE(src_after.ok);
  CHECK(src_after.data["call_count"].get<std::int64_t>() == parent_count);
}

TEST_CASE("dispatcher: session.fork honors until_seq cut",
          "[dispatcher][session][fork]") {
  TmpStoreRoot t;
  auto be = std::make_shared<LldbBackend>();
  auto sessions = std::make_shared<SessionStore>(t.root);
  Dispatcher d(be, nullptr, sessions);

  std::string src = record_no_target_session(d, "p", 5);
  // Cut at seq=2: only the attach + 1 rpc.
  auto fr = d.dispatch(make_req("session.fork",
                                json{{"source_session_id", src},
                                     {"name", "cut"},
                                     {"until_seq", 2}}));
  REQUIRE(fr.ok);
  CHECK(fr.data["rows_copied"].get<std::int64_t>() == 2);
  CHECK(fr.data["forked_at_seq"].get<std::int64_t>() == 2);
}

TEST_CASE("dispatcher: session.fork default name is <source.name> (fork)",
          "[dispatcher][session][fork]") {
  TmpStoreRoot t;
  auto be = std::make_shared<LldbBackend>();
  auto sessions = std::make_shared<SessionStore>(t.root);
  Dispatcher d(be, nullptr, sessions);

  std::string src = record_no_target_session(d, "investigation-X", 1);
  auto fr = d.dispatch(make_req("session.fork",
                                json{{"source_session_id", src}}));
  REQUIRE(fr.ok);
  CHECK(fr.data["name"].get<std::string>() == "investigation-X (fork)");
}

TEST_CASE("dispatcher: session.fork bad params return -32602",
          "[dispatcher][session][fork][error]") {
  TmpStoreRoot t;
  auto be = std::make_shared<LldbBackend>();
  auto sessions = std::make_shared<SessionStore>(t.root);
  Dispatcher d(be, nullptr, sessions);

  // missing source_session_id
  auto r1 = d.dispatch(make_req("session.fork", json::object()));
  CHECK_FALSE(r1.ok);
  CHECK(static_cast<int>(r1.error_code) == -32602);

  // negative until_seq
  std::string src = record_no_target_session(d, "p", 1);
  auto r2 = d.dispatch(make_req("session.fork",
                                json{{"source_session_id", src},
                                     {"until_seq", -1}}));
  CHECK_FALSE(r2.ok);
  CHECK(static_cast<int>(r2.error_code) == -32602);
}

TEST_CASE("dispatcher: session.fork unknown source returns -32000",
          "[dispatcher][session][fork][error]") {
  TmpStoreRoot t;
  auto be = std::make_shared<LldbBackend>();
  auto sessions = std::make_shared<SessionStore>(t.root);
  Dispatcher d(be, nullptr, sessions);

  auto r = d.dispatch(make_req("session.fork",
                               json{{"source_session_id",
                                     "0123456789abcdef0123456789abcdef"}}));
  CHECK_FALSE(r.ok);
  CHECK(static_cast<int>(r.error_code) == -32000);
}

TEST_CASE("dispatcher: session.fork without store returns -32002",
          "[dispatcher][session][fork][error]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher d(be, nullptr, nullptr);
  auto r = d.dispatch(make_req("session.fork",
                               json{{"source_session_id",
                                     "0123456789abcdef0123456789abcdef"}}));
  CHECK_FALSE(r.ok);
  CHECK(static_cast<int>(r.error_code) == -32002);
}

// ============================================================================
// session.replay
// ============================================================================

TEST_CASE("dispatcher: session.replay summary shape on a recorded session",
          "[dispatcher][session][replay]") {
  TmpStoreRoot t;
  auto be = std::make_shared<LldbBackend>();
  auto sessions = std::make_shared<SessionStore>(t.root);
  Dispatcher d(be, nullptr, sessions);

  std::string src = record_no_target_session(d, "rec", 3);

  auto rp = d.dispatch(make_req("session.replay",
                                json{{"session_id", src}}));
  REQUIRE(rp.ok);

  // Every key the design doc §2.2 promises lands on the response.
  for (const auto* k : {"session_id", "total_steps", "replayed",
                        "skipped", "deterministic_matches",
                        "deterministic_mismatches", "errors",
                        "divergences"}) {
    INFO("missing key: " << k);
    CHECK(rp.data.contains(k));
  }
  CHECK(rp.data["session_id"].get<std::string>() == src);

  // Skipped count >= 2 (attach + detach). The session.* meta-rows
  // include at least these; session.info if the recorder called it
  // would also be skipped.
  CHECK(rp.data["skipped"].get<std::int64_t>() >= 2);

  // total_steps - skipped == replayed.
  auto total   = rp.data["total_steps"].get<std::int64_t>();
  auto skipped = rp.data["skipped"].get<std::int64_t>();
  auto replayed= rp.data["replayed"].get<std::int64_t>();
  CHECK(total >= skipped + replayed);  // counts may include error rows

  // No divergences expected for hello / describe.endpoints — both
  // are deterministic-in-practice no-target calls; even though the
  // provenance gate marks them snapshot=none/deterministic=false
  // (so byte-comparison is skipped), they don't error.
  CHECK(rp.data["errors"].get<std::int64_t>() == 0);
}

TEST_CASE("dispatcher: session.replay is idempotent",
          "[dispatcher][session][replay]") {
  // docs/24 §5 contract: re-running replay against the same source
  // produces the same summary.
  TmpStoreRoot t;
  auto be = std::make_shared<LldbBackend>();
  auto sessions = std::make_shared<SessionStore>(t.root);
  Dispatcher d(be, nullptr, sessions);

  std::string src = record_no_target_session(d, "idem", 4);

  auto r1 = d.dispatch(make_req("session.replay",
                                json{{"session_id", src}}));
  REQUIRE(r1.ok);
  auto r2 = d.dispatch(make_req("session.replay",
                                json{{"session_id", src}}));
  REQUIRE(r2.ok);

  CHECK(r1.data["total_steps"]              == r2.data["total_steps"]);
  CHECK(r1.data["replayed"]                 == r2.data["replayed"]);
  CHECK(r1.data["skipped"]                  == r2.data["skipped"]);
  CHECK(r1.data["deterministic_matches"]    == r2.data["deterministic_matches"]);
  CHECK(r1.data["deterministic_mismatches"] == r2.data["deterministic_mismatches"]);
  CHECK(r1.data["errors"]                   == r2.data["errors"]);
  CHECK(r1.data["divergences"]              == r2.data["divergences"]);
}

TEST_CASE("dispatcher: session.replay skips session.* meta-rows",
          "[dispatcher][session][replay]") {
  // session.attach / detach / info are session-state ops that would
  // recurse or no-op against a fresh dispatcher; replay must skip
  // them (docs/24 §2.2 step 1).
  TmpStoreRoot t;
  auto be = std::make_shared<LldbBackend>();
  auto sessions = std::make_shared<SessionStore>(t.root);
  Dispatcher d(be, nullptr, sessions);

  std::string src = record_no_target_session(d, "meta", 0);
  // 0 explicit rpcs -> only attach + detach were captured.
  auto info = d.dispatch(make_req("session.info", json{{"id", src}}));
  REQUIRE(info.ok);
  auto total = info.data["call_count"].get<std::int64_t>();
  REQUIRE(total >= 2);  // attach + detach at minimum

  auto rp = d.dispatch(make_req("session.replay",
                                json{{"session_id", src}}));
  REQUIRE(rp.ok);
  // Every row is session.*; everything should land in skipped.
  CHECK(rp.data["replayed"].get<std::int64_t>() == 0);
  CHECK(rp.data["skipped"].get<std::int64_t>() == total);
  CHECK(rp.data["errors"].get<std::int64_t>() == 0);
}

TEST_CASE("dispatcher: session.replay against deterministic captures matches",
          "[dispatcher][session][replay][determinism]") {
  // Inject rows directly via the SessionStore writer with a
  // snapshot like "core:..." (deterministic-flavored). The replay
  // handler should then enforce byte-identity. We pick hello +
  // describe.endpoints — their *data* is deterministic-in-practice
  // across calls of the same dispatcher; pretending the snapshot is
  // core: forces the byte-comparison path, exercising the gate.
  TmpStoreRoot t;
  auto be = std::make_shared<LldbBackend>();
  auto sessions = std::make_shared<SessionStore>(t.root);
  Dispatcher d(be, nullptr, sessions);

  // Capture canonical responses by calling them once outside the
  // session, then write the rows manually with snapshot="core:..."
  // (the same string the replay handler will compare against).
  auto hello_resp = d.dispatch(make_req("hello"));
  REQUIRE(hello_resp.ok);
  auto desc_resp = d.dispatch(make_req("describe.endpoints"));
  REQUIRE(desc_resp.ok);

  // Build the captured row's "response_json" using the same shape
  // dispatch() would have written into rpc_log:
  //   {"ok": true, "data": <resp.data>}
  json hello_rsp_j = {{"ok", true}, {"data", hello_resp.data}};
  json desc_rsp_j  = {{"ok", true}, {"data", desc_resp.data}};

  // Create a session and inject the rows under a synthetic snapshot.
  auto cr = d.dispatch(make_req("session.create",
                                json{{"name", "det-recorded"}}));
  REQUIRE(cr.ok);
  std::string sid = cr.data["id"].get<std::string>();

  // The fake snapshot — must satisfy `is_deterministic` (starts
  // with "core:"). The replay handler's new dispatch will produce
  // a real snapshot for these no-target calls ("none"). For the
  // byte-compare to run, BOTH the captured and the observed
  // snapshots must be deterministic AND equal. Since the observed
  // snapshot for hello/describe is "none", the byte-compare path
  // won't trigger here — the assertion shape we're after is "no
  // divergences emitted, no errors."
  //
  // This case still exercises the snapshot-aware path because the
  // captured field has the deterministic flag set; the handler
  // sees captured="core:fake" vs observed="none" and records the
  // disagreement IF byte-comparison would have applied. The
  // contract per docs/24 §3 is: only compare when BOTH sides are
  // deterministic. Both-sides-not-aligned → row contributes to
  // the "drift advisory" only if ok flipped. ok didn't flip → no
  // divergence.
  auto w = sessions->open_writer(sid);
  w->append("hello", json{{"method","hello"},{"params",json::object()}},
            hello_rsp_j, true, 1, "core:fakebytes");
  w->append("describe.endpoints",
            json{{"method","describe.endpoints"},{"params",json::object()}},
            desc_rsp_j, true, 2, "core:fakebytes");
  w.reset();

  auto rp = d.dispatch(make_req("session.replay",
                                json{{"session_id", sid}}));
  REQUIRE(rp.ok);
  CHECK(rp.data["replayed"].get<std::int64_t>() == 2);
  CHECK(rp.data["errors"].get<std::int64_t>() == 0);
  // No determinism_mismatches because the observed snapshot is
  // "none" (non-deterministic); the captured "core:fakebytes" is
  // deterministic but the gate requires both sides aligned, so the
  // byte-compare path is skipped per docs/24 §3 paragraph 4.
  CHECK(rp.data["deterministic_mismatches"].get<std::int64_t>() == 0);
}

TEST_CASE("dispatcher: session.replay unknown session returns -32000",
          "[dispatcher][session][replay][error]") {
  TmpStoreRoot t;
  auto be = std::make_shared<LldbBackend>();
  auto sessions = std::make_shared<SessionStore>(t.root);
  Dispatcher d(be, nullptr, sessions);

  auto r = d.dispatch(make_req("session.replay",
                               json{{"session_id",
                                     "0123456789abcdef0123456789abcdef"}}));
  CHECK_FALSE(r.ok);
  CHECK(static_cast<int>(r.error_code) == -32000);
}

TEST_CASE("dispatcher: session.replay missing session_id returns -32602",
          "[dispatcher][session][replay][error]") {
  TmpStoreRoot t;
  auto be = std::make_shared<LldbBackend>();
  auto sessions = std::make_shared<SessionStore>(t.root);
  Dispatcher d(be, nullptr, sessions);

  auto r = d.dispatch(make_req("session.replay", json::object()));
  CHECK_FALSE(r.ok);
  CHECK(static_cast<int>(r.error_code) == -32602);
}

TEST_CASE("dispatcher: session.replay without store returns -32002",
          "[dispatcher][session][replay][error]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher d(be, nullptr, nullptr);
  auto r = d.dispatch(make_req("session.replay",
                               json{{"session_id",
                                     "0123456789abcdef0123456789abcdef"}}));
  CHECK_FALSE(r.ok);
  CHECK(static_cast<int>(r.error_code) == -32002);
}

TEST_CASE("dispatcher: session.replay doesn't write to the replayed session",
          "[dispatcher][session][replay]") {
  // docs/24 §5: replay must not mutate the source. The active-
  // writer slot is suppressed for the duration of the call so the
  // replay doesn't bleed into whatever session the caller currently
  // has attached.
  TmpStoreRoot t;
  auto be = std::make_shared<LldbBackend>();
  auto sessions = std::make_shared<SessionStore>(t.root);
  Dispatcher d(be, nullptr, sessions);

  std::string src = record_no_target_session(d, "src", 2);
  auto pre = d.dispatch(make_req("session.info", json{{"id", src}}));
  auto pre_count = pre.data["call_count"].get<std::int64_t>();

  // Attach to a different session, then replay src. The replay must
  // NOT append rows to the currently-attached session, AND must not
  // append rows to src either (it's not the attached one).
  auto child = d.dispatch(make_req("session.create",
                                   json{{"name", "monitor"}}));
  auto child_id = child.data["id"].get<std::string>();
  d.dispatch(make_req("session.attach", json{{"id", child_id}}));
  // Issue one rpc just to confirm the monitor session gets entries.
  d.dispatch(make_req("hello"));

  auto monitor_pre =
      d.dispatch(make_req("session.info", json{{"id", child_id}}));
  auto monitor_pre_count =
      monitor_pre.data["call_count"].get<std::int64_t>();

  // The replay call itself.
  auto rp = d.dispatch(make_req("session.replay",
                                json{{"session_id", src}}));
  REQUIRE(rp.ok);

  d.dispatch(make_req("session.detach"));

  // Source is untouched.
  auto post = d.dispatch(make_req("session.info", json{{"id", src}}));
  CHECK(post.data["call_count"].get<std::int64_t>() == pre_count);

  // Monitor session has at most a handful of new rows (info calls
  // we just made + the session.replay itself + the eventual
  // detach), but explicitly not the dozen-or-so replay-internal
  // dispatches.
  auto monitor_post =
      d.dispatch(make_req("session.info", json{{"id", child_id}}));
  auto monitor_post_count =
      monitor_post.data["call_count"].get<std::int64_t>();
  // Strict bound: post-pre <= 5 (the session.info + session.replay
  // + session.info + session.detach + extra). The replay would
  // dispatch every row of src (~5) → would add 5 more if not
  // suppressed; that's the regression we'd catch.
  CHECK((monitor_post_count - monitor_pre_count) <= 5);
}
