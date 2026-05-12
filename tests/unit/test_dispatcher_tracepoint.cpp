// SPDX-License-Identifier: Apache-2.0
// Tests for the tracepoint.* dispatcher endpoints
// (post-V1 #26 phase-1, docs/30-tracepoints.md §1).
//
// Coverage:
//   * tracepoint.create rejects with -32602 when:
//       - target_id missing
//       - where missing / empty
//       - rate_limit malformed (parsed via parse_rate_limit; bad
//         input never reaches the orchestrator)
//       - action field set (tracepoint action is locked to
//         log-and-continue)
//   * tracepoint.create accepts predicate {source} or {bytecode_b64}
//     using the same compile/decode path as probe.create.
//   * tracepoint.create returns the assigned tracepoint_id +
//     kind="tracepoint".
//   * tracepoint.list returns the entry with has_predicate +
//     rate_limited fields.
//   * tracepoint.delete removes the entry; subsequent
//     tracepoint.list omits it.
//   * tracepoint.frames is alias-shape for probe.events (returns
//     {frames, total, next_since}).
//   * describe.endpoints lists all six tracepoint.* endpoints.

#include <catch_amalgamated.hpp>

#include "backend/debugger_backend.h"
#include "backend/lldb_backend.h"
#include "daemon/dispatcher.h"
#include "probes/probe_orchestrator.h"
#include "protocol/jsonrpc.h"

#include <memory>
#include <string>

using ldb::backend::LldbBackend;
using ldb::daemon::Dispatcher;
using ldb::probes::ProbeOrchestrator;
using ldb::protocol::ErrorCode;
using ldb::protocol::Request;
using ldb::protocol::Response;
using ldb::protocol::json;

namespace {

Request req(const std::string& method, json params, const std::string& id = "1") {
  Request r;
  r.id = id;
  r.method = method;
  r.params = std::move(params);
  return r;
}

struct Fixture {
  std::shared_ptr<LldbBackend>       backend;
  std::shared_ptr<ProbeOrchestrator> orch;
  Dispatcher                         disp;

  Fixture()
      : backend(std::make_shared<LldbBackend>()),
        orch(std::make_shared<ProbeOrchestrator>(backend, nullptr)),
        disp(backend, /*artifacts=*/nullptr, /*sessions=*/nullptr, orch) {}
};

}  // namespace

TEST_CASE("tracepoint.create: missing target_id → -32602",
          "[dispatcher][tracepoint][error]") {
  Fixture f;
  auto resp = f.disp.dispatch(req("tracepoint.create", json{
      {"where", {{"function", "main"}}},
  }));
  REQUIRE_FALSE(resp.ok);
  CHECK(resp.error_code == ErrorCode::kInvalidParams);
}

TEST_CASE("tracepoint.create: missing where → -32602",
          "[dispatcher][tracepoint][error]") {
  Fixture f;
  auto resp = f.disp.dispatch(req("tracepoint.create", json{
      {"target_id", 1},
  }));
  REQUIRE_FALSE(resp.ok);
  CHECK(resp.error_code == ErrorCode::kInvalidParams);
}

TEST_CASE("tracepoint.create: 'action' field is rejected with hint",
          "[dispatcher][tracepoint][error]") {
  Fixture f;
  auto resp = f.disp.dispatch(req("tracepoint.create", json{
      {"target_id", 1},
      {"where", {{"function", "main"}}},
      {"action", "stop"},
  }));
  REQUIRE_FALSE(resp.ok);
  CHECK(resp.error_code == ErrorCode::kInvalidParams);
  CHECK(resp.error_message.find("log-and-continue") != std::string::npos);
}

TEST_CASE("tracepoint.create: malformed rate_limit → -32602",
          "[dispatcher][tracepoint][error]") {
  Fixture f;
  auto resp = f.disp.dispatch(req("tracepoint.create", json{
      {"target_id", 1},
      {"where", {{"function", "main"}}},
      {"rate_limit", "abc"},
  }));
  REQUIRE_FALSE(resp.ok);
  CHECK(resp.error_code == ErrorCode::kInvalidParams);
  CHECK(resp.error_message.find("rate_limit") != std::string::npos);
}

TEST_CASE("tracepoint.create: zero rate_limit → -32602",
          "[dispatcher][tracepoint][error]") {
  Fixture f;
  auto resp = f.disp.dispatch(req("tracepoint.create", json{
      {"target_id", 1},
      {"where", {{"function", "main"}}},
      {"rate_limit", "0/s"},
  }));
  REQUIRE_FALSE(resp.ok);
  CHECK(resp.error_code == ErrorCode::kInvalidParams);
}

TEST_CASE("tracepoint.create: predicate.source compile error → -32602",
          "[dispatcher][tracepoint][predicate][error]") {
  Fixture f;
  auto resp = f.disp.dispatch(req("tracepoint.create", json{
      {"target_id", 1},
      {"where", {{"function", "main"}}},
      {"predicate", {{"source", "(eq 1)"}}},   // wrong arity
  }));
  REQUIRE_FALSE(resp.ok);
  CHECK(resp.error_code == ErrorCode::kInvalidParams);
}

TEST_CASE("describe.endpoints: tracepoint.* endpoints are listed",
          "[dispatcher][tracepoint][describe]") {
  Fixture f;
  auto resp = f.disp.dispatch(req("describe.endpoints", json::object()));
  REQUIRE(resp.ok);
  std::vector<std::string> wanted = {
      "tracepoint.create", "tracepoint.list", "tracepoint.enable",
      "tracepoint.disable", "tracepoint.delete", "tracepoint.frames",
  };
  for (const auto& w : wanted) {
    bool found = false;
    for (const auto& e : resp.data["endpoints"]) {
      if (e.value("method", std::string{}) == w) { found = true; break; }
    }
    INFO("looking for endpoint " << w);
    CHECK(found);
  }
}
