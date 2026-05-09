// SPDX-License-Identifier: Apache-2.0
// View-retrofit regression test.
//
// Some endpoints used to return bare `{matches:[...]}` shapes; they
// have since been retrofitted with view::apply_to_array so agents can
// project / page / summarize their array results. This test pins down
// the contract on symbol.find specifically — if a future refactor
// drops the view application, this fails immediately.
//
// We exercise the full dispatcher stack against a real LldbBackend so
// the assertion covers the wire shape an agent actually sees, not
// just the protocol::view module in isolation (already tested
// extensively in test_protocol_view.cpp).

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"
#include "daemon/dispatcher.h"
#include "protocol/jsonrpc.h"

#include <memory>

using ldb::backend::LldbBackend;
using ldb::daemon::Dispatcher;
using ldb::protocol::Request;
using nlohmann::json;

namespace {

constexpr const char* kFixturePath = LDB_FIXTURE_STRUCTS_PATH;

}  // namespace

TEST_CASE("dispatcher: symbol.find responses carry view envelope (total)",
          "[dispatcher][view][symbol]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher d(be);

  Request open_req;
  open_req.id = "r1";
  open_req.method = "target.open";
  open_req.params = json{{"path", kFixturePath}};
  auto open_resp = d.dispatch(open_req);
  REQUIRE(open_resp.ok);
  std::uint64_t target_id = open_resp.data["target_id"].get<std::uint64_t>();

  // No view: still returns the envelope with `total`.
  Request bare_req;
  bare_req.id = "r2";
  bare_req.method = "symbol.find";
  bare_req.params = json{{"target_id", target_id},
                         {"name", "point2_distance_sq"}};
  auto bare = d.dispatch(bare_req);
  REQUIRE(bare.ok);
  REQUIRE(bare.data.contains("matches"));
  REQUIRE(bare.data.contains("total"));
  CHECK(bare.data["matches"].is_array());

  // view.fields=["name","kind"]: addr / sz / module / load_addr / mangled
  // must be dropped on every match.
  Request proj_req;
  proj_req.id = "r3";
  proj_req.method = "symbol.find";
  proj_req.params = json{
      {"target_id", target_id},
      {"name", "point2_distance_sq"},
      {"view", json{{"fields", json::array({"name", "kind"})}}}};
  auto proj = d.dispatch(proj_req);
  REQUIRE(proj.ok);
  REQUIRE(proj.data.contains("matches"));
  REQUIRE(proj.data["matches"].is_array());
  REQUIRE_FALSE(proj.data["matches"].empty());

  for (const auto& m : proj.data["matches"]) {
    CHECK(m.contains("name"));
    CHECK(m.contains("kind"));
    CHECK_FALSE(m.contains("addr"));
    CHECK_FALSE(m.contains("sz"));
    CHECK_FALSE(m.contains("module"));
    CHECK_FALSE(m.contains("load_addr"));
  }
}
