// Dispatcher integration test for `observer.net.igmp` (M4 §4.6 closeout).
//
// Drives Dispatcher::dispatch directly (no subprocess) so we lock down
// the JSON wire shape and the view::apply_to_array integration on
// `groups`.
//
// Live cases SKIP cleanly when /proc/net/igmp is missing (off-Linux).

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"
#include "daemon/dispatcher.h"
#include "protocol/jsonrpc.h"

#include <filesystem>
#include <memory>
#include <string>

namespace {

bool has_proc_net_igmp() {
  std::error_code ec;
  return std::filesystem::exists("/proc/net/igmp", ec);
}

ldb::protocol::Request make_req(const std::string& method,
                                const nlohmann::json& params,
                                const std::string& id = "1") {
  ldb::protocol::Request r;
  r.id = id;
  r.method = method;
  r.params = params;
  return r;
}

}  // namespace

TEST_CASE("describe.endpoints lists observer.net.igmp",
          "[observers][net][igmp][dispatcher]") {
  auto be = std::make_shared<ldb::backend::LldbBackend>();
  ldb::daemon::Dispatcher d{be};
  auto resp = d.dispatch(make_req("describe.endpoints", nlohmann::json::object()));
  REQUIRE(resp.ok);
  auto& eps = resp.data.at("endpoints");
  REQUIRE(eps.is_array());
  bool found = false;
  for (const auto& e : eps) {
    if (e.value("method", "") == "observer.net.igmp") {
      found = true;
      // requires_target should be false (host-side endpoint).
      CHECK(e.value("requires_target", true) == false);
      break;
    }
  }
  CHECK(found);
}

TEST_CASE("observer.net.igmp returns groups+total against current host",
          "[observers][net][igmp][dispatcher][live]") {
  if (!has_proc_net_igmp()) {
    SKIP("/proc/net/igmp not present (not Linux?)");
  }
  auto be = std::make_shared<ldb::backend::LldbBackend>();
  ldb::daemon::Dispatcher d{be};
  auto resp = d.dispatch(make_req("observer.net.igmp", nlohmann::json::object()));
  REQUIRE(resp.ok);
  REQUIRE(resp.data.contains("groups"));
  REQUIRE(resp.data.contains("total"));
  CHECK(resp.data["groups"].is_array());
  // total == size of returned groups array (no view spec passed).
  CHECK(resp.data["total"].get<std::uint64_t>() ==
        resp.data["groups"].size());
  for (const auto& g : resp.data["groups"]) {
    CHECK(g.contains("idx"));
    CHECK(g.contains("device"));
    CHECK(g.contains("addresses"));
    CHECK(g["addresses"].is_array());
  }
}

TEST_CASE("observer.net.igmp view limit applies",
          "[observers][net][igmp][dispatcher][live]") {
  if (!has_proc_net_igmp()) {
    SKIP("/proc/net/igmp not present (not Linux?)");
  }
  auto be = std::make_shared<ldb::backend::LldbBackend>();
  ldb::daemon::Dispatcher d{be};
  nlohmann::json params;
  params["view"] = {{"limit", 1}, {"offset", 0}};
  auto resp = d.dispatch(make_req("observer.net.igmp", params));
  REQUIRE(resp.ok);
  CHECK(resp.data["groups"].is_array());
  CHECK(resp.data["groups"].size() <= 1);
}
