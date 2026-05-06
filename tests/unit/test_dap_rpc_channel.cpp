// Tests for src/dap/rpc_channel — the DAP shim's subprocess channel
// to ldbd. The shim's translation layer is fully tested against the
// abstract `RpcChannel` interface in test_dap_handlers; this file
// verifies the concrete `SubprocessRpcChannel` actually spawns the
// daemon, sends a request, and decodes the response.
//
// Uses LDBD_PATH (compile-time path to the just-built daemon) to keep
// the test hermetic.

#include <catch_amalgamated.hpp>

#include "dap/rpc_channel.h"

#include <filesystem>
#include <string>

#ifndef LDBD_PATH
#error "LDBD_PATH must be defined by CMake to point at the test ldbd binary"
#endif

using ldb::dap::RpcChannel;
using ldb::dap::SubprocessRpcChannel;

TEST_CASE("SubprocessRpcChannel: spawn ldbd and call describe.endpoints",
          "[dap][rpc][live]") {
  std::filesystem::path ldbd = LDBD_PATH;
  if (!std::filesystem::exists(ldbd)) {
    SKIP("ldbd binary not built at " + ldbd.string());
  }

  SubprocessRpcChannel chan(ldbd.string());
  auto resp = chan.call("describe.endpoints", ldb::dap::json::object());
  REQUIRE(resp.ok);
  REQUIRE(resp.data.contains("endpoints"));
  REQUIRE(resp.data["endpoints"].is_array());
  // Sanity: the daemon advertises at least the methods the DAP shim
  // depends on.
  bool has_thread_list = false;
  for (const auto& ep : resp.data["endpoints"]) {
    if (ep.is_object() && ep.value("method", "") == "thread.list") {
      has_thread_list = true;
      break;
    }
  }
  REQUIRE(has_thread_list);
}

TEST_CASE("SubprocessRpcChannel: bad method returns ok=false",
          "[dap][rpc][live]") {
  std::filesystem::path ldbd = LDBD_PATH;
  if (!std::filesystem::exists(ldbd)) {
    SKIP("ldbd binary not built at " + ldbd.string());
  }
  SubprocessRpcChannel chan(ldbd.string());
  auto resp = chan.call("nonexistent.method", ldb::dap::json::object());
  REQUIRE_FALSE(resp.ok);
  REQUIRE(resp.error_code != 0);
  REQUIRE_FALSE(resp.error_message.empty());
}
