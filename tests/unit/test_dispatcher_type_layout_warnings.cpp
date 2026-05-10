// SPDX-License-Identifier: Apache-2.0
//
// Dispatcher test for the type.layout DWARF-consistency warning
// (papercut #4 from the cffex_server RE pass on 2026-05-10).
//
// Some toolchains emit DWARF where a type's recorded byte_size is
// smaller than the end of one or more of its fields (observed on a
// g++ -O2 build of CSeatInfo, where vAllowedProducts/vAllowedInsts/
// vNotAllowedInsts were placed at offsets > byte_size). The
// dispatcher must surface this as a non-fatal `warnings` array on
// type.layout responses so the agent can detect the inconsistency
// without re-disassembling the constructor itself.
//
// We use a stub backend so the test exercises only the dispatcher
// response shape; live LLDB/DWARF behavior is covered elsewhere.

#include <catch_amalgamated.hpp>

#include "backend/debugger_backend.h"
#include "daemon/dispatcher.h"
#include "protocol/jsonrpc.h"

#include <map>
#include <memory>
#include <optional>
#include <string>

using ldb::backend::DebuggerBackend;
using ldb::backend::Field;
using ldb::backend::TargetId;
using ldb::backend::ThreadId;
using ldb::backend::TypeLayout;
using ldb::daemon::Dispatcher;
using ldb::protocol::Request;
using ldb::protocol::Response;
using nlohmann::json;

namespace {

class TypeLayoutStub : public DebuggerBackend {
 public:
  using TID = TargetId;
  using ThrID = ThreadId;

  std::map<std::string, TypeLayout> layouts;
  TID known_target = 1;

  std::optional<TypeLayout>
      find_type_layout(TID t, const std::string& name) override {
    if (t != known_target) throw ldb::backend::Error("unknown target_id");
    auto it = layouts.find(name);
    if (it == layouts.end()) return std::nullopt;
    return it->second;
  }

  // The remaining overrides are inert — type.layout dispatch only
  // touches find_type_layout.
  ldb::backend::OpenResult open_executable(const std::string&) override { return {}; }
  ldb::backend::OpenResult create_empty_target() override { return {}; }
  ldb::backend::OpenResult load_core(const std::string&) override { return {}; }
  std::vector<ldb::backend::Module> list_modules(TID) override { return {}; }
  std::vector<ldb::backend::SymbolMatch>
      find_symbols(TID, const ldb::backend::SymbolQuery&) override { return {}; }
  std::vector<ldb::backend::GlobalVarMatch>
      find_globals_of_type(TID, std::string_view, bool&) override { return {}; }
  std::vector<ldb::backend::StringMatch>
      find_strings(TID, const ldb::backend::StringQuery&) override { return {}; }
  std::vector<ldb::backend::DisasmInsn>
      disassemble_range(TID, std::uint64_t, std::uint64_t) override { return {}; }
  std::vector<ldb::backend::XrefMatch>
      xref_address(TID, std::uint64_t) override { return {}; }
  std::vector<ldb::backend::StringXrefResult>
      find_string_xrefs(TID, const std::string&) override { return {}; }
  ldb::backend::ProcessStatus
      launch_process(TID, const ldb::backend::LaunchOptions&) override { return {}; }
  ldb::backend::ProcessStatus get_process_state(TID) override { return {}; }
  ldb::backend::ProcessStatus continue_process(TID) override { return {}; }
  ldb::backend::ProcessStatus continue_thread(TID, ThrID) override { return {}; }
  ldb::backend::ProcessStatus kill_process(TID) override { return {}; }
  ldb::backend::ProcessStatus attach(TID, std::int32_t) override { return {}; }
  ldb::backend::ProcessStatus detach_process(TID) override { return {}; }
  ldb::backend::ProcessStatus
      connect_remote_target(TID, const std::string&, const std::string&) override {
    return {};
  }
  ldb::backend::ConnectRemoteSshResult
      connect_remote_target_ssh(TID,
          const ldb::backend::ConnectRemoteSshOptions&) override { return {}; }
  bool save_core(TID, const std::string&) override { return false; }
  std::vector<ldb::backend::ThreadInfo> list_threads(TID) override { return {}; }
  std::vector<ldb::backend::FrameInfo>
      list_frames(TID, ThrID, std::uint32_t) override { return {}; }
  ldb::backend::ProcessStatus
      step_thread(TID, ThrID, ldb::backend::StepKind) override { return {}; }
  std::vector<ldb::backend::ValueInfo>
      list_locals(TID, ThrID, std::uint32_t) override { return {}; }
  std::vector<ldb::backend::ValueInfo>
      list_args(TID, ThrID, std::uint32_t) override { return {}; }
  std::vector<ldb::backend::ValueInfo>
      list_registers(TID, ThrID, std::uint32_t) override { return {}; }
  ldb::backend::EvalResult
      evaluate_expression(TID, ThrID, std::uint32_t,
                          const std::string&,
                          const ldb::backend::EvalOptions&) override {
    return {};
  }
  ldb::backend::ReadResult
      read_value_path(TID, ThrID, std::uint32_t,
                      const std::string&) override {
    return {};
  }
  std::vector<std::uint8_t>
      read_memory(TID, std::uint64_t, std::uint64_t) override { return {}; }
  std::string
      read_cstring(TID, std::uint64_t, std::uint32_t) override { return {}; }
  std::vector<ldb::backend::MemoryRegion> list_regions(TID) override { return {}; }
  std::vector<ldb::backend::MemorySearchHit>
      search_memory(TID, std::uint64_t, std::uint64_t,
                    const std::vector<std::uint8_t>&,
                    std::uint32_t) override { return {}; }
  ldb::backend::BreakpointHandle
      create_breakpoint(TID, const ldb::backend::BreakpointSpec&) override { return {}; }
  void set_breakpoint_callback(TID, std::int32_t,
                               ldb::backend::BreakpointCallback,
                               void*) override {}
  void disable_breakpoint(TID, std::int32_t) override {}
  void enable_breakpoint(TID, std::int32_t) override {}
  void delete_breakpoint(TID, std::int32_t) override {}
  std::uint64_t
      read_register(TID, ThrID, std::uint32_t,
                    const std::string&) override { return 0; }
  void close_target(TID) override {}
  void label_target(TID, std::string) override {}
  std::optional<std::string> get_target_label(TID) override { return std::nullopt; }
  std::string snapshot_for_target(TID) override { return "none"; }
  std::vector<ldb::backend::TargetInfo> list_targets() override {
    ldb::backend::TargetInfo i; i.target_id = known_target; i.triple = "stub";
    return {i};
  }
  void attach_target_resource(TID,
      std::unique_ptr<ldb::backend::DebuggerBackend::TargetResource>) override {}
};

Field mkfield(std::string name, std::uint64_t off, std::uint64_t sz) {
  Field f;
  f.name = std::move(name);
  f.type_name = "u8";
  f.offset = off;
  f.byte_size = sz;
  return f;
}

Request make_req(const char* method, json params, const char* id = "r1") {
  Request r;
  r.id = id;
  r.method = method;
  r.params = std::move(params);
  return r;
}

}  // namespace

TEST_CASE("type.layout: consistent layout has no warnings",
          "[dispatcher][type_layout][warnings]") {
  auto stub = std::make_shared<TypeLayoutStub>();
  TypeLayout t;
  t.name = "Pod";
  t.byte_size = 16;
  t.alignment = 8;
  t.fields = {mkfield("a", 0, 8), mkfield("b", 8, 8)};
  stub->layouts["Pod"] = std::move(t);

  Dispatcher d(stub);
  auto resp = d.dispatch(make_req("type.layout",
      json{{"target_id", stub->known_target}, {"name", "Pod"}}));

  REQUIRE(resp.ok);
  REQUIRE(resp.data["found"].get<bool>() == true);
  CHECK_FALSE(resp.data.contains("warnings"));
}

TEST_CASE("type.layout: field end > byte_size emits a warning",
          "[dispatcher][type_layout][warnings]") {
  auto stub = std::make_shared<TypeLayoutStub>();
  // Mirrors the cffex_server CSeatInfo case at miniature scale: the
  // trailing field's end (104) exceeds the recorded byte_size (96).
  TypeLayout t;
  t.name = "Broken";
  t.byte_size = 96;
  t.alignment = 8;
  t.fields = {
      mkfield("hdr",  0,  8),
      mkfield("body", 8, 80),
      mkfield("tail", 88, 16),  // ends at 104 > 96
  };
  stub->layouts["Broken"] = std::move(t);

  Dispatcher d(stub);
  auto resp = d.dispatch(make_req("type.layout",
      json{{"target_id", stub->known_target}, {"name", "Broken"}}));

  REQUIRE(resp.ok);
  REQUIRE(resp.data["found"].get<bool>() == true);
  REQUIRE(resp.data.contains("warnings"));
  REQUIRE(resp.data["warnings"].is_array());
  REQUIRE(resp.data["warnings"].size() >= 1);
  auto msg = resp.data["warnings"][0].get<std::string>();
  CHECK(msg.find("DWARF inconsistency") != std::string::npos);
  CHECK(msg.find("tail") != std::string::npos);
  CHECK(msg.find("96") != std::string::npos);
}

TEST_CASE("type.layout: field end exactly == byte_size has no warning",
          "[dispatcher][type_layout][warnings]") {
  auto stub = std::make_shared<TypeLayoutStub>();
  TypeLayout t;
  t.name = "Tight";
  t.byte_size = 16;
  t.alignment = 8;
  t.fields = {mkfield("a", 0, 8), mkfield("b", 8, 8)};  // ends exactly at 16
  stub->layouts["Tight"] = std::move(t);

  Dispatcher d(stub);
  auto resp = d.dispatch(make_req("type.layout",
      json{{"target_id", stub->known_target}, {"name", "Tight"}}));

  REQUIRE(resp.ok);
  REQUIRE(resp.data["found"].get<bool>() == true);
  CHECK_FALSE(resp.data.contains("warnings"));
}
