// SPDX-License-Identifier: Apache-2.0
//
// Dispatcher test for disasm.function / disasm.range instruction
// address aliasing (papercut #12 from the cffex_server RE pass
// round 2).
//
// Original symptom: a user filtered with
// `--view fields=address,mnemonic,operands,comment` and got
// instructions missing the address entirely (the JSON wire field is
// `addr`, not `address`; the unrelated `address` key at the function-
// wrapping level is independently emitted). The fix emits both
// `addr` AND `address` on each instruction so either name in a
// view-fields filter projects through to the caller.
//
// Uses a stub backend so the test exercises only the dispatcher
// serialization and projection logic; live LLDB disassembly is
// covered by test_backend_disasm.cpp.

#include <catch_amalgamated.hpp>

#include "backend/debugger_backend.h"
#include "daemon/dispatcher.h"
#include "protocol/jsonrpc.h"

#include <map>
#include <memory>
#include <optional>
#include <string>

using ldb::backend::DebuggerBackend;
using ldb::backend::DisasmInsn;
using ldb::backend::SymbolKind;
using ldb::backend::SymbolMatch;
using ldb::backend::SymbolQuery;
using ldb::backend::TargetId;
using ldb::backend::ThreadId;
using ldb::daemon::Dispatcher;
using ldb::protocol::Request;
using ldb::protocol::Response;
using nlohmann::json;

namespace {

class DisasmStub : public DebuggerBackend {
 public:
  using TID = TargetId;
  using ThrID = ThreadId;

  TID known_target = 1;
  std::vector<SymbolMatch> symbols;
  std::vector<DisasmInsn> instructions;

  std::vector<SymbolMatch>
      find_symbols(TID t, const SymbolQuery& q) override {
    if (t != known_target) throw ldb::backend::Error("unknown target_id");
    std::vector<SymbolMatch> out;
    for (const auto& s : symbols) {
      if (s.name == q.name && (q.kind == SymbolKind::kAny || q.kind == s.kind))
        out.push_back(s);
    }
    return out;
  }

  std::vector<DisasmInsn>
      disassemble_range(TID t, std::uint64_t /*start*/,
                        std::uint64_t /*end*/) override {
    if (t != known_target) throw ldb::backend::Error("unknown target_id");
    return instructions;
  }

  // Inert stubs.
  std::optional<ldb::backend::TypeLayout>
      find_type_layout(TID, const std::string&) override { return std::nullopt; }
  ldb::backend::OpenResult open_executable(const std::string&, const ldb::backend::OpenOptions& = {}) override { return {}; }
  ldb::backend::OpenResult create_empty_target() override { return {}; }
  ldb::backend::OpenResult load_core(const std::string&) override { return {}; }
  std::vector<ldb::backend::Module> list_modules(TID) override { return {}; }
  std::vector<ldb::backend::GlobalVarMatch>
      find_globals_of_type(TID, std::string_view, bool&) override { return {}; }
  std::vector<ldb::backend::StringMatch>
      find_strings(TID, const ldb::backend::StringQuery&) override { return {}; }
  ldb::backend::DebuggerBackend::ModuleSymbols
      iterate_symbols(TID, std::string_view) override { return {}; }
  ldb::backend::DebuggerBackend::ModuleTypes
      iterate_types(TID, std::string_view) override { return {}; }
  ldb::backend::DebuggerBackend::ModuleStrings
      iterate_strings(TID, std::string_view) override { return {}; }
  std::vector<ldb::backend::XrefMatch>
      xref_address(TID, std::uint64_t, ldb::backend::XrefProvenance*) override { return {}; }
  std::vector<ldb::backend::StringXrefResult>
      find_string_xrefs(TID, const std::string&) override { return {}; }
  ldb::backend::ProcessStatus
      launch_process(TID, const ldb::backend::LaunchOptions&) override { return {}; }
  ldb::backend::ProcessStatus get_process_state(TID) override { return {}; }
  ldb::backend::ProcessStatus continue_process(TID) override { return {}; }
  ldb::backend::ProcessStatus continue_thread(TID, ThrID) override { return {}; }
  ldb::backend::ProcessStatus suspend_thread(TID, ThrID) override { return {}; }
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
  ldb::backend::ProcessStatus reverse_continue(TID) override { return {}; }
  ldb::backend::ProcessStatus
      reverse_step_thread(TID, ThrID, ldb::backend::ReverseStepKind) override {
    return {};
  }
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

DisasmInsn mkinsn(std::uint64_t addr, std::string mn, std::string ops) {
  DisasmInsn d;
  d.address = addr;
  d.byte_size = 2;
  d.bytes = {0x90, 0x90};
  d.mnemonic = std::move(mn);
  d.operands = std::move(ops);
  return d;
}

std::shared_ptr<DisasmStub> make_stub() {
  auto s = std::make_shared<DisasmStub>();
  SymbolMatch sym;
  sym.name = "f";
  sym.kind = SymbolKind::kFunction;
  sym.address = 0x4010;
  sym.byte_size = 6;
  s->symbols.push_back(sym);
  s->instructions = {
      mkinsn(0x4010, "pushq", "%rbp"),
      mkinsn(0x4012, "movq",  "%rsp, %rbp"),
      mkinsn(0x4014, "retq",  ""),
  };
  return s;
}

Request make_req(const char* method, json params, const char* id = "r1") {
  Request r;
  r.id = id;
  r.method = method;
  r.params = std::move(params);
  return r;
}

}  // namespace

TEST_CASE("disasm.function: each instruction has both `addr` and `address`",
          "[dispatcher][disasm][address_alias]") {
  auto stub = make_stub();
  Dispatcher d(stub);
  auto resp = d.dispatch(make_req("disasm.function",
      json{{"target_id", stub->known_target}, {"name", "f"}}));

  REQUIRE(resp.ok);
  REQUIRE(resp.data["found"].get<bool>() == true);
  auto& insns = resp.data["instructions"];
  REQUIRE(insns.is_array());
  REQUIRE(insns.size() == 3);

  for (std::size_t i = 0; i < insns.size(); ++i) {
    INFO("instruction index " << i);
    REQUIRE(insns[i].contains("addr"));
    REQUIRE(insns[i].contains("address"));
    CHECK(insns[i]["addr"].get<std::uint64_t>() ==
          insns[i]["address"].get<std::uint64_t>());
    CHECK(insns[i]["addr"].get<std::uint64_t>() > 0);
  }

  CHECK(insns[0]["address"].get<std::uint64_t>() == 0x4010);
  CHECK(insns[1]["address"].get<std::uint64_t>() == 0x4012);
  CHECK(insns[2]["address"].get<std::uint64_t>() == 0x4014);
}

TEST_CASE("disasm.function: --view fields=address projects through",
          "[dispatcher][disasm][address_alias]") {
  auto stub = make_stub();
  Dispatcher d(stub);
  auto resp = d.dispatch(make_req("disasm.function",
      json{{"target_id", stub->known_target}, {"name", "f"},
           {"view", json{{"fields", json::array({"address", "mnemonic"})}}}}));

  REQUIRE(resp.ok);
  auto& insns = resp.data["instructions"];
  REQUIRE(insns.is_array());
  REQUIRE(insns.size() == 3);
  for (const auto& ix : insns) {
    REQUIRE(ix.contains("address"));
    REQUIRE(ix.contains("mnemonic"));
    CHECK_FALSE(ix.contains("addr"));    // projected out
    CHECK_FALSE(ix.contains("bytes"));   // projected out
    CHECK_FALSE(ix.contains("operands"));
  }
  CHECK(insns[0]["address"].get<std::uint64_t>() == 0x4010);
}

TEST_CASE("disasm.function: --view fields=addr still works (back-compat)",
          "[dispatcher][disasm][address_alias]") {
  auto stub = make_stub();
  Dispatcher d(stub);
  auto resp = d.dispatch(make_req("disasm.function",
      json{{"target_id", stub->known_target}, {"name", "f"},
           {"view", json{{"fields", json::array({"addr", "mnemonic"})}}}}));

  REQUIRE(resp.ok);
  auto& insns = resp.data["instructions"];
  REQUIRE(insns.size() == 3);
  for (const auto& ix : insns) {
    REQUIRE(ix.contains("addr"));
    CHECK_FALSE(ix.contains("address"));  // projected out — `addr` chosen
  }
}
