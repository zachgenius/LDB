// SPDX-License-Identifier: Apache-2.0
// Tests for the dispatcher routing of:
//   * thread.continue({target_id, tid})
//   * process.continue({target_id, tid?})  — tid is the new optional
//     param (Tier 4 §14, scoped slice).
//
// Both endpoints exercise the new backend::DebuggerBackend::continue_thread
// virtual when a `tid` is provided. In v0.3 continue_thread is a sync
// passthrough into continue_process (LLDB SetAsync(false) — no per-thread
// keep-running runtime). The protocol surface is async-shaped now so
// agent code can switch behavior on the daemon handshake when v0.4 lands
// true SBProcess::SetAsync(true).
//
// We use a CountingStub backend (not a live LldbBackend) so the tests
// run without a target / fixture. The stub records which method the
// dispatcher routed into and returns a deterministic ProcessStatus.

#include <catch_amalgamated.hpp>

#include "backend/debugger_backend.h"
#include "daemon/dispatcher.h"
#include "protocol/jsonrpc.h"

#include <memory>
#include <optional>
#include <string>

using ldb::backend::DebuggerBackend;
using ldb::backend::ProcessState;
using ldb::backend::ProcessStatus;
using ldb::backend::TargetId;
using ldb::backend::ThreadId;
using ldb::daemon::Dispatcher;
using ldb::protocol::ErrorCode;
using ldb::protocol::Request;
using ldb::protocol::Response;
using ldb::protocol::json;

namespace {

class CountingStub : public DebuggerBackend {
 public:
  using TID = TargetId;
  using ThrID = ThreadId;

  // Recording state.
  int continue_process_calls = 0;
  int continue_thread_calls  = 0;
  ThrID last_continue_thread_tid = 0;
  TID  last_continue_thread_target = 0;

  // The single registered target id; throws Error for anything else.
  TID known_target = 1;

  ProcessState ret_state = ProcessState::kStopped;

  ProcessStatus make_status() const {
    ProcessStatus s;
    s.state = ret_state;
    s.pid   = 42;
    return s;
  }

  ProcessStatus continue_process(TID t) override {
    if (t != known_target) throw ldb::backend::Error("unknown target_id");
    ++continue_process_calls;
    return make_status();
  }

  ProcessStatus continue_thread(TID t, ThrID th) override {
    if (t != known_target) throw ldb::backend::Error("unknown target_id");
    ++continue_thread_calls;
    last_continue_thread_target = t;
    last_continue_thread_tid    = th;
    return make_status();
  }

  ProcessStatus suspend_thread(TID t, ThrID) override {
    if (t != known_target) throw ldb::backend::Error("unknown target_id");
    return make_status();
  }

  // The rest are unused stubs.
  ldb::backend::OpenResult open_executable(const std::string&, const ldb::backend::OpenOptions& = {}) override { return {}; }
  ldb::backend::OpenResult create_empty_target() override { return {}; }
  ldb::backend::OpenResult load_core(const std::string&) override { return {}; }
  std::vector<ldb::backend::Module> list_modules(TID) override { return {}; }
  std::optional<ldb::backend::TypeLayout>
      find_type_layout(TID, const std::string&) override { return std::nullopt; }
  std::vector<ldb::backend::SymbolMatch>
      find_symbols(TID, const ldb::backend::SymbolQuery&) override { return {}; }
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
  std::vector<ldb::backend::DisasmInsn>
      disassemble_range(TID, std::uint64_t, std::uint64_t) override { return {}; }
  std::vector<ldb::backend::XrefMatch>
      xref_address(TID, std::uint64_t, ldb::backend::XrefProvenance*) override { return {}; }
  std::vector<ldb::backend::StringXrefResult>
      find_string_xrefs(TID, const std::string&, ldb::backend::XrefProvenance*) override { return {}; }
  ProcessStatus launch_process(TID, const ldb::backend::LaunchOptions&) override { return {}; }
  ProcessStatus get_process_state(TID) override { return {}; }
  ProcessStatus kill_process(TID) override { return {}; }
  ProcessStatus attach(TID, std::int32_t) override { return {}; }
  ProcessStatus detach_process(TID) override { return {}; }
  ProcessStatus
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
  ProcessStatus
      step_thread(TID, ThrID, ldb::backend::StepKind) override { return {}; }
  ProcessStatus reverse_continue(TID) override { return {}; }
  ProcessStatus
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
                          const ldb::backend::EvalOptions&) override { return {}; }
  ldb::backend::ReadResult
      read_value_path(TID, ThrID, std::uint32_t,
                      const std::string&) override { return {}; }
  std::vector<std::uint8_t>
      read_memory(TID, std::uint64_t, std::uint64_t) override { return {}; }
  std::string read_cstring(TID, std::uint64_t, std::uint32_t) override { return {}; }
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
  std::uint64_t read_register(TID, ThrID, std::uint32_t,
                              const std::string&) override { return 0; }
  void close_target(TID) override {}
  std::vector<ldb::backend::TargetInfo> list_targets() override {
    ldb::backend::TargetInfo i;
    i.target_id = known_target;
    i.triple = "stub";
    return {i};
  }
  void label_target(TID, std::string) override {}
  std::optional<std::string> get_target_label(TID) override { return std::nullopt; }
  std::string snapshot_for_target(TID) override { return "none"; }
  void attach_target_resource(TID,
      std::unique_ptr<DebuggerBackend::TargetResource>) override {}
};

Request make_req(const std::string& method, json params, const std::string& id = "1") {
  Request r;
  r.id = id;
  r.method = method;
  r.params = std::move(params);
  return r;
}

}  // namespace

TEST_CASE("process.continue: no tid routes to backend.continue_process",
          "[dispatcher][process][continue]") {
  auto be = std::make_shared<CountingStub>();
  Dispatcher d(be);
  auto resp = d.dispatch(make_req("process.continue", json{{"target_id", 1}}));
  REQUIRE(resp.ok);
  CHECK(be->continue_process_calls == 1);
  CHECK(be->continue_thread_calls  == 0);
  // Response carries the standard process_status shape.
  CHECK(resp.data.contains("state"));
  CHECK(resp.data.contains("pid"));
}

TEST_CASE("process.continue: with tid routes to backend.continue_thread",
          "[dispatcher][process][continue]") {
  auto be = std::make_shared<CountingStub>();
  Dispatcher d(be);
  auto resp = d.dispatch(make_req("process.continue",
      json{{"target_id", 1}, {"tid", 7777}}));
  REQUIRE(resp.ok);
  CHECK(be->continue_process_calls == 0);
  CHECK(be->continue_thread_calls  == 1);
  CHECK(be->last_continue_thread_target == 1);
  CHECK(be->last_continue_thread_tid    == 7777u);
}

TEST_CASE("process.continue: missing target_id → -32602",
          "[dispatcher][process][continue][error]") {
  auto be = std::make_shared<CountingStub>();
  Dispatcher d(be);
  auto resp = d.dispatch(make_req("process.continue", json::object()));
  REQUIRE_FALSE(resp.ok);
  CHECK(resp.error_code == ErrorCode::kInvalidParams);
}

TEST_CASE("thread.continue: routes to backend.continue_thread",
          "[dispatcher][thread][continue]") {
  auto be = std::make_shared<CountingStub>();
  Dispatcher d(be);
  auto resp = d.dispatch(make_req("thread.continue",
      json{{"target_id", 1}, {"tid", 12345}}));
  REQUIRE(resp.ok);
  CHECK(be->continue_thread_calls == 1);
  CHECK(be->last_continue_thread_target == 1);
  CHECK(be->last_continue_thread_tid    == 12345u);
  CHECK(resp.data.contains("state"));
  CHECK(resp.data.contains("pid"));
}

TEST_CASE("thread.continue: missing target_id → -32602",
          "[dispatcher][thread][continue][error]") {
  auto be = std::make_shared<CountingStub>();
  Dispatcher d(be);
  auto resp = d.dispatch(make_req("thread.continue", json{{"tid", 1}}));
  REQUIRE_FALSE(resp.ok);
  CHECK(resp.error_code == ErrorCode::kInvalidParams);
}

TEST_CASE("thread.continue: missing tid → -32602",
          "[dispatcher][thread][continue][error]") {
  auto be = std::make_shared<CountingStub>();
  Dispatcher d(be);
  auto resp = d.dispatch(make_req("thread.continue", json{{"target_id", 1}}));
  REQUIRE_FALSE(resp.ok);
  CHECK(resp.error_code == ErrorCode::kInvalidParams);
}

TEST_CASE("thread.continue: unknown target_id surfaces backend error (-32000)",
          "[dispatcher][thread][continue][error]") {
  auto be = std::make_shared<CountingStub>();
  Dispatcher d(be);
  auto resp = d.dispatch(make_req("thread.continue",
      json{{"target_id", 9999}, {"tid", 1}}));
  REQUIRE_FALSE(resp.ok);
  CHECK(resp.error_code == ErrorCode::kBackendError);
}

TEST_CASE("describe.endpoints: thread.continue is registered with v0.3-sync disclosure",
          "[dispatcher][describe][thread][continue]") {
  auto be = std::make_shared<CountingStub>();
  Dispatcher d(be);
  auto resp = d.dispatch(make_req("describe.endpoints", json::object()));
  REQUIRE(resp.ok);
  REQUIRE(resp.data.contains("endpoints"));

  bool found_thread_continue = false;
  bool found_process_continue_with_tid = false;

  for (const auto& e : resp.data["endpoints"]) {
    const auto m = e.value("method", "");
    if (m == "thread.continue") {
      found_thread_continue = true;
      // Schema must declare both target_id and tid as required.
      const auto& ps = e["params_schema"];
      REQUIRE(ps.contains("required"));
      const auto& req = ps["required"];
      bool has_target_id = false;
      bool has_tid = false;
      for (const auto& r : req) {
        if (r == "target_id") has_target_id = true;
        if (r == "tid")       has_tid = true;
      }
      CHECK(has_target_id);
      CHECK(has_tid);
      // Summary must surface the v0.3-sync caveat so agents see it
      // without round-tripping into docs/11-non-stop.md.
      const auto summary = e.value("summary", std::string{});
      CHECK(summary.find("v0.3") != std::string::npos);
    }
    if (m == "process.continue") {
      const auto& ps = e["params_schema"];
      // tid must be advertised as a property; only target_id required.
      REQUIRE(ps.contains("properties"));
      const auto& props = ps["properties"];
      if (props.contains("tid")) found_process_continue_with_tid = true;
    }
  }
  CHECK(found_thread_continue);
  CHECK(found_process_continue_with_tid);
}
