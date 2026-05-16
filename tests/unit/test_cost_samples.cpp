// SPDX-License-Identifier: Apache-2.0
// Unit tests for the dispatcher's in-process cost-sample recorder
// (post-V1 plan #4: measured cost preview).
//
// The dispatcher accumulates a bounded ring (last N=100) of
// _cost.tokens_est observations per endpoint, and exposes a p50
// query that describe.endpoints uses to surface measured costs
// alongside the static cost_hint.
//
// We exercise the recorder via the public Dispatcher seam used by
// describe.endpoints: dispatch a sequence of mixed-success calls,
// then issue describe.endpoints and inspect each entry's
// cost_n_samples and cost_p50_tokens fields.

#include <catch_amalgamated.hpp>

#include "backend/debugger_backend.h"
#include "daemon/dispatcher.h"
#include "protocol/jsonrpc.h"

#include <memory>
#include <optional>
#include <string>

using ldb::backend::DebuggerBackend;
using ldb::daemon::Dispatcher;
using ldb::protocol::Request;
using ldb::protocol::Response;
using ldb::protocol::json;

namespace {

// Minimal stub: hello + describe.endpoints work; everything else
// throws backend::Error. The cost-sample test only needs enough
// surface to fire many calls and inspect the schema.
class HelloStub : public DebuggerBackend {
 public:
  using TID = ldb::backend::TargetId;
  using ThrID = ldb::backend::ThreadId;
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
  ldb::backend::ProcessStatus launch_process(TID, const ldb::backend::LaunchOptions&) override { return {}; }
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
      reverse_step_thread(TID, ThrID, ldb::backend::ReverseStepKind) override { return {}; }
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
  std::vector<ldb::backend::TargetInfo> list_targets() override { return {}; }
  void label_target(TID, std::string) override {}
  std::optional<std::string> get_target_label(TID) override { return std::nullopt; }
  std::string snapshot_for_target(TID) override { return "none"; }
  void attach_target_resource(TID,
      std::unique_ptr<DebuggerBackend::TargetResource>) override {}
};

Request make_req(const std::string& method, const std::string& id = "1") {
  Request r;
  r.id = id;
  r.method = method;
  r.params = json::object();
  return r;
}

// Build a describe.endpoints request with view.include_cost_stats=true.
// The cost-sample fields are opt-in so the default-shape responses
// stay byte-deterministic for session.diff / provenance audits.
Request describe_with_cost_stats() {
  Request r;
  r.id = "desc";
  r.method = "describe.endpoints";
  r.params = json{{"view", json{{"include_cost_stats", true}}}};
  return r;
}

// Find the describe entry for `method` and return its data block.
json find_endpoint(const json& endpoints, const std::string& method) {
  for (const auto& e : endpoints) {
    if (e.value("method", std::string{}) == method) return e;
  }
  return json::object();
}

}  // namespace

TEST_CASE("cost samples: hello records p50 across repeated calls",
          "[dispatcher][cost][p50]") {
  auto be = std::make_shared<HelloStub>();
  Dispatcher d(be);

  for (int i = 0; i < 5; ++i) {
    auto r = d.dispatch(make_req("hello"));
    REQUIRE(r.ok);
  }

  auto desc = d.dispatch(describe_with_cost_stats());
  REQUIRE(desc.ok);
  REQUIRE(desc.data.contains("endpoints"));

  auto hello_entry = find_endpoint(desc.data["endpoints"], "hello");
  REQUIRE(!hello_entry.empty());
  REQUIRE(hello_entry.contains("cost_n_samples"));
  CHECK(hello_entry["cost_n_samples"].get<std::int64_t>() == 5);

  REQUIRE(hello_entry.contains("cost_p50_tokens"));
  // The hello response is small and stable. We don't pin the exact
  // p50 number here (CI vs local can differ if the daemon version
  // string sizes shift) but it must be a positive integer.
  CHECK(hello_entry["cost_p50_tokens"].get<std::uint64_t>() > 0);
}

TEST_CASE("cost samples: endpoints with no calls report zero samples",
          "[dispatcher][cost][p50]") {
  auto be = std::make_shared<HelloStub>();
  Dispatcher d(be);

  auto desc = d.dispatch(describe_with_cost_stats());
  REQUIRE(desc.ok);

  // module.list was never called — count should be zero, p50 absent.
  auto entry = find_endpoint(desc.data["endpoints"], "module.list");
  REQUIRE(!entry.empty());
  REQUIRE(entry.contains("cost_n_samples"));
  CHECK(entry["cost_n_samples"].get<std::int64_t>() == 0);
  // p50 must be absent when n_samples == 0 (a "0" value would be
  // ambiguous — agents can't tell "cheap" from "uncalled" otherwise).
  CHECK_FALSE(entry.contains("cost_p50_tokens"));
}

TEST_CASE("cost samples: cost_hint string still present (backward compat)",
          "[dispatcher][cost][p50]") {
  // The static cost_hint (low / medium / high) is part of the v1.0
  // schema. Adding measured p50 must not displace it.
  auto be = std::make_shared<HelloStub>();
  Dispatcher d(be);
  auto desc = d.dispatch(describe_with_cost_stats());
  REQUIRE(desc.ok);

  bool found_at_least_one = false;
  for (const auto& e : desc.data["endpoints"]) {
    if (e.contains("cost_hint")) found_at_least_one = true;
  }
  CHECK(found_at_least_one);
}

TEST_CASE("cost samples: bounded ring eviction (recent-N policy)",
          "[dispatcher][cost][p50]") {
  // Drive >100 calls through hello so the ring rolls over. The total
  // count should reflect EVERY call (not capped at the ring size), so
  // agents see "this endpoint has been hit many times" while p50 only
  // reflects the most recent 100 (window can shift if the workload
  // shifts).
  auto be = std::make_shared<HelloStub>();
  Dispatcher d(be);

  for (int i = 0; i < 150; ++i) {
    auto r = d.dispatch(make_req("hello"));
    REQUIRE(r.ok);
  }

  auto desc = d.dispatch(describe_with_cost_stats());
  REQUIRE(desc.ok);
  auto entry = find_endpoint(desc.data["endpoints"], "hello");
  REQUIRE(entry.contains("cost_n_samples"));
  // n_samples is the true total — every call counts.
  CHECK(entry["cost_n_samples"].get<std::int64_t>() == 150);
  REQUIRE(entry.contains("cost_p50_tokens"));
  CHECK(entry["cost_p50_tokens"].get<std::uint64_t>() > 0);
}
