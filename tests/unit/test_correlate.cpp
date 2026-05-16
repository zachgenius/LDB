// SPDX-License-Identifier: Apache-2.0
// Dispatcher integration tests for cross-binary correlation
// (Tier 3 §10, post-v0.1 scoped slice).
//
// Three composition endpoints over existing primitives:
//
//   correlate.types({target_ids: [N+], name})
//     → {results: [{target_id, layout?, status}], drift, drift_reason?}
//
//   correlate.symbols({target_ids: [N+], name})
//     → {results: [{target_id, matches: [...]}], total}
//
//   correlate.strings({target_ids: [N+], text})
//     → {results: [{target_id, callsites: [...]}], total}
//
// Pinned policies (see docs/WORKLOG.md):
//   • Empty target_ids → -32602.
//   • Unknown target_id in the list → -32602 with the offending id in
//     the message (no silent skip).
//   • Duplicate target_ids → silently deduped (caller's mistake).
//   • drift=false when fewer than 2 targets have the type (nothing to
//     compare across).
//   • drift_reason priority (first difference wins, deterministic):
//     byte_size > alignment > fields_count > field_offsets > field_types.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"
#include "daemon/dispatcher.h"
#include "protocol/jsonrpc.h"

#include <map>
#include <memory>
#include <string>
#include <vector>

using ldb::backend::LldbBackend;
using ldb::daemon::Dispatcher;
using ldb::protocol::Request;
using nlohmann::json;

namespace {

constexpr const char* kStructsPath = LDB_FIXTURE_STRUCTS_PATH;
constexpr const char* kSleeperPath = LDB_FIXTURE_SLEEPER_PATH;

Request make_req(const char* method, json params = json::object(),
                 const char* id = "rX") {
  Request r;
  r.id = id;
  r.method = method;
  r.params = std::move(params);
  return r;
}

}  // namespace

// --- correlate.types -------------------------------------------------------

TEST_CASE("correlate.types: same struct in both targets → drift=false",
          "[correlate][types]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher d(be);

  // Open the same fixture twice — the layouts are bit-identical, so
  // any non-spurious drift report would be a bug.
  auto a = d.dispatch(make_req("target.open", json{{"path", kStructsPath}}));
  REQUIRE(a.ok);
  auto b = d.dispatch(make_req("target.open", json{{"path", kStructsPath}}));
  REQUIRE(b.ok);
  auto tid_a = a.data["target_id"].get<std::uint64_t>();
  auto tid_b = b.data["target_id"].get<std::uint64_t>();

  auto resp = d.dispatch(make_req("correlate.types",
      json{{"target_ids", json::array({tid_a, tid_b})},
           {"name", "point2"}}));
  REQUIRE(resp.ok);
  REQUIRE(resp.data.contains("results"));
  REQUIRE(resp.data.contains("drift"));
  REQUIRE(resp.data["results"].is_array());
  REQUIRE(resp.data["results"].size() == 2);

  // Both should be "found" with a layout.
  for (const auto& r : resp.data["results"]) {
    REQUIRE(r.contains("status"));
    CHECK(r["status"].get<std::string>() == "found");
    REQUIRE(r.contains("layout"));
    CHECK_FALSE(r["layout"].is_null());
    CHECK(r["layout"].contains("byte_size"));
    CHECK(r["layout"].contains("alignment"));
    CHECK(r["layout"].contains("fields"));
  }
  CHECK(resp.data["drift"].get<bool>() == false);
}

TEST_CASE("correlate.types: missing in one target → drift=false (single found)",
          "[correlate][types][missing]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher d(be);

  auto a = d.dispatch(make_req("target.open", json{{"path", kStructsPath}}));
  REQUIRE(a.ok);
  auto b = d.dispatch(make_req("target.open", json{{"path", kSleeperPath}}));
  REQUIRE(b.ok);
  auto tid_a = a.data["target_id"].get<std::uint64_t>();
  auto tid_b = b.data["target_id"].get<std::uint64_t>();

  // point2 is a structs.c-only type; sleeper has no such DWARF.
  auto resp = d.dispatch(make_req("correlate.types",
      json{{"target_ids", json::array({tid_a, tid_b})},
           {"name", "point2"}}));
  REQUIRE(resp.ok);
  REQUIRE(resp.data["results"].size() == 2);

  // Find each by target_id.
  json found_for_a, found_for_b;
  for (const auto& r : resp.data["results"]) {
    auto tid = r["target_id"].get<std::uint64_t>();
    if (tid == tid_a) found_for_a = r;
    else if (tid == tid_b) found_for_b = r;
  }
  REQUIRE_FALSE(found_for_a.is_null());
  REQUIRE_FALSE(found_for_b.is_null());

  CHECK(found_for_a["status"].get<std::string>() == "found");
  CHECK(found_for_b["status"].get<std::string>() == "missing");
  // layout key present but null on missing; absent or null is acceptable.
  if (found_for_b.contains("layout")) {
    CHECK(found_for_b["layout"].is_null());
  }

  // Only one target found the type — nothing to compare across, so no drift.
  CHECK(resp.data["drift"].get<bool>() == false);
  // No drift_reason emitted when drift=false.
  CHECK_FALSE(resp.data.contains("drift_reason"));
}

TEST_CASE("correlate.types: unknown target_id → -32602 with offender id",
          "[correlate][types][error]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher d(be);

  auto a = d.dispatch(make_req("target.open", json{{"path", kStructsPath}}));
  REQUIRE(a.ok);
  auto tid_a = a.data["target_id"].get<std::uint64_t>();

  auto resp = d.dispatch(make_req("correlate.types",
      json{{"target_ids", json::array({tid_a, 9999})},
           {"name", "point2"}}));
  CHECK_FALSE(resp.ok);
  CHECK(static_cast<int>(resp.error_code) == -32602);
  // Message names the offending id so the agent can surface which one.
  CHECK(resp.error_message.find("9999") != std::string::npos);
}

TEST_CASE("correlate.types: empty target_ids → -32602",
          "[correlate][types][error]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher d(be);

  auto resp = d.dispatch(make_req("correlate.types",
      json{{"target_ids", json::array()},
           {"name", "point2"}}));
  CHECK_FALSE(resp.ok);
  CHECK(static_cast<int>(resp.error_code) == -32602);
}

TEST_CASE("correlate.types: missing 'name' → -32602",
          "[correlate][types][error]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher d(be);

  auto a = d.dispatch(make_req("target.open", json{{"path", kStructsPath}}));
  REQUIRE(a.ok);
  auto tid_a = a.data["target_id"].get<std::uint64_t>();

  auto resp = d.dispatch(make_req("correlate.types",
      json{{"target_ids", json::array({tid_a})}}));
  CHECK_FALSE(resp.ok);
  CHECK(static_cast<int>(resp.error_code) == -32602);
}

TEST_CASE("correlate.types: duplicate target_ids are silently deduped",
          "[correlate][types]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher d(be);

  auto a = d.dispatch(make_req("target.open", json{{"path", kStructsPath}}));
  REQUIRE(a.ok);
  auto tid_a = a.data["target_id"].get<std::uint64_t>();

  // [tid_a, tid_a, tid_a] should produce ONE result (deduped).
  auto resp = d.dispatch(make_req("correlate.types",
      json{{"target_ids", json::array({tid_a, tid_a, tid_a})},
           {"name", "point2"}}));
  REQUIRE(resp.ok);
  REQUIRE(resp.data["results"].size() == 1);
  CHECK(resp.data["drift"].get<bool>() == false);
}

// --- correlate.symbols -----------------------------------------------------

TEST_CASE("correlate.symbols: round-trip across two targets",
          "[correlate][symbols]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher d(be);

  auto a = d.dispatch(make_req("target.open", json{{"path", kStructsPath}}));
  REQUIRE(a.ok);
  auto b = d.dispatch(make_req("target.open", json{{"path", kSleeperPath}}));
  REQUIRE(b.ok);
  auto tid_a = a.data["target_id"].get<std::uint64_t>();
  auto tid_b = b.data["target_id"].get<std::uint64_t>();

  auto resp = d.dispatch(make_req("correlate.symbols",
      json{{"target_ids", json::array({tid_a, tid_b})},
           {"name", "main"}}));
  REQUIRE(resp.ok);
  REQUIRE(resp.data.contains("results"));
  REQUIRE(resp.data.contains("total"));
  REQUIRE(resp.data["results"].size() == 2);

  // Both fixtures define main; each should report >= 1 match.
  std::int64_t total_seen = 0;
  for (const auto& r : resp.data["results"]) {
    REQUIRE(r.contains("target_id"));
    REQUIRE(r.contains("matches"));
    REQUIRE(r["matches"].is_array());
    CHECK_FALSE(r["matches"].empty());
    total_seen += static_cast<std::int64_t>(r["matches"].size());
    // Each match keeps the symbol_match shape (name, kind, addr).
    for (const auto& m : r["matches"]) {
      CHECK(m.contains("name"));
      CHECK(m.contains("addr"));
      CHECK(m.contains("kind"));
    }
  }
  // total counts every match across results.
  CHECK(resp.data["total"].get<std::int64_t>() == total_seen);
}

TEST_CASE("correlate.symbols: unknown target_id → -32602",
          "[correlate][symbols][error]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher d(be);

  auto a = d.dispatch(make_req("target.open", json{{"path", kStructsPath}}));
  REQUIRE(a.ok);
  auto tid_a = a.data["target_id"].get<std::uint64_t>();

  auto resp = d.dispatch(make_req("correlate.symbols",
      json{{"target_ids", json::array({tid_a, 12345})},
           {"name", "main"}}));
  CHECK_FALSE(resp.ok);
  CHECK(static_cast<int>(resp.error_code) == -32602);
  CHECK(resp.error_message.find("12345") != std::string::npos);
}

TEST_CASE("correlate.symbols: empty target_ids → -32602",
          "[correlate][symbols][error]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher d(be);

  auto resp = d.dispatch(make_req("correlate.symbols",
      json{{"target_ids", json::array()}, {"name", "main"}}));
  CHECK_FALSE(resp.ok);
  CHECK(static_cast<int>(resp.error_code) == -32602);
}

// --- correlate.strings -----------------------------------------------------

TEST_CASE("correlate.strings: present in one target, absent in the other",
          "[correlate][strings]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher d(be);

  auto a = d.dispatch(make_req("target.open", json{{"path", kStructsPath}}));
  REQUIRE(a.ok);
  auto b = d.dispatch(make_req("target.open", json{{"path", kSleeperPath}}));
  REQUIRE(b.ok);
  auto tid_a = a.data["target_id"].get<std::uint64_t>();
  auto tid_b = b.data["target_id"].get<std::uint64_t>();

  // sleeper has LDB_SLEEPER_MARKER_v1; structs does not.
  auto resp = d.dispatch(make_req("correlate.strings",
      json{{"target_ids", json::array({tid_a, tid_b})},
           {"text", "LDB_SLEEPER_MARKER_v1"}}));
  REQUIRE(resp.ok);
  REQUIRE(resp.data.contains("results"));
  REQUIRE(resp.data.contains("total"));
  REQUIRE(resp.data["results"].size() == 2);

  json result_for_a, result_for_b;
  for (const auto& r : resp.data["results"]) {
    auto tid = r["target_id"].get<std::uint64_t>();
    if (tid == tid_a) result_for_a = r;
    else if (tid == tid_b) result_for_b = r;
  }
  REQUIRE_FALSE(result_for_a.is_null());
  REQUIRE_FALSE(result_for_b.is_null());

  // structs has no such string → empty callsites array.
  REQUIRE(result_for_a.contains("callsites"));
  CHECK(result_for_a["callsites"].is_array());
  CHECK(result_for_a["callsites"].empty());
  // sleeper has the string; whether there are xrefs depends on codegen,
  // but the field must exist as an array.
  REQUIRE(result_for_b.contains("callsites"));
  CHECK(result_for_b["callsites"].is_array());
}

TEST_CASE("correlate.strings: unknown target_id → -32602",
          "[correlate][strings][error]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher d(be);

  auto a = d.dispatch(make_req("target.open", json{{"path", kStructsPath}}));
  REQUIRE(a.ok);
  auto tid_a = a.data["target_id"].get<std::uint64_t>();

  auto resp = d.dispatch(make_req("correlate.strings",
      json{{"target_ids", json::array({tid_a, 7777})},
           {"text", "DXP/1.0"}}));
  CHECK_FALSE(resp.ok);
  CHECK(static_cast<int>(resp.error_code) == -32602);
  CHECK(resp.error_message.find("7777") != std::string::npos);
}

TEST_CASE("correlate.strings: empty target_ids → -32602",
          "[correlate][strings][error]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher d(be);

  auto resp = d.dispatch(make_req("correlate.strings",
      json{{"target_ids", json::array()}, {"text", "x"}}));
  CHECK_FALSE(resp.ok);
  CHECK(static_cast<int>(resp.error_code) == -32602);
}

// --- describe.endpoints registration --------------------------------------

TEST_CASE("describe.endpoints lists correlate.* endpoints",
          "[correlate][describe]") {
  auto be = std::make_shared<LldbBackend>();
  Dispatcher d(be);
  auto resp = d.dispatch(make_req("describe.endpoints"));
  REQUIRE(resp.ok);

  bool seen_types = false, seen_symbols = false, seen_strings = false;
  for (const auto& e : resp.data["endpoints"]) {
    auto m = e.value("method", "");
    if (m == "correlate.types")   seen_types = true;
    if (m == "correlate.symbols") seen_symbols = true;
    if (m == "correlate.strings") seen_strings = true;
  }
  CHECK(seen_types);
  CHECK(seen_symbols);
  CHECK(seen_strings);
}

// --- drift_reason — specific failure modes via fakes ----------------------
//
// These three pin the drift_reason priority order using a stub backend
// that returns hand-rolled TypeLayouts. We can't easily provoke
// byte_size / alignment / field-offsets / field-types drift between two
// real ELF fixtures without committing custom DWARF, and the priority
// ordering is the contract worth pinning.

namespace {

class StubBackend : public ldb::backend::DebuggerBackend {
 public:
  using TID = ldb::backend::TargetId;
  using ThreadID = ldb::backend::ThreadId;

  std::map<TID, std::optional<ldb::backend::TypeLayout>> layouts;

  // Surface the registered ids so the dispatcher's
  // first_unknown_target_id preflight passes.
  std::vector<ldb::backend::TargetInfo> list_targets() override {
    std::vector<ldb::backend::TargetInfo> out;
    for (const auto& kv : layouts) {
      ldb::backend::TargetInfo i;
      i.target_id = kv.first;
      i.triple    = "stub";
      out.push_back(std::move(i));
    }
    return out;
  }

  // The only method the correlate.types path exercises.
  std::optional<ldb::backend::TypeLayout>
      find_type_layout(TID tid, const std::string&) override {
    auto it = layouts.find(tid);
    if (it == layouts.end()) {
      throw ldb::backend::Error("unknown target_id");
    }
    return it->second;
  }

  // Stubs — none of the rest are touched by correlate.types.
  ldb::backend::OpenResult open_executable(const std::string&, const ldb::backend::OpenOptions& = {}) override { return {}; }
  ldb::backend::OpenResult create_empty_target() override { return {}; }
  ldb::backend::OpenResult load_core(const std::string&) override { return {}; }
  std::vector<ldb::backend::Module> list_modules(TID) override { return {}; }
  std::vector<ldb::backend::SymbolMatch>
      find_symbols(TID, const ldb::backend::SymbolQuery&) override { return {}; }
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
      find_string_xrefs(TID, const std::string&) override { return {}; }
  ldb::backend::ProcessStatus
      launch_process(TID, const ldb::backend::LaunchOptions&) override { return {}; }
  ldb::backend::ProcessStatus get_process_state(TID) override { return {}; }
  ldb::backend::ProcessStatus continue_process(TID) override { return {}; }
  ldb::backend::ProcessStatus continue_thread(TID, ThreadID) override { return {}; }
  ldb::backend::ProcessStatus suspend_thread(TID, ThreadID) override { return {}; }
  ldb::backend::ProcessStatus kill_process(TID) override { return {}; }
  ldb::backend::ProcessStatus attach(TID, std::int32_t) override { return {}; }
  ldb::backend::ProcessStatus detach_process(TID) override { return {}; }
  ldb::backend::ProcessStatus
      connect_remote_target(TID, const std::string&, const std::string&) override {
    return {};
  }
  bool save_core(TID, const std::string&) override { return false; }
  std::vector<ldb::backend::ThreadInfo> list_threads(TID) override { return {}; }
  std::vector<ldb::backend::FrameInfo>
      list_frames(TID, ThreadID, std::uint32_t) override { return {}; }
  ldb::backend::ProcessStatus
      step_thread(TID, ThreadID, ldb::backend::StepKind) override { return {}; }
  ldb::backend::ProcessStatus reverse_continue(TID) override { return {}; }
  ldb::backend::ProcessStatus
      reverse_step_thread(TID, ThreadID, ldb::backend::ReverseStepKind) override {
    return {};
  }
  std::vector<ldb::backend::ValueInfo>
      list_locals(TID, ThreadID, std::uint32_t) override { return {}; }
  std::vector<ldb::backend::ValueInfo>
      list_args(TID, ThreadID, std::uint32_t) override { return {}; }
  std::vector<ldb::backend::ValueInfo>
      list_registers(TID, ThreadID, std::uint32_t) override { return {}; }
  ldb::backend::EvalResult
      evaluate_expression(TID, ThreadID, std::uint32_t,
                          const std::string&,
                          const ldb::backend::EvalOptions&) override {
    return {};
  }
  ldb::backend::ReadResult
      read_value_path(TID, ThreadID, std::uint32_t,
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
      read_register(TID, ThreadID, std::uint32_t,
                    const std::string&) override { return 0; }
  void close_target(TID) override {}
  void label_target(TID, std::string) override {}
  std::optional<std::string> get_target_label(TID) override { return std::nullopt; }
  std::string snapshot_for_target(TID) override { return "none"; }
  std::vector<ldb::backend::GlobalVarMatch>
      find_globals_of_type(TID, std::string_view, bool&) override {
    return {};
  }
  void attach_target_resource(TID,
      std::unique_ptr<ldb::backend::DebuggerBackend::TargetResource>) override {}
  ldb::backend::ConnectRemoteSshResult
      connect_remote_target_ssh(TID,
          const ldb::backend::ConnectRemoteSshOptions&) override { return {}; }
};

ldb::backend::TypeLayout make_layout(std::uint64_t byte_size,
                                      std::uint64_t alignment,
                                      std::vector<ldb::backend::Field> fields) {
  ldb::backend::TypeLayout t;
  t.name = "T";
  t.byte_size = byte_size;
  t.alignment = alignment;
  t.fields = std::move(fields);
  return t;
}

ldb::backend::Field
mkfield(std::string name, std::string type_name,
        std::uint64_t off, std::uint64_t sz) {
  ldb::backend::Field f;
  f.name = std::move(name);
  f.type_name = std::move(type_name);
  f.offset = off;
  f.byte_size = sz;
  return f;
}

}  // namespace

TEST_CASE("correlate.types: drift on byte_size",
          "[correlate][types][drift]") {
  auto be = std::make_shared<StubBackend>();
  // Same fields, same alignment, different byte_size.
  std::vector<ldb::backend::Field> fs{mkfield("x", "int", 0, 4)};
  be->layouts[1] = make_layout(/*byte_size=*/4,  /*align=*/4, fs);
  be->layouts[2] = make_layout(/*byte_size=*/8,  /*align=*/4, fs);
  Dispatcher d(be);

  auto resp = d.dispatch(make_req("correlate.types",
      json{{"target_ids", json::array({1, 2})}, {"name", "T"}}));
  REQUIRE(resp.ok);
  CHECK(resp.data["drift"].get<bool>() == true);
  REQUIRE(resp.data.contains("drift_reason"));
  CHECK(resp.data["drift_reason"].get<std::string>() == "byte_size");
}

TEST_CASE("correlate.types: drift on alignment",
          "[correlate][types][drift]") {
  auto be = std::make_shared<StubBackend>();
  std::vector<ldb::backend::Field> fs{mkfield("x", "int", 0, 4)};
  // byte_size matches, alignment differs.
  be->layouts[1] = make_layout(/*byte_size=*/4, /*align=*/4, fs);
  be->layouts[2] = make_layout(/*byte_size=*/4, /*align=*/8, fs);
  Dispatcher d(be);

  auto resp = d.dispatch(make_req("correlate.types",
      json{{"target_ids", json::array({1, 2})}, {"name", "T"}}));
  REQUIRE(resp.ok);
  CHECK(resp.data["drift"].get<bool>() == true);
  CHECK(resp.data["drift_reason"].get<std::string>() == "alignment");
}

TEST_CASE("correlate.types: drift on fields_count",
          "[correlate][types][drift]") {
  auto be = std::make_shared<StubBackend>();
  std::vector<ldb::backend::Field> fs1{mkfield("x", "int", 0, 4)};
  std::vector<ldb::backend::Field> fs2{
      mkfield("x", "int", 0, 4),
      mkfield("y", "int", 4, 4)};
  // byte_size & alignment line up; field counts diverge.
  be->layouts[1] = make_layout(/*byte_size=*/8, /*align=*/4, fs1);
  be->layouts[2] = make_layout(/*byte_size=*/8, /*align=*/4, fs2);
  Dispatcher d(be);

  auto resp = d.dispatch(make_req("correlate.types",
      json{{"target_ids", json::array({1, 2})}, {"name", "T"}}));
  REQUIRE(resp.ok);
  CHECK(resp.data["drift"].get<bool>() == true);
  CHECK(resp.data["drift_reason"].get<std::string>() == "fields_count");
}

TEST_CASE("correlate.types: drift on field_offsets",
          "[correlate][types][drift]") {
  auto be = std::make_shared<StubBackend>();
  std::vector<ldb::backend::Field> fs1{
      mkfield("x", "int", 0, 4), mkfield("y", "int", 4, 4)};
  // Same shape, but y at offset 8 instead of 4.
  std::vector<ldb::backend::Field> fs2{
      mkfield("x", "int", 0, 4), mkfield("y", "int", 8, 4)};
  be->layouts[1] = make_layout(/*byte_size=*/12, /*align=*/4, fs1);
  be->layouts[2] = make_layout(/*byte_size=*/12, /*align=*/4, fs2);
  Dispatcher d(be);

  auto resp = d.dispatch(make_req("correlate.types",
      json{{"target_ids", json::array({1, 2})}, {"name", "T"}}));
  REQUIRE(resp.ok);
  CHECK(resp.data["drift"].get<bool>() == true);
  CHECK(resp.data["drift_reason"].get<std::string>() == "field_offsets");
}

TEST_CASE("correlate.types: drift on field_types",
          "[correlate][types][drift]") {
  auto be = std::make_shared<StubBackend>();
  std::vector<ldb::backend::Field> fs1{mkfield("x", "int",      0, 4)};
  std::vector<ldb::backend::Field> fs2{mkfield("x", "uint32_t", 0, 4)};
  // Same offsets, same size, different DWARF-reported type name.
  be->layouts[1] = make_layout(/*byte_size=*/4, /*align=*/4, fs1);
  be->layouts[2] = make_layout(/*byte_size=*/4, /*align=*/4, fs2);
  Dispatcher d(be);

  auto resp = d.dispatch(make_req("correlate.types",
      json{{"target_ids", json::array({1, 2})}, {"name", "T"}}));
  REQUIRE(resp.ok);
  CHECK(resp.data["drift"].get<bool>() == true);
  CHECK(resp.data["drift_reason"].get<std::string>() == "field_types");
}

TEST_CASE("correlate.types: backend exception → status=backend_error",
          "[correlate][types][error]") {
  // Stub setup: tid=1 known, tid=2 unknown to the stub but the
  // dispatcher's per-target-id pre-validation can't see that. To
  // exercise the backend_error branch we need find_type_layout itself
  // to throw on a target the dispatcher accepted.
  //
  // Solution: subclass the stub to throw selectively.
  class ThrowingStub : public StubBackend {
   public:
    std::optional<ldb::backend::TypeLayout>
        find_type_layout(TID tid, const std::string&) override {
      if (tid == 1) {
        ldb::backend::TypeLayout t;
        t.name = "T"; t.byte_size = 4; t.alignment = 4;
        return t;
      }
      throw ldb::backend::Error("simulated DWARF parse failure");
    }
  };
  auto be = std::make_shared<ThrowingStub>();
  // Register both ids so the dispatcher preflight (list_targets check)
  // accepts them; the throw happens inside find_type_layout.
  be->layouts[1] = std::nullopt;
  be->layouts[2] = std::nullopt;
  Dispatcher d(be);

  auto resp = d.dispatch(make_req("correlate.types",
      json{{"target_ids", json::array({1, 2})}, {"name", "T"}}));
  REQUIRE(resp.ok);
  REQUIRE(resp.data["results"].size() == 2);

  json for_2;
  for (const auto& r : resp.data["results"]) {
    if (r["target_id"].get<std::uint64_t>() == 2) for_2 = r;
  }
  REQUIRE_FALSE(for_2.is_null());
  CHECK(for_2["status"].get<std::string>() == "backend_error");
  CHECK(for_2.contains("error"));
  CHECK(for_2["error"].get<std::string>().find("DWARF") != std::string::npos);
  // One found, one error → only one in the found-set → no drift.
  CHECK(resp.data["drift"].get<bool>() == false);
}
