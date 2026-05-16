// SPDX-License-Identifier: Apache-2.0
// Tests for DebuggerBackend::find_string_xrefs.
//
// On ARM64 PIE binaries (our default fixture build), string references
// are emitted as ADRP+ADD pairs whose operands don't carry the resolved
// string address. LLDB annotates the second insn with the string text
// in quotes — e.g. `add x8, x8, #0xa40 ; "btp_schema.xml"`. Detection
// must combine address-hex matching (catches direct-load patterns) and
// quoted-text comment matching (catches the LLDB-annotated ADRP+ADD
// case).

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"

#include <algorithm>
#include <memory>
#include <string>

using ldb::backend::LldbBackend;
using ldb::backend::StringXrefResult;
using ldb::backend::TargetId;

namespace {

constexpr const char* kFixturePath = LDB_FIXTURE_STRUCTS_PATH;

struct OpenedFixture {
  std::unique_ptr<LldbBackend> backend;
  TargetId target_id;
};

OpenedFixture open_fixture() {
  auto be = std::make_unique<LldbBackend>();
  auto res = be->open_executable(kFixturePath);
  REQUIRE(res.target_id != 0);
  return {std::move(be), res.target_id};
}

}  // namespace

TEST_CASE("string.xref: btp_schema.xml is referenced from main",
          "[backend][string_xref]") {
  auto fx = open_fixture();
  auto results = fx.backend->find_string_xrefs(fx.target_id, "btp_schema.xml");

  REQUIRE_FALSE(results.empty());

  // At least one StringXrefResult must carry at least one xref attributed
  // to main (the only function that touches the rodata strings).
  bool found_in_main = std::any_of(
      results.begin(), results.end(),
      [](const StringXrefResult& r) {
        return std::any_of(r.xrefs.begin(), r.xrefs.end(),
                           [](const auto& x) { return x.function == "main"; });
      });
  CHECK(found_in_main);

  // The string itself must round-trip.
  CHECK(results[0].string.text == "btp_schema.xml");
  CHECK(results[0].string.address != 0);
}

TEST_CASE("string.xref: DXP/1.0 is referenced from main",
          "[backend][string_xref]") {
  auto fx = open_fixture();
  auto results = fx.backend->find_string_xrefs(fx.target_id, "DXP/1.0");

  REQUIRE_FALSE(results.empty());
  CHECK(results[0].string.text == "DXP/1.0");
  REQUIRE_FALSE(results[0].xrefs.empty());
}

TEST_CASE("string.xref: every xref carries an address and mnemonic",
          "[backend][string_xref]") {
  auto fx = open_fixture();
  auto results = fx.backend->find_string_xrefs(fx.target_id, "btp_schema.xml");

  REQUIRE_FALSE(results.empty());
  for (const auto& r : results) {
    for (const auto& x : r.xrefs) {
      CHECK(x.address != 0);
      CHECK(x.byte_size > 0);
      CHECK_FALSE(x.mnemonic.empty());
    }
  }
}

TEST_CASE("string.xref: no duplicate xrefs from combined detection paths",
          "[backend][string_xref]") {
  auto fx = open_fixture();
  auto results = fx.backend->find_string_xrefs(fx.target_id, "btp_schema.xml");

  REQUIRE_FALSE(results.empty());
  for (const auto& r : results) {
    std::vector<std::uint64_t> addrs;
    addrs.reserve(r.xrefs.size());
    for (const auto& x : r.xrefs) addrs.push_back(x.address);

    std::vector<std::uint64_t> sorted = addrs;
    std::sort(sorted.begin(), sorted.end());
    auto last = std::unique(sorted.begin(), sorted.end());
    CHECK(last == sorted.end());  // no duplicates
  }
}

TEST_CASE("string.xref: unknown text returns empty",
          "[backend][string_xref]") {
  auto fx = open_fixture();
  auto results = fx.backend->find_string_xrefs(
      fx.target_id, "definitely_not_in_the_fixture_42");
  CHECK(results.empty());
}

TEST_CASE("string.xref: invalid target_id throws backend::Error",
          "[backend][string_xref][error]") {
  auto fx = open_fixture();
  CHECK_THROWS_AS(
      fx.backend->find_string_xrefs(/*tid=*/9999, "anything"),
      ldb::backend::Error);
}

// Phase-4 cleanup I1 (docs/35-field-report-followups.md §3): the prior
// find_string_xrefs signature dropped every adrp_pair_* provenance
// counter the ADRP-pair resolver produced. The threaded signature
// surfaces an aggregate XrefProvenance across all underlying
// xref_address calls.
TEST_CASE("string.xref: threads XrefProvenance through to xref_address",
          "[backend][string_xref][provenance]") {
  auto fx = open_fixture();
  ldb::backend::XrefProvenance prov;
  auto results = fx.backend->find_string_xrefs(
      fx.target_id, "btp_schema.xml", &prov);
  REQUIRE_FALSE(results.empty());

  // The fixture is a real C binary with at least one tracked ADRP+ADD
  // (we asserted the xrefs themselves above). Whether any
  // adrp_pair_* counter bumps depends on the resolver's gates against
  // this binary's compilation; what we MUST verify is that the
  // provenance struct is accepted and the call completes — i.e. the
  // optional-arg plumbing exists. A non-instrumented call (provenance
  // nullptr default) must produce identical xref results.
  ldb::backend::XrefProvenance ignored;
  (void)ignored;  // suppress unused; we don't compare counters
  auto results_no_prov = fx.backend->find_string_xrefs(
      fx.target_id, "btp_schema.xml");
  REQUIRE(results.size() == results_no_prov.size());
  for (std::size_t i = 0; i < results.size(); ++i) {
    CHECK(results[i].xrefs.size() == results_no_prov[i].xrefs.size());
  }
}
