// SPDX-License-Identifier: Apache-2.0
// Tests for DebuggerBackend::find_strings.
//
// The structs fixture contains exactly two strings in __TEXT/__cstring
// (Mach-O) / .rodata (ELF):
//
//   "btp_schema.xml"  (14 chars, 15 bytes incl NUL)
//   "DXP/1.0"         ( 7 chars,  8 bytes incl NUL)
//
// These tests assert that find_strings discovers both with reasonable
// defaults, that min_length filters work, that section_name narrows the
// scan, and that defaults limit results to the main executable (not the
// transitively-loaded dyld / libSystem on macOS).

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"

#include <algorithm>
#include <memory>
#include <string>

using ldb::backend::LldbBackend;
using ldb::backend::StringMatch;
using ldb::backend::StringQuery;
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

bool any_text(const std::vector<StringMatch>& v, const std::string& text) {
  return std::any_of(v.begin(), v.end(),
                     [&](const StringMatch& s) { return s.text == text; });
}

const StringMatch* find_text(const std::vector<StringMatch>& v,
                             const std::string& text) {
  for (const auto& s : v) if (s.text == text) return &s;
  return nullptr;
}

}  // namespace

TEST_CASE("string.list: default scan finds fixture rodata strings",
          "[backend][string_list]") {
  auto fx = open_fixture();
  StringQuery q;  // defaults
  auto strings = fx.backend->find_strings(fx.target_id, q);

  REQUIRE_FALSE(strings.empty());
  CHECK(any_text(strings, "btp_schema.xml"));
  CHECK(any_text(strings, "DXP/1.0"));
}

TEST_CASE("string.list: every match carries an address, section, and module",
          "[backend][string_list]") {
  auto fx = open_fixture();
  StringQuery q;
  auto strings = fx.backend->find_strings(fx.target_id, q);

  const auto* schema = find_text(strings, "btp_schema.xml");
  REQUIRE(schema);
  CHECK(schema->address != 0);
  CHECK_FALSE(schema->section.empty());
  CHECK_FALSE(schema->module_path.empty());
}

TEST_CASE("string.list: min_length excludes shorter strings",
          "[backend][string_list]") {
  auto fx = open_fixture();
  StringQuery q;
  q.min_length = 10;  // excludes "DXP/1.0" (7) but not "btp_schema.xml" (14)
  auto strings = fx.backend->find_strings(fx.target_id, q);

  CHECK(any_text(strings, "btp_schema.xml"));
  CHECK_FALSE(any_text(strings, "DXP/1.0"));
}

TEST_CASE("string.list: very high min_length yields no fixture strings",
          "[backend][string_list]") {
  auto fx = open_fixture();
  StringQuery q;
  q.min_length = 100;
  auto strings = fx.backend->find_strings(fx.target_id, q);
  // Both fixture strings are < 100 chars; whatever else may have been
  // picked up incidentally, our two known ones must be absent.
  CHECK_FALSE(any_text(strings, "btp_schema.xml"));
  CHECK_FALSE(any_text(strings, "DXP/1.0"));
}

TEST_CASE("string.list: section filter restricts the scan",
          "[backend][string_list]") {
  auto fx = open_fixture();
  StringQuery q;
  // Mach-O cstring section name. ELF would be ".rodata".
  // We accept either by trying both.
  q.section_name = "__TEXT/__cstring";
  auto a = fx.backend->find_strings(fx.target_id, q);
  if (a.empty()) {
    q.section_name = ".rodata";
    a = fx.backend->find_strings(fx.target_id, q);
  }
  CHECK(any_text(a, "btp_schema.xml"));
  CHECK(any_text(a, "DXP/1.0"));
}

TEST_CASE("string.list: nonexistent section yields empty",
          "[backend][string_list]") {
  auto fx = open_fixture();
  StringQuery q;
  q.section_name = "__NOPE__/__nope__";
  auto a = fx.backend->find_strings(fx.target_id, q);
  CHECK(a.empty());
}

TEST_CASE("string.list: default scope is the main executable, not all modules",
          "[backend][string_list]") {
  // Sanity check on scope: scanning every loaded module would return
  // tens of thousands of strings (libSystem, dyld, libc++abi, ...).
  // The default must be the single main executable. We don't assert an
  // exact count — that varies with compiler/ABI — but it must be small
  // (well under 1000) for our tiny 50KB fixture.
  auto fx = open_fixture();
  StringQuery q;
  auto strings = fx.backend->find_strings(fx.target_id, q);
  CHECK(strings.size() < 200);
}

TEST_CASE("string.list: invalid target_id throws backend::Error",
          "[backend][string_list][error]") {
  auto fx = open_fixture();
  StringQuery q;
  CHECK_THROWS_AS(
      fx.backend->find_strings(/*tid=*/9999, q),
      ldb::backend::Error);
}
