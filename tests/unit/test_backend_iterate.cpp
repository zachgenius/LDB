// SPDX-License-Identifier: Apache-2.0
// Unit tests for the bulk module-iteration APIs added to DebuggerBackend
// for post-V1 plan #18 (own symbol index, docs/23-symbol-index.md).
//
// The bulk APIs (iterate_symbols / iterate_types / iterate_strings)
// enumerate everything in a module by build_id, so the dispatcher can
// populate the SymbolIndex once and serve subsequent correlate.* calls
// from sqlite. The contract pinned here:
//
//   • iterate_symbols returns non-empty for a real fixture with at
//     least `main` somewhere in the function list.
//   • iterate_types includes `dxp_login_frame` (an exact-name type
//     defined in structs.c with DWARF in -O0 -g build).
//   • iterate_strings includes one of the rodata string literals that
//     find_strings would surface for the default-scope query
//     (e.g. "DXP/1.0").
//
// Why this is "lossless w.r.t. find_*": the dispatcher's correlate.*
// callers ask find_type_layout(name="dxp_login_frame") /
// find_symbols(name="main") / find_string_xrefs(text="DXP/1.0"). If the
// bulk iteration sees those records, the SymbolIndex's query_* against
// the same build_id returns them too. Cases the bulk path can't carry
// losslessly (e.g. arg-stripped C++ name fallback in find_symbols pass
// 2) are documented in the dispatcher's index-route comment and fall
// through to the backend.

#include <catch_amalgamated.hpp>

#include "backend/lldb_backend.h"

#include <algorithm>
#include <memory>
#include <string>

using ldb::backend::LldbBackend;
using ldb::backend::TargetId;

namespace {

constexpr const char* kStructsPath = LDB_FIXTURE_STRUCTS_PATH;

// Resolve the structs fixture's build_id (= LLDB's UUID on ELF) by
// walking list_modules and picking the executable. The fixture is
// built with -Wl,--build-id so this is always populated on Linux.
std::string fixture_build_id(LldbBackend& be, TargetId tid) {
  auto mods = be.list_modules(tid);
  for (const auto& m : mods) {
    // The main executable's path matches kStructsPath; otherwise the
    // first module is libc / interpreter etc.
    if (m.path == kStructsPath) return m.uuid;
  }
  // Fallback: first module's uuid. On stripped binaries this may be
  // empty; the test then SKIPs at the REQUIRE below.
  return mods.empty() ? std::string{} : mods.front().uuid;
}

}  // namespace

TEST_CASE("iterate_symbols enumerates main in the structs fixture",
          "[backend][iterate][symbols]") {
  auto be = std::make_shared<LldbBackend>();
  auto r = be->open_executable(kStructsPath);
  REQUIRE(r.target_id != 0);

  std::string bid = fixture_build_id(*be, r.target_id);
  if (bid.empty()) {
    SKIP("fixture has no build_id (stripped binary?)");
  }

  auto ms = be->iterate_symbols(r.target_id, bid);
  // main is a function — must appear in the functions bucket.
  bool found_main = false;
  for (const auto& s : ms.functions) {
    if (s.name == "main") { found_main = true; break; }
  }
  CHECK(found_main);
  // The structs fixture also defines g_origin / g_login_template /
  // g_arr / k_schema_name as data symbols. We don't pin which bucket
  // each lands in (LLDB's classification of "const char* const" is
  // version-y) but the total data+other count should be non-zero.
  CHECK((ms.data.size() + ms.other.size()) > 0);
}

TEST_CASE("iterate_types enumerates dxp_login_frame in the structs fixture",
          "[backend][iterate][types]") {
  auto be = std::make_shared<LldbBackend>();
  auto r = be->open_executable(kStructsPath);
  REQUIRE(r.target_id != 0);

  std::string bid = fixture_build_id(*be, r.target_id);
  if (bid.empty()) {
    SKIP("fixture has no build_id (stripped binary?)");
  }

  auto mt = be->iterate_types(r.target_id, bid);
  REQUIRE_FALSE(mt.types.empty());

  // dxp_login_frame is a struct defined in structs.c with DWARF.
  bool found = false;
  for (const auto& t : mt.types) {
    if (t.name == "dxp_login_frame" || t.name == "struct dxp_login_frame") {
      found = true;
      CHECK(t.byte_size == 16);
      break;
    }
  }
  CHECK(found);
}

TEST_CASE("iterate_strings enumerates a known rodata literal in structs",
          "[backend][iterate][strings]") {
  auto be = std::make_shared<LldbBackend>();
  auto r = be->open_executable(kStructsPath);
  REQUIRE(r.target_id != 0);

  std::string bid = fixture_build_id(*be, r.target_id);
  if (bid.empty()) {
    SKIP("fixture has no build_id (stripped binary?)");
  }

  auto mstr = be->iterate_strings(r.target_id, bid);
  // structs.c places "DXP/1.0" and "btp_schema.xml" in rodata; either
  // hits this list (default-scope find_strings on main executable).
  bool found_dxp = false;
  for (const auto& s : mstr.strings) {
    if (s.text == "DXP/1.0" || s.text == "btp_schema.xml") {
      found_dxp = true;
      break;
    }
  }
  CHECK(found_dxp);
}
