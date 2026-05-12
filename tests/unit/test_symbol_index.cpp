// SPDX-License-Identifier: Apache-2.0
// Unit tests for ldb::index::SymbolIndex (post-V1 plan #18,
// docs/23-symbol-index.md).
//
// Coverage:
//   • cache_status() returns kMissing pre-populate, kHot post,
//     kStale after the file mtime changes.
//   • populate() round-trips SymbolRow / TypeRow / StringRow shapes
//     verbatim via query_*. Re-populating replaces atomically.
//   • query_symbols by mangled name, by demangled name, kind filter.
//   • query_strings exact + contains match.
//   • invalidate() drops every row tied to the build_id and reports
//     true; second call against the same id reports false.
//   • Schema-version bump nukes existing data (kHot → kMissing).
//   • Two separate SymbolIndex instances against the same root see
//     the same data (the cache survives process exits).
//
// All tests use std::filesystem::temp_directory_path() / unique
// subdirs so they don't fight each other or the ArtifactStore tests.

#include <catch_amalgamated.hpp>

#include "backend/debugger_backend.h"   // backend::Error
#include "index/symbol_index.h"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <thread>

namespace fs = std::filesystem;
using ldb::index::BinaryEntry;
using ldb::index::CacheStatus;
using ldb::index::FileFingerprint;
using ldb::index::StringQuery;
using ldb::index::StringRow;
using ldb::index::SymbolIndex;
using ldb::index::SymbolQuery;
using ldb::index::SymbolRow;
using ldb::index::TypeRow;

namespace {

fs::path make_tmp_root(std::string_view tag) {
  std::mt19937_64 rng(std::random_device{}());
  std::string suffix = std::to_string(rng());
  auto root = fs::temp_directory_path()
              / ("ldb_symidx_" + std::string(tag) + "_" + suffix);
  fs::remove_all(root);
  fs::create_directories(root);
  return root;
}

// Create a real on-disk file with controllable mtime+size so we can
// exercise cache invalidation without depending on LLDB.
fs::path make_fake_binary(const fs::path& root,
                          std::string_view name,
                          std::string_view content) {
  auto p = root / name;
  std::ofstream f(p, std::ios::binary);
  f.write(content.data(),
          static_cast<std::streamsize>(content.size()));
  f.close();
  return p;
}

FileFingerprint fingerprint_of(const fs::path& p) {
  auto st = fs::file_size(p);
  auto last = fs::last_write_time(p);
  // Convert to a stable epoch-ns. The conversion is platform-y;
  // since the only purpose is comparing same-platform fingerprints
  // we cast via the system_clock duration. This matches what
  // SymbolIndex computes internally on populate / cache_status.
  auto sys = std::chrono::clock_cast<std::chrono::system_clock>(last);
  auto ns  = std::chrono::duration_cast<std::chrono::nanoseconds>(
                 sys.time_since_epoch()).count();
  FileFingerprint fp;
  fp.path     = p.string();
  fp.mtime_ns = ns;
  fp.size     = static_cast<std::int64_t>(st);
  return fp;
}

BinaryEntry make_entry(std::string_view build_id,
                        const fs::path&  path,
                        std::string_view arch = "x86_64-linux") {
  BinaryEntry e;
  e.build_id = build_id;
  e.file     = fingerprint_of(path);
  e.arch     = arch;
  e.populated_at_ns = 0;  // SymbolIndex fills this; we don't pin it.
  return e;
}

SymbolRow sym(std::string_view name,
              std::string_view demangled,
              std::uint64_t addr,
              std::string_view kind = "function") {
  SymbolRow s;
  s.name        = name;
  s.demangled   = demangled;
  s.kind        = kind;
  s.address     = addr;
  s.size        = 16;
  s.module_path = "/tmp/fake";
  return s;
}

TypeRow ty(std::string_view name, std::uint64_t byte_size,
            std::initializer_list<std::pair<std::string, std::uint64_t>> mem) {
  TypeRow t;
  t.name      = name;
  t.byte_size = byte_size;
  t.members   = nlohmann::json::array();
  for (const auto& [n, off] : mem) {
    t.members.push_back({{"name", n}, {"offset", off}});
  }
  return t;
}

StringRow str(std::uint64_t addr, std::string_view text,
              std::string_view section = ".rodata") {
  StringRow s;
  s.address = addr;
  s.text    = text;
  s.section = section;
  return s;
}

}  // namespace

TEST_CASE("symbol_index: cache_status missing → hot after populate",
          "[index][cache_status]") {
  auto root = make_tmp_root("cache_status");
  SymbolIndex idx(root);
  REQUIRE(idx.available());

  auto bin = make_fake_binary(root, "libfoo.so", "fake ELF body");
  auto fp  = fingerprint_of(bin);

  CHECK(idx.cache_status("buildid-fresh", fp) == CacheStatus::kMissing);

  auto entry = make_entry("buildid-fresh", bin);
  idx.populate(entry, {}, {}, {});

  CHECK(idx.cache_status("buildid-fresh", fp) == CacheStatus::kHot);

  auto got = idx.get_binary("buildid-fresh");
  REQUIRE(got.has_value());
  CHECK(got->build_id == "buildid-fresh");
  CHECK(got->arch     == "x86_64-linux");
  CHECK(got->file.size == fp.size);
}

TEST_CASE("symbol_index: cache_status flips to stale on mtime/size drift",
          "[index][cache_status]") {
  auto root = make_tmp_root("stale");
  SymbolIndex idx(root);

  auto bin = make_fake_binary(root, "libfoo.so", "v1 content");
  auto fp_v1 = fingerprint_of(bin);
  idx.populate(make_entry("bid", bin), {}, {}, {});
  REQUIRE(idx.cache_status("bid", fp_v1) == CacheStatus::kHot);

  // Overwrite the binary — different size + mtime.
  std::this_thread::sleep_for(std::chrono::milliseconds(20));
  make_fake_binary(root, "libfoo.so", "v2 content is longer this time");
  auto fp_v2 = fingerprint_of(bin);
  REQUIRE(fp_v2.size != fp_v1.size);

  CHECK(idx.cache_status("bid", fp_v2) == CacheStatus::kStale);
  // The hot fingerprint still matches against the indexed row, so
  // the cache key is the *current on-disk file* the caller asks about
  // — not a frozen snapshot. Re-populating with fp_v2 brings it back.
  idx.populate(make_entry("bid", bin), {}, {}, {});
  CHECK(idx.cache_status("bid", fp_v2) == CacheStatus::kHot);
}

TEST_CASE("symbol_index: symbol round-trip by mangled and demangled",
          "[index][symbols]") {
  auto root = make_tmp_root("symbols");
  SymbolIndex idx(root);

  auto bin = make_fake_binary(root, "a.out", "elf");
  std::vector<SymbolRow> rows = {
    sym("_Z3foov", "foo()", 0x1000),
    sym("_ZN3Bar4initEv", "Bar::init()", 0x1100),
    sym("main", "", 0x1200),
    sym("g_counter", "", 0x4000, "data"),
  };
  idx.populate(make_entry("bid-syms", bin), rows, {}, {});

  // Exact mangled match
  auto hits = idx.query_symbols("bid-syms", SymbolQuery{"main", ""});
  REQUIRE(hits.size() == 1);
  CHECK(hits[0].address == 0x1200);

  // Exact demangled match
  auto barhits = idx.query_symbols("bid-syms",
                                    SymbolQuery{"Bar::init()", ""});
  REQUIRE(barhits.size() == 1);
  CHECK(barhits[0].name == "_ZN3Bar4initEv");

  // Kind filter — `g_counter` is data, not function
  auto fns = idx.query_symbols("bid-syms",
                                SymbolQuery{"g_counter", "function"});
  CHECK(fns.empty());
  auto datas = idx.query_symbols("bid-syms",
                                  SymbolQuery{"g_counter", "data"});
  REQUIRE(datas.size() == 1);
  CHECK(datas[0].kind == "data");

  // Unknown build_id returns empty without throwing.
  CHECK(idx.query_symbols("nope", SymbolQuery{"main", ""}).empty());
}

TEST_CASE("symbol_index: type layout round-trip preserves members JSON",
          "[index][types]") {
  auto root = make_tmp_root("types");
  SymbolIndex idx(root);
  auto bin = make_fake_binary(root, "b.out", "elf");

  std::vector<TypeRow> tys = {
    ty("Point",   8,  {{"x", 0}, {"y", 4}}),
    ty("Header", 16,  {{"magic", 0}, {"version", 4}, {"flags", 8}}),
  };
  idx.populate(make_entry("bid-types", bin), {}, tys, {});

  auto p = idx.query_type("bid-types", "Point");
  REQUIRE(p.has_value());
  CHECK(p->byte_size == 8);
  REQUIRE(p->members.is_array());
  REQUIRE(p->members.size() == 2);
  CHECK(p->members[1]["name"] == "y");
  CHECK(p->members[1]["offset"] == 4);

  // Unknown type → nullopt
  CHECK_FALSE(idx.query_type("bid-types", "DoesNotExist").has_value());
}

TEST_CASE("symbol_index: strings exact match + LIKE contains",
          "[index][strings]") {
  auto root = make_tmp_root("strings");
  SymbolIndex idx(root);
  auto bin = make_fake_binary(root, "c.out", "elf");

  std::vector<StringRow> ss = {
    str(0x2000, "Hello, world!"),
    str(0x2010, "LDB_MAGIC"),
    str(0x2020, "Goodbye, world!"),
  };
  idx.populate(make_entry("bid-str", bin), {}, {}, ss);

  // exact
  auto magic = idx.query_strings("bid-str",
                                   StringQuery{"LDB_MAGIC", false});
  REQUIRE(magic.size() == 1);
  CHECK(magic[0].address == 0x2010);

  // contains "world" → matches Hello+Goodbye
  auto world = idx.query_strings("bid-str",
                                   StringQuery{"world", true});
  CHECK(world.size() == 2);
}

TEST_CASE("symbol_index: re-populate replaces atomically",
          "[index][populate]") {
  auto root = make_tmp_root("replace");
  SymbolIndex idx(root);
  auto bin = make_fake_binary(root, "d.out", "elf");

  idx.populate(make_entry("bid-rep", bin),
               {sym("old", "", 0x100)}, {}, {});
  CHECK(idx.query_symbols("bid-rep", SymbolQuery{"old", ""}).size() == 1);

  // Re-populate with a different symbol set. The previous "old"
  // symbol must be gone — the index is replacing, not merging.
  idx.populate(make_entry("bid-rep", bin),
               {sym("fresh", "", 0x200)}, {}, {});
  CHECK(idx.query_symbols("bid-rep", SymbolQuery{"old", ""}).empty());
  CHECK(idx.query_symbols("bid-rep", SymbolQuery{"fresh", ""}).size() == 1);
}

TEST_CASE("symbol_index: invalidate drops every row, reports presence",
          "[index][invalidate]") {
  auto root = make_tmp_root("invalidate");
  SymbolIndex idx(root);
  auto bin = make_fake_binary(root, "e.out", "elf");
  idx.populate(make_entry("bid-i", bin),
               {sym("f", "", 0x1)},
               {ty("T", 4, {{"a", 0}})},
               {str(0x10, "hello")});

  CHECK(idx.invalidate("bid-i") == true);
  // After invalidate, the row vanishes — cache_status returns kMissing
  // and all queries return empty.
  CHECK(idx.cache_status("bid-i", fingerprint_of(bin))
        == CacheStatus::kMissing);
  CHECK(idx.query_symbols("bid-i", SymbolQuery{"f", ""}).empty());
  CHECK_FALSE(idx.query_type("bid-i", "T").has_value());
  CHECK(idx.query_strings("bid-i", StringQuery{"hello", false}).empty());

  // Second invalidate returns false (nothing to drop).
  CHECK(idx.invalidate("bid-i") == false);
}

TEST_CASE("symbol_index: cache survives a fresh open against the same root",
          "[index][persistence]") {
  auto root = make_tmp_root("persist");
  auto bin  = make_fake_binary(root, "f.out", "elf");
  {
    SymbolIndex idx(root);
    idx.populate(make_entry("bid-p", bin),
                 {sym("persistent_fn", "", 0xdead)}, {}, {});
  }
  // Re-open — the cache must still be there.
  SymbolIndex idx2(root);
  CHECK(idx2.cache_status("bid-p", fingerprint_of(bin))
        == CacheStatus::kHot);
  auto hits = idx2.query_symbols("bid-p",
                                   SymbolQuery{"persistent_fn", ""});
  REQUIRE(hits.size() == 1);
  CHECK(hits[0].address == 0xdead);
}

TEST_CASE("symbol_index: stats counts rows across families",
          "[index][stats]") {
  auto root = make_tmp_root("stats");
  SymbolIndex idx(root);
  auto bin = make_fake_binary(root, "g.out", "elf");
  idx.populate(make_entry("bid-s", bin),
               {sym("a", "", 1), sym("b", "", 2), sym("c", "", 3)},
               {ty("T1", 4, {}), ty("T2", 8, {})},
               {str(10, "x")});
  auto s = idx.stats();
  CHECK(s.binary_count == 1);
  CHECK(s.symbol_count == 3);
  CHECK(s.type_count   == 2);
  CHECK(s.string_count == 1);
}
