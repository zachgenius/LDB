// SPDX-License-Identifier: Apache-2.0
// Unit tests for ldb::store pack/unpack — `.ldbpack` format helpers
// (M5 part 5).
//
// Three layers under test:
//   1. tar_pack / tar_unpack — pure byte-buffer USTAR codec.
//   2. gzip_compress / gzip_decompress — zlib wrappers, with the
//      decompressed-size cap.
//   3. pack_session / pack_artifacts / unpack — end-to-end against
//      live SessionStore + ArtifactStore tmpdir fixtures.

#include <catch_amalgamated.hpp>

#include "store/pack.h"

#include "backend/debugger_backend.h"  // backend::Error
#include "store/artifact_store.h"
#include "store/session_store.h"

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;

using ldb::store::ArtifactStore;
using ldb::store::ConflictPolicy;
using ldb::store::ImportEntry;
using ldb::store::ImportReport;
using ldb::store::PackResult;
using ldb::store::SessionStore;
using ldb::store::TarEntry;

namespace {

struct TmpDir {
  fs::path root;
  TmpDir() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    char buf[40];
    std::snprintf(buf, sizeof(buf), "ldb_pack_test_%016llx",
                  static_cast<unsigned long long>(gen()));
    root = fs::temp_directory_path() / buf;
    std::error_code ec;
    fs::remove_all(root, ec);
    fs::create_directories(root, ec);
  }
  ~TmpDir() {
    std::error_code ec;
    fs::remove_all(root, ec);
  }
};

std::vector<std::uint8_t> bytes_of(std::string_view s) {
  return {s.begin(), s.end()};
}

std::vector<std::uint8_t> read_file_bytes(const fs::path& p) {
  std::ifstream in(p, std::ios::binary);
  if (!in) return {};
  std::vector<std::uint8_t> out;
  in.seekg(0, std::ios::end);
  out.resize(static_cast<std::size_t>(in.tellg()));
  in.seekg(0, std::ios::beg);
  in.read(reinterpret_cast<char*>(out.data()),
          static_cast<std::streamsize>(out.size()));
  return out;
}

}  // namespace

// ---- tar_pack / tar_unpack ------------------------------------------------

TEST_CASE("tar_pack: empty input yields just the two zero blocks",
          "[store][pack][tar]") {
  auto buf = ldb::store::tar_pack({});
  REQUIRE(buf.size() == 1024);
  for (auto b : buf) CHECK(b == 0);
}

TEST_CASE("tar round-trip: small file", "[store][pack][tar]") {
  std::vector<TarEntry> in = {
      {"manifest.json", bytes_of(R"({"format":"ldbpack/1"})"), 0},
      {"sessions/abc.db", bytes_of("hello world"), 0},
  };
  auto buf = ldb::store::tar_pack(in);
  // Each entry: 1 header block + ceil(size/512) data blocks; +2 zero
  // blocks at the end.
  // Entry 0: 22 bytes → 1 data block. Entry 1: 11 bytes → 1 data block.
  CHECK(buf.size() == (1 + 1) * 512 + (1 + 1) * 512 + 1024);

  auto out = ldb::store::tar_unpack(buf);
  REQUIRE(out.size() == 2);
  CHECK(out[0].name == "manifest.json");
  CHECK(out[0].data == in[0].data);
  CHECK(out[1].name == "sessions/abc.db");
  CHECK(out[1].data == in[1].data);
}

TEST_CASE("tar round-trip: multi-block payload", "[store][pack][tar]") {
  std::vector<std::uint8_t> big(2000);
  for (std::size_t i = 0; i < big.size(); ++i) {
    big[i] = static_cast<std::uint8_t>(i & 0xFFu);
  }
  std::vector<TarEntry> in = {{"big.bin", big, 0}};
  auto buf = ldb::store::tar_pack(in);
  // 2000 bytes → ceil(2000/512) = 4 data blocks; + 1 header; + 2 trailer.
  CHECK(buf.size() == 512 * (1 + 4) + 1024);
  auto out = ldb::store::tar_unpack(buf);
  REQUIRE(out.size() == 1);
  CHECK(out[0].data == big);
}

TEST_CASE("tar round-trip: nested path with embedded slashes",
          "[store][pack][tar]") {
  std::vector<TarEntry> in = {
      {"artifacts/abc123/meta/btp_schema.xml.json", bytes_of("{}"), 0},
  };
  auto buf = ldb::store::tar_pack(in);
  auto out = ldb::store::tar_unpack(buf);
  REQUIRE(out.size() == 1);
  CHECK(out[0].name == "artifacts/abc123/meta/btp_schema.xml.json");
}

TEST_CASE("tar round-trip: large blob > 10 MB", "[store][pack][tar]") {
  std::vector<std::uint8_t> big(11 * 1024 * 1024);
  // Pseudo-random fill; actual content doesn't matter, just size.
  std::mt19937 gen(42);
  for (auto& b : big) b = static_cast<std::uint8_t>(gen() & 0xFFu);
  std::vector<TarEntry> in = {{"giant.bin", big, 0}};
  auto buf = ldb::store::tar_pack(in);
  auto out = ldb::store::tar_unpack(buf);
  REQUIRE(out.size() == 1);
  CHECK(out[0].data.size() == big.size());
  CHECK(out[0].data == big);
}

TEST_CASE("tar_unpack: rejects path traversal '..'",
          "[store][pack][tar][security]") {
  std::vector<TarEntry> in = {{"../etc/passwd", bytes_of("evil"), 0}};
  auto buf = ldb::store::tar_pack(in);
  CHECK_THROWS_AS(ldb::store::tar_unpack(buf), ldb::backend::Error);
}

TEST_CASE("tar_unpack: rejects absolute path",
          "[store][pack][tar][security]") {
  std::vector<TarEntry> in = {{"/etc/passwd", bytes_of("evil"), 0}};
  auto buf = ldb::store::tar_pack(in);
  CHECK_THROWS_AS(ldb::store::tar_unpack(buf), ldb::backend::Error);
}

TEST_CASE("tar_unpack: bad magic throws", "[store][pack][tar]") {
  // 512-byte block with garbage in the magic field — not "ustar".
  std::vector<std::uint8_t> bad(512);
  for (std::size_t i = 0; i < bad.size(); ++i) {
    bad[i] = static_cast<std::uint8_t>('A' + (i & 7u));
  }
  CHECK_THROWS_AS(ldb::store::tar_unpack(bad), ldb::backend::Error);
}

// ---- gzip ----------------------------------------------------------------

TEST_CASE("gzip round-trip: empty input", "[store][pack][gzip]") {
  std::vector<std::uint8_t> empty;
  auto z = ldb::store::gzip_compress(empty);
  CHECK(z.size() > 0);  // gzip header + footer even for empty
  auto back = ldb::store::gzip_decompress(z);
  CHECK(back.empty());
}

TEST_CASE("gzip round-trip: small string", "[store][pack][gzip]") {
  auto in = bytes_of("hello world this is a test of gzip compression");
  auto z = ldb::store::gzip_compress(in);
  auto back = ldb::store::gzip_decompress(z);
  CHECK(back == in);
}

TEST_CASE("gzip round-trip: highly compressible", "[store][pack][gzip]") {
  std::vector<std::uint8_t> in(100000, 0x41);  // 100k 'A's
  auto z = ldb::store::gzip_compress(in);
  CHECK(z.size() < 1000);  // RLE-friendly; trivially compresses
  auto back = ldb::store::gzip_decompress(z);
  CHECK(back == in);
}

TEST_CASE("gzip_decompress: rejects malformed", "[store][pack][gzip]") {
  std::vector<std::uint8_t> garbage{1, 2, 3, 4, 5, 6, 7, 8};
  CHECK_THROWS_AS(ldb::store::gzip_decompress(garbage),
                  ldb::backend::Error);
}

TEST_CASE("gzip_decompress: cap rejects oversize",
          "[store][pack][gzip][security]") {
  // 100k 'A's compresses to ~120 bytes. Decompressing with a 1k cap
  // must throw rather than allocate the full 100k.
  std::vector<std::uint8_t> in(100000, 0x41);
  auto z = ldb::store::gzip_compress(in);
  CHECK_THROWS_AS(ldb::store::gzip_decompress(z, 1024),
                  ldb::backend::Error);
  // Same buffer with a generous cap decodes fine.
  auto back = ldb::store::gzip_decompress(z, 1024 * 1024);
  CHECK(back.size() == 100000);
}

// ---- sha256 sanity -------------------------------------------------------

TEST_CASE("sha256_hex: empty bytes", "[store][pack][sha256]") {
  std::vector<std::uint8_t> empty;
  CHECK(ldb::store::sha256_hex(empty) ==
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

// ---- conflict policy enum -----------------------------------------------

TEST_CASE("parse_conflict_policy", "[store][pack]") {
  ConflictPolicy p;
  CHECK(ldb::store::parse_conflict_policy("error", &p));
  CHECK(p == ConflictPolicy::kError);
  CHECK(ldb::store::parse_conflict_policy("skip", &p));
  CHECK(p == ConflictPolicy::kSkip);
  CHECK(ldb::store::parse_conflict_policy("overwrite", &p));
  CHECK(p == ConflictPolicy::kOverwrite);
  CHECK_FALSE(ldb::store::parse_conflict_policy("nonsense", &p));
  CHECK_FALSE(ldb::store::parse_conflict_policy("", &p));
}

// ---- end-to-end: pack_session round-trips through unpack ----------------

TEST_CASE("pack_session: round-trip through unpack",
          "[store][pack][e2e]") {
  TmpDir t;
  auto src_root = t.root / "src";
  auto pack_path = t.root / "out.ldbpack";
  auto dst_root = t.root / "dst";

  std::string sid;
  {
    SessionStore ss(src_root);
    ArtifactStore as(src_root);
    auto row = ss.create("investigation-1", std::optional<std::string>{"tgt-1"});
    sid = row.id;
    auto w = ss.open_writer(sid);
    nlohmann::json req = {{"method", "hello"}};
    nlohmann::json rsp = {{"ok", true}};
    w->append("hello", req, rsp, true, 100);
    w->append("describe.endpoints", req, rsp, true, 200);
    w.reset();

    as.put("buildA", "btp_schema.xml",
           bytes_of("<schema/>"), std::optional<std::string>("xml"),
           nlohmann::json{{"author", "agent"}});
    as.put("buildA", "login_frame.bin",
           bytes_of("\x01\x02\x03\x04"), std::nullopt,
           nlohmann::json::object());
    as.put("buildB", "other.bin",
           bytes_of("xyz"), std::nullopt,
           nlohmann::json::object());

    auto result = ldb::store::pack_session(ss, as, sid, pack_path);
    CHECK(fs::exists(result.path));
    CHECK(result.byte_size > 0);
    CHECK(result.byte_size == fs::file_size(result.path));
    CHECK(result.sha256.size() == 64);
    REQUIRE(result.manifest.contains("sessions"));
    CHECK(result.manifest["sessions"].size() == 1);
    REQUIRE(result.manifest.contains("artifacts"));
    CHECK(result.manifest["artifacts"].size() == 3);
    CHECK(result.manifest["format"] == "ldbpack/1");

    // Verify the on-disk file matches the reported sha256.
    auto disk = read_file_bytes(result.path);
    CHECK(ldb::store::sha256_hex(disk) == result.sha256);
  }

  // Now import into a fresh store.
  {
    SessionStore ss(dst_root);
    ArtifactStore as(dst_root);
    auto report = ldb::store::unpack(ss, as, pack_path,
                                     ConflictPolicy::kError);
    CHECK(report.imported.size() == 4);   // 1 session + 3 artifacts
    CHECK(report.skipped.empty());

    auto info = ss.info(sid);
    REQUIRE(info.has_value());
    CHECK(info->name == "investigation-1");
    CHECK(info->target_id.has_value());
    CHECK(*info->target_id == "tgt-1");
    CHECK(info->call_count == 2);

    auto a1 = as.get_by_name("buildA", "btp_schema.xml");
    REQUIRE(a1.has_value());
    auto a1_bytes = as.read_blob(*a1);
    CHECK(a1_bytes == bytes_of("<schema/>"));
    CHECK(a1->format.has_value());
    CHECK(*a1->format == "xml");
    CHECK(a1->meta.contains("author"));
    CHECK(a1->meta["author"] == "agent");

    auto a2 = as.get_by_name("buildA", "login_frame.bin");
    REQUIRE(a2.has_value());
    auto a3 = as.get_by_name("buildB", "other.bin");
    REQUIRE(a3.has_value());
    auto a3_bytes = as.read_blob(*a3);
    CHECK(a3_bytes == bytes_of("xyz"));
  }
}

TEST_CASE("pack_artifacts: pure-artifact pack omits sessions",
          "[store][pack][e2e]") {
  TmpDir t;
  auto src_root = t.root / "src";
  auto pack_path = t.root / "art.ldbpack";

  ArtifactStore as(src_root);
  as.put("buildA", "one.bin", bytes_of("aaa"), std::nullopt,
         nlohmann::json::object());
  as.put("buildB", "two.bin", bytes_of("bbb"), std::nullopt,
         nlohmann::json::object());

  auto r = ldb::store::pack_artifacts(as, std::nullopt, std::nullopt,
                                      pack_path);
  CHECK(r.manifest["artifacts"].size() == 2);
  CHECK(r.manifest.contains("sessions"));
  CHECK(r.manifest["sessions"].empty());
}

TEST_CASE("pack_artifacts: build_id filter",
          "[store][pack][e2e]") {
  TmpDir t;
  auto src_root = t.root / "src";
  auto pack_path = t.root / "art.ldbpack";

  ArtifactStore as(src_root);
  as.put("buildA", "one.bin", bytes_of("aaa"), std::nullopt,
         nlohmann::json::object());
  as.put("buildB", "two.bin", bytes_of("bbb"), std::nullopt,
         nlohmann::json::object());
  as.put("buildA", "three.bin", bytes_of("ccc"), std::nullopt,
         nlohmann::json::object());

  auto r = ldb::store::pack_artifacts(as,
                                      std::optional<std::string>("buildA"),
                                      std::nullopt,
                                      pack_path);
  CHECK(r.manifest["artifacts"].size() == 2);
  for (const auto& a : r.manifest["artifacts"]) {
    CHECK(a["build_id"] == "buildA");
  }
}

TEST_CASE("unpack: conflict_policy=error aborts on duplicate",
          "[store][pack][e2e]") {
  TmpDir t;
  auto src_root = t.root / "src";
  auto pack_path = t.root / "p.ldbpack";
  auto dst_root = t.root / "dst";

  std::string sid;
  {
    SessionStore ss(src_root);
    ArtifactStore as(src_root);
    auto row = ss.create("inv", std::nullopt);
    sid = row.id;
    as.put("bid", "n", bytes_of("x"), std::nullopt,
           nlohmann::json::object());
    ldb::store::pack_session(ss, as, sid, pack_path);
  }

  // Pre-seed the destination so the artifact's (build_id, name) collides.
  {
    SessionStore ss(dst_root);
    ArtifactStore as(dst_root);
    as.put("bid", "n", bytes_of("Y"), std::nullopt,
           nlohmann::json::object());
    CHECK_THROWS_AS(
        ldb::store::unpack(ss, as, pack_path, ConflictPolicy::kError),
        ldb::backend::Error);
  }
}

TEST_CASE("unpack: conflict_policy=skip preserves local entries",
          "[store][pack][e2e]") {
  TmpDir t;
  auto src_root = t.root / "src";
  auto pack_path = t.root / "p.ldbpack";
  auto dst_root = t.root / "dst";

  std::string sid;
  {
    SessionStore ss(src_root);
    ArtifactStore as(src_root);
    auto row = ss.create("inv", std::nullopt);
    sid = row.id;
    as.put("bid", "n", bytes_of("FROM_PACK"), std::nullopt,
           nlohmann::json::object());
    as.put("bid", "n2", bytes_of("NEW"), std::nullopt,
           nlohmann::json::object());
    ldb::store::pack_session(ss, as, sid, pack_path);
  }

  {
    SessionStore ss(dst_root);
    ArtifactStore as(dst_root);
    as.put("bid", "n", bytes_of("LOCAL"), std::nullopt,
           nlohmann::json::object());
    auto report = ldb::store::unpack(ss, as, pack_path,
                                     ConflictPolicy::kSkip);
    // The duplicate artifact got skipped; the new one got imported;
    // the session got imported.
    CHECK(report.skipped.size() == 1);
    CHECK(report.skipped[0].kind == "artifact");
    // Local "n" still has its original bytes.
    auto a = as.get_by_name("bid", "n");
    REQUIRE(a.has_value());
    auto bytes = as.read_blob(*a);
    CHECK(bytes == bytes_of("LOCAL"));
    // Session and new artifact present.
    CHECK(ss.info(sid).has_value());
    auto a2 = as.get_by_name("bid", "n2");
    REQUIRE(a2.has_value());
  }
}

TEST_CASE("unpack: conflict_policy=overwrite replaces local",
          "[store][pack][e2e]") {
  TmpDir t;
  auto src_root = t.root / "src";
  auto pack_path = t.root / "p.ldbpack";
  auto dst_root = t.root / "dst";

  std::string sid;
  {
    SessionStore ss(src_root);
    ArtifactStore as(src_root);
    auto row = ss.create("inv", std::nullopt);
    sid = row.id;
    as.put("bid", "n", bytes_of("FROM_PACK"), std::nullopt,
           nlohmann::json::object());
    ldb::store::pack_session(ss, as, sid, pack_path);
  }

  {
    SessionStore ss(dst_root);
    ArtifactStore as(dst_root);
    as.put("bid", "n", bytes_of("LOCAL"), std::nullopt,
           nlohmann::json::object());
    auto report = ldb::store::unpack(ss, as, pack_path,
                                     ConflictPolicy::kOverwrite);
    CHECK(report.skipped.empty());
    auto a = as.get_by_name("bid", "n");
    REQUIRE(a.has_value());
    auto bytes = as.read_blob(*a);
    CHECK(bytes == bytes_of("FROM_PACK"));
  }
}

// ---- pack/unpack carries relations across the .ldbpack boundary --------
// Tier 3 §7: a packed session that carries 2 artifacts + 1 relation
// must round-trip the relation, with the new (re-mapped) artifact ids on
// the import side.

TEST_CASE("pack/unpack: relations round-trip with id remapping",
          "[store][pack][e2e][relations]") {
  TmpDir t;
  auto src_root  = t.root / "src";
  auto pack_path = t.root / "rel.ldbpack";
  auto dst_root  = t.root / "dst";

  std::string sid;
  std::int64_t src_a = 0, src_b = 0;
  {
    SessionStore ss(src_root);
    ArtifactStore as(src_root);
    auto row = ss.create("rel-investigation", std::nullopt);
    sid = row.id;
    auto a = as.put("buildA", "schema.xml", bytes_of("<schema/>"),
                    std::optional<std::string>("xml"),
                    nlohmann::json::object());
    auto b = as.put("buildA", "frame.bin", bytes_of("\x01\x02"),
                    std::nullopt, nlohmann::json::object());
    src_a = a.id;
    src_b = b.id;
    as.add_relation(src_a, src_b, "parsed_by",
                    nlohmann::json{{"function", "xml_parse"}, {"line", 42}});
    ldb::store::pack_session(ss, as, sid, pack_path);
  }

  {
    SessionStore ss(dst_root);
    ArtifactStore as(dst_root);
    auto report = ldb::store::unpack(ss, as, pack_path,
                                     ConflictPolicy::kError);
    // 1 session + 2 artifacts + 1 relation = 4 imports.
    CHECK(report.imported.size() == 4);
    CHECK(report.skipped.empty());

    // The new ids may not match the source ids — fetch by (build_id, name).
    auto a = as.get_by_name("buildA", "schema.xml");
    auto b = as.get_by_name("buildA", "frame.bin");
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());

    auto rels = as.list_relations(std::nullopt, std::nullopt,
                                   ldb::store::RelationDir::kBoth);
    REQUIRE(rels.size() == 1);
    CHECK(rels[0].from_id == a->id);
    CHECK(rels[0].to_id   == b->id);
    CHECK(rels[0].predicate == "parsed_by");
    REQUIRE(rels[0].meta.contains("function"));
    CHECK(rels[0].meta["function"] == "xml_parse");
  }
}

// pack_artifacts (no session) carries relations whose endpoints are both
// inside the exported set; relations whose endpoints fall outside the
// filter are dropped.
TEST_CASE("pack_artifacts: relations exported when both endpoints in set",
          "[store][pack][e2e][relations]") {
  TmpDir t;
  auto src_root  = t.root / "src";
  auto pack_path = t.root / "rel.ldbpack";
  auto dst_root  = t.root / "dst";

  {
    ArtifactStore as(src_root);
    auto a = as.put("buildA", "schema.xml", bytes_of("<schema/>"),
                    std::nullopt, nlohmann::json::object());
    auto b = as.put("buildA", "frame.bin", bytes_of("\x01"),
                    std::nullopt, nlohmann::json::object());
    auto c = as.put("buildB", "other.bin", bytes_of("xyz"),
                    std::nullopt, nlohmann::json::object());
    // a→b inside buildA — should be packed when filtering by buildA.
    as.add_relation(a.id, b.id, "parsed_by", nlohmann::json::object());
    // a→c crosses build boundary — should be DROPPED when only buildA
    // is exported (the pack should not produce a dangling relation).
    as.add_relation(a.id, c.id, "extracted_from", nlohmann::json::object());

    ldb::store::pack_artifacts(as,
                                std::optional<std::string>("buildA"),
                                std::nullopt, pack_path);
  }

  {
    SessionStore ss(dst_root);
    ArtifactStore as(dst_root);
    auto report = ldb::store::unpack(ss, as, pack_path,
                                     ConflictPolicy::kError);
    // 2 artifacts + 1 relation (the buildA→buildA edge), no sessions.
    CHECK(report.imported.size() == 3);

    auto rels = as.list_relations(std::nullopt, std::nullopt,
                                   ldb::store::RelationDir::kBoth);
    REQUIRE(rels.size() == 1);
    CHECK(rels[0].predicate == "parsed_by");
  }
}
