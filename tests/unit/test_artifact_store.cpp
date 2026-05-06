// Unit tests for ldb::store::ArtifactStore.
//
// Contract under test (M3 part 1, plan §4.7 + §8):
//
//   • put(build_id, name, bytes, format?, meta) inserts one row, writes
//     the blob to disk under <root>/builds/<build_id>/artifacts/<id>,
//     returns the inserted row with sha256+byte_size+stored_path.
//   • get_by_name and get_by_id both round-trip everything (bytes match,
//     sha256 matches, meta+format+tags reconstruct).
//   • (build_id, name) is unique — putting twice with the same pair
//     replaces the prior entry: old blob file is deleted, the row's id
//     CHANGES (new INSERT after DELETE), and listing returns one entry,
//     not two.
//   • list filters by build_id and name_pattern. The matcher is sqlite
//     LIKE semantics: % is multi-char wildcard, _ is single-char. We
//     document this explicitly because agents will guess.
//   • add_tags is additive (existing tags preserved) and idempotent
//     (re-adding the same tag is a no-op).
//   • read_blob with max_bytes=0 returns the full blob; max_bytes=N
//     truncates to first N bytes.
//   • Corrupt-blob recovery: row exists but file is gone → read_blob
//     throws backend::Error. We verify by manually rm-ing the file.
//
// The fixture uses std::filesystem::temp_directory_path() / a per-test
// random subdir. **NEVER touch ~/.ldb from tests.**

#include <catch_amalgamated.hpp>

#include "store/artifact_store.h"

#include "backend/debugger_backend.h"   // backend::Error

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <random>
#include <string>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;
using ldb::store::ArtifactRow;
using ldb::store::ArtifactStore;

namespace {

// Per-test fixture: makes a tmpdir under the system temp area, hands it
// to the store, removes it on destruction. Random suffix avoids
// collisions when tests run in parallel and avoids leaking state across
// runs.
struct TmpStoreRoot {
  fs::path root;

  TmpStoreRoot() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    char buf[32];
    std::snprintf(buf, sizeof(buf), "ldb_test_%016llx",
                  static_cast<unsigned long long>(gen()));
    root = fs::temp_directory_path() / buf;
    // Defensive: should not exist, but if a stale dir is here, blow it
    // away. We're in /tmp/ldb_test_<random>; this can't escape.
    std::error_code ec;
    fs::remove_all(root, ec);
  }

  ~TmpStoreRoot() {
    std::error_code ec;
    fs::remove_all(root, ec);
  }
};

std::vector<std::uint8_t> bytes_from(const std::string& s) {
  return {s.begin(), s.end()};
}

std::vector<std::uint8_t> rand_bytes(std::size_t n, std::uint64_t seed = 1) {
  std::mt19937_64 g(seed);
  std::vector<std::uint8_t> out(n);
  for (auto& b : out) b = static_cast<std::uint8_t>(g() & 0xFFu);
  return out;
}

}  // namespace

TEST_CASE("artifact_store: put + get_by_name round-trip",
          "[store][artifact]") {
  TmpStoreRoot t;
  ArtifactStore s(t.root);

  auto payload = bytes_from("<schema name=\"btp\"><frame/></schema>");
  auto row = s.put("build-deadbeef", "btp_schema.xml", payload,
                   std::string("xml"),
                   nlohmann::json{{"captured_at", "2026-05-05"}});
  REQUIRE(row.id > 0);
  CHECK(row.build_id == "build-deadbeef");
  CHECK(row.name == "btp_schema.xml");
  CHECK(row.byte_size == payload.size());
  CHECK(row.sha256.size() == 64);              // 32 bytes lower-hex
  REQUIRE(row.format.has_value());
  CHECK(*row.format == "xml");
  CHECK(row.meta.contains("captured_at"));
  CHECK(row.tags.empty());
  // The blob file exists at the documented location.
  CHECK(fs::exists(row.stored_path));

  auto got = s.get_by_name("build-deadbeef", "btp_schema.xml");
  REQUIRE(got.has_value());
  CHECK(got->id == row.id);
  CHECK(got->sha256 == row.sha256);
  CHECK(got->byte_size == row.byte_size);

  auto blob = s.read_blob(*got);
  CHECK(blob == payload);
}

TEST_CASE("artifact_store: get_by_id parallels get_by_name",
          "[store][artifact]") {
  TmpStoreRoot t;
  ArtifactStore s(t.root);
  auto row = s.put("b1", "a", bytes_from("hello"),
                   std::nullopt, nlohmann::json::object());
  auto by_id = s.get_by_id(row.id);
  REQUIRE(by_id.has_value());
  CHECK(by_id->name == "a");
  CHECK(by_id->build_id == "b1");
  CHECK_FALSE(by_id->format.has_value());

  // Bogus id is nullopt, not an error.
  CHECK_FALSE(s.get_by_id(999'999).has_value());
  CHECK_FALSE(s.get_by_name("b1", "no_such_name").has_value());
}

TEST_CASE("artifact_store: replace-on-duplicate (build_id, name)",
          "[store][artifact]") {
  TmpStoreRoot t;
  ArtifactStore s(t.root);

  auto v1 = bytes_from("first version");
  auto v2 = bytes_from("SECOND VERSION (longer)");

  auto r1 = s.put("b1", "thing", v1, std::nullopt, nlohmann::json::object());
  fs::path p1 = r1.stored_path;
  REQUIRE(fs::exists(p1));

  auto r2 = s.put("b1", "thing", v2, std::nullopt, nlohmann::json::object());
  // Replace contract: row id must differ (we DELETE then INSERT, no UPDATE),
  // old blob file is gone, new one exists, list returns 1 row.
  CHECK(r2.id != r1.id);
  CHECK_FALSE(fs::exists(p1));
  CHECK(fs::exists(r2.stored_path));
  CHECK(r2.byte_size == v2.size());
  CHECK(r2.sha256 != r1.sha256);

  auto got = s.get_by_name("b1", "thing");
  REQUIRE(got.has_value());
  CHECK(got->id == r2.id);
  CHECK(s.read_blob(*got) == v2);

  auto all = s.list(std::nullopt, std::nullopt);
  CHECK(all.size() == 1);
}

TEST_CASE("artifact_store: list filters by build_id",
          "[store][artifact]") {
  TmpStoreRoot t;
  ArtifactStore s(t.root);

  s.put("ba", "x", bytes_from("ax"), std::nullopt, nlohmann::json::object());
  s.put("ba", "y", bytes_from("ay"), std::nullopt, nlohmann::json::object());
  s.put("bb", "x", bytes_from("bx"), std::nullopt, nlohmann::json::object());

  auto all = s.list(std::nullopt, std::nullopt);
  CHECK(all.size() == 3);

  auto ba = s.list(std::string("ba"), std::nullopt);
  CHECK(ba.size() == 2);
  for (const auto& r : ba) CHECK(r.build_id == "ba");

  auto bb = s.list(std::string("bb"), std::nullopt);
  CHECK(bb.size() == 1);
  CHECK(bb[0].build_id == "bb");

  CHECK(s.list(std::string("nope"), std::nullopt).empty());
}

TEST_CASE("artifact_store: list filters by name_pattern (LIKE semantics)",
          "[store][artifact]") {
  // We rely on sqlite's LIKE: '%' = multi-char wildcard, '_' = single
  // char. Document explicitly because agents will guess.
  TmpStoreRoot t;
  ArtifactStore s(t.root);

  s.put("b", "schema_login.xml", bytes_from("a"), std::nullopt,
        nlohmann::json::object());
  s.put("b", "schema_logout.xml", bytes_from("b"), std::nullopt,
        nlohmann::json::object());
  s.put("b", "frame.bin", bytes_from("c"), std::nullopt,
        nlohmann::json::object());

  auto schemas = s.list(std::nullopt, std::string("schema_%.xml"));
  CHECK(schemas.size() == 2);
  for (const auto& r : schemas) {
    CHECK(r.name.starts_with("schema_"));
  }

  auto bins = s.list(std::nullopt, std::string("%.bin"));
  CHECK(bins.size() == 1);
  CHECK(bins[0].name == "frame.bin");

  auto exact = s.list(std::nullopt, std::string("frame.bin"));
  CHECK(exact.size() == 1);

  // Combine build_id + pattern.
  s.put("c", "schema_other.xml", bytes_from("d"), std::nullopt,
        nlohmann::json::object());
  auto b_schemas = s.list(std::string("b"), std::string("schema_%"));
  CHECK(b_schemas.size() == 2);
}

TEST_CASE("artifact_store: add_tags is additive and idempotent",
          "[store][artifact]") {
  TmpStoreRoot t;
  ArtifactStore s(t.root);
  auto r = s.put("b", "n", bytes_from("p"), std::nullopt,
                 nlohmann::json::object());

  auto tags1 = s.add_tags(r.id, {"a", "b"});
  std::sort(tags1.begin(), tags1.end());
  CHECK(tags1 == std::vector<std::string>{"a", "b"});

  // Additive — adding "c" keeps a/b.
  auto tags2 = s.add_tags(r.id, {"c"});
  std::sort(tags2.begin(), tags2.end());
  CHECK(tags2 == std::vector<std::string>{"a", "b", "c"});

  // Idempotent — re-adding "a" must not duplicate.
  auto tags3 = s.add_tags(r.id, {"a"});
  std::sort(tags3.begin(), tags3.end());
  CHECK(tags3 == std::vector<std::string>{"a", "b", "c"});

  // get_by_id reflects the same.
  auto reread = s.get_by_id(r.id);
  REQUIRE(reread.has_value());
  auto rt = reread->tags;
  std::sort(rt.begin(), rt.end());
  CHECK(rt == std::vector<std::string>{"a", "b", "c"});
}

TEST_CASE("artifact_store: add_tags on missing id throws",
          "[store][artifact][error]") {
  TmpStoreRoot t;
  ArtifactStore s(t.root);
  CHECK_THROWS_AS(s.add_tags(424242, {"x"}), ldb::backend::Error);
}

TEST_CASE("artifact_store: read_blob max_bytes truncates",
          "[store][artifact]") {
  TmpStoreRoot t;
  ArtifactStore s(t.root);
  auto big = rand_bytes(4096, 0xC0FFEE);
  auto r = s.put("b", "big.bin", big, std::nullopt, nlohmann::json::object());

  auto full = s.read_blob(r);
  CHECK(full.size() == 4096);
  CHECK(full == big);

  auto first128 = s.read_blob(r, 128);
  REQUIRE(first128.size() == 128);
  for (std::size_t i = 0; i < 128; ++i) {
    CHECK(first128[i] == big[i]);
  }

  // 0 means unlimited.
  auto zero = s.read_blob(r, 0);
  CHECK(zero.size() == 4096);

  // Cap larger than blob returns the whole blob (no padding).
  auto over = s.read_blob(r, 1'000'000);
  CHECK(over.size() == 4096);
}

TEST_CASE("artifact_store: read_blob throws when on-disk file is missing",
          "[store][artifact][error]") {
  TmpStoreRoot t;
  ArtifactStore s(t.root);
  auto r = s.put("b", "n", bytes_from("payload"), std::nullopt,
                 nlohmann::json::object());
  REQUIRE(fs::exists(r.stored_path));

  // Manually clobber the blob file behind the store's back. The row
  // still exists in the index — read_blob must surface the IO error
  // as backend::Error, not return junk or hang.
  std::error_code ec;
  fs::remove(r.stored_path, ec);
  REQUIRE_FALSE(fs::exists(r.stored_path));

  CHECK_THROWS_AS(s.read_blob(r), ldb::backend::Error);
}

TEST_CASE("artifact_store: index persists across reopen",
          "[store][artifact]") {
  TmpStoreRoot t;
  ArtifactRow r;
  std::vector<std::uint8_t> payload = bytes_from("persistent");
  {
    ArtifactStore s(t.root);
    r = s.put("b", "n", payload, std::string("raw"),
              nlohmann::json{{"k", "v"}});
    s.add_tags(r.id, {"saved"});
  }
  {
    ArtifactStore s2(t.root);
    auto got = s2.get_by_name("b", "n");
    REQUIRE(got.has_value());
    CHECK(got->id == r.id);
    CHECK(got->sha256 == r.sha256);
    REQUIRE(got->format.has_value());
    CHECK(*got->format == "raw");
    CHECK(got->meta["k"] == "v");
    REQUIRE(got->tags == std::vector<std::string>{"saved"});
    CHECK(s2.read_blob(*got) == payload);
  }
}

TEST_CASE("artifact_store: empty bytes are allowed",
          "[store][artifact]") {
  // An agent might capture a region that turns out to be zero-length
  // (e.g. a parsed packet with no payload). Don't reject; round-trip.
  TmpStoreRoot t;
  ArtifactStore s(t.root);
  auto r = s.put("b", "empty", {}, std::nullopt, nlohmann::json::object());
  CHECK(r.byte_size == 0);
  CHECK(r.sha256 ==
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  CHECK(s.read_blob(r).empty());
}

// Tier 2 §6 (probe recipes) prep: ArtifactStore::remove drops a row
// AND its on-disk blob AND its tags (FK CASCADE). Recipes will pile up
// and need a clean delete path; rather than have the recipe layer do
// raw sqlite, we expose the operation here and reuse it.
TEST_CASE("artifact_store: remove drops row, blob, and cascades tags",
          "[store][artifact]") {
  TmpStoreRoot t;
  ArtifactStore s(t.root);
  auto r = s.put("b", "n", bytes_from("payload"),
                 std::string("recipe-v1"), nlohmann::json{{"k", "v"}});
  s.add_tags(r.id, {"alpha", "beta"});
  REQUIRE(fs::exists(r.stored_path));
  REQUIRE(s.get_by_id(r.id).has_value());

  CHECK(s.remove(r.id) == true);

  CHECK_FALSE(fs::exists(r.stored_path));
  CHECK_FALSE(s.get_by_id(r.id).has_value());
  CHECK(s.list(std::nullopt, std::nullopt).empty());
}

TEST_CASE("artifact_store: remove on missing id returns false",
          "[store][artifact]") {
  // No throw — recipe.delete needs an idempotent semantic.
  TmpStoreRoot t;
  ArtifactStore s(t.root);
  CHECK(s.remove(999'999) == false);
}

TEST_CASE("artifact_store: remove tolerates missing on-disk blob",
          "[store][artifact]") {
  // A previously-corrupt store (blob removed out-of-band) must still let
  // us delete the dangling row; otherwise we have no way to GC it.
  TmpStoreRoot t;
  ArtifactStore s(t.root);
  auto r = s.put("b", "n", bytes_from("p"), std::nullopt,
                 nlohmann::json::object());
  std::error_code ec;
  fs::remove(r.stored_path, ec);
  REQUIRE_FALSE(fs::exists(r.stored_path));

  CHECK(s.remove(r.id) == true);
  CHECK_FALSE(s.get_by_id(r.id).has_value());
}
