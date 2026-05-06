// Unit tests for ldb::store::ArtifactStore relation methods (Tier 3 §7).
//
// Contract under test (post-v0.1 §7):
//
//   • add_relation(from_id, to_id, predicate, meta?) inserts a row into
//     `artifact_relations` and returns it. created_at is unix epoch
//     nanoseconds (matches the rest of the store's ns timestamps).
//   • list_relations(artifact_id?, predicate?, direction) reads back
//     rows; direction in {"out", "in", "both"} (default both). Ordering
//     is by id ASC for determinism.
//   • remove_relation(id) drops one row by id.
//   • ON DELETE CASCADE: deleting an artifact (ArtifactStore::remove)
//     drops every relation referencing it on either endpoint.
//   • Adding a relation with a non-existent endpoint id throws
//     backend::Error (FK violation OR explicit pre-check — either is
//     fine, both surface as an error to the caller).
//
// Predicate policy (decided in the worklog): free-form short string;
// no enum. Empty string is rejected.

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
using ldb::store::ArtifactRelation;
using ldb::store::ArtifactStore;

namespace {

struct TmpStoreRoot {
  fs::path root;
  TmpStoreRoot() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    char buf[40];
    std::snprintf(buf, sizeof(buf), "ldb_relations_%016llx",
                  static_cast<unsigned long long>(gen()));
    root = fs::temp_directory_path() / buf;
    std::error_code ec;
    fs::remove_all(root, ec);
  }
  ~TmpStoreRoot() {
    std::error_code ec;
    fs::remove_all(root, ec);
  }
};

std::vector<std::uint8_t> bytes_of(std::string_view s) {
  return {s.begin(), s.end()};
}

// Convenience: stand up two artifacts and return their ids.
struct PairIds { std::int64_t a = 0; std::int64_t b = 0; };

PairIds two_artifacts(ArtifactStore& s) {
  auto r1 = s.put("buildA", "schema.xml", bytes_of("<schema/>"),
                  std::optional<std::string>("xml"),
                  nlohmann::json::object());
  auto r2 = s.put("buildA", "frame.bin", bytes_of("\x01\x02\x03"),
                  std::nullopt, nlohmann::json::object());
  return {r1.id, r2.id};
}

}  // namespace

TEST_CASE("artifact_relations: add_relation + list_relations basic round-trip",
          "[store][artifact][relations]") {
  TmpStoreRoot t;
  ArtifactStore s(t.root);
  auto p = two_artifacts(s);

  auto rel = s.add_relation(p.a, p.b, "parsed_by",
                             nlohmann::json{{"function", "xml_parse"},
                                            {"line", 42}});
  CHECK(rel.id > 0);
  CHECK(rel.from_id == p.a);
  CHECK(rel.to_id == p.b);
  CHECK(rel.predicate == "parsed_by");
  CHECK(rel.meta.contains("function"));
  CHECK(rel.meta["function"] == "xml_parse");
  CHECK(rel.created_at > 0);

  // both-direction list (no filter) returns the one relation.
  auto all = s.list_relations(std::nullopt, std::nullopt,
                               ldb::store::RelationDir::kBoth);
  REQUIRE(all.size() == 1);
  CHECK(all[0].id == rel.id);
  CHECK(all[0].from_id == p.a);
  CHECK(all[0].to_id == p.b);
  CHECK(all[0].predicate == "parsed_by");
  CHECK(all[0].meta == rel.meta);
}

TEST_CASE("artifact_relations: filter by predicate",
          "[store][artifact][relations]") {
  TmpStoreRoot t;
  ArtifactStore s(t.root);
  auto p = two_artifacts(s);
  auto r3 = s.put("buildA", "third.bin", bytes_of("xyz"),
                   std::nullopt, nlohmann::json::object());

  s.add_relation(p.a, p.b, "parsed_by", nlohmann::json::object());
  s.add_relation(p.a, r3.id, "extracted_from", nlohmann::json::object());
  s.add_relation(p.b, r3.id, "parsed_by", nlohmann::json::object());

  auto parsed = s.list_relations(std::nullopt,
                                  std::optional<std::string>("parsed_by"),
                                  ldb::store::RelationDir::kBoth);
  CHECK(parsed.size() == 2);
  for (const auto& r : parsed) CHECK(r.predicate == "parsed_by");

  auto extracted = s.list_relations(std::nullopt,
                                     std::optional<std::string>("extracted_from"),
                                     ldb::store::RelationDir::kBoth);
  CHECK(extracted.size() == 1);
  CHECK(extracted[0].predicate == "extracted_from");
}

TEST_CASE("artifact_relations: filter by direction",
          "[store][artifact][relations]") {
  TmpStoreRoot t;
  ArtifactStore s(t.root);
  auto p = two_artifacts(s);

  // a -> b (out from a) and b -> a (in to a)
  s.add_relation(p.a, p.b, "parsed_by", nlohmann::json::object());
  s.add_relation(p.b, p.a, "ancestor_of", nlohmann::json::object());

  auto out = s.list_relations(p.a, std::nullopt,
                               ldb::store::RelationDir::kOut);
  REQUIRE(out.size() == 1);
  CHECK(out[0].from_id == p.a);
  CHECK(out[0].predicate == "parsed_by");

  auto in_ = s.list_relations(p.a, std::nullopt,
                               ldb::store::RelationDir::kIn);
  REQUIRE(in_.size() == 1);
  CHECK(in_[0].to_id == p.a);
  CHECK(in_[0].predicate == "ancestor_of");

  auto both = s.list_relations(p.a, std::nullopt,
                                ldb::store::RelationDir::kBoth);
  CHECK(both.size() == 2);
}

TEST_CASE("artifact_relations: ON DELETE CASCADE on artifact removal",
          "[store][artifact][relations]") {
  TmpStoreRoot t;
  ArtifactStore s(t.root);
  auto p = two_artifacts(s);
  auto r3 = s.put("buildA", "third.bin", bytes_of("xyz"),
                   std::nullopt, nlohmann::json::object());

  s.add_relation(p.a, p.b, "parsed_by", nlohmann::json::object());
  s.add_relation(p.a, r3.id, "extracted_from", nlohmann::json::object());
  s.add_relation(p.b, r3.id, "parsed_by", nlohmann::json::object());

  // Sanity: 3 relations.
  CHECK(s.list_relations(std::nullopt, std::nullopt,
                          ldb::store::RelationDir::kBoth).size() == 3);

  // Delete a: should drop the two relations involving it (a->b, a->r3).
  CHECK(s.remove(p.a));
  auto remaining = s.list_relations(std::nullopt, std::nullopt,
                                     ldb::store::RelationDir::kBoth);
  REQUIRE(remaining.size() == 1);
  CHECK(remaining[0].from_id == p.b);
  CHECK(remaining[0].to_id == r3.id);

  // Delete r3: drops the last relation.
  CHECK(s.remove(r3.id));
  CHECK(s.list_relations(std::nullopt, std::nullopt,
                          ldb::store::RelationDir::kBoth).empty());
}

TEST_CASE("artifact_relations: remove_relation by id",
          "[store][artifact][relations]") {
  TmpStoreRoot t;
  ArtifactStore s(t.root);
  auto p = two_artifacts(s);

  auto rel1 = s.add_relation(p.a, p.b, "parsed_by", nlohmann::json::object());
  auto rel2 = s.add_relation(p.a, p.b, "extracted_from", nlohmann::json::object());

  CHECK(s.remove_relation(rel1.id));
  auto remaining = s.list_relations(std::nullopt, std::nullopt,
                                     ldb::store::RelationDir::kBoth);
  REQUIRE(remaining.size() == 1);
  CHECK(remaining[0].id == rel2.id);

  // Idempotent: a second remove returns false.
  CHECK_FALSE(s.remove_relation(rel1.id));
}

TEST_CASE("artifact_relations: add to non-existent artifact fails",
          "[store][artifact][relations]") {
  TmpStoreRoot t;
  ArtifactStore s(t.root);
  auto p = two_artifacts(s);

  // Bogus to_id.
  CHECK_THROWS_AS(
      s.add_relation(p.a, 99999, "parsed_by", nlohmann::json::object()),
      ldb::backend::Error);
  // Bogus from_id.
  CHECK_THROWS_AS(
      s.add_relation(99999, p.b, "parsed_by", nlohmann::json::object()),
      ldb::backend::Error);

  // Empty predicate is rejected too.
  CHECK_THROWS_AS(
      s.add_relation(p.a, p.b, "", nlohmann::json::object()),
      ldb::backend::Error);
}

TEST_CASE("artifact_relations: ordering is stable (id ASC)",
          "[store][artifact][relations]") {
  TmpStoreRoot t;
  ArtifactStore s(t.root);
  auto p = two_artifacts(s);

  auto r1 = s.add_relation(p.a, p.b, "parsed_by", nlohmann::json::object());
  auto r2 = s.add_relation(p.a, p.b, "extracted_from", nlohmann::json::object());
  auto r3 = s.add_relation(p.b, p.a, "ancestor_of", nlohmann::json::object());

  auto all = s.list_relations(std::nullopt, std::nullopt,
                               ldb::store::RelationDir::kBoth);
  REQUIRE(all.size() == 3);
  CHECK(all[0].id == r1.id);
  CHECK(all[1].id == r2.id);
  CHECK(all[2].id == r3.id);
}
