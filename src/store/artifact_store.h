#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Build-ID-keyed, sqlite-indexed, on-disk store for binary blobs the
// agent has captured (memory dumps, decoded payloads, etc.).
//
// Layout (per docs/02-ldb-mvp-plan.md §8):
//
//   ${root}/
//   ├── index.db                       sqlite: artifacts, tags
//   └── builds/
//       └── <build-id>/
//           └── artifacts/
//               └── <artifact-id>      content blob
//
// Schema:
//
//   artifacts(id INTEGER PK, build_id TEXT, name TEXT, sha256 TEXT,
//             byte_size INTEGER, format TEXT?, meta TEXT(JSON),
//             created_at INTEGER, stored_path TEXT,
//             UNIQUE(build_id, name))
//   artifact_tags(artifact_id, tag, PRIMARY KEY(artifact_id, tag),
//                 FOREIGN KEY(artifact_id) ON DELETE CASCADE)
//
// Contracts:
//   • (build_id, name) is unique. put() with an existing pair *replaces*
//     the prior entry: the old blob file is unlinked, the row deleted,
//     and a fresh row inserted (so the artifact id changes — DELETE +
//     INSERT, not UPDATE).
//   • read_blob throws backend::Error if the on-disk blob is missing
//     (corrupt store / out-of-band rm).
//   • Wraps sqlite errors as backend::Error with the sqlite errmsg as
//     the message; the dispatcher maps this to JSON-RPC -32000.
//   • The store opens the db in WAL mode so a future read-side path
//     (probes / sessions) can read concurrently with writes. WAL is
//     bog-standard for the project per plan §3.4.

namespace ldb::store {

struct ArtifactRow {
  std::int64_t                 id          = 0;
  std::string                  build_id;
  std::string                  name;
  std::string                  sha256;       // 64-char lower-hex
  std::uint64_t                byte_size   = 0;
  std::optional<std::string>   format;
  nlohmann::json               meta = nlohmann::json::object();
  std::vector<std::string>     tags;         // unsorted; sort at the seam
  std::int64_t                 created_at  = 0;   // unix epoch seconds
  std::string                  stored_path;       // absolute path to blob
};

class ArtifactStore {
 public:
  // Open (or create) a store rooted at [root]. Creates intermediate
  // directories, opens / migrates index.db, sets WAL.
  // Throws backend::Error on filesystem or sqlite failure.
  explicit ArtifactStore(std::filesystem::path root);
  ~ArtifactStore();

  ArtifactStore(const ArtifactStore&)            = delete;
  ArtifactStore& operator=(const ArtifactStore&) = delete;
  ArtifactStore(ArtifactStore&&) noexcept;
  ArtifactStore& operator=(ArtifactStore&&) noexcept;

  // Insert (or replace) an artifact. The blob file is written first to
  // a temp path under the destination directory, then atomically renamed
  // into place; a prior file at the same (build_id, name) is unlinked.
  ArtifactRow put(std::string_view build_id,
                  std::string_view name,
                  const std::vector<std::uint8_t>& bytes,
                  std::optional<std::string> format,
                  const nlohmann::json& meta);

  // Lookup. Returns nullopt for "not found"; only sqlite errors throw.
  std::optional<ArtifactRow> get_by_id(std::int64_t id);
  std::optional<ArtifactRow> get_by_name(std::string_view build_id,
                                          std::string_view name);

  // Read the blob from disk. max_bytes=0 means no cap; otherwise return
  // the first min(byte_size, max_bytes) bytes. Throws backend::Error on
  // any filesystem failure (including missing file).
  std::vector<std::uint8_t> read_blob(const ArtifactRow& row,
                                       std::uint64_t max_bytes = 0);

  // List rows, optionally filtered by exact build_id and/or name LIKE
  // pattern. The pattern is sqlite LIKE: '%' = multi-char, '_' = single-
  // char. Sorted by id ASC for stability across calls.
  std::vector<ArtifactRow> list(std::optional<std::string> build_id,
                                 std::optional<std::string> name_pattern);

  // Add tags to an existing artifact. Returns the resulting full tag
  // set (post-add). Existing tags are preserved; duplicates are no-ops.
  // Throws backend::Error if [id] doesn't exist.
  std::vector<std::string> add_tags(std::int64_t id,
                                     const std::vector<std::string>& tags);

  // Import an artifact from a `.ldbpack` archive (M5 part 5). Bypasses
  // the hashing + timestamp behavior of put() — the supplied [sha256]
  // and [created_at] are used verbatim, the supplied [tags] are
  // attached. If a row already exists for (build_id, name) and
  // [overwrite] is false, throws; if true, the prior row + blob are
  // replaced. Returns the new row.
  ArtifactRow import_artifact(std::string_view build_id,
                              std::string_view name,
                              const std::vector<std::uint8_t>& bytes,
                              std::string_view sha256,
                              std::optional<std::string> format,
                              const nlohmann::json& meta,
                              const std::vector<std::string>& tags,
                              std::int64_t created_at,
                              bool overwrite);

  // Resolve the configured store root (post-canonicalization). Useful
  // for tests and the --help output.
  const std::filesystem::path& root() const noexcept;

  // Forward-declared opaque impl (sqlite handle, mutex, root path).
  // Public-by-name only because the .cpp's anonymous-namespace helpers
  // need to take it by reference; nothing outside the .cpp uses it.
  struct Impl;

 private:
  std::unique_ptr<Impl> impl_;
};

}  // namespace ldb::store
