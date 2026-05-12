// SPDX-License-Identifier: Apache-2.0
#pragma once

// Own symbol index — post-V1 plan #18 (docs/23-symbol-index.md).
//
// SQLite-backed cache of LLDB-derived symbols, types, and strings,
// keyed by build_id. Survives daemon restarts and is shared across
// targets that load the same binary. Today's correlate.* re-walks
// LLDB for every call; the index turns warm queries into sqlite
// SELECTs while leaving the wire shape unchanged.
//
// Lifetime / threading:
//   • One SymbolIndex per daemon, owned by the Dispatcher.
//   • Single-writer (population), many-reader (queries). PRAGMA WAL
//     so a future async dispatcher can read concurrently without
//     waiting on a population transaction.
//   • The class is NOT thread-safe today; the dispatcher's single-
//     threaded model is the locking discipline. Forward-compat:
//     wrap with std::shared_mutex when the runtime goes async.
//
// Failure model — the index is a cache:
//   • LDB_STORE_ROOT unset / sqlite open failure → callers treat as
//     "not available" and fall through to backend.
//   • Corrupted DB → wipe + restart cold; warned via util::log.
//   • Out-of-disk / write errors during populate → rollback;
//     caller falls through to backend, the cold-walk is paid again
//     on next call.
//
// Schema-version bump: drops all tables. The cache is recoverable
// from LLDB at worst-case cost; no in-place migrations.

#include <nlohmann/json.hpp>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ldb::index {

inline constexpr int kSymbolIndexSchemaVersion = 1;

// File / mtime / size tuple — the cache-invalidation key. Matches
// what `stat()` reports; the index records the values seen at
// population time and compares on every query.
struct FileFingerprint {
  std::string   path;
  std::int64_t  mtime_ns = 0;
  std::int64_t  size     = 0;
};

// One indexed binary. `populated_at` is unix-ns; useful for
// `index.stats` diagnostics.
struct BinaryEntry {
  std::string     build_id;
  FileFingerprint file;
  std::string     arch;
  std::int64_t    populated_at_ns = 0;
};

// Result of `cache_status()`. Drives whether the dispatcher uses the
// index or falls through.
enum class CacheStatus {
  // No row for this build_id at all — call populate() before query.
  kMissing = 0,
  // Row present but file mtime/size don't match — re-walk needed.
  kStale,
  // Row present and the on-disk file matches; queries are safe.
  kHot,
};

// Mirrors backend::SymbolHit closely. We keep our own struct here so
// the index can compile without dragging in lldb_backend.h.
struct SymbolRow {
  std::string   name;          // mangled
  std::string   demangled;     // empty when N/A
  std::string   kind;          // "function" | "data" | "other"
  std::uint64_t address = 0;   // file-relative
  std::uint64_t size    = 0;
  std::string   module_path;
  std::string   source_file;   // empty when unknown
  std::int32_t  source_line = 0;
};

// Mirrors backend::TypeLayout's wire shape. Members are stored as a
// JSON blob in sqlite (see design §3.1) and re-emitted by the
// dispatcher; we don't re-parse member-by-member.
struct TypeRow {
  std::string     name;
  std::uint64_t   byte_size = 0;
  nlohmann::json  members;     // array of member objects
};

struct StringRow {
  std::uint64_t   address = 0;
  std::string     text;
  std::string     section;     // e.g. ".rodata"
};

// Query knobs. Currently exact-name lookups + an optional substring
// match for strings. Mirrors what correlate.* exposes today.
struct SymbolQuery {
  std::string name;      // exact mangled OR exact demangled
  std::string kind;      // empty = any
};
struct StringQuery {
  // Match shape: exact text, or "contains" via SQL LIKE '%text%'.
  // The latter mirrors strings.list's `contains` knob.
  std::string text;
  bool        contains = false;
};

class SymbolIndex {
 public:
  // Open or create `${root}/symbol_index.db`. Throws backend::Error
  // on sqlite failure that isn't a missing-file (which we create).
  // Schema is brought up to kSymbolIndexSchemaVersion; mismatch
  // drops every table and restarts cold.
  explicit SymbolIndex(std::filesystem::path root);
  ~SymbolIndex();

  SymbolIndex(const SymbolIndex&)            = delete;
  SymbolIndex& operator=(const SymbolIndex&) = delete;

  // True after a successful open. Callers should fall through to the
  // backend when this is false (e.g. LDB_STORE_ROOT unset, sqlite
  // refused to open).
  bool available() const noexcept;

  // Cache key probe. `file` is the binary's current on-disk shape;
  // mismatch against the indexed shape returns kStale.
  CacheStatus cache_status(std::string_view       build_id,
                            const FileFingerprint& file);

  // Single binary lookup. Returns nullopt if not indexed.
  std::optional<BinaryEntry> get_binary(std::string_view build_id);

  // Bulk population. The caller (typically the dispatcher) supplies
  // the rows it harvested from the backend. populate() opens a
  // transaction, replaces every row keyed by build_id, upserts the
  // binaries row with the supplied file fingerprint + arch +
  // populated_at. Throws backend::Error on sqlite failure.
  void populate(const BinaryEntry&            entry,
                const std::vector<SymbolRow>& symbols,
                const std::vector<TypeRow>&   types,
                const std::vector<StringRow>& strings);

  // Read paths. Each returns an empty container when build_id is
  // unindexed; callers MUST consult cache_status() before relying
  // on these for correctness.
  std::vector<SymbolRow> query_symbols(std::string_view   build_id,
                                        const SymbolQuery& q);
  std::optional<TypeRow> query_type(std::string_view build_id,
                                     std::string_view name);
  std::vector<StringRow> query_strings(std::string_view   build_id,
                                        const StringQuery& q);

  // Drop everything for this build_id. The dispatcher exposes this
  // via `index.invalidate` (phase-2 endpoint). Returns true if a row
  // was present.
  bool invalidate(std::string_view build_id);

  // Operator-facing diagnostics. Useful for `index.stats` (phase-2).
  struct Stats {
    std::int64_t binary_count  = 0;
    std::int64_t symbol_count  = 0;
    std::int64_t type_count    = 0;
    std::int64_t string_count  = 0;
  };
  Stats stats();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace ldb::index
