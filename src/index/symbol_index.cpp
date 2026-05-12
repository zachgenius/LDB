// SPDX-License-Identifier: Apache-2.0
#include "index/symbol_index.h"

#include "backend/debugger_backend.h"  // backend::Error
#include "util/log.h"

#include <sqlite3.h>

#include <chrono>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <string>
#include <utility>

namespace ldb::index {

namespace {

namespace fs = std::filesystem;

[[noreturn]] void throw_sqlite(sqlite3* db, std::string_view ctx) {
  std::string msg = "symbol_index: sqlite: ";
  msg.append(ctx);
  msg.append(": ");
  msg.append(db ? sqlite3_errmsg(db) : "no db");
  throw backend::Error(std::move(msg));
}

class StmtGuard {
 public:
  StmtGuard() = default;
  explicit StmtGuard(sqlite3_stmt* s) : s_(s) {}
  ~StmtGuard() { if (s_) sqlite3_finalize(s_); }
  StmtGuard(const StmtGuard&)            = delete;
  StmtGuard& operator=(const StmtGuard&) = delete;
  StmtGuard(StmtGuard&& o) noexcept : s_(o.s_) { o.s_ = nullptr; }
  StmtGuard& operator=(StmtGuard&& o) noexcept {
    if (this != &o) { if (s_) sqlite3_finalize(s_); s_ = o.s_; o.s_ = nullptr; }
    return *this;
  }
  sqlite3_stmt* get() const { return s_; }
  sqlite3_stmt* operator->() const { return s_; }
 private:
  sqlite3_stmt* s_ = nullptr;
};

sqlite3_stmt* prepare(sqlite3* db, const char* sql) {
  sqlite3_stmt* st = nullptr;
  int rc = sqlite3_prepare_v2(db, sql, -1, &st, nullptr);
  if (rc != SQLITE_OK) throw_sqlite(db, "prepare");
  return st;
}

void exec(sqlite3* db, const char* sql) {
  char* err = nullptr;
  int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err);
  if (rc != SQLITE_OK) {
    std::string msg = err ? err : "unknown";
    if (err) sqlite3_free(err);
    throw backend::Error(std::string("symbol_index: exec: ") + msg);
  }
}

void bind_text(sqlite3_stmt* st, int idx, std::string_view s) {
  // SQLITE_TRANSIENT copies into sqlite-owned storage so a view of a
  // temporary survives statement execution.
  int rc = sqlite3_bind_text(st, idx, s.data(),
                              static_cast<int>(s.size()), SQLITE_TRANSIENT);
  if (rc != SQLITE_OK) throw_sqlite(sqlite3_db_handle(st), "bind_text");
}

void bind_int64(sqlite3_stmt* st, int idx, std::int64_t v) {
  int rc = sqlite3_bind_int64(st, idx, v);
  if (rc != SQLITE_OK) throw_sqlite(sqlite3_db_handle(st), "bind_int64");
}

void bind_null(sqlite3_stmt* st, int idx) {
  int rc = sqlite3_bind_null(st, idx);
  if (rc != SQLITE_OK) throw_sqlite(sqlite3_db_handle(st), "bind_null");
}

std::string col_text(sqlite3_stmt* st, int idx) {
  const unsigned char* p = sqlite3_column_text(st, idx);
  int n = sqlite3_column_bytes(st, idx);
  if (!p || n <= 0) return {};
  return std::string(reinterpret_cast<const char*>(p),
                     static_cast<std::size_t>(n));
}

std::int64_t now_ns() {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
             std::chrono::system_clock::now().time_since_epoch()).count();
}

// Note: filesystem mtime → ns is computed at the dispatcher site
// (fingerprint_for in dispatcher.cpp) so the conversion lives next to
// the only caller. Keeping the rule in two places would be invariant-
// breaking; one is enough.

}  // namespace

struct SymbolIndex::Impl {
  fs::path  root;
  fs::path  db_path;
  sqlite3*  db = nullptr;
  bool      ok = false;

  void ensure_schema();
  void wipe_and_recreate();
};

void SymbolIndex::Impl::ensure_schema() {
  // Read the on-disk version. Empty DB returns 0; mismatch with our
  // kSymbolIndexSchemaVersion forces a full wipe (cache is recoverable).
  int on_disk = 0;
  {
    sqlite3_stmt* raw = nullptr;
    if (sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &raw, nullptr)
        != SQLITE_OK) {
      throw_sqlite(db, "prepare user_version");
    }
    StmtGuard g(raw);
    if (sqlite3_step(raw) == SQLITE_ROW) {
      on_disk = sqlite3_column_int(raw, 0);
    }
  }
  if (on_disk != 0 && on_disk != kSymbolIndexSchemaVersion) {
    ::ldb::log::warn(
        "symbol_index: schema version " + std::to_string(on_disk)
        + " ≠ " + std::to_string(kSymbolIndexSchemaVersion)
        + "; dropping cache");
    wipe_and_recreate();
    return;
  }

  // Idempotent create. Reflects docs/23-symbol-index.md §3.1.
  exec(db, "PRAGMA foreign_keys=ON");
  exec(db,
       "CREATE TABLE IF NOT EXISTS binaries ("
       "  build_id      TEXT NOT NULL PRIMARY KEY,"
       "  path          TEXT NOT NULL,"
       "  file_mtime_ns INTEGER NOT NULL,"
       "  file_size     INTEGER NOT NULL,"
       "  arch          TEXT NOT NULL,"
       "  populated_at  INTEGER NOT NULL,"
       "  schema_ver    INTEGER NOT NULL"
       ")");
  exec(db,
       "CREATE TABLE IF NOT EXISTS symbols ("
       "  build_id      TEXT NOT NULL,"
       "  name          TEXT NOT NULL,"
       "  demangled     TEXT,"
       "  kind          TEXT NOT NULL,"
       "  address       INTEGER NOT NULL,"
       "  size          INTEGER NOT NULL,"
       "  module_path   TEXT NOT NULL,"
       "  source_file   TEXT,"
       "  source_line   INTEGER,"
       "  PRIMARY KEY (build_id, name, address),"
       "  FOREIGN KEY (build_id) REFERENCES binaries(build_id) "
       "    ON DELETE CASCADE"
       ")");
  exec(db,
       "CREATE INDEX IF NOT EXISTS symbols_by_demangled "
       "  ON symbols(build_id, demangled)");
  exec(db,
       "CREATE INDEX IF NOT EXISTS symbols_by_kind_addr "
       "  ON symbols(build_id, kind, address)");
  exec(db,
       "CREATE TABLE IF NOT EXISTS types ("
       "  build_id      TEXT NOT NULL,"
       "  name          TEXT NOT NULL,"
       "  byte_size     INTEGER NOT NULL,"
       "  members_json  TEXT NOT NULL,"
       "  PRIMARY KEY (build_id, name),"
       "  FOREIGN KEY (build_id) REFERENCES binaries(build_id) "
       "    ON DELETE CASCADE"
       ")");
  exec(db,
       "CREATE TABLE IF NOT EXISTS strings ("
       "  build_id      TEXT NOT NULL,"
       "  address       INTEGER NOT NULL,"
       "  text          TEXT NOT NULL,"
       "  section       TEXT NOT NULL,"
       "  PRIMARY KEY (build_id, address),"
       "  FOREIGN KEY (build_id) REFERENCES binaries(build_id) "
       "    ON DELETE CASCADE"
       ")");
  exec(db,
       "CREATE INDEX IF NOT EXISTS strings_by_text "
       "  ON strings(build_id, text)");

  if (on_disk == 0) {
    // Fresh DB: stamp the version. Use sprintf because PRAGMA
    // user_version doesn't accept a bound parameter.
    char buf[64];
    std::snprintf(buf, sizeof(buf), "PRAGMA user_version = %d",
                  kSymbolIndexSchemaVersion);
    exec(db, buf);
  }
}

void SymbolIndex::Impl::wipe_and_recreate() {
  exec(db, "DROP TABLE IF EXISTS symbols");
  exec(db, "DROP TABLE IF EXISTS types");
  exec(db, "DROP TABLE IF EXISTS strings");
  exec(db, "DROP TABLE IF EXISTS binaries");
  char buf[64];
  std::snprintf(buf, sizeof(buf), "PRAGMA user_version = %d",
                kSymbolIndexSchemaVersion);
  exec(db, buf);
  // Now build everything fresh via the same path.
  ensure_schema();
}

SymbolIndex::SymbolIndex(fs::path root)
    : impl_(std::make_unique<Impl>()) {
  impl_->root = std::move(root);
  impl_->db_path = impl_->root / "symbol_index.db";
  std::error_code ec;
  fs::create_directories(impl_->root, ec);
  // ec ignored — sqlite3_open_v2 will report a clearer error if the
  // directory really isn't usable.

  int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
  int rc = sqlite3_open_v2(impl_->db_path.c_str(), &impl_->db, flags,
                           nullptr);
  if (rc != SQLITE_OK) {
    // Sqlite hands back a handle even on most open failures so we can
    // read errmsg; close it before bailing.
    ::ldb::log::warn(
        std::string("symbol_index: sqlite3_open_v2 failed: ")
        + (impl_->db ? sqlite3_errmsg(impl_->db) : "no db"));
    if (impl_->db) sqlite3_close(impl_->db);
    impl_->db = nullptr;
    impl_->ok = false;
    return;
  }
  // PRAGMAs per docs/23 §3.2.
  exec(impl_->db, "PRAGMA journal_mode=WAL");
  exec(impl_->db, "PRAGMA synchronous=NORMAL");
  exec(impl_->db, "PRAGMA temp_store=MEMORY");
  exec(impl_->db, "PRAGMA cache_size=-65536");
  impl_->ensure_schema();
  impl_->ok = true;
}

SymbolIndex::~SymbolIndex() {
  if (impl_ && impl_->db) {
    sqlite3_close(impl_->db);
    impl_->db = nullptr;
  }
}

bool SymbolIndex::available() const noexcept {
  return impl_ && impl_->ok;
}

CacheStatus SymbolIndex::cache_status(std::string_view build_id,
                                       const FileFingerprint& file) {
  if (!available()) return CacheStatus::kMissing;
  StmtGuard st(prepare(impl_->db,
      "SELECT file_mtime_ns, file_size FROM binaries WHERE build_id = ?"));
  bind_text(st.get(), 1, build_id);
  int rc = sqlite3_step(st.get());
  if (rc == SQLITE_DONE) return CacheStatus::kMissing;
  if (rc != SQLITE_ROW) throw_sqlite(impl_->db, "cache_status step");
  std::int64_t mt = sqlite3_column_int64(st.get(), 0);
  std::int64_t sz = sqlite3_column_int64(st.get(), 1);
  if (mt != file.mtime_ns || sz != file.size) return CacheStatus::kStale;
  return CacheStatus::kHot;
}

std::optional<BinaryEntry>
SymbolIndex::get_binary(std::string_view build_id) {
  if (!available()) return std::nullopt;
  StmtGuard st(prepare(impl_->db,
      "SELECT build_id, path, file_mtime_ns, file_size, arch, "
      "       populated_at "
      "FROM binaries WHERE build_id = ?"));
  bind_text(st.get(), 1, build_id);
  int rc = sqlite3_step(st.get());
  if (rc == SQLITE_DONE) return std::nullopt;
  if (rc != SQLITE_ROW) throw_sqlite(impl_->db, "get_binary step");
  BinaryEntry e;
  e.build_id        = col_text(st.get(), 0);
  e.file.path       = col_text(st.get(), 1);
  e.file.mtime_ns   = sqlite3_column_int64(st.get(), 2);
  e.file.size       = sqlite3_column_int64(st.get(), 3);
  e.arch            = col_text(st.get(), 4);
  e.populated_at_ns = sqlite3_column_int64(st.get(), 5);
  return e;
}

void SymbolIndex::populate(const BinaryEntry&            entry,
                            const std::vector<SymbolRow>& symbols,
                            const std::vector<TypeRow>&   types,
                            const std::vector<StringRow>& strings) {
  if (!available()) {
    throw backend::Error("symbol_index: populate: index not available");
  }

  exec(impl_->db, "BEGIN IMMEDIATE");
  try {
    // Upsert binaries row. The CASCADE on the row-tables drops prior
    // symbols/types/strings; we re-issue the inserts below.
    {
      StmtGuard st(prepare(impl_->db,
          "DELETE FROM binaries WHERE build_id = ?"));
      bind_text(st.get(), 1, entry.build_id);
      if (sqlite3_step(st.get()) != SQLITE_DONE) {
        throw_sqlite(impl_->db, "populate: delete binaries");
      }
    }
    {
      StmtGuard st(prepare(impl_->db,
          "INSERT INTO binaries (build_id, path, file_mtime_ns, "
          "  file_size, arch, populated_at, schema_ver) "
          "VALUES (?,?,?,?,?,?,?)"));
      bind_text(st.get(),  1, entry.build_id);
      bind_text(st.get(),  2, entry.file.path);
      bind_int64(st.get(), 3, entry.file.mtime_ns);
      bind_int64(st.get(), 4, entry.file.size);
      bind_text(st.get(),  5, entry.arch);
      bind_int64(st.get(), 6, entry.populated_at_ns != 0
                              ? entry.populated_at_ns : now_ns());
      bind_int64(st.get(), 7, kSymbolIndexSchemaVersion);
      if (sqlite3_step(st.get()) != SQLITE_DONE) {
        throw_sqlite(impl_->db, "populate: insert binaries");
      }
    }

    if (!symbols.empty()) {
      StmtGuard st(prepare(impl_->db,
          "INSERT INTO symbols (build_id, name, demangled, kind, "
          "  address, size, module_path, source_file, source_line) "
          "VALUES (?,?,?,?,?,?,?,?,?)"));
      for (const auto& s : symbols) {
        sqlite3_reset(st.get());
        bind_text(st.get(),  1, entry.build_id);
        bind_text(st.get(),  2, s.name);
        if (s.demangled.empty()) bind_null(st.get(), 3);
        else                     bind_text(st.get(), 3, s.demangled);
        bind_text(st.get(),  4, s.kind);
        bind_int64(st.get(), 5, static_cast<std::int64_t>(s.address));
        bind_int64(st.get(), 6, static_cast<std::int64_t>(s.size));
        bind_text(st.get(),  7, s.module_path);
        if (s.source_file.empty()) bind_null(st.get(), 8);
        else                       bind_text(st.get(), 8, s.source_file);
        if (s.source_line == 0)    bind_null(st.get(), 9);
        else                       bind_int64(st.get(), 9, s.source_line);
        if (sqlite3_step(st.get()) != SQLITE_DONE) {
          throw_sqlite(impl_->db, "populate: insert symbols");
        }
      }
    }

    if (!types.empty()) {
      StmtGuard st(prepare(impl_->db,
          "INSERT INTO types (build_id, name, byte_size, members_json) "
          "VALUES (?,?,?,?)"));
      for (const auto& t : types) {
        sqlite3_reset(st.get());
        bind_text(st.get(),  1, entry.build_id);
        bind_text(st.get(),  2, t.name);
        bind_int64(st.get(), 3, static_cast<std::int64_t>(t.byte_size));
        bind_text(st.get(),  4, t.members.dump());
        if (sqlite3_step(st.get()) != SQLITE_DONE) {
          throw_sqlite(impl_->db, "populate: insert types");
        }
      }
    }

    if (!strings.empty()) {
      StmtGuard st(prepare(impl_->db,
          "INSERT INTO strings (build_id, address, text, section) "
          "VALUES (?,?,?,?)"));
      for (const auto& s : strings) {
        sqlite3_reset(st.get());
        bind_text(st.get(),  1, entry.build_id);
        bind_int64(st.get(), 2, static_cast<std::int64_t>(s.address));
        bind_text(st.get(),  3, s.text);
        bind_text(st.get(),  4, s.section);
        if (sqlite3_step(st.get()) != SQLITE_DONE) {
          throw_sqlite(impl_->db, "populate: insert strings");
        }
      }
    }

    exec(impl_->db, "COMMIT");
  } catch (...) {
    exec(impl_->db, "ROLLBACK");
    throw;
  }
}

std::vector<SymbolRow>
SymbolIndex::query_symbols(std::string_view build_id,
                            const SymbolQuery& q) {
  std::vector<SymbolRow> out;
  if (!available() || q.name.empty()) return out;
  // Match on either mangled or demangled with an optional kind filter.
  // Two ORs keep both indexes (PK on (build_id,name,address) and the
  // by-demangled index) usable.
  std::string sql =
      "SELECT name, demangled, kind, address, size, module_path, "
      "       source_file, source_line "
      "FROM symbols "
      "WHERE build_id = ? AND (name = ? OR demangled = ?)";
  if (!q.kind.empty()) sql += " AND kind = ?";
  sql += " ORDER BY address";
  StmtGuard st(prepare(impl_->db, sql.c_str()));
  bind_text(st.get(), 1, build_id);
  bind_text(st.get(), 2, q.name);
  bind_text(st.get(), 3, q.name);
  if (!q.kind.empty()) bind_text(st.get(), 4, q.kind);
  for (;;) {
    int rc = sqlite3_step(st.get());
    if (rc == SQLITE_DONE) break;
    if (rc != SQLITE_ROW) throw_sqlite(impl_->db, "query_symbols");
    SymbolRow r;
    r.name        = col_text(st.get(), 0);
    r.demangled   = col_text(st.get(), 1);
    r.kind        = col_text(st.get(), 2);
    r.address     = static_cast<std::uint64_t>(
                       sqlite3_column_int64(st.get(), 3));
    r.size        = static_cast<std::uint64_t>(
                       sqlite3_column_int64(st.get(), 4));
    r.module_path = col_text(st.get(), 5);
    r.source_file = col_text(st.get(), 6);
    r.source_line = sqlite3_column_int(st.get(), 7);
    out.push_back(std::move(r));
  }
  return out;
}

std::optional<TypeRow>
SymbolIndex::query_type(std::string_view build_id,
                         std::string_view name) {
  if (!available() || name.empty()) return std::nullopt;
  StmtGuard st(prepare(impl_->db,
      "SELECT name, byte_size, members_json FROM types "
      "WHERE build_id = ? AND name = ?"));
  bind_text(st.get(), 1, build_id);
  bind_text(st.get(), 2, name);
  int rc = sqlite3_step(st.get());
  if (rc == SQLITE_DONE) return std::nullopt;
  if (rc != SQLITE_ROW) throw_sqlite(impl_->db, "query_type");
  TypeRow t;
  t.name      = col_text(st.get(), 0);
  t.byte_size = static_cast<std::uint64_t>(
                  sqlite3_column_int64(st.get(), 1));
  std::string mj = col_text(st.get(), 2);
  try {
    t.members = nlohmann::json::parse(mj);
  } catch (const std::exception& e) {
    ::ldb::log::warn(std::string("symbol_index: corrupt members_json for ")
                    + std::string(name) + ": " + e.what());
    t.members = nlohmann::json::array();
  }
  return t;
}

std::vector<StringRow>
SymbolIndex::query_strings(std::string_view build_id,
                            const StringQuery& q) {
  std::vector<StringRow> out;
  if (!available() || q.text.empty()) return out;
  std::string sql =
      "SELECT address, text, section FROM strings "
      "WHERE build_id = ? AND ";
  std::string like_pattern;  // backing storage if we need it
  if (q.contains) {
    sql += "text LIKE ? ORDER BY address";
    like_pattern.reserve(q.text.size() + 2);
    like_pattern.push_back('%');
    like_pattern.append(q.text);
    like_pattern.push_back('%');
  } else {
    sql += "text = ? ORDER BY address";
  }
  StmtGuard st(prepare(impl_->db, sql.c_str()));
  bind_text(st.get(), 1, build_id);
  bind_text(st.get(), 2, q.contains ? std::string_view(like_pattern)
                                     : std::string_view(q.text));
  for (;;) {
    int rc = sqlite3_step(st.get());
    if (rc == SQLITE_DONE) break;
    if (rc != SQLITE_ROW) throw_sqlite(impl_->db, "query_strings");
    StringRow r;
    r.address = static_cast<std::uint64_t>(
                  sqlite3_column_int64(st.get(), 0));
    r.text    = col_text(st.get(), 1);
    r.section = col_text(st.get(), 2);
    out.push_back(std::move(r));
  }
  return out;
}

bool SymbolIndex::invalidate(std::string_view build_id) {
  if (!available()) return false;
  StmtGuard st(prepare(impl_->db,
      "DELETE FROM binaries WHERE build_id = ?"));
  bind_text(st.get(), 1, build_id);
  if (sqlite3_step(st.get()) != SQLITE_DONE) {
    throw_sqlite(impl_->db, "invalidate");
  }
  // ON DELETE CASCADE drops the rows in symbols/types/strings.
  return sqlite3_changes(impl_->db) > 0;
}

SymbolIndex::Stats SymbolIndex::stats() {
  Stats s;
  if (!available()) return s;
  auto count = [&](const char* sql) -> std::int64_t {
    StmtGuard st(prepare(impl_->db, sql));
    if (sqlite3_step(st.get()) != SQLITE_ROW) return 0;
    return sqlite3_column_int64(st.get(), 0);
  };
  s.binary_count = count("SELECT COUNT(*) FROM binaries");
  s.symbol_count = count("SELECT COUNT(*) FROM symbols");
  s.type_count   = count("SELECT COUNT(*) FROM types");
  s.string_count = count("SELECT COUNT(*) FROM strings");
  return s;
}

}  // namespace ldb::index
