#include "store/artifact_store.h"

#include "backend/debugger_backend.h"
#include "util/sha256.h"

#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

// SHA-256 has lived inside this TU since M3. As of M5 part 6 the
// implementation moved to src/util/sha256.{h,cpp} so the cores-only
// `_provenance.snapshot` (target.load_core) can hash files through the
// same code path; we re-export sha256_hex into ldb::store anonymous
// scope so existing call sites stay unchanged.

namespace ldb::store {

namespace {

using ::ldb::util::sha256_hex;

[[noreturn]] void throw_sqlite(sqlite3* db, std::string_view ctx) {
  std::string msg = "sqlite: ";
  msg.append(ctx);
  msg.append(": ");
  msg.append(db ? sqlite3_errmsg(db) : "no db");
  throw backend::Error(msg);
}

[[noreturn]] void throw_io(std::string_view what, const std::error_code& ec) {
  std::string m = "store io: ";
  m.append(what);
  m.append(": ");
  m.append(ec.message());
  throw backend::Error(m);
}

class StmtGuard {
 public:
  StmtGuard() = default;
  explicit StmtGuard(sqlite3_stmt* s) : s_(s) {}
  ~StmtGuard() { if (s_) sqlite3_finalize(s_); }
  StmtGuard(const StmtGuard&) = delete;
  StmtGuard& operator=(const StmtGuard&) = delete;
  StmtGuard(StmtGuard&& o) noexcept : s_(o.s_) { o.s_ = nullptr; }
  StmtGuard& operator=(StmtGuard&& o) noexcept {
    if (this != &o) { if (s_) sqlite3_finalize(s_); s_ = o.s_; o.s_ = nullptr; }
    return *this;
  }
  sqlite3_stmt* get() const { return s_; }
 private:
  sqlite3_stmt* s_ = nullptr;
};

}  // namespace

// ----------------------------------------------------------------------------

struct ArtifactStore::Impl {
  std::filesystem::path root;
  sqlite3*              db = nullptr;
  // Single-process serialization. The store itself is fine concurrent
  // (WAL), but we hold a mutex to keep multi-statement put() atomic at
  // the C++ layer — the caller can hand the same store to multiple
  // dispatcher threads in M3+ without surprises.
  std::mutex            mu;

  ~Impl() {
    if (db) sqlite3_close(db);
  }

  void exec(const char* sql) {
    char* err = nullptr;
    int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
      std::string m = "sqlite exec: ";
      m.append(err ? err : sqlite3_errmsg(db));
      sqlite3_free(err);
      throw backend::Error(m);
    }
  }

  StmtGuard prepare(std::string_view sql) {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, sql.data(),
                                static_cast<int>(sql.size()), &stmt, nullptr);
    if (rc != SQLITE_OK) throw_sqlite(db, "prepare");
    return StmtGuard{stmt};
  }
};

namespace {

void migrate(ArtifactStore::Impl& I) {
  I.exec("PRAGMA journal_mode=WAL;");
  I.exec("PRAGMA synchronous=NORMAL;");
  I.exec("PRAGMA foreign_keys=ON;");
  I.exec(
    "CREATE TABLE IF NOT EXISTS artifacts("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  build_id TEXT NOT NULL,"
    "  name TEXT NOT NULL,"
    "  sha256 TEXT NOT NULL,"
    "  byte_size INTEGER NOT NULL,"
    "  format TEXT,"
    "  meta TEXT,"
    "  created_at INTEGER NOT NULL,"
    "  stored_path TEXT NOT NULL,"
    "  UNIQUE(build_id, name)"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_art_build ON artifacts(build_id);"
    "CREATE INDEX IF NOT EXISTS idx_art_name  ON artifacts(name);"
    "CREATE TABLE IF NOT EXISTS artifact_tags("
    "  artifact_id INTEGER NOT NULL,"
    "  tag TEXT NOT NULL,"
    "  PRIMARY KEY(artifact_id, tag),"
    "  FOREIGN KEY(artifact_id) REFERENCES artifacts(id) ON DELETE CASCADE"
    ");"
  );
}

std::vector<std::string> tags_for(ArtifactStore::Impl& I, std::int64_t id) {
  auto stmt = I.prepare(
      "SELECT tag FROM artifact_tags WHERE artifact_id = ?1 ORDER BY tag;");
  sqlite3_bind_int64(stmt.get(), 1, id);
  std::vector<std::string> out;
  for (;;) {
    int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_DONE) break;
    if (rc != SQLITE_ROW) throw_sqlite(I.db, "tags step");
    auto t = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
    out.emplace_back(t ? t : "");
  }
  return out;
}

ArtifactRow row_from_stmt(ArtifactStore::Impl& I, sqlite3_stmt* s) {
  ArtifactRow r;
  r.id          = sqlite3_column_int64(s, 0);
  auto bid      = reinterpret_cast<const char*>(sqlite3_column_text(s, 1));
  auto nm       = reinterpret_cast<const char*>(sqlite3_column_text(s, 2));
  auto sh       = reinterpret_cast<const char*>(sqlite3_column_text(s, 3));
  r.build_id    = bid ? bid : "";
  r.name        = nm  ? nm  : "";
  r.sha256      = sh  ? sh  : "";
  r.byte_size   = static_cast<std::uint64_t>(sqlite3_column_int64(s, 4));
  if (sqlite3_column_type(s, 5) != SQLITE_NULL) {
    auto fmt = reinterpret_cast<const char*>(sqlite3_column_text(s, 5));
    if (fmt) r.format = std::string(fmt);
  }
  if (sqlite3_column_type(s, 6) != SQLITE_NULL) {
    auto m = reinterpret_cast<const char*>(sqlite3_column_text(s, 6));
    if (m && *m) {
      try { r.meta = nlohmann::json::parse(m); }
      catch (const std::exception&) { r.meta = nlohmann::json::object(); }
    }
  }
  r.created_at  = sqlite3_column_int64(s, 7);
  auto sp       = reinterpret_cast<const char*>(sqlite3_column_text(s, 8));
  r.stored_path = sp ? sp : "";
  r.tags        = tags_for(I, r.id);
  return r;
}

constexpr const char* kSelectCols =
    "id, build_id, name, sha256, byte_size, format, meta, "
    "created_at, stored_path";

void write_blob_atomic(const std::filesystem::path& dest,
                       const std::vector<std::uint8_t>& bytes) {
  namespace fs = std::filesystem;
  std::error_code ec;
  fs::create_directories(dest.parent_path(), ec);
  if (ec) throw_io("create_directories", ec);

  // Write to a sibling temp file, then rename. Avoids torn writes if
  // we crash mid-write; rename(2) is atomic on the same filesystem.
  fs::path tmp = dest;
  tmp += ".tmp";
  {
    std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
    if (!out) {
      throw backend::Error("store io: open temp blob: " + tmp.string());
    }
    if (!bytes.empty()) {
      out.write(reinterpret_cast<const char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
    }
    out.flush();
    if (!out) throw backend::Error("store io: write blob: " + tmp.string());
  }
  fs::rename(tmp, dest, ec);
  if (ec) {
    std::error_code ignore;
    fs::remove(tmp, ignore);  // best-effort cleanup
    throw_io("rename blob", ec);
  }
}

}  // namespace

// ----------------------------------------------------------------------------

ArtifactStore::ArtifactStore(std::filesystem::path root)
    : impl_(std::make_unique<Impl>()) {
  namespace fs = std::filesystem;
  std::error_code ec;
  fs::create_directories(root, ec);
  if (ec) throw_io("create_directories(root)", ec);
  fs::create_directories(root / "builds", ec);
  if (ec) throw_io("create_directories(root/builds)", ec);
  impl_->root = fs::absolute(root, ec);
  if (ec) impl_->root = root;  // best-effort; relative still works

  fs::path db_path = impl_->root / "index.db";
  int rc = sqlite3_open(db_path.c_str(), &impl_->db);
  if (rc != SQLITE_OK) {
    std::string m = "sqlite open ";
    m.append(db_path.string());
    m.append(": ");
    m.append(impl_->db ? sqlite3_errmsg(impl_->db) : sqlite3_errstr(rc));
    if (impl_->db) sqlite3_close(impl_->db);
    impl_->db = nullptr;
    throw backend::Error(m);
  }
  // Treat sqlite errors as our error type via Impl::exec.
  migrate(*impl_);
}

ArtifactStore::~ArtifactStore() = default;
ArtifactStore::ArtifactStore(ArtifactStore&&) noexcept = default;
ArtifactStore& ArtifactStore::operator=(ArtifactStore&&) noexcept = default;

const std::filesystem::path& ArtifactStore::root() const noexcept {
  return impl_->root;
}

ArtifactRow ArtifactStore::put(std::string_view build_id,
                               std::string_view name,
                               const std::vector<std::uint8_t>& bytes,
                               std::optional<std::string> format,
                               const nlohmann::json& meta) {
  namespace fs = std::filesystem;
  std::lock_guard<std::mutex> lk(impl_->mu);

  // 1. If a prior row exists for (build_id, name), grab its stored_path
  //    (so we can unlink the stale file) and DELETE it. ON DELETE CASCADE
  //    drops its tags too.
  std::string old_path;
  {
    auto sel = impl_->prepare(
        "SELECT stored_path FROM artifacts "
        "WHERE build_id = ?1 AND name = ?2;");
    sqlite3_bind_text(sel.get(), 1, build_id.data(),
                      static_cast<int>(build_id.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(sel.get(), 2, name.data(),
                      static_cast<int>(name.size()), SQLITE_TRANSIENT);
    int rc = sqlite3_step(sel.get());
    if (rc == SQLITE_ROW) {
      auto sp = reinterpret_cast<const char*>(
          sqlite3_column_text(sel.get(), 0));
      if (sp) old_path = sp;
    } else if (rc != SQLITE_DONE) {
      throw_sqlite(impl_->db, "put: select prior");
    }
  }
  if (!old_path.empty()) {
    auto del = impl_->prepare(
        "DELETE FROM artifacts WHERE build_id = ?1 AND name = ?2;");
    sqlite3_bind_text(del.get(), 1, build_id.data(),
                      static_cast<int>(build_id.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(del.get(), 2, name.data(),
                      static_cast<int>(name.size()), SQLITE_TRANSIENT);
    if (sqlite3_step(del.get()) != SQLITE_DONE) {
      throw_sqlite(impl_->db, "put: delete prior");
    }
    std::error_code ec;
    fs::remove(old_path, ec);  // best-effort: file may be gone already
  }

  // 2. Insert the row. We need the new id to compute stored_path; insert
  //    with a placeholder, fetch the rowid, then UPDATE the path. (We
  //    can't pre-allocate the id; sqlite assigns autoincrement on insert.)
  auto sha   = sha256_hex(bytes);
  auto now   = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
  std::string fmt_str = format.value_or("");
  std::string meta_str = meta.is_null() ? std::string("{}") : meta.dump();

  std::int64_t new_id = 0;
  {
    auto ins = impl_->prepare(
        "INSERT INTO artifacts(build_id, name, sha256, byte_size, format, "
        "                      meta, created_at, stored_path) "
        "VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, '');");
    sqlite3_bind_text(ins.get(), 1, build_id.data(),
                      static_cast<int>(build_id.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(ins.get(), 2, name.data(),
                      static_cast<int>(name.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(ins.get(), 3, sha.c_str(),
                      static_cast<int>(sha.size()), SQLITE_TRANSIENT);
    sqlite3_bind_int64(ins.get(), 4,
                       static_cast<sqlite3_int64>(bytes.size()));
    if (format.has_value()) {
      sqlite3_bind_text(ins.get(), 5, fmt_str.c_str(),
                        static_cast<int>(fmt_str.size()), SQLITE_TRANSIENT);
    } else {
      sqlite3_bind_null(ins.get(), 5);
    }
    sqlite3_bind_text(ins.get(), 6, meta_str.c_str(),
                      static_cast<int>(meta_str.size()), SQLITE_TRANSIENT);
    sqlite3_bind_int64(ins.get(), 7, static_cast<sqlite3_int64>(now));
    if (sqlite3_step(ins.get()) != SQLITE_DONE) {
      throw_sqlite(impl_->db, "put: insert");
    }
    new_id = sqlite3_last_insert_rowid(impl_->db);
  }

  // 3. Compute the canonical path and write the blob to disk.
  fs::path blob = impl_->root / "builds" / std::string(build_id)
                                / "artifacts" / std::to_string(new_id);
  write_blob_atomic(blob, bytes);

  // 4. Patch the stored_path now that we have the canonical location.
  {
    auto upd = impl_->prepare(
        "UPDATE artifacts SET stored_path = ?1 WHERE id = ?2;");
    auto p = blob.string();
    sqlite3_bind_text(upd.get(), 1, p.c_str(),
                      static_cast<int>(p.size()), SQLITE_TRANSIENT);
    sqlite3_bind_int64(upd.get(), 2, new_id);
    if (sqlite3_step(upd.get()) != SQLITE_DONE) {
      throw_sqlite(impl_->db, "put: update stored_path");
    }
  }

  ArtifactRow r;
  r.id          = new_id;
  r.build_id    = std::string(build_id);
  r.name        = std::string(name);
  r.sha256      = std::move(sha);
  r.byte_size   = bytes.size();
  r.format      = std::move(format);
  r.meta        = meta.is_null() ? nlohmann::json::object() : meta;
  r.created_at  = static_cast<std::int64_t>(now);
  r.stored_path = blob.string();
  return r;
}

std::optional<ArtifactRow> ArtifactStore::get_by_id(std::int64_t id) {
  std::lock_guard<std::mutex> lk(impl_->mu);
  std::string sql = std::string("SELECT ") + kSelectCols +
                    " FROM artifacts WHERE id = ?1;";
  auto stmt = impl_->prepare(sql);
  sqlite3_bind_int64(stmt.get(), 1, id);
  int rc = sqlite3_step(stmt.get());
  if (rc == SQLITE_DONE) return std::nullopt;
  if (rc != SQLITE_ROW) throw_sqlite(impl_->db, "get_by_id");
  return row_from_stmt(*impl_, stmt.get());
}

std::optional<ArtifactRow>
ArtifactStore::get_by_name(std::string_view build_id, std::string_view name) {
  std::lock_guard<std::mutex> lk(impl_->mu);
  std::string sql = std::string("SELECT ") + kSelectCols +
                    " FROM artifacts WHERE build_id = ?1 AND name = ?2;";
  auto stmt = impl_->prepare(sql);
  sqlite3_bind_text(stmt.get(), 1, build_id.data(),
                    static_cast<int>(build_id.size()), SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt.get(), 2, name.data(),
                    static_cast<int>(name.size()), SQLITE_TRANSIENT);
  int rc = sqlite3_step(stmt.get());
  if (rc == SQLITE_DONE) return std::nullopt;
  if (rc != SQLITE_ROW) throw_sqlite(impl_->db, "get_by_name");
  return row_from_stmt(*impl_, stmt.get());
}

std::vector<std::uint8_t>
ArtifactStore::read_blob(const ArtifactRow& row, std::uint64_t max_bytes) {
  // No mutex: file IO doesn't touch sqlite. The on-disk blob is content-
  // addressed-named (id is monotonic) so a concurrent put() can't
  // clobber it — only a same-(build_id,name) replace would, and the
  // caller already has the row.
  std::ifstream in(row.stored_path, std::ios::binary);
  if (!in) {
    throw backend::Error("store io: open blob: " + row.stored_path);
  }
  std::uint64_t cap = (max_bytes == 0) ? row.byte_size
                                       : std::min<std::uint64_t>(max_bytes,
                                                                 row.byte_size);
  std::vector<std::uint8_t> out;
  out.resize(static_cast<std::size_t>(cap));
  if (cap > 0) {
    in.read(reinterpret_cast<char*>(out.data()),
            static_cast<std::streamsize>(cap));
    auto got = in.gcount();
    if (got < 0) {
      throw backend::Error("store io: read blob: " + row.stored_path);
    }
    out.resize(static_cast<std::size_t>(got));
  }
  return out;
}

std::vector<ArtifactRow>
ArtifactStore::list(std::optional<std::string> build_id,
                    std::optional<std::string> name_pattern) {
  std::lock_guard<std::mutex> lk(impl_->mu);
  std::string sql = std::string("SELECT ") + kSelectCols + " FROM artifacts";
  std::vector<std::string> clauses;
  if (build_id.has_value())     clauses.emplace_back("build_id = ?");
  if (name_pattern.has_value()) clauses.emplace_back("name LIKE ?");
  if (!clauses.empty()) {
    sql += " WHERE ";
    for (std::size_t i = 0; i < clauses.size(); ++i) {
      if (i) sql += " AND ";
      sql += clauses[i];
    }
  }
  sql += " ORDER BY id ASC;";
  auto stmt = impl_->prepare(sql);

  int idx = 1;
  if (build_id.has_value()) {
    sqlite3_bind_text(stmt.get(), idx++, build_id->c_str(),
                      static_cast<int>(build_id->size()), SQLITE_TRANSIENT);
  }
  if (name_pattern.has_value()) {
    sqlite3_bind_text(stmt.get(), idx++, name_pattern->c_str(),
                      static_cast<int>(name_pattern->size()), SQLITE_TRANSIENT);
  }

  std::vector<ArtifactRow> out;
  for (;;) {
    int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_DONE) break;
    if (rc != SQLITE_ROW) throw_sqlite(impl_->db, "list step");
    out.push_back(row_from_stmt(*impl_, stmt.get()));
  }
  return out;
}

ArtifactRow
ArtifactStore::import_artifact(std::string_view build_id,
                               std::string_view name,
                               const std::vector<std::uint8_t>& bytes,
                               std::string_view sha256,
                               std::optional<std::string> format,
                               const nlohmann::json& meta,
                               const std::vector<std::string>& tags,
                               std::int64_t created_at,
                               bool overwrite) {
  namespace fs = std::filesystem;
  std::lock_guard<std::mutex> lk(impl_->mu);

  // Conflict check.
  std::string existing_path;
  bool exists = false;
  {
    auto sel = impl_->prepare(
        "SELECT stored_path FROM artifacts "
        "WHERE build_id = ?1 AND name = ?2;");
    sqlite3_bind_text(sel.get(), 1, build_id.data(),
                      static_cast<int>(build_id.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(sel.get(), 2, name.data(),
                      static_cast<int>(name.size()), SQLITE_TRANSIENT);
    int rc = sqlite3_step(sel.get());
    if (rc == SQLITE_ROW) {
      exists = true;
      auto sp = reinterpret_cast<const char*>(
          sqlite3_column_text(sel.get(), 0));
      if (sp) existing_path = sp;
    } else if (rc != SQLITE_DONE) {
      throw_sqlite(impl_->db, "import_artifact: pre-check");
    }
  }
  if (exists && !overwrite) {
    throw backend::Error("artifact_store.import_artifact: already exists: "
                         + std::string(build_id) + "/" + std::string(name));
  }
  if (exists) {
    auto del = impl_->prepare(
        "DELETE FROM artifacts WHERE build_id = ?1 AND name = ?2;");
    sqlite3_bind_text(del.get(), 1, build_id.data(),
                      static_cast<int>(build_id.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(del.get(), 2, name.data(),
                      static_cast<int>(name.size()), SQLITE_TRANSIENT);
    if (sqlite3_step(del.get()) != SQLITE_DONE) {
      throw_sqlite(impl_->db, "import_artifact: delete prior");
    }
    std::error_code ec;
    if (!existing_path.empty()) fs::remove(existing_path, ec);
  }

  // sha256 may be empty if the producer didn't declare it; recompute
  // in that case so the new row carries something meaningful.
  std::string sha;
  if (!sha256.empty()) {
    sha = std::string(sha256);
  } else {
    sha = sha256_hex(bytes);
  }
  std::string fmt_str  = format.value_or("");
  std::string meta_str = meta.is_null() ? std::string("{}") : meta.dump();

  std::int64_t new_id = 0;
  {
    auto ins = impl_->prepare(
        "INSERT INTO artifacts(build_id, name, sha256, byte_size, format, "
        "                      meta, created_at, stored_path) "
        "VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, '');");
    sqlite3_bind_text(ins.get(), 1, build_id.data(),
                      static_cast<int>(build_id.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(ins.get(), 2, name.data(),
                      static_cast<int>(name.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(ins.get(), 3, sha.c_str(),
                      static_cast<int>(sha.size()), SQLITE_TRANSIENT);
    sqlite3_bind_int64(ins.get(), 4,
                       static_cast<sqlite3_int64>(bytes.size()));
    if (format.has_value()) {
      sqlite3_bind_text(ins.get(), 5, fmt_str.c_str(),
                        static_cast<int>(fmt_str.size()), SQLITE_TRANSIENT);
    } else {
      sqlite3_bind_null(ins.get(), 5);
    }
    sqlite3_bind_text(ins.get(), 6, meta_str.c_str(),
                      static_cast<int>(meta_str.size()), SQLITE_TRANSIENT);
    sqlite3_bind_int64(ins.get(), 7, static_cast<sqlite3_int64>(created_at));
    if (sqlite3_step(ins.get()) != SQLITE_DONE) {
      throw_sqlite(impl_->db, "import_artifact: insert");
    }
    new_id = sqlite3_last_insert_rowid(impl_->db);
  }

  fs::path blob = impl_->root / "builds" / std::string(build_id)
                                / "artifacts" / std::to_string(new_id);
  write_blob_atomic(blob, bytes);

  {
    auto upd = impl_->prepare(
        "UPDATE artifacts SET stored_path = ?1 WHERE id = ?2;");
    auto p = blob.string();
    sqlite3_bind_text(upd.get(), 1, p.c_str(),
                      static_cast<int>(p.size()), SQLITE_TRANSIENT);
    sqlite3_bind_int64(upd.get(), 2, new_id);
    if (sqlite3_step(upd.get()) != SQLITE_DONE) {
      throw_sqlite(impl_->db, "import_artifact: update stored_path");
    }
  }

  // Tags — same INSERT OR IGNORE pattern as add_tags().
  if (!tags.empty()) {
    auto ins = impl_->prepare(
        "INSERT OR IGNORE INTO artifact_tags(artifact_id, tag) "
        "VALUES(?1, ?2);");
    for (const auto& t : tags) {
      sqlite3_reset(ins.get());
      sqlite3_clear_bindings(ins.get());
      sqlite3_bind_int64(ins.get(), 1, new_id);
      sqlite3_bind_text(ins.get(), 2, t.c_str(),
                        static_cast<int>(t.size()), SQLITE_TRANSIENT);
      if (sqlite3_step(ins.get()) != SQLITE_DONE) {
        throw_sqlite(impl_->db, "import_artifact: tag insert");
      }
    }
  }

  ArtifactRow r;
  r.id          = new_id;
  r.build_id    = std::string(build_id);
  r.name        = std::string(name);
  r.sha256      = std::move(sha);
  r.byte_size   = bytes.size();
  r.format      = std::move(format);
  r.meta        = meta.is_null() ? nlohmann::json::object() : meta;
  r.tags        = tags;
  r.created_at  = created_at;
  r.stored_path = blob.string();
  return r;
}

bool ArtifactStore::remove(std::int64_t id) {
  namespace fs = std::filesystem;
  std::lock_guard<std::mutex> lk(impl_->mu);

  // Capture stored_path (so we can unlink the blob) and verify the row
  // exists in one shot. If absent, return false — idempotent semantics
  // for the recipe.delete caller.
  std::string stored_path;
  bool exists = false;
  {
    auto sel = impl_->prepare(
        "SELECT stored_path FROM artifacts WHERE id = ?1;");
    sqlite3_bind_int64(sel.get(), 1, id);
    int rc = sqlite3_step(sel.get());
    if (rc == SQLITE_ROW) {
      exists = true;
      auto sp = reinterpret_cast<const char*>(
          sqlite3_column_text(sel.get(), 0));
      if (sp) stored_path = sp;
    } else if (rc != SQLITE_DONE) {
      throw_sqlite(impl_->db, "remove: select");
    }
  }
  if (!exists) return false;

  // Delete the index row first; ON DELETE CASCADE drops artifact_tags.
  // Only after the row is gone do we unlink the blob — if the unlink
  // fails (e.g. permissions), the blob may dangle but the index is
  // consistent and a future remove() / put() can recover.
  {
    auto del = impl_->prepare("DELETE FROM artifacts WHERE id = ?1;");
    sqlite3_bind_int64(del.get(), 1, id);
    if (sqlite3_step(del.get()) != SQLITE_DONE) {
      throw_sqlite(impl_->db, "remove: delete");
    }
  }
  if (!stored_path.empty()) {
    std::error_code ec;
    fs::remove(stored_path, ec);
    // Best-effort: a missing file is fine (caller may have rm'd it).
  }
  return true;
}

std::vector<std::string>
ArtifactStore::add_tags(std::int64_t id,
                        const std::vector<std::string>& tags) {
  std::lock_guard<std::mutex> lk(impl_->mu);

  // Verify the artifact exists; otherwise add_tags would silently no-op
  // because INSERT OR IGNORE doesn't enforce FK presence (FKs only fire
  // on INSERTs that conflict with non-existent parents — depends on
  // sqlite version). Be explicit.
  {
    auto chk = impl_->prepare("SELECT 1 FROM artifacts WHERE id = ?1;");
    sqlite3_bind_int64(chk.get(), 1, id);
    int rc = sqlite3_step(chk.get());
    if (rc == SQLITE_DONE) {
      throw backend::Error("artifact_store.add_tags: no such id: " +
                           std::to_string(id));
    }
    if (rc != SQLITE_ROW) throw_sqlite(impl_->db, "add_tags: id check");
  }

  // INSERT OR IGNORE silently drops dup-key violations — that's the
  // idempotent path. Wrap in a single transaction for atomicity.
  impl_->exec("BEGIN IMMEDIATE;");
  try {
    auto ins = impl_->prepare(
        "INSERT OR IGNORE INTO artifact_tags(artifact_id, tag) "
        "VALUES(?1, ?2);");
    for (const auto& t : tags) {
      sqlite3_reset(ins.get());
      sqlite3_clear_bindings(ins.get());
      sqlite3_bind_int64(ins.get(), 1, id);
      sqlite3_bind_text(ins.get(), 2, t.c_str(),
                        static_cast<int>(t.size()), SQLITE_TRANSIENT);
      int rc = sqlite3_step(ins.get());
      if (rc != SQLITE_DONE) throw_sqlite(impl_->db, "add_tags: insert");
    }
    impl_->exec("COMMIT;");
  } catch (...) {
    impl_->exec("ROLLBACK;");
    throw;
  }
  return tags_for(*impl_, id);
}

}  // namespace ldb::store
