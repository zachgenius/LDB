#include "store/session_store.h"

#include "backend/debugger_backend.h"

#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <random>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace ldb::store {

namespace {

// 16 random bytes → 32 lower-hex chars. We don't pull a UUID dep; this
// is "UUID-compatible enough" for our purposes — the namespace is local
// to the operator's machine, the only consumer is the agent itself, and
// 128 bits of entropy is well past collision concern at any session
// scale we'll hit. Documented as a deliberate choice in the worklog.
std::string make_session_id() {
  static constexpr char kHex[] = "0123456789abcdef";
  std::random_device rd;
  std::array<std::uint8_t, 16> b{};
  // std::random_device output is implementation-defined width; treat as
  // a generic byte source by extracting one std::uint32_t at a time.
  for (std::size_t i = 0; i < b.size(); i += 4) {
    std::uint32_t v = rd();
    b[i + 0] = static_cast<std::uint8_t>((v >>  0) & 0xFFu);
    b[i + 1] = static_cast<std::uint8_t>((v >>  8) & 0xFFu);
    b[i + 2] = static_cast<std::uint8_t>((v >> 16) & 0xFFu);
    b[i + 3] = static_cast<std::uint8_t>((v >> 24) & 0xFFu);
  }
  std::string out;
  out.reserve(32);
  for (auto x : b) {
    out.push_back(kHex[(x >> 4) & 0xFu]);
    out.push_back(kHex[x & 0xFu]);
  }
  return out;
}

[[noreturn]] void throw_sqlite(sqlite3* db, std::string_view ctx) {
  std::string msg = "sqlite: ";
  msg.append(ctx);
  msg.append(": ");
  msg.append(db ? sqlite3_errmsg(db) : "no db");
  throw backend::Error(msg);
}

[[noreturn]] void throw_io(std::string_view what, const std::error_code& ec) {
  std::string m = "session_store io: ";
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

void exec_or_throw(sqlite3* db, const char* sql) {
  char* err = nullptr;
  int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err);
  if (rc != SQLITE_OK) {
    std::string m = "sqlite exec: ";
    m.append(err ? err : sqlite3_errmsg(db));
    sqlite3_free(err);
    throw backend::Error(m);
  }
}

StmtGuard prepare_or_throw(sqlite3* db, std::string_view sql) {
  sqlite3_stmt* stmt = nullptr;
  int rc = sqlite3_prepare_v2(db, sql.data(),
                              static_cast<int>(sql.size()), &stmt, nullptr);
  if (rc != SQLITE_OK) throw_sqlite(db, "prepare");
  return StmtGuard{stmt};
}

void migrate_index(sqlite3* db) {
  exec_or_throw(db, "PRAGMA journal_mode=WAL;");
  exec_or_throw(db, "PRAGMA synchronous=NORMAL;");
  exec_or_throw(db, "PRAGMA foreign_keys=ON;");
  exec_or_throw(db,
    "CREATE TABLE IF NOT EXISTS sessions("
    "  id TEXT PRIMARY KEY,"
    "  name TEXT NOT NULL,"
    "  target_id TEXT,"
    "  created_at INTEGER NOT NULL,"
    "  path TEXT NOT NULL"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_sess_created ON sessions(created_at DESC);"
  );
}

void migrate_session_db(sqlite3* db,
                        std::string_view name,
                        const std::optional<std::string>& target_id,
                        std::int64_t created_at) {
  exec_or_throw(db, "PRAGMA journal_mode=WAL;");
  exec_or_throw(db, "PRAGMA synchronous=NORMAL;");
  exec_or_throw(db, "PRAGMA foreign_keys=ON;");
  exec_or_throw(db,
    "CREATE TABLE IF NOT EXISTS meta("
    "  k TEXT PRIMARY KEY,"
    "  v TEXT NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS rpc_log("
    "  seq INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  ts_ns INTEGER NOT NULL,"
    "  method TEXT NOT NULL,"
    "  request TEXT NOT NULL,"
    "  response TEXT NOT NULL,"
    "  ok INTEGER NOT NULL,"
    "  duration_us INTEGER NOT NULL"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_rpc_method ON rpc_log(method);"
  );

  auto put_meta = [&](const char* k, const std::string& v) {
    auto stmt = prepare_or_throw(db,
      "INSERT OR REPLACE INTO meta(k, v) VALUES(?1, ?2);");
    sqlite3_bind_text(stmt.get(), 1, k, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, v.c_str(),
                      static_cast<int>(v.size()), SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
      throw_sqlite(db, "meta insert");
    }
  };
  put_meta("schema_version", "1");
  put_meta("name", std::string(name));
  put_meta("created_at", std::to_string(created_at));
  if (target_id.has_value()) put_meta("target_id", *target_id);
}

// Pull aggregates (call_count, last_call_at) from a session's per-db
// rpc_log. Returns 0 / nullopt on a fresh session with no rows yet.
struct LogAggregates {
  std::int64_t                count = 0;
  std::optional<std::int64_t> last_ts_ns;
};

LogAggregates read_aggregates(const std::filesystem::path& session_db_path) {
  LogAggregates out;
  sqlite3* db = nullptr;
  // Open read-only — we don't want a stale aggregate read to flip on
  // WAL just because list() was called before any append.
  int rc = sqlite3_open_v2(session_db_path.c_str(), &db,
                           SQLITE_OPEN_READONLY, nullptr);
  if (rc != SQLITE_OK) {
    if (db) sqlite3_close(db);
    // A missing/corrupt session db (e.g. created in another process and
    // gone) shouldn't fail list() of every other session. Surface as
    // count=0; the row still exists in the index.
    return out;
  }
  auto stmt = prepare_or_throw(db,
      "SELECT COUNT(*), MAX(ts_ns) FROM rpc_log;");
  rc = sqlite3_step(stmt.get());
  if (rc == SQLITE_ROW) {
    out.count = sqlite3_column_int64(stmt.get(), 0);
    if (sqlite3_column_type(stmt.get(), 1) != SQLITE_NULL) {
      out.last_ts_ns = sqlite3_column_int64(stmt.get(), 1);
    }
  }
  sqlite3_close(db);
  return out;
}

SessionRow row_from_index_stmt(sqlite3_stmt* s) {
  SessionRow r;
  auto id   = reinterpret_cast<const char*>(sqlite3_column_text(s, 0));
  auto nm   = reinterpret_cast<const char*>(sqlite3_column_text(s, 1));
  r.id      = id ? id : "";
  r.name    = nm ? nm : "";
  if (sqlite3_column_type(s, 2) != SQLITE_NULL) {
    auto tid = reinterpret_cast<const char*>(sqlite3_column_text(s, 2));
    if (tid) r.target_id = std::string(tid);
  }
  r.created_at = sqlite3_column_int64(s, 3);
  auto p = reinterpret_cast<const char*>(sqlite3_column_text(s, 4));
  r.path = p ? p : "";
  return r;
}

constexpr const char* kSelectIndexCols =
    "id, name, target_id, created_at, path";

}  // namespace

// ---------------------------------------------------------------------------

struct SessionStore::Impl {
  std::filesystem::path root;
  std::filesystem::path sessions_dir;
  sqlite3*              index_db = nullptr;
  std::mutex            mu;

  ~Impl() {
    if (index_db) sqlite3_close(index_db);
  }
};

SessionStore::SessionStore(std::filesystem::path root)
    : impl_(std::make_unique<Impl>()) {
  namespace fs = std::filesystem;
  std::error_code ec;
  fs::create_directories(root, ec);
  if (ec) throw_io("create_directories(root)", ec);
  impl_->root = fs::absolute(root, ec);
  if (ec) impl_->root = root;

  impl_->sessions_dir = impl_->root / "sessions";
  fs::create_directories(impl_->sessions_dir, ec);
  if (ec) throw_io("create_directories(sessions)", ec);

  fs::path idx = impl_->sessions_dir / "index.db";
  int rc = sqlite3_open(idx.c_str(), &impl_->index_db);
  if (rc != SQLITE_OK) {
    std::string m = "sqlite open ";
    m.append(idx.string());
    m.append(": ");
    m.append(impl_->index_db ? sqlite3_errmsg(impl_->index_db)
                              : sqlite3_errstr(rc));
    if (impl_->index_db) sqlite3_close(impl_->index_db);
    impl_->index_db = nullptr;
    throw backend::Error(m);
  }
  migrate_index(impl_->index_db);
}

SessionStore::~SessionStore() = default;
SessionStore::SessionStore(SessionStore&&) noexcept = default;
SessionStore& SessionStore::operator=(SessionStore&&) noexcept = default;

const std::filesystem::path& SessionStore::root() const noexcept {
  return impl_->root;
}

SessionRow SessionStore::create(std::string_view name,
                                std::optional<std::string> target_id) {
  namespace fs = std::filesystem;
  std::lock_guard<std::mutex> lk(impl_->mu);

  std::string id = make_session_id();
  fs::path session_path = impl_->sessions_dir / (id + ".db");
  // Nanoseconds, not seconds: list() sorts on this, and an agent
  // creating two sessions in the same wall-clock second still wants
  // the order it sees during a `session.list` to match the order it
  // created them in.
  auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(
                 std::chrono::system_clock::now().time_since_epoch()).count();

  // Open and migrate the per-session db first; if that fails we don't
  // want a dangling index row pointing at nothing.
  sqlite3* sdb = nullptr;
  int rc = sqlite3_open(session_path.c_str(), &sdb);
  if (rc != SQLITE_OK) {
    std::string m = "sqlite open ";
    m.append(session_path.string());
    m.append(": ");
    m.append(sdb ? sqlite3_errmsg(sdb) : sqlite3_errstr(rc));
    if (sdb) sqlite3_close(sdb);
    throw backend::Error(m);
  }
  try {
    migrate_session_db(sdb, name, target_id,
                       static_cast<std::int64_t>(now));
  } catch (...) {
    sqlite3_close(sdb);
    std::error_code ec;
    fs::remove(session_path, ec);
    throw;
  }
  sqlite3_close(sdb);

  // Then write the index row.
  auto ins = prepare_or_throw(impl_->index_db,
      "INSERT INTO sessions(id, name, target_id, created_at, path) "
      "VALUES(?1, ?2, ?3, ?4, ?5);");
  sqlite3_bind_text(ins.get(), 1, id.c_str(),
                    static_cast<int>(id.size()), SQLITE_TRANSIENT);
  std::string name_s(name);
  sqlite3_bind_text(ins.get(), 2, name_s.c_str(),
                    static_cast<int>(name_s.size()), SQLITE_TRANSIENT);
  if (target_id.has_value()) {
    sqlite3_bind_text(ins.get(), 3, target_id->c_str(),
                      static_cast<int>(target_id->size()),
                      SQLITE_TRANSIENT);
  } else {
    sqlite3_bind_null(ins.get(), 3);
  }
  sqlite3_bind_int64(ins.get(), 4, static_cast<sqlite3_int64>(now));
  std::string ps = session_path.string();
  sqlite3_bind_text(ins.get(), 5, ps.c_str(),
                    static_cast<int>(ps.size()), SQLITE_TRANSIENT);
  if (sqlite3_step(ins.get()) != SQLITE_DONE) {
    throw_sqlite(impl_->index_db, "create: insert index");
  }

  SessionRow r;
  r.id         = std::move(id);
  r.name       = std::move(name_s);
  r.target_id  = std::move(target_id);
  r.created_at = static_cast<std::int64_t>(now);
  r.call_count = 0;
  r.path       = std::move(ps);
  return r;
}

std::optional<SessionRow> SessionStore::info(std::string_view id) {
  std::lock_guard<std::mutex> lk(impl_->mu);
  std::string sql = std::string("SELECT ") + kSelectIndexCols +
                    " FROM sessions WHERE id = ?1;";
  auto stmt = prepare_or_throw(impl_->index_db, sql);
  sqlite3_bind_text(stmt.get(), 1, id.data(),
                    static_cast<int>(id.size()), SQLITE_TRANSIENT);
  int rc = sqlite3_step(stmt.get());
  if (rc == SQLITE_DONE) return std::nullopt;
  if (rc != SQLITE_ROW) throw_sqlite(impl_->index_db, "info");
  auto row = row_from_index_stmt(stmt.get());
  auto agg = read_aggregates(row.path);
  row.call_count   = agg.count;
  row.last_call_at = agg.last_ts_ns;
  return row;
}

std::vector<SessionRow> SessionStore::list() {
  std::lock_guard<std::mutex> lk(impl_->mu);
  std::string sql = std::string("SELECT ") + kSelectIndexCols +
                    " FROM sessions ORDER BY created_at DESC, id ASC;";
  auto stmt = prepare_or_throw(impl_->index_db, sql);
  std::vector<SessionRow> out;
  for (;;) {
    int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_DONE) break;
    if (rc != SQLITE_ROW) throw_sqlite(impl_->index_db, "list step");
    auto row = row_from_index_stmt(stmt.get());
    auto agg = read_aggregates(row.path);
    row.call_count   = agg.count;
    row.last_call_at = agg.last_ts_ns;
    out.push_back(std::move(row));
  }
  return out;
}

// ---------------------------------------------------------------------------

struct SessionStore::Writer::Impl {
  std::string           id;
  std::filesystem::path path;
  sqlite3*              db = nullptr;
  std::mutex            mu;

  ~Impl() {
    if (db) sqlite3_close(db);
  }
};

SessionStore::Writer::Writer(std::unique_ptr<SessionStore::Writer::Impl> impl)
    : impl_(std::move(impl)) {}

SessionStore::Writer::~Writer() = default;

void SessionStore::Writer::append(std::string_view method,
                                  const nlohmann::json& request,
                                  const nlohmann::json& response,
                                  bool ok,
                                  std::int64_t duration_us) {
  std::lock_guard<std::mutex> lk(impl_->mu);
  auto stmt = prepare_or_throw(impl_->db,
      "INSERT INTO rpc_log(ts_ns, method, request, response, ok, "
      "                    duration_us) "
      "VALUES(?1, ?2, ?3, ?4, ?5, ?6);");

  auto ts_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
  std::string m_s(method);
  std::string req_s = request.dump();
  std::string rsp_s = response.dump();

  sqlite3_bind_int64(stmt.get(), 1, static_cast<sqlite3_int64>(ts_ns));
  sqlite3_bind_text (stmt.get(), 2, m_s.c_str(),
                     static_cast<int>(m_s.size()), SQLITE_TRANSIENT);
  sqlite3_bind_text (stmt.get(), 3, req_s.c_str(),
                     static_cast<int>(req_s.size()), SQLITE_TRANSIENT);
  sqlite3_bind_text (stmt.get(), 4, rsp_s.c_str(),
                     static_cast<int>(rsp_s.size()), SQLITE_TRANSIENT);
  sqlite3_bind_int  (stmt.get(), 5, ok ? 1 : 0);
  sqlite3_bind_int64(stmt.get(), 6, static_cast<sqlite3_int64>(duration_us));

  if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
    throw_sqlite(impl_->db, "rpc_log: insert");
  }
}

std::unique_ptr<SessionStore::Writer>
SessionStore::open_writer(std::string_view id) {
  // Look up the session path under the index lock; release it before
  // opening the per-session db so other queries don't block.
  std::filesystem::path session_path;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto stmt = prepare_or_throw(impl_->index_db,
        "SELECT path FROM sessions WHERE id = ?1;");
    sqlite3_bind_text(stmt.get(), 1, id.data(),
                      static_cast<int>(id.size()), SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_DONE) {
      throw backend::Error("session_store.open_writer: no such id: " +
                           std::string(id));
    }
    if (rc != SQLITE_ROW) throw_sqlite(impl_->index_db, "open_writer");
    auto p = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
    session_path = p ? p : "";
  }

  auto wimpl = std::make_unique<Writer::Impl>();
  wimpl->id   = std::string(id);
  wimpl->path = session_path;
  int rc = sqlite3_open(session_path.c_str(), &wimpl->db);
  if (rc != SQLITE_OK) {
    std::string m = "sqlite open ";
    m.append(session_path.string());
    m.append(": ");
    m.append(wimpl->db ? sqlite3_errmsg(wimpl->db) : sqlite3_errstr(rc));
    if (wimpl->db) sqlite3_close(wimpl->db);
    throw backend::Error(m);
  }
  // Ensure WAL on this handle too (PRAGMA is per-connection in some
  // failure paths, though sqlite normally persists journal_mode).
  exec_or_throw(wimpl->db, "PRAGMA journal_mode=WAL;");
  exec_or_throw(wimpl->db, "PRAGMA synchronous=NORMAL;");

  return std::unique_ptr<Writer>(new Writer(std::move(wimpl)));
}

}  // namespace ldb::store
