// SPDX-License-Identifier: Apache-2.0
#include "store/session_store.h"

#include "backend/debugger_backend.h"
#include "util/sha256.h"

#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <map>
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
    "  duration_us INTEGER NOT NULL,"
    // Post-V1 #16 phase-1 (docs/24 §3.1): captured snapshot for
    // replay's determinism gate. Empty string for rows recorded
    // before this migration — replay treats those as
    // "snapshot unknown -> non-deterministic by default."
    "  snapshot TEXT NOT NULL DEFAULT ''"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_rpc_method ON rpc_log(method);"
  );
  // Backward-compat: dbs created before #16-phase-1 won't have
  // the snapshot column. Try to add it; ignore "duplicate column"
  // errors when we hit a freshly-created db where CREATE already
  // included it.
  {
    char* err = nullptr;
    int rc = sqlite3_exec(db,
        "ALTER TABLE rpc_log ADD COLUMN snapshot TEXT NOT NULL DEFAULT '';",
        nullptr, nullptr, &err);
    if (rc != SQLITE_OK && err) {
      std::string msg = err;
      sqlite3_free(err);
      // "duplicate column" is the expected case on new dbs. Anything
      // else escalates to the canonical throw path.
      if (msg.find("duplicate column") == std::string::npos) {
        throw backend::Error(std::string("sqlite migrate add snapshot: ") + msg);
      }
    } else if (err) {
      sqlite3_free(err);
    }
  }

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
  // Audit §11.2 (revised by reviewer): the secondary key was previously
  // `id ASC`, but `id` is a 32-hex-char random uuid, which turns the
  // tiebreak into a non-deterministic shuffle when two sessions share
  // a `created_at` ns. Use the operator-supplied `name` as the
  // deterministic secondary key; fall back to `id` only when both
  // `created_at` and `name` collide (vanishingly rare — same operator
  // typed the same name twice within the same wall-clock ns).
  std::string sql = std::string("SELECT ") + kSelectIndexCols +
                    " FROM sessions ORDER BY created_at DESC, "
                    "name ASC, id ASC;";
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

std::vector<SessionStore::LogRow>
SessionStore::read_log(std::string_view id,
                       std::int64_t since_seq,
                       std::int64_t until_seq) {
  std::filesystem::path session_path;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto stmt = prepare_or_throw(impl_->index_db,
        "SELECT path FROM sessions WHERE id = ?1;");
    sqlite3_bind_text(stmt.get(), 1, id.data(),
                      static_cast<int>(id.size()), SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_DONE) {
      throw backend::Error("session_store.read_log: no such id: " +
                           std::string(id));
    }
    if (rc != SQLITE_ROW) throw_sqlite(impl_->index_db, "read_log");
    auto p = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
    session_path = p ? p : "";
  }
  // Open read-only — read_log is a query path; the writer (if any) holds
  // its own handle and WAL lets us read concurrently without contention.
  sqlite3* db = nullptr;
  int rc = sqlite3_open_v2(session_path.c_str(), &db,
                           SQLITE_OPEN_READONLY, nullptr);
  if (rc != SQLITE_OK) {
    if (db) sqlite3_close(db);
    throw backend::Error("session_store.read_log: open " +
                         session_path.string());
  }
  // Per-session dbs created before commit d7f5137 lack the `snapshot`
  // column on rpc_log. migrate_session_db only runs on writer-side
  // paths (create / fork / import); reads against a pre-#16 db would
  // otherwise throw "no such column: snapshot" — bricking every
  // session.diff / session.targets / session.replay against legacy
  // stores. Mirror pack.cpp's two-attempt fallback: try the new SELECT
  // first, fall back to the legacy SELECT with snapshot="" on prepare
  // failure. Empty snapshot maps to non-deterministic at the replay
  // gate (docs/24 §3.1), which is the conservative semantics for any
  // log row written before the column existed.
  std::string sql_tail;
  bool has_since = (since_seq > 0);
  bool has_until = (until_seq > 0);
  if (has_since || has_until) sql_tail += " WHERE";
  if (has_since)               sql_tail += " seq >= ?1";
  if (has_since && has_until)  sql_tail += " AND";
  if (has_until)               sql_tail += has_since ? " seq < ?2" : " seq < ?1";
  sql_tail += " ORDER BY seq ASC;";

  std::string sql_new =
      "SELECT seq, ts_ns, method, request, response, ok, duration_us, "
      "       snapshot "
      "FROM rpc_log" + sql_tail;
  std::string sql_old =
      "SELECT seq, ts_ns, method, request, response, ok, duration_us "
      "FROM rpc_log" + sql_tail;

  sqlite3_stmt* raw_stmt = nullptr;
  bool has_snapshot = true;
  if (sqlite3_prepare_v2(db, sql_new.c_str(), -1, &raw_stmt, nullptr)
      != SQLITE_OK) {
    has_snapshot = false;
    if (sqlite3_prepare_v2(db, sql_old.c_str(), -1, &raw_stmt, nullptr)
        != SQLITE_OK) {
      std::string msg = std::string("sqlite: read_log prepare: ")
                      + sqlite3_errmsg(db);
      sqlite3_close(db);
      throw backend::Error(msg);
    }
  }
  StmtGuard stmt(raw_stmt);
  int bind_idx = 1;
  if (has_since) sqlite3_bind_int64(stmt.get(), bind_idx++, since_seq);
  if (has_until) sqlite3_bind_int64(stmt.get(), bind_idx++, until_seq);

  std::vector<LogRow> out;
  for (;;) {
    int step = sqlite3_step(stmt.get());
    if (step == SQLITE_DONE) break;
    if (step != SQLITE_ROW) {
      // Capture the error message BEFORE closing the handle —
      // sqlite3_errmsg(db) on a freed handle is UB.
      std::string msg = std::string("sqlite: read_log step: ")
                      + sqlite3_errmsg(db);
      sqlite3_close(db);
      throw backend::Error(msg);
    }
    LogRow r;
    r.seq         = sqlite3_column_int64(stmt.get(), 0);
    r.ts_ns       = sqlite3_column_int64(stmt.get(), 1);
    auto m        = reinterpret_cast<const char*>(
        sqlite3_column_text(stmt.get(), 2));
    auto req      = reinterpret_cast<const char*>(
        sqlite3_column_text(stmt.get(), 3));
    auto rsp      = reinterpret_cast<const char*>(
        sqlite3_column_text(stmt.get(), 4));
    r.method       = m   ? m   : "";
    r.request_json = req ? req : "{}";
    r.response_json= rsp ? rsp : "{}";
    r.ok           = sqlite3_column_int(stmt.get(), 5) != 0;
    r.duration_us  = sqlite3_column_int64(stmt.get(), 6);
    if (has_snapshot) {
      auto snap    = reinterpret_cast<const char*>(
          sqlite3_column_text(stmt.get(), 7));
      r.snapshot   = snap ? snap : "";
    }
    out.push_back(std::move(r));
  }
  sqlite3_close(db);
  return out;
}

// ---------------------------------------------------------------------------
// Tier 3 §11 — diff_logs
//
// Walks both rpc_logs (in seq order), canonicalizes each row's params and
// response via re-parse + re-dump (sorted-key), and aligns the two
// (method, params_canon) sequences with classic O(n*m) LCS DP. The
// alignment is then walked top-down to emit DiffEntry rows in a stable
// order: removed runs (A-side gap) come before added runs (B-side gap)
// inside each block; aligned pairs are emitted at their alignment point.

namespace {

// Re-parse and re-dump a stored JSON string to obtain a canonical-key
// representation. nlohmann::json's object_t is std::map, so dump()
// already sorts keys alphabetically. The stored string is *probably*
// already canonical (Writer::append goes through json::dump too) but
// re-canonicalizing here is belt-and-braces: a future client that bypasses
// the writer (or a `.ldbpack` round-trip through some other library) can
// still produce comparable output.
std::string canon_json(std::string_view raw) {
  if (raw.empty()) return "{}";
  try {
    auto j = nlohmann::json::parse(raw);
    return j.dump();
  } catch (...) {
    // Fall back to the raw bytes — a malformed row is its own equivalence
    // class. Diffing two malformed rows with byte-identical text still
    // works; a malformed row vs a parseable one will simply not align.
    return std::string(raw);
  }
}

// Extract canonical params from a stored request_json. The Writer writes
// requests as `{"params": <user-params>, ...}` — see Writer::append's
// caller in dispatcher.cpp — but the dispatcher actually passes the
// caller-supplied `req.params` *directly* as the request body in some
// paths (e.g. session.detach packs explicitly). To be robust we accept
// either shape: if the parsed JSON has a top-level "params" key, treat
// that as the params object; otherwise treat the whole object as params.
// The choice doesn't affect correctness as long as it's consistent across
// both sessions in the diff.
std::string canon_params_from_request(std::string_view request_json) {
  if (request_json.empty()) return "{}";
  try {
    auto j = nlohmann::json::parse(request_json);
    if (j.is_object() && j.contains("params")) {
      return j["params"].dump();
    }
    return j.dump();
  } catch (...) {
    return std::string(request_json);
  }
}

// 64-bit truncation of sha256, hex-encoded — 16 chars. Plenty for a
// short label; the actual diff key is the canonical params string, not
// the hash. Reusing sha256 keeps us within the dependencies already
// vendored for util/.
std::string short_hash(std::string_view bytes) {
  auto full = ldb::util::sha256_hex(bytes);
  return full.substr(0, 16);
}

struct CanonRow {
  std::int64_t seq           = 0;
  std::string  method;
  std::string  params_canon;
  std::string  response_canon;
};

std::vector<CanonRow> canonicalize_log(
    const std::vector<SessionStore::LogRow>& log) {
  std::vector<CanonRow> out;
  out.reserve(log.size());
  for (const auto& r : log) {
    CanonRow c;
    c.seq             = r.seq;
    c.method          = r.method;
    c.params_canon    = canon_params_from_request(r.request_json);
    c.response_canon  = canon_json(r.response_json);
    out.push_back(std::move(c));
  }
  return out;
}

// Pack (method, params_canon) into one comparison key. Using '\x1f'
// (unit-separator) as a delimiter — never legal inside JSON-without-
// escapes, never in a method name. Keeps the LCS comparison a single
// std::string == op rather than two compares per cell.
std::string make_key(const CanonRow& r) {
  std::string k;
  k.reserve(r.method.size() + 1 + r.params_canon.size());
  k.append(r.method);
  k.push_back('\x1f');
  k.append(r.params_canon);
  return k;
}

}  // namespace

SessionStore::DiffResult
SessionStore::diff_logs(std::string_view a_id, std::string_view b_id) {
  auto log_a = read_log(a_id);
  auto log_b = read_log(b_id);
  auto can_a = canonicalize_log(log_a);
  auto can_b = canonicalize_log(log_b);

  const std::size_t n = can_a.size();
  const std::size_t m = can_b.size();

  // Pre-compute keys to avoid concatenating inside the DP loop.
  std::vector<std::string> ka, kb;
  ka.reserve(n); kb.reserve(m);
  for (const auto& r : can_a) ka.push_back(make_key(r));
  for (const auto& r : can_b) kb.push_back(make_key(r));

  // O(n*m) LCS DP, length only. We back out the alignment by walking
  // backward through the table. For session traces of "human-driven
  // investigation" size (low thousands of rows) this fits comfortably.
  // Unbounded cost-hint on the wire endpoint warns callers if they go
  // bigger.
  std::vector<std::vector<std::int32_t>> dp(
      n + 1, std::vector<std::int32_t>(m + 1, 0));
  for (std::size_t i = 0; i < n; ++i) {
    for (std::size_t j = 0; j < m; ++j) {
      if (ka[i] == kb[j]) {
        dp[i + 1][j + 1] = dp[i][j] + 1;
      } else {
        dp[i + 1][j + 1] = std::max(dp[i + 1][j], dp[i][j + 1]);
      }
    }
  }

  // Backtrack to recover the alignment. We collect pair-records in
  // reverse, then walk forward to emit DiffEntries in stable order.
  enum Op { kCommon, kRemoved, kAdded };
  struct Pair { Op op; std::size_t ia; std::size_t ib; };
  std::vector<Pair> pairs;
  pairs.reserve(n + m);
  {
    std::size_t i = n, j = m;
    while (i > 0 && j > 0) {
      if (ka[i - 1] == kb[j - 1]) {
        pairs.push_back({kCommon, i - 1, j - 1});
        --i; --j;
      } else if (dp[i - 1][j] >= dp[i][j - 1]) {
        pairs.push_back({kRemoved, i - 1, 0});
        --i;
      } else {
        pairs.push_back({kAdded, 0, j - 1});
        --j;
      }
    }
    while (i > 0) { pairs.push_back({kRemoved, i - 1, 0}); --i; }
    while (j > 0) { pairs.push_back({kAdded,   0, j - 1}); --j; }
  }
  std::reverse(pairs.begin(), pairs.end());

  DiffResult out;
  out.summary.total_a = static_cast<std::int64_t>(n);
  out.summary.total_b = static_cast<std::int64_t>(m);

  for (const auto& p : pairs) {
    DiffEntry e;
    if (p.op == kCommon) {
      const auto& a = can_a[p.ia];
      const auto& b = can_b[p.ib];
      e.method        = a.method;
      e.params_canon  = a.params_canon;
      e.params_hash   = short_hash(a.params_canon);
      e.seq_a         = a.seq;
      e.seq_b         = b.seq;
      if (a.response_canon == b.response_canon) {
        e.kind             = "common";
        e.response_a_canon = a.response_canon;
        // response_b_canon left empty for "common" — they're identical;
        // duplicating wastes bytes on the wire.
        ++out.summary.common;
      } else {
        e.kind             = "diverged";
        e.response_a_canon = a.response_canon;
        e.response_b_canon = b.response_canon;
        ++out.summary.diverged;
      }
    } else if (p.op == kRemoved) {
      const auto& a = can_a[p.ia];
      e.kind             = "removed";
      e.method           = a.method;
      e.params_canon     = a.params_canon;
      e.params_hash      = short_hash(a.params_canon);
      e.seq_a            = a.seq;
      e.response_a_canon = a.response_canon;
      ++out.summary.removed;
    } else {  // kAdded
      const auto& b = can_b[p.ib];
      e.kind             = "added";
      e.method           = b.method;
      e.params_canon     = b.params_canon;
      e.params_hash      = short_hash(b.params_canon);
      e.seq_b            = b.seq;
      e.response_b_canon = b.response_canon;
      ++out.summary.added;
    }
    out.entries.push_back(std::move(e));
  }
  return out;
}

// ---------------------------------------------------------------------------
// Tier 3 §9 — extract_target_ids
//
// Re-uses the existing read_log path (handles "id not found" → throws,
// open-readonly + WAL-friendly). Per-row, parse the stored request_json
// defensively: malformed JSON, missing/non-object params, missing or
// non-integer target_id all collapse to "row contributes nothing" rather
// than throwing — we don't want one weird row to poison an inventory
// query.

std::vector<SessionStore::TargetBucket>
SessionStore::extract_target_ids(std::string_view id) {
  auto rows = read_log(id);
  // Use std::map so the final iteration is sorted ascending by target_id.
  std::map<std::uint64_t, TargetBucket> buckets;
  for (const auto& r : rows) {
    nlohmann::json parsed;
    try {
      parsed = nlohmann::json::parse(r.request_json);
    } catch (const std::exception&) {
      continue;  // malformed JSON — skip
    }
    if (!parsed.is_object()) continue;
    auto pit = parsed.find("params");
    if (pit == parsed.end() || !pit->is_object()) continue;
    auto tit = pit->find("target_id");
    if (tit == pit->end()) continue;
    if (!tit->is_number_integer() && !tit->is_number_unsigned()) {
      // Float / string / null — not the documented integer shape.
      continue;
    }
    // Reject negative integers (TargetId is uint64).
    if (tit->is_number_integer() && tit->get<std::int64_t>() < 0) continue;
    std::uint64_t tid = tit->get<std::uint64_t>();
    auto& b = buckets[tid];
    if (b.call_count == 0) {
      b.target_id = tid;
      b.first_seq = r.seq;
    }
    b.call_count += 1;
    b.last_seq    = r.seq;
  }
  std::vector<TargetBucket> out;
  out.reserve(buckets.size());
  for (auto& [_, b] : buckets) out.push_back(std::move(b));
  return out;
}

// ---------------------------------------------------------------------------
// Post-V1 plan #16 phase-1 — fork_session
//
// Implementation outline (docs/24-session-fork-replay.md §8 step 2):
//   1. Resolve the source's index row under the index mutex; capture
//      path / name / target_id. Release the mutex before any per-session
//      sqlite work so other queries (info/list) don't block on the copy.
//   2. Allocate a new id + per-session db path.
//   3. Open the source db read-only and the new db read-write.
//   4. Migrate the new db (same canonical schema as create()), populate
//      meta with the inherited target_id and the resolved child name.
//   5. BEGIN IMMEDIATE on the new db. Prepare a SELECT on the source's
//      rpc_log (filtered by until_seq if non-zero); prepare an INSERT
//      against the new rpc_log. Step the SELECT, bind every column to
//      the INSERT, step it. Track the highest source seq seen.
//   6. COMMIT on the new db.
//   7. Insert the index row.
//
// If anything fails between steps 3 and 7, the partially-written child
// db is unlinked so the index never references half-state — same
// approach as create() and import_session().

SessionStore::ForkResult
SessionStore::fork_session(std::string_view source_id,
                           std::string_view name,
                           std::optional<std::string> description,
                           std::int64_t until_seq) {
  namespace fs = std::filesystem;
  (void)description;  // Captured for future meta-row use; not surfaced today.

  // ----- 1. resolve the source under the index mutex ----------------------
  std::filesystem::path source_path;
  std::string           source_name;
  std::optional<std::string> source_target_id;
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    std::string sql = std::string("SELECT ") + kSelectIndexCols +
                      " FROM sessions WHERE id = ?1;";
    auto stmt = prepare_or_throw(impl_->index_db, sql);
    sqlite3_bind_text(stmt.get(), 1, source_id.data(),
                      static_cast<int>(source_id.size()), SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_DONE) {
      throw backend::Error("session_store.fork_session: no such source id: "
                           + std::string(source_id));
    }
    if (rc != SQLITE_ROW) throw_sqlite(impl_->index_db, "fork_session: lookup");
    auto row = row_from_index_stmt(stmt.get());
    source_path      = row.path;
    source_name      = row.name;
    source_target_id = row.target_id;
  }

  // ----- 2. allocate child id + path --------------------------------------
  std::string id = make_session_id();
  fs::path session_path = impl_->sessions_dir / (id + ".db");

  // Resolve child name. Per docs/24 §2.3: empty -> "<source.name> (fork)".
  std::string child_name(name);
  if (child_name.empty()) {
    child_name = source_name + " (fork)";
  }

  // The created_at timestamp is a fresh ns sample — the fork is a new
  // session, not a clone of the source's birth time. list() sorts by
  // created_at DESC so the freshly-forked child appears at the top of
  // the agent's session.list, which matches the "I just made this"
  // expectation.
  auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(
                 std::chrono::system_clock::now().time_since_epoch()).count();

  // ----- 3. open the source db read-only ----------------------------------
  sqlite3* src_db = nullptr;
  int rc = sqlite3_open_v2(source_path.c_str(), &src_db,
                           SQLITE_OPEN_READONLY, nullptr);
  if (rc != SQLITE_OK) {
    if (src_db) sqlite3_close(src_db);
    throw backend::Error("session_store.fork_session: open source "
                         + source_path.string());
  }

  // RAII: ensure src_db is closed on every exit path. Use a small lambda
  // wrapper rather than a class because the close is unconditional and
  // we already have try/catch for the destination side.
  struct SrcCloser {
    sqlite3* db;
    ~SrcCloser() { if (db) sqlite3_close(db); }
  } src_closer{src_db};

  // ----- 4. open + migrate the child db ----------------------------------
  sqlite3* dst_db = nullptr;
  rc = sqlite3_open(session_path.c_str(), &dst_db);
  if (rc != SQLITE_OK) {
    std::string m = "sqlite open ";
    m.append(session_path.string());
    m.append(": ");
    m.append(dst_db ? sqlite3_errmsg(dst_db) : sqlite3_errstr(rc));
    if (dst_db) sqlite3_close(dst_db);
    throw backend::Error(m);
  }

  std::int64_t forked_at_seq = 0;
  std::int64_t rows_copied   = 0;
  try {
    migrate_session_db(dst_db, child_name, source_target_id,
                       static_cast<std::int64_t>(now));

    // ----- 5. SELECT-then-INSERT row copy in one transaction --------------
    exec_or_throw(dst_db, "BEGIN IMMEDIATE;");
    try {
      // SELECT on the source. `?1 = 0` means "no upper bound"; otherwise
      // seq <= ?1.
      auto sel = prepare_or_throw(src_db,
          "SELECT seq, ts_ns, method, request, response, ok, duration_us, "
          "       snapshot "
          "FROM rpc_log "
          "WHERE (?1 = 0 OR seq <= ?1) "
          "ORDER BY seq ASC;");
      sqlite3_bind_int64(sel.get(), 1, until_seq);

      auto ins = prepare_or_throw(dst_db,
          "INSERT INTO rpc_log(ts_ns, method, request, response, ok, "
          "                    duration_us, snapshot) "
          "VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7);");

      for (;;) {
        int s = sqlite3_step(sel.get());
        if (s == SQLITE_DONE) break;
        if (s != SQLITE_ROW) {
          throw_sqlite(src_db, "fork_session: source step");
        }
        // SELECT column 0 = seq (informational; used for forked_at_seq).
        std::int64_t src_seq = sqlite3_column_int64(sel.get(), 0);

        sqlite3_reset(ins.get());
        sqlite3_clear_bindings(ins.get());
        sqlite3_bind_int64(ins.get(), 1,
                           sqlite3_column_int64(sel.get(), 1));  // ts_ns
        // method/request/response are TEXT; bind_text needs a length —
        // pull from the source statement to avoid an extra copy.
        const unsigned char* method = sqlite3_column_text(sel.get(), 2);
        int method_n = sqlite3_column_bytes(sel.get(), 2);
        sqlite3_bind_text(ins.get(), 2,
                          reinterpret_cast<const char*>(method),
                          method_n, SQLITE_TRANSIENT);
        const unsigned char* req = sqlite3_column_text(sel.get(), 3);
        int req_n = sqlite3_column_bytes(sel.get(), 3);
        sqlite3_bind_text(ins.get(), 3,
                          reinterpret_cast<const char*>(req),
                          req_n, SQLITE_TRANSIENT);
        const unsigned char* rsp = sqlite3_column_text(sel.get(), 4);
        int rsp_n = sqlite3_column_bytes(sel.get(), 4);
        sqlite3_bind_text(ins.get(), 4,
                          reinterpret_cast<const char*>(rsp),
                          rsp_n, SQLITE_TRANSIENT);
        sqlite3_bind_int(ins.get(), 5,
                         sqlite3_column_int(sel.get(), 5));      // ok
        sqlite3_bind_int64(ins.get(), 6,
                           sqlite3_column_int64(sel.get(), 6));  // duration_us
        const unsigned char* snap = sqlite3_column_text(sel.get(), 7);
        int snap_n = sqlite3_column_bytes(sel.get(), 7);
        sqlite3_bind_text(ins.get(), 7,
                          reinterpret_cast<const char*>(snap ? snap
                                                              : reinterpret_cast<const unsigned char*>("")),
                          snap ? snap_n : 0, SQLITE_TRANSIENT);

        if (sqlite3_step(ins.get()) != SQLITE_DONE) {
          throw_sqlite(dst_db, "fork_session: insert row");
        }
        rows_copied   += 1;
        forked_at_seq  = src_seq;
      }
      exec_or_throw(dst_db, "COMMIT;");
    } catch (...) {
      exec_or_throw(dst_db, "ROLLBACK;");
      throw;
    }
  } catch (...) {
    sqlite3_close(dst_db);
    std::error_code ec;
    fs::remove(session_path, ec);
    throw;
  }
  sqlite3_close(dst_db);

  // ----- 7. insert the child's index row ---------------------------------
  {
    std::lock_guard<std::mutex> lk(impl_->mu);
    auto ins = prepare_or_throw(impl_->index_db,
        "INSERT INTO sessions(id, name, target_id, created_at, path) "
        "VALUES(?1, ?2, ?3, ?4, ?5);");
    sqlite3_bind_text(ins.get(), 1, id.c_str(),
                      static_cast<int>(id.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(ins.get(), 2, child_name.c_str(),
                      static_cast<int>(child_name.size()), SQLITE_TRANSIENT);
    if (source_target_id.has_value()) {
      sqlite3_bind_text(ins.get(), 3, source_target_id->c_str(),
                        static_cast<int>(source_target_id->size()),
                        SQLITE_TRANSIENT);
    } else {
      sqlite3_bind_null(ins.get(), 3);
    }
    sqlite3_bind_int64(ins.get(), 4, static_cast<sqlite3_int64>(now));
    std::string ps = session_path.string();
    sqlite3_bind_text(ins.get(), 5, ps.c_str(),
                      static_cast<int>(ps.size()), SQLITE_TRANSIENT);
    if (sqlite3_step(ins.get()) != SQLITE_DONE) {
      // Unlink the per-session db so the index never references half-
      // state. Best-effort — if the unlink itself fails, the index row
      // we never inserted is the worst we can leave behind.
      std::error_code ec;
      fs::remove(session_path, ec);
      throw_sqlite(impl_->index_db, "fork_session: insert index row");
    }
  }

  ForkResult out;
  out.source_session_id = std::string(source_id);
  out.id                = std::move(id);
  out.name              = std::move(child_name);
  out.created_at        = static_cast<std::int64_t>(now);
  out.path              = session_path.string();
  out.forked_at_seq     = forked_at_seq;
  out.rows_copied       = rows_copied;
  return out;
}

// ---------------------------------------------------------------------------

void SessionStore::import_session(std::string_view id,
                                  std::string_view name,
                                  std::optional<std::string> target_id,
                                  std::int64_t created_at_ns,
                                  const std::vector<ImportRow>& rows,
                                  bool overwrite) {
  namespace fs = std::filesystem;
  std::lock_guard<std::mutex> lk(impl_->mu);

  // Does this id already live in the index?
  bool already_exists = false;
  std::string existing_path;
  {
    auto stmt = prepare_or_throw(impl_->index_db,
        "SELECT path FROM sessions WHERE id = ?1;");
    sqlite3_bind_text(stmt.get(), 1, id.data(),
                      static_cast<int>(id.size()), SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
      already_exists = true;
      auto p = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
      if (p) existing_path = p;
    } else if (rc != SQLITE_DONE) {
      throw_sqlite(impl_->index_db, "import_session: pre-check");
    }
  }
  if (already_exists && !overwrite) {
    throw backend::Error("session_store.import_session: id already exists: "
                         + std::string(id));
  }

  fs::path session_path = impl_->sessions_dir / (std::string(id) + ".db");
  if (already_exists) {
    auto del = prepare_or_throw(impl_->index_db,
        "DELETE FROM sessions WHERE id = ?1;");
    sqlite3_bind_text(del.get(), 1, id.data(),
                      static_cast<int>(id.size()), SQLITE_TRANSIENT);
    if (sqlite3_step(del.get()) != SQLITE_DONE) {
      throw_sqlite(impl_->index_db, "import_session: delete prior index row");
    }
    std::error_code ec;
    if (!existing_path.empty()) fs::remove(existing_path, ec);
    fs::remove(session_path, ec);
  }

  // Build a fresh per-session db.
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
    migrate_session_db(sdb, name, target_id, created_at_ns);
    if (!rows.empty()) {
      exec_or_throw(sdb, "BEGIN IMMEDIATE;");
      try {
        auto ins = prepare_or_throw(sdb,
            "INSERT INTO rpc_log(ts_ns, method, request, response, ok, "
            "                    duration_us, snapshot) "
            "VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7);");
        for (const auto& r : rows) {
          sqlite3_reset(ins.get());
          sqlite3_clear_bindings(ins.get());
          sqlite3_bind_int64(ins.get(), 1, r.ts_ns);
          sqlite3_bind_text (ins.get(), 2, r.method.c_str(),
                             static_cast<int>(r.method.size()),
                             SQLITE_TRANSIENT);
          sqlite3_bind_text (ins.get(), 3, r.request_json.c_str(),
                             static_cast<int>(r.request_json.size()),
                             SQLITE_TRANSIENT);
          sqlite3_bind_text (ins.get(), 4, r.response_json.c_str(),
                             static_cast<int>(r.response_json.size()),
                             SQLITE_TRANSIENT);
          sqlite3_bind_int  (ins.get(), 5, r.ok ? 1 : 0);
          sqlite3_bind_int64(ins.get(), 6, r.duration_us);
          sqlite3_bind_text (ins.get(), 7, r.snapshot.c_str(),
                             static_cast<int>(r.snapshot.size()),
                             SQLITE_TRANSIENT);
          if (sqlite3_step(ins.get()) != SQLITE_DONE) {
            throw_sqlite(sdb, "import_session: rpc_log insert");
          }
        }
        exec_or_throw(sdb, "COMMIT;");
      } catch (...) {
        exec_or_throw(sdb, "ROLLBACK;");
        throw;
      }
    }
  } catch (...) {
    sqlite3_close(sdb);
    std::error_code ec;
    fs::remove(session_path, ec);
    throw;
  }
  sqlite3_close(sdb);

  // Insert the index row.
  auto ins = prepare_or_throw(impl_->index_db,
      "INSERT INTO sessions(id, name, target_id, created_at, path) "
      "VALUES(?1, ?2, ?3, ?4, ?5);");
  sqlite3_bind_text(ins.get(), 1, id.data(),
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
  sqlite3_bind_int64(ins.get(), 4, static_cast<sqlite3_int64>(created_at_ns));
  std::string ps = session_path.string();
  sqlite3_bind_text(ins.get(), 5, ps.c_str(),
                    static_cast<int>(ps.size()), SQLITE_TRANSIENT);
  if (sqlite3_step(ins.get()) != SQLITE_DONE) {
    throw_sqlite(impl_->index_db, "import_session: insert index");
  }
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
                                  std::int64_t duration_us,
                                  std::string_view snapshot) {
  std::lock_guard<std::mutex> lk(impl_->mu);
  auto stmt = prepare_or_throw(impl_->db,
      "INSERT INTO rpc_log(ts_ns, method, request, response, ok, "
      "                    duration_us, snapshot) "
      "VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7);");

  auto ts_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
  std::string m_s(method);
  std::string req_s = request.dump();
  std::string rsp_s = response.dump();
  std::string snap_s(snapshot);

  sqlite3_bind_int64(stmt.get(), 1, static_cast<sqlite3_int64>(ts_ns));
  sqlite3_bind_text (stmt.get(), 2, m_s.c_str(),
                     static_cast<int>(m_s.size()), SQLITE_TRANSIENT);
  sqlite3_bind_text (stmt.get(), 3, req_s.c_str(),
                     static_cast<int>(req_s.size()), SQLITE_TRANSIENT);
  sqlite3_bind_text (stmt.get(), 4, rsp_s.c_str(),
                     static_cast<int>(rsp_s.size()), SQLITE_TRANSIENT);
  sqlite3_bind_int  (stmt.get(), 5, ok ? 1 : 0);
  sqlite3_bind_int64(stmt.get(), 6, static_cast<sqlite3_int64>(duration_us));
  sqlite3_bind_text (stmt.get(), 7, snap_s.c_str(),
                     static_cast<int>(snap_s.size()), SQLITE_TRANSIENT);

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
