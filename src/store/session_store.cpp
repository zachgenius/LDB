#include "store/session_store.h"

#include "backend/debugger_backend.h"
#include "util/sha256.h"

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
  std::string sql =
      "SELECT seq, ts_ns, method, request, response, ok, duration_us "
      "FROM rpc_log";
  bool has_since = (since_seq > 0);
  bool has_until = (until_seq > 0);
  if (has_since || has_until) sql += " WHERE";
  if (has_since)               sql += " seq >= ?1";
  if (has_since && has_until)  sql += " AND";
  if (has_until)               sql += has_since ? " seq < ?2" : " seq < ?1";
  sql += " ORDER BY seq ASC;";

  auto stmt = prepare_or_throw(db, sql);
  int bind_idx = 1;
  if (has_since) sqlite3_bind_int64(stmt.get(), bind_idx++, since_seq);
  if (has_until) sqlite3_bind_int64(stmt.get(), bind_idx++, until_seq);

  std::vector<LogRow> out;
  for (;;) {
    int step = sqlite3_step(stmt.get());
    if (step == SQLITE_DONE) break;
    if (step != SQLITE_ROW) {
      sqlite3_close(db);
      throw_sqlite(db, "read_log step");
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
            "                    duration_us) "
            "VALUES(?1, ?2, ?3, ?4, ?5, ?6);");
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
