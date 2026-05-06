#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Per-session sqlite databases holding the RPC log of an investigation.
// Sessions live alongside the artifact store under the same root.
//
// Layout (per docs/02-ldb-mvp-plan.md §3.4 + §8):
//
//   ${root}/
//   └── sessions/
//       ├── index.db           sqlite: meta-index of all sessions
//       └── <uuid>.db          one db per session: meta + rpc_log
//
// Per-session schema:
//
//   meta(k TEXT PRIMARY KEY, v TEXT NOT NULL)
//     -- holds: name, created_at, target_id (opt), schema_version
//   rpc_log(seq INTEGER PRIMARY KEY AUTOINCREMENT,
//           ts_ns INTEGER NOT NULL,
//           method TEXT NOT NULL,
//           request TEXT NOT NULL,    -- compact JSON
//           response TEXT NOT NULL,   -- compact JSON
//           ok INTEGER NOT NULL,
//           duration_us INTEGER NOT NULL)
//
// We also keep an `index.db` at the sessions root (alongside the
// per-session dbs) so list() doesn't have to walk the filesystem and
// open every db just to enumerate. The per-session db remains
// authoritative for its own rpc_log; index.db is just a convenience
// directory.
//
// Concurrency contract (single-threaded dispatcher today):
//   • One Writer per session, held by the Dispatcher while a session
//     is attached. The dispatcher is single-threaded — no inter-thread
//     contention on a Writer. If a future agent makes the dispatcher
//     multi-threaded, the Writer's per-statement lock-free behavior
//     needs revisiting; the obvious fix is a mutex around append().
//   • Multiple SessionStore instances (different processes) can run
//     against the same root: sqlite WAL handles inter-process locking.
//   • info() / list() use the index db — they're safe to call while a
//     Writer is holding the per-session db.

namespace ldb::store {

struct SessionRow {
  std::string                 id;             // 32 lower-hex chars
  std::string                 name;
  std::optional<std::string>  target_id;
  std::int64_t                created_at = 0; // unix epoch nanoseconds
  std::int64_t                call_count = 0; // computed at query time
  std::optional<std::int64_t> last_call_at;   // ts_ns of last rpc, or none
  std::string                 path;           // absolute path to <uuid>.db
};

class SessionStore {
 public:
  // Open (or create) the session root. Creates ${root}/sessions/ if
  // absent; opens / migrates ${root}/sessions/index.db.
  // Throws backend::Error on filesystem or sqlite failure.
  explicit SessionStore(std::filesystem::path root);
  ~SessionStore();

  SessionStore(const SessionStore&)            = delete;
  SessionStore& operator=(const SessionStore&) = delete;
  SessionStore(SessionStore&&) noexcept;
  SessionStore& operator=(SessionStore&&) noexcept;

  // Create a new session: allocate a uuid (16 random bytes → 32 lower-
  // hex chars; sufficient entropy for our purposes — see worklog), make
  // the per-session db, write the index row, return a fresh SessionRow
  // with call_count=0 / last_call_at unset.
  SessionRow create(std::string_view name,
                    std::optional<std::string> target_id);

  // Lookup. Returns nullopt for "not found"; only sqlite errors throw.
  // Aggregates (call_count, last_call_at) are computed on demand from
  // the per-session rpc_log table — they reflect everything appended so
  // far, including by another in-flight Writer.
  std::optional<SessionRow> info(std::string_view id);

  // Enumerate every session. Sorted by created_at DESC (newest first —
  // the natural "what was I just doing" order).
  std::vector<SessionRow> list();

  // Open a per-session writer. The Writer holds its own sqlite handle
  // to the <uuid>.db; multiple Writers on the same id are allowed and
  // both can append (WAL handles it), but the dispatcher only ever
  // holds one at a time today.
  // Throws backend::Error if [id] doesn't exist in the index.
  class Writer;
  std::unique_ptr<Writer> open_writer(std::string_view id);

  // Import-side of `.ldbpack` (M5 part 5). One row in the rpc_log of an
  // imported session. Created and persisted by import_session below.
  // Times are inherited from the source session; we don't restamp them.
  struct ImportRow {
    std::int64_t  ts_ns        = 0;
    std::string   method;
    std::string   request_json;
    std::string   response_json;
    bool          ok           = true;
    std::int64_t  duration_us  = 0;
  };

  // import_session — used by `pack::unpack` to materialize a session
  // from a `.ldbpack` archive into this store. Behavior:
  //
  //   • [id] is the imported session's UUID. We preserve it (so cross-
  //     pack references remain stable).
  //   • If [overwrite] is false and the id already exists, throws
  //     backend::Error. If true, the existing row is dropped and the
  //     per-session db is replaced.
  //   • Writes a fresh per-session db at ${root}/sessions/<id>.db with
  //     the canonical meta + rpc_log schema, populated with [rows].
  //   • Inserts (or replaces) the index row.
  //
  // Note: this bypasses the normal create() / Writer::append() path —
  // it's the dual of the export side, not a general "ingest log."
  void import_session(std::string_view id,
                      std::string_view name,
                      std::optional<std::string> target_id,
                      std::int64_t created_at_ns,
                      const std::vector<ImportRow>& rows,
                      bool overwrite);

  // Resolve the configured root (post-canonicalization). Useful for
  // tests and the --help output.
  const std::filesystem::path& root() const noexcept;

  // Forward-declared opaque impl. Public-by-name only because the
  // .cpp's anonymous-namespace helpers need to take it by reference;
  // nothing outside the .cpp uses it. Same trick as ArtifactStore.
  struct Impl;

 private:
  std::unique_ptr<Impl> impl_;
};

class SessionStore::Writer {
 public:
  // Append one RPC row to the session's rpc_log. Compact-JSON-stringifies
  // [request] and [response]; stores [ok] as INTEGER (0/1) and
  // [duration_us] as the wall-clock cost the dispatcher measured for
  // dispatch_inner(). [ts_ns] is taken from system_clock at append-time.
  void append(std::string_view method,
              const nlohmann::json& request,
              const nlohmann::json& response,
              bool ok,
              std::int64_t duration_us);

  ~Writer();
  Writer(const Writer&) = delete;
  Writer& operator=(const Writer&) = delete;

  // Internal — constructed only by SessionStore::open_writer.
  struct Impl;
  explicit Writer(std::unique_ptr<Impl> impl);

 private:
  std::unique_ptr<Impl> impl_;
};

}  // namespace ldb::store
