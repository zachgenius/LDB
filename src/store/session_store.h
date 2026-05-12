// SPDX-License-Identifier: Apache-2.0
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

  // Tier 2 §6: one rpc_log row read back from a session's per-db.
  // recipe.from_session walks these to extract a recipe body.
  struct LogRow {
    std::int64_t  seq         = 0;
    std::int64_t  ts_ns       = 0;
    std::string   method;
    std::string   request_json;     // compact JSON as written by Writer::append
    std::string   response_json;
    bool          ok          = true;
    std::int64_t  duration_us = 0;
    // Post-V1 #16 phase-1 (docs/24 §3.1): captured response's
    // _provenance.snapshot. Empty string for rows written before
    // this column was added — replay treats empty as
    // "non-deterministic by default".
    std::string   snapshot;
  };

  // Read the rpc_log of a session in seq-ascending order. Optional
  // half-open [since_seq, until_seq) range filter (since_seq=0 means
  // from the beginning; until_seq=0 means to the end). Throws
  // backend::Error if the session id doesn't exist.
  std::vector<LogRow> read_log(std::string_view id,
                                std::int64_t since_seq = 0,
                                std::int64_t until_seq = 0);

  // Tier 3 §11: structured diff between two sessions' rpc_logs.
  //
  // The diff is content-only (timing fields are ignored). Two log rows
  // match iff their (method, canonical-params-JSON) tuples are
  // byte-equal; an aligned pair is "common" iff the canonical
  // response-JSON strings are also byte-equal, otherwise "diverged".
  // Unmatched A rows are "removed", unmatched B rows are "added".
  //
  // Alignment is computed via Longest Common Subsequence on the
  // (method, params_canon) tuple sequence. Entries are emitted in a
  // stable backtrack order: runs of "removed" (in A order) precede
  // "added" runs (in B order) within each gap; aligned entries
  // (common/diverged) appear at their alignment point.
  //
  // Canonicalization: stored request/response JSON strings are
  // re-parsed and re-dumped through nlohmann::json (whose object_t is
  // std::map, so keys are alphabetically sorted at dump time). This
  // shields the diff from key-order drift that might appear if a future
  // client emits its requests through a different JSON library.
  //
  // Throws backend::Error if either session id is unknown.
  struct DiffSummary {
    std::int64_t total_a   = 0;
    std::int64_t total_b   = 0;
    std::int64_t added     = 0;
    std::int64_t removed   = 0;
    std::int64_t common    = 0;
    std::int64_t diverged  = 0;
  };

  struct DiffEntry {
    // "common" | "added" | "removed" | "diverged"
    std::string  kind;
    std::string  method;
    // Canonical-JSON params string (alphabetically-keyed object dump).
    // Always set on every entry (it's the diff key).
    std::string  params_canon;
    // Short stable hash of params_canon — present on every entry. Used
    // by the wire shape on `common` entries to keep the response small
    // (caller can re-fetch full params via session.read_log if needed).
    std::string  params_hash;
    // seq from session A. 0 when entry is "added" (A had no row).
    std::int64_t seq_a = 0;
    // seq from session B. 0 when entry is "removed" (B had no row).
    std::int64_t seq_b = 0;
    // Canonical response strings.
    //   common:   response_a_canon == response_b_canon (set on a only)
    //   diverged: both set, differ
    //   added:    response_b_canon set, a empty
    //   removed:  response_a_canon set, b empty
    std::string  response_a_canon;
    std::string  response_b_canon;
  };

  struct DiffResult {
    DiffSummary             summary;
    std::vector<DiffEntry>  entries;
  };

  DiffResult diff_logs(std::string_view a_id, std::string_view b_id);

  // Tier 3 §9 — bucket a session's rpc_log rows by `params.target_id`.
  //
  // Walks the log in seq-ascending order; each row whose stored
  // request_json carries `params.target_id` as a non-negative integer
  // contributes to the bucket for that id. Rows without target_id (e.g.
  // hello, describe.endpoints, session.* themselves) and rows with
  // malformed JSON / non-integer target_id are silently skipped — the
  // function is a best-effort post-hoc inventory, not a parser
  // conformance check.
  //
  // Output is sorted ascending by target_id. Throws backend::Error if
  // the session id is unknown.
  struct TargetBucket {
    std::uint64_t  target_id  = 0;
    std::int64_t   call_count = 0;
    std::int64_t   first_seq  = 0;
    std::int64_t   last_seq   = 0;
  };
  std::vector<TargetBucket> extract_target_ids(std::string_view id);

  // Post-V1 plan #16 (docs/24-session-fork-replay.md §2.1).
  //
  // Allocate a fresh session id and copy [source_id]'s rpc_log row
  // payloads (ts_ns/method/request/response/ok/duration_us) up to and
  // including `until_seq` into it. `until_seq == 0` means "every row"
  // (head-of-source). `until_seq > source.max_seq` copies everything;
  // the reported `forked_at_seq` reflects the actual cut.
  //
  // The child re-numbers seq from 1 — sqlite AUTOINCREMENT is per-
  // table; what's semantically preserved is the per-row payload, not
  // the strict-monotonic seq id. See docs/24 §4 for the rationale.
  //
  // Target_id and the source's name (suffixed with " (fork)" when
  // `name` is empty) are copied into the child's meta. The parent
  // session is not mutated; concurrent appends to the parent during
  // the fork are not visible to the child (single sqlite transaction
  // on the child's db over a snapshot-read of the parent's rpc_log).
  //
  // Throws backend::Error if [source_id] doesn't exist or sqlite
  // fails mid-copy (the partially-written child db is removed in
  // that case so the index never references half-state).
  struct ForkResult {
    std::string  source_session_id;
    std::string  id;             // new 32-hex session id
    std::string  name;
    std::int64_t created_at   = 0;
    std::string  path;
    std::int64_t forked_at_seq= 0; // last source seq actually copied
    std::int64_t rows_copied  = 0;
  };
  ForkResult fork_session(std::string_view source_id,
                          std::string_view name,
                          std::optional<std::string> description,
                          std::int64_t until_seq);

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
    // Post-V1 #16 phase-1: pack-side snapshot column. Empty for
    // packs produced before this column existed; import preserves
    // whatever the manifest carried.
    std::string   snapshot;
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
  // [snapshot] is the dispatcher's resp.provenance_snapshot (see plan
  // §3.5) — empty string is allowed and means "snapshot not recorded";
  // post-V1 #16's replay gate treats empty as "non-deterministic by
  // default" (docs/24 §3.1).
  void append(std::string_view method,
              const nlohmann::json& request,
              const nlohmann::json& response,
              bool ok,
              std::int64_t duration_us,
              std::string_view snapshot = "");

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
