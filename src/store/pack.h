// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// `.ldbpack` — gzip-compressed POSIX-tar (USTAR) archive of one or more
// sessions plus the artifacts associated with them. The format is the
// portable side of the artifact / session stores: a `.ldbpack` produced
// on machine A by an `ldbd` instance can be imported by another `ldbd`
// (or the same one after a wipe) and the agent's investigation state —
// sqlite session log, captured blobs — comes back exactly.
//
// Layout inside the archive (per docs/02-ldb-mvp-plan.md §8):
//
//   manifest.json                               required, top-level
//   sessions/
//     <session-uuid>.db                         per-session sqlite db
//     <session-uuid>.meta.json                  name, created_at, target_id, call_count
//   artifacts/
//     <build-id>/
//       <name>                                  the blob bytes
//       meta/
//         <name>.json                           sha256, byte_size, format,
//                                               meta, tags, created_at
//
// The format version is "ldbpack/1". Signing is deferred — MVP just
// emits and consumes the tarball.
//
// All public functions in this module throw backend::Error on any
// failure (missing file, bad tar header, sqlite import error, decompress
// overflow, path-traversal attempt). The dispatcher maps that to
// JSON-RPC -32000 with the original message verbatim.

namespace ldb::store {

class ArtifactStore;
class SessionStore;

enum class ConflictPolicy {
  kError,       // any duplicate aborts the whole import (default)
  kSkip,        // skip duplicates, import the rest, list them in `skipped`
  kOverwrite,   // replace local entries with imported ones
};

bool parse_conflict_policy(std::string_view s, ConflictPolicy* out);
const char* conflict_policy_str(ConflictPolicy p);

// One entry of the import report. The pair (kind, key) is opaque to the
// caller; the dispatcher just forwards it onto the wire as a list of
// strings ("session:<id>" / "artifact:<build_id>/<name>").
struct ImportEntry {
  std::string kind;     // "session" or "artifact"
  std::string key;      // session-id, or "<build_id>/<name>"
  std::string reason;   // populated on the skipped list (e.g. "duplicate id")
};

struct ImportReport {
  std::vector<ImportEntry> imported;
  std::vector<ImportEntry> skipped;
};

// What a freshly produced pack contains (returned by pack_session /
// pack_artifacts so the dispatcher can echo it back to the agent
// alongside the path).
struct PackResult {
  std::filesystem::path path;
  std::uint64_t         byte_size = 0;
  std::string           sha256;       // 64-char lower-hex
  nlohmann::json        manifest;     // whole manifest.json contents
};

// pack_session — write a single named session plus EVERY artifact in
// the artifact store (across all build_ids) to [output_path]. The
// "include all artifacts" choice is documented in the plan and the
// worklog: scoping to "artifacts whose build_id appears in the session
// log" is a separate, post-MVP slice.
PackResult pack_session(SessionStore& sessions,
                        ArtifactStore& artifacts,
                        std::string_view session_id,
                        const std::filesystem::path& output_path);

// pack_artifacts — write only artifacts to [output_path]. With
// [build_id] set, only that build_id's artifacts are included; with
// [names] set, only artifacts whose name is in that list. Both filters
// can be combined; both omitted means every artifact in the store.
PackResult pack_artifacts(ArtifactStore& artifacts,
                          std::optional<std::string> build_id,
                          std::optional<std::vector<std::string>> names,
                          const std::filesystem::path& output_path);

// unpack — open [input_path], walk the manifest, insert sessions and
// artifacts into the local stores. [policy] decides how duplicates are
// handled.
//
// Path-traversal defense: any tar entry whose canonicalized name
// contains ".." or starts with "/" is rejected with backend::Error.
//
// Decompressed-size cap: the unzipper aborts with backend::Error if the
// total decompressed bytes exceed 1 GiB. (Configurable in the helper if
// a future test needs to override it.)
ImportReport unpack(SessionStore& sessions,
                    ArtifactStore& artifacts,
                    const std::filesystem::path& input_path,
                    ConflictPolicy policy);

// ---- Lower-level primitives (exposed for unit tests) ---------------------

// One file in a tar archive — bytes-in-memory, USTAR layout.
struct TarEntry {
  std::string                name;     // relative; UTF-8; ≤ 255 bytes
  std::vector<std::uint8_t>  data;
  std::uint64_t              mtime = 0;
};

// Encode [entries] into a single uncompressed tar buffer. Output is a
// concatenation of 512-byte USTAR records plus the two zero blocks at
// the end.
std::vector<std::uint8_t> tar_pack(const std::vector<TarEntry>& entries);

// Decode an uncompressed tar buffer. Throws backend::Error on a torn
// header, a non-USTAR magic, an entry with ".." in its name, or an
// absolute path. Pax/long-link extensions are intentionally not
// supported — we control the producer side and we keep names short.
std::vector<TarEntry> tar_unpack(const std::vector<std::uint8_t>& bytes);

// Gzip the input. wbits=31 (gzip wrapping). Default compression level.
std::vector<std::uint8_t> gzip_compress(const std::vector<std::uint8_t>& in);

// Gunzip the input. Caps the *output* at [max_decompressed] bytes and
// throws backend::Error if the decoded stream would exceed it. This is
// the zip-bomb defense — pass 0 to mean "the default 1 GiB cap" or a
// smaller positive value if a unit test wants to exercise the trip.
std::vector<std::uint8_t>
gzip_decompress(const std::vector<std::uint8_t>& in,
                std::uint64_t max_decompressed = 0);

// Compute the lower-hex SHA-256 of [bytes]. Re-uses the same
// implementation as ArtifactStore (still confined to one TU per
// CLAUDE.md "no exceptions across module boundaries"; pack.cpp owns
// its own copy of the helper to avoid linkage shenanigans for now).
std::string sha256_hex(const std::vector<std::uint8_t>& bytes);

// ---- Internal pack-body builders (shared with pack_signing.cpp) ---------
//
// `build_session_pack_body` and `build_artifacts_pack_body` produce the
// raw tar-body entries (sessions/db, sessions/meta.json, artifacts/...,
// artifacts/.../meta/*.json) plus the assembled manifest. The manifest
// entry itself is NOT prepended — callers are expected to serialize the
// manifest after any final mutations (the signing layer bumps
// `manifest["format"]` to `"ldbpack/1+sig"` before serialization), then
// insert the manifest TarEntry at index 0 and gzip+write themselves.
//
// Exposed here so `src/store/pack_signing.cpp` can compose signed packs
// without duplicating session-export / artifact-export logic. Not part
// of the dispatcher surface.
struct PackBodyBuild {
  std::vector<TarEntry> tar_body;
  nlohmann::json        manifest;
};

PackBodyBuild
build_session_pack_body(SessionStore& sessions,
                        ArtifactStore& artifacts,
                        std::string_view session_id);

PackBodyBuild
build_artifacts_pack_body(ArtifactStore& artifacts,
                          const std::optional<std::string>& build_id,
                          const std::optional<std::vector<std::string>>& names);

// Serialize [manifest] into a TarEntry named "manifest.json" with the
// supplied mtime (epoch seconds). Used by both the unsigned and signed
// finalize paths so the bytes shape is identical when no signature is
// added.
TarEntry make_manifest_entry(const nlohmann::json& manifest,
                             std::uint64_t         mtime);

}  // namespace ldb::store
