// SPDX-License-Identifier: Apache-2.0
#include "store/pack.h"

#include "backend/debugger_backend.h"
#include "store/artifact_store.h"
#include "store/session_store.h"
#include "util/sha256.h"

#include <sqlite3.h>
#include <zlib.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ldb::store {

namespace {

// SHA-256 used to live here as a private nested class; it now lives in
// src/util/sha256.{h,cpp} so target.load_core (cores-only `_provenance`
// in M5 part 6) can re-use the same implementation. We keep the public
// `sha256_hex(bytes)` declaration in pack.h — it's part of the lower-
// level primitive surface — but it now forwards to ldb::util.

// ---------- USTAR ---------------------------------------------------------
//
// We emit a minimal USTAR-compliant header — magic "ustar\0", version
// "00". File mode is fixed 0644 (regular files only); uid/gid/uname/
// gname are zeroed; typeflag is '0' (regular file). devmajor / devminor
// blank. mtime is the entry's stamp (epoch seconds).

constexpr std::size_t kBlock = 512;

struct UstarHeader {
  char name[100];
  char mode[8];
  char uid[8];
  char gid[8];
  char size[12];
  char mtime[12];
  char chksum[8];
  char typeflag;
  char linkname[100];
  char magic[6];
  char version[2];
  char uname[32];
  char gname[32];
  char devmajor[8];
  char devminor[8];
  char prefix[155];
  char pad[12];
};
static_assert(sizeof(UstarHeader) == 512, "USTAR header must be 512 bytes");

void write_octal(char* dst, std::size_t width, std::uint64_t v) {
  // POSIX octal field, NUL-terminated. Width-1 octal digits + NUL.
  std::string s;
  if (v == 0) {
    s = "0";
  } else {
    std::uint64_t x = v;
    while (x) {
      s.push_back(static_cast<char>('0' + static_cast<int>(x & 7u)));
      x >>= 3;
    }
    std::reverse(s.begin(), s.end());
  }
  // Pad with leading zeros to width-1.
  if (s.size() >= width) {
    // Field overflow — caller bug. We only emit this for sizes/times we
    // control, so just truncate the high digits; the consumer's checksum
    // verification will catch the inconsistency.
    s = s.substr(s.size() - (width - 1));
  } else {
    s = std::string(width - 1 - s.size(), '0') + s;
  }
  std::memset(dst, 0, width);
  std::memcpy(dst, s.data(), s.size());  // NUL terminator from memset
}

std::uint64_t parse_octal(const char* src, std::size_t width) {
  std::uint64_t v = 0;
  for (std::size_t i = 0; i < width; ++i) {
    char c = src[i];
    if (c == 0 || c == ' ') break;
    if (c < '0' || c > '7') {
      // Garbage in the field. POSIX leaves trailing-space behavior up
      // to producers; we don't see those because we control both ends.
      throw backend::Error("pack.tar: bad octal digit in header field");
    }
    v = (v << 3) | static_cast<std::uint64_t>(c - '0');
  }
  return v;
}

void write_header(UstarHeader& h, const TarEntry& e) {
  std::memset(&h, 0, sizeof(h));
  if (e.name.size() > sizeof(h.name) - 1) {
    // We don't pack the prefix field — keeps the codec simple. Caller
    // must keep names ≤ 99 chars. None of the names we emit (sha256-ish
    // hashes, sqlite db filenames, build_id/name pairs) reach that.
    throw backend::Error("pack.tar: name too long: " + e.name);
  }
  std::memcpy(h.name, e.name.data(), e.name.size());
  write_octal(h.mode, sizeof(h.mode), 0644);
  write_octal(h.uid,  sizeof(h.uid),  0);
  write_octal(h.gid,  sizeof(h.gid),  0);
  write_octal(h.size, sizeof(h.size), e.data.size());
  write_octal(h.mtime, sizeof(h.mtime), e.mtime);
  // Compute checksum over the header with the chksum field treated as
  // 8 spaces. That's the USTAR convention.
  std::memset(h.chksum, ' ', sizeof(h.chksum));
  h.typeflag = '0';
  std::memcpy(h.magic,   "ustar", 5);
  h.magic[5] = '\0';
  h.version[0] = '0';
  h.version[1] = '0';

  std::uint32_t sum = 0;
  const auto* raw = reinterpret_cast<const std::uint8_t*>(&h);
  for (std::size_t i = 0; i < sizeof(h); ++i) sum += raw[i];
  // Field is 6 octal digits + NUL + space (per spec).
  write_octal(h.chksum, 7, sum);
  h.chksum[7] = ' ';
}

bool name_is_safe(std::string_view name) {
  if (name.empty()) return false;
  if (name.front() == '/') return false;
  // Reject any path component that is exactly "..".
  std::string_view rest = name;
  while (!rest.empty()) {
    auto slash = rest.find('/');
    std::string_view comp = (slash == std::string_view::npos)
                                ? rest
                                : rest.substr(0, slash);
    if (comp == "..") return false;
    if (slash == std::string_view::npos) break;
    rest = rest.substr(slash + 1);
  }
  return true;
}

// ---------- helpers used by the high-level pack/unpack -------------------

[[noreturn]] void throw_io(std::string_view what,
                            const std::error_code& ec) {
  std::string m = "pack io: ";
  m.append(what);
  m.append(": ");
  m.append(ec.message());
  throw backend::Error(m);
}

std::vector<std::uint8_t> read_file_all(const std::filesystem::path& p) {
  std::ifstream in(p, std::ios::binary);
  if (!in) throw backend::Error("pack io: open: " + p.string());
  in.seekg(0, std::ios::end);
  auto sz = in.tellg();
  if (sz < 0) throw backend::Error("pack io: tellg: " + p.string());
  in.seekg(0, std::ios::beg);
  std::vector<std::uint8_t> out(static_cast<std::size_t>(sz));
  if (sz > 0) {
    in.read(reinterpret_cast<char*>(out.data()),
            static_cast<std::streamsize>(out.size()));
    if (!in.good() && !in.eof()) {
      throw backend::Error("pack io: read: " + p.string());
    }
  }
  return out;
}

void write_file_all(const std::filesystem::path& p,
                    const std::vector<std::uint8_t>& bytes) {
  namespace fs = std::filesystem;
  std::error_code ec;
  fs::create_directories(p.parent_path(), ec);
  if (ec) throw_io("create_directories", ec);
  std::ofstream out(p, std::ios::binary | std::ios::trunc);
  if (!out) throw backend::Error("pack io: open out: " + p.string());
  if (!bytes.empty()) {
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
  }
  out.flush();
  if (!out) throw backend::Error("pack io: write: " + p.string());
}

constexpr std::uint64_t kDefaultDecompressCap = 1ull << 30;  // 1 GiB

std::int64_t epoch_seconds_now() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch()).count();
}

// Read every row from a session's per-session sqlite db so we can write
// it into a fresh local db on import. Cleaner than copying the file
// because the importer can choose a fresh uuid (avoids an id clash) and
// because a copy-with-WAL mid-write would be fragile.
struct SessionExport {
  std::string                 name;
  std::optional<std::string>  target_id;
  std::int64_t                created_at = 0;
  // Each rpc_log row, in order.
  struct Row {
    std::int64_t  ts_ns;
    std::string   method;
    std::string   request_json;
    std::string   response_json;
    bool          ok;
    std::int64_t  duration_us;
  };
  std::vector<Row> rows;
};

[[noreturn]] void throw_sqlite_open(const std::filesystem::path& p) {
  throw backend::Error("pack: sqlite open: " + p.string());
}

// Build a fresh, coherent per-session sqlite db (in a temp file) from
// an existing SessionExport's rows. Returns the file's bytes. We do
// this on the export side so the bytes shipped in the tar are a clean
// non-WAL snapshot — the live source db may have its newest rows still
// sitting in `<id>.db-wal`, and copying just `<id>.db` would miss them.
std::vector<std::uint8_t>
materialize_session_db(const SessionExport& src,
                       std::string_view name) {
  namespace fs = std::filesystem;
  fs::path tmp = fs::temp_directory_path() /
      ("ldbpack_export_" + std::string(name) + "_" +
       std::to_string(static_cast<std::uint64_t>(
           std::chrono::system_clock::now().time_since_epoch().count()))
       + ".db");

  sqlite3* db = nullptr;
  int rc = sqlite3_open(tmp.c_str(), &db);
  if (rc != SQLITE_OK) {
    if (db) sqlite3_close(db);
    std::error_code ignore;
    fs::remove(tmp, ignore);
    throw backend::Error("pack: sqlite open " + tmp.string());
  }

  auto exec = [&](const char* sql) {
    char* err = nullptr;
    int r = sqlite3_exec(db, sql, nullptr, nullptr, &err);
    if (r != SQLITE_OK) {
      std::string m = "pack: sqlite exec: ";
      m.append(err ? err : sqlite3_errmsg(db));
      sqlite3_free(err);
      sqlite3_close(db);
      std::error_code ignore;
      fs::remove(tmp, ignore);
      throw backend::Error(m);
    }
  };

  // Use rollback journal mode (default) — we want a single-file db,
  // not a WAL pair, and the destination won't be written to after this.
  exec("PRAGMA journal_mode=DELETE;");
  exec("PRAGMA synchronous=NORMAL;");
  exec(
    "CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);"
    "CREATE TABLE rpc_log("
    "  seq INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  ts_ns INTEGER NOT NULL,"
    "  method TEXT NOT NULL,"
    "  request TEXT NOT NULL,"
    "  response TEXT NOT NULL,"
    "  ok INTEGER NOT NULL,"
    "  duration_us INTEGER NOT NULL"
    ");"
    "CREATE INDEX idx_rpc_method ON rpc_log(method);"
  );

  auto put_meta = [&](const char* k, const std::string& v) {
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO meta(k, v) VALUES(?1, ?2);",
            -1, &stmt, nullptr) != SQLITE_OK) {
      sqlite3_close(db);
      std::error_code ignore;
      fs::remove(tmp, ignore);
      throw backend::Error("pack: prepare meta insert");
    }
    sqlite3_bind_text(stmt, 1, k, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, v.c_str(), static_cast<int>(v.size()),
                      SQLITE_TRANSIENT);
    int r = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (r != SQLITE_DONE) {
      sqlite3_close(db);
      std::error_code ignore;
      fs::remove(tmp, ignore);
      throw backend::Error("pack: meta insert failed");
    }
  };
  put_meta("schema_version", "1");
  put_meta("name", src.name);
  put_meta("created_at", std::to_string(src.created_at));
  if (src.target_id.has_value()) put_meta("target_id", *src.target_id);

  if (!src.rows.empty()) {
    exec("BEGIN IMMEDIATE;");
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db,
        "INSERT INTO rpc_log(ts_ns, method, request, response, ok, "
        "                    duration_us) "
        "VALUES(?1, ?2, ?3, ?4, ?5, ?6);", -1, &stmt, nullptr) != SQLITE_OK) {
      sqlite3_close(db);
      std::error_code ignore;
      fs::remove(tmp, ignore);
      throw backend::Error("pack: prepare rpc_log insert");
    }
    for (const auto& r : src.rows) {
      sqlite3_reset(stmt);
      sqlite3_clear_bindings(stmt);
      sqlite3_bind_int64(stmt, 1, r.ts_ns);
      sqlite3_bind_text (stmt, 2, r.method.c_str(),
                         static_cast<int>(r.method.size()),
                         SQLITE_TRANSIENT);
      sqlite3_bind_text (stmt, 3, r.request_json.c_str(),
                         static_cast<int>(r.request_json.size()),
                         SQLITE_TRANSIENT);
      sqlite3_bind_text (stmt, 4, r.response_json.c_str(),
                         static_cast<int>(r.response_json.size()),
                         SQLITE_TRANSIENT);
      sqlite3_bind_int  (stmt, 5, r.ok ? 1 : 0);
      sqlite3_bind_int64(stmt, 6, r.duration_us);
      if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        std::error_code ignore;
        fs::remove(tmp, ignore);
        throw backend::Error("pack: rpc_log insert failed");
      }
    }
    sqlite3_finalize(stmt);
    exec("COMMIT;");
  }

  sqlite3_close(db);
  auto bytes = read_file_all(tmp);
  std::error_code ignore;
  fs::remove(tmp, ignore);
  return bytes;
}

SessionExport read_session_db(const std::filesystem::path& dbpath) {
  SessionExport out;
  sqlite3* db = nullptr;
  int rc = sqlite3_open_v2(dbpath.c_str(), &db, SQLITE_OPEN_READONLY,
                           nullptr);
  if (rc != SQLITE_OK) {
    if (db) sqlite3_close(db);
    throw_sqlite_open(dbpath);
  }

  // meta
  {
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, "SELECT k, v FROM meta;", -1, &stmt,
                           nullptr) != SQLITE_OK) {
      sqlite3_close(db);
      throw backend::Error(std::string("pack: prepare meta: ") +
                           sqlite3_errmsg(db));
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
      std::string k = reinterpret_cast<const char*>(
          sqlite3_column_text(stmt, 0));
      std::string v = reinterpret_cast<const char*>(
          sqlite3_column_text(stmt, 1));
      if (k == "name")              out.name = v;
      else if (k == "target_id")    out.target_id = v;
      else if (k == "created_at") {
        try { out.created_at = std::stoll(v); }
        catch (...) { /* best effort */ }
      }
    }
    sqlite3_finalize(stmt);
  }

  // rpc_log
  {
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT ts_ns, method, request, response, ok, "
                      "duration_us FROM rpc_log ORDER BY seq ASC;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
      sqlite3_close(db);
      throw backend::Error(std::string("pack: prepare rpc_log: ") +
                           sqlite3_errmsg(db));
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
      SessionExport::Row r;
      r.ts_ns        = sqlite3_column_int64(stmt, 0);
      auto m         = reinterpret_cast<const char*>(
          sqlite3_column_text(stmt, 1));
      auto req       = reinterpret_cast<const char*>(
          sqlite3_column_text(stmt, 2));
      auto rsp       = reinterpret_cast<const char*>(
          sqlite3_column_text(stmt, 3));
      r.method       = m   ? m   : "";
      r.request_json = req ? req : "{}";
      r.response_json= rsp ? rsp : "{}";
      r.ok           = sqlite3_column_int(stmt, 4) != 0;
      r.duration_us  = sqlite3_column_int64(stmt, 5);
      out.rows.push_back(std::move(r));
    }
    sqlite3_finalize(stmt);
  }

  sqlite3_close(db);
  return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// Public lower-level primitives

std::string sha256_hex(const std::vector<std::uint8_t>& bytes) {
  return ::ldb::util::sha256_hex(bytes);
}

std::vector<std::uint8_t> tar_pack(const std::vector<TarEntry>& entries) {
  std::vector<std::uint8_t> out;
  for (const auto& e : entries) {
    UstarHeader h{};
    write_header(h, e);
    auto p = reinterpret_cast<const std::uint8_t*>(&h);
    out.insert(out.end(), p, p + sizeof(h));
    if (!e.data.empty()) {
      out.insert(out.end(), e.data.begin(), e.data.end());
      // Pad to multiple of 512.
      auto rem = e.data.size() % kBlock;
      if (rem != 0) {
        out.insert(out.end(), kBlock - rem, std::uint8_t{0});
      }
    }
  }
  // Two zero blocks terminate the archive.
  out.insert(out.end(), 2 * kBlock, std::uint8_t{0});
  return out;
}

std::vector<TarEntry> tar_unpack(const std::vector<std::uint8_t>& bytes) {
  std::vector<TarEntry> out;
  std::size_t off = 0;
  while (off + kBlock <= bytes.size()) {
    // Trailing zero blocks → end of archive.
    bool all_zero = true;
    for (std::size_t i = 0; i < kBlock; ++i) {
      if (bytes[off + i] != 0) { all_zero = false; break; }
    }
    if (all_zero) break;

    if (off + kBlock > bytes.size()) {
      throw backend::Error("pack.tar: truncated header");
    }

    UstarHeader h;
    std::memcpy(&h, bytes.data() + off, sizeof(h));
    off += kBlock;

    // Magic check — be lenient about NUL/space variants.
    if (std::memcmp(h.magic, "ustar", 5) != 0) {
      throw backend::Error("pack.tar: not a USTAR header (bad magic)");
    }

    std::string name(h.name, ::strnlen(h.name, sizeof(h.name)));
    std::uint64_t size = parse_octal(h.size, sizeof(h.size));
    if (off + size > bytes.size()) {
      throw backend::Error("pack.tar: entry data overruns archive");
    }
    if (!name_is_safe(name)) {
      throw backend::Error("pack.tar: unsafe path: " + name);
    }
    if (h.typeflag != '0' && h.typeflag != '\0') {
      // We only emit regular files; importers that see a different
      // typeflag (directory '5', symlink '2') get a clear refusal.
      throw backend::Error("pack.tar: unsupported typeflag for " + name);
    }

    TarEntry e;
    e.name  = std::move(name);
    e.mtime = parse_octal(h.mtime, sizeof(h.mtime));
    if (size > 0) {
      e.data.assign(bytes.begin() + static_cast<std::ptrdiff_t>(off),
                    bytes.begin() + static_cast<std::ptrdiff_t>(off + size));
      off += size;
      // Skip zero padding to the next 512-boundary.
      auto rem = size % kBlock;
      if (rem != 0) off += kBlock - rem;
    }
    out.push_back(std::move(e));
  }
  return out;
}

std::vector<std::uint8_t>
gzip_compress(const std::vector<std::uint8_t>& in) {
  z_stream zs{};
  // wbits = 31 → 15 + 16 = max window + gzip wrapper.
  if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 31, 8,
                   Z_DEFAULT_STRATEGY) != Z_OK) {
    throw backend::Error("pack.gzip: deflateInit2 failed");
  }
  zs.next_in  = const_cast<Bytef*>(in.data());
  zs.avail_in = static_cast<uInt>(in.size());

  std::vector<std::uint8_t> out;
  std::vector<std::uint8_t> chunk(64 * 1024);
  int rc;
  do {
    zs.next_out  = chunk.data();
    zs.avail_out = static_cast<uInt>(chunk.size());
    rc = deflate(&zs, Z_FINISH);
    if (rc == Z_STREAM_ERROR) {
      deflateEnd(&zs);
      throw backend::Error("pack.gzip: deflate stream error");
    }
    auto produced = chunk.size() - zs.avail_out;
    out.insert(out.end(), chunk.begin(),
               chunk.begin() + static_cast<std::ptrdiff_t>(produced));
  } while (rc != Z_STREAM_END);
  deflateEnd(&zs);
  return out;
}

std::vector<std::uint8_t>
gzip_decompress(const std::vector<std::uint8_t>& in,
                std::uint64_t max_decompressed) {
  if (max_decompressed == 0) max_decompressed = kDefaultDecompressCap;

  z_stream zs{};
  if (inflateInit2(&zs, 31) != Z_OK) {
    throw backend::Error("pack.gzip: inflateInit2 failed");
  }
  zs.next_in  = const_cast<Bytef*>(in.data());
  zs.avail_in = static_cast<uInt>(in.size());

  std::vector<std::uint8_t> out;
  std::vector<std::uint8_t> chunk(64 * 1024);
  int rc;
  do {
    zs.next_out  = chunk.data();
    zs.avail_out = static_cast<uInt>(chunk.size());
    rc = inflate(&zs, Z_NO_FLUSH);
    if (rc == Z_NEED_DICT || rc == Z_DATA_ERROR ||
        rc == Z_MEM_ERROR  || rc == Z_STREAM_ERROR) {
      inflateEnd(&zs);
      throw backend::Error("pack.gzip: inflate failed (corrupt input)");
    }
    auto produced = chunk.size() - zs.avail_out;
    if (out.size() + produced > max_decompressed) {
      inflateEnd(&zs);
      throw backend::Error("pack.gzip: decompressed output exceeds cap");
    }
    out.insert(out.end(), chunk.begin(),
               chunk.begin() + static_cast<std::ptrdiff_t>(produced));
    if (rc == Z_STREAM_END) break;
    if (zs.avail_in == 0 && zs.avail_out != 0) {
      // Decoder is stalled with no more input — input was truncated.
      inflateEnd(&zs);
      throw backend::Error("pack.gzip: input truncated");
    }
  } while (rc != Z_STREAM_END);
  inflateEnd(&zs);
  return out;
}

bool parse_conflict_policy(std::string_view s, ConflictPolicy* out) {
  if (s == "error")     { *out = ConflictPolicy::kError;     return true; }
  if (s == "skip")      { *out = ConflictPolicy::kSkip;      return true; }
  if (s == "overwrite") { *out = ConflictPolicy::kOverwrite; return true; }
  return false;
}

const char* conflict_policy_str(ConflictPolicy p) {
  switch (p) {
    case ConflictPolicy::kError:     return "error";
    case ConflictPolicy::kSkip:      return "skip";
    case ConflictPolicy::kOverwrite: return "overwrite";
  }
  return "error";
}

// ---------------------------------------------------------------------------
// Manifest helpers

namespace {

nlohmann::json make_manifest_skeleton() {
  nlohmann::json m;
  m["format"]      = "ldbpack/1";
  m["created_at"]  = epoch_seconds_now();
  m["creator"]     = "ldbd 0.1.0";
  m["sessions"]    = nlohmann::json::array();
  m["artifacts"]   = nlohmann::json::array();
  // Relations live alongside artifacts (post-v0.1 §7). Endpoint ids on
  // the wire are the SOURCE store's ids; on import they are remapped to
  // the destination store's ids by looking up (build_id, name).
  m["relations"]   = nlohmann::json::array();
  return m;
}

// Encode one artifact into both the manifest entry and the tar entries
// (blob + meta sidecar). Pushes onto [tar] and returns the manifest
// row.
//
// Relations are emitted later, after every artifact has been processed,
// so we know the full id-set for the "both endpoints inside the export"
// filter.
nlohmann::json
emit_artifact(std::vector<TarEntry>& tar,
              ArtifactStore& as,
              const ArtifactRow& row) {
  std::string blob_name = "artifacts/" + row.build_id + "/" + row.name;
  std::string meta_name = "artifacts/" + row.build_id + "/meta/" +
                           row.name + ".json";
  // Defense in depth: the build_id and name are agent-supplied at
  // creation time. Safe-name verification happens on extract too, but
  // catch obviously bad producers here.
  if (!name_is_safe(blob_name) || !name_is_safe(meta_name)) {
    throw backend::Error("pack: unsafe artifact key (build_id or name "
                         "contains '/' or '..')");
  }
  auto bytes = as.read_blob(row);
  TarEntry blob_entry;
  blob_entry.name  = blob_name;
  blob_entry.data  = bytes;
  blob_entry.mtime = static_cast<std::uint64_t>(row.created_at);
  tar.push_back(std::move(blob_entry));

  nlohmann::json meta;
  meta["build_id"]   = row.build_id;
  meta["name"]       = row.name;
  meta["sha256"]     = row.sha256;
  meta["byte_size"]  = row.byte_size;
  if (row.format.has_value()) meta["format"] = *row.format;
  meta["meta"]       = row.meta;
  meta["tags"]       = row.tags;
  meta["created_at"] = row.created_at;
  std::string meta_str = meta.dump();

  TarEntry meta_entry;
  meta_entry.name  = meta_name;
  meta_entry.data  = std::vector<std::uint8_t>(meta_str.begin(),
                                                meta_str.end());
  meta_entry.mtime = static_cast<std::uint64_t>(row.created_at);
  tar.push_back(std::move(meta_entry));

  nlohmann::json mrow;
  mrow["build_id"]  = row.build_id;
  mrow["name"]      = row.name;
  mrow["sha256"]    = row.sha256;
  mrow["byte_size"] = row.byte_size;
  mrow["path"]      = blob_name;
  return mrow;
}

// Walk the store's relations, drop edges whose endpoints aren't both in
// [exported] (the rows we just emitted), and rewrite each endpoint to
// (build_id, name). The destination side will resolve those back to its
// own ids during unpack — this is the id-remap channel.
nlohmann::json
emit_relations_for(ArtifactStore& as,
                   const std::vector<ArtifactRow>& exported) {
  // Map source-store id → ArtifactRow* for both the in-set check and
  // the (build_id, name) lookup. Linear over `exported` is fine — these
  // sets are small (an investigation captures dozens, not millions).
  std::unordered_map<std::int64_t, const ArtifactRow*> by_id;
  by_id.reserve(exported.size());
  for (const auto& r : exported) by_id.emplace(r.id, &r);

  auto rels = as.list_relations(std::nullopt, std::nullopt,
                                 RelationDir::kBoth);
  nlohmann::json arr = nlohmann::json::array();
  for (const auto& rel : rels) {
    auto fit = by_id.find(rel.from_id);
    auto tit = by_id.find(rel.to_id);
    if (fit == by_id.end() || tit == by_id.end()) continue;  // dangling
    nlohmann::json e;
    e["from_build_id"] = fit->second->build_id;
    e["from_name"]     = fit->second->name;
    e["to_build_id"]   = tit->second->build_id;
    e["to_name"]       = tit->second->name;
    e["predicate"]     = rel.predicate;
    e["meta"]          = rel.meta;
    e["created_at"]    = rel.created_at;
    arr.push_back(std::move(e));
  }
  return arr;
}

}  // namespace

PackBodyBuild
build_session_pack_body(SessionStore& sessions,
                        ArtifactStore& artifacts,
                        std::string_view session_id) {
  auto info = sessions.info(session_id);
  if (!info.has_value()) {
    throw backend::Error("pack: no such session: " + std::string(session_id));
  }

  PackBodyBuild out;
  out.manifest = make_manifest_skeleton();

  // session db + meta sidecar. Read the rows via sqlite read-only,
  // then materialize a clean non-WAL .db in a temp file and ship those
  // bytes — copying the live <id>.db verbatim would miss committed
  // rows still sitting in <id>.db-wal.
  auto src = read_session_db(info->path);
  // Source's metadata wins for the in-pack copy; the index data lives
  // outside the per-session db and is only relevant for the index row
  // we stash in the manifest.
  if (src.name.empty()) src.name = info->name;
  if (!src.target_id.has_value() && info->target_id.has_value()) {
    src.target_id = info->target_id;
  }
  if (src.created_at == 0) src.created_at = info->created_at;
  auto db_bytes = materialize_session_db(src, info->id);

  std::string db_name = "sessions/" + info->id + ".db";
  std::string mt_name = "sessions/" + info->id + ".meta.json";

  TarEntry db_entry;
  db_entry.name  = db_name;
  db_entry.data  = std::move(db_bytes);
  db_entry.mtime = static_cast<std::uint64_t>(info->created_at / 1'000'000'000);
  out.tar_body.push_back(std::move(db_entry));

  nlohmann::json sess_meta;
  sess_meta["id"]         = info->id;
  sess_meta["name"]       = info->name;
  if (info->target_id.has_value()) sess_meta["target_id"] = *info->target_id;
  sess_meta["created_at"] = info->created_at;
  sess_meta["call_count"] = info->call_count;
  if (info->last_call_at.has_value()) {
    sess_meta["last_call_at"] = *info->last_call_at;
  }
  std::string mt_str = sess_meta.dump();

  TarEntry mt_entry;
  mt_entry.name  = mt_name;
  mt_entry.data  = std::vector<std::uint8_t>(mt_str.begin(), mt_str.end());
  mt_entry.mtime = out.tar_body.back().mtime;
  out.tar_body.push_back(std::move(mt_entry));

  nlohmann::json srow;
  srow["id"]         = info->id;
  srow["name"]       = info->name;
  srow["call_count"] = info->call_count;
  srow["path"]       = db_name;
  if (info->target_id.has_value()) srow["target_id"] = *info->target_id;
  out.manifest["sessions"].push_back(std::move(srow));

  // every artifact in the store. This is the documented MVP
  // simplification — narrowing to "artifacts referenced by the session
  // log" is a separate, post-MVP slice.
  auto rows = artifacts.list(std::nullopt, std::nullopt);
  for (const auto& r : rows) {
    auto mrow = emit_artifact(out.tar_body, artifacts, r);
    out.manifest["artifacts"].push_back(std::move(mrow));
  }

  // Knowledge-graph relations (post-v0.1 §7). Endpoints not in the
  // exported artifact set are filtered out so the import side never has
  // to chase a dangling id.
  out.manifest["relations"] = emit_relations_for(artifacts, rows);
  return out;
}

PackBodyBuild
build_artifacts_pack_body(ArtifactStore& artifacts,
                          const std::optional<std::string>& build_id,
                          const std::optional<std::vector<std::string>>& names) {
  PackBodyBuild out;
  out.manifest = make_manifest_skeleton();

  auto rows = artifacts.list(build_id, std::nullopt);
  std::vector<ArtifactRow> exported;
  for (const auto& r : rows) {
    if (names.has_value()) {
      bool matched = false;
      for (const auto& n : *names) {
        if (n == r.name) { matched = true; break; }
      }
      if (!matched) continue;
    }
    auto mrow = emit_artifact(out.tar_body, artifacts, r);
    out.manifest["artifacts"].push_back(std::move(mrow));
    exported.push_back(r);
  }
  out.manifest["relations"] = emit_relations_for(artifacts, exported);
  return out;
}

TarEntry make_manifest_entry(const nlohmann::json& manifest,
                             std::uint64_t         mtime) {
  std::string manifest_str = manifest.dump();
  TarEntry m_entry;
  m_entry.name  = "manifest.json";
  m_entry.data  = std::vector<std::uint8_t>(manifest_str.begin(),
                                             manifest_str.end());
  m_entry.mtime = mtime;
  return m_entry;
}

PackResult pack_session(SessionStore& sessions,
                        ArtifactStore& artifacts,
                        std::string_view session_id,
                        const std::filesystem::path& output_path) {
  auto built = build_session_pack_body(sessions, artifacts, session_id);

  // manifest goes first inside the tar (top-level introspection).
  auto m_entry = make_manifest_entry(built.manifest,
      static_cast<std::uint64_t>(epoch_seconds_now()));
  built.tar_body.insert(built.tar_body.begin(), std::move(m_entry));

  auto raw  = tar_pack(built.tar_body);
  auto comp = gzip_compress(raw);

  write_file_all(output_path, comp);

  PackResult res;
  res.path      = output_path;
  res.byte_size = static_cast<std::uint64_t>(comp.size());
  res.sha256    = sha256_hex(comp);
  res.manifest  = std::move(built.manifest);
  return res;
}

PackResult pack_artifacts(ArtifactStore& artifacts,
                          std::optional<std::string> build_id,
                          std::optional<std::vector<std::string>> names,
                          const std::filesystem::path& output_path) {
  auto built = build_artifacts_pack_body(artifacts, build_id, names);

  auto m_entry = make_manifest_entry(built.manifest,
      static_cast<std::uint64_t>(epoch_seconds_now()));
  built.tar_body.insert(built.tar_body.begin(), std::move(m_entry));

  auto raw  = tar_pack(built.tar_body);
  auto comp = gzip_compress(raw);
  write_file_all(output_path, comp);

  PackResult res;
  res.path      = output_path;
  res.byte_size = static_cast<std::uint64_t>(comp.size());
  res.sha256    = sha256_hex(comp);
  res.manifest  = std::move(built.manifest);
  return res;
}

// ---------------------------------------------------------------------------
// unpack — the importer

ImportReport unpack(SessionStore& sessions,
                    ArtifactStore& artifacts,
                    const std::filesystem::path& input_path,
                    ConflictPolicy policy) {
  auto comp = read_file_all(input_path);
  auto raw  = gzip_decompress(comp);
  auto entries = tar_unpack(raw);

  // Bucket by name for cheap lookup during the manifest walk.
  std::vector<std::uint8_t>* manifest_bytes = nullptr;
  for (auto& e : entries) {
    if (e.name == "manifest.json") {
      manifest_bytes = &e.data;
      break;
    }
  }
  if (manifest_bytes == nullptr) {
    throw backend::Error("pack: manifest.json missing");
  }

  nlohmann::json manifest;
  try {
    manifest = nlohmann::json::parse(manifest_bytes->begin(),
                                     manifest_bytes->end());
  } catch (const std::exception& e) {
    throw backend::Error(std::string("pack: manifest.json parse error: ") +
                         e.what());
  }
  if (!manifest.is_object() || !manifest.contains("format")) {
    throw backend::Error("pack: manifest format missing");
  }
  {
    auto fmt = manifest["format"].is_string()
                   ? manifest["format"].get<std::string>()
                   : std::string{};
    if (fmt != "ldbpack/1" && fmt != "ldbpack/1+sig") {
      throw backend::Error("pack: manifest format != ldbpack/1 (got '" +
                           fmt + "')");
    }
  }

  auto find_entry = [&](const std::string& name)
      -> std::vector<std::uint8_t>* {
    for (auto& e : entries) if (e.name == name) return &e.data;
    return nullptr;
  };

  // First pass under "error" policy: detect every conflict before
  // mutating either store. (Skip / overwrite operate row-by-row.)
  if (policy == ConflictPolicy::kError) {
    if (manifest.contains("sessions")) {
      for (const auto& s : manifest["sessions"]) {
        if (!s.contains("id")) continue;
        std::string id = s["id"].get<std::string>();
        if (sessions.info(id).has_value()) {
          throw backend::Error("pack: duplicate session id: " + id);
        }
      }
    }
    if (manifest.contains("artifacts")) {
      for (const auto& a : manifest["artifacts"]) {
        if (!a.contains("build_id") || !a.contains("name")) continue;
        std::string bid = a["build_id"].get<std::string>();
        std::string nm  = a["name"].get<std::string>();
        if (artifacts.get_by_name(bid, nm).has_value()) {
          throw backend::Error("pack: duplicate artifact: " + bid + "/" + nm);
        }
      }
    }
  }

  ImportReport report;

  // sessions
  if (manifest.contains("sessions")) {
    for (const auto& s : manifest["sessions"]) {
      if (!s.contains("id") || !s.contains("path")) {
        throw backend::Error("pack: malformed session manifest entry");
      }
      std::string id   = s["id"].get<std::string>();
      std::string path = s["path"].get<std::string>();
      auto* dbb = find_entry(path);
      if (dbb == nullptr) {
        throw backend::Error("pack: missing tar entry for session "
                             + id + " at " + path);
      }
      bool exists = sessions.info(id).has_value();
      if (exists && policy == ConflictPolicy::kSkip) {
        report.skipped.push_back(
            {"session", id, "duplicate id"});
        continue;
      }
      // Read the in-tar db so we can copy rows into the local store.
      // We materialize it to a temp file first so we can use sqlite
      // open-readonly on the original schema; round-trip via
      // SessionStore::import_session to honor the public contract.
      std::filesystem::path tmp = std::filesystem::temp_directory_path() /
          ("ldbpack_import_" + id + ".db");
      write_file_all(tmp, *dbb);
      auto src = read_session_db(tmp);
      std::error_code ignore;
      std::filesystem::remove(tmp, ignore);

      // Source's metadata; the manifest-supplied target_id (if any)
      // overrides for safety.
      std::optional<std::string> target_id = src.target_id;
      if (s.contains("target_id") && s["target_id"].is_string()) {
        target_id = s["target_id"].get<std::string>();
      }
      std::string name = src.name;
      if (s.contains("name") && s["name"].is_string()) {
        name = s["name"].get<std::string>();
      }

      // Forward the rows verbatim.
      std::vector<SessionStore::ImportRow> rows;
      rows.reserve(src.rows.size());
      for (const auto& r : src.rows) {
        SessionStore::ImportRow ir;
        ir.ts_ns         = r.ts_ns;
        ir.method        = r.method;
        ir.request_json  = r.request_json;
        ir.response_json = r.response_json;
        ir.ok            = r.ok;
        ir.duration_us   = r.duration_us;
        rows.push_back(std::move(ir));
      }

      sessions.import_session(id, name, target_id, src.created_at,
                               rows,
                               policy == ConflictPolicy::kOverwrite);
      report.imported.push_back({"session", id, ""});
    }
  }

  // artifacts
  if (manifest.contains("artifacts")) {
    for (const auto& a : manifest["artifacts"]) {
      if (!a.contains("build_id") || !a.contains("name") ||
          !a.contains("path")) {
        throw backend::Error("pack: malformed artifact manifest entry");
      }
      std::string bid  = a["build_id"].get<std::string>();
      std::string nm   = a["name"].get<std::string>();
      std::string path = a["path"].get<std::string>();
      auto* blob_bytes = find_entry(path);
      if (blob_bytes == nullptr) {
        throw backend::Error("pack: missing tar entry for artifact " +
                             bid + "/" + nm);
      }

      // Side-meta blob.
      std::string meta_path = "artifacts/" + bid + "/meta/" + nm + ".json";
      auto* meta_bytes = find_entry(meta_path);
      nlohmann::json meta_j;
      std::optional<std::string> format;
      std::vector<std::string>   tags;
      std::int64_t created_at = 0;
      std::string declared_sha;
      if (meta_bytes != nullptr) {
        try {
          meta_j = nlohmann::json::parse(meta_bytes->begin(),
                                          meta_bytes->end());
        } catch (...) {
          meta_j = nlohmann::json::object();
        }
      }
      nlohmann::json user_meta = nlohmann::json::object();
      if (meta_j.is_object()) {
        if (meta_j.contains("format") && meta_j["format"].is_string()) {
          format = meta_j["format"].get<std::string>();
        }
        if (meta_j.contains("tags") && meta_j["tags"].is_array()) {
          for (const auto& t : meta_j["tags"]) {
            if (t.is_string()) tags.push_back(t.get<std::string>());
          }
        }
        if (meta_j.contains("created_at") &&
            meta_j["created_at"].is_number_integer()) {
          created_at = meta_j["created_at"].get<std::int64_t>();
        }
        if (meta_j.contains("sha256") && meta_j["sha256"].is_string()) {
          declared_sha = meta_j["sha256"].get<std::string>();
        }
        if (meta_j.contains("meta") && meta_j["meta"].is_object()) {
          user_meta = meta_j["meta"];
        }
      }
      // Verify sha if declared — protects against tar corruption.
      if (!declared_sha.empty()) {
        auto computed = sha256_hex(*blob_bytes);
        if (computed != declared_sha) {
          throw backend::Error("pack: sha256 mismatch for " + bid + "/" +
                               nm + " (got " + computed + ", expected "
                               + declared_sha + ")");
        }
      }

      bool exists = artifacts.get_by_name(bid, nm).has_value();
      if (exists && policy == ConflictPolicy::kSkip) {
        report.skipped.push_back(
            {"artifact", bid + "/" + nm, "duplicate (build_id, name)"});
        continue;
      }
      artifacts.import_artifact(bid, nm, *blob_bytes,
                                 declared_sha,
                                 format, user_meta, tags, created_at,
                                 policy == ConflictPolicy::kOverwrite);
      report.imported.push_back({"artifact", bid + "/" + nm, ""});
    }
  }

  // Knowledge-graph relations (post-v0.1 §7). Endpoints arrive as
  // (build_id, name) pairs and are remapped here to the destination
  // store's freshly-assigned ids. A relation whose endpoint isn't
  // resolvable (artifact missing locally and not in this pack) is
  // skipped with a deterministic reason — the typical case is a `skip`
  // policy that landed on a duplicate artifact, leaving its relations
  // dangling.
  if (manifest.contains("relations") && manifest["relations"].is_array()) {
    for (const auto& r : manifest["relations"]) {
      if (!r.is_object() ||
          !r.contains("from_build_id") || !r.contains("from_name") ||
          !r.contains("to_build_id")   || !r.contains("to_name")   ||
          !r.contains("predicate")) {
        throw backend::Error("pack: malformed relation manifest entry");
      }
      std::string fb = r["from_build_id"].get<std::string>();
      std::string fn = r["from_name"].get<std::string>();
      std::string tb = r["to_build_id"].get<std::string>();
      std::string tn = r["to_name"].get<std::string>();
      std::string pred = r["predicate"].get<std::string>();

      auto a = artifacts.get_by_name(fb, fn);
      auto b = artifacts.get_by_name(tb, tn);
      if (!a.has_value() || !b.has_value()) {
        // Either endpoint is missing locally — happens under the skip
        // policy when its anchor artifact was preserved-as-local.
        report.skipped.push_back(
            {"relation",
             fb + "/" + fn + " -> " + tb + "/" + tn,
             "endpoint not present after import"});
        continue;
      }

      nlohmann::json meta = nlohmann::json::object();
      if (r.contains("meta") && r["meta"].is_object()) meta = r["meta"];
      std::int64_t created_at = 0;
      if (r.contains("created_at") &&
          r["created_at"].is_number_integer()) {
        created_at = r["created_at"].get<std::int64_t>();
      }

      artifacts.import_relation(a->id, b->id, pred, meta, created_at);
      report.imported.push_back(
          {"relation", fb + "/" + fn + " -> " + tb + "/" + tn, ""});
    }
  }

  return report;
}

}  // namespace ldb::store
