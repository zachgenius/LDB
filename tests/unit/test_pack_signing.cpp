// SPDX-License-Identifier: Apache-2.0
// Unit tests for `.ldbpack` ed25519 signing — see docs/14-pack-signing.md
// §"Test Plan" for the numbered list this file pins.
//
// At the TDD-step-1 checkpoint (this commit):
//   * tests 1-4 (libsodium glue, OpenSSH key parse, encrypted-key
//     rejection, .pub parse) pass — the underlying primitives live in
//     `src/store/pack_signing.cpp` and are fully real.
//   * tests 5-10 (pack producer/verifier round-trip, tamper detection,
//     trust-root behaviors, `entries` mismatch) fail with
//     `pack_signing: not implemented` — those depend on producer /
//     verifier work that lands in the next task. The assertions still
//     pin the contract so the next task can flip the WHEN-implemented
//     CHECKs to REQUIREs without re-shaping anything.

#include <catch_amalgamated.hpp>

#include "store/pack.h"
#include "store/pack_signing.h"

#include "backend/debugger_backend.h"
#include "store/artifact_store.h"
#include "store/session_store.h"

#include <nlohmann/json.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;

using ldb::store::ArtifactStore;
using ldb::store::ConflictPolicy;
using ldb::store::Ed25519KeyPair;
using ldb::store::Ed25519PublicKey;
using ldb::store::PackVerifyReport;
using ldb::store::SessionStore;
using ldb::store::SignedPackResult;
using ldb::store::TarEntry;

#ifndef LDB_FIXTURE_KEYS_DIR
#define LDB_FIXTURE_KEYS_DIR "tests/fixtures/keys"
#endif

namespace {

struct TmpDir {
  fs::path root;
  TmpDir() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    char buf[40];
    std::snprintf(buf, sizeof(buf), "ldb_packsig_test_%016llx",
                  static_cast<unsigned long long>(gen()));
    root = fs::temp_directory_path() / buf;
    std::error_code ec;
    fs::remove_all(root, ec);
    fs::create_directories(root, ec);
  }
  ~TmpDir() {
    std::error_code ec;
    fs::remove_all(root, ec);
  }
};

std::vector<std::uint8_t> read_file_bytes(const fs::path& p) {
  std::ifstream in(p, std::ios::binary);
  if (!in) return {};
  std::vector<std::uint8_t> out;
  in.seekg(0, std::ios::end);
  out.resize(static_cast<std::size_t>(in.tellg()));
  in.seekg(0, std::ios::beg);
  in.read(reinterpret_cast<char*>(out.data()),
          static_cast<std::streamsize>(out.size()));
  return out;
}

std::string read_file_text(const fs::path& p) {
  auto b = read_file_bytes(p);
  return std::string(b.begin(), b.end());
}

void write_file_bytes(const fs::path& p,
                      const std::vector<std::uint8_t>& bytes) {
  fs::create_directories(p.parent_path());
  std::ofstream out(p, std::ios::binary | std::ios::trunc);
  if (!bytes.empty()) {
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
  }
}

std::vector<std::uint8_t> bytes_of(std::string_view s) {
  return {s.begin(), s.end()};
}

// Decode a lower-hex string ("ab12...") into raw bytes. Used to hold the
// RFC 8032 test vector inline without dragging in another helper TU.
std::vector<std::uint8_t> from_hex(std::string_view s) {
  auto nyb = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
  };
  std::vector<std::uint8_t> out;
  out.reserve(s.size() / 2u);
  for (std::size_t i = 0; i + 1u < s.size(); i += 2u) {
    int hi = nyb(s[i]);
    int lo = nyb(s[i + 1]);
    REQUIRE(hi >= 0);
    REQUIRE(lo >= 0);
    out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
  }
  return out;
}

fs::path keys_dir() {
  return fs::path(LDB_FIXTURE_KEYS_DIR);
}

}  // namespace

// =========================================================================
// 1. libsodium glue — RFC 8032 test vector.
//
// RFC 8032 §7.1 TEST 1:
//   secret seed = 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
//   public key  = d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
//   message     = "" (empty)
//   signature   = e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065
//                 224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24
//                 655141438e7a100b
// =========================================================================
TEST_CASE("pack_signing: RFC 8032 vector signs and verifies",
          "[store][pack][signing][crypto]") {
  auto seed   = from_hex(
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
  auto pubhex = from_hex(
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
  auto expect = from_hex(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065"
      "224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24"
      "655141438e7a100b");
  REQUIRE(seed.size()   == 32);
  REQUIRE(pubhex.size() == 32);
  REQUIRE(expect.size() == 64);

  Ed25519KeyPair k;
  std::copy(pubhex.begin(), pubhex.end(), k.public_key.begin());
  // libsodium secret-key layout: seed (32) || pub (32).
  std::copy(seed.begin(),   seed.end(),   k.secret_key.begin());
  std::copy(pubhex.begin(), pubhex.end(), k.secret_key.begin() + 32);

  std::vector<std::uint8_t> empty_msg;
  auto sig = ldb::store::sign_buffer(empty_msg, k);
  CHECK(std::vector<std::uint8_t>(sig.begin(), sig.end()) == expect);

  CHECK(ldb::store::verify_buffer(empty_msg,
                                  sig, k.public_key));
  // Flip a single bit; verify must fail.
  auto bad = sig;
  bad[0] ^= static_cast<std::uint8_t>(0x01);
  CHECK_FALSE(ldb::store::verify_buffer(empty_msg, bad, k.public_key));
}

// =========================================================================
// 2. OpenSSH secret-key parse — round-trip the fixture and assert the
//    32-byte public half matches what `ssh-keygen -y` produces (we baked
//    that into a sibling .pub fixture).
// =========================================================================
TEST_CASE("pack_signing: parses unencrypted OpenSSH secret key",
          "[store][pack][signing][openssh]") {
  auto priv_bytes = read_file_bytes(keys_dir() / "alice_ed25519");
  REQUIRE_FALSE(priv_bytes.empty());

  auto kp = ldb::store::parse_openssh_secret_key(priv_bytes);

  // Cross-check: the .pub fixture's base64 body is exactly the public
  // key (after stripping the "ssh-ed25519" length-prefixed header).
  auto pub_line = read_file_text(keys_dir() / "alice_ed25519.pub");
  auto parsed_pub = ldb::store::parse_openssh_public_key(pub_line);
  CHECK(parsed_pub.bytes == kp.public_key);

  // Sign + verify a small payload using the freshly parsed pair —
  // proves both halves of the secret key landed in the right slots.
  std::vector<std::uint8_t> msg = bytes_of("ldbpack signing smoke");
  auto sig = ldb::store::sign_buffer(msg, kp);
  CHECK(ldb::store::verify_buffer(msg, sig, kp.public_key));
}

// =========================================================================
// 3. Encrypted OpenSSH key rejected with the exact "encrypted" message
//    the dispatcher will forward verbatim.
// =========================================================================
TEST_CASE("pack_signing: encrypted OpenSSH key rejected",
          "[store][pack][signing][openssh]") {
  auto enc_bytes = read_file_bytes(keys_dir() / "charlie_ed25519_enc");
  REQUIRE_FALSE(enc_bytes.empty());

  try {
    (void)ldb::store::parse_openssh_secret_key(enc_bytes);
    FAIL("expected parse_openssh_secret_key to throw on encrypted key");
  } catch (const ldb::backend::Error& e) {
    std::string msg = e.what();
    CHECK(msg.find("encrypted OpenSSH keys not supported in v1") !=
          std::string::npos);
    CHECK(msg.find("decrypt first") != std::string::npos);
  }
}

// =========================================================================
// 4. OpenSSH `.pub` parse — the same public key that test 2 derived from
//    the secret half, plus the trailing comment string.
// =========================================================================
TEST_CASE("pack_signing: parses OpenSSH .pub public key",
          "[store][pack][signing][openssh]") {
  auto pub_line = read_file_text(keys_dir() / "alice_ed25519.pub");
  auto pk = ldb::store::parse_openssh_public_key(pub_line);

  CHECK(pk.comment == "alice@ldb-test");
  CHECK(pk.key_id.rfind("SHA256:", 0) == 0u);
  CHECK(pk.key_id.size() > std::string("SHA256:").size());

  // Pair-trip: derive the key_id from the raw 32 bytes and match.
  CHECK(ldb::store::compute_key_id(pk.bytes) == pk.key_id);

  // Round-trip through the private fixture too — sign with the secret
  // half, verify with the public half loaded here.
  auto priv_bytes = read_file_bytes(keys_dir() / "alice_ed25519");
  auto kp = ldb::store::parse_openssh_secret_key(priv_bytes);
  std::vector<std::uint8_t> msg = bytes_of("hello from .pub parse test");
  auto sig = ldb::store::sign_buffer(msg, kp);
  CHECK(ldb::store::verify_buffer(msg, sig, pk.bytes));
}

// =========================================================================
// 5. Round-trip pack sign + verify: producer emits a `ldbpack/1+sig`
//    pack; the verifier reports `verified=true` against a matching
//    trust root.
//
//    EXPECTED TO FAIL at this commit — pack_session_signed is a stub.
//    The assertion below will report `pack_signing: not implemented` as
//    the first failure, which is the documented "fails for the expected
//    reason" we want before the producer lands.
// =========================================================================
TEST_CASE("pack_signing: signed pack round-trips through verify",
          "[store][pack][signing][e2e]") {
  TmpDir t;
  auto src_root  = t.root / "src";
  auto pack_path = t.root / "signed.ldbpack";
  auto trust_dir = t.root / "trust";
  fs::create_directories(trust_dir);
  // Copy alice's public key into the trust root.
  fs::copy_file(keys_dir() / "alice_ed25519.pub",
                trust_dir / "alice.pub",
                fs::copy_options::overwrite_existing);

  std::string sid;
  Ed25519KeyPair alice;
  {
    auto pem = read_file_bytes(keys_dir() / "alice_ed25519");
    alice = ldb::store::parse_openssh_secret_key(pem);
  }

  {
    SessionStore ss(src_root);
    ArtifactStore as(src_root);
    auto row = ss.create("inv-signed",
                         std::optional<std::string>{"tgt-x"});
    sid = row.id;
    auto w = ss.open_writer(sid);
    nlohmann::json req = {{"method", "hello"}};
    nlohmann::json rsp = {{"ok", true}};
    w->append("hello", req, rsp, true, 100);
    w->append("describe.endpoints", req, rsp, true, 200);
    w.reset();
    as.put("buildA", "a.bin", bytes_of("aaa"),
           std::nullopt, nlohmann::json::object());
    as.put("buildA", "b.bin", bytes_of("bbb"),
           std::nullopt, nlohmann::json::object());
    as.put("buildB", "c.bin", bytes_of("ccc"),
           std::nullopt, nlohmann::json::object());

    SignedPackResult sr = ldb::store::pack_session_signed(
        ss, as, sid, pack_path,
        std::optional<Ed25519KeyPair>(alice),
        std::optional<std::string>{"alice@ldb-test"});
    CHECK(sr.result.manifest["format"] == "ldbpack/1+sig");
    REQUIRE(sr.signature_json.has_value());
    auto sj = nlohmann::json::parse(*sr.signature_json);
    CHECK(sj["algorithm"] == "ed25519");
    CHECK(sj["signer"]    == "alice@ldb-test");
    CHECK(sj["key_id"]    == ldb::store::compute_key_id(alice.public_key));
    REQUIRE(sj.contains("covered"));
    CHECK(sj["covered"]["scheme"] == "ldbpack-sig/1");
  }

  PackVerifyReport rep = ldb::store::verify_pack(
      pack_path, std::optional<fs::path>(trust_dir));
  CHECK(rep.is_signed);
  CHECK(rep.verified);
  CHECK(rep.key_id == ldb::store::compute_key_id(alice.public_key));
  CHECK(rep.signer == "alice@ldb-test");
}

// =========================================================================
// 6. Tampered pack fails verify with the offending entry's name in the
//    error message.
//
//    EXPECTED TO FAIL — depends on (5).
// =========================================================================
TEST_CASE("pack_signing: tampered session db fails verify",
          "[store][pack][signing][e2e][tamper]") {
  TmpDir t;
  auto src_root  = t.root / "src";
  auto pack_path = t.root / "signed.ldbpack";
  auto tampered  = t.root / "tampered.ldbpack";
  auto trust_dir = t.root / "trust";
  fs::create_directories(trust_dir);
  fs::copy_file(keys_dir() / "alice_ed25519.pub",
                trust_dir / "alice.pub",
                fs::copy_options::overwrite_existing);

  std::string sid;
  Ed25519KeyPair alice;
  {
    auto pem = read_file_bytes(keys_dir() / "alice_ed25519");
    alice = ldb::store::parse_openssh_secret_key(pem);
  }

  {
    SessionStore ss(src_root);
    ArtifactStore as(src_root);
    auto row = ss.create("inv-tamper", std::nullopt);
    sid = row.id;
    auto w = ss.open_writer(sid);
    w->append("hello", nlohmann::json::object(),
              nlohmann::json::object(), true, 1);
    w.reset();
    as.put("bid", "a", bytes_of("zzz"),
           std::nullopt, nlohmann::json::object());

    (void)ldb::store::pack_session_signed(
        ss, as, sid, pack_path,
        std::optional<Ed25519KeyPair>(alice),
        std::optional<std::string>{"alice@ldb-test"});
  }

  // Decompress -> untar -> flip one byte inside the `sessions/<uuid>.db`
  // entry -> retar -> recompress. The signature.sig must now mismatch.
  auto comp     = read_file_bytes(pack_path);
  auto raw      = ldb::store::gzip_decompress(
      std::vector<std::uint8_t>(comp.begin(), comp.end()));
  auto entries  = ldb::store::tar_unpack(raw);
  bool flipped  = false;
  std::string victim_name;
  for (auto& e : entries) {
    if (e.name.rfind("sessions/", 0) == 0 &&
        e.name.size() >= 3 &&
        e.name.compare(e.name.size() - 3, 3, ".db") == 0 &&
        !e.data.empty()) {
      // Flip a byte deep in the payload to avoid header collateral.
      auto mid = e.data.size() / 2;
      e.data[mid] = static_cast<std::uint8_t>(e.data[mid] ^ 0xFFu);
      victim_name = e.name;
      flipped = true;
      break;
    }
  }
  REQUIRE(flipped);
  auto retar  = ldb::store::tar_pack(entries);
  auto regz   = ldb::store::gzip_compress(retar);
  write_file_bytes(tampered, regz);

  try {
    auto rep = ldb::store::verify_pack(
        tampered, std::optional<fs::path>(trust_dir));
    CHECK_FALSE(rep.verified);
    CHECK(rep.error_message.find(victim_name) != std::string::npos);
  } catch (const ldb::backend::Error& e) {
    std::string m = e.what();
    CHECK(m.find(victim_name) != std::string::npos);
  }
}

// =========================================================================
// 7. Unsigned pack rejected when `require_signed=true` — exercised at
//    the verify_pack layer (the dispatcher wires `require_signed` on
//    top of it). Until then, unsigned packs must report `is_signed=false`
//    and `verified=false`.
//
//    EXPECTED TO FAIL — depends on verify_pack landing.
// =========================================================================
TEST_CASE("pack_signing: unsigned pack reports is_signed=false",
          "[store][pack][signing][e2e][unsigned]") {
  TmpDir t;
  auto src_root  = t.root / "src";
  auto pack_path = t.root / "plain.ldbpack";

  std::string sid;
  {
    SessionStore ss(src_root);
    ArtifactStore as(src_root);
    auto row = ss.create("inv-plain", std::nullopt);
    sid = row.id;
    as.put("bid", "x", bytes_of("xx"),
           std::nullopt, nlohmann::json::object());
    ldb::store::pack_session(ss, as, sid, pack_path);
  }

  auto rep = ldb::store::verify_pack(pack_path, std::nullopt);
  CHECK_FALSE(rep.is_signed);
  CHECK_FALSE(rep.verified);
  CHECK(rep.key_id.empty());
}

// =========================================================================
// 8. Signed pack with key NOT in trust root must report verified=false
//    and name the unknown key_id in the message.
//
//    EXPECTED TO FAIL — depends on (5) + trust-root scanning.
// =========================================================================
TEST_CASE("pack_signing: signer not in trust root rejected",
          "[store][pack][signing][e2e][trust]") {
  TmpDir t;
  auto src_root  = t.root / "src";
  auto pack_path = t.root / "alice.ldbpack";
  auto trust_dir = t.root / "trust-bob-only";
  fs::create_directories(trust_dir);
  fs::copy_file(keys_dir() / "bob_ed25519.pub",
                trust_dir / "bob.pub",
                fs::copy_options::overwrite_existing);

  Ed25519KeyPair alice;
  {
    auto pem = read_file_bytes(keys_dir() / "alice_ed25519");
    alice = ldb::store::parse_openssh_secret_key(pem);
  }
  std::string alice_key_id =
      ldb::store::compute_key_id(alice.public_key);

  std::string sid;
  {
    SessionStore ss(src_root);
    ArtifactStore as(src_root);
    auto row = ss.create("inv-trust", std::nullopt);
    sid = row.id;
    as.put("bid", "x", bytes_of("xx"),
           std::nullopt, nlohmann::json::object());
    (void)ldb::store::pack_session_signed(
        ss, as, sid, pack_path,
        std::optional<Ed25519KeyPair>(alice),
        std::optional<std::string>{"alice@ldb-test"});
  }

  auto rep = ldb::store::verify_pack(
      pack_path, std::optional<fs::path>(trust_dir));
  CHECK(rep.is_signed);
  CHECK_FALSE(rep.verified);
  CHECK(rep.error_message.find(alice_key_id) != std::string::npos);
}

// =========================================================================
// 9. Signed pack with key IN trust root accepted; manifest format
//    correctly advertises ldbpack/1+sig and the verify report echoes
//    the signer.
//
//    EXPECTED TO FAIL — depends on (5).
// =========================================================================
TEST_CASE("pack_signing: signer in trust root accepted",
          "[store][pack][signing][e2e][trust]") {
  TmpDir t;
  auto src_root  = t.root / "src";
  auto pack_path = t.root / "alice.ldbpack";
  auto trust_dir = t.root / "trust-alice";
  fs::create_directories(trust_dir);
  fs::copy_file(keys_dir() / "alice_ed25519.pub",
                trust_dir / "alice.pub",
                fs::copy_options::overwrite_existing);

  Ed25519KeyPair alice;
  {
    auto pem = read_file_bytes(keys_dir() / "alice_ed25519");
    alice = ldb::store::parse_openssh_secret_key(pem);
  }

  std::string sid;
  {
    SessionStore ss(src_root);
    ArtifactStore as(src_root);
    auto row = ss.create("inv-trust-ok", std::nullopt);
    sid = row.id;
    as.put("bid", "x", bytes_of("xx"),
           std::nullopt, nlohmann::json::object());
    auto sr = ldb::store::pack_session_signed(
        ss, as, sid, pack_path,
        std::optional<Ed25519KeyPair>(alice),
        std::optional<std::string>{"alice@ldb-test"});
    CHECK(sr.result.manifest["format"] == "ldbpack/1+sig");
  }

  auto rep = ldb::store::verify_pack(
      pack_path, std::optional<fs::path>(trust_dir));
  CHECK(rep.is_signed);
  CHECK(rep.verified);
  CHECK(rep.signer == "alice@ldb-test");
  CHECK(rep.key_id == ldb::store::compute_key_id(alice.public_key));
}

// =========================================================================
// 10. `entries` set mismatch fails verify — forge a `signature.json`
//     that claims one extra entry, repack, and assert verify rejects.
//
//     EXPECTED TO FAIL — depends on (5) producing the signed pack we
//     then tamper with.
// =========================================================================
TEST_CASE("pack_signing: entries-set mismatch fails verify",
          "[store][pack][signing][e2e][tamper]") {
  TmpDir t;
  auto src_root  = t.root / "src";
  auto pack_path = t.root / "alice.ldbpack";
  auto forged    = t.root / "forged.ldbpack";
  auto trust_dir = t.root / "trust";
  fs::create_directories(trust_dir);
  fs::copy_file(keys_dir() / "alice_ed25519.pub",
                trust_dir / "alice.pub",
                fs::copy_options::overwrite_existing);

  Ed25519KeyPair alice;
  {
    auto pem = read_file_bytes(keys_dir() / "alice_ed25519");
    alice = ldb::store::parse_openssh_secret_key(pem);
  }

  std::string sid;
  {
    SessionStore ss(src_root);
    ArtifactStore as(src_root);
    auto row = ss.create("inv-forge", std::nullopt);
    sid = row.id;
    as.put("bid", "x", bytes_of("xx"),
           std::nullopt, nlohmann::json::object());
    (void)ldb::store::pack_session_signed(
        ss, as, sid, pack_path,
        std::optional<Ed25519KeyPair>(alice),
        std::optional<std::string>{"alice@ldb-test"});
  }

  // Read back, locate signature.json, mutate the `entries` list, repack.
  auto comp    = read_file_bytes(pack_path);
  auto raw     = ldb::store::gzip_decompress(
      std::vector<std::uint8_t>(comp.begin(), comp.end()));
  auto entries = ldb::store::tar_unpack(raw);
  bool forged_done = false;
  for (auto& e : entries) {
    if (e.name == "signature.json") {
      auto j = nlohmann::json::parse(e.data.begin(), e.data.end());
      REQUIRE(j.contains("covered"));
      REQUIRE(j["covered"].contains("entries"));
      nlohmann::json extra;
      extra["name"]   = "nonsense/ghost.bin";
      extra["sha256"] =
          "0000000000000000000000000000000000000000000000000000000000000000";
      j["covered"]["entries"].push_back(extra);
      auto s = j.dump();
      e.data.assign(s.begin(), s.end());
      forged_done = true;
      break;
    }
  }
  REQUIRE(forged_done);
  auto retar = ldb::store::tar_pack(entries);
  auto regz  = ldb::store::gzip_compress(retar);
  write_file_bytes(forged, regz);

  auto rep = ldb::store::verify_pack(
      forged, std::optional<fs::path>(trust_dir));
  CHECK(rep.is_signed);
  CHECK_FALSE(rep.verified);
  // The message should call out the entries-set mismatch (or, before
  // ed25519 even runs, the JSON-bytes-vs-sig mismatch — either is a
  // valid acceptance criterion).
  CHECK_FALSE(rep.error_message.empty());
}
