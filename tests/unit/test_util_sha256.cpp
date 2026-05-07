// Tests for src/util/sha256 — public-domain SHA-256 verified against
// the NIST short-message vectors and against the (already field-tested)
// implementation that's lived inside store/artifact_store.cpp since M3.
//
// We need this test before any of the M5 part 6 (cores-only `_provenance`)
// work because the snapshot key is "core:<sha256>" — wrong hash, broken
// determinism gate.

#include <catch_amalgamated.hpp>

#include "util/sha256.h"

#include <cstdio>
#include <filesystem>
#include <string>
#include <unistd.h>
#include <vector>

using ldb::util::Sha256;
using ldb::util::sha256_file_hex;
using ldb::util::sha256_hex;

TEST_CASE("sha256: empty input matches NIST vector",
          "[util][sha256]") {
  // NIST CSRC: SHA-256 of the empty bit string.
  CHECK(sha256_hex(std::string_view{""}) ==
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  CHECK(sha256_hex(std::vector<std::uint8_t>{}) ==
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST_CASE("sha256: \"abc\" matches NIST short-message vector",
          "[util][sha256]") {
  CHECK(sha256_hex(std::string_view{"abc"}) ==
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_CASE("sha256: 56-byte block boundary vector",
          "[util][sha256]") {
  // FIPS-180-2 sample: 448-bit ("abcdbcde...nopq") message.
  CHECK(sha256_hex(std::string_view{
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"}) ==
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST_CASE("sha256: streaming update matches one-shot",
          "[util][sha256]") {
  // Update a megabyte of 'A's in 1-byte, 7-byte, 64-byte chunks; all
  // three should produce the same digest as one big buffer.
  std::vector<std::uint8_t> mb(1u << 20, 0x41);
  std::string oneshot = sha256_hex(mb);

  Sha256 h1;
  for (auto b : mb) h1.update(&b, 1);
  CHECK(sha256_hex(h1.finalize()) == oneshot);

  Sha256 h7;
  std::size_t i = 0;
  while (i < mb.size()) {
    std::size_t n = std::min(std::size_t{7}, mb.size() - i);
    h7.update(mb.data() + i, n);
    i += n;
  }
  CHECK(sha256_hex(h7.finalize()) == oneshot);

  Sha256 h64;
  i = 0;
  while (i < mb.size()) {
    std::size_t n = std::min(std::size_t{64}, mb.size() - i);
    h64.update(mb.data() + i, n);
    i += n;
  }
  CHECK(sha256_hex(h64.finalize()) == oneshot);
}

TEST_CASE("sha256: file streaming matches buffer hash",
          "[util][sha256]") {
  // Write a deterministic blob to a tmp file, hash it via both surfaces,
  // expect identical output. Covers the chunked-file path that load_core
  // takes against multi-MB core files.
  auto path = std::filesystem::temp_directory_path() /
              ("ldb_unit_sha256_" + std::to_string(::getpid()) + ".bin");
  std::vector<std::uint8_t> blob(64 * 1024 + 17);  // crosses 64 KiB chunk
  for (std::size_t i = 0; i < blob.size(); ++i) {
    blob[i] = static_cast<std::uint8_t>((i * 31u + 7u) & 0xFFu);
  }
  {
    std::FILE* f = std::fopen(path.c_str(), "wb");
    REQUIRE(f != nullptr);
    REQUIRE(std::fwrite(blob.data(), 1, blob.size(), f) == blob.size());
    std::fclose(f);
  }
  CHECK(sha256_file_hex(path.string()) == sha256_hex(blob));
  std::filesystem::remove(path);
}

TEST_CASE("sha256: file open failure throws",
          "[util][sha256][error]") {
  CHECK_THROWS_AS(
      sha256_file_hex("/nonexistent/path/almost-certainly-not-here.bin"),
      std::runtime_error);
}
