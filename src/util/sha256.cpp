// SPDX-License-Identifier: Apache-2.0
#include "util/sha256.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>

namespace ldb::util {

void Sha256::reset() {
  h_ = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
  buf_len_   = 0;
  bit_count_ = 0;
}

void Sha256::update(const std::uint8_t* data, std::size_t len) {
  while (len > 0) {
    std::size_t take = std::min(len, std::size_t{64} - buf_len_);
    std::memcpy(buf_ + buf_len_, data, take);
    buf_len_ += take;
    data     += take;
    len      -= take;
    bit_count_ += static_cast<std::uint64_t>(take) * 8u;
    if (buf_len_ == 64) {
      compress(buf_);
      buf_len_ = 0;
    }
  }
}

std::array<std::uint8_t, 32> Sha256::finalize() {
  std::uint64_t bits = bit_count_;
  std::uint8_t one = 0x80;
  update(&one, 1);
  static const std::uint8_t zero = 0x00;
  while (buf_len_ != 56) update(&zero, 1);
  std::uint8_t length_be[8];
  for (int i = 7; i >= 0; --i) {
    length_be[i] = static_cast<std::uint8_t>(bits & 0xFFu);
    bits >>= 8;
  }
  update(length_be, 8);
  std::array<std::uint8_t, 32> out{};
  for (std::size_t i = 0; i < 8; ++i) {
    out[i * 4 + 0] = static_cast<std::uint8_t>((h_[i] >> 24) & 0xFFu);
    out[i * 4 + 1] = static_cast<std::uint8_t>((h_[i] >> 16) & 0xFFu);
    out[i * 4 + 2] = static_cast<std::uint8_t>((h_[i] >>  8) & 0xFFu);
    out[i * 4 + 3] = static_cast<std::uint8_t>((h_[i] >>  0) & 0xFFu);
  }
  reset();
  return out;
}

void Sha256::compress(const std::uint8_t* p) {
  static constexpr std::uint32_t k[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,
    0x923f82a4u,0xab1c5ed5u,0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
    0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,0xe49b69c1u,0xefbe4786u,
    0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,
    0x06ca6351u,0x14292967u,0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
    0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,0xa2bfe8a1u,0xa81a664bu,
    0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,
    0x5b9cca4fu,0x682e6ff3u,0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
    0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};

  std::uint32_t w[64];
  for (int i = 0; i < 16; ++i) {
    w[i] = (static_cast<std::uint32_t>(p[i*4+0]) << 24) |
           (static_cast<std::uint32_t>(p[i*4+1]) << 16) |
           (static_cast<std::uint32_t>(p[i*4+2]) <<  8) |
           (static_cast<std::uint32_t>(p[i*4+3]) <<  0);
  }
  for (int i = 16; i < 64; ++i) {
    std::uint32_t s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
    std::uint32_t s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);
    w[i] = w[i-16] + s0 + w[i-7] + s1;
  }
  std::uint32_t a=h_[0],b=h_[1],c=h_[2],d=h_[3],
                e=h_[4],f=h_[5],g=h_[6],h=h_[7];
  for (int i = 0; i < 64; ++i) {
    std::uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    std::uint32_t ch = (e & f) ^ ((~e) & g);
    std::uint32_t t1 = h + S1 + ch + k[i] + w[i];
    std::uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    std::uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
    std::uint32_t t2 = S0 + mj;
    h = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }
  h_[0]+=a; h_[1]+=b; h_[2]+=c; h_[3]+=d;
  h_[4]+=e; h_[5]+=f; h_[6]+=g; h_[7]+=h;
}

std::string sha256_hex(const std::array<std::uint8_t, 32>& digest) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(64);
  for (auto by : digest) {
    out.push_back(kHex[(by >> 4) & 0xFu]);
    out.push_back(kHex[by & 0xFu]);
  }
  return out;
}

std::string sha256_hex(const std::vector<std::uint8_t>& bytes) {
  Sha256 h;
  if (!bytes.empty()) h.update(bytes.data(), bytes.size());
  return sha256_hex(h.finalize());
}

std::string sha256_hex(std::string_view bytes) {
  Sha256 h;
  if (!bytes.empty()) h.update(bytes);
  return sha256_hex(h.finalize());
}

std::string sha256_file_hex(const std::string& path) {
  // Stream — never materialize the file in memory. Cores can be hundreds
  // of MB and we run this on the hot path of target.load_core.
  std::FILE* f = std::fopen(path.c_str(), "rb");
  if (!f) {
    throw std::runtime_error("sha256_file_hex: open failed: " + path);
  }
  Sha256 hasher;
  std::array<std::uint8_t, 64 * 1024> chunk{};
  while (true) {
    std::size_t n = std::fread(chunk.data(), 1, chunk.size(), f);
    if (n > 0) hasher.update(chunk.data(), n);
    if (n < chunk.size()) {
      bool eof = std::feof(f) != 0;
      bool err = std::ferror(f) != 0;
      std::fclose(f);
      if (err && !eof) {
        throw std::runtime_error("sha256_file_hex: read failed: " + path);
      }
      break;
    }
  }
  return sha256_hex(hasher.finalize());
}

}  // namespace ldb::util
