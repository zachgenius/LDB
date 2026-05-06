#include "protocol/transport.h"

#include <arpa/inet.h>

#include <cstddef>
#include <cstdint>
#include <istream>
#include <limits>
#include <ostream>
#include <string>
#include <vector>

namespace ldb::protocol {

namespace {

// Read at most `n` bytes from `in` into `out`. Returns the number of
// bytes actually read. Stops at EOF; does NOT throw.
std::size_t read_n(std::istream& in, char* out, std::size_t n) {
  in.read(out, static_cast<std::streamsize>(n));
  return static_cast<std::size_t>(in.gcount());
}

std::optional<json> read_json_line(std::istream& in) {
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty()) continue;
    try {
      return json::parse(line);
    } catch (const json::parse_error& e) {
      throw Error(std::string("malformed JSON frame: ") + e.what());
    }
  }
  // getline failed — distinguish clean EOF from a stream error.
  if (in.eof() && !in.bad()) return std::nullopt;
  if (in.bad()) throw Error("stream error reading JSON frame");
  return std::nullopt;
}

std::optional<json> read_cbor_frame(std::istream& in) {
  // Length prefix.
  unsigned char prefix[4];
  std::size_t got = read_n(in, reinterpret_cast<char*>(prefix), 4);
  if (got == 0 && in.eof()) return std::nullopt;  // clean EOF, no partial frame
  if (got != 4) {
    throw Error("short read on CBOR length prefix (got " +
                std::to_string(got) + " of 4 bytes)");
  }

  uint32_t be_len;
  std::memcpy(&be_len, prefix, 4);
  uint32_t len = ntohl(be_len);

  if (len == 0) {
    throw Error("CBOR frame with zero-byte body");
  }
  // Sanity bound — refuse silly frame sizes rather than allocate
  // gigabytes on a corrupt prefix. 64 MiB is well above any realistic
  // single-message debugger payload.
  static constexpr uint32_t kMaxFrame = 64u * 1024u * 1024u;
  if (len > kMaxFrame) {
    throw Error("CBOR frame length exceeds limit (" +
                std::to_string(len) + " > " + std::to_string(kMaxFrame) + ")");
  }

  std::vector<std::uint8_t> body(len);
  std::size_t got_body = read_n(in,
                                reinterpret_cast<char*>(body.data()),
                                len);
  if (got_body != len) {
    throw Error("truncated CBOR frame body (got " +
                std::to_string(got_body) + " of " + std::to_string(len) +
                " bytes)");
  }

  try {
    // strict=true: every byte of `body` must be consumed by exactly one
    // top-level CBOR value. Trailing bytes inside a frame are a protocol
    // error.
    return json::from_cbor(body,
                           /*strict=*/true,
                           /*allow_exceptions=*/true);
  } catch (const json::exception& e) {
    throw Error(std::string("malformed CBOR body: ") + e.what());
  }
}

void write_json_line(std::ostream& out, const json& j) {
  out << j.dump() << '\n';
  out.flush();
}

void write_cbor_frame(std::ostream& out, const json& j) {
  std::vector<std::uint8_t> body = json::to_cbor(j);
  if (body.size() > std::numeric_limits<uint32_t>::max()) {
    throw Error("CBOR frame too large to encode in 32-bit length prefix");
  }
  uint32_t len = static_cast<uint32_t>(body.size());
  uint32_t be_len = htonl(len);
  out.write(reinterpret_cast<const char*>(&be_len), 4);
  out.write(reinterpret_cast<const char*>(body.data()),
            static_cast<std::streamsize>(body.size()));
  out.flush();
}

}  // namespace

std::optional<json> read_message(std::istream& in, WireFormat fmt) {
  switch (fmt) {
    case WireFormat::kJson: return read_json_line(in);
    case WireFormat::kCbor: return read_cbor_frame(in);
  }
  // Unreachable in C++20 with the closed enum; silence -Wreturn-type.
  throw Error("unknown wire format");
}

void write_message(std::ostream& out, const json& j, WireFormat fmt) {
  switch (fmt) {
    case WireFormat::kJson: write_json_line(out, j); return;
    case WireFormat::kCbor: write_cbor_frame(out, j); return;
  }
  throw Error("unknown wire format");
}

}  // namespace ldb::protocol
