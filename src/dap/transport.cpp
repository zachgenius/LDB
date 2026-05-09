// SPDX-License-Identifier: Apache-2.0
#include "dap/transport.h"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <istream>
#include <ostream>
#include <string>
#include <vector>

namespace ldb::dap {

namespace {

std::string ascii_lower(std::string s) {
  for (auto& c : s) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return s;
}

std::string strip(const std::string& s) {
  std::size_t a = 0, b = s.size();
  while (a < b && (s[a] == ' ' || s[a] == '\t')) ++a;
  while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t')) --b;
  return s.substr(a, b - a);
}

// Read one header line into `out`. Recognized terminators are CRLF or
// bare LF (some clients are sloppy). Returns true on success; on EOF
// before any byte arrives, returns false with `out` empty. Throws on
// stream error.
bool read_header_line(std::istream& in, std::string& out) {
  out.clear();
  char c;
  while (in.get(c)) {
    if (c == '\r') {
      if (in.peek() == '\n') in.get(c);  // consume the \n after \r
      return true;
    }
    if (c == '\n') return true;
    out.push_back(c);
  }
  // EOF — fail iff we'd already read partial data.
  if (in.bad()) throw Error("stream error reading DAP header");
  return !out.empty();  // partial header before EOF is malformed; let caller decide
}

}  // namespace

std::optional<json> read_dap_message(std::istream& in) {
  // Loop reading header lines until we hit the empty separator. The
  // first non-blank line must give us a Content-Length; we tolerate
  // arbitrary additional headers (Content-Type) and ignore them.
  std::optional<std::size_t> content_length;
  std::string line;

  // First line: distinguish "clean EOF before any input" from "malformed
  // headers". We peek for any byte; if none, the peer closed cleanly.
  if (in.peek() == std::char_traits<char>::eof()) {
    return std::nullopt;
  }

  while (true) {
    bool got = read_header_line(in, line);
    if (!got) {
      // EOF mid-header block — this is a framing error if we haven't
      // already seen the blank-line separator, which by construction we
      // haven't (the loop exits on blank below).
      throw Error("DAP framing: unexpected EOF in header block");
    }
    if (line.empty()) break;  // blank line: end of headers

    auto colon = line.find(':');
    if (colon == std::string::npos) {
      throw Error("DAP framing: header line without ':' — " + line);
    }
    std::string name = ascii_lower(strip(line.substr(0, colon)));
    std::string value = strip(line.substr(colon + 1));

    if (name == "content-length") {
      try {
        std::size_t pos = 0;
        unsigned long long v = std::stoull(value, &pos);
        if (pos != value.size()) {
          throw Error("DAP framing: Content-Length has trailing garbage: " +
                      value);
        }
        content_length = static_cast<std::size_t>(v);
      } catch (const Error&) {
        throw;
      } catch (const std::exception& e) {
        throw Error(std::string("DAP framing: bad Content-Length value: ") +
                    e.what());
      }
    }
    // Other headers (Content-Type, etc.) are ignored.
  }

  if (!content_length.has_value()) {
    throw Error("DAP framing: missing Content-Length header");
  }

  // Read exactly N bytes of body. A short read means the peer
  // truncated the frame — no recovery is possible without resyncing,
  // so we throw.
  std::vector<char> body(*content_length);
  in.read(body.data(), static_cast<std::streamsize>(body.size()));
  std::streamsize got = in.gcount();
  if (static_cast<std::size_t>(got) != *content_length) {
    throw Error("DAP framing: short body read (got " + std::to_string(got) +
                " of " + std::to_string(*content_length) + " bytes)");
  }

  try {
    return json::parse(body.begin(), body.end());
  } catch (const json::parse_error& e) {
    throw Error(std::string("DAP framing: malformed JSON body: ") + e.what());
  }
}

void write_dap_message(std::ostream& out, const json& body) {
  std::string serialized = body.dump();
  out << "Content-Length: " << serialized.size() << "\r\n\r\n"
      << serialized;
  out.flush();
  if (!out.good()) {
    throw Error("DAP framing: stream error on write");
  }
}

}  // namespace ldb::dap
