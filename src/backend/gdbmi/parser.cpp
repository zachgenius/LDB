// SPDX-License-Identifier: Apache-2.0
#include "backend/gdbmi/parser.h"

#include <cctype>
#include <cstdint>
#include <utility>

namespace ldb::backend::gdbmi {

// ── MiValue ────────────────────────────────────────────────────────────

MiValue::MiValue() : v_(std::string{}) {}
MiValue::MiValue(std::string s)    : v_(std::move(s)) {}
MiValue::MiValue(MiTuple t)        : v_(std::move(t)) {}
MiValue::MiValue(MiList l)         : v_(std::move(l)) {}

MiValue::MiValue(const MiValue&)             = default;
MiValue::MiValue(MiValue&&) noexcept         = default;
MiValue& MiValue::operator=(const MiValue&)  = default;
MiValue& MiValue::operator=(MiValue&&) noexcept = default;
MiValue::~MiValue() = default;

bool MiValue::is_string() const { return std::holds_alternative<std::string>(v_); }
bool MiValue::is_tuple()  const { return std::holds_alternative<MiTuple>(v_); }
bool MiValue::is_list()   const { return std::holds_alternative<MiList>(v_); }

const std::string& MiValue::as_string() const { return std::get<std::string>(v_); }
const MiTuple&     MiValue::as_tuple()  const { return std::get<MiTuple>(v_); }
const MiList&      MiValue::as_list()   const { return std::get<MiList>(v_); }

// ── Cursor-based scanner ───────────────────────────────────────────────
//
// One-pass recursive descent. The cursor (`pos`) advances through
// `s`; helpers return false on EOF or malformed input. All parser
// entry points catch this and return nullopt rather than throw.

namespace {

struct Scanner {
  std::string_view s;
  std::size_t      pos = 0;

  bool eof() const { return pos >= s.size(); }
  char peek() const { return eof() ? '\0' : s[pos]; }
  char next() { return eof() ? '\0' : s[pos++]; }
  bool consume(char c) {
    if (peek() == c) { ++pos; return true; }
    return false;
  }

  void skip_ws() {
    while (!eof() && (s[pos] == ' ' || s[pos] == '\t')) ++pos;
  }
};

bool parse_string(Scanner& sc, std::string& out) {
  if (!sc.consume('"')) return false;
  out.clear();
  while (!sc.eof()) {
    char c = sc.next();
    if (c == '"') return true;
    if (c == '\\') {
      if (sc.eof()) return false;
      char e = sc.next();
      switch (e) {
        case 'n': out.push_back('\n'); break;
        case 't': out.push_back('\t'); break;
        case 'r': out.push_back('\r'); break;
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case '0': out.push_back('\0'); break;
        default:
          // Unknown escape — pass through both bytes verbatim so we
          // don't silently corrupt the payload.
          out.push_back('\\');
          out.push_back(e);
          break;
      }
    } else {
      out.push_back(c);
    }
  }
  return false;  // ran off end before closing quote
}

// Forward decl for mutual recursion (tuple/list contain values).
bool parse_value_inner(Scanner& sc, MiValue& out);

// A "name" token is a bareword: [a-zA-Z_][a-zA-Z0-9_-]*. MI uses
// hyphenated names like "thread-id" and "stopped-threads".
bool parse_name(Scanner& sc, std::string& out) {
  out.clear();
  if (sc.eof()) return false;
  char c = sc.peek();
  if (!(std::isalpha(static_cast<unsigned char>(c)) || c == '_')) {
    return false;
  }
  while (!sc.eof()) {
    char n = sc.peek();
    if (std::isalnum(static_cast<unsigned char>(n)) || n == '_' || n == '-') {
      out.push_back(n);
      ++sc.pos;
    } else {
      break;
    }
  }
  return !out.empty();
}

bool parse_tuple(Scanner& sc, MiTuple& out) {
  if (!sc.consume('{')) return false;
  out.clear();
  if (sc.consume('}')) return true;   // empty {}
  while (true) {
    sc.skip_ws();
    std::string name;
    if (!parse_name(sc, name)) return false;
    if (!sc.consume('=')) return false;
    MiValue v;
    if (!parse_value_inner(sc, v)) return false;
    out[std::move(name)] = std::move(v);
    sc.skip_ws();
    if (sc.consume(',')) continue;
    if (sc.consume('}')) return true;
    return false;
  }
}

// List parser handles both forms:
//   [v, v, ...]
//   [name=v, name=v, ...]    ← discard names, keep values in order
bool parse_list(Scanner& sc, MiList& out) {
  if (!sc.consume('[')) return false;
  out.clear();
  if (sc.consume(']')) return true;
  while (true) {
    sc.skip_ws();
    // Look ahead: is this `name=` (named element) or a bare value?
    std::size_t save = sc.pos;
    std::string maybe_name;
    if (parse_name(sc, maybe_name) && sc.peek() == '=') {
      sc.next();  // consume '='
      MiValue v;
      if (!parse_value_inner(sc, v)) return false;
      out.push_back(std::move(v));
    } else {
      sc.pos = save;
      MiValue v;
      if (!parse_value_inner(sc, v)) return false;
      out.push_back(std::move(v));
    }
    sc.skip_ws();
    if (sc.consume(',')) continue;
    if (sc.consume(']')) return true;
    return false;
  }
}

bool parse_value_inner(Scanner& sc, MiValue& out) {
  sc.skip_ws();
  if (sc.eof()) return false;
  char c = sc.peek();
  if (c == '"') {
    std::string s;
    if (!parse_string(sc, s)) return false;
    out = MiValue(std::move(s));
    return true;
  }
  if (c == '{') {
    MiTuple t;
    if (!parse_tuple(sc, t)) return false;
    out = MiValue(std::move(t));
    return true;
  }
  if (c == '[') {
    MiList l;
    if (!parse_list(sc, l)) return false;
    out = MiValue(std::move(l));
    return true;
  }
  return false;
}

// Drop a single trailing space or CR/LF (gdb sometimes emits a space
// after `(gdb)`; tolerate it for the prompt match).
std::string_view rtrim(std::string_view s) {
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t' ||
                        s.back() == '\r' || s.back() == '\n')) {
    s.remove_suffix(1);
  }
  return s;
}

// Token prefix: optional leading run of decimal digits before the
// record-kind character. Sets *token and advances *cursor past the
// digits if any digits are present.
void take_optional_token(std::string_view s, std::size_t& cursor,
                         std::optional<std::uint64_t>& token) {
  std::size_t start = cursor;
  while (cursor < s.size() &&
         std::isdigit(static_cast<unsigned char>(s[cursor]))) {
    ++cursor;
  }
  if (cursor > start) {
    std::uint64_t v = 0;
    for (std::size_t i = start; i < cursor; ++i) {
      v = v * 10 + static_cast<unsigned>(s[i] - '0');
    }
    token = v;
  }
}

bool parse_klass(Scanner& sc, std::string& out) {
  // The class is an MI keyword: alpha + hyphen, terminated by either
  // EOF or ',' (start of the payload tuple-body).
  out.clear();
  while (!sc.eof()) {
    char c = sc.peek();
    if (std::isalpha(static_cast<unsigned char>(c)) || c == '-') {
      out.push_back(c);
      ++sc.pos;
    } else {
      break;
    }
  }
  return !out.empty();
}

}  // namespace

// ── Public entry points ────────────────────────────────────────────────

std::optional<MiValue> parse_value(std::string_view input) {
  Scanner sc{input, 0};
  MiValue v;
  if (!parse_value_inner(sc, v)) return std::nullopt;
  sc.skip_ws();
  if (!sc.eof()) return std::nullopt;  // trailing garbage
  return v;
}

std::optional<MiRecord> parse_line(std::string_view raw) {
  std::string_view line = rtrim(raw);
  if (line.empty()) return std::nullopt;

  // Prompt: `(gdb)` with optional trailing space (handled by rtrim).
  if (line == "(gdb)") {
    MiRecord r;
    r.kind = MiRecordKind::kPrompt;
    return r;
  }

  std::size_t cursor = 0;
  std::optional<std::uint64_t> token;
  take_optional_token(line, cursor, token);
  if (cursor >= line.size()) return std::nullopt;
  char kind_char = line[cursor++];

  // Stream records take a quoted string body.
  if (kind_char == '~' || kind_char == '&' || kind_char == '@') {
    Scanner sc{line, cursor};
    std::string s;
    if (!parse_string(sc, s)) return std::nullopt;
    sc.skip_ws();
    if (!sc.eof()) return std::nullopt;
    MiRecord r;
    r.kind = kind_char == '~' ? MiRecordKind::kConsoleStream
           : kind_char == '&' ? MiRecordKind::kLogStream
                              : MiRecordKind::kTargetStream;
    r.stream_text = std::move(s);
    return r;
  }

  // Result/async record: kind-char, then a class keyword, then
  // optional `,name=value,name=value,...` payload.
  MiRecord r;
  switch (kind_char) {
    case '^': r.kind = MiRecordKind::kResult;       break;
    case '*': r.kind = MiRecordKind::kExecAsync;    break;
    case '+': r.kind = MiRecordKind::kStatusAsync;  break;
    case '=': r.kind = MiRecordKind::kNotifyAsync;  break;
    default:  return std::nullopt;
  }
  if (token.has_value() && r.kind != MiRecordKind::kResult) {
    // Tokens only legal on result records; reject the malformed
    // line rather than silently dropping the token.
    return std::nullopt;
  }
  r.token = token;

  Scanner sc{line, cursor};
  if (!parse_klass(sc, r.klass)) return std::nullopt;

  MiTuple payload;
  if (sc.consume(',')) {
    // Status-async records sometimes carry `+download,{...}` — a
    // single tuple value rather than a flat name=value pair list.
    sc.skip_ws();
    if (sc.peek() == '{') {
      MiValue inner;
      if (!parse_value_inner(sc, inner)) return std::nullopt;
      // Promote the tuple's contents to the payload root for a
      // uniform caller experience.
      if (!inner.is_tuple()) return std::nullopt;
      payload = inner.as_tuple();
    } else {
      // Parse zero-or-more name=value pairs.
      while (true) {
        sc.skip_ws();
        std::string name;
        if (!parse_name(sc, name)) return std::nullopt;
        if (!sc.consume('=')) return std::nullopt;
        MiValue v;
        if (!parse_value_inner(sc, v)) return std::nullopt;
        payload[std::move(name)] = std::move(v);
        sc.skip_ws();
        if (!sc.consume(',')) break;
      }
    }
  }
  sc.skip_ws();
  if (!sc.eof()) return std::nullopt;

  r.payload = MiValue(std::move(payload));
  return r;
}

}  // namespace ldb::backend::gdbmi
