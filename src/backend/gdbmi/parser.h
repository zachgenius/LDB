// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

// GDB/MI3 protocol parser — line-in, MiRecord-out.
//
// Used by `GdbMiBackend` (post-V1 plan #8). The full protocol shape
// and mapping rationale live in docs/18-gdbmi-backend.md; this header
// only formalises the value grammar:
//
//   value  ::= string | tuple | list
//   string ::= " ... "    (C-style escapes; \n \t \" \\ \r supported)
//   tuple  ::= { name=value, name=value, ... }
//   list   ::= [ value, value, ... ]    (plain)
//          ::= [ name=value, name=value, ... ]   (named-element variant)
//                                                used by frames=[],
//                                                threads=[], etc.
//
// The named-element list variant flattens: callers receive a plain
// list where each element is the unnamed value (the `name=` prefix
// is discarded since the name is implicit from context).

namespace ldb::backend::gdbmi {

class MiValue;

using MiTuple = std::map<std::string, MiValue>;
using MiList  = std::vector<MiValue>;

class MiValue {
 public:
  MiValue();
  explicit MiValue(std::string s);
  explicit MiValue(MiTuple t);
  explicit MiValue(MiList l);

  MiValue(const MiValue&);
  MiValue(MiValue&&) noexcept;
  MiValue& operator=(const MiValue&);
  MiValue& operator=(MiValue&&) noexcept;
  ~MiValue();

  bool is_string() const;
  bool is_tuple()  const;
  bool is_list()   const;

  const std::string& as_string() const;
  const MiTuple&     as_tuple()  const;
  const MiList&      as_list()   const;

 private:
  std::variant<std::string, MiTuple, MiList> v_;
};

enum class MiRecordKind {
  kResult,         // ^
  kExecAsync,      // *
  kStatusAsync,    // +
  kNotifyAsync,    // =
  kConsoleStream,  // ~
  kLogStream,      // &
  kTargetStream,   // @
  kPrompt,         // (gdb)
};

struct MiRecord {
  MiRecordKind                  kind   = MiRecordKind::kPrompt;
  std::optional<std::uint64_t>  token;        // result records only
  std::string                   klass;        // "done"/"error"/"running"/"stopped"/...
  MiValue                       payload;      // tuple for result/async, empty otherwise
  std::string                   stream_text;  // stream records only
};

// Parse one line from gdb's stdout. Returns nullopt for malformed
// input — the daemon logs the offending line via log::warn and
// continues. The parser never throws.
std::optional<MiRecord> parse_line(std::string_view line);

// Public for the unit tests: parse a value-grammar production
// directly from a string. Used by the test suite to pin grammar
// edge cases without wrapping each one in a synthetic record.
std::optional<MiValue> parse_value(std::string_view input);

}  // namespace ldb::backend::gdbmi
