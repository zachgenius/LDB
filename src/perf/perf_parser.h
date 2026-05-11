// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

// perf-script text parser (post-V1 plan #13; see docs/22-perf-integration.md).
//
// The runner invokes `perf script -i <perf.data> --header --fields
// comm,pid,tid,cpu,time,event,ip,sym,dso` and feeds the textual
// output into PerfParser::parse. The output is a list of Sample structs
// shaped to align with the BPF agent event schema #12 is landing:
//
//   { ts_ns, tid, pid, cpu, event, comm, stack: [{addr, sym, mod}] }
//
// The parser is intentionally tolerant:
//   - Header lines (prefix `#`) are scanned for hostname / os release /
//     arch and otherwise ignored.
//   - Stack-frame lines whose IP / symbol / DSO is missing or `[unknown]`
//     are still emitted as frames (with empty / verbatim fields).
//   - A stack-frame line that arrives WITHOUT a preceding event header
//     is recorded as a parse_error and skipped — no exception thrown.
//
// Sample-boundary detection: a blank line OR an event-header line that
// follows >=1 stack frame closes the current sample.

namespace ldb::perf {

struct Frame {
  std::uint64_t addr = 0;
  std::string   sym;
  std::string   mod;       // shared object / module basename or path
};

struct Sample {
  std::int64_t              ts_ns = 0;  // nanoseconds since epoch
  std::uint64_t             tid   = 0;
  std::uint64_t             pid   = 0;
  int                       cpu   = -1;
  std::string               comm;
  std::string               event;
  std::vector<Frame>        stack;
};

class PerfParser {
 public:
  struct Result {
    std::vector<Sample>      samples;
    // Non-fatal parse errors, one entry per skipped line / unparsable
    // sample. Populated alongside `samples` so the caller can decide
    // whether to surface them; the dispatcher logs the count and
    // includes the first N in the response for diagnostics.
    std::vector<std::string> parse_errors;
    // Trace metadata sniffed from the `# ...` header block. Best-effort.
    std::string              hostname;
    std::string              os_release;
    std::string              arch;
  };

  // Parse a buffer of perf-script output. Tolerant; never throws.
  static Result parse(std::string_view text);

  // Convert one sample to its canonical JSON wire shape (see header
  // doc-comment for the schema). Stable across daemon versions —
  // changes here are wire-protocol breaks.
  static nlohmann::json sample_to_json(const Sample& s);
};

}  // namespace ldb::perf
