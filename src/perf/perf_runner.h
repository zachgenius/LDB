// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "perf/perf_parser.h"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// Synchronous wrapper around `perf record` + `perf script` (post-V1
// plan #13; see docs/22-perf-integration.md).
//
// PerfRunner shells out to the system `perf` binary; we do NOT link
// libperf or libtraceevent (GPLv2 + kernel-version coupling). Output
// goes to a temp `perf.data` file the caller can persist via
// ArtifactStore.
//
// The runner is synchronous in phase 1: `record(spec)` blocks for
// `spec.duration` (pid mode) or until the supplied command exits
// (command mode), then returns. An async variant flips the wait to a
// background thread and threads a record_id through `perf.cancel`;
// the data path here doesn't change, only the wait shape.
//
// Errors: `record` and `report` throw ldb::backend::Error on
// subprocess-side failure (no perf on PATH, perf rc!=0, perf.data
// missing). Parse errors are non-fatal and live in
// `RecordResult::parse_errors` / `ReportResult::parse_errors`.

namespace ldb::perf {

struct RecordSpec {
  // Exactly one of pid or command must be set. Empty `command` means
  // "use pid"; non-empty `command` means "spawn this and record it".
  std::optional<std::int64_t> pid;
  std::vector<std::string>    command;

  std::chrono::milliseconds   duration{500};
  std::uint32_t               frequency_hz   = 99;
  // perf -e <events,...>; defaults to "cycles" when empty.
  std::vector<std::string>    events;
  // perf --call-graph <mode>; "fp" | "dwarf" | "lbr". Empty defaults to "fp".
  std::string                 call_graph;

  // Hard cap on duration so an agent typo doesn't pin the daemon for
  // hours. 5 minutes is generous.
  static constexpr std::int64_t kMaxDurationMs = 5 * 60 * 1000;
};

struct RecordResult {
  std::string               perf_data_path;     // absolute path to the temp file
  std::uint64_t             perf_data_size = 0; // bytes
  // Argv actually invoked (post-resolution; useful for "what did the
  // daemon do?" inspection).
  std::vector<std::string>  perf_argv;
  // Whole `perf script` parsing result (samples, parse_errors, meta).
  PerfParser::Result        parsed;
  // Wall-clock duration of the perf record subprocess.
  std::chrono::milliseconds wall_duration{0};
  // Tail of perf's stderr (bounded ~4 KiB) for diagnostics.
  std::string               stderr_tail;
};

struct ReportSpec {
  std::string perf_data_path;
  std::int64_t max_samples      = 0;   // 0 = no cap
  std::int64_t max_stack_depth  = 0;   // 0 = no cap
};

struct ReportResult {
  PerfParser::Result parsed;
  bool               truncated = false; // sample count > max_samples
  // Pre-truncation sample count. `parsed.samples.size()` reflects the
  // capped/sliced view; `total_samples` is what the trace actually held.
  // An agent calling `perf.report` with `max_samples=10` against a trace
  // of 2000 samples needs to see 2000 to know whether to widen the cap.
  std::size_t        total_samples = 0;
};

class PerfRunner {
 public:
  // Locate the `perf` binary. Honors $LDB_PERF first, then PATH lookup.
  // Returns "" if perf is unavailable.
  static std::string discover_perf();

  // Synchronously run `perf record`. Caller owns the perf.data file at
  // RecordResult::perf_data_path; PerfRunner does NOT delete it (the
  // dispatcher persists it via ArtifactStore then unlinks).
  static RecordResult record(const RecordSpec& spec);

  // Run `perf script` against an existing perf.data path and parse.
  static ReportResult report(const ReportSpec& spec);
};

}  // namespace ldb::perf
