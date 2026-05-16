// SPDX-License-Identifier: Apache-2.0
#pragma once

// Internal-only parser helpers used by the ARM64 ADRP-pair resolver in
// xref_address (src/backend/lldb_backend.cpp). Lifted out of the
// translation unit's anonymous namespace so unit tests can exercise the
// signed/unsigned immediate parsing without piping disassembly through
// a live LLDB target.
//
// Not part of the public ldb::backend API — these helpers exist purely
// because LLDB's disassembler renders ADRP immediates as text we then
// have to re-tokenise. If LLDB exposes a typed operand walker later, we
// can delete this file.
//
// See docs/35-field-report-followups.md §3 phase 2 review punch-list
// item I1 — negative ADRP page counts (`adrp x8, -2`) must parse as
// signed, otherwise the page-math silently drops the entry or re-uses
// a stale prior ADRP for the same destination register.

#include <cstddef>
#include <cstdint>
#include <string>
#include <tuple>

namespace ldb::backend::xref_arm64 {

// Parse a decimal-or-hex non-negative integer starting at s[pos].
// Skips leading whitespace and an optional leading '#'. Returns
// {ok, value, end_pos}.
std::tuple<bool, std::uint64_t, std::size_t>
parse_uint_at(const std::string& s, std::size_t pos);

// Parse a decimal-or-hex signed integer starting at s[pos]. Skips
// leading whitespace + optional '#' + optional '-'. Magnitude
// accumulation matches parse_uint_at; the sign is applied last.
// Returns {ok, value, end_pos}.
//
// Used by the ADRP-recording block: LLDB renders negative page counts
// (compiler-emitted when ADRP targets a page below the PC's page) as
// e.g. `adrp x8, -2`. parse_uint_at would fail on the `-` and the ADRP
// would not be recorded, producing either a missed xref or — worse —
// a silent wrong xref against a stale prior ADRP entry for the same
// register.
std::tuple<bool, std::int64_t, std::size_t>
parse_int_at(const std::string& s, std::size_t pos);

// Parse an ARM64 register token starting at s[pos]. Skips leading
// whitespace and commas. Returns {ok, normalised_lowercase_token,
// end_pos}; "w8" / "X8" / "x8" all normalise to "x8". This lets us
// key the AdrpPair map on a single canonical name even though the
// underlying register pair (w/x) is the same architectural register.
std::tuple<bool, std::string, std::size_t>
parse_reg_at(const std::string& s, std::size_t pos);

}  // namespace ldb::backend::xref_arm64
