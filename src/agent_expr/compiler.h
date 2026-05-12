// SPDX-License-Identifier: Apache-2.0
#pragma once

// S-expression → agent-expression bytecode compiler
// (post-V1 #25 phase-2, docs/29-predicate-compiler.md §2).
//
// The compiler is the agent-facing front-end for the bytecode VM
// shipped in phase-1 (src/agent_expr/bytecode.h + evaluator.cpp).
// It takes a small S-expression DSL — `(eq (reg "rax") 42)` — and
// emits a Program ready to feed into `eval`. The DSL maps 1:1 onto
// the phase-1 opcode table; nothing new in the VM is required.

#include "agent_expr/bytecode.h"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace ldb::agent_expr {

struct CompileError {
  std::size_t line   = 0;  // 1-based; 0 if unset
  std::size_t column = 0;  // 1-based
  std::string message;
};

struct CompileResult {
  // On success: program holds the emitted Program; error is nullopt.
  // On failure: program is nullopt; error holds the anchored message.
  std::optional<Program>      program;
  std::optional<CompileError> error;
};

// Cap on input source bytes — anti-DoS for the predicate.compile
// endpoint. Larger inputs surface a CompileError ahead of tokenising.
// 16 KiB easily fits the realistic predicates we expect; raise later
// if a user case demands it.
constexpr std::size_t kMaxSourceBytes = 16 * 1024;

// Compile S-expression source into bytecode. Empty source compiles
// to a single kEnd (evaluates to 0 — "always false" predicate).
CompileResult compile(std::string_view source);

}  // namespace ldb::agent_expr
