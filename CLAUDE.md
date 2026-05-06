# LDB — Project Rules

This file is loaded automatically by Claude Code (and similar agent harnesses).
Read it before doing any work in this repo.

> Human contributors: see [`CONTRIBUTING.md`](CONTRIBUTING.md) for the
> external-facing workflow guide. This file is the internal AI-agent
> surface; both files agree on the hard requirements (TDD, warning-clean
> build, ctest green, stdout reserved for JSON-RPC, WHY-not-WHAT commits).

## Project

LDB is an LLM/agent-first universal debugger. C++17/20 daemon (`ldbd`)
wrapping LLDB SBAPI as the v1 backend. Schema-typed JSON-RPC. Strategy
is progressive replacement of LLDB components — never a from-scratch
rewrite. Full design is in `docs/`.

Always start by reading:
1. `docs/00-README.md`
2. `docs/WORKLOG.md` (most recent few entries — see what was done last and why)
3. The relevant phase doc (`02-ldb-mvp-plan.md` for current work)

## Workflow rules — non-negotiable

### TDD

**Tests first.** Before writing any new feature, fix, or refactor:

1. Write a failing test that captures the desired behavior or regression.
2. Run it. Confirm it fails for the *expected* reason.
3. Write the minimal implementation that makes it pass.
4. Run all tests. Confirm green.
5. Refactor if needed; tests stay green.

Test surfaces in this repo:

- **`tests/smoke/`** — bash drivers that pipe JSON-RPC into `ldbd` and assert on output. Use for end-to-end coverage of new endpoints.
- **`tests/unit/`** *(to be added in M1)* — Catch2-based unit tests for protocol parsing, backend conversions, JSON shape generators. Use for anything that doesn't need a live LLDB target.
- **`tests/golden/`** *(to be added in M1)* — canonical JSON outputs against fixed binaries, to enforce determinism across releases.

When the existing harness cannot express the test you need (e.g. you need Catch2 but it's not vendored yet), the *first* commit on a branch is the harness expansion, with its own minimal test.

Do not skip TDD because "the change is small" or "the test is obvious." Bugs in a debugger are silent — the user only finds them when their investigation produces wrong answers.

### Commits

- One commit = one logical change with its tests, ending in a green CI state.
- Don't batch unrelated changes.
- Commit messages explain *why*, not just *what*. Reference the milestone (M0/M1/...), endpoint (`type.layout`), or design-doc section when relevant.
- Co-author trailer: `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>` (or the appropriate model line) when an agent did substantive work.
- Never `git push --force` on shared branches without explicit user instruction.
- Never skip hooks (`--no-verify`).

### Worklog

End every session with an entry in `docs/WORKLOG.md`. Format:

```
## YYYY-MM-DD — <one-line session title>

**Goal:** what we set out to do
**Done:** bullet list of concrete completions, with commit shas where applicable
**Decisions:** non-obvious choices and the reason
**Surprises / blockers:** unexpected findings, fixes, or things deferred
**Next:** what the next session should pick up
```

The worklog is for future-you and future agents. Anyone resuming work should be able to read the last entry and continue without re-reading every commit.

Worklog updates can be their own commit (`worklog: ...`) or appended to the final code commit of the session. Don't leave a session without one.

## Build

```bash
cmake -B build -G Ninja
cmake --build build
build/bin/ldbd --version
ctest --test-dir build --output-on-failure
```

Requires Homebrew LLVM (`brew install llvm`) for `liblldb`. Override with `cmake -B build -DLDB_LLDB_ROOT=/path/to/llvm-prefix`.

## Source layout

```
include/ldb/         public headers
src/main.cpp         entry point
src/protocol/        JSON-RPC framing
src/daemon/          stdio loop, dispatcher
src/backend/         DebuggerBackend interface + LldbBackend
src/util/            logging
third_party/         vendored deps (json.hpp single-header)
tests/smoke/         end-to-end smoke tests via ldbd subprocess
docs/                design + WORKLOG
```

## Code style

- C++20, no exceptions across module boundaries except the typed `backend::Error`.
- `snake_case` for functions and variables, `PascalCase` for types.
- One `namespace ldb::<area>` per area (`protocol`, `daemon`, `backend`, `util`).
- Logs go to stderr. **Stdout is reserved for the JSON-RPC channel.** Anything that breaks this rule breaks every client.
- No comments explaining *what* — names + structure should carry that. Comments only for non-obvious *why*.

## What "done" looks like for an endpoint

1. A failing smoke test (or unit test) exists that exercises the endpoint with a realistic input and asserts on the response shape.
2. The endpoint is registered in `dispatcher.cpp` and listed in `describe.endpoints`.
3. Any backend additions are first added to the `DebuggerBackend` virtual interface, then to `LldbBackend`.
4. JSON shape matches what `docs/02-ldb-mvp-plan.md` specifies. If it differs, the plan is updated in the same commit and the reason recorded in the worklog.
5. Build is warning-clean. `ctest` is green.
6. Worklog entry mentions it.
