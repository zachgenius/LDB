# Contributing to LDB

Thanks for your interest in LDB. This document is the surface for **external
human contributors**. The internal AI-agent workflow rules (loaded by Claude
Code and similar harnesses) live in [`CLAUDE.md`](CLAUDE.md); much of what is
strict-required there is also strict-required here, but this file is the
canonical entry point for someone arriving at the repo for the first time.

If a section here disagrees with `CLAUDE.md`, this file wins for human
contributors. Both files agree on the hard requirements below.

---

## 1. Project ethos

LDB is an **LLM/agent-first universal debugger.** The primary user is an
agent, not a person at a REPL. That decision shapes every contribution we
accept:

- **Schema-first.** Every endpoint advertises a JSON Schema in
  `describe.endpoints`. Wire shapes are not folklore; they are written down,
  drift-tested, and versioned (see `docs/05-protocol-versioning.md`).
- **Deterministic.** The same `(method, params, snapshot)` returns
  byte-identical output. The cores-only determinism gate runs in CI; the
  live-process audit (`docs/04-determinism-audit.md`) defines what to check
  for live targets.
- **Cost-aware.** Every successful response carries `_cost: {bytes,
  items?, tokens_est}`. Endpoints declare a `cost_hint` (`low` /
  `medium` / `high` / `unbounded`) and `requires_stopped` so a planning
  agent can budget before it spends tokens.
- **Token-efficient.** Every endpoint accepts a `view` descriptor
  (`fields` / `limit` / `offset` / `summary`). No "just dump everything"
  responses; pagination and projection are first-class.
- **Progressive replacement, not rewrite.** V1 wraps LLDB. Components get
  owned only when measured pain plus an architectural reason justify it.
  Read `docs/03-ldb-full-roadmap.md §3` before proposing a swap.

Read [`docs/00-README.md`](docs/00-README.md) once before your first PR. The
two-paragraph skim is enough; the design philosophy will save you a round
trip in review.

---

## 2. Hard requirements

These are **non-negotiable** for every PR. Reviewers will block on any of
them.

### 2.1 Tests first

Every PR includes a test that captures the desired behavior or regression.

- New feature → unit test (`tests/unit/`, Catch2) + smoke test
  (`tests/smoke/`, Python or bash) if the wire shape changes.
- Bug fix → a regression test that fails on `master` and passes with your
  change.
- Refactor → existing tests cover it; if they don't, expand the suite first
  in a separate commit.

There is no "trivial change, no test needed" exception. A debugger's bugs
are silent — the user only finds them when their investigation produces
wrong answers. Catch them in the suite.

If the existing harness can't express the test you need, expand the harness
in the **first** commit on your branch (with its own minimal test).

### 2.2 ctest is 100% green

```bash
ctest --test-dir build --output-on-failure
```

Must show every test green before you request review. If a test SKIPs on
your machine because of an optional dependency (see §6), that is fine — but
note it in the PR. Failing tests are not.

### 2.3 Build is warning-clean

The project compiles under:

```
-Wall -Wextra -Wpedantic -Wshadow -Wnon-virtual-dtor -Wold-style-cast
-Wcast-align -Wunused -Woverloaded-virtual -Wconversion -Wsign-conversion
-Wnull-dereference -Wdouble-promotion -Wformat=2 -Wmisleading-indentation
```

A new warning is a regression. If a warning is unavoidable (rare),
suppress it locally with a `#pragma` and explain in a comment.

### 2.4 Stdout is reserved for the JSON-RPC channel

Logs go to **stderr.** Anything that prints to stdout outside the protocol
framing breaks every client, silently. There is no exception. If you need a
trace, use `LDB_LOG` / the logging macros, which write to stderr.

### 2.5 Commit messages explain WHY

Subject lines are short and prefixed (`feat(daemon): …`, `fix(probes): …`,
`docs: …`). Bodies explain the motivation, the design tradeoff, or the bug
that was hiding — not a restatement of the diff. Reference the milestone
(M0–M5 or post-v0.1 slice) and the endpoint or component when relevant.

If an AI agent did substantive work, add a co-author trailer (see §10).

---

## 3. Soft expectations

These are **strongly preferred** but won't block a PR by themselves.

- **One commit = one logical change**, with its tests, ending in a green
  state. Don't batch unrelated work; split it.
- **Reference the milestone or slice** in the commit subject or body
  (`Tier 1 §3a`, `M3 part 2`, etc.). Makes `git log` greppable.
- **Update `docs/WORKLOG.md`** with a session entry if you closed a
  substantial slice. Format and rationale are in `CLAUDE.md`. The worklog
  is for future contributors resuming the project; treat it that way.
- **Match existing code style** — `snake_case` for functions and variables,
  `PascalCase` for types, one `namespace ldb::<area>` per area
  (`protocol`, `daemon`, `backend`, `util`, `store`, `probes`,
  `observers`, `transport`).
- **Comments only for non-obvious WHY.** Names and structure should carry
  the *what*. If you find yourself explaining what a line does, rename
  the variable instead.
- **No exceptions across module boundaries**, except the typed
  `backend::Error`.

---

## 4. What needs design discussion before code

Some changes affect the wire protocol or the architecture and must be
discussed in an issue before code lands. Open a GitHub issue with the
`rfc:` prefix and a one-page design. Cost analysis is part of the design,
not an afterthought:

- New endpoints or changes to existing endpoint shapes.
- Schema changes to `describe.endpoints` (additions to the catalog
  shape itself, not per-endpoint schemas).
- New external dependencies (`find_package`, vendored code, runtime
  binaries).
- Anything that changes the wire protocol — see
  `docs/05-protocol-versioning.md` for the minor (additive) vs major
  (breaking) policy. A major bump is a real cost; budget for it
  explicitly.
- Component-ownership swaps (per the progressive-replacement strategy in
  `docs/03-ldb-full-roadmap.md §3`). Replacing an LLDB component with our
  own implementation is a strategic decision, not a coding decision.
- Anything that touches the determinism contract (cores-only or live).

A design RFC should include:

- Motivation: what hurts today.
- Proposed wire shape (request / response / errors), with full
  draft-2020-12 schema.
- Cost analysis: estimated bytes, tokens, round-trips for typical use.
- `requires_stopped` semantics: does it run on a stopped target, a
  running target, or both? Default to false (i.e. doesn't require stop)
  unless you can justify otherwise.
- `cost_hint`: `low` / `medium` / `high` / `unbounded` and the
  reasoning.
- Determinism: deterministic against `(method, params, snapshot)`? If
  not, why, and is the non-determinism fenced (e.g. live-only)?
- Test plan: what unit / smoke / golden tests cover it.

Trivial fixes don't need an RFC. When in doubt, open the issue —
back-and-forth on the design is cheaper than redoing the implementation.

---

## 5. Build setup

See [`README.md`](README.md#build) for the canonical quickstart. The short
version:

```bash
cmake -B build -G Ninja \
  -DLDB_LLDB_ROOT=/path/to/llvm-prefix
cmake --build build
build/bin/ldbd --version
```

`LDB_LLDB_ROOT` should point at a directory containing `include/lldb/API/`
and `lib/liblldb.so` (Linux) or `lib/liblldb.dylib` (macOS).

---

## 6. Running the test suite

```bash
ctest --test-dir build --output-on-failure
```

Some tests SKIP without optional dependencies. That is expected; it is not
a failure.

| Optional dep | What SKIPs without it |
|---|---|
| `bpftrace` not installed | `kind: "uprobe_bpf"` probe live tests |
| `tcpdump` without `CAP_NET_RAW` | `observer.net.tcpdump` live test |
| No local `sshd` reachable | SSH transport live tests |
| No `lldb-server` on PATH | `target.connect_remote*` live tests |

If you are on macOS arm64, read `docs/macos-arm64-status.md` first. Hardware
sign-off for that platform is currently a known gap (Tier 1 §2 in
`docs/POST-V0.1-PROGRESS.md`); some Linux-flavored fixtures do not yet gate
on `__APPLE__` and may not build cleanly there.

The determinism gate (`tests/smoke/test_provenance_replay.py`) runs the
same RPC sequence twice across two daemon processes and asserts
byte-identical `data`. If your change touches any cores-path endpoint,
expect this test to flag non-determinism.

---

## 7. Submitting changes

1. Fork the repo on GitHub.
2. Create a branch off `master`. Use a descriptive name —
   `feat/probe-recipes`, `fix/string-list-escape`, `docs/contributing`.
3. Make commits per §2 and §3 above. Push to your fork.
4. Open a PR against `master`. Fill in the PR template (see
   `.github/PULL_REQUEST_TEMPLATE.md`); the checkboxes are not
   decoration, they're the review checklist.
5. Reviewer feedback comes via PR comments. Address it in **new commits**
   on the branch (don't `--amend` an already-reviewed commit; it makes
   the diff history harder to follow). The maintainer will squash if
   appropriate at merge time.

PRs are merged via squash or rebase, never via merge commit (the history
stays linear).

---

## 8. Code of conduct

Be respectful. Harassment, discriminatory language, or personal attacks
are not tolerated and are grounds for removal from the project.

A full Code of Conduct will be adopted before the project hits broader
public exposure. Until then, treat the above as the working policy and
escalate concerns to the maintainer (`@zachgenius` on GitHub).

---

## 9. License

The project license is **currently undecided** (see `README.md`). Apache
2.0 with LLVM exception is the leading candidate, matching the LLDB
upstream. By contributing, you agree that your contribution will be
licensed under whatever license the project ultimately adopts. We will
not adopt a license you couldn't have anticipated — practically that means
"Apache-2.0 with LLVM exception, or something materially similar."

If you have a strong preference (or a constraint), say so in your first
PR; better to surface it early.

No CLA. No DCO bot. The implicit license-grant above is the entire legal
ceremony for now. This may change before 1.0.

---

## 10. AI-assisted contributions

LDB is an agent-first project; using AI tools to help author contributions
is welcome and expected.

**If an AI agent did substantive work on a commit, disclose it via a
co-author trailer:**

```
Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
```

(or the appropriate model line — `Claude Sonnet 4.5`, `GPT-5`, etc.)

The internal-agent workflow (TDD-strict, commit-per-slice, worklog every
session) is codified in `CLAUDE.md` and is loaded automatically by Claude
Code. External contributors using AI tools should follow the spirit of it
— tests first, one commit per logical change, honest commit messages —
even if the harness isn't enforcing it.

A PR that is mostly AI-authored is fine. A PR that fakes its commit
authorship to hide that fact is not. The disclosure helps reviewers
calibrate; it is not a black mark.

---

## 11. Where to ask questions

- **Bug?** Open an issue with the `bug` template
  (`.github/ISSUE_TEMPLATE/bug_report.yml`).
- **Feature idea?** Open an issue with the `feature` or `rfc` template.
- **Design question or "is this in scope?"** Open a discussion or an
  `rfc:`-prefixed issue.
- **Quick "how does X work?"** Read the docs in `docs/` first; they're
  the source of truth for design decisions. If you can't find an answer,
  open an issue with the `question` label.

The maintainer is single-person at v0.1 — response time is
best-effort. Prefer well-formed issues with repros over chat-style
back-and-forth.
