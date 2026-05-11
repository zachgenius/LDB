# LDB

[![CI](https://github.com/zachgenius/LDB/actions/workflows/ci.yml/badge.svg)](https://github.com/zachgenius/LDB/actions/workflows/ci.yml)

**An LLM/agent-first universal debugger.**

LDB is a debugger built for LLM agents and reverse engineers, not for humans
typing at a REPL. It collapses the classical "live debugger + core-dump
analyzer + binary investigation kit" workflow — `gdb`, `pahole`, `objdump`,
`strings`, `strace`, `tcpdump`, `/proc`, and scratch shell scripts — into a
single schema-typed protocol an agent can drive autonomously, with structured
responses, deterministic replay, cost-aware metadata, and portable
investigation bundles.

It is not a GDB clone. It is a GDB-class tool with a different primary user:
an LLM that wants typed, paginated, cost-budgeted answers, and a knowledge
graph that survives across sessions.

---

## Status

**V1 released.** `v1.0.0` closed all release gates tracked in
[docs/13-v1-readiness.md](docs/13-v1-readiness.md). `v1.3.0` is the
current tag — an agent-UX polish release on top of v1.2.0's signing
+ reverse-exec foundations:

- `recipe.reload` + `LDB_RECIPE_DIR` startup scan for hot-reloading
  file-backed probe recipes;
- `artifact.put format="hypothesis-v1"` + `artifact.hypothesis_template`
  for structured belief tracking;
- `view.diff_against=<snapshot>` on `module.list` / `thread.list`
  (set-symmetric-difference against a cached baseline snapshot);
- `process.reverse_step` / `thread.reverse_step` now accept
  `kind=in/over/out` via client-side `bs`-loop emulation
  (see [docs/16-reverse-exec.md](docs/16-reverse-exec.md));
- `describe.endpoints` with `view.include_cost_stats=true` returns
  measured `cost_p50_tokens` alongside the static `cost_hint`;
- Token-budget regression CI gate (`tests/baselines/agent_workflow_tokens.json`)
  locks `_cost.tokens_est` totals across a canonical RPC sequence,
  fails on ±10% drift.

Earlier additive features remain: `.ldbpack` ed25519 signing
([docs/14](docs/14-pack-signing.md)), reverse-execution endpoints
([docs/16](docs/16-reverse-exec.md)), and the dogfood fixes from
v1.1.0 (qualified C++ symbol lookup, DWARF `byte_size` warnings,
`address` alias on disassembled instructions).

No breaking wire changes since v1.0.0; everything since is additive.
See [docs/17-version-plan.md](docs/17-version-plan.md) for the full
v1.3 / v1.4 / v1.5 bundling and [docs/15-post-v1-plan.md](docs/15-post-v1-plan.md)
for the item-level catalog.

| | |
|---|---|
| **Validation** | Default `ctest` suite (58 tests) plus GitHub Actions on Linux x86-64, Linux arm64, macOS arm64, and an opt-in Capstone leg |
| **Endpoints** | 87 across target / process / thread / frame / value / memory / probe / observer / session / artifact / recipe / correlate |
| **Wire formats** | Line-delimited JSON (default); length-prefixed CBOR (`--format=cbor`) |
| **Protocol schema** | JSON Schema draft 2020-12 for every endpoint via `describe.endpoints` |
| **Determinism** | Core-backed replay gate plus live↔core parity checks for selected static-analysis endpoints |

---

## Architecture

```
┌──────────────────────────────────────────────────┐
│  LLM agent host  /  human via ldb CLI            │
└──────────────────────────────────────────────────┘
                ↕  JSON (line-delimited) | CBOR (length-prefix)
┌──────────────────────────────────────────────────┐
│  ldbd  — C++17/20 daemon, runs on operator host  │
│  • Schema-first JSON-RPC server (stdio)          │
│  • Sessions (sqlite WAL log, replayable)         │
│  • Artifacts (build-ID keyed, portable bundles)  │
│  • View descriptors (projection / pagination /   │
│    summary / cost preview)                       │
│  • Probe orchestrator (LLDB breakpoint + uprobe  │
│    BPF, one event shape)                         │
│  • Typed observer plugins (/proc, ss, tcpdump,   │
│    igmp; allowlisted exec escape hatch)          │
│  • DebuggerBackend abstraction                   │
└──────────────────────────────────────────────────┘
       ↓ liblldb (SBAPI)              ↓ ssh
  local target / core            remote target host:
                                   • lldb-server platform
                                   • bpftrace (optional)
                                   • observer probes
```

The daemon runs on the operator's machine. Remote targets are reached over SSH
plus `lldb-server platform` — no LDB-specific code on the target.

---

## Capability matrix

| Surface | Endpoints | Replaces |
|---|---|---|
| **Static analysis** | `target.open`, `target.close`, `target.list`, `target.label`, `module.list`, `type.layout`, `symbol.find`, `string.list`, `string.xref`, `disasm.range`, `disasm.function`, `xref.addr`, `static.globals_of_type` | `pahole`, `nm`, `readelf`, `strings`, `objdump` |
| **Cross-target correlation** | `correlate.types`, `correlate.symbols`, `correlate.strings` | hand-rolled diffing between two binaries / cores |
| **Process control** | `target.attach`, `target.connect_remote`, `target.connect_remote_ssh`, `target.load_core`, `target.create_empty`, `process.launch`, `process.state`, `process.continue`, `process.kill`, `process.detach`, `process.save_core`, `process.step`, `process.reverse_continue`, `process.reverse_step` | `gdb`, `lldb`, `rr` |
| **Thread / frame / value** | `thread.list`, `thread.frames`, `thread.continue`, `thread.reverse_step`, `frame.locals`, `frame.args`, `frame.registers`, `value.eval`, `value.read` | `gdb` `bt`/`info`/`print`, `lldb` `frame` family |
| **Memory** | `mem.read`, `mem.read_cstr`, `mem.regions`, `mem.search`, `mem.dump_artifact` | `gdb` `x`/`find`, `/proc/<pid>/mem` scraping |
| **Probes** | `probe.create` (kind: `lldb_breakpoint` or `uprobe_bpf`), `probe.events`, `probe.list`, `probe.enable`, `probe.disable`, `probe.delete` | `strace`, `bpftrace`, hand-rolled tracepoints |
| **Typed observers** | `observer.proc.fds`, `observer.proc.maps`, `observer.proc.status`, `observer.net.sockets`, `observer.net.tcpdump`, `observer.net.igmp`, `observer.exec` (allowlisted) | `lsof`, `ss`, `tcpdump`, `cat /proc/...`, `run_host_command` |
| **Sessions** | `session.create`, `session.attach`, `session.detach`, `session.list`, `session.info`, `session.diff`, `session.targets`, `session.export`, `session.import` | sqlite-backed RPC log; `.ldbpack` portable bundles |
| **Artifacts** | `artifact.put`, `artifact.get`, `artifact.list`, `artifact.tag`, `artifact.delete`, `artifact.relate`, `artifact.relations`, `artifact.unrelate`, `artifact.export`, `artifact.import` | build-ID-keyed store with typed relations, queryable across sessions |
| **Recipes** | `recipe.create`, `recipe.from_session`, `recipe.list`, `recipe.get`, `recipe.run`, `recipe.delete`, `recipe.lint` | parametric replayable RPC scripts captured from sessions |

Every endpoint accepts a `view` descriptor (`fields`/`limit`/`offset`/`summary`)
for token-budget control. Every successful response carries `_cost: {bytes,
items?, tokens_est}` and `_provenance: {snapshot, deterministic}`.

---

## Requirements

| Component | Version | Notes |
|---|---|---|
| C++ compiler | GCC 13+ / Clang 16+ | C++20 features used in the daemon |
| CMake | 3.20+ | Ninja generator recommended |
| LLDB / liblldb | 18 or newer | 22.1.x verified; older versions likely work via SBAPI stability |
| SQLite | 3.40+ | Sessions and artifact index |
| zlib | system | `.ldbpack` gzip compression |
| libsodium | 1.0.18+ | `.ldbpack` ed25519 signing (hard dep) |
| Python | 3.11+ | Smoke tests and `tools/ldb/ldb` client |
| Ninja | 1.10+ | Optional; default build generator |
| `bpftrace` | 0.18+ | Optional; required for `kind: "uprobe_bpf"` probes |
| `lldb-server` | from LLDB | Optional; required for `target.connect_remote*` live tests |
| `tcpdump` | system | Optional; required for `observer.net.tcpdump` (needs CAP_NET_RAW) |
| `rr` | 5.6+ | Optional; required for reverse-execution endpoints. Linux only; needs `kernel.perf_event_paranoid <= 1` to record |

LLDB's prebuilt LLVM tarballs link against `libpython3.11` for embedded
scripting; ensure that runtime is available even if you don't use embedded
Python features.

On Linux, attach-style debugging requires `kernel.yama.ptrace_scope=0` (or
appropriate capabilities) for non-child target processes.

---

## Install

Linux (Ubuntu 24.04-class host):

```bash
sudo apt-get update
sudo apt-get install -y \
  ninja-build cmake build-essential \
  liblldb-dev lldb \
  libsqlite3-dev zlib1g-dev libsodium-dev \
  python3 \
  bpftrace tcpdump \
  openssh-server openssh-client \
  rr
```

macOS (Apple Silicon / Homebrew):

```bash
brew install llvm ninja cmake sqlite libsodium
```

Optional Capstone backend:

```bash
brew install capstone pkgconf
```

`bpftrace`, `tcpdump`, `lldb-server`, `openssh-server`, and `rr` are only
needed for their respective live probe / observer / remote-connection /
reverse-execution paths; the static analysis and core-backed paths build
without them. `libsodium` is a hard build dep (used by `.ldbpack` ed25519
signing). `rr` is Linux x86-64 / arm64 only — macOS has no equivalent.

---

## Build

```bash
# Configure
cmake -B build -G Ninja \
  -DLDB_LLDB_ROOT=/path/to/llvm-prefix \
  -DCMAKE_PREFIX_PATH=/usr/local

# Build
cmake --build build

# Test
ctest --test-dir build --output-on-failure

# Verify
build/bin/ldbd --version
```

`LDB_LLDB_ROOT` should point at a directory containing `include/lldb/API/` and
`lib/liblldb.so` (or `liblldb.dylib` on macOS). On Homebrew this is typically
`/opt/homebrew/opt/llvm`; on apt-installed LLVM it is `/usr/lib/llvm-NN`; for
prebuilt tarballs from `releases.llvm.org` it is the extracted directory.

`CMAKE_PREFIX_PATH=/usr/local` is needed only when SQLite headers were
installed to `/usr/local` (e.g. via manual deb extraction).

---

## Test

Default suite:

```bash
ctest --test-dir build --output-on-failure
```

Capstone-enabled build:

```bash
cmake -B build-capstone -G Ninja \
  -DLDB_LLDB_ROOT=/path/to/llvm-prefix \
  -DLDB_ENABLE_CAPSTONE=ON
cmake --build build-capstone --parallel
ctest --test-dir build-capstone --output-on-failure \
  -R "smoke_hello_capabilities|smoke_disasm|smoke_agent_workflow|unit_tests"
```

See [docs/06-ci.md](docs/06-ci.md) for the exact CI matrix, SKIP behavior, and
reproduction notes.

---

## Supported platforms

The intended V1 support matrix is intentionally narrow:

| Platform | Status | Notes |
|---|---:|---|
| Linux x86-64 | Supported | Primary CI leg; apt LLDB 18 in CI, local LLVM roots supported |
| Linux arm64 | Validation | CI validates behavior; V1 remains source-only and does not promise separate arm64 packaging |
| macOS arm64 | Supported | Homebrew LLVM plus Apple's signed `debugserver`; some Linux-only observers SKIP |
| Windows | Out of scope | No V1 support claim |
| FreeBSD | Out of scope | Roadmap item, not a V1 promise |

---

## Quickstart

The `ldb` CLI is a thin Python client that spawns `ldbd` per invocation,
fetches the catalog from `describe.endpoints`, and synthesizes per-method
argparse subcommands from each endpoint's JSON Schema.

```bash
# Top-level help — lists every method
./tools/ldb/ldb --help

# Server identity
./tools/ldb/ldb hello

# Catalog with view descriptor
./tools/ldb/ldb describe.endpoints --view fields=method,summary --view limit=10

# Per-method help (reads the schema)
./tools/ldb/ldb type.layout --help

# Open a binary statically
./tools/ldb/ldb target.open path=./build/bin/fixtures/structs

# Inspect a struct
./tools/ldb/ldb type.layout target_id=1 name=dxp_login_frame

# Use the CBOR wire format (binary; for tooling clients)
./tools/ldb/ldb --format=cbor describe.endpoints --view summary=true

# See the full envelope including _cost and _provenance
./tools/ldb/ldb --raw hello
```

---

## Wire protocol

JSON-RPC 2.0 framing with extensions. Default transport is line-delimited JSON
on stdio; CBOR (RFC 8949) is selectable per-process via `--format=cbor` with
length-prefixed framing.

Requests:
```json
{ "id": "r7", "jsonrpc": "2.0", "method": "type.layout",
  "params": { "target_id": 1, "name": "dxp_login_frame",
              "view": { "fields": ["off","sz","name"], "limit": 100 } } }
```

Responses:
```json
{ "id": "r7", "jsonrpc": "2.0", "ok": true,
  "data": { "name": "dxp_login_frame", "byte_size": 128, "fields": [...] },
  "_cost":       { "bytes": 1842, "items": 14, "tokens_est": 461 },
  "_provenance": { "snapshot": "core:e3b0c44...", "deterministic": true } }
```

Errors carry a typed `error.code` from a fixed enum so an agent can match on
code rather than prose. Codes in the V1 surface:

| Code | Meaning |
|---|---|
| `-32600` | Invalid request |
| `-32601` | Method not found |
| `-32602` | Invalid params |
| `-32700` | Parse error / framing error |
| `-32000` | Backend error (typed `backend::Error` from the daemon) |
| `-32002` | Bad state (store / allowlist not configured) |
| `-32003` | Forbidden (operator allowlist denied the argv) |

---

## Known limitations

These are acceptable in the planned V1 cut and are part of the public contract:

- LLDB remains the default backend and owns target, process, and DWARF semantics.
- Capstone is opt-in and affects only `disasm.range` and `disasm.function`.
- `xref.addr` and `string.xref` intentionally keep LLDB disassembly/comment semantics.
- True async/non-stop runtime is deferred; the per-thread protocol surface is present but sync-backed.
- Reverse execution is supported only against rr-backed targets (reached via `target.connect_remote rr://`); `process.reverse_step` / `thread.reverse_step` accept all four kinds (`in`/`over`/`out`/`insn`) — `in`/`over`/`out` use a bounded `bs`-loop emulation with source-line + frame-depth termination ([`docs/16-reverse-exec.md`](docs/16-reverse-exec.md) §"Reverse-step-over/into").
- Linux-only observers and BPF/tcpdump paths SKIP on macOS or unprivileged runners.
- macOS local-process tests depend on Apple's signed `debugserver`.

---

## Release artifact policy

Planned V1 releases are **source-only**: semantic-version tags plus release
notes, with no promise of prebuilt binary tarballs yet. Binary packaging can
move to post-V1 without changing the wire contract.

---

## Project structure

```
include/ldb/         Public headers
src/main.cpp         Entry point
src/protocol/        JSON-RPC framing, CBOR transport, view, cost, provenance
src/daemon/          Stdio loop, dispatcher, describe.endpoints catalog
src/backend/         DebuggerBackend interface, LldbBackend implementation
src/store/           Artifact store, session store, .ldbpack pack/unpack
src/probes/          Probe orchestrator, lldb_breakpoint + bpftrace engines
src/observers/       Typed proc/net observers, exec allowlist
src/transport/       SSH (exec, port-forward, tunneled-cmd), local exec, streaming exec
src/util/            sha256, log
tools/ldb/           Python CLI client
tests/smoke/         End-to-end tests via ldbd subprocess
tests/unit/          Catch2 unit tests
tests/fixtures/      Test binaries (structs, sleeper) + canned text fixtures
third_party/         Vendored deps (nlohmann/json, Catch2 amalgamated)
docs/                Design docs and engineering worklog
```

---

## Documentation

| File | Purpose |
|---|---|
| [`docs/00-README.md`](docs/00-README.md) | Architecture overview, design decisions, reading order |
| [`docs/01-gdb-core-methodology.md`](docs/01-gdb-core-methodology.md) | Analysis of GDB 17.1's architecture — foundational reading |
| [`docs/02-ldb-mvp-plan.md`](docs/02-ldb-mvp-plan.md) | V1 plan: protocol spec, RPC surface, milestones, reference workflow |
| [`docs/03-ldb-full-roadmap.md`](docs/03-ldb-full-roadmap.md) | Post-V1 trajectory: progressive replacement of LLDB components |
| [`docs/06-ci.md`](docs/06-ci.md) | What CI runs, what SKIPs on the runner, how to reproduce locally |
| [`docs/07-dap-shim.md`](docs/07-dap-shim.md) | `ldb-dap` Debug Adapter Protocol shim — supported requests, capabilities, VS Code launch.json example |
| [`docs/13-v1-readiness.md`](docs/13-v1-readiness.md) | V1 release gates, supported matrix, validation commands, and known limitations |
| [`docs/14-pack-signing.md`](docs/14-pack-signing.md) | `.ldbpack` ed25519 signing — design, key format, failure matrix |
| [`docs/15-post-v1-plan.md`](docs/15-post-v1-plan.md) | Tiered breakdown of post-V1 deferred work with dependency graph and execution order |
| [`docs/16-reverse-exec.md`](docs/16-reverse-exec.md) | Reverse-execution endpoints over rr via RSP packet injection — design, scope, kind=insn-only contract |
| [`docs/WORKLOG.md`](docs/WORKLOG.md) | Engineering journal — newest entries on top |
| [`CLAUDE.md`](CLAUDE.md) | Workflow rules for AI-assisted development on this repo |

---

## Development workflow

LDB is developed under strict TDD: every feature, fix, or refactor begins with
a failing test. Test surfaces:

- **`tests/unit/`** — Catch2 against compiled-in source modules. Fast,
  deterministic; covers protocol parsing, backend conversions, store
  invariants, parser correctness against canned input.
- **`tests/smoke/`** — Bash and Python drivers that spawn `ldbd` as a
  subprocess and exercise endpoints over the real JSON-RPC channel.
- **Determinism gate** (`tests/smoke/test_provenance_replay.py`) — runs the
  same RPC sequence twice across two daemon processes and asserts byte-
  identical `data` payloads, enforcing the `(method, params, snapshot)`
  determinism contract on the cores-only path.

Build is warning-clean under
`-Wall -Wextra -Wpedantic -Wshadow -Wnon-virtual-dtor -Wold-style-cast`
`-Wcast-align -Wunused -Woverloaded-virtual -Wconversion -Wsign-conversion`
`-Wnull-dereference -Wdouble-promotion -Wformat=2 -Wmisleading-indentation`.

Every session ends with an entry in [`docs/WORKLOG.md`](docs/WORKLOG.md);
commit messages reference the endpoint or component being changed and
the design doc that governs it.

See [`CLAUDE.md`](CLAUDE.md) for the full workflow rules.

---

## Out of scope (post-v1.x)

The cores-only provenance scope was a deliberate decision; live-process
provenance is the largest deferred item and is tracked as a major post-V1
milestone in [`docs/03-ldb-full-roadmap.md`](docs/03-ldb-full-roadmap.md).
Other deferrals:

- **Live-process provenance** — resume-counter + register-hash snapshot
  model + per-endpoint determinism audit. Unblocks `session.fork` and
  `session.replay` against live targets. Scheduled for v1.5.
- **`session.fork` / `session.replay`** — depend on live provenance.
- **GDB/MI second backend** — proves the `DebuggerBackend` abstraction
  doesn't quietly leak LLDB-isms. Scheduled for v1.4.
- **Embedded Python for user-authored probe callbacks** — current probes
  are C++-only. Scheduled for v1.4.
- **CLI: interactive REPL, ssh-remote daemon mode.** Scheduled for v1.4.

See [`docs/15-post-v1-plan.md`](docs/15-post-v1-plan.md) for the full
tiered breakdown of post-V1 work with dependencies and execution order.

---

## License

Apache 2.0 — see [`LICENSE`](LICENSE).

Matches the upstream LLDB/LLVM license stack; includes an explicit patent
grant. Compatible with proprietary agent embedding.

Contributors: see [`CONTRIBUTING.md`](CONTRIBUTING.md) for the workflow,
required tests, and the PR checklist.

---

## References

- [LLVM project (LLDB SBAPI)](https://github.com/llvm/llvm-project) — Apache 2.0 with LLVM exception
- [GDB 17.1](https://www.gnu.org/software/gdb/) — referenced in `docs/01-gdb-core-methodology.md`
- [nlohmann/json](https://github.com/nlohmann/json) — vendored under `third_party/nlohmann/`
- [Catch2 v3](https://github.com/catchorg/Catch2) — amalgamated under `third_party/catch2/`
