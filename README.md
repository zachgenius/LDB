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

**V1.** The protocol contract is stable; everything in the wire surface is
additive. The architectural arc — own the critical investigation path
(symbol indexing, deterministic replay, async runtime, in-target predicates)
without forking LLDB — is in place. Future work is responsive to user pull,
not a planned roadmap.

What V1 delivers end-to-end:

- **Static + cross-binary investigation.** Type layouts, symbol queries,
  string and xref hunting across a symbol index keyed by build-ID, cached
  to SQLite so warm queries are sub-millisecond.
- **Process control.** Live attach / launch / detach, core load, remote
  targets over the daemon's own GDB RSP client OR LLDB's gdb-remote, all
  through one wire surface.
- **Async non-stop runtime.** Per-thread suspend/resume, push notifications
  (`thread.event{kind:stopped}`) on a listener thread, and `vCont`-routed
  resume verbs against the own RSP transport. Phase-2 of the LLDB-backed
  non-stop integration is post-V1; the daemon-side state machine and the
  wire surface are stable.
- **Probes + tracepoints.** Auto-resuming breakpoints with structured
  capture (`probe.*`) and no-stop high-frequency observation
  (`tracepoint.*`) with rate-limit grammar (`<N>/{s,ms,us,total}`) and
  agent-expression predicates compiled from a small S-expression DSL.
- **Determinism + replay.** Per-endpoint provenance audit
  (`_provenance.deterministic`), byte-identical replay across daemon
  restarts via `session.fork` / `session.replay`, signed `.ldbpack`
  portable bundles.
- **Multi-backend.** LLDB SBAPI (default) or GDB/MI subprocess
  (`--backend=gdb`) through a single `DebuggerBackend` interface.
- **Scriptable probes + recipes.** Embedded Python callbacks for
  `lldb_breakpoint` probes; user-authored frame unwinders;
  parametric replayable RPC scripts captured from sessions.
- **Observers + perf + BPF.** Typed `/proc`, `ss`, `tcpdump`, `igmp`
  observers; `perf record/report` integration; `libbpf`-backed
  `ldb-probe-agent` for CO-RE BPF uprobes.

| | |
|---|---|
| **Validation** | `ctest` suite (100% pass on a stock Linux dev box; SKIP-gated live-attach tests run when `kernel.yama.ptrace_scope=0` or with CAP_SYS_PTRACE) plus GitHub Actions on Linux x86-64, Linux arm64, macOS arm64, and an opt-in Capstone leg |
| **Endpoints** | 100+ across target / process / thread / frame / value / memory / probe / tracepoint / predicate / agent / perf / observer / session / artifact / recipe / correlate |
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
│  • Probe + tracepoint orchestrator with          │
│    agent-expression predicate evaluation         │
│  • Symbol index (SQLite, build-ID keyed)         │
│  • Non-stop runtime + listener thread for        │
│    push-notification stop events                 │
│  • Own GDB RSP transport (parallel to LLDB's     │
│    gdb-remote plugin)                            │
│  • Typed observer plugins (/proc, ss, tcpdump,   │
│    igmp; allowlisted exec escape hatch)          │
│  • DebuggerBackend abstraction (LLDB / GDB-MI)   │
└──────────────────────────────────────────────────┘
       ↓ liblldb (SBAPI)        ↓ ssh         ↓ TCP
  local target / core      remote target host:    gdb-remote target
                            • lldb-server         (lldb-server,
                            • bpftrace             gdbserver, qemu,
                            • observer probes      OpenOCD, rr)
```

The daemon runs on the operator's machine. Remote targets are reached over
SSH plus `lldb-server platform`, OR directly over TCP to any gdb-remote
server via the own RSP client (`target.connect_remote_rsp`).

---

## Capability matrix

| Surface | Endpoints | Replaces |
|---|---|---|
| **Static analysis** | `target.open`, `target.close`, `target.list`, `target.label`, `module.list`, `type.layout`, `symbol.find`, `string.list`, `string.xref`, `disasm.range`, `disasm.function`, `xref.addr`, `static.globals_of_type` | `pahole`, `nm`, `readelf`, `strings`, `objdump` |
| **Cross-target correlation** | `correlate.types`, `correlate.symbols`, `correlate.strings` (build-ID keyed, SQLite-cached) | hand-rolled diffing between two binaries / cores |
| **Process control** | `target.attach`, `target.connect_remote`, `target.connect_remote_ssh`, `target.connect_remote_rsp`, `target.load_core`, `target.create_empty`, `process.launch`, `process.state`, `process.continue`, `process.kill`, `process.detach`, `process.save_core`, `process.step`, `process.reverse_continue`, `process.reverse_step` | `gdb`, `lldb`, `rr` |
| **Thread / frame / value** | `thread.list`, `thread.list_state`, `thread.frames`, `thread.continue`, `thread.suspend`, `thread.reverse_step`, `frame.locals`, `frame.args`, `frame.registers`, `value.eval`, `value.read` | `gdb` `bt`/`info`/`print`, `lldb` `frame` family |
| **Non-stop events** | `thread.event{kind:stopped}` push notifications via JSON-RPC §4.1 framing on the same stdio channel | replaces polling `process.state` after `process.continue` |
| **Memory** | `mem.read`, `mem.read_cstr`, `mem.regions`, `mem.search`, `mem.dump_artifact` | `gdb` `x`/`find`, `/proc/<pid>/mem` scraping |
| **Probes** | `probe.create` (kind: `lldb_breakpoint`, `uprobe_bpf`, `agent`), `probe.events`, `probe.list`, `probe.enable`, `probe.disable`, `probe.delete` | `strace`, `bpftrace`, hand-rolled tracepoints |
| **Tracepoints (no-stop)** | `tracepoint.create`, `tracepoint.list`, `tracepoint.enable`, `tracepoint.disable`, `tracepoint.delete`, `tracepoint.frames` — agent-expression predicate + rate-limit grammar (`<N>/{s,ms,us,total}`) | `bpftrace`-style filtered observation, but with the same wire-typed schema as LDB probes |
| **Agent expressions** | `predicate.compile({source})` — S-expression DSL compiled to a stack-based bytecode VM, used by probes and tracepoints for cheap per-hit filtering | hand-rolling C++ callbacks per filter |
| **Typed observers** | `observer.proc.fds`, `observer.proc.maps`, `observer.proc.status`, `observer.net.sockets`, `observer.net.tcpdump`, `observer.net.igmp`, `observer.exec` (allowlisted) | `lsof`, `ss`, `tcpdump`, `cat /proc/...`, `run_host_command` |
| **Sessions** | `session.create`, `session.attach`, `session.detach`, `session.list`, `session.info`, `session.diff`, `session.targets`, `session.export`, `session.import`, `session.fork`, `session.replay` | sqlite-backed RPC log; `.ldbpack` portable bundles; deterministic-byte replay across daemon restarts |
| **Artifacts** | `artifact.put`, `artifact.get`, `artifact.list`, `artifact.tag`, `artifact.delete`, `artifact.relate`, `artifact.relations`, `artifact.unrelate`, `artifact.export`, `artifact.import` | build-ID-keyed store with typed relations, queryable across sessions |
| **Recipes** | `recipe.create`, `recipe.from_session`, `recipe.list`, `recipe.get`, `recipe.run`, `recipe.delete`, `recipe.lint`, `recipe.reload` — `format=python-v1` recipes run user-authored Python callbacks against the dispatcher | parametric replayable RPC scripts captured from sessions |
| **Perf** | `perf.record`, `perf.report`, `perf.cancel` | `perf` CLI invocations |
| **Probe agent** | `agent.hello` + `ldb-probe-agent` binary speaking length-prefixed JSON over libbpf for CO-RE BPF uprobes | bpftrace shellout |

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
| SQLite | 3.40+ | Sessions, artifact index, symbol index |
| zlib | system | `.ldbpack` gzip compression |
| libsodium | 1.0.18+ | `.ldbpack` ed25519 signing (hard dep) |
| Python | 3.11+ | Smoke tests and `tools/ldb/ldb` client |
| `python3-embed` | 3.11+ | Optional; embedded CPython for `format=python-v1` recipes + `process.set_python_unwinder`. Auto-detected via pkg-config; `cmake -DLDB_ENABLE_PYTHON=OFF` opts out |
| libbpf | 1.0+ | Optional; required to build `ldb-probe-agent`. Auto-detected via pkg-config; `cmake -DLDB_ENABLE_BPF_AGENT=OFF` opts out. Live BPF programs additionally need `clang` + `bpftool` |
| Ninja | 1.10+ | Optional; default build generator |
| `bpftrace` | 0.18+ | Optional; required for `kind: "uprobe_bpf"` probes |
| `linux-tools-generic` | match kernel | Optional; provides `perf` for `perf.record` / `perf.report` |
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
  ninja-build cmake build-essential pkg-config \
  liblldb-dev lldb \
  libsqlite3-dev zlib1g-dev libsodium-dev \
  python3 python3-dev \
  libbpf-dev clang bpftool \
  bpftrace tcpdump linux-tools-generic \
  openssh-server openssh-client \
  rr
```

macOS (Apple Silicon / Homebrew):

```bash
brew install llvm ninja cmake sqlite libsodium python@3.12
# libbpf, bpftool, perf, rr, bpftrace are Linux-only — the libbpf-agent
# and perf-integration build paths are auto-disabled on macOS.
```

Optional Capstone backend:

```bash
brew install capstone pkgconf
```

`bpftrace`, `tcpdump`, `lldb-server`, `openssh-server`, `rr`, `perf`,
`libbpf`, `clang+bpftool`, and `python3-embed` are only needed for
their respective live probe / observer / remote-connection /
reverse-execution / sampling / agent / scripted-recipe paths; the
static analysis and core-backed paths build without them. `libsodium`
is a hard build dep (used by `.ldbpack` ed25519 signing). `rr` is
Linux x86-64 / arm64 only — macOS has no equivalent. The `ldb-probe-
agent` binary is only built when libbpf is present; embedded CO-RE BPF
programs additionally require `clang` and `bpftool` (from
`linux-tools-generic` or `bpfcc-tools`).

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

The V1 support matrix is intentionally narrow:

| Platform | Status | Notes |
|---|---:|---|
| Linux x86-64 | Supported | Primary CI leg; apt LLDB 18 in CI, local LLVM roots supported |
| Linux arm64 | Validation | CI validates behavior; source-only, no separate arm64 packaging |
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

# Compile an agent-expression predicate (returns bytecode_b64)
./tools/ldb/ldb predicate.compile source='(eq (reg "rax") (const 42))'

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

Notifications (JSON-RPC 2.0 §4.1, no `id`):
```json
{ "jsonrpc": "2.0", "method": "thread.event",
  "params": { "seq": 42, "target_id": 1, "tid": 1234,
              "kind": "stopped", "reason": "trace", "pc": 0x7f8c123456 } }
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
| `-32001` | Not implemented (e.g. `thread.suspend` on LLDB-backed targets pre-SetAsync flip) |
| `-32002` | Bad state (store / allowlist not configured) |
| `-32003` | Forbidden (operator allowlist denied the argv) |
| `-32011` | Protocol version mismatch |

---

## Known limitations

These are acceptable in V1 and part of the public contract:

- LLDB remains the default backend and owns target, process, and DWARF semantics.
- Capstone is opt-in and affects only `disasm.range` and `disasm.function`.
- `xref.addr` and `string.xref` intentionally keep LLDB disassembly/comment semantics.
- `thread.suspend` on LLDB-backed targets returns `-32001` — requires the
  pending `SBDebugger::SetAsync(true)` flip + LLDB-side listener integration.
  RSP-backed targets (`target.connect_remote_rsp`) honour `thread.suspend`
  via `vCont;t` and have full non-stop semantics today.
- Tracepoints run daemon-side in V1. The `QTDP` / `QTStart` / `QTFrame`
  in-target collection path is a follow-up; the bytecode VM and wire surface
  are stable so the migration is non-breaking.
- The rate-limit grammar is fixed-pivot, not true sliding window — worst-
  case burst is `2 × cap` events in `window + ε`. Token-bucket sliding is
  a follow-up; agents needing a hard bound should over-budget by 2× or use
  a tighter window.
- Reverse execution is supported only against rr-backed targets (reached via
  `target.connect_remote rr://`); `process.reverse_step` / `thread.reverse_step`
  accept all four kinds (`in`/`over`/`out`/`insn`) — `in`/`over`/`out` use a
  bounded `bs`-loop emulation with source-line + frame-depth termination.
- Linux-only observers and BPF/tcpdump paths SKIP on macOS or unprivileged runners.
- macOS local-process tests depend on Apple's signed `debugserver`.

---

## Release artifact policy

V1 releases are **source-only**: semantic-version tags plus release notes,
with no promise of prebuilt binary tarballs. Binary packaging can move to a
later milestone without changing the wire contract.

---

## Project structure

```
include/ldb/         Public headers
src/main.cpp         Entry point
src/protocol/        JSON-RPC framing, CBOR transport, view, cost, provenance, notifications
src/daemon/          Stdio loop, dispatcher, describe.endpoints catalog
src/backend/         DebuggerBackend interface, LldbBackend, GdbMiBackend
src/store/           Artifact store, session store, .ldbpack pack/unpack
src/probes/          Probe orchestrator, lldb_breakpoint + bpftrace engines, rate-limit grammar
src/observers/       Typed proc/net observers, exec allowlist
src/transport/       SSH (exec, port-forward, tunneled-cmd), local exec, streaming exec, own GDB RSP client
src/index/           SQLite-backed symbol index
src/runtime/         Non-stop runtime + listener thread
src/agent_expr/      Agent-expression bytecode VM + S-expression compiler
src/util/            sha256, base64, log
src/dap/             ldb-dap shim (Debug Adapter Protocol)
tools/ldb/           Python CLI client
tests/smoke/         End-to-end tests via ldbd subprocess
tests/unit/          Catch2 unit tests
tests/fixtures/      Test binaries + canned text fixtures
third_party/         Vendored deps (nlohmann/json, Catch2 amalgamated)
docs/                Design docs and engineering worklog
```

---

## Documentation

| File | Purpose |
|---|---|
| [`docs/00-README.md`](docs/00-README.md) | Architecture overview, design decisions, reading order |
| [`docs/01-gdb-core-methodology.md`](docs/01-gdb-core-methodology.md) | Analysis of GDB's architecture — foundational reading |
| [`docs/02-ldb-mvp-plan.md`](docs/02-ldb-mvp-plan.md) | Protocol spec, RPC surface, reference workflow |
| [`docs/03-ldb-full-roadmap.md`](docs/03-ldb-full-roadmap.md) | Progressive replacement of LLDB components |
| [`docs/06-ci.md`](docs/06-ci.md) | What CI runs, what SKIPs on the runner, how to reproduce locally |
| [`docs/07-dap-shim.md`](docs/07-dap-shim.md) | `ldb-dap` Debug Adapter Protocol shim |
| [`docs/13-v1-readiness.md`](docs/13-v1-readiness.md) | V1 release gates, supported matrix, validation commands |
| [`docs/14-pack-signing.md`](docs/14-pack-signing.md) | `.ldbpack` ed25519 signing |
| [`docs/15-post-v1-plan.md`](docs/15-post-v1-plan.md) | Tiered breakdown of post-V1 work with dependency graph |
| [`docs/16-reverse-exec.md`](docs/16-reverse-exec.md) | Reverse-execution endpoints over rr |
| [`docs/23-symbol-index.md`](docs/23-symbol-index.md) | SQLite-backed cross-binary symbol index |
| [`docs/24-session-fork-replay.md`](docs/24-session-fork-replay.md) | `session.fork` / `session.replay` design |
| [`docs/25-own-rsp-client.md`](docs/25-own-rsp-client.md) | Own GDB Remote Serial Protocol transport |
| [`docs/26-nonstop-runtime.md`](docs/26-nonstop-runtime.md) | Per-thread state machine + push notifications |
| [`docs/27-nonstop-listener.md`](docs/27-nonstop-listener.md) | Listener thread + stream-locked notifications |
| [`docs/28-agent-expressions.md`](docs/28-agent-expressions.md) | Agent-expression bytecode VM (GDB-compatible subset) |
| [`docs/29-predicate-compiler.md`](docs/29-predicate-compiler.md) | S-expression DSL → bytecode compiler |
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

## License

Apache 2.0 — see [`LICENSE`](LICENSE).

Matches the upstream LLDB/LLVM license stack; includes an explicit patent
grant. Compatible with proprietary agent embedding.

Contributors: see [`CONTRIBUTING.md`](CONTRIBUTING.md) for the workflow,
required tests, and the PR checklist.

---

## References

- [LLVM project (LLDB SBAPI)](https://github.com/llvm/llvm-project) — Apache 2.0 with LLVM exception
- [GDB](https://www.gnu.org/software/gdb/) — referenced in `docs/01-gdb-core-methodology.md`
- [GDB Agent Expressions](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Agent-Expressions.html) — the bytecode subset LDB's `predicate.compile` emits
- [nlohmann/json](https://github.com/nlohmann/json) — vendored under `third_party/nlohmann/`
- [Catch2 v3](https://github.com/catchorg/Catch2) — amalgamated under `third_party/catch2/`
