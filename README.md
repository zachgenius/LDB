# LDB

[![CI](https://github.com/zachgenius/LDB/actions/workflows/ci.yml/badge.svg)](https://github.com/zachgenius/LDB/actions/workflows/ci.yml)

**An LLM/agent-first universal debugger.**

LDB collapses the classical "live debugger + core analyzer + binary
investigation kit" workflow — `gdb`, `pahole`, `objdump`, `strings`,
`strace`, `tcpdump`, `/proc`, scratch shell scripts — into a single
schema-typed JSON-RPC protocol an agent can drive autonomously, with
typed responses, deterministic replay, cost-aware metadata, and
portable investigation bundles.

It is not a GDB clone. It is a GDB-class tool with a different primary
user: an LLM that wants typed, paginated, cost-budgeted answers, and a
knowledge graph that survives across sessions.

**If you don't know how to configure this project, just simply let your LLM agent to check it and set it up**

---

## Status — V1

The protocol contract is stable; everything in the wire surface is
additive. The architectural arc — own the critical investigation path
without forking LLDB — is in place.

| | |
|---|---|
| **Endpoints** | 100+ across `target`/`process`/`thread`/`frame`/`value`/`memory`/`probe`/`tracepoint`/`predicate`/`session`/`artifact`/`recipe`/`correlate`/`observer`/`perf`/`agent` |
| **Wire formats** | Line-delimited JSON (default); length-prefixed CBOR (`--format=cbor`) |
| **Schema** | JSON Schema draft 2020-12 for every endpoint via `describe.endpoints` |
| **Backends** | LLDB SBAPI (default) and GDB/MI subprocess (`--backend=gdb`) behind one `DebuggerBackend` interface |
| **Transports** | Local liblldb, SSH-tunneled `lldb-server platform`, native GDB-RSP TCP client |
| **Validation** | CI on Linux x86-64, Linux arm64, macOS arm64, plus an opt-in Capstone leg |

---

## Architecture

```
┌──────────────────────────────────────────────────┐
│  LLM agent host  /  human via ldb CLI            │
└──────────────────────────────────────────────────┘
                ↕  JSON (line-delim) | CBOR (len-prefix)
┌──────────────────────────────────────────────────┐
│  ldbd  — C++20 daemon                            │
│  • Schema-first JSON-RPC over stdio              │
│  • Sessions (sqlite WAL log, replayable)         │
│  • Artifacts (build-ID keyed, portable bundles)  │
│  • Symbol index (SQLite, cross-binary)           │
│  • Probe + tracepoint orchestrator               │
│  • Agent-expression bytecode VM + S-expr DSL     │
│  • Non-stop runtime + listener push events       │
│  • Own GDB-RSP transport (alongside LLDB's)      │
│  • Typed observers (/proc, ss, tcpdump, igmp)    │
│  • DebuggerBackend abstraction (LLDB / GDB-MI)   │
└──────────────────────────────────────────────────┘
       ↓ liblldb (SBAPI)      ↓ ssh          ↓ TCP
  local target / core    remote target    gdb-remote target
                          host             (lldb-server,
                                            gdbserver, qemu,
                                            OpenOCD, rr)
```

Every successful response carries `_cost: {bytes, items?, tokens_est}` +
`_provenance: {snapshot, deterministic}`. Every endpoint accepts a
`view` descriptor (`fields`/`limit`/`offset`/`summary`) for
token-budget control.

The full endpoint catalog is in `describe.endpoints`. See the
documentation index below for design notes.

---

## Requirements

| Component | Notes |
|---|---|
| C++ compiler (GCC 13+ / Clang 16+) | C++20 |
| CMake 3.20+, Ninja | Ninja generator recommended |
| LLDB / liblldb 18+ | 22.1.x verified |
| SQLite 3.40+, zlib, libsodium 1.0.18+ | Hard deps |
| Python 3.11+ | Smoke tests + `tools/ldb/ldb` client |
| `python3-embed` 3.11+ *(optional)* | Embedded Python recipes + unwinders. `cmake -DLDB_ENABLE_PYTHON=OFF` opts out |
| `libbpf` 1.0+ + `clang` + `bpftool` *(optional)* | Builds `ldb-probe-agent`. `cmake -DLDB_ENABLE_BPF_AGENT=OFF` opts out |
| `bpftrace`, `tcpdump`, `perf`, `rr`, `lldb-server`, `openssh-server` *(optional)* | Runtime deps for matching live paths |

Capstone disasm is opt-in via `cmake -DLDB_ENABLE_CAPSTONE=ON`.

On Linux, attach-style debugging needs `kernel.yama.ptrace_scope=0` or
CAP_SYS_PTRACE. `rr` needs `kernel.perf_event_paranoid <= 1`. macOS
local-process tests depend on Apple's signed `debugserver` (Xcode CLT).

---

## Install + build

Linux (Ubuntu 24.04-class):

```bash
sudo apt-get install -y \
  ninja-build cmake build-essential pkg-config \
  liblldb-dev lldb \
  libsqlite3-dev zlib1g-dev libsodium-dev \
  python3 python3-dev \
  libbpf-dev clang bpftool \
  bpftrace tcpdump linux-tools-generic \
  openssh-server openssh-client rr
```

macOS (Apple Silicon / Homebrew):

```bash
brew install llvm ninja cmake sqlite libsodium python@3.12
# libbpf / bpftool / perf / rr / bpftrace are Linux-only and auto-skip
```

Build:

```bash
cmake -B build -G Ninja -DLDB_LLDB_ROOT=/path/to/llvm-prefix
cmake --build build
ctest --test-dir build --output-on-failure
build/bin/ldbd --version
```

`LDB_LLDB_ROOT` points at a prefix containing `include/lldb/API/` and
`lib/liblldb.{so,dylib}` — typically `/opt/homebrew/opt/llvm` (brew),
`/usr/lib/llvm-NN` (apt), or the extracted directory from
`releases.llvm.org`.

---

## Supported platforms

| Platform | Status |
|---|---|
| Linux x86-64 | Supported — primary CI |
| Linux arm64 | Validated in CI; source-only |
| macOS arm64 | Supported — Homebrew LLVM + Apple `debugserver` |
| Windows | Out of scope |
| FreeBSD | Out of scope |

---

## Quickstart

```bash
# Server identity + catalog
./tools/ldb/ldb hello
./tools/ldb/ldb describe.endpoints --view fields=method,summary --view limit=20

# Static investigation
./tools/ldb/ldb target.open path=./build/bin/fixtures/structs
./tools/ldb/ldb type.layout target_id=1 name=dxp_login_frame

# Predicate pre-flight (compiles S-expression → bytecode)
./tools/ldb/ldb predicate.compile source='(eq (reg "rax") (const 42))'

# CBOR wire format
./tools/ldb/ldb --format=cbor describe.endpoints --view summary=true

# Full envelope with _cost + _provenance
./tools/ldb/ldb --raw hello
```

The `ldb` CLI spawns `ldbd` per invocation, pulls the catalog, and
synthesizes argparse subcommands from each endpoint's JSON Schema.

---

## Wire protocol

JSON-RPC 2.0 framing. Default transport is line-delimited JSON on
stdio; CBOR (RFC 8949) is selectable per-process via `--format=cbor`.

Request:
```json
{ "id": "r7", "jsonrpc": "2.0", "method": "type.layout",
  "params": { "target_id": 1, "name": "dxp_login_frame" } }
```

Response (success):
```json
{ "id": "r7", "ok": true,
  "data": { "name": "dxp_login_frame", "byte_size": 128, "fields": [...] },
  "_cost":       { "bytes": 1842, "items": 14, "tokens_est": 461 },
  "_provenance": { "snapshot": "core:e3b0c44...", "deterministic": true } }
```

Notification (JSON-RPC §4.1, no `id` — used for non-stop runtime
push events):
```json
{ "jsonrpc": "2.0", "method": "thread.event",
  "params": { "seq": 42, "target_id": 1, "tid": 1234,
              "kind": "stopped", "reason": "trace", "pc": 140281234567 } }
```

Typed error codes (V1 surface):

| Code | Meaning |
|---|---|
| `-32600` | Invalid request |
| `-32601` | Method not found |
| `-32602` | Invalid params |
| `-32700` | Parse / framing error |
| `-32000` | Backend error |
| `-32001` | Not implemented |
| `-32002` | Bad state |
| `-32003` | Forbidden (allowlist) |
| `-32011` | Protocol version mismatch |

---

## Known limitations

- LLDB owns target, process, and DWARF semantics by default.
- Capstone is opt-in and affects only `disasm.range` / `disasm.function`.
- Reverse execution requires an rr-backed target (`target.connect_remote rr://`).
- Tracepoints run daemon-side; in-target collection via `QTDP`/`QTFrame`
  has wire vocabulary in place but orchestrator integration is post-V1.
- The agent-expression VM is signed-int64 only; agents needing unsigned
  comparisons must mask explicitly.
- Linux-only observers (BPF, tcpdump, perf) SKIP on macOS.

---

## Project structure

```
include/ldb/    Public headers
src/main.cpp    Entry point
src/protocol/   JSON-RPC framing, CBOR, view, cost, provenance, notifications
src/daemon/     Stdio loop, dispatcher, describe.endpoints catalog
src/backend/    DebuggerBackend interface, LLDB, GDB-MI
src/store/      Artifact store, session store, .ldbpack
src/probes/     Probe + tracepoint orchestrator, rate-limit grammar
src/observers/  Typed proc / net observers
src/transport/  SSH, local exec, own GDB-RSP client
src/index/      Symbol index (SQLite)
src/runtime/    Non-stop runtime + listener
src/agent_expr/ Bytecode VM + S-expression compiler
src/dap/        ldb-dap shim (Debug Adapter Protocol)
tools/ldb/      Python CLI client
tests/{unit,smoke}/  Catch2 unit tests + JSON-RPC subprocess tests
docs/           Design docs + WORKLOG (see docs/00-README.md)
```

---

## Documentation

Start with [`docs/00-README.md`](docs/00-README.md) for the
architecture overview + reading order. Subsystem design notes live
in numbered files under `docs/`; the engineering journal is
[`docs/WORKLOG.md`](docs/WORKLOG.md) (newest entries on top).
Development workflow rules are in [`CLAUDE.md`](CLAUDE.md).

Notable design docs:

- `docs/02-ldb-mvp-plan.md` — protocol spec + reference workflow
- `docs/04-determinism-audit.md` — per-endpoint provenance contract
- `docs/14-pack-signing.md` — `.ldbpack` ed25519 signing
- `docs/16-reverse-exec.md` — rr-backed reverse execution
- `docs/23-symbol-index.md` — SQLite cross-binary symbol cache
- `docs/24-session-fork-replay.md` — `session.fork` / `session.replay`
- `docs/25-own-rsp-client.md` — native GDB-RSP transport
- `docs/26-nonstop-runtime.md` + `docs/27-nonstop-listener.md` — non-stop runtime
- `docs/28-agent-expressions.md` + `docs/29-predicate-compiler.md` — agent-expression VM
- `docs/30-tracepoints.md` + `docs/34-tracepoints-in-target.md` — tracepoints
- `docs/31`–`docs/33` — deferred items (own ptrace, hardware tracing, criu)

---

## License

Apache 2.0 — see [`LICENSE`](LICENSE). Matches the upstream LLDB/LLVM
license stack with explicit patent grant; compatible with proprietary
agent embedding.

Contributors: [`CONTRIBUTING.md`](CONTRIBUTING.md) for workflow, tests,
PR checklist.

---

## References

- [LLVM (LLDB SBAPI)](https://github.com/llvm/llvm-project) — Apache 2.0 with LLVM exception
- [GDB Agent Expressions](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Agent-Expressions.html) — the bytecode subset `predicate.compile` emits
- [nlohmann/json](https://github.com/nlohmann/json), [Catch2 v3](https://github.com/catchorg/Catch2) — vendored under `third_party/`
