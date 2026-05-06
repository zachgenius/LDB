# LDB

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

**Version 0.1 (MVP).** Tagged `v0.1`. Feature-complete against the
[reference workflow](docs/02-ldb-mvp-plan.md#5-the-reference-workflow-as-rpc-trace)
defined in the MVP plan.

| | |
|---|---|
| **Test suite** | 35/35 passing on Pop!_OS 24.04 / Ubuntu 24.04 / GCC 13.3.0 / LLVM 22.1.5 |
| **Endpoints** | 65 across target / process / thread / frame / value / memory / probe / observer / session / artifact |
| **Wire formats** | Line-delimited JSON (default); length-prefixed CBOR (`--format=cbor`) |
| **Protocol schema** | JSON Schema draft 2020-12 for every endpoint via `describe.endpoints` |
| **Determinism** | Cores-only provenance; cross-process byte-identical replay verified in CI |

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
| **Static analysis** | `target.open`, `module.list`, `type.layout`, `type.find`, `symbol.find`, `string.list`, `string.xref`, `disasm.range`, `disasm.function`, `xref.addr` | `pahole`, `nm`, `readelf`, `strings`, `objdump` |
| **Process control** | `target.attach`, `target.connect_remote`, `target.connect_remote_ssh`, `target.load_core`, `target.create_empty`, `process.launch`, `process.state`, `process.continue`, `process.kill`, `process.detach`, `process.save_core`, `process.step` | `gdb`, `lldb` |
| **Thread / frame / value** | `thread.list`, `thread.frames`, `frame.locals`, `frame.args`, `frame.registers`, `value.eval`, `value.read` | `gdb` `bt`/`info`/`print`, `lldb` `frame` family |
| **Memory** | `mem.read`, `mem.read_cstr`, `mem.regions`, `mem.search`, `mem.dump_artifact` | `gdb` `x`/`find`, `/proc/<pid>/mem` scraping |
| **Probes** | `probe.create` (kind: `lldb_breakpoint` or `uprobe_bpf`), `probe.events`, `probe.list`, `probe.enable`, `probe.disable`, `probe.delete` | `strace`, `bpftrace`, hand-rolled tracepoints |
| **Typed observers** | `observer.proc.fds`, `observer.proc.maps`, `observer.proc.status`, `observer.net.sockets`, `observer.net.tcpdump`, `observer.net.igmp`, `observer.exec` (allowlisted) | `lsof`, `ss`, `tcpdump`, `cat /proc/...`, `run_host_command` |
| **Sessions** | `session.create`, `session.attach`, `session.detach`, `session.list`, `session.info`, `session.export`, `session.import` | sqlite-backed RPC log; `.ldbpack` portable bundles |
| **Artifacts** | `artifact.put`, `artifact.get`, `artifact.list`, `artifact.tag`, `artifact.export`, `artifact.import` | build-ID-keyed store, queryable across sessions |

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
| Python | 3.11+ | Smoke tests and `tools/ldb/ldb` client |
| Ninja | 1.10+ | Optional; default build generator |
| `bpftrace` | 0.18+ | Optional; required for `kind: "uprobe_bpf"` probes |
| `lldb-server` | from LLDB | Optional; required for `target.connect_remote*` live tests |
| `tcpdump` | system | Optional; required for `observer.net.tcpdump` (needs CAP_NET_RAW) |

LLDB's prebuilt LLVM tarballs link against `libpython3.11` for embedded
scripting; ensure that runtime is available even if you don't use embedded
Python features.

On Linux, attach-style debugging requires `kernel.yama.ptrace_scope=0` (or
appropriate capabilities) for non-child target processes.

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
code rather than prose. Codes used in the MVP:

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
| [`docs/02-ldb-mvp-plan.md`](docs/02-ldb-mvp-plan.md) | MVP plan: protocol spec, RPC surface, milestones, reference workflow |
| [`docs/03-ldb-full-roadmap.md`](docs/03-ldb-full-roadmap.md) | Post-MVP trajectory: progressive replacement of LLDB components |
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
commit messages reference the milestone (M0–M5) and endpoint or component.

See [`CLAUDE.md`](CLAUDE.md) for the full workflow rules.

---

## Out of scope (post-v0.1)

The cores-only provenance scope was a deliberate decision; live-process
provenance is the largest deferred item and is tracked as a major post-MVP
milestone in [`docs/03-ldb-full-roadmap.md`](docs/03-ldb-full-roadmap.md).
Other deferrals:

- **Live-process provenance** — resume-counter + register-hash snapshot
  model + per-endpoint determinism audit. Unblocks `session.fork` and
  `session.replay` against live targets.
- **`session.fork` / `session.replay`** — depend on live provenance.
- **`.ldbpack` signing** — operator-trust feature; meaningful once packs
  travel to untrusted hands.
- **GDB/MI second backend** — proves the `DebuggerBackend` abstraction
  doesn't quietly leak LLDB-isms.
- **Embedded Python for user-authored probe callbacks** — current probes
  are C++-only.
- **CLI: interactive REPL, ssh-remote daemon mode, session diff.**

---

## License

Undecided. LLDB is Apache 2.0 with LLVM exception, so an LDB built atop it is
unencumbered. GPLv3 is *not* required and would foreclose embedding LLDB-
derived code into proprietary clients — that option is being kept open.

---

## References

- [LLVM project (LLDB SBAPI)](https://github.com/llvm/llvm-project) — Apache 2.0 with LLVM exception
- [GDB 17.1](https://www.gnu.org/software/gdb/) — referenced in `docs/01-gdb-core-methodology.md`
- [nlohmann/json](https://github.com/nlohmann/json) — vendored under `third_party/nlohmann/`
- [Catch2 v3](https://github.com/catchorg/Catch2) — amalgamated under `third_party/catch2/`
