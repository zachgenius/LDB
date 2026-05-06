# LDB

LLM/agent-first universal debugger. A C++17/20 daemon (`ldbd`) wrapping LLDB
SBAPI as the v1 backend, exposing a schema-typed JSON-RPC + CBOR protocol that
collapses `gdb` + `pahole` + `objdump` + `strings` + `strace` + `tcpdump` +
`/proc` + scratch shell scripts into a single surface an LLM can drive
autonomously.

It is *not* a GDB clone. It is a GDB-class tool with a different primary user:
an LLM that wants structured, deterministic, paginated, cost-aware answers,
and a knowledge graph that survives across sessions.

## Status

**v0.1 (MVP)** — feature-complete against the
[reference workflow](docs/02-ldb-mvp-plan.md#5-the-reference-workflow-as-rpc-trace).
65 endpoints across target/process/thread/frame/value/memory/probe/observer/
session/artifact, two probe engines (LLDB breakpoint + bpftrace BPF), JSON +
CBOR transports, full JSON Schema in `describe.endpoints`, cost-preview and
cores-only provenance metadata on every response, portable `.ldbpack`
session/artifact bundles, and a thin Python CLI (`tools/ldb/ldb`).

## Quickstart

```bash
# 1. Build
cmake -B build -G Ninja \
  -DLDB_LLDB_ROOT=/path/to/llvm-prefix \
  -DCMAKE_PREFIX_PATH=/usr/local
cmake --build build

# 2. Test
ctest --test-dir build --output-on-failure

# 3. Drive via the CLI
build/bin/ldbd --version
./tools/ldb/ldb hello
./tools/ldb/ldb describe.endpoints --view fields=method,summary
./tools/ldb/ldb target.open path=./build/bin/fixtures/structs
./tools/ldb/ldb type.layout target_id=1 name=dxp_login_frame
```

The CLI is schema-driven: `--help` lists every available subcommand by reading
`describe.endpoints` once at startup, and `<method> --help` prints that
endpoint's params/returns schema.

## Documentation

| File | Purpose |
|---|---|
| [`docs/00-README.md`](docs/00-README.md) | Architecture overview, design decisions |
| [`docs/01-gdb-core-methodology.md`](docs/01-gdb-core-methodology.md) | Foundational analysis of GDB 17.1's architecture |
| [`docs/02-ldb-mvp-plan.md`](docs/02-ldb-mvp-plan.md) | The 8–10 week MVP plan, RPC surface, milestones |
| [`docs/03-ldb-full-roadmap.md`](docs/03-ldb-full-roadmap.md) | Trajectory beyond MVP — progressive replacement of LLDB components |
| [`docs/WORKLOG.md`](docs/WORKLOG.md) | Engineering journal, newest entries on top |

## License

To be decided. LLDB is Apache 2.0 with LLVM exception, so an LDB built atop
it is unencumbered. GPLv3 is *not* required and would foreclose embedding
LLDB-derived code into proprietary clients — that option is kept open.
