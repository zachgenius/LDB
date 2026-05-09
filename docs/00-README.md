# LDB — an LLM/Agent-first universal debugger

LDB is a debugger built for LLM agents and reverse engineers, not for humans typing at a REPL. It collapses the classical "live debugger + core-dump analyzer + binary investigation kit" workflow — `gdb` + `pahole` + `objdump` + `strings` + `strace` + `tcpdump` + `/proc` + scratch shell scripts — into a single schema-typed protocol an agent can drive autonomously.

It is *not* a GDB clone. It is a GDB-class tool with a different primary user: an LLM that wants structured, deterministic, paginated, cost-aware answers, and a knowledge graph that survives across sessions.

## Status

V1 hardening complete. `master` is the V1 release candidate; all CI legs green.
See [`13-v1-readiness.md`](./13-v1-readiness.md) for the gate checklist.

## Documents

| File | Purpose |
|---|---|
| [`01-gdb-core-methodology.md`](./01-gdb-core-methodology.md) | Deep technical analysis of GDB 17.1's architecture — the 10 cross-cutting methodologies that define a real debugger. Foundational reading. |
| [`02-ldb-mvp-plan.md`](./02-ldb-mvp-plan.md) | The MVP plan: C++17/20 daemon, LLDB SBAPI, JSON-RPC + CBOR, artifact store, sessions, probes, observers. Full RPC surface spec. |
| [`03-ldb-full-roadmap.md`](./03-ldb-full-roadmap.md) | Post-MVP trajectory: progressive LLDB component replacement, three parallel tracks, upstream tracking strategy. |
| [`04-determinism-audit.md`](./04-determinism-audit.md) | Live-provenance determinism audit — per-endpoint analysis of what breaks byte-identity when lifting snapshot model to live targets. |
| [`05-protocol-versioning.md`](./05-protocol-versioning.md) | Wire-shape freeze rules, semver policy, backward-compatibility contract for the JSON-RPC protocol. |
| [`06-ci.md`](./06-ci.md) | CI matrix: jobs, timeouts, dependency setup for Linux x86-64, Linux arm64, macOS arm64, and Capstone opt-in legs. |
| [`07-dap-shim.md`](./07-dap-shim.md) | DAP shim architecture: how `ldbd` translates Debug Adapter Protocol into LDB JSON-RPC. |
| [`08-probe-recipes.md`](./08-probe-recipes.md) | Probe recipe design: named, parameterized, replayable session traces promoted to stored recipes. |
| [`09-artifact-knowledge-graph.md`](./09-artifact-knowledge-graph.md) | Artifact knowledge graph: typed relation model, traversal API, and schema. |
| [`11-non-stop.md`](./11-non-stop.md) | Non-stop / per-thread state model: protocol surface design and sync-backed V1 limitations. |
| [`12-capstone-disasm.md`](./12-capstone-disasm.md) | Opt-in Capstone disassembly backend: fallback rules, supported architectures, hello capability reporting. |
| [`13-v1-readiness.md`](./13-v1-readiness.md) | V1 release gates: supported matrix, validation commands, known limitations, cut criteria. All gates green. |

## Architecture in one diagram

```
┌──────────────────────────────────────────────────┐
│  LLM agent host  /  human via ldb CLI            │
└──────────────────────────────────────────────────┘
                ↕  CBOR (binary) | JSON (compact/tabular)
┌──────────────────────────────────────────────────┐
│  ldbd  — C++17/20 daemon (operator host)         │
│  • Schema-first JSON-RPC server                  │
│  • Sessions (sqlite WAL log, replayable)         │
│  • Artifacts (build-ID keyed, .ldbpack portable) │
│  • View descriptors (projection / pagination /   │
│    summary / cost preview)                       │
│  • Probe orchestrator (lldb-bp + uprobe-bpf)     │
│  • Typed observer plugins (/proc, ss, tcpdump)   │
│  • Embedded Python (extension scripts only)      │
│  • DebuggerBackend abstraction                   │
└──────────────────────────────────────────────────┘
       ↓ liblldb (SBAPI)              ↓ ssh
  local target / core            remote target host:
                                   • lldb-server platform
                                   • ldb-probe-agent (opt.)
                                   • observer probes
```

## Core design decisions (links to detail)

- **Wrapper, not rewrite.** V1 wraps LLDB. Components get owned only when measured pain plus an architectural reason justify it. No "V2 from scratch" milestone exists. — `03`
- **C++17/20 daemon, not Python.** Python is for user extensions only. Probe callbacks, protocol, sessions, artifacts all live in C++. — `02`
- **LLDB over GDB.** Apache 2.0 license, in-process SBAPI, Clang-based expression eval, broader OS support. GDB stays as a future secondary backend. — context in `01` and `03`
- **Schema-first protocol.** Every endpoint has a JSON Schema in `describe.endpoints`. Clients can generate typed bindings; agents don't hardcode field names. — `02 §3, §4.8`
- **CBOR on the wire, smart JSON for LLMs.** Two surfaces, two formats. The bigger token-saving lever is *view descriptors*, not encoding choice. — `02 §3`
- **Build-ID-keyed, portable artifact store.** What you extract today is queryable next week. Sharable across machines. — `02 §8`
- **Local daemon, remote `lldb-server platform`.** Don't grow attack surface on the target. — `02 §9`
- **Two probe engines, one event shape.** LLDB breakpoints for low-rate / app-level. eBPF/uprobe for high-rate / syscall. Same JSON event shape; the agent picks the kind. — `02 §7`
- **Typed observers, not generic shell.** No `run_host_command` foot-gun. — `02 §4.6`
- **Provenance and determinism are tested in CI.** Same `(method, params, snapshot)` ⇒ byte-identical output. **MVP scope: cores only** (snapshot = SHA-256 of core file). Live-process provenance is a major post-MVP milestone. — `02 §3.5`, `03 §4`

## Reading order

1. `01-gdb-core-methodology.md` — what a debugger actually *is*, evidenced from GDB source.
2. `02-ldb-mvp-plan.md` — what we're building first.
3. `03-ldb-full-roadmap.md` — where it goes.

## Source dependencies

- GDB 17.1 source: `/Users/zach/Downloads/gdb-17.1` (analysis reference; not linked).
- LLVM/LLDB 22.1.4 source: `/Users/zach/Downloads/llvm-project-llvmorg-22.1.4` (linked as `liblldb` for V1).

## License

Apache 2.0 — see [`LICENSE`](../LICENSE) at the repo root.
