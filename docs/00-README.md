# LDB — an LLM/Agent-first universal debugger

LDB is a debugger built for LLM agents and reverse engineers, not for humans typing at a REPL. It collapses the classical "live debugger + core-dump analyzer + binary investigation kit" workflow — `gdb` + `pahole` + `objdump` + `strings` + `strace` + `tcpdump` + `/proc` + scratch shell scripts — into a single schema-typed protocol an agent can drive autonomously.

It is *not* a GDB clone. It is a GDB-class tool with a different primary user: an LLM that wants structured, deterministic, paginated, cost-aware answers, and a knowledge graph that survives across sessions.

## Status

Pre-v0.1. Design phase. The four documents in this folder define the work.

## Documents

| File | Purpose |
|---|---|
| [`01-gdb-core-methodology.md`](./01-gdb-core-methodology.md) | Deep technical analysis of GDB 17.1's architecture. The 10 cross-cutting methodologies that define a real debugger, evidenced from `/Users/zach/Downloads/gdb-17.1`. Foundational reading. |
| [`02-ldb-mvp-plan.md`](./02-ldb-mvp-plan.md) | The 8–10 week MVP. C++17/20 daemon (`ldbd`), LLDB SBAPI as backend, schema-first JSON-RPC + CBOR protocol, build-ID-keyed artifact store, sessions, probes, typed observers. Includes the full RPC surface and the reference workflow that gates "MVP done." |
| [`03-ldb-full-roadmap.md`](./03-ldb-full-roadmap.md) | The trajectory beyond MVP: progressive replacement of LLDB components as measurement justifies, never a from-scratch rewrite. Three parallel tracks (coverage, power features, LLM differentiators). Process for tracking GDB and LLDB upstream. |
| [`12-capstone-disasm.md`](./12-capstone-disasm.md) | Opt-in Capstone disassembly backend behavior, fallback rules, supported architectures, and hello capability reporting. |

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

To be decided. LLDB is Apache 2.0 with LLVM exception, so an LDB built atop it is unencumbered. GPLv3 is *not* required and would foreclose embedding LLDB-derived code into proprietary clients — keep that option open.
