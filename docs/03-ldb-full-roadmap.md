# LDB Full Roadmap — Progressive Replacement Strategy

> Premise: V1 wraps LLDB and ships fast (see `02-ldb-mvp-plan.md`). Subsequent versions **own components only when measurement justifies it**, never as a rewrite. Differentiation lives in the agent surface, not in re-implementing DWARF parsers.
>
> Cadence: quarterly minor versions, monthly point releases for upstream tracking.

---

## 1. The architectural arc

```
v0.1 (MVP)         v0.5                        v1.0                     v2.0
────────────       ───────                     ──────                   ──────
agent surface      half the stack is ours      most of the stack        platform
LLDB carries       (probes, artifacts,         is ours; LLDB only       (multi-target,
the engine        sessions, BPF agent,        for expr-eval +          replay-native,
                   own indexer, own            macOS process            semantic-query
                   disasm, own RSP client)     control                  engine, IDE
                                                                        ecosystem)
        ↑                  ↑                          ↑                      ↑
        |                  |                          |                      |
        Track A: Coverage breadth (OSes, arches, formats, languages, runtimes)
        Track B: Power features (replay, non-stop, kernel, JIT, perf)
        Track C: LLM differentiators (semantic queries, multi-binary, knowledge graph)
```

Each version is the union of progress on three tracks plus opportunistic component ownership.

---

## 2. Three tracks

The roadmap is *not* a list of versions. It's three tracks running in parallel, with versions = synchronization points.

### Track A — Coverage

Make LDB work in more environments. Most of this comes from LLDB upstream + light glue work; we own the validation matrix.

| Bucket | Items | Rough timing |
|---|---|---|
| OS | Linux x86-64 (MVP), macOS arm64 (MVP parity), Linux arm64, FreeBSD, Windows/x64 | v0.2 → v1.0 |
| Arch | x86-64, arm64, riscv64, x86, ppc64le | v0.3 → v1.5 |
| Binary fmt | ELF (MVP), Mach-O (MVP), PE/COFF, WASM | v0.4 → v1.5 |
| Debug fmt | DWARF 4/5 (MVP), DWARF split, .dwo/.dwp, CTF, PDB | v0.5 → v1.5 |
| Lang modules | C/C++ (MVP), Rust (MVP+), Go, Swift, Obj-C, Ada, Fortran | LLDB-driven, validated incrementally |
| Runtimes | bare native (MVP), JIT (V8/JVM/Python/.NET), eBPF programs, WASM hosts | v0.7 → v2.0 |
| Kernel | none (MVP), Linux kgdb-over-RSP, KDP (macOS) | v1.5 → v2.0 |

Validation gate: every supported entry has a CI golden test running the reference workflow §5 of the MVP plan against a representative binary.

### Track B — Power features

Capabilities GDB has that MVP doesn't, plus the ones GDB doesn't have but should.

| Feature | Mechanism | Target |
|---|---|---|
| **Non-stop debugging** | LLDB has it for some targets; we expose it through the protocol with a per-thread state model | v0.3 |
| **Displaced stepping** | LLDB native; expose for non-stop correctness | v0.4 |
| **Reverse execution via rr** | LDB connects to `rr` as a remote target via RSP; replay is just another `target.connect_remote` URL | v0.5 |
| **Hardware tracing** | Intel PT / ARM ETM via perf or LLDB trace plugin; our probe layer treats it as a high-volume event source | v0.7 |
| **In-target conditional probes** | Compile probe predicates to GDB-compatible agent-expression bytecode; ship to gdbserver/lldb-server | v0.8 |
| **Custom unwinders** | Expose LLDB's unwinder plugin via Python ext API; agent can register a Python unwinder for async runtimes | v0.6 |
| **JIT debugging** | Implement the GDB JIT interface client-side; auto-load symbols when V8/JVM register code | v0.9 |
| **Tracepoints (no-stop collection)** | Same agent-expression bytecode but with a target-side ring buffer — collect state without halting | v1.0 |
| **Snapshot / fork-and-replay** | OS-level fork on Linux for cheap "what if" exploration; `criu` for full process snapshot | v1.0 |
| **Kernel probe injection** | eBPF/uprobes/USDT for production; integrates with the probe orchestrator | v0.6 (Linux) |
| **Performance integration** | `perf record/report` parsed into structured events; correlate with debug events | v0.8 |
| **DAP shim** | Generated automatically from `describe.endpoints` so any IDE can attach | v0.6 |

### Track C — LLM differentiators (the actual moat)

These are the features no current debugger has and no LLDB-wrapper alternative will get for free. **This is where we win.**

| Feature | Description | Target |
|---|---|---|
| **View descriptors** | Already in MVP; expanded with cost preview, diff-mode, change-only updates | v0.2 |
| **Schema-typed everything** | Every endpoint has a JSON Schema in `describe.endpoints`; clients generate typed bindings | v0.2 |
| **Provenance & determinism** | **MVP scope: cores only** (snapshot = SHA-256 of core). v0.3 lifts this to live processes — resume-counter + register-hash, audit of every endpoint for non-deterministic elements, snapshot IDs become first-class refs across the live branch too. | v0.3 |
| **Artifact knowledge graph** | Artifacts gain typed relations: "this XML is the schema parsed by `xml_parse` which is called from `init_schema` in build `<bid>`" — queryable as a graph | v0.4 |
| **Cross-binary correlation** | Same struct (by DWARF type-hash), same string, same function-fingerprint across multiple binaries — find drift between versions | v0.5 |
| **Semantic queries** | First-class operators: `heap.objects_of_type("MyClass")`, `mutex.lock_graph()`, `string.flow_to(addr)`, `thread.blockers()` | v0.5 → v1.0 |
| **Probe recipes** | Promote replayable session traces to named recipes the agent can re-issue with parameter substitution | v0.4 |
| **Cost-aware planning** | Every endpoint advertises `est_bytes`, `est_round_trips`, `requires_stopped`; the agent plans queries against these | v0.3 |
| **Diff-able sessions** | `session.diff(s1, s2)` shows what changed between two investigations of the same binary | v0.6 |
| **LLM-native pretty printing** | Type-tagged, deterministic, length-bounded output; no human-facing formatting heuristics | v0.3 |
| **Hypothesis tracking** | Agent records hypotheses as artifacts (`hypothesis.md` with confidence + evidence refs); ldbd checks them against subsequent observations and flips them to confirmed/refuted | v0.7 |
| **Multi-binary investigations** | One session can hold N targets (binary + core + live process) and join across them | v0.5 |
| **Hot-reload of pretty-printers / probe recipes** | Edit a Python extension, ldbd hot-loads without losing state | v0.4 |
| **Embedded protocol replay** | Captured wire frames + extracted schemas → auto-generated stub responder code (Python/Scapy or C); a real differentiator for the user's RE workflow | v0.8 |

Track C is the reason the project exists. If we drop a Track A or B item under pressure, fine. Track C must keep moving every release.

---

## 3. Component-ownership trajectory

The progressive-replacement plan, with measurement triggers:

| Component | Source today | Owned when | Trigger |
|---|---|---|---|
| Protocol server | ours | already | n/a |
| Session log | ours | already | n/a |
| Artifact store | ours | already | n/a |
| Capability descriptor | ours | already | n/a |
| Probe orchestrator (LLDB engine) | ours wrapping LLDB cb | already | n/a |
| Probe orchestrator (BPF engine) | ours via libbpf | v0.3 | when MVP `bpftrace` shellout proves too slow / too restricted |
| Static-xref scanner | ours on top of SBAPI | already | n/a |
| Pretty-printer engine | LLDB synthetic-children | v0.5 | when SBAPI synthetics are too slow for big containers |
| Disassembler | LLDB / LLVM-MC | **v0.5** | reduce LLVM dep weight; Capstone is sufficient for our needs |
| RSP client | LLDB's `process gdb-remote` | **v0.7** | own it for control over packet-level retries, custom q-packets, and to talk to gdbserver/QEMU/OpenOCD without LLDB |
| Symbol index | LLDB's | **v0.8** | LLDB indexes per-target; we want a *cross-binary* index keyed by build-ID with persistent on-disk store |
| DWARF reader | LLDB's | **v0.9** | use `libDebugInfoDWARF` (LLVM, but standalone) directly to decouple indexer from full LLDB |
| Linux ptrace driver | LLDB's `ProcessLinux` | **v1.0** | control over non-stop, displaced stepping, snapshot semantics, BPF integration |
| Frame unwinder | LLDB's | **v1.2** | only if we hit a runtime LLDB doesn't support; otherwise keep |
| Expression evaluator | LLDB+Clang | **never** | replicating Clang is a non-starter |
| macOS process control | LLDB's | **never** | Apple support, codesigning, debugserver — keep |
| Less-common language modules | LLDB's | **never** | Swift, Obj-C, Ada, Fortran — keep |

Each ownership transition gets its own design doc and a feature-flag rollout (`backend.disasm = lldb | capstone`, default flips after burn-in).

---

## 4. Versioning & release cadence

### Cadence

- **Quarterly minor releases** (`v0.2`, `v0.3`, …) — feature drops along the three tracks.
- **Monthly point releases** (`v0.2.x`) — bug fixes, upstream-tracking absorptions.
- **Semantic versioning on the protocol** — protocol minor version bumps are backward-compatible, major bumps require migration; agents send `protocol_min` in `hello`.
- `v1.0` = "production-ready, GDB-feature-equivalent for our supported matrix" + stable protocol.
- `v2.0` = platform-grade (multi-tenant daemon, cloud-hosted backends, IDE ecosystem) — *not* a rewrite.

### Per-release definition of done

Every minor release ships:
1. CI green on the supported coverage matrix (Track A entries × reference workflow).
2. Token-budget regression test: the reference workflow's total LLM context cost is within ±10% of previous release (regressions require justification).
3. Determinism CI green: 1000 randomized snapshot replays produce byte-identical output.
4. Upstream-tracking issues resolved (see §6).
5. Migration notes for any protocol changes.

---

## 5. Long-form roadmap (illustrative — quarterly rhythm)

> Calendar dates omitted intentionally; map to your team velocity. Use these as ordering, not deadlines.

### v0.1 — MVP
See `02-ldb-mvp-plan.md`. Reference workflow runs autonomously on Linux x86-64 + macOS arm64.

### v0.2 — Hardening
- macOS arm64 elevated from "smoke-tests pass" to first-class.
- Capability advertisement matures: every endpoint has full request/response JSON Schema; cost preview is real (not estimate).
- View descriptors: diff-mode, change-only updates.
- LLM-native pretty printing baseline (deterministic field order, type tags, length caps).
- CBOR transport stable.
- First public release.

### v0.3 — Probes & non-stop
- Native libbpf-based `ldb-probe-agent` replaces `bpftrace` shellout.
- Non-stop mode through the protocol.
- Provenance: snapshot IDs as first-class arguments to all read endpoints.
- Probe recipes (named, parameterized, replayable).
- Cost-aware planning: agent receives `requires_stopped`, `est_bytes`, `est_round_trips`.

### v0.4 — Knowledge graph
- Artifact knowledge graph: typed relations, queryable.
- Hot-reload of Python extensions.
- DAP shim auto-generated from descriptor (parity for VS Code attach + breakpoint + locals).
- Linux arm64 added to coverage matrix.

### v0.5 — Replay & multi-binary
- `rr` integration via remote target URL (`rr://...`).
- Multi-binary sessions: one session, N targets, join queries.
- Cross-binary type/function/string correlation.
- Pretty-printer engine owned (away from LLDB synthetic-children).
- Disassembler swap to Capstone (with LLVM-MC fallback feature-flag).
- Semantic queries v1: heap object enumeration, mutex graph.

### v0.6 — Custom unwinders & DAP polish
- Python unwinder API for async runtimes (Rust async, Go goroutines, Python `asyncio`).
- DAP feature-complete for VS Code, JetBrains.
- Linux kernel probes via uprobe/USDT, kernel addresses resolvable via kallsyms.
- `session.diff(s1, s2)`.

### v0.7 — Hardware tracing & RSP
- Intel PT / ARM ETM as a high-volume probe source.
- Own RSP client; talk directly to gdbserver, QEMU, OpenOCD.
- Hypothesis tracking artifact type.
- Windows / x64 added to coverage matrix (PDB read-only first).

### v0.8 — In-target predicates & perf
- Agent expressions: predicate compiler emitting GDB-compatible bytecode for in-target evaluation.
- `perf record/report` integration.
- Embedded protocol replay generator: from captured probe events + extracted schemas, emit Python/Scapy stub.
- Own symbol index (cross-binary, build-ID keyed, persistent).

### v0.9 — JIT & DWARF
- JIT interface client (V8, JVM, Python, .NET).
- Own DWARF reader (using `libDebugInfoDWARF` directly).
- Riscv64 added.

### v1.0 — Production
- Own Linux ptrace driver (deprecate LLDB's `ProcessLinux` for our targets, keep as fallback).
- Tracepoints with no-stop collection.
- Snapshot/fork via criu.
- Stable protocol v1.0.
- GDB-feature-equivalent on the supported matrix (validated against ported GDB testsuite subset).

### v1.x — Polish & ecosystem
- IDE integrations (VS Code, JetBrains, Zed, custom Claude/Codex agents).
- Pretty-printer ecosystem (std lib formatters for C++, Rust, Go).
- More languages, archs, runtimes.
- LLM-curated public probe-recipe registry.

### v2.0 — Platform
- Multi-tenant daemon (one ldbd, many concurrent sessions across users).
- Cloud-hosted backend (managed lldb-server pools).
- Federated artifact store (organizational knowledge graph).
- Workflow templates / blueprints.
- *Not* a rewrite. Same codebase, evolved.

---

## 6. Tracking GDB and LLDB upstream

Three channels keep us aware of what the reference debuggers are doing.

### 6.1 Methodology channel (manual, monthly)

For each upstream release of GDB and LLDB:
1. Read the release `NEWS` / `release-notes`.
2. `git log --stat` between release tags on:
   - GDB: `gdb/infrun.c`, `gdb/breakpoint.c`, `gdb/dwarf2/`, `gdb/remote.c`, `gdb/python/`, NEWS.
   - LLDB: `lldb/source/Plugins/Process/`, `lldb/source/Symbol/`, `lldb/source/Expression/`, `lldb/source/API/`, release notes.
3. Anything new (new bp type, DWARF attr, arch, packet, plugin) → triage issue tagged `upstream:gdb` or `upstream:lldb` with one of: `must-port`, `nice-to-port`, `irrelevant`, `superseded-by-our-design`.
4. `must-port` items get scheduled into the next minor; `nice-to-port` accumulates for prioritization.

### 6.2 Test-corpus channel (semi-automated)

- Port slices of `gdb/testsuite/` and `lldb/test/` as conformance tests against `ldbd`. Start with `dwarf2/`, `breakpoint/`, `inline-frame/`, `signals/`, `corefile/`.
- These tests run through the LDB protocol — if they pass against LLDB-backend and our protocol, they should pass against future backends. They're how we prove component swaps don't regress behavior.

### 6.3 Bug-fix channel (continuous)

- Subscribe to `gdb-patches@` and `lldb-commits@` mailing lists for security and correctness fixes; mirror relevant fixes into our integration tests.
- For LLDB specifically, since we depend on it, pin to a known-good release and run a weekly bot that updates the pin and runs the full CI matrix. Bumping the pin is a normal PR.

### 6.4 Process governance

- A single "upstream watcher" issue per release — assigned to one engineer per quarter on rotation.
- Quarterly "upstream digest" doc summarizing what GDB and LLDB shipped, what we ported, what we deliberately didn't.

---

## 7. Component-replacement triggers (how we decide)

Replace an LLDB-provided component only if all three are true:

1. **Measured pain.** A specific benchmark or workflow exceeds an SLA we set. (Examples: indexing a 1 GB binary >30 s, probe callback latency >1 ms p99, DAP attach >2 s.)
2. **No upstream fix in flight.** We've checked LLDB issue tracker / mailing list and the fix isn't coming.
3. **Architectural reason.** The replacement enables a Track C feature we can't otherwise deliver (e.g., cross-binary indexing requires us to own the indexer).

If only 1 and 2 are true → file an upstream patch first. Replacement is the last resort.

---

## 8. The thing we will not build

For honesty, here's the explicit "no" list:

- **A new debug info format.** DWARF + (eventually) PDB are it. No "LDB-format."
- **A from-scratch DWARF reader before v0.9.** LLDB's is fine until it's not.
- **A custom probe DSL before v1.0.** Session recipes do the job; if patterns force a DSL, we'll know.
- **A from-scratch expression evaluator.** Clang via LLDB, forever.
- **GDB compatibility shim.** We don't try to *be* GDB. We try to be better. Users migrate by choice, not by API mimicry.
- **A web UI in v0.x.** CLI + agent + IDE-via-DAP cover the surfaces. UI comes if and when there's pull.
- **Multi-tenant in v0.x.** One operator per daemon. Multi-tenant is v2.0 work.

---

## 9. North-star metrics (per quarter review)

These tell us if the strategy is working.

| Metric | Why it matters |
|---|---|
| **Reference-workflow tokens (LLM context cost)** | The whole agent-first thesis is tokens-spent-per-task. Should *fall* over time. |
| **Coverage matrix CI pass rate** | Track A health. |
| **Determinism CI pass rate** | Track C foundation; non-negotiable. |
| **Time to first probe-event (cold-start)** | LLDB-bottleneck signal. |
| **Probe event throughput (events/sec sustained)** | High-rate-tracing health. |
| **Upstream-port lag (median days from GDB/LLDB release to port)** | Are we keeping up. |
| **Component-ownership %** | Progressive-replacement progress; *not* a goal in itself. |
| **External adoption (Claude/Codex/IDE plugins built on ldbd)** | Whether the protocol is good enough to build on. |

If a release moves none of these and adds no Track C feature, we did the wrong thing.
