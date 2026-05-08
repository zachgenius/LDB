# V1 Readiness

This is the release gate for calling LDB V1-quality. It is intentionally
operational: every item should either be green, explicitly deferred with a
reason, or backed by a tracked follow-up.

## Current Position

LDB is still pre-V1. The core daemon, protocol shape, LLDB backend, sessions,
artifacts, observers, probes, DAP shim, rr URL integration, and opt-in Capstone
disassembly path are all present, but V1 should mean more than "features
exist." V1 means a user can build it, run the supported workflows, understand
the limitations, and trust CI to catch regressions on the declared platform
matrix.

## Release Gates

| Gate | Status | Required before V1 |
|---|---:|---|
| Linux x86-64 CI | Green | Keep full default `ctest` green on Ubuntu 24.04 with apt LLDB 18. |
| Linux arm64 CI | Green | Keep validation leg green; document validation-only status. |
| macOS arm64 CI | Green | Keep Homebrew LLVM leg green; avoid unbounded timeout growth. |
| Capstone opt-in CI | Green | Keep `-DLDB_ENABLE_CAPSTONE=ON` build plus hello/disasm/unit checks green. |
| Default install/build docs | Partial | Consolidate Linux/macOS dependency and CMake commands in `README.md`. |
| Protocol versioning | Mostly green | Freeze V1 wire-shape rules and confirm `describe.endpoints` schemas are complete. |
| Endpoint smoke coverage | Partial | Add one agent-style RE workflow smoke, not just isolated endpoint checks. |
| Known limitations | Partial | Publish a concise limitations section in `README.md` before tagging. |
| Release artifacts | Open | Decide whether V1 ships source-only, binary artifacts, or both. |
| License | Open | Choose and record the project license. |

## Supported V1 Matrix

The V1 supported matrix should be narrow and honest:

| Platform | Status | Notes |
|---|---:|---|
| Linux x86-64 | Supported | Primary CI leg; apt LLDB 18 in CI, local LLVM roots supported. |
| Linux arm64 | Validation | CI validates behavior, but release packaging is not yet promised. |
| macOS arm64 | Supported | Homebrew LLVM plus Apple's debugserver path. Some Linux-only observers SKIP. |
| Windows | Out of scope | No V1 support claim. |
| FreeBSD | Out of scope | Roadmap item, not V1. |

## Required Local Validation

Before tagging V1, run these locally on at least one Linux host:

```sh
cmake -B build -G Ninja -DLDB_LLDB_ROOT=/path/to/llvm-prefix
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

If Capstone is installed:

```sh
cmake -B build-capstone -G Ninja \
  -DLDB_LLDB_ROOT=/path/to/llvm-prefix \
  -DLDB_ENABLE_CAPSTONE=ON
cmake --build build-capstone --parallel
ctest --test-dir build-capstone --output-on-failure \
  -R "smoke_hello_capabilities|smoke_disasm|unit_tests"
```

## Agent Workflow Gate

V1 needs one end-to-end workflow smoke that resembles how an agent will
actually use LDB. The minimum useful path is:

1. `hello`
2. `target.open`
3. `module.list`
4. `string.list`
5. `string.xref`
6. `disasm.function`
7. `session.create`
8. replay or export enough session state to prove the transcript is durable

This should run against the existing fixture binaries and assert shapes and
high-level invariants, not exact instruction text.

## Protocol Freeze Checklist

Before V1, review:

- `src/daemon/dispatcher.cpp` `describe.endpoints` entries.
- `docs/05-protocol-versioning.md`.
- Smoke tests that pin error codes and required fields.
- Optional fields added since protocol `0.1`, including
  `hello.data.capabilities`.

Do not bump the protocol version for purely additive optional fields. Do bump
it for any required-field, meaning, or error-code change a client cannot safely
ignore.

## Known Limitations To Publish

These are acceptable for V1 if documented:

- LLDB remains the default backend and owns target/process/DWARF semantics.
- Capstone is opt-in and affects only `disasm.range` and `disasm.function`.
- `xref.addr` and `string.xref` intentionally keep LLDB disassembly/comment
  semantics.
- True async/non-stop runtime is deferred; the per-thread protocol surface is
  present but sync-backed.
- rr support is a `target.connect_remote` URL path; reverse execution endpoints
  are deferred because LLDB SBAPI does not expose them directly.
- Linux-only observers and BPF/tcpdump paths SKIP on macOS or unprivileged
  runners.
- macOS local process tests depend on Apple's signed debugserver.
- Release artifacts are not promised until the artifact policy is decided.

## V1 Cut Decision

V1 is ready when:

- master CI is green on all required jobs for the release commit;
- the agent workflow smoke is present and green;
- README has install, test, supported-platform, and limitation sections;
- license and artifact policy are explicit;
- no open high-severity correctness issue affects the supported matrix.

Anything outside that list can move to post-V1 unless it changes the public
protocol contract or invalidates the supported workflows.
