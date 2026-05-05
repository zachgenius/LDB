# LDB Engineering Worklog

Daily/per-session journal. Newest entries on top. See `CLAUDE.md` for the format and why this exists.

---

## 2026-05-05 (cont.) — M1 kickoff: harness, fixture, type.layout, symbol.find

**Goal:** Stand up the unit-test harness, create a static-analysis fixture binary, and TDD the first two M1 endpoints (`type.layout` and `symbol.find`). Per the prior session's plan, this is the first session running under strict TDD per `CLAUDE.md`.

**Done:**

- **Catch2 unit-test harness** (commit `5f4d380`):
  - Vendored Catch2 v3.5.4 amalgamated single-header at `third_party/catch2/`.
  - Added `tests/unit/` CMake target (`ldb_unit_tests`) wired into ctest. Catch2's amalgamated cpp built with `-w` to silence its internal warnings under our strict warning set.
  - Seeded with 12 retroactive characterization tests of `src/protocol/jsonrpc.{h,cpp}` (request parse, notifications, error paths, response serialize, round-trip). Justified under CLAUDE.md "first commit on a branch is harness expansion."
- **Fixture binary** (commit `cb9e3e9`):
  - `tests/fixtures/c/structs.c` with four structs whose layouts are deterministic on the default x86-64/arm64 ABI: `point2` (8B no padding), `stride_pad` (8B 3-byte hole), `nested` (16B), `dxp_login_frame` (16B 4-byte hole — mirrors the user's RE workflow).
  - Plus rodata strings (`k_schema_name`, `k_protocol_name`) and globals (`g_origin`, `g_login_template`) for later string.xref / symbol.find tests.
  - Built with `-g -O0 -fno-omit-frame-pointer -fno-eliminate-unused-debug-types`. LLDB resolves DWARF via Mach-O OSO load commands without a `.dSYM` — verified via `lldb -b -o "type lookup struct ..."`.
- **`type.layout` endpoint** (commit `cf79cb2`) — first true TDD increment:
  - Wrote `tests/unit/test_backend_type_layout.cpp` (7 cases). Build failed at compile because `find_type_layout` / `TypeLayout` / `Field` didn't exist. Confirmed correct failure mode.
  - Added `Field` and `TypeLayout` to `backend::DebuggerBackend`, implemented `LldbBackend::find_type_layout` via `SBTarget::FindFirstType` + `SBType::GetFieldAtIndex` / `GetOffsetInBytes` / `GetByteSize`. Holes computed as gap between end-of-field-i and start-of-field-i+1 (or struct end for last field).
  - Wire shape (per MVP plan §4.2): `{"found":bool, "layout":{name, byte_size, alignment, fields[{name,type,off,sz,holes_after}], holes_total}}`.
  - Unknown type → `{"found":false}` (not an error). Invalid target_id → `-32602` error response.
  - Alignment inferred as max power-of-two field size ≤ 16 (SBAPI doesn't expose struct alignment directly). Matches default ABI for our fixtures.
  - Smoke test added (`tests/smoke/test_type_layout.sh`): 6 wire-format assertions across all four fixture structs + missing-name error path.
- **`symbol.find` endpoint** (commit `408906d`):
  - 8-case unit test, also TDD-first.
  - Added `SymbolKind` enum, `SymbolQuery`, `SymbolMatch` to backend interface. Implemented `LldbBackend::find_symbols` via `SBTarget::FindSymbols`, post-filtering on `lldb::SymbolType` mapped to `SymbolKind`. Reject non-exact name matches (FindSymbols sometimes returns adjacent hits that share a prefix). Owning module resolved through `ResolveSymbolContextForAddress`.
  - Wire shape: `{"matches":[{"name","kind","addr","sz","module","mangled"?}]}`.
  - Smoke test covers function hit, variable hit (sz=8 = sizeof(struct point2)), kind filtering both directions, unknown→empty, invalid kind→error.

**Decisions:**

- **Catch2 v3 over v2.** v3 is current; amalgamated build (single .hpp + .cpp) keeps deps minimal while giving us modern matchers. ~25k lines of vendored code; acceptable.
- **Build CMake exposes test fixtures via `target_compile_definitions(... LDB_FIXTURE_STRUCTS_PATH=$<TARGET_FILE:...>)`** so unit tests can locate the fixture without env vars or relative paths. Forces a build-system dependency on the fixture target.
- **Fixture C compiled bypasses our C++ warnings interface.** They're separate languages and the strict C++ flags would noise up real C compile errors.
- **Smoke-test assertions extract the per-id response line then match on it,** rather than treating the entire daemon output as one string. The earlier `*"r6"*"matches":[]*` pattern allowed cross-line false matches (matches:[] is per-response, so any-after-id satisfies `*"r6"*` even when r6 itself contains a populated array). Caught this on `symbol.find` and rewrote that script; `test_type_layout.sh` happens to be ordered such that it isn't bitten, but it's fragile.
- **`type.layout` alignment is heuristic** (max power-of-two field size ≤ 16). Works for default ABI; will need an SBAPI escape hatch when we hit `__attribute__((aligned(N)))` or packed structs. Marked in the commit message; not blocking M1.
- **Unknown name → ok-with-`found`:false`** rather than error. Distinguishes "valid query, no match" from "malformed request" — important for LLM agents that branch on error vs. negative-result.

**Surprises / blockers:**

- **`SBTarget::FindSymbols` returns prefix-matches sometimes.** A bare query for `point2_distance_sq` could return a hit list with extra entries whose names begin with the same string. Filtering on exact name fixes this; documented inline.
- **macOS Mach-O OSO debug info.** Initially worried we'd need `dsymutil` to produce a `.dSYM` next to the binary. Turns out LLDB happily resolves DWARF from the original `.o` files via Mach-O `LC_OSO` load commands. Works for development. We'll need `dsymutil` post-build if/when fixtures need to travel between machines.
- **Per-response key order is alphabetical** (nlohmann's default). This is actually a feature for our smoke tests — exact substrings are stable across runs — but it's a footgun if you forget and write order-dependent globs. Documented the bite-and-fix in the symbol_find commit.
- **No real test framework for the fixture itself.** It builds and is opaquely consumed by other tests. If a future fixture has a test that depends on a value computed at runtime (`return some_function();` etc.), that's fine — we don't run the fixture, we only inspect its statics.

**Verification:**

- `ctest --output-on-failure` → 4/4 PASS in 0.91s:
  - `smoke_hello` (5 RPC responses against `/bin/ls`)
  - `smoke_type_layout` (6 assertions against fixture)
  - `smoke_symbol_find` (per-id assertions, 7 responses)
  - `unit_tests` (Catch2: 34 cases, 136 assertions, no failures)
- Manual: `point2_distance_sq` is a 96-byte function; `g_origin` resolves to a variable of size 8; struct layouts match expected by-byte.

**Next:**

- Continue M1 endpoint TDD in this rhythm. Suggested order:
  1. `string.list` — enumerate rodata strings (need a section-bytes scanner). Tests against `k_schema_name` and `k_protocol_name` in the fixture.
  2. `disasm.range` and `disasm.function` via `SBTarget::ReadInstructions` (or `SBFunction::GetInstructions`). Use `point2_distance_sq` for the test.
  3. `string.xref` — needs disasm + memory-immediate scanning to find references to the strings we just enumerated.
  4. `xref.imm` and `xref.addr`.
  5. **View descriptors** — start with `module.list` as the model endpoint (`fields`, `limit`, `cursor`, `summary`, `tabular`). Once that pattern is established, retrofit `type.layout` and `symbol.find`.
- Cleanup deferred:
  - Tighten `tests/smoke/test_type_layout.sh` to use the per-id `get_resp` pattern (currently fragile by luck).
  - Drop the `[INF] lldb backend initialized` log spam to debug-level — it's emitted once per test case in the unit suite. Cosmetic, not blocking.
- Watch for: the `_cost` / `_provenance` response envelope (MVP §3.2) is not yet emitted. We should add it when we start adding view descriptors so cost-aware planning can land alongside.

---

## 2026-05-05 — Project bootstrap & M0 scaffold

**Goal:** Establish the project — design docs, build system, and a working `ldbd` daemon that wraps LLDB SBAPI and answers a few JSON-RPC requests over stdio. Validate that the LLDB-wrapper architecture is mechanically sound before committing further to it.

**Done:**

- Wrote four design docs (commit `9921d92`):
  - `docs/00-README.md` — project framing
  - `docs/01-gdb-core-methodology.md` — deep analysis of GDB 17.1 source: 10 cross-cutting methodologies with file-level evidence
  - `docs/02-ldb-mvp-plan.md` — MVP scope, RPC surface, milestones, reference workflow as acceptance test
  - `docs/03-ldb-full-roadmap.md` — Option A (progressive replacement), three tracks, component-ownership trajectory, upstream-tracking process
- Built M0 scaffold (commit `51e168d`):
  - CMake build linking Homebrew LLVM 22.1.2's `liblldb.dylib`
  - C++20, warning-strict, exports `compile_commands.json`
  - `src/protocol/` JSON-RPC 2.0 framing (line-delimited)
  - `src/daemon/` stdio loop + method dispatcher
  - `src/backend/` `DebuggerBackend` virtual interface + `LldbBackend` impl
  - `src/util/log.{h,cpp}` stderr logger (stdout reserved for RPC)
  - Five working endpoints: `hello`, `describe.endpoints`, `target.open`, `target.close`, `module.list`
  - End-to-end smoke test (`tests/smoke/run.sh`) hooked into CTest, opens `/bin/ls`, verifies all five responses; green
- Vendored `nlohmann/json` v3.11.3 single-header.

**Decisions:**

- **Wrap LLDB, don't fork.** Confirmed with the user against the alternative of a from-scratch native debugger. Strategy is progressive replacement — own components only when measurement justifies. See `docs/03-ldb-full-roadmap.md §3`.
- **C++20 in the daemon, not Python.** Python is reserved for user extension scripts. Probe callbacks and protocol code stay native.
- **Homebrew LLVM, not Apple's system LLDB.** Apple's lives in a `PrivateFrameworks` location; Homebrew gives us regular include + dylib paths. CMake auto-finds it; `LDB_LLDB_ROOT` overrides.
- **CBOR / view descriptors / sessions / artifacts deferred to M1+.** M0 is "prove the wrapper works." MVP plan keeps the protocol forward-compatible (extra fields parsed but ignored).
- **`DebuggerBackend` virtual interface from day one.** Even though only `LldbBackend` exists, the seam is in place so v0.3 GDB/MI and v1.0+ native backends slot in without rewrites.
- **Module schema.** Each module returns `{path, uuid, triple, load_addr, sections[]}`. UUID is the build-id on ELF and LC_UUID on Mach-O — same key works on both OSes for artifact-store correlation later.

**Surprises / blockers:**

- **LLDB SBAPI methods are non-const.** SB classes are refcounted handles by design; calling `parent.GetName()` on a `const SBSection&` fails to compile. Fix: take SB types by value (cheap copy of a refcounted handle). Documented in code comments.
- **`SBTarget::GetModuleAtIndex(uint32_t)` not `size_t`.** Compiler warned on the implicit narrowing; switched loop counter to `uint32_t`. Worth grepping for similar in M1.
- **Smoke-test SIGPIPE bug.** First version of `tests/smoke/run.sh` did `printf "$BIG_OUTPUT" | grep -q '...'`. With `set -o pipefail`, `grep -q` exits early on first match → upstream `printf` gets SIGPIPE → pipeline fails despite the match succeeding. Replaced with bash glob match (`[[ "$OUTPUT" == *needle* ]]`). Lesson for any future test: either drop `pipefail` for early-exit greps or avoid the pipe entirely.
- **`.gitignore` over-broad pattern.** Initial `ldb` line (intended to ignore the binary if it ever ends up at repo root) also ignored `include/ldb/`. Fixed with `/ldbd` (root-anchored, file-name explicit). Build artifacts only ever land in `build/bin/` which is already excluded.
- **Stale clangd diagnostics.** Until `compile_commands.json` exists, the LSP shows phantom errors ("file not found", "C++17 extension"). Resolved after first CMake configure. Note for next session: if diagnostics look wrong, check the LSP has refreshed its compile DB.

**Verification:**

- `ctest --output-on-failure` → 1/1 PASS in 0.24s.
- Manual: `target.open` against `/bin/ls` returns `triple=arm64e-apple-macosx11.0.0`, UUID `322CB148-C401-3EA0-A023-4B21A104D42F`, all 16 Mach-O sections with correct file_addr/size/perms.

**Next:**

- Adopt strict TDD from M1 onward (this session was scaffolding; tests came alongside, not before).
- M1 = static surface. Order of attack:
  1. Add Catch2 (vendored single-header) and a unit-test target. First test is the protocol parser (round-trip request → response).
  2. `target.open` already covers section enumeration; add `module.list` *unit* test against a fixture binary.
  3. `type.layout` first endpoint — TDD: write a smoke test against a fixture C binary with a known `struct foo` layout, watch fail, implement.
  4. `symbol.find`, `string.list`, `string.xref` (need section-bytes scan + xref pass).
  5. `disasm.range` + `disasm.function` via `SBTarget::ReadInstructions`.
  6. `xref.imm` + `xref.addr` via instruction iteration.
  7. View descriptors: projection, pagination, summary, max_string, max_bytes, tabular mode. Apply to `module.list` first as the model endpoint.
- Consider adding a tiny `fixtures/` C program built by CMake, with a few well-known structs/strings, as the substrate for static-surface tests.
