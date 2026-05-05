# LDB Engineering Worklog

Daily/per-session journal. Newest entries on top. See `CLAUDE.md` for the format and why this exists.

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
