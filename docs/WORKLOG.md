# LDB Engineering Worklog

Daily/per-session journal. Newest entries on top. See `CLAUDE.md` for the format and why this exists.

---

## 2026-05-05 (cont. 6) — M2: thread.list + thread.frames

**Goal:** Land thread enumeration and per-thread backtrace. Together with the M2 process lifecycle, an agent can now launch a binary, observe what threads exist, and inspect each thread's stack — the foundation for every subsequent dynamic-analysis primitive.

**Done:**

- **9-case unit test** (`test_backend_threads.cpp`, 37 assertions) covering both endpoints. Asserts on shape and invariants rather than specific entry-point function names (which differ macOS/Linux): at least one thread, tids unique, every frame has a non-zero pc, indices are 0..N, `max_depth` caps correctly, bogus tid throws.
- **`ThreadInfo` / `FrameInfo`** added to `DebuggerBackend` along with `list_threads` / `list_frames`. `ThreadId` aliased to `uint64` (= `SBThread::GetThreadID()`, kernel-level); LLDB's 1-based index id also exposed for human display. `list_frames` walks `SBThread::GetFrameAtIndex`; function name preferred via `SBFunction`, fallback to `SBSymbol` for dyld-style frames whose DWARF is sparse; source file/line via `SBLineEntry`.
- **Wire layer**: `thread.list` and `thread.frames` JSON-RPC endpoints registered in `describe.endpoints`. Optional fields (name, stop_reason, file, line, inlined, module) omitted when empty so the agent's context window is bounded.
- **Smoke test in Python** (`test_threads.py`): bash chained-stdin couldn't express the cross-request data dependency (we need `tid` from response N for request N+1, against the *same* live process). Switched to `subprocess.Popen`-driven interactive smoke. Pattern is reusable for any future test that needs to thread state across requests.

**Decisions:**

- **`ThreadId = SBThread::GetThreadID()` not the index id.** Kernel-level tids match what `ps`, `top`, and stack traces from elsewhere show. The 1-based index id is also exposed for human display, but lookups go through the kernel tid.
- **`list_threads` returns empty (not throws) when there's no process.** Symmetric with `process.state` returning `kNone`. Agents differentiate "no process" from "no threads in process" via the proc state, not via this endpoint's error path.
- **`max_depth=0` means no cap**, matching the convention from view descriptors. `max_depth=N` returns up to N frames innermost-first.
- **Function-then-symbol fallback** in `to_frame_info` matters in dyld frames where function-level DWARF is absent. Without it, frame.function is empty for any non-app code; the symbol fallback gives the user `_dyld_start`-class names where they exist.
- **Smoke harness gets a Python branch.** Now there are two smoke patterns: bash (chained stdin) for sequence-tests, Python (Popen) for cross-request-state tests. Both invoked uniformly via `add_test`. Worth promoting to a small `tests/smoke/_shared.py` if a third Python smoke test joins.

**Surprises / blockers:**

- **First smoke attempt was bash, and failed on r5.** Chained stdin meant we could capture output but couldn't feed an extracted TID back into the same conversation — the second invocation's launched process has different TIDs. Switched to Python-driven Popen interaction inside ten minutes; the test now reads each response before composing the next.
- **`tests/CMakeLists.txt` was updated to invoke `python3 ...`** explicitly. CMake's `add_test(COMMAND ...)` with the script as the first argument failed with "Unable to find executable: ...sh" because we'd renamed but the build dir still referenced the old name; reconfigure fixed it.

**Verification:**

- `ctest` → 11/11 PASS in 18.91s. unit_tests is 98 cases / ~524 assertions; total includes 6 process+thread test cases that each spawn a real inferior, so wall clock grew from 9s to 19s. Acceptable for now; consider gating these behind `--include` in CI when we get to a multi-platform matrix.
- Manual: `thread.frames` against the entry-point stop returns 1 frame on macOS arm64 (just `_dyld_start`); on Linux it'd typically be more (dyld + libc start). Either way the assertion `>=1` holds.

**Next:**

- **`frame.locals` / `frame.args` / `frame.registers`** — these need `SBFrame::GetVariables` (locals + args) and `SBFrame::GetRegisters` plus `SBValue` walking. SBValue is the meaty abstraction; rolling its conversion to JSON is the bulk of the work. View descriptors apply naturally (`fields` to project, `summary` to cap deep struct walks).
- **`target.attach`** (by PID) — needed for the user's stated workflow (attach to the running `quoter` process on `192.168.191.90`). API mirrors `process.launch` at the wire layer; backend uses `SBTarget::AttachToProcessWithID`.
- **`target.load_core`** — postmortem path. Reuses every read-only endpoint we've built (target, modules, sections, types, symbols, threads, frames). Worth doing before too long because debugging a core is *the* lowest-friction integration test for everything we have.
- **Memory primitives** (`mem.read`, `mem.read_cstr`, `mem.search`, `mem.regions`) — light wrappers on `SBProcess::ReadMemory`. Useful immediately for the user's "extract btp_schema.xml from the buffer" pattern once we have a long-running fixture.
- **Long-running fixture** still pending. Suggested: a small C program that opens a socket, writes a known buffer, and `pause()`s. That gives us a process to attach to AND a buffer to extract.
- **Cleanup queue (still deferred):**
  - `[INF] lldb backend initialized` log spam.
  - `tests/smoke/test_type_layout.sh` per-id extraction tightening.
  - View retrofit on string.list / disasm / xref / symbol.find / type.layout.

---

## 2026-05-05 (cont. 5) — M2 kickoff: process lifecycle

**Goal:** Open M2 with the smallest meaningful slice — process launch / state / continue / kill — synchronously against the structs fixture. Unblocks every subsequent dynamic-analysis endpoint (threads, frames, locals, memory).

**Done:**

- **9-case unit test** (`test_backend_process.cpp`, 30 assertions) covering the full lifecycle plus error paths: pre-launch state is `kNone`, `stop_at_entry=true` → `kStopped` with valid pid, continue → `kExited` with exit code in `[0,255]`, kill from stopped is terminal, continue/launch on bad target_id throws, kill on no-process is idempotent, relaunch auto-kills the prior process and the new pid differs.
- **`launch_process` / `get_process_state` / `continue_process` / `kill_process`** added to `DebuggerBackend` and implemented in `LldbBackend`. Sync mode (already set in M0) makes Launch and Continue block until the next stop or terminal event. Stop reason populated from `SBThread::GetStopDescription()` best-effort.
- **JSON-RPC layer**: `process.launch` / `process.state` / `process.continue` / `process.kill` with `state` exposed as a string enum (`"none"` | `"running"` | `"stopped"` | `"exited"` | `"crashed"` | `"detached"` | `"invalid"`). Each registered in `describe.endpoints`.
- **Smoke test** (`test_process.sh`) runs the full lifecycle on the wire — including the proper error code (`-32000` `kBackendError`) for `continue` after `exited`, and the idempotency contract on `kill`.

**Decisions:**

- **Sync mode for the M2 first slice.** `SBDebugger::SetAsync(false)` was already set in M0; we lean into it. Async + event handling lands later when we need long-running fixtures or non-stop multi-thread scenarios. For the structs fixture (exits in <50ms) sync is correct.
- **`stop_at_entry` defaults to true.** A debugger you can't pause is useless. Agents wanting "run to completion" can pass `stop_at_entry=false` (added but not yet smoke-tested explicitly).
- **`launch_process` auto-kills any prior process.** The alternative (error on relaunch) requires the agent to track lifecycle state; auto-kill matches what `lldb` and `gdb` do at the prompt and is what an agent intuitively expects.
- **State exposed as a lowercase string**, not the integer enum. LLMs read `"stopped"` more reliably than `4`. The mapping from `ProcessState` to string is centralized so we don't drift.

**Surprises / blockers (both real, both fixed):**

- **Homebrew LLVM 22.1.2 doesn't ship `debugserver` on macOS.** SBProcess::Launch silently failed with the unhelpful `"failed to launch or debug process"`. Apple's signed `debugserver` is shipped with the Command Line Tools at `/Library/Developer/CommandLineTools/.../debugserver`. Added `maybe_seed_apple_debugserver()` to set `LLDB_DEBUGSERVER_PATH` from a candidate list before `SBDebugger::Initialize`. Logs the path it picked or warns if it found nothing. Lookup is one-shot via `std::call_once` — must happen exactly once before init.
- **`SBDebugger::Initialize` / `Terminate` are process-global and break under cycling.** First test passed; second test's `Launch` failed with the same generic error. Root cause: `LldbBackend` dtor called `SBDebugger::Terminate()`; the next test's ctor called `Initialize()` again; LLDB's internal state was corrupted. Fix: hoist `Initialize` into `std::call_once`; never call `Terminate` (process exit reaps it). Documented inline so the next person doesn't re-add the dtor call.

**Verification:**

- `ctest` → 10/10 PASS in 9.02s. unit_tests at 89 cases / ~487 assertions. (Process tests dominate the runtime — actual processes get spawned, that's expected.)
- Manual: `process.launch` returns within ~100ms; `process.continue` blocks the expected ~50ms then returns `state="exited"` with `exit_code=184` — matches the byte-XOR computation in `structs.c::main`.

**Next:**

- **Threads & frames** are the natural follow-on:
  - `thread.list` (id, name, state, pc, sp)
  - `thread.frames` (per-thread backtrace via SBThread::GetFrameAtIndex; depth bounded by view.limit)
  - `frame.locals` / `frame.args` / `frame.registers` (using SBValue, with view.fields for projection)
  - All read-only for now; stepping (`step`/`next`/`finish`/`until`) lands as a separate commit.
- **`target.attach`** (by pid) and **`target.load_core`** (postmortem) — same wire shape as `target.open` results plus `target_id`, but different SBAPI entry points. Worth doing alongside threads since debugging a core dump exercises the same thread/frame stack.
- **A long-running fixture** is needed before async-mode tests. Something like a `read(stdin)` loop or `sleep(60)`. Add as a new fixture target alongside `ldb_fix_structs`.
- **Memory primitives** (`mem.read`, `mem.read_cstr`, `mem.search`, `mem.regions`) — lightweight on top of `SBProcess::ReadMemory`; could land before threads if it's tactically useful.
- **View retrofit on string.list / disasm / xref** still pending from the M1 close-out queue.
- **Cleanup queue (still deferred):**
  - `[INF] lldb backend initialized` log spam in unit tests (now that there's a `setenv` trace too, the noise is louder).
  - `tests/smoke/test_type_layout.sh` per-id extraction.

---

## 2026-05-05 (cont. 4) — M1 closes: view descriptors

**Goal:** Land the last cross-cutting M1 feature — view descriptors — and wire onto `module.list` as the model endpoint. Per the prior session's "Next," first cut covers `fields` (projection), `limit`+`offset` (pagination), `summary` (count + sample). Defer `tabular`, `max_string`, `max_bytes`, cursor.

**Done:**

- **`src/protocol/view.{h,cpp}`** — pure JSON-manipulation module, no LLDB. `parse_from_params(params)` reads `params["view"]` and validates every field's type, throwing `std::invalid_argument` with descriptive messages on malformed input. `apply_to_array(items, spec, items_key)` returns a JSON object of the documented shape (`{<key>: [...], total, next_offset?, summary?}`).
- **20-case Catch2 unit test** (`test_protocol_view.cpp`, 87 assertions) covering parse errors, default behaviour, limit/offset combinations, fields projection (incl. unknown fields silently ignored), summary mode, edge cases (empty array, offset past end, non-object items pass through fields-projection unchanged).
- **Wired into `module.list`**: handler now parses view, applies it, and returns the shaped object instead of the bare `{modules:[...]}` shape. Empty/no-view requests still get `total` so the agent can plan follow-up paging without an extra round-trip.
- **Dispatcher outer try/catch** translates `std::invalid_argument` → kInvalidParams (-32602). View-parse errors are agent-side mistakes; mapping them to a typed error keeps the protocol contract clean.
- **Smoke test (`test_view_module_list.sh`)**: 7 assertions covering default response (has `total`), limit=2 (`next_offset=2`), offset=1+limit=1 (`next_offset=2`), `fields=["path","uuid"]` (no `sections`/`triple`), `summary=true` (sample + summary flag), `limit=-1` → -32602, non-object view → -32602.

**Decisions:**

- **Parse + apply is a separate module** (`src/protocol/view.cpp`) rather than living inside the dispatcher. It's a pure JSON transform; making it its own module means it's unit-testable without LLDB and reusable across every endpoint that returns an array.
- **`view` lives inside `params`**, not as a top-level sibling. `docs/02-ldb-mvp-plan.md §3.2` showed it top-level, but JSON-RPC 2.0 only specifies `id`/`method`/`params` at the envelope. Keeping our extension inside `params` is one less spec violation. The doc is sketchy; the parser is now the contract.
- **`total` is always emitted.** Even on a default request that includes everything, the agent can plan ("there are 50 modules; I'll page through them") without re-asking. Costs nothing.
- **`next_offset` only when more remain.** Its absence is the "you're done" signal; saves a few bytes per terminal page.
- **Default summary sample size is 5** (`kSummarySampleSize`). Small enough to be a "preview"; agent can override with explicit limit. Tests assert `<=5` rather than `==5` to leave room to tune.
- **Unknown fields in `view.fields` are silently ignored**, not an error. Agents may speculatively project across endpoint variants; failing on a stale field name would be brittle.

**Surprises / blockers:**

- **No real surprises.** The pure-JSON-transform design fell out cleanly; tests caught a couple of subtle bugs early (offset > items.size needed clamping; project_fields had to skip non-object items).
- **CMake reconfigure was needed** because we added a new source file (`view.cpp`) referenced by both `src/CMakeLists.txt` and `tests/unit/CMakeLists.txt`. Standard CMake quirk; ninja's auto-rerun caught it on the second build.

**Verification:**

- `ctest` → 9/9 PASS in 2.27s. unit_tests at 80 cases / ~457 assertions.
- Manual: `module.list` with `view:{fields:["path","uuid"]}` returns ~3KB instead of the 70KB+ default — the practical token-saving payoff for an agent.

**Next:**

- **Retrofit other endpoints** with views in priority order:
  1. `string.list` — already volume-bounded by default scope, but pagination + summary still useful for big binaries.
  2. `disasm.range` / `disasm.function` — large functions can produce hundreds of insns; `fields` (e.g., just mnemonic+operands) and `limit`+`offset` pay off.
  3. `xref.addr` / `string.xref` — `summary` is especially useful when an address is referenced from many sites.
  4. `type.layout` — `fields` to project per-field metadata (e.g., just `name,off,sz`).
  5. `symbol.find` — `summary` helps when name is a common substring (post-introduction of glob/regex patterns).
- **Future view features** to land when forced by a workflow:
  - `tabular` (cols+rows for arrays of homogeneous structs — major token win).
  - `max_string` / `max_bytes` to truncate long string and byte fields in-place.
  - `cursor` (opaque token instead of integer offset) when pagination needs to be stable across mutations.
- **`xref.imm`** still pending — useful for finding magic-number constants in binary.
- **ARM64 ADRP+ADD reconstruction** in `xref.addr` — would close the gap that `string.xref`'s second detection path currently papers over.
- **Cleanup queue (still deferred):**
  - `tests/smoke/test_type_layout.sh` per-id extraction.
  - `[INF] lldb backend initialized` log spam in unit tests.
- **M1 status:** functionally complete — every "what should this endpoint do" item from `docs/02-ldb-mvp-plan.md §4.2` ships and is tested. Next major milestone is M2 (process / thread / frame / value / memory) which is materially more work than M1; consider whether to do an M1 "polish pass" first (view retrofits, log cleanup, glob patterns on symbol.find) or jump to M2.

---

## 2026-05-05 (cont. 3) — M1 xref pair: xref.addr + string.xref

**Goal:** Land the cross-reference primitives so the user's RE workflow ("find where `btp_schema.xml` is referenced") runs end-to-end as a single RPC.

**Done:**

- **`xref.addr` endpoint** (commit `669e80a`): Walk the main executable's code sections, disassemble each via `disassemble_range`, scan operand and comment strings for the target address as a hex literal. Owning function resolved via `ResolveSymbolContextForAddress`. Catches direct branches (BL/BR on arm64, CALL on x86) where LLDB renders the resolved target into the operand. Documented gap: ARM64 ADRP+ADD pairs whose individual operands don't carry the full address. 5-case unit test, smoke test asserts ≥1 hit attributed to `main` for the address of `point2_distance_sq`.
- **`string.xref` endpoint** (commit `4eb4050`): Combines the address-hex path (via `xref_address`) with a new comment-text path that scans for the string in quotes (`"btp_schema.xml"`) — exactly the form LLDB emits when it has resolved an ARM64 ADRP+ADD pair. Both paths feed one xrefs vector, deduped by instruction address. 6-case unit test (including dedup), smoke test runs the user's actual workflow.

**Decisions:**

- **Two detection paths for `string.xref`, not one.** The address-hex match catches x86-64 direct loads / function pointers; the comment-text match catches ARM64 PIE ADRP+ADD pairs. Either alone leaves a major arch with broken results. Combined, we get the headline workflow working on the project's primary platforms.
- **Dedup by instruction address.** Both paths can hit the same insn — explicit `std::unique` after sort to enforce the contract. Tested.
- **No `xref.imm` endpoint yet.** It would scan for arbitrary immediate values (not just addresses). Useful for finding magic-number constants and shift amounts but not blocking; defer until a workflow demands it.
- **No ADRP+ADD reconstruction in `xref.addr`.** Could add it (decode ADRP imm21 → page, ADD imm12 → offset, sum) but `string.xref` already gets the right answer via the comment-text path. Document the gap; revisit when something needs `xref.addr` against a string address (not text).
- **`string.xref` runs `find_strings` with `min_length=max_length=text.size()` to narrow** the scan upfront, then exact-match-filters in C++. Avoids returning the whole exe's strings to be dropped client-side. Cheap.

**Surprises / blockers:**

- **None major.** The combined-detection design fell out of looking at LLDB's actual disasm output for `main` before writing the test. Worth noting: bias toward "see what the data actually looks like" before committing to detection logic, especially for fragile heuristics.
- **Smoke test setup-output extraction** uses `python3 -c '...json.loads...'` to pull the function address from the first request's response, then injects it into the second request. Slightly awkward bash but more robust than parsing JSON in pure bash. Worth keeping a lightweight helper in mind if more smoke tests need this pattern.

**Verification:**

- `ctest` → 8/8 PASS in 1.97s. unit_tests at 60 cases / ~370 assertions.
- Manual end-to-end: from a clean `target.open` of the fixture, a single `string.xref({text:"btp_schema.xml"})` returns the ADRP+ADD pair in `main` with correct function attribution. This is the user's stated workflow §5.

**Next:**

- **View descriptors** on `module.list` as the model. Most useful first-cut features: `fields` (projection), `limit`+`offset` (pagination), `summary` (count + sample). Defer `tabular`, `max_string`, `max_bytes` until a test forces them. Once the pattern is set on `module.list`, retrofit `string.list` (default scope already controls volume but pagination still useful) and the xref endpoints.
- Optional follow-ups (not urgent):
  - `xref.imm` for immediate values (magic numbers, shift amounts).
  - ARM64 ADRP+ADD reconstruction inside `xref.addr` so it works for string addresses without going through `string.xref`. Not needed for the documented workflow.
  - The `[INF] lldb backend initialized` log spam (still emitted once per Catch2 test case).
- Cleanup deferred:
  - `tests/smoke/test_type_layout.sh` per-id extraction (still uses the looser glob pattern that happens to pass by ordering luck).

---

## 2026-05-05 (cont. 2) — M1 continued: string.list and disasm.{range,function}

**Goal:** Continue M1 endpoint TDD per the previous session's "Next." Build out `string.list` (the rodata scanner) and the disasm pair (`disasm.range` + `disasm.function`). Both unblock `string.xref` / `xref.*` for the next push.

**Done:**

- **`string.list` endpoint** (commit `a895cb9`): 8-case unit test (TDD-fail first), backend `find_strings` walking module sections, raw bytes via `SBSection::GetSectionData()` + `SBData::ReadRawData()`, scanning for printable-ASCII runs (space..~ plus tab — same alphabet as `strings(1)`). Recurses into subsections so Mach-O `__TEXT/__cstring` is reachable from its `__TEXT` parent. Wire shape: `{strings:[{text,addr,section,module}]}`. Smoke test exercises default scan (finds both fixture strings), `min_len=10` (drops "DXP/1.0"), `min_len=100` (drops both), nonexistent section → empty, negative `min_len` → -32602.
- **`disasm.range` and `disasm.function` endpoints** (commit `ba04e7e`): 7-case unit test asserting invariants rather than mnemonics (every insn within range, addresses strictly increasing, `bytes.size() == byte_size`, function ends with a ret-family insn). Backend `disassemble_range` via `ResolveFileAddress` + `ReadInstructions`. Wire layer exposes both endpoints from one backend method: `disasm.range` is a thin pass-through; `disasm.function` composes `find_symbols(kind=function)` → range → `disassemble_range`. Bytes serialized as space-separated lowercase hex.

**Decisions:**

- **`string.list` defaults to main executable only.** Scanning every loaded module on macOS returns the entire libSystem string table (10K+ entries) — useless for agent context. Override via `module:"*"` (all) or a path/basename. Documented in the commit and in `describe.endpoints`.
- **Default `string.list` section selection** is anything classified as "data" (per M0's `eSectionType`-to-string mapping). Section names are slash-joined hierarchical (`__TEXT/__cstring`) so the override is unambiguous.
- **`disasm.range` upper-bounds the count by `(end-start)`.** Assumes ≥1 byte/insn — always sufficient. On ARM64 (4 bytes/insn) we ask for 4× too many but `ReadInstructions` returns only what fits. We trim instructions whose address ≥ end_addr to handle the boundary case.
- **`disasm.function` returns `{found:false}` for unknown names**, matching the `type.layout` precedent. Agents can branch on `found` instead of relying on errors.
- **Bytes as hex strings, not arrays.** A 4-byte ARM64 insn is `"08 00 80 d2"` — 11 bytes — vs `[8,0,128,210]` JSON which is 13. Hex also reads naturally; arrays don't. Will revisit if/when we add CBOR (binary becomes free).

**Surprises / blockers:**

- **`SBInstructionList::GetSize()` return type drift.** First build produced a `-Wshorten-64-to-32` warning. Switched the loop to `size_t`, casting only at the `GetInstructionAtIndex(uint32_t)` call site. Worth grepping for similar narrowings as we add more SBAPI usage.
- **`SBSection::GetSubSectionAtIndex` recursion blew up briefly** in `scan_module_for_strings`. Initial code recursed twice (once from `scan_section_for_strings`, once from the caller), yielding duplicated strings. Fixed by making `scan_section_for_strings` own the recursion and the caller do top-level dispatch only.
- **`SBAddress::SetLoadAddress` vs file address semantics on a non-running target.** Both ended up identical for our case (no process, no relocation). `target.ResolveFileAddress` is the cleanest entry point and is what we used.

**Verification:**

- `ctest --output-on-failure` → 6/6 PASS in 1.36s:
  - `smoke_hello`, `smoke_type_layout`, `smoke_symbol_find`, `smoke_string_list`, `smoke_disasm`, `unit_tests` (49 cases / ~325 assertions).
- Manual: `disasm.function` on `point2_distance_sq` returns 24 ARM64 instructions, ending in `retab` (Apple's auth-ret variant — the test's `looks_like_return` correctly catches it).

**Next:**

- `xref.addr` and `xref.imm` — these are the substrate `string.xref` will compose on. Approach: walk `disassemble_range` over each code section, parse operand strings for hex literals + use the SBInstruction comment field where LLDB has resolved a target. Fragile; expect arch-specific edge cases. ARM64 ADRP/ADD pairs are the main pattern; LLDB's disassembler tends to annotate the resolved address in the second operand of the pair.
- `string.xref` as a thin composition: locate string by text or address (extending `find_strings` if needed), then `xref.addr` against that address.
- **View descriptors** are still pending. Should land on `module.list` as the model endpoint before retrofit. Suggested first-cut features: `fields` (projection), `limit` + `offset` (pagination), `summary` (count + sample). Defer `tabular`, `max_string`, `max_bytes` until needed by an actual test case.
- Consider downgrading the `[INF] lldb backend initialized` log spam — emitted once per Catch2 test case in the unit suite. Cosmetic; not a blocker.

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
