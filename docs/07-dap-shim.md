# 07 — DAP Shim (`ldb-dap`)

> Tier 2 §4 from `docs/POST-V0.1-PROGRESS.md`. Track B "DAP shim —
> Generated automatically from `describe.endpoints` so any IDE can
> attach" in `docs/03-ldb-full-roadmap.md` (planned for v0.6, shipped
> early in the post-v0.1 autonomous run).

## Why

LDB's primary surface is its schema-typed JSON-RPC. That's perfect for
agents but invisible to GUI debuggers. The Debug Adapter Protocol (DAP)
is the standard adapter contract VS Code, JetBrains, Zed, Eclipse, and
Neovim's `nvim-dap` all speak. Shipping a DAP shim means LDB gets every
DAP-capable IDE for free — no per-IDE plugin work.

The shim is intentionally a **separate binary**, `ldb-dap`. It does
nothing but translate one wire format to another. The actual debugger
(ldbd) and the actual LLDB engine are subprocesses behind it. When DAP
adds a new request we don't care about, or the IDE sends something
weird, the shim refuses or forwards — neither path can crash the
daemon.

## Architecture

```
   IDE (VS Code, Zed, ...) ──── DAP / stdio ────┐
                                                 ▼
                                          ┌─────────────┐
                                          │  ldb-dap    │
                                          └──────┬──────┘
                                                 │  JSON-RPC / stdio
                                                 ▼
                                          ┌─────────────┐
                                          │  ldbd       │
                                          └──────┬──────┘
                                                 │  liblldb
                                                 ▼
                                              target
```

* Stdin/stdout of `ldb-dap` carries DAP frames (`Content-Length:`-
  prefixed JSON).
* Stdin/stdout of the spawned `ldbd --stdio --format json` carries
  line-delimited JSON-RPC.
* Stderr of both flows up to the operator.
* The shim's process model is one DAP session = one shim instance =
  one ldbd child. No multiplexing.

## Discovery order for `ldbd`

When `ldb-dap` starts it has to find the daemon. Order:

1. `--ldbd <path>` argument (explicit).
2. Anywhere on `PATH` (most installed setups).
3. `./build/bin/ldbd` (in-tree dev fallback, matches the `ldb` CLI).

If none resolves, the shim prints a specific error and exits 1.
Nothing forks if the daemon can't be located.

## Supported DAP requests (v0.1 of the shim)

The minimum useful set for VS Code's "attach to running process" and
"step through code with breakpoints" workflow.

| DAP request | LDB endpoint(s) | Notes |
|---|---|---|
| `initialize` | (no daemon call) | Returns capabilities; queues `initialized` event after the response (per DAP spec ordering). |
| `launch` | `target.open` + `process.launch` | Required arg: `program` (string path). Optional: `stopOnEntry` (bool). |
| `attach` | `target.create_empty` + `target.attach` | Required arg: `processId` (int). |
| `configurationDone` | (no-op) | Acknowledges end of configuration phase. |
| `setBreakpoints` | `probe.create({kind:lldb_breakpoint, action:stop, where:{file,line}})` per breakpoint | Each result carries `verified` (true on `probe.create` success) and `id` (probe_id). Failures put the daemon error into `message`. |
| `threads` | `thread.list` | Direct mapping. DAP `id` = LDB `tid`. |
| `stackTrace` | `thread.frames` | Allocates a stable `frame_id` per (tid, frame_index) so `scopes`/`evaluate` can recover the daemon-side coordinates. Also fills `instructionPointerReference` from frame `pc`. |
| `scopes` | (no daemon call) | Returns three fixed scopes per frame: Locals, Arguments, Registers, each with a freshly-allocated `variablesReference`. |
| `variables` | `frame.locals` / `frame.args` / `frame.registers` | Picked by which scope's `variablesReference` is being expanded. |
| `evaluate` | `value.eval` | Looks up `frameId` for context if provided. |
| `continue` | `process.continue` | Polls `process.state` until non-running (5s cap) and emits `stopped` or `exited`. |
| `next` / `stepIn` / `stepOut` | `process.step({kind: over\|in\|out})` | Daemon's step is synchronous, so the `stopped` event is emitted directly without polling. |
| `disconnect` | `process.detach` (default) or `process.kill` (if `terminateDebuggee=true`) + `target.close` | Emits `terminated`, then exits. |

### Deferred (not implemented in this slice)

- `setExceptionBreakpoints`, `setFunctionBreakpoints`, `setDataBreakpoints`
- `restart`, `terminate` (DAP terminate ≠ DAP disconnect with terminate)
- `goto`, `gotoTargets`
- `loadedSources`, `source`
- `completions`, `gotoLocation`
- Reverse-execution requests (no replay engine yet)
- Per-thread state events (we're stop-the-world today)
- `setVariable`, `setExpression`
- Disassemble request
- Memory read/write requests

The shim returns `success=false` with a specific `message` for any
deferred request. The IDE will gray out the corresponding UI.

## Capability advertisement

The `initialize` response is honest. Every supported feature is
advertised `true`; every unsupported feature is `false`. This lets the
IDE skip greying out the relevant menu items without us having to
guess at heuristics.

## Event sequencing

DAP requires specific ordering rules. The shim implements them:

* After the `initialize` response, an `initialized` event must arrive
  before the IDE will send `configurationDone`. The shim queues the
  event in the handler's result; the main loop emits it AFTER writing
  the response.
* After a `continue`, the IDE expects a `stopped` (or `exited`) event
  at the next stop. The shim's `on_continue` polls `process.state`
  with a 5s cap; the resulting state determines the event emitted.
  This is **polling-based**, not push-based — the daemon doesn't
  currently emit unsolicited events on its JSON-RPC channel. A
  follow-up will switch to a streamed events channel.
* After a `step`, the daemon's `process.step` is synchronous, so the
  shim emits the `stopped` event directly without polling.
* After a `disconnect`, a `terminated` event is emitted before the
  shim exits.

## Server-side `seq` numbers

DAP messages carry a `seq`. Per the spec, the server's `seq` counter
is independent of the client's: the IDE counts requests starting at 1
and the shim counts responses+events starting at 1. The shim never
re-uses the client's `seq` for its own outbound frames.

## Stdout discipline

Same rule that applies to ldbd:

> Stdout is reserved for the JSON-RPC channel.

For `ldb-dap`, stdout is reserved for the DAP channel. Logs go to
stderr. The daemon child's stderr is left attached so its log lines
flow up to the operator unchanged.

## Limits and known gaps

* **No push-based events from the daemon yet.** The shim simulates
  `stopped`/`exited` by polling `process.state`. A real-world IDE
  flow that watches a long-running process between steps will see no
  intermediate events. Adequate for attach + step + breakpoint; not
  adequate for "show me when the inferior crashes" UX.
* **Children of variables** aren't expanded. Every variable returned
  has `variablesReference: 0`. Structs and arrays appear as a single
  flat `value` string from the daemon's pretty printer.
* **`evaluate` requires a `frameId`** for context. Watch-style
  evaluations from the IDE's "Watch" panel without a frame context
  will use frame 0 of an arbitrary thread; this is rarely what the
  user wants. Will revisit when a multi-frame UX requirement
  surfaces.
* **No conditional breakpoints.** `probe.create` doesn't yet expose a
  predicate, and we explicitly say `supportsConditionalBreakpoints=false`.
* **One DAP session per shim process.** No multiplexing.

## VS Code launch.json example

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "LDB: attach to PID",
      "type": "ldb",
      "request": "attach",
      "processId": "${command:pickProcess}"
    },
    {
      "name": "LDB: launch program",
      "type": "ldb",
      "request": "launch",
      "program": "${workspaceFolder}/build/bin/myprog",
      "stopOnEntry": true
    }
  ]
}
```

To register `ldb-dap` as the adapter binary, add to your VS Code
`settings.json` (or via an extension's `package.json`
`debuggers` entry):

```json
{
  "ldb.adapter": "/usr/local/bin/ldb-dap"
}
```

The minimal "type":"ldb" extension is out of scope for this slice —
the shim is the binary the extension would invoke.

## Tests

* `tests/unit/test_dap_transport.cpp` — DAP `Content-Length:` framer
  unit tests (round-trip, malformed length, missing CRLF, short
  body, multiple back-to-back frames, sloppy bare-LF, case-
  insensitive header, ignored Content-Type, malformed JSON body).
  11 cases / 22 assertions.
* `tests/unit/test_dap_handlers.cpp` — every shipped handler against
  a stub `RpcChannel`. Asserts both the LDB-side calls made and the
  DAP-side response shape. 13 cases / 119 assertions.
* `tests/unit/test_dap_rpc_channel.cpp` — concrete subprocess
  channel against the real ldbd binary (built via CMake dependency).
  Verifies `describe.endpoints` round-trip and unknown-method error
  surface.
* `tests/smoke/test_dap_shim.py` — end-to-end via the sleeper
  fixture. Drives `initialize → attach → configurationDone →
  threads → stackTrace → scopes → variables → evaluate →
  disconnect` and verifies event sequencing.

## Future slices

| Item | Why deferred |
|---|---|
| Push-based events | Daemon needs an event channel on its JSON-RPC stream first. Track in the post-MVP roadmap. |
| Hierarchical variables | Daemon's `value.read` already returns `children`; a follow-up wires it to the DAP `variablesReference` mechanism. |
| `setExceptionBreakpoints` | Need an exception-breakpoint primitive in `probe.create` first. |
| `restart`, `terminate` | Independent of `disconnect`; semantics differ. Add when an IDE complains. |
| `setVariable` / `setExpression` | Daemon doesn't yet support write-back to memory through expressions. |
| Disassemble request | Daemon's `disasm.function` exists; map to DAP's `disassemble` once UX is clarified. |
| Conditional breakpoints | Needs `probe.create` to take a predicate. |
| Auto-generated capability list | Today's capability list is hand-curated against the spec. The roadmap suggests deriving it from `describe.endpoints`; a future slice can do the codegen. |
