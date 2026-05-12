# Embedded Python for User-Authored Probe Callbacks

> Companion to `docs/15-post-v1-plan.md` items **#9** (probe callbacks) and
> **#14** (frame unwinders); landed in v1.4 — see
> `docs/17-version-plan.md`. This doc is the design rationale; the
> reference for the implementation is `src/python/embed.{h,cpp}` and the
> recipe-store `python-v1` format in `src/store/recipe_store.{h,cpp}`.

## 1. Why embed Python at all

Probes today are C++-only — the orchestrator in
`src/probes/probe_orchestrator.cpp` runs a fixed set of capture actions
(`log_and_continue`, `stop`, `store_artifact`) with no extension point.
Recipes are sequences of pre-canned RPCs (`recipe-v1`) — also no
predicate or compute step.

The agent's investigation loop tends to want *both*: "when this breakpoint
fires, examine `register('rax')` and decide whether to keep going or
artifact-and-stop." Today the agent has to multiplex that decision over
many RPC round-trips. The cheaper answer is to let the agent author the
predicate once, ship it down, and have the daemon run it.

Two deliverables share the embedding cost:

- **#9** — user-authored Python probe callbacks (and, in v1.4, Python-
  authored recipes via the `python-v1` format).
- **#14** — Python frame unwinders for async runtimes that LLDB's
  default unwinder can't follow.

Embedding CPython once supports both.

## 2. Scope of the v1.4 phase-1 cut

This document covers what landed in v1.4. Phase-2 work — extending the
probe orchestrator's callback path to invoke `python-v1` recipes inline,
and wiring `process.set_python_unwinder` into LLDB's `SBUnwinder` — is
deferred and called out at the bottom.

What phase-1 lands:

1. CMake gate `LDB_ENABLE_PYTHON` (default `ON`; auto-disables with a
   notice if `python3-embed` is missing).
2. `ldb::python::Interpreter` and `ldb::python::Callable` in
   `src/python/embed.{h,cpp}` — the thin RAII wrapper around CPython.
3. New recipe format `python-v1` in `RecipeStore`. A `python-v1` recipe
   stores a Python module source string instead of an RPC call list; its
   `run(ctx)` function is invoked by `recipe.run` with a context dict.
4. `recipe.lint` accepts `python-v1` recipes and surfaces compile errors
   from `compile(body, '<recipe>', 'exec')`.
5. `recipe.run` for `python-v1` produces an artifact containing the JSON
   return value of the callable, with stdout/stderr captured into the
   artifact's meta (never leaked to fd 1).

## 3. Python version + pkg-config discovery

Target: **CPython 3.11+** via the `python3-embed` pkg-config module.

Discovery in `CMakeLists.txt`:

```cmake
option(LDB_ENABLE_PYTHON "Enable embedded Python probe callbacks" ON)
if(LDB_ENABLE_PYTHON)
  pkg_check_modules(LDB_PYTHON QUIET python3-embed>=3.11)
  if(NOT LDB_PYTHON_FOUND)
    message(STATUS
      "ldb: python3-embed (>=3.11) not found — disabling embedded Python")
    set(LDB_ENABLE_PYTHON OFF)
  endif()
endif()
```

When the gate is OFF the `python-v1` recipe format is rejected at
`recipe.create` time with `-32001 kNotImplemented`, the unit tests in
`test_embedded_python.cpp` are conditionally excluded via
`target_compile_definitions(... LDB_ENABLE_PYTHON=1)` so the file
compiles to an empty translation unit on OFF builds, and the
`smoke_recipe_python` ctest registration is gated by the same flag.

3.11 is the minimum because we depend on `PyObject_CallOneArg`,
sub-interpreter API stability we'll need in v1.5, and the `Py_GETENV`
behaviour. Debian/Ubuntu LTS (Jammy) ships 3.10 by default; the local
dev box and CI both have 3.12. Documenting 3.11+ as the floor; below
that the build auto-disables.

## 4. Interpreter lifecycle

**Init at first use, finalize at process exit.** The `Interpreter`
singleton is constructed lazily on the first `python-v1` recipe call
(or, in phase-2, the first probe callback registration). The daemon's
`main()` does NOT call `Py_Initialize` at startup — many sessions never
touch Python, and a 4–5 MB resident-set bump for the interpreter on
every short-lived `ldbd --stdio` invocation isn't worth it.

Finalization happens in the singleton's destructor at static-storage
teardown. CPython's `Py_Finalize` is documented as imperfect; we accept
the leak (the process is going away anyway) over the risk of
double-init crashes from late `Callable`-held PyObject references.

**GIL discipline.** The daemon dispatcher is single-threaded today, but
the embedding layer must not assume that — observers and (post-phase-2)
probe-event threads will need to call back into Python. Every
`Callable::invoke` acquires the GIL with `PyGILState_Ensure` and
releases on scope exit. The first init also calls
`PyEval_SaveThread` after `Py_Initialize` so subsequent Ensure/Release
pairs work correctly.

A `Callable` holds an owned `PyObject*` reference; its destructor
acquires the GIL (so it's safe to drop from any thread) and runs
`Py_DECREF` before release.

## 5. Sandbox — explicit non-decision

The plan calls this out: "Sandbox question resolved in design." The
resolution for v1.4 is **no sandbox**.

A `python-v1` recipe runs in the daemon's address space with full
Python power: `os.system`, `subprocess`, network sockets, the file
system, anything else `import` can reach. This matches the existing
trust model of the daemon — the agent driving JSON-RPC is *already*
trusted to send arbitrary `target.open` / `bpftrace` / shell-flavored
calls. A Python recipe is one more thing that runs with daemon
authority, not a privilege escalation over what the agent already has.

Specifically:

| Surface | Trust level | Equivalent existing surface |
|---|---|---|
| `python-v1` recipe `run(ctx)` | full daemon power | `bpftrace_engine.cpp` exec, observer shellouts |
| Future `process.set_python_unwinder` | reads target memory | LLDB SBAPI already does |
| Future probe-callback `python-v1` | runs in `ldbd` PID | C++-side `probe_orchestrator` callbacks |

What we lose by not sandboxing: a malicious recipe can `rm -rf /`,
exfiltrate the artifact store, install a backdoor. Same blast radius
as a `recipe-v1` containing a `target.exec --command "rm -rf /"` —
which the daemon already accepts.

What gates a v1.5 sandbox decision (if it happens):

- **Cheap option**: `RestrictedPython` (Zope's Python AST rewriter) +
  AST-time import allow-listing. Hard to make airtight; well-known
  bypasses through `__builtins__` mutation.
- **Real option**: PEP 684 sub-interpreters (3.12+) with their own GIL,
  cleared `sys.path`, restricted import set. Cleaner isolation; costs
  ~1 MB and a few ms per recipe-run; mature in 3.13.
- **Strong option**: out-of-process per-recipe sandbox via `seccomp` +
  the existing `transport/local_exec` machinery — like bpftrace runs
  today, but talking JSON-RPC over a pipe. Heavyweight; defers
  callback latency.

We do NOT pick one in v1.4. The decision is "trust the agent" — same as
`recipe-v1` shellouts and `bpftrace_engine`. Revisit when (not if) we
introduce multi-tenancy or a remote control plane.

## 6. JSON ↔ Python conversion

`Callable::invoke(json args) -> json result` converts:

| JSON shape | Python shape |
|---|---|
| `null` | `None` |
| `true` / `false` | `True` / `False` |
| integer | `int` |
| float | `float` |
| string | `str` |
| array | `list` |
| object | `dict` (str-keyed) |

The conversion is recursive and depth-bounded (1024) to defend against
hostile recipes that build self-referential return values. Non-finite
floats (`NaN`, `Inf`) round-trip as Python floats but JSON-encode to
`null` per nlohmann::json default — documented limitation.

Python `tuple` returns are coerced to JSON arrays. Custom objects, sets,
bytes, datetime — anything outside the table — produce a
`backend::Error` with kind `kInvalidParams` and a message naming the
type.

## 7. Error propagation

Python exceptions raised in `run(ctx)` are intercepted by
`Callable::invoke`. The traceback is rendered via `traceback.format_exc()`,
the exception type and message are extracted, and the whole thing is
packaged as:

```cpp
throw backend::Error("python: " + type_name + ": " + message);
```

…with the full traceback attached as the `error_data` field in the
JSON-RPC response (mapped through dispatcher to the `data` field of the
`-32000 kBackendError` envelope):

```jsonc
{
  "code": -32000,
  "message": "python: ValueError: oops",
  "data": {
    "exception_type": "ValueError",
    "exception_message": "oops",
    "traceback": "Traceback (most recent call last):\n  File ..."
  }
}
```

`SyntaxError` from `recipe.lint` (compile step) currently surfaces the
same shape as runtime exceptions — the wrapper captures `exception_type`
("SyntaxError"), the message, and a synthesised one-line traceback.
Structured `lineno` / `offset` / `text` fields are **deferred**: they
require extracting `SyntaxError.lineno` / `.offset` / `.text` attributes
from the value object before normalisation, which is a small additive
change but adds shape that no caller consumes yet. Phase-2 will land it
together with the first `recipe.lint` smoke that exercises malformed
Python. Until then `data` carries the same three fields as any other
Python exception:

```jsonc
{
  "code": -32602,
  "message": "python: SyntaxError: invalid syntax",
  "data": {
    "exception_type": "SyntaxError",
    "message": "invalid syntax",
    "traceback": "SyntaxError: invalid syntax"
  }
}
```

`-32602 kInvalidParams` for `SyntaxError`, `-32000 kBackendError` for
runtime exceptions. This matches the existing distinction between
malformed-input and runtime-failure that the dispatcher uses for
recipe-v1 path validation vs. recipe.run failures.

## 7a. Frame unwinders (post-V1 plan #14 phase-1)

The same `Callable` surface backs Python frame unwinders:

```
process.set_python_unwinder({target_id, body})  →  registers
process.unwind_one({target_id, ip, sp, fp})     →  invokes synchronously
```

The module must define `def run(ctx): ...`. `ctx` is a dict with
`{ip, sp, fp, registers?}`; the callable returns either `null` (fall
through to LLDB's default unwind) or a dict with `{next_ip, next_sp,
next_fp}`.

**Phase-1 stores the callable per target_id and exposes `unwind_one`
as a synchronous test endpoint** — agents and tests exercise the
unwinder without needing a real stopped process. **Phase-2 ships
`process.list_frames_python`**, an iterative driver that calls the
Callable until it returns `null`, returns an incomplete dict, hits
`max_frames` (default 32, hard-capped at 1024), or trips the
`(next_ip, next_sp)` cycle guard. Response carries the frames array
plus a `stop_reason` of `null_return | incomplete_return | max_frames
| cycle`.

The deeper hookup into LLDB's SBUnwinder — so the LLDB stack walker
itself calls into the Callable during ordinary `process.list_frames`
— remains deferred:

- It needs `SBUnwindPlan` interception via `SBLanguageRuntime` or a
  custom command-interpreter hook; the SBAPI surface is in flux.
- The contract (set / unwind_one / list_frames_python) is now
  pinned, so the SBUnwinder side can land independently without
  breaking any client.
- Until then, `list_frames_python` is useful for offline analysis
  and for validating a custom unwinder against a known-good trace.

Failure mapping:
- Compile error at registration → `-32602 kInvalidParams`.
- Unset target / unwinder not registered → `-32002 kBadState`.
- Runtime Python exception during invoke → `-32000 kBackendError`,
  same shape as `recipe.run`.

Lifetime: re-registration replaces. Map is cleared at dispatcher
shutdown (the Callable destructor acquires the GIL to `Py_XDECREF`
its module references).

## 8. Stdout discipline

CPython by default writes to fd 1, which is also the JSON-RPC channel.
On `Interpreter::init` we redirect:

```python
import io, sys
sys.stdout = io.StringIO()
sys.stderr = io.StringIO()
```

…and `Callable::invoke` snapshots both buffers post-call, truncates to
8 KiB (anti-OOM), and attaches them to the result. For `recipe.run`
they go into the produced artifact's `meta.stdout` /
`meta.stderr` fields; the artifact body carries only the return value
as compact JSON. The stringio buffers are RE-CREATED per invoke so
output doesn't bleed across calls — anti-confusion: a previous-call
`print` won't appear in a subsequent-call's artifact.

**Stdout written to fd 1 from inside Python** — e.g. `os.write(1, ...)`
— bypasses this and would corrupt the JSON-RPC channel. Documented as
a footgun; the standard `print()` is safe. Future hardening: `dup2`
fd 1 to a pipe on `Interpreter::init`, drain that pipe in
`Callable::invoke`. Not done in phase-1.

## 9. Recipe format `python-v1`

A `python-v1` recipe is an artifact whose envelope is:

```jsonc
{
  "format": "python-v1",
  "description": "...",
  "parameters": [...],     // same shape as recipe-v1
  "body": "def run(ctx):\n    return {'echoed': ctx.get('target_id')}\n"
}
```

- `body` is the full module source. The module must define a
  top-level callable named `run` taking one positional argument
  `ctx`. `run` is what `recipe.run` invokes.
- `parameters` re-uses recipe-v1's slot shape. At `recipe.run` time
  the caller's `parameters` map is passed straight through into
  `ctx["parameters"]`; substitution does NOT happen, because there's
  no string templating for Python source code (the agent can read
  `ctx["parameters"]["whatever"]` directly).
- `ctx` is at minimum `{ "parameters": { ... },
  "target_id": <optional int>, "recipe_id": <int> }`. Future
  phase-2 additions will populate `ctx["frame"]`, `ctx["event"]`
  for callback-flavored invocation.

The `recipe-v1` ↔ `python-v1` choice happens at `recipe.create` time
via an optional `format` parameter (default `"recipe-v1"`, preserves
backward compatibility). When `format = "python-v1"`:

- `body` is required (string).
- `calls` is forbidden (would be confusing — there are no calls).
- `parameters` is still accepted (for `ctx["parameters"]`).

`recipe.lint` dispatches on `format`:
- `recipe-v1`: existing placeholder lint.
- `python-v1`: compile via `compile(body, '<recipe:NAME>', 'exec')`,
  surface `SyntaxError` as a single warning at step_index=0.

`recipe.run` dispatches on `format`:
- `recipe-v1`: existing call-list replay.
- `python-v1`: import the body, fetch `run`, invoke with `ctx`,
  capture the return value, persist it as an artifact under the
  current store (build_id = `_recipes`, name =
  `recipe-result:<recipe-name>:<seq>`), include the artifact id and
  the return value in the response.

## 10. Hot-reload

`recipe.reload` for `python-v1` recipes reuses the existing file-backed
reload path (post-V1 plan #3) — re-read the file, replace the artifact.
The newly-stored recipe's `body` is re-compiled lazily at the next
`recipe.lint` or `recipe.run`; we do NOT cache the compiled `PyObject*`
across reloads, because we don't have a way to invalidate that cache
from outside the dispatcher.

The phase-2 work to attach a `python-v1` recipe to a probe callback
will need an explicit cache-invalidation hook so that a reload swaps
the live callable without stopping the probe; tracked in
`docs/17-version-plan.md` v1.5 watchlist.

## 11. Frame unwinders (`#14`) — sketch

Phase-1 of #14 lands in v1.4 only if the embed (this doc, §1–§10) is
green with time left over. The shape:

- `process.set_python_unwinder({target_id, recipe_id})` registers a
  `python-v1` recipe as the per-target unwinder. The recipe's
  `run(ctx)` is called with `ctx = {"ip": ..., "sp": ..., "fp": ...,
  "memory_read": <callable>, "reg_read": <callable>}` and must
  return either `null` (fall through to LLDB's default unwinder) or
  `{"next_ip": ..., "next_sp": ..., "next_fp": ...}`.
- For phase-1, the registration is recorded in the dispatcher's
  per-target state and surfaced as a `python_unwinder` field in
  `process.list_threads` provenance. The actual hook into LLDB's
  `SBUnwinder` SBAPI is phase-2; for phase-1 the test only confirms
  the registration round-trips.

## 12. Out of scope (deferred)

- **Probe-callback invocation.** The recipe.run path is the testable
  surface for v1.4; wiring `python-v1` into the live probe orchestrator
  callback path lands in v1.5 (cleaner thread-safety story once
  non-stop / displaced stepping is also in flight).
- **Sub-interpreter isolation.** §5. Re-evaluate when multi-tenancy is
  on the table.
- **stdout fd-redirect.** §8 mentions; relying on `sys.stdout`
  reassignment is enough for honest Python code.
- **Compile-cache invalidation across reload.** §10.
- **Python venv selection.** The daemon uses the system Python the
  build linked against (via `python3-embed`); switching to a venv at
  runtime via `PYTHONHOME` is documented but untested.
- **Real SBUnwinder hook for #14.** §11.

## 13. References

- `docs/15-post-v1-plan.md` §Tier 2 #9 and #14.
- `docs/17-version-plan.md` v1.4 row.
- `docs/08-probe-recipes.md` — recipe-v1 storage decisions, reused
  almost verbatim for python-v1.
- CPython embedding HOWTO:
  https://docs.python.org/3/extending/embedding.html
- PEP 684 (per-interpreter GIL) — gates v1.5 sandbox option.
