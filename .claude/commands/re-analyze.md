Perform a reverse engineering investigation of a binary, live process, or core dump using LDB's full toolchain.

## Usage

```
/re-analyze [target] [goal]
```

- `target` — binary path (e.g. `/usr/bin/foo`), PID (e.g. `pid:31415`), or core file (e.g. `core:/var/cores/foo.core`)
- `goal` — optional free-form investigation objective (e.g. "find where the TLS certificate is validated")

If no arguments are provided, ask the user for the target and goal before proceeding.

## What you have available

**LDB CLI:** `tools/ldb/ldb` — schema-driven JSON-RPC client that spawns `ldbd --stdio` per call. Each invocation is one RPC call. Usage:

```bash
tools/ldb/ldb <method> [key=value ...]
tools/ldb/ldb <method> --help          # show params for a method
tools/ldb/ldb --help                   # list all available methods
```

**LDB daemon:** `build/bin/ldbd --stdio` — direct JSON-RPC if you need multi-call sessions or batching.

**Full endpoint catalog:** run `tools/ldb/ldb --help` to get the live list from the daemon.

## The reference RE workflow

Run these phases in order, adapting based on findings. Skip or extend phases based on the investigation goal.

---

### Phase 1 — Static orientation

```bash
tools/ldb/ldb target.open path="<binary_path>"
tools/ldb/ldb module.list
tools/ldb/ldb symbol.find name="<interesting_symbol>"      # repeat for suspects
tools/ldb/ldb type.layout name="<struct_name>"             # for interesting types
tools/ldb/ldb string.list section=".rodata" min_len=6
tools/ldb/ldb string.xref addr_or_text="<suspicious_string>"
tools/ldb/ldb disasm.function name="<function_name>"       # for callsites found via xref
```

**Goal:** build a map of interesting symbols, types, strings, and control flow before touching a live process.

**Save notable artifact findings as you go:**

```bash
tools/ldb/ldb artifact.store name="<label>" content='{"findings": ...}'
```

---

### Phase 2 — Dynamic analysis (live process or attach)

If the target is a running process or you need to trigger behavior:

**Attach to PID:**
```bash
tools/ldb/ldb target.attach pid=<pid>
```

**Open for remote debugging:**
```bash
tools/ldb/ldb target.connect_remote url="connect://host:port"
```

**Set breakpoint probes and capture data:**
```bash
tools/ldb/ldb probe.create kind="lldb_breakpoint" \
  where='{"function":"<func_name>"}' \
  capture='{"registers":["rdi","rsi"],"memory":[{"reg":"rdi","len":256}]}' \
  action="store_artifact" \
  artifact_name="<capture_label>"

tools/ldb/ldb process.resume
tools/ldb/ldb probe.events probe_id="<probe_id>" --view summary=true
```

**Read memory directly:**
```bash
tools/ldb/ldb mem.read addr=0x<addr> size=<bytes>
tools/ldb/ldb mem.dump_artifact addr=0x<addr> size=<bytes> name="<label>"
```

**Inspect threads and frames:**
```bash
tools/ldb/ldb process.threads
tools/ldb/ldb process.frame_values thread_id=<tid> frame=0
```

---

### Phase 3 — Network and OS-level observers

Run these in parallel with dynamic analysis when the investigation involves network, FDs, or child processes:

```bash
tools/ldb/ldb observer.net.tcpdump iface="<iface>" bpf="<filter>" count=200
tools/ldb/ldb observer.proc.fds pid=<pid>
tools/ldb/ldb observer.proc.list
```

**eBPF/uprobes (requires bpftrace, Linux only):**
```bash
tools/ldb/ldb uprobe.bpf function="<func>" program="<bpftrace_program>"
```

---

### Phase 4 — Artifact retrieval and correlation

Retrieve captured artifacts and relate them:

```bash
tools/ldb/ldb artifact.list
tools/ldb/ldb artifact.get name="<label>"
tools/ldb/ldb artifact.relate src_name="<a>" dst_name="<b>" rel="causally_follows"
```

---

### Phase 5 — Session export

When investigation is complete, export a portable record:

```bash
tools/ldb/ldb session.list
tools/ldb/ldb session.export id="<session_id>"
```

The `.ldbpack` bundle can be shared with others or re-opened later.

---

## Your investigation instructions

1. **Start with Phase 1** unless the target is a PID (then begin with `target.attach` and run static analysis against the mapped modules).

2. **Narrate as you go.** After each LDB command, interpret the output in one sentence before deciding the next step. Don't just dump raw JSON — extract the signal.

3. **Follow the goal.** Use the user's stated investigation objective to decide which symbols, types, strings, and functions to dig into. If no goal was given, produce a general reconnaissance summary (entry points, interesting strings, suspicious symbols, network/crypto indicators).

4. **Record findings as artifacts.** When you find something significant (a struct layout, a decoded buffer, a network pattern), store it via `artifact.store` so it's part of the session record.

5. **Produce a structured report** at the end:

   ```
   ## RE Investigation Report
   **Target:** <path or pid>
   **Goal:** <stated objective>
   **Session:** <session_id from session.list>

   ### Key Findings
   - <finding 1>
   - <finding 2>

   ### Interesting Symbols / Types
   | Symbol/Type | Address | Notes |
   |-------------|---------|-------|

   ### String Evidence
   | String | Xref'd From | Significance |
   |--------|-------------|--------------|

   ### Dynamic Observations
   - <breakpoint hits, memory captures, etc.>

   ### Network / OS
   - <tcpdump, FD, process observations>

   ### Artifacts Stored
   - <name>: <what it contains>

   ### Next Steps
   - <what a follow-on session should investigate>
   ```

6. **Export the session** at the end so findings are persistent.

---

## Tips

- `tools/ldb/ldb <method> --help` shows the JSON schema for any method's parameters — use it when unsure of field names.
- String xref is one of the most powerful entry points: find a string you see in traffic or error logs, xref it to find the function, then disasm that function.
- If `target.open` or `target.attach` returns a session ID, keep track of it — you'll need it for `session.export`.
- For large memory regions, use `mem.dump_artifact` rather than `mem.read` — it stores directly into the artifact store without going through JSON encoding.
- The `view` system limits output: pass `--view limit=20` to any list call to avoid flooding context.
