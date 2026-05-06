# LDB Wire-Protocol Versioning

> Codifies the semver-on-the-protocol policy referenced in
> `docs/03-ldb-full-roadmap.md §4`. Wired end-to-end in the `hello`
> handshake (Tier 1 §3a). Source of truth for `kProtocolVersion*` is
> `src/protocol/version.h`.

## 1. What gets versioned

The wire shape — request params, response data, error codes — has its
own version, **separate from the daemon version**. The daemon version
moves on every release; the protocol version moves only when the wire
shape changes.

| | Daemon version | Protocol version |
|---|---|---|
| **Format** | semver `<major>.<minor>.<patch>` (e.g. `0.1.0`) | `<major>.<minor>` |
| **Bumps on** | every release | wire-shape changes only |
| **Lives in** | `LDB_VERSION_STRING` (CMake-baked) | `src/protocol/version.h` |
| **Reported as** | `data.version` in `hello` | `data.protocol.version` in `hello` |

There is no patch component on the protocol version. A bug fix that
keeps the wire shape identical advances the daemon version only.

## 2. Bump rules

### Daemon version (`LDB_VERSION_STRING`)

Bumps every release per standard semver:

- **Patch** (`0.1.0 → 0.1.1`): bug fix, no behavior change observable
  on the wire.
- **Minor** (`0.1.0 → 0.2.0`): new feature; protocol version may or
  may not move with it.
- **Major** (`0.x → 1.0`): stable line — first version with a
  long-term backward-compat commitment.

### Protocol version (`kProtocolVersionMajor.kProtocolVersionMinor`)

| Class | When to bump | Effect on `kProtocolVersionMinor` | Effect on `kProtocolVersionMajor` |
|---|---|---|---|
| **No change** | Bug fix, new endpoint addition, new optional response field, new optional request field — everything an old client can ignore | unchanged | unchanged (in practice we rebuild every release; the constants only move on real shape changes) |
| **Minor** | Backward-compatible additions that warrant advertising — e.g. a new view-descriptor option. Old clients still work. | **+1** | unchanged |
| **Major** | Breaking change: renamed field, removed endpoint, required-vs-optional flip, semantics change. Old clients must upgrade. | reset to `0` | **+1** |

A new endpoint is technically a wire-shape addition, but it costs
nothing to add and old clients can't call it anyway, so we don't bump
on every endpoint addition. Bump minor only when a *response shape*
or *required behavior* expansion is significant enough that a client
might want to gate on it.

### Pre-1.0 caveat

While `kProtocolVersionMajor == 0`, **minor bumps may be breaking.**
This matches the convention in cargo / Python packaging that 0.x
versions are pre-stable. Once we reach `1.0`, minor bumps are
guaranteed backward-compat.

## 3. The `hello` handshake

### Request

```jsonc
{ "id":"r1", "method":"hello",
  "params": { "protocol_min": "0.1" } }   // optional
```

`params.protocol_min` is the **client's floor** — the lowest version
the client is willing to talk to. It must match `^[0-9]+\.[0-9]+$`.

### Response

```jsonc
{ "id":"r1", "ok":true,
  "data": {
    "name":     "ldbd",
    "version":  "0.1.0",                  // daemon version
    "formats":  ["json"],                 // wire formats supported
    "protocol": {
      "version":       "0.1",             // current protocol
      "major":         0,
      "minor":         1,
      "min_supported": "0.1"              // oldest we'd still serve
    }
  }
}
```

### Negotiation rule

The daemon serves the request iff:

```
daemon_current_version >= client.protocol_min
```

That's it. `min_supported` is **informational metadata** — it tells
the client how far back this daemon's compat code reaches, but it
doesn't enter the satisfy check. A client floor below ours is always
satisfied (a daemon at `0.1` still talks `0.0` because there's no
shape difference to "forget"). For MVP, `min_supported == current`
because we ship exactly one minor; a future daemon that keeps
backward-compat code for older minors lowers it.

### Errors

| Condition | Code | Constant |
|---|---|---|
| `params.protocol_min` is not a string | `-32602` | `kInvalidParams` |
| `params.protocol_min` doesn't match the pattern | `-32602` | `kInvalidParams` |
| `protocol_min > current` | `-32011` | `kProtocolVersionMismatch` |

The `-32011` error message names both sides: e.g.
`"client requires protocol >= 0.2; daemon is 0.1"`. Don't parse the
message — gate on the code; the wording is documentation, not
contract.

### What's deferred

* **`protocol_max`** — a ceiling on what clients accept. Useful only
  when a multi-minor daemon exists. Defer until then.
* **Server-pushed migration hints** — the daemon could include a
  "preferred upgrade" pointer in the mismatch error data; defer.
* **Multi-minor daemon** — when we want `min_supported < current`,
  the affected handlers will need branching code. The constants in
  `src/protocol/version.h` are already shaped for it.

## 4. Negotiating from a client

A planning agent at session start should:

1. Send `hello` with the lowest `protocol_min` it can tolerate.
2. On `-32011`, log the daemon version and either upgrade itself or
   route to a different daemon.
3. On success, read `data.protocol.version` to decide which optional
   features to use.

The CLI in `tools/ldb/ldb` is schema-driven and reads
`describe.endpoints` for params, so it picks up the new `protocol_min`
field automatically. It currently sends no `protocol_min` in `hello`;
once we ship a daemon at a higher minor, we'll wire the CLI to send
its compatibility floor.

## 5. References

- `src/protocol/version.h` — the constants.
- `src/protocol/version.cpp` — the parser.
- `src/protocol/jsonrpc.h` — `ErrorCode::kProtocolVersionMismatch`.
- `src/daemon/dispatcher.cpp::handle_hello` — the negotiation logic.
- `tests/unit/test_protocol_version.cpp` — pure-protocol tests.
- `tests/unit/test_dispatcher_hello.cpp` — handshake tests.
- `tests/smoke/test_hello_handshake.py` — end-to-end.
- `docs/03-ldb-full-roadmap.md §4` — the original commitment.
