# ssh-remote daemon mode

Post-V1 plan item #11 from `docs/17-version-plan.md` / `docs/15-post-v1-plan.md`:
*"`ldbd` runs on the target via SSH-launched stdio."*

## Shape

The CLI (`tools/ldb/ldb`) grows three flags:

```
--ssh         [user@]host[:port]   spawn ldbd on a remote via ssh
--ssh-key     PATH                 forwarded as `ssh -i`
--ssh-options "raw -o ... str"     shlex-split and inserted before host
--ldbd-path   PATH                 where ldbd lives on the remote
                                   (default: `ldbd` on $PATH)
```

Environment override: `LDB_SSH_TARGET=user@host` overrides `--ssh`,
matching the `LDB_STORE_ROOT` precedence convention (env beats flag).
`--ssh` and `--ldbd` are mutually exclusive; passing both exits rc=2.

The resulting argv is:

```
ssh [-p PORT] [-i KEY -o IdentitiesOnly=yes] [...ssh-options...] \
    HOST -- REMOTE_LDBD --stdio --format FMT --log-level error
```

## Why no daemon changes

`ldbd --stdio` is already a transport-agnostic JSON-RPC peer over a byte
stream. ssh's exec channel is a byte stream. There is no protocol
mismatch, no framing change, no auth handshake to add. The CLI's
`spawn_daemon(spec, ...)` just `Popen`s `ssh ...` instead of `ldbd ...`
and the rest of the client (transports, REPL session, RPC, catalog
fetch) works unchanged.

Threading the spec — not just a path string — through `spawn_daemon`,
`fetch_catalog`, `do_rpc`, `run_repl`, and `_ReplSession` is the only
client-side surgery. The existing `--repl` automatically becomes
"persistent remote daemon" with no extra code.

## The `DaemonSpec` object

```python
class DaemonSpec:
    local_ldbd: str | None        # path to ldbd on this machine
    ssh_target: str | None        # user@host (port stripped)
    ssh_key: str | None           # -i forward
    ssh_options: str | None       # raw "-o A=B -o C=D" string
    remote_ldbd: str = "ldbd"     # remote-side ldbd command
```

The class is a plain bag — no behaviour beyond `is_ssh`. Argv
composition lives in `_build_ssh_argv(spec, fmt)` so it's unit-testable
in isolation.

## Failure matrix

| Failure                                          | Where it surfaces                                              |
|--------------------------------------------------|----------------------------------------------------------------|
| `ssh: command not found`                         | `Popen` raises `FileNotFoundError` → CLI prints + exits nonzero |
| ssh auth failure (wrong key, password prompt)    | ssh exits before responding; CLI sees EOF on JSON-RPC read     |
| Host-key prompt (TOFU) — interactive on stderr   | ssh blocks on tty input we don't provide; surfaces as EOF      |
| Remote `ldbd` missing on $PATH                   | `sh -c ldbd ...` exits 127; CLI sees EOF                       |
| Remote `ldbd` older than CLI                     | JSON-RPC `describe.endpoints` returns trimmed catalog          |
| Network drop mid-session                         | ssh terminates; next read raises broken-pipe                   |

For the auth/host-key cases, recommend non-interactive setup:

```sh
ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new $HOST true
```

before reaching for `ldb --ssh`. The CLI does not try to guess a
strict-host-key policy — users compose `--ssh-options` for that.

## Design notes

- **`--ssh` does not detect local vs remote.** If the user passes
  `--ssh localhost` and runs locally over ssh-to-self, it works.
  The CLI doesn't optimize this — the cost is one ssh round-trip on
  startup, and short-circuiting would create a flag-vs-actual-transport
  gap that would surprise users debugging connection issues.
- **Port stripping.** `_split_ssh_target` only strips a trailing
  numeric `:NNN`. IPv6 literals (`[::1]:22`) are not parsed; users
  with IPv6 should pass the port via `--ssh-options "-p 22"` for now.
  Documented limitation; not a v1.4 must-fix.
- **`--ldbd-path` defaults to bare `ldbd`.** Resolved by the remote
  shell's $PATH lookup; not by us. The remote may have ldbd at
  `/opt/ldb/bin/ldbd` (typical) or in `$HOME/.local/bin`. Users who
  installed via the agent-deploy story (#12 territory) get it on
  $PATH automatically.
- **No SSH connection multiplexing yet.** Each `ldb` one-shot
  invocation spawns a fresh ssh. The REPL (`--repl`) keeps one ssh for
  its whole lifetime, which is the right tool when latency matters.
  ssh's own ControlMaster (`-o ControlPersist`) is reachable via
  `--ssh-options` for users who want it.

## What's tested

`tests/smoke/test_ldb_cli_ssh.py` covers, via a shell shim on PATH:

1. argv composition — host parsing, `-p`, `-i` + `IdentitiesOnly=yes`,
   shlex-split `--ssh-options`, `--ldbd-path`, the `--` separator, and
   the trailing `--stdio --format json --log-level error` payload.
2. `LDB_SSH_TARGET` env-only path triggers ssh transport with no flag.
3. `--ssh` + `--ldbd` mutual exclusion exits rc=2 with the message.
4. End-to-end JSON-RPC round-trip via a shim that exec's local ldbd —
   proves `DaemonSpec` threads cleanly through `fetch_catalog` and
   `do_rpc`.

Real-ssh integration testing is not in CI: it would require a
configured remote (or passwordless ssh-to-localhost, which is what
`test_connect_remote_ssh.py` does). The shim-based test catches every
CLI-side regression that doesn't depend on real network/auth behaviour.

## Out of scope for v1.4

- Connection multiplexing / ControlMaster auto-setup.
- IPv6 literal parsing.
- Auto-installing `ldbd` on the remote — that's #12's deploy story.
- ssh agent forwarding policies (users compose `--ssh-options`).
- DAP shim's transport when run remotely — DAP is local-stdio only.
