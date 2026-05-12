# LDB Claude Code Skills

Installable Claude Code slash commands that expose LDB's reverse
engineering capabilities to any user, in any repo.

## Install

Copy a skill file to `~/.claude/commands/` and it becomes available as
a `/skill-name` command in every Claude Code session:

```bash
# One-liner install (re-analyze)
curl -fsSL https://raw.githubusercontent.com/zachgenius/LDB/master/skills/re-analyze.md \
  -o ~/.claude/commands/re-analyze.md
```

Or clone and symlink:

```bash
git clone https://github.com/zachgenius/LDB ~/ldb
mkdir -p ~/.claude/commands
ln -s ~/ldb/skills/re-analyze.md ~/.claude/commands/re-analyze.md
```

Then in any Claude Code session:

```
/re-analyze /usr/bin/target-binary "find where TLS certificates are validated"
/re-analyze pid:31415 "trace what data gets sent to the C2 server"
/re-analyze core:/var/cores/app.core "determine the crash cause"
```

## Prerequisites

- [Claude Code](https://claude.ai/code) (any plan)
- [LDB installed](../docs/00-README.md) — the skill checks for `ldbd` and `ldb` on startup and prints build instructions if missing

## Available skills

| Skill | Install | What it does |
|-------|---------|--------------|
| [`re-analyze.md`](re-analyze.md) | `curl .../re-analyze.md -o ~/.claude/commands/re-analyze.md` | Full 5-phase RE investigation against V1: static orientation → dynamic probing + tracepoints + predicates → network / BPF / perf observers → artifact capture → session record / replay / export. Covers static binaries, live PIDs, core dumps, and remote gdb-remote targets. |

## How it works

Claude Code loads `.md` files from `~/.claude/commands/` as slash commands. When you type `/re-analyze <args>`, Claude receives the skill's markdown as its instructions — with `$ARGUMENTS` substituted for whatever you typed after the command name — and drives LDB's JSON-RPC API to conduct the investigation.

The skill is self-contained: it discovers `ldbd` and the `ldb` CLI automatically, handles the case where LDB isn't installed yet, and produces a structured investigation report at the end.

## Project-level commands

If you're working in the LDB repo itself, the same skill is also available as a project-level command in `.claude/commands/re-analyze.md` — no install needed, it activates automatically when Claude Code opens this directory.
