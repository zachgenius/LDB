# LDB Claude Code Skills

Installable [Claude Code skills](https://docs.claude.com/en/docs/claude-code/skills) that
expose LDB's reverse engineering capabilities to any user, in any repo.

## Install

Each skill lives in its own folder with a `SKILL.md` file. Drop the folder into
`~/.claude/skills/` and Claude Code will auto-discover it (no restart needed):

```bash
# Clone and symlink (recommended — picks up upstream updates)
git clone https://github.com/zachgenius/LDB ~/ldb
mkdir -p ~/.claude/skills
ln -s ~/ldb/skills/re-analyze ~/.claude/skills/re-analyze
```

Or copy a single skill manually:

```bash
mkdir -p ~/.claude/skills/re-analyze
curl -fsSL https://raw.githubusercontent.com/zachgenius/LDB/master/skills/re-analyze/SKILL.md \
  -o ~/.claude/skills/re-analyze/SKILL.md
```

Then in any Claude Code session, the skill is invoked automatically when its
description matches your request, or you can ask Claude to use it explicitly:

```
Use re-analyze on /usr/bin/target-binary — find where TLS certificates are validated
Use re-analyze on pid:31415 — trace what data gets sent to the C2 server
Use re-analyze on core:/var/cores/app.core — determine the crash cause
```

## Prerequisites

- [Claude Code](https://claude.ai/code) (any plan)
- [LDB installed](../docs/00-README.md) — the skill checks for `ldbd` and `ldb` on startup and prints build instructions if missing

## Available skills

| Skill | What it does |
|-------|--------------|
| [`re-analyze/`](re-analyze/SKILL.md) | Full 5-phase RE investigation against V1: static orientation → dynamic probing + tracepoints + predicates → network / BPF / perf observers → artifact capture → session record / replay / export. Covers static binaries, live PIDs, core dumps, and remote gdb-remote targets. |

## How it works

Claude Code loads each `~/.claude/skills/<name>/SKILL.md` and reads its YAML
frontmatter (`name`, `description`, `allowed-tools`, `argument-hint`) to decide
when the skill applies. When triggered, the body of `SKILL.md` becomes the
instructions Claude follows — driving LDB's JSON-RPC API to conduct the
investigation.

The skill is self-contained: it discovers `ldbd` and the `ldb` CLI automatically,
handles the case where LDB isn't installed yet, and produces a structured
investigation report at the end.

## Project-level use

If you're hacking on LDB itself, you can also expose the skill at the
project level by symlinking it into `.claude/skills/` inside this repo —
it will only activate in Claude Code sessions opened against this directory.
