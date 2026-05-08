#!/usr/bin/env python3
"""Sanity check for `.github/workflows/ci.yml`.

CI is infrastructure, not a code feature; the workflow itself can only
truly be validated by GitHub Actions. The closest a local ctest run can
do is parse the YAML and assert the documented shape so a reviewer
notices structural rot before pushing.

Asserts:
- File exists and parses as valid YAML.
- Top-level `name`, `on`, `jobs` keys exist.
- `on` triggers only include pushes to `master` and manual dispatch.
- The Linux x86-64 build job runs on `ubuntu-24.04`, has a 30-minute timeout,
  uses `actions/checkout@v4`, installs the documented apt deps, sets
  `kernel.yama.ptrace_scope=0`, configures `ldbd` against
  `/usr/lib/llvm-18`, builds, and runs `ctest`.
- The Linux arm64 build job runs on `ubuntu-24.04-arm`, has a 45-minute
  timeout, and mirrors the same apt/LLDB/build/test shape.
The intent is not to lint every YAML detail — `actionlint` does that on
the runner side — but to fail loudly if a future edit silently drops
the steps the docs promise.
"""
import os
import sys


def usage():
    sys.stderr.write("usage: check_ci_yaml.py <repo_root>\n")
    sys.exit(2)


def fail(msg):
    sys.stderr.write(f"check_ci_yaml: FAIL: {msg}\n")
    sys.exit(1)


def main():
    if len(sys.argv) != 2:
        usage()
    repo_root = sys.argv[1]
    yaml_path = os.path.join(repo_root, ".github", "workflows", "ci.yml")
    if not os.path.isfile(yaml_path):
        fail(f"missing workflow file: {yaml_path}")

    try:
        import yaml  # PyYAML
    except ImportError:
        sys.stderr.write(
            "check_ci_yaml: PyYAML not available; "
            "skipping structural check (file presence verified)\n"
        )
        sys.exit(0)

    with open(yaml_path, "r", encoding="utf-8") as f:
        raw = f.read()

    try:
        doc = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        fail(f"YAML parse error: {exc}")

    if not isinstance(doc, dict):
        fail("top-level YAML is not a mapping")

    for key in ("name", "jobs"):
        if key not in doc:
            fail(f"missing top-level key: {key}")

    # PyYAML normalizes `on:` to True (boolean) because YAML 1.1 treats
    # the bareword `on` as a true literal. Accept either spelling.
    on_block = doc.get("on", doc.get(True))
    if on_block is None:
        fail("missing `on:` triggers block")
    if not isinstance(on_block, dict):
        fail("`on:` is not a mapping")
    if set(on_block.keys()) != {"push", "workflow_dispatch"}:
        fail(
            "`on:` must only contain push and workflow_dispatch triggers; "
            f"got {sorted(on_block.keys())!r}"
        )

    # Push trigger must be restricted to the master branch.
    push_block = on_block["push"]
    if not isinstance(push_block, dict):
        fail("`on.push` must be a mapping with branches")
    branches = push_block.get("branches")
    if branches != ["master"]:
        fail(f"`on.push.branches` must be exactly ['master']; got {branches!r}")
    if "tags" in push_block:
        fail("`on.push` must not include tags")

    jobs = doc["jobs"]
    if not isinstance(jobs, dict) or not jobs:
        fail("`jobs:` must be a non-empty mapping")

    # Identify the Linux build/test jobs by shape rather than name, so
    # a future rename doesn't false-fail.
    linux_job = None
    linux_arm_job = None
    for jname, jdef in jobs.items():
        if not isinstance(jdef, dict):
            fail(f"job `{jname}` is not a mapping")
        if jdef.get("if") != "github.ref == 'refs/heads/master'":
            fail(f"job `{jname}` must be guarded to run only on master")
        runs_on = jdef.get("runs-on", "")
        steps = jdef.get("steps", []) or []
        step_text = " ".join(
            s.get("run", "") + " " + s.get("uses", "")
            for s in steps if isinstance(s, dict)
        )
        runs_on_s = str(runs_on)
        if runs_on_s == "ubuntu-24.04" and "ctest" in step_text:
            linux_job = (jname, jdef, steps, step_text)
        if runs_on_s == "ubuntu-24.04-arm" and "ctest" in step_text:
            linux_arm_job = (jname, jdef, steps, step_text)

    if linux_job is None:
        fail("no job runs ctest on ubuntu-24.04")
    if linux_arm_job is None:
        fail("no job runs ctest on ubuntu-24.04-arm")

    _, ldef, lsteps, ltext = linux_job
    _, adef, _, atext = linux_arm_job

    if ldef.get("timeout-minutes") not in (30, "30"):
        fail(
            "Linux job missing 30-minute timeout-minutes "
            f"(got {ldef.get('timeout-minutes')!r})"
        )
    if adef.get("timeout-minutes") not in (45, "45"):
        fail(
            "Linux arm64 job missing 45-minute timeout-minutes "
            f"(got {adef.get('timeout-minutes')!r})"
        )

    required_substrings = [
        "actions/checkout@v4",
        "ninja-build",
        "liblldb-dev",
        "bpftrace",
        "tcpdump",
        "kernel.yama.ptrace_scope=0",
        "/usr/lib/llvm-18",
        "cmake --build build",
        "ctest",
    ]
    for needle in required_substrings:
        if needle not in ltext:
            fail(f"Linux job missing expected step content: {needle!r}")
        if needle not in atext:
            fail(f"Linux arm64 job missing expected step content: {needle!r}")

    # Failure-only artifact upload step.
    if "upload-artifact" not in ltext:
        fail("Linux job has no upload-artifact step (failure log capture)")
    if "upload-artifact" not in atext:
        fail("Linux arm64 job has no upload-artifact step (failure log capture)")

    print(f"check_ci_yaml: ok ({len(jobs)} jobs, {len(lsteps)} steps in linux job)")


if __name__ == "__main__":
    main()
