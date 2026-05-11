#!/usr/bin/env python3
"""Token-budget regression CI gate (post-V1 plan item #7).

Drives a deterministic RPC sequence against ldbd, sums each response's
`_cost.tokens_est`, and compares the per-method totals against a
checked-in baseline. Fails if the absolute drift on the total exceeds
±10% of the baseline. The gate locks the agent-cost metric so future
features cannot silently inflate the wire surface — wire-shape changes
that materially move tokens must update the baseline in the same
commit.

`_cost.tokens_est` is defined in src/protocol/cost.cpp as
`(bytes + 3) / 4` — a deterministic function of the response payload
size, so identical RPCs across runs produce identical token counts
provided the fixture and daemon code are unchanged.

Baseline file: tests/baselines/agent_workflow_tokens.json

To regenerate the baseline locally (e.g. after an intentional schema
change), run:

    LDB_UPDATE_BASELINE=1 python3 tests/smoke/test_token_budget.py \
        <ldbd> <fixture> <baseline-path>

CI never sets LDB_UPDATE_BASELINE; the gate fails if observed totals
diverge.
"""
import json
import os
import subprocess
import sys
import tempfile


# How far observed totals may drift from baseline before the gate fires.
# 10% is generous enough to absorb minor wording / formatting noise but
# tight enough to catch unexpected envelope additions.
DRIFT_TOLERANCE = 0.10


def usage():
    sys.stderr.write(
        "usage: test_token_budget.py <ldbd> <fixture> <baseline-path>\n"
    )
    sys.exit(2)


class Daemon:
    """Minimal JSON-RPC pipe-driver. Mirrors the pattern in
    test_agent_workflow.py but keeps the cost-envelope intact so this
    test can inspect _cost.tokens_est on every response."""

    def __init__(self, ldbd, store_root):
        env = dict(os.environ)
        env["LDB_STORE_ROOT"] = store_root
        env.setdefault("LLDB_LOG_LEVEL", "error")
        self.proc = subprocess.Popen(
            [ldbd, "--stdio", "--log-level", "error"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
            bufsize=1,
        )
        self._next_id = 0

    def call(self, method, params=None):
        self._next_id += 1
        rid = f"r{self._next_id}"
        req = {
            "jsonrpc": "2.0",
            "id": rid,
            "method": method,
            "params": params or {},
        }
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            stderr = self.proc.stderr.read()
            raise RuntimeError(
                f"daemon closed stdout (stderr was: {stderr})"
            )
        return json.loads(line)

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


def tokens_of(response):
    """Pull `_cost.tokens_est` from a response, or 0 if missing.

    Some endpoints (errors, void responses) may omit the cost envelope.
    Treat absence as zero so the sum stays well-defined."""
    return int(response.get("_cost", {}).get("tokens_est", 0))


def run_sequence(ldbd, fixture, store_root):
    """Run the canonical budget-tested RPC sequence and return a
    `{method: tokens}` map. The sequence is small, deterministic, and
    exercises one read from each major surface (target, module, string,
    disasm) — enough to catch envelope regressions without being so
    large that the baseline takes a long time to settle."""
    d = Daemon(ldbd, store_root)
    per_method = {}

    def record(method, response):
        # If the same method is called twice (it isn't in this sequence,
        # but be defensive), sum the contributions.
        per_method[method] = per_method.get(method, 0) + tokens_of(response)

    try:
        record("hello", d.call("hello"))

        opened = d.call("target.open", {"path": fixture})
        record("target.open", opened)
        if not opened.get("ok"):
            raise RuntimeError(f"target.open failed: {opened}")
        target_id = opened["data"]["target_id"]

        record("module.list",
               d.call("module.list", {"target_id": target_id}))
        record("string.list",
               d.call("string.list",
                      {"target_id": target_id, "min_len": 6}))
        record("disasm.function",
               d.call("disasm.function",
                      {"target_id": target_id,
                       "name": "point2_distance_sq"}))
        record("describe.endpoints",
               d.call("describe.endpoints",
                      {"view": {"fields": ["method", "summary"]}}))
        record("target.close",
               d.call("target.close", {"target_id": target_id}))
    finally:
        d.close()
    return per_method


def load_baseline(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_baseline(path, observed_total, observed_per_method):
    payload = {
        "version": 1,
        "drift_tolerance": DRIFT_TOLERANCE,
        "total_tokens": observed_total,
        "per_method": dict(sorted(observed_per_method.items())),
        "note": "Regenerate with LDB_UPDATE_BASELINE=1 after an "
                "intentional wire-shape change.",
    }
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")


def main():
    if len(sys.argv) != 4:
        usage()
    ldbd, fixture, baseline_path = sys.argv[1:4]

    if not os.access(ldbd, os.X_OK):
        sys.stderr.write(f"ldbd not executable: {ldbd}\n")
        sys.exit(1)
    if not os.path.isfile(fixture):
        sys.stderr.write(f"fixture missing: {fixture}\n")
        sys.exit(1)

    store_root = tempfile.mkdtemp(prefix="ldb_smoke_tokenbudget_")
    try:
        per_method = run_sequence(ldbd, fixture, store_root)
        total = sum(per_method.values())

        if os.environ.get("LDB_UPDATE_BASELINE") == "1":
            write_baseline(baseline_path, total, per_method)
            print(
                f"token_budget: baseline written to {baseline_path} "
                f"(total={total}, methods={len(per_method)})"
            )
            return

        if not os.path.isfile(baseline_path):
            sys.stderr.write(
                f"token_budget: baseline missing at {baseline_path}.\n"
                "Run with LDB_UPDATE_BASELINE=1 once to create it.\n"
            )
            sys.exit(1)

        baseline = load_baseline(baseline_path)
        baseline_total = int(baseline["total_tokens"])
        tolerance = float(baseline.get("drift_tolerance", DRIFT_TOLERANCE))

        if baseline_total == 0:
            sys.stderr.write(
                "token_budget: baseline total is zero, refusing to "
                "compute drift\n"
            )
            sys.exit(1)

        drift = abs(total - baseline_total) / baseline_total
        if drift > tolerance:
            sys.stderr.write(
                f"token_budget: TOTAL DRIFT {drift * 100:.1f}% exceeds "
                f"tolerance {tolerance * 100:.0f}%\n"
                f"  baseline total: {baseline_total}\n"
                f"  observed total: {total}\n"
                f"  diff:           {total - baseline_total:+d}\n"
                "  per-method observed vs baseline:\n"
            )
            base_pm = baseline.get("per_method", {})
            all_methods = sorted(set(per_method) | set(base_pm))
            for m in all_methods:
                obs = per_method.get(m, 0)
                base = base_pm.get(m, 0)
                if obs != base:
                    sys.stderr.write(
                        f"    {m:30s} {base:6d} → {obs:6d} "
                        f"({obs - base:+d})\n"
                    )
            sys.stderr.write(
                "Update the baseline only if the change is intentional:\n"
                "  LDB_UPDATE_BASELINE=1 python3 "
                "tests/smoke/test_token_budget.py ...\n"
            )
            sys.exit(1)

        print(
            f"token_budget: total={total} (baseline={baseline_total}, "
            f"drift={drift * 100:.2f}%, tolerance="
            f"{tolerance * 100:.0f}%) — within budget"
        )
    finally:
        import shutil
        shutil.rmtree(store_root, ignore_errors=True)


if __name__ == "__main__":
    main()
