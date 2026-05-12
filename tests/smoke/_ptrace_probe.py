"""Shared skip-gate for smoke tests that need PTRACE_ATTACH.

Linux's `kernel.yama.ptrace_scope` sysctl defaults to 1 (restricted)
on most distros, which blocks `process.attach` against a non-child
inferior unless the daemon either runs as root or carries
CAP_SYS_PTRACE. We follow the same pattern as `_local_sshd_available`
in `tests/smoke/test_connect_remote_ssh.py`: probe at test start,
print SKIP, and exit 0 when the prerequisite isn't met. That keeps
ctest's notion of "green" stable across dev boxes with different
hardening profiles.
"""
import os
import shutil
import subprocess


def ptrace_attach_available(ldbd_path: str = "") -> bool:
    """Return True iff `target.attach` against a non-child pid will
    succeed on this host. False means callers should SKIP.

    Order:
      1. Non-Linux (no Yama LSM) → assume attach works.
      2. euid == 0 → root bypasses Yama entirely.
      3. /proc/sys/kernel/yama/ptrace_scope == 0 → unrestricted.
      4. ldbd binary carries cap_sys_ptrace → bypass.
      5. Otherwise restricted.
    """
    scope_path = "/proc/sys/kernel/yama/ptrace_scope"
    if not os.path.isfile(scope_path):
        return True
    try:
        if os.geteuid() == 0:
            return True
    except AttributeError:
        # geteuid not available on Windows; we don't run smokes there.
        return True
    try:
        with open(scope_path) as f:
            if f.read().strip() == "0":
                return True
    except OSError:
        pass
    if ldbd_path and os.path.isfile(ldbd_path):
        getcap = shutil.which("getcap")
        if getcap:
            try:
                out = subprocess.run(
                    [getcap, ldbd_path],
                    capture_output=True, text=True, timeout=5,
                ).stdout
                if "cap_sys_ptrace" in out:
                    return True
            except Exception:
                pass
    return False


def maybe_skip_ptrace(ldbd_path: str, test_name: str = "") -> None:
    """If ptrace attach isn't available, print SKIP and exit 0."""
    if ptrace_attach_available(ldbd_path):
        return
    label = test_name or "ptrace-attach test"
    print(
        f"SKIP: {label} — kernel.yama.ptrace_scope={_scope_value()} and "
        "ldbd lacks CAP_SYS_PTRACE. Set ptrace_scope=0 (`sudo sysctl "
        "kernel.yama.ptrace_scope=0`) or `sudo setcap cap_sys_ptrace+ep "
        f"{ldbd_path}` to enable."
    )
    raise SystemExit(0)


def _scope_value() -> str:
    try:
        with open("/proc/sys/kernel/yama/ptrace_scope") as f:
            return f.read().strip()
    except OSError:
        return "?"
