"""cli-build — build cli/hook_tool.exe and cli/syscall_monitor.exe.

Shells out to cli/build.bat and verifies both executables land next to it.
"""
from __future__ import annotations

import pathlib
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]

BUILD_BAT = ROOT / "cli" / "build.bat"
HOOK_EXE = ROOT / "cli" / "hook_tool.exe"
SC_EXE   = ROOT / "cli" / "syscall_monitor.exe"

MIN_SIZE_BYTES = 10_000


def run():
    if not BUILD_BAT.exists():
        return (1, f"missing {BUILD_BAT.relative_to(ROOT)}", {})

    print(f"[+] running {BUILD_BAT}")
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            ["cmd.exe", "/c", str(BUILD_BAT)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        return (1, "cli build timed out after 300s", {"timeout": True})
    duration = time.perf_counter() - t0

    for line in (proc.stdout or "").splitlines()[-25:]:
        print(line)
    if proc.stderr:
        for line in proc.stderr.splitlines()[-10:]:
            print(line)

    if proc.returncode != 0:
        return (1, f"build.bat returned {proc.returncode}",
                {"returncode": proc.returncode, "duration_s": round(duration, 2)})

    out = {}
    for name, path in [("hook_tool", HOOK_EXE), ("syscall_monitor", SC_EXE)]:
        if not path.exists():
            return (1, f"{path.name} missing after build",
                    {"duration_s": round(duration, 2)})
        size = path.stat().st_size
        if size < MIN_SIZE_BYTES:
            return (1, f"{path.name} is only {size} bytes",
                    {"duration_s": round(duration, 2), "size": size})
        out[f"{name}_size"] = size

    print(f"OK — hook_tool {HOOK_EXE.stat().st_size} B, "
          f"syscall_monitor {SC_EXE.stat().st_size} B, "
          f"built in {duration:.1f}s")
    return (0,
            f"hook_tool + syscall_monitor built in {duration:.1f}s",
            {"duration_s": round(duration, 2), **out})
