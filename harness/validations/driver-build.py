"""driver-build — rebuild ao.efi and assert it lands where it should.

Shells out to driver/aoPkg/tools/do_build.bat, confirms exit code 0,
and checks the resulting ao.efi file. Also sanity-checks the PE header
and MZ signature so a zero-byte or truncated build is caught.
"""
from __future__ import annotations

import pathlib
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]

BUILD_BAT = ROOT / "driver" / "aoPkg" / "tools" / "do_build.bat"
EDK2_DIR  = pathlib.Path(r"C:\Users\riley\Projects\canopy\edk2")
EFI_OUT   = EDK2_DIR / "Build" / "aoPkg" / "NOOPT_VS2026" / "X64" / "ao.efi"

# Minimum sane size — a real driver is >>50 KiB; anything smaller is a stub.
MIN_SIZE_BYTES = 50_000


def _looks_like_pe(data: bytes) -> tuple[bool, str]:
    """Return (ok, why). Confirms MZ + PE header + x64 machine type."""
    if len(data) < 0x100:
        return False, f"file too small: {len(data)} bytes"
    if data[:2] != b"MZ":
        return False, f"missing MZ signature (got {data[:2]!r})"
    # e_lfanew at offset 0x3C
    pe_off = int.from_bytes(data[0x3C:0x40], "little")
    if pe_off + 6 > len(data):
        return False, f"e_lfanew ({pe_off}) points past EOF"
    if data[pe_off:pe_off+4] != b"PE\0\0":
        return False, f"missing PE\\0\\0 at offset {pe_off}"
    machine = int.from_bytes(data[pe_off+4:pe_off+6], "little")
    if machine != 0x8664:  # IMAGE_FILE_MACHINE_AMD64
        return False, f"wrong machine type: 0x{machine:04X} (want 0x8664 / x64)"
    return True, f"MZ+PE, x64, pe_off=0x{pe_off:X}"


def run():
    if not BUILD_BAT.exists():
        return (1, f"missing {BUILD_BAT.relative_to(ROOT)}", {})
    if not EDK2_DIR.exists():
        return (1, f"EDK2 workspace not found at {EDK2_DIR}", {})

    print(f"[+] running {BUILD_BAT}")
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            ["cmd.exe", "/c", str(BUILD_BAT)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        return (1, "build timed out after 600s", {"timeout": True})
    duration = time.perf_counter() - t0

    # Always print build output so logs capture it.
    tail = (proc.stdout or "").splitlines()[-25:]
    for line in tail:
        print(line)
    if proc.stderr:
        print("--- stderr tail ---")
        for line in (proc.stderr.splitlines())[-15:]:
            print(line)

    if proc.returncode != 0:
        return (1,
                f"build.bat returned {proc.returncode} after {duration:.1f}s",
                {"returncode": proc.returncode, "duration_s": round(duration, 2)})

    if not EFI_OUT.exists():
        return (1,
                f"build succeeded but {EFI_OUT} is missing",
                {"duration_s": round(duration, 2)})

    size = EFI_OUT.stat().st_size
    if size < MIN_SIZE_BYTES:
        return (1,
                f"{EFI_OUT.name} is only {size} bytes (<{MIN_SIZE_BYTES})",
                {"size": size, "duration_s": round(duration, 2)})

    data = EFI_OUT.read_bytes()
    ok, why = _looks_like_pe(data)
    if not ok:
        return (1, f"ao.efi failed PE check: {why}",
                {"size": size, "duration_s": round(duration, 2)})

    print(f"OK — ao.efi {size} bytes, {why}, built in {duration:.1f}s")
    return (0,
            f"ao.efi {size} bytes, built in {duration:.1f}s",
            {"size": size, "duration_s": round(duration, 2),
             "path": str(EFI_OUT)})
