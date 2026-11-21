"""abi-sync — enforce that driver and host ao_client.h are byte-identical.

The hypercall ABI is defined once, duplicated into two files. If they
diverge, driver and user-mode will disagree about command IDs or magic,
and the whole stack silently breaks. This validation fails loudly.
"""
from __future__ import annotations

import hashlib
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]

DRIVER_COPY = ROOT / "driver" / "aoPkg" / "Drivers" / "ao" / "ao_client.h"
HOST_COPY   = ROOT / "host" / "ao_client.h"


def run():
    if not DRIVER_COPY.exists():
        return (1, f"missing {DRIVER_COPY.relative_to(ROOT)}", {})
    if not HOST_COPY.exists():
        return (1, f"missing {HOST_COPY.relative_to(ROOT)}", {})

    d_bytes = DRIVER_COPY.read_bytes()
    h_bytes = HOST_COPY.read_bytes()
    d_hash = hashlib.sha256(d_bytes).hexdigest()[:16]
    h_hash = hashlib.sha256(h_bytes).hexdigest()[:16]

    if d_bytes == h_bytes:
        print(f"OK — ao_client.h copies match ({d_hash}, {len(d_bytes)} bytes)")
        return (0, f"abi hash: {d_hash}", {"sha256_short": d_hash, "size": len(d_bytes)})

    print(f"FAIL — ao_client.h copies DIVERGE")
    print(f"  driver: {DRIVER_COPY.relative_to(ROOT)}  sha256={d_hash}  size={len(d_bytes)}")
    print(f"  host:   {HOST_COPY.relative_to(ROOT)}    sha256={h_hash}  size={len(h_bytes)}")
    print("  Fix: pick one as canonical, copy over the other, re-run.")
    return (1, f"abi divergence: driver={d_hash} host={h_hash}",
            {"driver_sha256_short": d_hash, "host_sha256_short": h_hash})
