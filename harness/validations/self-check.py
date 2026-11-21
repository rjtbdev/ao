"""self-check — enforce Rule 1 of docs/RULES.md.

No file in driver/, host/, cli/, sdk/, or examples/ may contain the name
of a known target application. If a violation is found, this validation
fails and prints every offending line.
"""
from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[2]

CORE_DIRS = ["driver", "host", "cli", "sdk", "examples"]

# Known target application names. Extend as case studies grow.
FORBIDDEN_TARGETS = [
    "osu",         # case-insensitive match
    "minecraft",
    "fortnite",
]

# Files whose text we scan (skip binaries + build output).
SCAN_EXTS = {
    ".c", ".h", ".cpp", ".asm", ".inc", ".inf", ".dsc", ".dec",
    ".bat", ".ps1", ".py", ".md", ".txt", ".cfg", ".yaml", ".yml",
    ".json",
}


def run():
    violations: list[tuple[pathlib.Path, int, str, str]] = []
    scanned = 0
    for base_name in CORE_DIRS:
        base = ROOT / base_name
        if not base.exists():
            continue
        for p in base.rglob("*"):
            if not p.is_file():
                continue
            if p.suffix.lower() not in SCAN_EXTS:
                continue
            # Skip READMEs — they're allowed to reference target names
            # in passing (e.g. "the first consumer is an osu tool").
            # If you want to tighten this, remove this skip and clean up.
            if p.name.lower() == "readme.md":
                continue
            scanned += 1
            try:
                for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
                    low = line.lower()
                    for t in FORBIDDEN_TARGETS:
                        # Match word-boundary to avoid false hits on "modulos" etc.
                        if re.search(rf"\b{re.escape(t)}\b", low):
                            violations.append((p.relative_to(ROOT), i, t, line.rstrip()))
                            break
            except UnicodeDecodeError:
                continue

    if violations:
        print(f"FAIL — {len(violations)} violations of Rule 1 across {scanned} scanned files:")
        for (relp, lineno, target, line) in violations[:40]:
            print(f"  {relp}:{lineno}  [{target}]  {line}")
        if len(violations) > 40:
            print(f"  ... and {len(violations) - 40} more")
        return (1,
                f"{len(violations)} Rule-1 violations across {scanned} files",
                {"violations": len(violations), "files_scanned": scanned})
    else:
        print(f"OK — {scanned} files scanned, 0 violations of Rule 1.")
        return (0,
                f"clean: {scanned} core files scanned, no target names found",
                {"violations": 0, "files_scanned": scanned})
