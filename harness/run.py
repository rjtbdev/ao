"""ao harness — single entry point for all validations.

Usage:
    python harness/run.py <name>              run one named validation
    python harness/run.py list                list every available validation
    python harness/run.py <name> --fresh      force re-run (ignore cache)

Output lands in artifacts/<YYYY-MM-DD-HHMMSS>/<name>/ with:
    stdout.log       everything the validation printed
    stderr.log       stderr
    summary.txt      one-line result + a few metrics
    metadata.json    exit code, duration, python version
"""
from __future__ import annotations

import argparse
import datetime
import json
import pathlib
import subprocess
import sys
import time
import importlib.util

ROOT = pathlib.Path(__file__).resolve().parent.parent
HARNESS_DIR = pathlib.Path(__file__).resolve().parent
ARTIFACTS = ROOT / "artifacts"
VALIDATIONS_DIR = HARNESS_DIR / "validations"


def _discover() -> dict[str, pathlib.Path]:
    """Return {slug: path_to_module} for every validation module in validations/."""
    VALIDATIONS_DIR.mkdir(parents=True, exist_ok=True)
    out: dict[str, pathlib.Path] = {}
    for p in sorted(VALIDATIONS_DIR.glob("*.py")):
        if p.name.startswith("_"):
            continue
        out[p.stem] = p
    return out


def _load_module(path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _run_one(name: str, mod_path: pathlib.Path) -> int:
    ts = datetime.datetime.now().strftime("%Y-%m-%d-%H%M%S")
    out_dir = ARTIFACTS / ts / name
    out_dir.mkdir(parents=True, exist_ok=True)

    start = time.perf_counter()
    mod = _load_module(mod_path)

    if not hasattr(mod, "run"):
        print(f"[harness] {name}: no run() function; skipping", file=sys.stderr)
        return 2

    stdout_path = out_dir / "stdout.log"
    stderr_path = out_dir / "stderr.log"
    summary_path = out_dir / "summary.txt"
    metadata_path = out_dir / "metadata.json"

    # Validations return (exit_code: int, summary_line: str, extra_metrics: dict)
    with open(stdout_path, "w", encoding="utf-8") as fo, \
         open(stderr_path, "w", encoding="utf-8") as fe:
        class TeeOut:
            def __init__(self, *streams): self.streams = streams
            def write(self, s):
                for st in self.streams: st.write(s)
            def flush(self):
                for st in self.streams: st.flush()
        orig_out, orig_err = sys.stdout, sys.stderr
        sys.stdout = TeeOut(orig_out, fo)
        sys.stderr = TeeOut(orig_err, fe)
        try:
            result = mod.run()
        except SystemExit as e:
            result = (int(e.code) if isinstance(e.code, int) else 1,
                      f"SystemExit: {e.code}", {})
        except Exception as exc:
            import traceback
            traceback.print_exc()
            result = (1, f"exception: {exc!r}", {})
        finally:
            sys.stdout = orig_out
            sys.stderr = orig_err

    duration = time.perf_counter() - start

    if isinstance(result, tuple) and len(result) == 3:
        exit_code, summary_line, metrics = result
    elif isinstance(result, int):
        exit_code, summary_line, metrics = result, "", {}
    else:
        exit_code, summary_line, metrics = 0, str(result), {}

    with open(summary_path, "w", encoding="utf-8") as f:
        status = "PASS" if exit_code == 0 else "FAIL"
        f.write(f"{status}  {name}  ({duration:.2f}s)\n")
        if summary_line:
            f.write(summary_line.rstrip() + "\n")
        for k, v in metrics.items():
            f.write(f"  {k}: {v}\n")

    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump({
            "name": name, "exit_code": exit_code, "duration_s": duration,
            "python": sys.version.split()[0], "timestamp": ts,
            "metrics": metrics,
        }, f, indent=2)

    status = "PASS" if exit_code == 0 else "FAIL"
    print(f"[{status}] {name} ({duration:.2f}s)  →  artifacts/{ts}/{name}/")
    if summary_line:
        print(f"       {summary_line}")
    return exit_code


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("name", nargs="?")
    ap.add_argument("--fresh", action="store_true")
    args = ap.parse_args()

    v = _discover()
    if not args.name or args.name == "list":
        print("available validations:")
        for slug in sorted(v):
            print(f"  {slug}")
        return 0

    if args.name not in v:
        print(f"[harness] unknown validation: {args.name}", file=sys.stderr)
        print(f"          available: {sorted(v)}", file=sys.stderr)
        return 2

    return _run_one(args.name, v[args.name])


if __name__ == "__main__":
    sys.exit(main())
