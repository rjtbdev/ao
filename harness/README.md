# harness

The one authoritative way to run anything validatable in this repo.

## Usage (once populated)

    harness run <name>           run a named validation
    harness list                 list every available validation
    harness run <name> --fresh   force re-run even if artifacts exist

## Convention

- Every validation has a short slug name.
- Running `harness run <name>` creates `artifacts/<YYYY-MM-DD-HHMMSS>/<name>/`
  and writes:
  - `stdout.log` — everything the validation wrote to stdout
  - `stderr.log` — stderr
  - `summary.txt` — one line of result + a few lines of key metrics
  - `metadata.json` — git commit, tool versions, duration, exit code

- A validation is self-contained: its failure criterion is its exit code.
  Nonzero = failure. Zero + a line in summary = success.

## Why not just `python scripts/foo.py`?

Because `scripts/foo.py` becomes `scripts/foo_v2.py` becomes
`scripts/foo_final.py` and then nobody runs any of them. The harness is
the discipline. Pay the tax of adding your validation here now; reap
the benefit of one place to look later.

## Status

Placeholder. First validation to land: `driver-smoke` — rebuilds the
driver and asserts it builds cleanly. Then `cli-smoke` — runs
`hook_tool status` against a stub and asserts it parses correctly.
