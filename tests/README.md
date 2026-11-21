# tests

Three tiers. No more, no fewer. See `docs/RULES.md` Rule 3.

## smoke/

End-to-end, mocked where needed, full pipeline in under 60 seconds.
Each project's smoke test proves "the pipeline is not broken."

Expected files: `smoke_driver.py`, `smoke_cli.py`, etc. — each one
orchestrates one project's entry point and asserts a basic success
criterion.

## golden/

Known-input → known-output comparisons. The input is a committed
fixture; the output is a committed golden file; the test asserts
equality (modulo an allow-list of fields that are RNG-dependent).

Must have a documented procedure to regenerate goldens when the
code intentionally changes.

## unit/

Only for logic that is genuinely isolatable AND worth isolating.
Examples: PH opcode encoding/decoding, sig recipe parsing, AOB
pattern matching. NOT every function.

## Runners

Tests are invoked via the harness. Direct invocation works too but
the harness is authoritative:

    harness run tests/smoke
    harness run tests/golden
    harness run tests/unit
