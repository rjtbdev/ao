# examples

Teaching demos only. These exist so a new contributor can read one small
working thing and understand what ao does.

## What belongs here

- A trivial test binary (e.g. `test_target.exe`) built in-tree, whose
  bytes and behavior we control.
- A minimal hook against that binary that exercises one feature:
  - `hello_hook/` — simplest possible hook: PH_LOG on an entry, prints
    a line when fired.
  - `force_retval/` — hook returns `PH_RETCONT` after writing a constant
    into EAX. Shows the Option-7 single-step flip.
  - `native_call/` — PH_OP_CALL into the test target to invoke one of
    its own functions, confirms the call/resume state machine.

## What does NOT belong here

- Hooks against real applications. Those go in `docs/case-studies/`
  as notes, and in downstream repos as code.
- Anything long enough to need its own README beyond a few lines.
- Anything that depends on a specific external file the user doesn't
  have.

## Status

Placeholder. Will be populated once the ao driver is building and
runnable on dev hardware.
