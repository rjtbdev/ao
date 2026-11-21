# sdk

Headers and helpers for downstream tools. If someone is writing an
ao-powered tool in another repo, this is what they consume.

## Intended contents

- Re-export of `ao_client.h` (ABI) in a form that is stable across
  minor ao versions.
- A PH script builder — the set of `PH_LOADI(...)`, `PH_CALL(...)`, etc.
  macros that live next to `ao_client.h`, promoted into a cleaner
  public surface.
- A sig-recipe schema (likely a C struct + a Python dataclass mirror):
  a target name, AOB string, match-offset, displacement-offset, scan
  bounds, verified-against version + date. Downstream projects use this
  to catalog their sigs.
- Optional: Python bindings for `ao_client.h` via ctypes, so
  Python-based downstream tools don't have to roll their own.

## Rules

- SDK code is LIBRARY code. No command-line tools here. The CLI lives
  in `cli/`.
- No target-specific code.
- Breaking changes to SDK surface require an ADR and a version bump.

## Status

Placeholder. First concrete artifact: the sig-recipe schema, once the
first case study (osu-stable) lands and shows us what fields matter.
