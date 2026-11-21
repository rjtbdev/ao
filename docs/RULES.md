# ao — modular discipline rules

These rules exist so this repo doesn't rot the way most reverse-engineering
projects do. Read them once. Enforce them on yourself.

---

## Rule 1 — No target in core

No file in `driver/`, `host/`, `cli/`, `sdk/`, or `examples/` may contain:

- The name of a specific application (`osu`, `minecraft`, `chrome`, etc.)
- Any sig or AOB pattern for a specific application's code
- Any hardcoded VA, offset, or struct layout for a specific application
- Prose describing what a specific application does

If you find yourself wanting to add any of those, it belongs in one of:

- `docs/case-studies/<target>.md` — notes, sigs, recipes, lessons learned
- A separate downstream repo that depends on ao (e.g. `new-era/` for osu)

**This rule is what makes ao reusable.** Break it once and the next
consumer has to fork.

## Rule 2 — Docs stay true, or they're deleted

If the code changes and the doc is now wrong, the doc is a liability.

- Every PR that changes a public interface MUST update the corresponding
  doc in the same change.
- Every ADR in `docs/decisions/` is immutable once merged. If a decision
  is reversed, write a NEW ADR citing the old one.
- `docs/architecture.md` is the Bible. If a reader of it would be
  confused or misled by what they then find in code, the doc is broken
  and must be fixed before further work.

## Rule 3 — Tests are tiered, not uniform

Three tiers only:

- `tests/smoke/` — end-to-end, mocked where needed, full pipeline runs
  in under 60 seconds. Each project's smoke test proves "the pipeline
  is not broken."
- `tests/golden/` — known-input → known-output comparisons. Catch silent
  regressions. Must have a documented procedure to update the golden
  when the code is intentionally changed.
- `tests/unit/` — only for logic that is genuinely isolatable and
  worth isolating. Do NOT reflexively write a test for every function.

**No `tests/integration/` tier.** Integration gets tested by smoke +
golden + manual harness runs. Integration suites always rot.

## Rule 4 — The harness is the only runner

If you want to validate something, it lives under `harness/` and is
callable as `harness run <name>`. One entry point, one convention,
timestamped output in `artifacts/<date>/<name>/`.

Ad-hoc `python scripts/foo.py` validation scripts rot within a week.
Pay the tax of putting it in the harness now.

## Rule 5 — No scope creep in ao itself

ao is a hypervisor + a script engine + a hypercall ABI. That is all.

Things that are NOT ao, even if they'd be useful:

- A sigscan algorithm beyond the bare minimum needed by cli/host
- A memory introspection library (process enumeration, module parsing)
  beyond what Introspect.c already does
- A UI framework
- Anything that wraps a specific OS beyond Windows guest
- Anti-detection research beyond Option 7's existing invariants

Those things belong in `sdk/` (if general) or downstream repos (if
target-specific).

## Rule 6 — Downstream repos are first-class

Any application built on ao (new-era osu stuff, future projects) is a
separate repo that imports ao as a dependency. It does not get special
status in this tree beyond being mentioned in `case-studies/`.

If you catch yourself wanting to add a downstream project's sig to
this repo "temporarily," stop. Add it to the downstream repo and have
it reference back if needed.

---

## Enforcement

- Every PR touching `driver/`, `host/`, `cli/`, or `sdk/`: grep the diff
  for the name of any known target application. If matched, fail review.
- The `harness run self-check` validator (TBD) greps the whole tree for
  violations. Run before any sizable change.
- When in doubt, ask: "would a new consumer want to see this if they
  didn't care about [the application I'm thinking of]?" If no, it
  belongs downstream.
