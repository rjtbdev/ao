# ADR 0001 — Rename hemlock to ao, split out osu-specific content

**Date:** 2026-11-20
**Status:** Accepted

## Context

The hemlock project was built around one specific case study (osu! stable).
The core framework — hypervisor, NPT model, Option 7 hook primitive, PH
script engine, hypercall ABI — is fully game-agnostic, but the repo
structure and documentation both bleed osu-specific content into the core
layer:

- `tools/osu_overlay/` and `tools/osu_menu/` live at the same tier as the
  generic `tools/hook_tool/`.
- `docs/hemlock-architecture.md` dedicates § 9 to osu as a worked example,
  including sigs, VAs, and recipes.
- Future targets (anything that isn't osu) have no clean place to live
  without inheriting osu's naming or getting a special-case subfolder.

The user asked specifically for the core framework to be modular and
reusable across game/exe targets, with no target-specific content baked
into core code or core docs.

## Decision

Rename the core framework from "hemlock" to **"ao"** and restructure:

1. The core framework lives at `C:\Users\riley\projects\ao\` with the
   layout documented in the top-level README: `driver/`, `host/`, `cli/`,
   `sdk/`, `examples/`, `docs/`, `tests/`, `harness/`, `artifacts/`.
2. Target-specific content (osu sigs, recipes, prose) moves out of core:
   reference notes live in `docs/case-studies/<target>.md`; working code
   lives in separate downstream repos (e.g. a `new-era/` umbrella for all
   osu-related consumers).
3. A `docs/RULES.md` codifies the modular-discipline rules, chief among
   them "no target-specific content in `driver/`, `host/`, `cli/`,
   `sdk/`, or `examples/`."
4. The hemlock repo itself is not deleted or renamed in place; migration
   happens by copying the generic parts into `ao/` and verifying the new
   structure before the predecessor is retired.

## Alternatives considered

- **Keep the hemlock name, split folders only.** Rejected: the name
  itself appears throughout code, build files, and docs. Rebranding is
  cheaper now than later, and a neutral mythological name reads better
  for a general-purpose framework.
- **Monorepo with all downstream projects inside ao/.** Rejected: it
  invites violations of Rule 1 (no target-specific content in core)
  because the boundary is just a folder, not a repo.
- **Keep everything in hemlock and add a `games/osu/` folder.** Rejected:
  pushes the same problem down one level. Same outcome in six months.

## Consequences

**Positive:**
- A new consumer (different game, firmware RE project, whatever) lands
  in a tree that already looks ready for them.
- `docs/architecture.md` can stand on its own as a general RE/HV framework
  document, citable in reports or shared with collaborators without
  implying it's an osu tool.
- Downstream repos are forced to be real libraries-of-ao, not fork-points.

**Negative:**
- Short-term churn: existing hemlock contributor familiarity is a cost
  until the new layout is internalized.
- Case-study notes split from code means contributors have to look in
  two places for a target. Mitigated by the case-study README naming
  convention and the downstream repo's README pointing back.

**Follow-ups:**
- Migrate hemlock's `driver/` sources into `ao/driver/` with every
  `hemlock*` identifier renamed to `ao*`.
- Migrate hemlock's `tools/hook_tool/` into `ao/cli/`.
- Write `docs/case-studies/osu-stable.md` with everything useful from
  hemlock's § 9 osu case study.
- Set up the osu umbrella repo (likely `C:\Users\riley\projects\new-era\`)
  and move `osu_overlay` / `osu_menu` / `new-era-relax` into it.
