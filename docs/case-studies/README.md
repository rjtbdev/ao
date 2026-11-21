# case-studies

One markdown file per target application.

## Purpose

Case studies hold everything that would VIOLATE the core modularity rules
if it lived in `driver/`, `host/`, `cli/`, or `sdk/`:

- Application-specific sigs and AOB patterns
- Hardcoded VAs, offsets, struct layouts
- Prose describing what the target application does and how
- "This worked / this didn't" notes for that specific target

These files are reference material. The actual working code built against
a case study lives in a separate downstream repo that depends on ao.

## File naming

`<target-slug>.md`. Lowercase, kebab-case.

- `osu-stable.md` — osu! stable (Windows x86 game)
- `minecraft-java.md` — would hold Minecraft Java edition notes if we did it
- `firefox.md` — etc.

## Minimum content per case study

- **What the target is.** One paragraph. OS, arch, language, protections.
- **Known sigs.** Each sig gets a name, the AOB string, how to resolve
  the field VA from it (match-offset + displacement-offset), source of
  the sig (observed? inherited from another project? verified on which
  binary version?), and last-verified date.
- **Hook recipes.** For each useful hook: target VA source (which sig),
  what the hook does, what CFG slots it exposes, failure modes.
- **Lessons learned / rejected approaches.** Things that looked good but
  didn't work. Protects the next person from repeating them.

## Rules

- Case studies are reference, not code. If you find yourself writing
  code in a case study, move the code to a downstream repo and keep a
  pointer here.
- Sigs rot when the target application updates. Every sig entry carries
  a last-verified date and a target-version it was verified against.
  No ambiguity.
