# ao

UEFI AMD-SVM hypervisor for invisible, scriptable process hooks. Ring -1.

Named for the sea turtle whose shell holds up the world in Chinese mythology —
every guest OS and user-mode tool built on `ao` runs on top of it, and
cannot see it from where they stand.

## What ao is

- A DXE driver that loads before Windows, takes over AMD-V on every CPU,
  keeps the OS running as a nested guest, and intercepts selected guest
  events.
- A primitive called **Option 7**: a split-page hook that leaves the
  original page bytes unchanged in the guest's read view and redirects
  dispatch when the CPU fetches an instruction at a specific VA. Invisible
  to user-mode scanners.
- A 128-insn **bytecode script engine (PH)** attached to each `(CR3, VA)`
  hook. Scripts read/write guest state, call native guest functions,
  and emit log entries.
- A user-mode **hypercall ABI** (`ud2` + magic) for installing hooks,
  reading/writing memory, resolving processes and modules, pushing config.

## What ao is NOT

- **ao has zero target-specific logic.** No game names, no sigs for any
  specific binary, no application-specific recipes, no case-study prose
  outside `docs/case-studies/`. Those live in downstream projects that
  depend on ao as a library.
- **ao is not a cheat framework.** It is a reverse-engineering and
  system-integration primitive. Its first serious consumer is an osu!
  tool (see `docs/case-studies/osu-stable.md`), but other consumers can
  and should live in separate repos.
- **ao does not ship with example sigs or scripts for any real target.**
  `examples/` contains only teaching demos against trivial test binaries.
  Real applications live outside this tree.

## Repo layout

```
ao/
├─ driver/          EFI DXE driver source (the hypervisor itself)
├─ host/            User-mode C library: hypercall stub + typed wrappers
├─ cli/             hook_tool — generic install/status/log CLI
├─ sdk/             Headers + helpers for downstream tools (PH script
│                   builder, typed hypercall wrappers, sig recipe schema)
├─ examples/        Teaching demos only. hello_hook against a test .exe.
├─ docs/
│  ├─ architecture.md        provider-neutral core design doc (the Bible)
│  ├─ case-studies/          notes on specific applications. Real sigs
│  │                         and recipes live here, not in core code.
│  └─ decisions/             ADRs — one short file per non-obvious call
├─ tests/
│  ├─ smoke/                 fast end-to-end tests, <60s total
│  ├─ golden/                known-input/known-output comparisons
│  └─ unit/                  focused unit tests for isolatable logic
├─ harness/                  single entry point: `harness run <name>`
└─ artifacts/                dated output of harness runs; gitignored
```

## Rules

Read [`docs/RULES.md`](docs/RULES.md) before contributing. The one that
matters most:

> No file in `driver/`, `host/`, `cli/`, or `sdk/` may contain the name
> of a specific application (osu, minecraft, etc.) or a sig for one.
> If it does, it belongs in `docs/case-studies/` or in a separate repo
> that depends on ao.

## Status

Freshly scaffolded. The functional code is being migrated from the
predecessor project (`hemlock`) with the osu-specific pieces split out
into case studies and downstream repos.
