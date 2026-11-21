# cli

Generic command-line tools for ao. Each one works against any target
application — processes, modules, sigs, VAs are all arguments.

## Contents

- `hook_tool.c` — the main CLI.
  - `status`, `log`, `clear`, `unregister <slot>`, `diag_counters`
  - `install <process> <va_hex> <recipe> [args]`
  - `install_sig <process> <module> <pattern> <mask> <offset> <scan_mb> <recipe> [args]`
  - `sigscan <process> <module> <pattern> <mask> [scan_mb]`
  - Built-in recipes: `force_eax`, `force_eax_cont`, `mul_eax`, `add_eax`,
    `clamp_eax`, `log_args`, `log_eax_edx`. Add new generic recipes in
    the switch at the bottom of the file; target-specific recipes do NOT
    go here.
- `syscall_monitor.c` — logs every syscall a target process makes,
  in real time, via the ao hypercall ring buffer.
- `read_target_byte.ps1` — small helper that reads one byte at a VA
  from a target process. Used during sig discovery / validation.

## Build

```
ml64 /c ..\host\ao_call.asm
cl /O2 /W3 hook_tool.c ao_call.obj /link /out:hook_tool.exe
cl /O2 /W3 syscall_monitor.c ao_call.obj /link /out:syscall_monitor.exe
```

(Actual build flags & linker opts will live in `harness run cli-build`
once the harness lands.)

## Rules

- No target-specific code. No hardcoded process names, sigs, or VAs.
- Every command takes the target as an argument so the same binary works
  for any application.
- Extensions to the recipe list get a note in `docs/architecture.md`
  § 7.1.
