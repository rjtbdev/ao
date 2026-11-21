# driver

The EFI DXE driver. Loads before Windows, takes over AMD-V on every CPU,
intercepts selected guest events.

## Contents (will land here on migration)

- `aoPkg/Drivers/ao/` — the driver module (output: `ao.efi`)
  - `ao.h` — core types (GUEST_STATE, SHARED_SVM_DATA, NPT_HOOK_REGION,
    PROCESS_HOOK_ENTRY, PH opcodes)
  - `ao_client.h` — user-mode hypercall ABI + PH script macros (mirrors
    the user-mode copy in `host/`)
  - `Setup.c` — HV init, NPT build, hook install primitives
  - `Host.c` — VMEXIT dispatch, NPF handler, #DB handler, hypercalls,
    PH interpreter
  - `Introspect.c` — EPROCESS walk, module resolution
  - `Svm.h` — SVM intercept bit defines

## Rules

- No target-specific code. See `docs/RULES.md` Rule 1.
- Changes here are tested via boot-to-dev-hardware (`harness run
  driver-smoke` will wrap this once the harness lands).
- `ao.h` and `host/ao_client.h` must stay bit-for-bit compatible on the
  hypercall ABI side. Breaking changes require an ADR.
