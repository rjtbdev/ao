# host

User-mode C library. The typed, approachable surface above the raw
hypercall stub.

## Contents

- `ao_call.asm` — the `ud2` hypercall stub. Build with `ml64 /c ao_call.asm`.
- `ao_client.h` — ABI-exact mirror of the driver's hypercall header:
  magic value, command IDs, `AO_HYPERCALL()` SEH-protected macro, PH
  operand/opcode enums and script-builder macros.
- Thin typed wrappers around each hypercall return `AO_NOT_PRESENT`
  (= UINT64_MAX) when ao isn't loaded, so callers never crash from
  running outside the HV.

## Rules

- This is a library. No binaries ship from here.
- No target-specific code.
- Changes to `ao_client.h` must stay in lockstep with the driver's copy
  at `driver/aoPkg/Drivers/ao/ao_client.h`. If the two diverge, the
  user-mode tool and the driver will disagree about command IDs or ABI,
  and nothing will work. Treat the two copies as a single ABI contract.
