# Process-Hook Scripting Layer

Author tiny bytecode scripts that fire on a specific (CR3, VA) pair in a
guest process. The script runs inside the HV during the NPF VMEXIT; it has
read/write access to the guest's 32-bit GPRs, EIP/EFLAGS, and guest memory
in the target process. No reboot to change behavior: re-send the script.

## When does a hook fire

1. You register a hook at `(target_cr3, target_va)`.
2. The HV installs a shadow-page NPT hook on the 4KB page containing `va`.
3. Guest executes anything on that page → NPF.
4. If `RIP == target_va` and `CR3` matches (or `target_cr3 == 0`), the script runs.
5. Depending on the terminating opcode, either:
   - **CONTINUE**: the original instruction executes once from the shadow page.
   - **SKIP**: EIP has been moved past the hook; original never runs.

From a usermode scanner's view the function's bytes are unchanged. Only a
timing side-channel is observable (roughly 5–20 µs per hook).

## Script shape

- Max 64 instructions per script (`PH_SCRIPT_MAX_INSNS`).
- Each instruction is 8 bytes.
- Max 256 instructions executed before forced abort.
- 16 scratch registers (`PH_R0`..`PH_R15`), each UINT64.
- A read-only internal flag register set by `CMP`, consumed by `JEQ`/`JNE`/`JLT`/`JGT`.

## Operands

| encoding       | meaning                                                                |
| -------------- | ---------------------------------------------------------------------- |
| `PH_R0..R15`   | script scratch, UINT64                                                 |
| `PH_GR_EAX..EDI` | guest 32-bit GPRs (writes zero the high 32 of the underlying RAX..RDI)|
| `PH_GR_EIP`    | guest EIP                                                              |
| `PH_GR_EFLAGS` | guest EFLAGS                                                           |
| `PH_GR_ESP`    | **read-only** — modify via `RETRET`                                    |
| `PH_GR_ARG1..ARG8` | pre-loaded from `[ESP+4*n]` at script start; writes commit on exit |

## Opcodes

| mnemonic         | encoding                        | effect                                                  |
| ---------------- | ------------------------------- | ------------------------------------------------------- |
| `NOP`            | –                               | nothing                                                 |
| `LOADI dst, imm` | `PH_LOADI`                      | `dst = imm` (zero-extended)                             |
| `MOV dst, src`   | `PH_MOV`                        | `dst = src`                                             |
| `ADD/SUB/MUL`    | `PH_ADD/PH_SUB/PH_MUL`          | `dst = a <op> b`                                        |
| `AND/OR/XOR`     | `PH_AND/PH_OR/PH_XOR`           | bitwise                                                 |
| `SHL/SHR dst,a,imm` | `PH_SHL/PH_SHR`              | logical shift                                           |
| `CMP a, b`       | `PH_CMP`                        | sets internal `LT/EQ/GT`                                |
| `JMP/JEQ/JNE/JLT/JGT delta` | `PH_JMP/...`         | relative branch (delta is instructions, signed)         |
| `READ1/2/4 dst, addr, disp` | `PH_READ1/PH_READ2/PH_READ4` | guest-VA read in target CR3                     |
| `WRITE1/2/4 addr, src, disp` | `PH_WRITE1/PH_WRITE2/PH_WRITE4` | guest-VA write                             |
| `LOG a, b`       | `PH_LOG`                        | push `(cr3, target_va, a, b)` to debug ring             |
| `RETCONT`        | `PH_RETCONT`                    | let original run (flips NCr3 to exec)                   |
| `RETSKIP bytes`  | `PH_RETSKIP`                    | `EIP = target_va + bytes`; original does not run        |
| `RETRET stacksize` | `PH_RETRET`                   | `EIP = [ESP]; ESP += 4 + stacksize`                     |
| `HALT`           | `PH_HALT`                       | stop (defaults to SKIP)                                 |

## Faults (safe degradation)

Any fault sets `last_fault_reason` on the entry and returns CONTINUE so the
guest never crashes. Reasons:

| code                       | meaning                                      |
| -------------------------- | -------------------------------------------- |
| `PH_FAULT_BAD_OPCODE`      | unknown op in script                         |
| `PH_FAULT_BAD_OPERAND`     | operand encoding out of range                |
| `PH_FAULT_READ_FAILED`     | guest-VA translation failed on `READ*`       |
| `PH_FAULT_WRITE_FAILED`    | guest-VA translation failed on `WRITE*`      |
| `PH_FAULT_CYCLE_LIMIT`     | hit 256-insn cap                             |
| `PH_FAULT_BAD_JUMP`        | jump target out of script                    |
| `PH_FAULT_WRITE_RO_REG`    | wrote to `ESP` or similar                    |

Check faults with `hook_tool status`.

## Recipes

### Force a return value

```c
ph_insn s[] = {
    PH_LOADI(PH_R0, 100),
    PH_MOV(PH_GR_EAX, PH_R0),
    PH_RETSKIP(1),          // 1-byte `ret`; use 3 if `ret 8`
    PH_HALT(),
};
ao_ph_register(cr3, va, s, sizeof(s)/sizeof(s[0]));
```

### Multiply the computed value before returning

```c
ph_insn s[] = {
    PH_LOADI(PH_R0, 2),
    PH_MUL(PH_R1, PH_GR_EAX, PH_R0),
    PH_MOV(PH_GR_EAX, PH_R1),
    PH_RETSKIP(1),
    PH_HALT(),
};
```

### Clamp a score

```c
ph_insn s[] = {
    PH_LOADI(PH_R0, 1000),
    PH_CMP(PH_GR_EAX, PH_R0),
    PH_JLT(2),                   // skip clamp if EAX < 1000
    PH_MOV(PH_GR_EAX, PH_R0),
    PH_LOG(PH_GR_EAX, PH_R0),    // record the clamp
    PH_RETCONT(),                // let `ret` run normally
    PH_HALT(),
};
```

### Modify an incoming stack arg before the function runs

```c
ph_insn s[] = {
    PH_MOV(PH_R0, PH_GR_ARG1),
    PH_ADD(PH_R1, PH_R0, PH_R0),       // double it
    PH_MOV(PH_GR_ARG1, PH_R1),         // commits to [ESP+4] on exit
    PH_RETCONT(),
    PH_HALT(),
};
```

### Modify an object field via `this` (`ECX` in managed `fastcall`)

If `this` is in ECX and the field you care about is at `this+0x1C`:

```c
ph_insn s[] = {
    PH_READ4(PH_R0, PH_GR_ECX, 0x1C),   // R0 = this->field
    PH_LOADI(PH_R1, 100),
    PH_ADD(PH_R2, PH_R0, PH_R1),        // field + 100
    PH_WRITE4(PH_GR_ECX, PH_R2, 0x1C),  // write back
    PH_LOG(PH_R0, PH_R2),
    PH_RETCONT(),
    PH_HALT(),
};
```

## Usermode CLI

```
hook_tool status                             # dump table state
hook_tool log                                # drain debug log ring
hook_tool install <proc> <va_hex> <recipe>   # install built-in recipe
hook_tool sigscan <proc> <module> <hex> <mask>
hook_tool unregister <slot>
hook_tool clear
```

Built-in recipes: `force_eax`, `mul_eax`, `add_eax`, `clamp_eax`,
`log_args`, `log_eax_edx`.
