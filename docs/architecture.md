# ao: UEFI AMD-SVM hypervisor for invisible process hooks

**Audience.** This document is written for a software engineer who has never
seen this project and needs to be able to work on ao — add new hooks,
diagnose issues, port to new targets. Nothing is assumed beyond general
systems-programming literacy (C, Windows user/kernel interfaces, x86-64
basics, basic virtualization concepts). It is a full technical reference,
not a tour.

**Scope.** This is the Bible for the ao framework ITSELF. Nothing in here
is specific to any one target application; target-specific notes live in
`docs/case-studies/`. The first serious consumer of ao is an osu! tool
family; see `docs/case-studies/osu-stable.md` for that application's sigs
and recipes, and the separate `new-era/` repo for its working code.

---

## 0. Executive summary

- **ao is a UEFI DXE driver that loads before Windows.** It takes
  control of AMD-V (SVM) on every CPU, keeps the OS running as a nested
  guest, and intercepts selected guest events. Ring -1.
- The headline primitive is **Option 7**: a split-page hook that leaves
  the original page bytes unchanged in the guest's "read view," redirects
  dispatch when the CPU fetches an instruction at a specific VA, and uses
  a one-instruction single-step window to let strays on the same page
  execute from a shadow copy. A user-mode scanner reading the page via
  `ReadProcessMemory` sees the original bytes 100% of the time.
- Hooks are **scripted**: user-mode registers a 128-insn bytecode program
  attached to a `(CR3, VA)` pair. The script engine (PH) runs inside the
  VMEXIT handler with read/write access to guest GPRs, guest memory, and
  a 16-slot per-hook config array that user-mode updates via hypercalls.
- Scripts can **call native guest functions** (`PH_OP_CALL`): push args,
  redirect EIP, suspend the script; when the callee's `ret` lands back
  at the hook VA, the dispatch path recognizes the resume and continues
  the script on the next opcode.
- User-mode talks to the HV via a `ud2`-based hypercall ABI
  (`AO_MAGIC | cmd` in RAX, args in GPRs, HV catches `#UD`).

---

## 1. Repository layout

```
ao/
├─ driver/                    EFI DXE driver (the hypervisor itself)
│  └─ aoPkg/
│     ├─ Drivers/ao/
│     │  ├─ ao.h              core types (GUEST_STATE, SHARED_SVM_DATA,
│     │  │                    NPT_HOOK_REGION, PROCESS_HOOK_ENTRY, PH opcodes)
│     │  ├─ ao_client.h       user-mode hypercall ABI + PH script macros
│     │  ├─ Setup.c           HV init, NPT build, InstallNptHook, NptSplitTo4KB
│     │  ├─ Host.c            VMEXIT dispatch, NPF handler, #DB handler,
│     │  │                    hypercalls, RunProcessHookScript
│     │  ├─ Introspect.c      EPROCESS walk, module resolution
│     │  └─ Svm.h             SVM intercept bit defines
│     ├─ Applications/        standalone EFI applications (LogDump etc.)
│     └─ tools/               build scripts, QEMU runners
├─ host/                      user-mode C library
│  ├─ ao_call.asm             ud2 hypercall stub
│  └─ ao_client.h             mirror of driver's ABI header (bit-identical)
├─ cli/                       command-line tools (generic)
│  ├─ hook_tool.c             install/status/log/sigscan CLI
│  └─ syscall_monitor.c       live syscall log dumper
├─ sdk/                       (future) headers + helpers for downstream tools
├─ examples/                  (future) teaching demos against test binaries
├─ docs/
│  ├─ architecture.md         this file
│  ├─ RULES.md                modular-discipline rules
│  ├─ case-studies/           per-target notes (osu-stable.md, etc.)
│  └─ decisions/              ADRs
├─ tests/                     smoke / golden / unit
├─ harness/                   `harness run <name>` — one authoritative runner
└─ artifacts/                 timestamped harness output (gitignored)
```

Downstream applications (osu, minecraft, whatever) live in SEPARATE repos
that depend on ao as a library. They do not live in this tree beyond
their case-study notes.

---

## 2. HV lifecycle

### 2.1 How it loads

ao is a **DXE driver** — a UEFI module loaded by the firmware's DXE
dispatcher before the OS bootloader runs. Users drop `ao.efi` on the
ESP (EFI System Partition) and either:

- Add a `Load` command in the firmware's UEFI shell startup, or
- Chain-load it from an EFI shell script, or
- Use a firmware feature like `rEFInd`/`shim` to launch it, then
  continue to Windows.

At load time the driver's `_ModuleEntryPoint` runs (`UefiDriverEntryPoint`
lib → `DxeInitialize` in Setup.c) and performs:

1. CPU feature checks (AMD-V present, SVME supported, NPT supported).
2. Allocates `ROOT_CONTEXT` + `SHARED_SVM_DATA` (one SHARED_SVM_DATA per
   logical processor; HV paging tables; LAPIC intercept region; HV guard
   page; NPT read + exec trees; shadow page pool; HookMeta).
3. Builds identity-mapped NPT (`SetupNptBootstrap`) covering low 512GB
   and a high-canonical mirror.
4. Overlays a 4KB intercept on the LAPIC page (`SetupLapicNptIntercept`).
5. Copies the configured read NPT into the exec NPT
   (`SetupNptExec`) so both trees share the LAPIC + HV-guard
   modifications. The two trees then diverge only where hooks are
   installed.
6. For each logical processor: enables SVME in EFER, allocates a VMCB,
   configures intercepts (listed below), sets guest state from the
   current CPU state, and `VMRUN`s. From this instant the CPU is running
   as a guest of ao, and Windows boots normally inside it.

The `_ModuleEntryPoint` returns success; the firmware proceeds to boot
Windows, which has no idea it's virtualized.

### 2.2 What's intercepted

Set in `Setup.c` (`ConfigureVmcb`):

- **`InterceptCpuid`** — we hide the hypervisor-present bit in CPUID leaf
  1 ECX bit 31 and in leaves 0x40000000..0x400000FF.
- **`InterceptException |= (1<<1 | 1<<6)`** — `#DB` (debug) and `#UD`
  (invalid opcode). `#DB` drives Option 7's single-step flip-back. `#UD`
  is our hypercall channel.
- **`InterceptCrWrite.Cr3`** — currently off (we don't need every context
  switch), but easy to enable for process-creation detection later.
- **`InterceptMsr` for a handful of MSRs** — EFER guard (prevent nested VMs),
  LSTAR hook (syscall-log diag) when enabled.
- **NPT (`NpEnable = 1`)** — all guest memory accesses go through ao's
  NPT. Fundamental to everything.

All other VMEXITs (I/O, VMMCALL, etc.) are not intercepted and run
natively through the VMCB's default behavior.

### 2.3 Multi-CPU

Each logical processor gets its own VMCB and its own `GUEST_STATE`
(inside `CONTEXT_COLLECTION`, 4KB per CPU). Per-CPU state includes:

- `NptMode` — 0 if the CPU is currently running on the read NCr3, 1 if
  flipped to exec NCr3 for a single-step window.
- `NCr3UpdatePending`, `NCr3PendingValue` — cross-CPU TLB flush queue;
  if a hook install needs to force other CPUs onto the read NCr3 on
  their next VMEXIT, we queue it.
- `ExpectDbForFlipBack`, `GuestSavedRflagsTf`, `GuestSavedRflagsIf` —
  Option 7 single-step state (section 4).
- `CallActive`, `CallHookSlot`, `CallSavedEsp`, `CallSavedCr3`,
  `CallSavedEip`, `CallSavedScratch[16]`, `CallResumePc`, `CallRetValReg`
  — per-CPU `PH_OP_CALL` suspend state (section 5.4).

The per-CPU separation of CALL state is critical. An earlier design put
it in `PROCESS_HOOK_ENTRY` (per-hook, cross-CPU) and caused
`REFERENCE_BY_POINTER` BSODs when one CPU was mid-CALL and another CPU
hit the same TargetVa for an unrelated thread — the stale `CallSavedEsp`
was stamped into the second CPU's VMCB RSP. The lesson: anything stashed
between VMEXITs on a specific logical processor MUST live per-CPU.

### 2.4 Shutdown

In practice ao does not exit. A reboot takes it out of memory and the
firmware doesn't reload it (unless the user re-installed it to
auto-load). There is no graceful "unload Windows's HV guest" path.
Rebooting is how you test a new driver build.

---

## 3. Memory model: the two NPT trees

ao maintains **two Nested Page Table trees** per guest, named for their
role at hook sites:

- **`g_ReadNcr3Pa`** (sometimes via `g_ShadowNcr3Pa` indirection — see
  below) — the "normal" tree the guest runs on. Identity-mapped except at
  hooked pages, where the hooked page is marked **NX** (no-execute) so
  that any instruction fetch at the hooked page triggers an NPF.
- **`g_ExecNcr3Pa`** — a sibling tree used during single-step windows.
  At hooked pages the exec tree maps the **shadow page** (a copy the HV
  controls) with execution enabled. Reads on this tree still see the
  shadow page.

Because the shadow page is byte-identical to the original in our
"invisible" model (section 4), a guest reader on either tree sees the
same bytes. The difference is purely which physical frame the CPU
fetches instructions from during the one-instruction single-step
window.

### 3.1 Why two trees? Why not just mark pages R/X/N?

Because AMD NPT does not have separate Read and Execute bits — it has
Valid, Writable, User, and NX (bit 63). We cannot say "allow read, trap
exec" and simultaneously "allow exec, trap read" in a single tree. So we
build two trees:

| Tree           | Hooked-page PTE                     |
|----------------|-------------------------------------|
| Read (default) | original PFN, NX=1 (fetch → NPF)    |
| Exec (flipped) | shadow PFN, NX=0 (fetch → shadow)   |

The CPU is on the read tree normally. When a hook dispatches, the HV
either (a) emulates the instruction entirely in the VMEXIT and never
runs the original (stays on read tree), or (b) flips to the exec tree
with `EFLAGS.TF=1` so the CPU executes exactly one instruction from the
shadow page then takes a `#DB`, which we handle by flipping back to the
read tree. See section 4.

### 3.2 `NPT_HOOK_REGION`

Hooks live in a fine-grained region inside each tree
(`Svm->HookRead` and `Svm->HookExec` in `SHARED_SVM_DATA`). The region
provides fully-populated 4KB granularity around hooked pages, while the
rest of guest memory remains covered by 2MB or 1GB leaves.

```c
typedef struct _NPT_HOOK_REGION
{
    PT_ENTRY_4KB   PtArr[NPT_HOOK_SLOT_COUNT][PAGE_TABLE_ENTRY_COUNT];
    //             16 × 4KB — one PT per hooked 2MB range (up to 16 2MB slots)
    PML4_ENTRY_2MB Pd[NPT_HOOK_1GB_SLOT_COUNT][PAGE_TABLE_ENTRY_COUNT];
    //              8 × 4KB — ONE PD PER HOOKED 1GB RANGE
    UINT64         TwoMbBase[NPT_HOOK_SLOT_COUNT];
    UINT64         OneGbBase[NPT_HOOK_1GB_SLOT_COUNT];
    UINT8          Pad[...];
} NPT_HOOK_REGION;
```

`NptSplitTo4KB` (Setup.c) finds or allocates a `Pd` slot by matching
`oneGbBase`, then finds or allocates a `PtArr` slot by matching
`twoMbBase`, then patches the specific PT entry for the hooked 4KB page.

**Historical note.** Earlier versions had `Pd[512]` (one PD total). When
a second hook landed in a different 1GB region, the install's 2MB-leaf
fill loop would rewrite that single PD for the new 1GB, causing the
first hook's PDPT entry to point at a PD that now described the new
1GB — meaning writes to hook #1's 1GB landed on wrong physical frames
(often kernel objects → `REFERENCE_BY_POINTER` BSOD). Fixed by giving
each 1GB its own PD slot.

### 3.3 Shadow pages

Shadow pages live in `Svm->ShadowPages[NPT_SHADOW_COUNT][4096]`. Each is
a plain 4KB identity-mapped page of host RAM. `InstallNptHook` copies
the original guest page into the next free shadow page, points the exec
tree's PT entry at the shadow's PFN, and points the read tree's PT entry
at the original PFN with NX=1. No modification is made to the shadow
content — this is what makes the hook "invisible" in the Option 7 sense.
Older/alternative hook styles that patch the shadow with `0xCC` or
substitute instruction bytes are detectable by a user-mode scanner
because they differ from the original; Option 7 keeps them identical.

### 3.4 Lazy NPT population

Windows allocates new physical memory regions (new processes starting,
DLLs mapping, etc.) that weren't present at ao init time. The NPF
handler fills these in lazily:

- Read tree: `HandleNestedPageFault` (Host.c) sees an NPF on a `P=0` PDPT
  entry and synthesizes an identity 1GB leaf.
- Exec tree: likewise, EXCEPT we must never copy a non-leaf PDPT entry
  from the read tree (if it's non-leaf, it's a hook split that belongs
  to `HookRead`'s PD — the exec tree would walk through wrong PFNs). If
  the read-side entry is non-leaf, the handler synthesizes a fresh
  identity 1GB leaf for the exec side instead.

See Host.c near line 3908. This gate is the complement to the
per-1GB-PD fix above.

---

## 4. Option 7: the invisible hook primitive

This is the headline. Pay attention.

### 4.1 Problem

You want to intercept execution at a specific VA in a specific process.
You cannot modify any byte at that VA because the guest might
`ReadProcessMemory` the page at any time and detect the modification.
You cannot stay on the "exec allowed" tree because then execution of
unrelated instructions on the hooked page (strays) must also be
intercepted (defeats the point) or run from a potentially-modified
shadow (detectable). You need a model where:

- Guest reads of the hooked page always see the original bytes.
- Guest fetches at the HOOKED VA cause the HV to run a script.
- Guest fetches at OTHER instructions on the same page execute normally.
- A separate CPU reading the page at any time, in parallel with the hook
  firing, sees the original bytes.

### 4.2 Solution

Mark the hooked 4KB page NX in the read tree. That means:

- **Any instruction fetch anywhere on the page** causes an NPF. Reads
  are fine and see original bytes.
- When NPF fires, examine `RIP`:

**(a) RIP is the hook VA.** Dispatch the PH script
(`TryDispatchProcessHook` → `RunProcessHookScript`). The script either
emulates the original instruction (`PH_OP_RETCONT` via a dedicated
emulator like `PhEmulateHookedInstruction` for simple ops like `RET`,
`MOV r/m32, r32`) or indicates "run the real original":

1. Save guest `EFLAGS.TF` and `EFLAGS.IF`.
2. Flip this CPU's NCr3 to the exec tree (`PhArmExecFlipWithSingleStep`).
3. Set `EFLAGS.TF=1` (single step), clear `EFLAGS.IF` (critical — stops
   interrupts preempting the single step), clear `EFLAGS.RF`.
4. Set `ExpectDbForFlipBack=1`.
5. VMRUN. CPU executes ONE instruction from the shadow (byte-identical
   to the original). Then `#DB` fires.
6. `HandleDebugException` sees `ExpectDbForFlipBack=1`, flips back to
   the read tree, ALWAYS clears TF (never re-injects a guest's prior
   TF — doing so caused crashes), restores IF, clears
   `ExpectDbForFlipBack`, returns. VMRUN continues.

**(b) RIP is some other address on the page (stray).** Same
"flip + single-step" sequence as above. One instruction runs from the
shadow, then flip back.

### 4.3 Why it's invisible

- The read tree never changes its hooked-page mapping. Any
  `ReadProcessMemory` from any thread reads the ORIGINAL PFN. This has
  been empirically validated (hundreds of consecutive reads during live
  hook activity → always original bytes).
- The exec-tree exposure is one instruction long. For another CPU to
  "catch" the exec-tree mapping, it would have to simultaneously fault
  on the hooked GPA during that specific nanosecond, AND be able to
  observe the physical frame mapping (requires ring-0 or lower). User-
  mode cannot.
- The HV never writes to the guest's physical memory under the hook.
- The guest's `#UD`/`#BP`/`#DB` handlers, module list, PEB, handle
  table are all unchanged. The hook has zero in-process footprint.

### 4.4 Critical invariants

Breaking any of these will crash the guest or make the hook visible.
If you touch the Option-7 code paths:

1. **Always clear `EFLAGS.TF` in `HandleDebugException`.** Do not restore
   a "saved guest TF" from before the arm-single-step. The guest almost
   never has TF on, and injecting a `STATUS_SINGLE_STEP` into the guest
   on flip-back kills the process.
2. **Clear `EFLAGS.IF` during the single-step window.** Without this, a
   timer interrupt can arrive between VMRUN and the single-stepped
   instruction; the kernel ISR runs on the exec tree (one instruction
   with the hook region's NX=0), and the CPU can reach the hook VA
   through the ISR path without a dispatcher, so the hook "misses" (~50%
   rate without this fix).
3. **Safety net at end of `HandleVmExit`.** If `ExpectDbForFlipBack=1`
   and the exit reason wasn't `VMEXIT_EXCEPTION_DB`, unconditionally flip
   back to the read tree and clear TF/restore IF. Covers the case where
   the single-step was swallowed by a different exit path.
4. **`#DB` intercept bit `(1U<<1)` must be set in `InterceptException`.**

### 4.5 Alternative paths and why we don't use them

- **`0xCC` byte-trap in the shadow** — simpler but detectable (RPM sees
  `CC`). We used this early, got caught by a simple polling script,
  removed it.
- **Hardware breakpoints (DR0-7)** — detectable (`GetThreadContext`,
  `NtGetContextThread`), per-thread, limited slots.
- **Software int3 / jmp overlay on the real page** — detectable, breaks
  page hashes.

Option 7 is the winning design.

---

## 5. The PH script engine

User-mode registers a hook by sending a script. Scripts run inside the
NPF VMEXIT handler when the hook fires, with full access to guest state.

### 5.1 Hook entry

```c
typedef struct _PROCESS_HOOK_ENTRY
{
    UINT32            Active;
    UINT32            InsnCount;
    UINT64            TargetCr3;     // 0 = any process
    UINT64            TargetVa;      // RIP-exact match
    UINT64            TargetGpa4K;   // page we NPT-hooked
    UINT64            HitCount;
    UINT64            LastFaultPc;
    UINT32            LastFaultReason;
    UINT32            Reserved;
    UINT32            Config[16];    // UINT32 slots for user-mode params
    UINT32            CfgPad;
    PROCESS_HOOK_INSN Script[128];   // 8 bytes each = 1024 bytes
} PROCESS_HOOK_ENTRY;
```

`PROCESS_HOOK_MAX = 8` entries max.

### 5.2 Instruction encoding

```c
typedef struct {
    UINT8  op;    // PH_OP_*
    UINT8  dst;   // operand register encoding
    UINT8  a;     // operand A
    UINT8  b;     // operand B or nargs
    UINT32 imm;   // immediate / displacement / jump delta / packed arg encodings
} ph_insn;        // 8 bytes
```

### 5.3 Operand classes

| Range       | Name            | Meaning                                       |
|-------------|------------------|-----------------------------------------------|
| `0x00-0x0F` | `PH_R0..R15`    | Script-local scratch (UINT64)                 |
| `0x10-0x19` | `PH_GR_EAX..EIP`| Guest 32-bit regs (EAX/ECX/EDX/EBX/ESP/EBP/ESI/EDI/EIP/EFLAGS) |
| `0x20-0x27` | `PH_GR_ARG1..8` | Stdcall/cdecl stack arg shadow (preloaded `[ESP+4..ESP+32]`) |
| `0x30-0x3F` | `PH_CFG0..CFG15`| Per-hook UINT32 config slots, user-mode writable |

Reads of `PH_GR_ESP` return the current ESP. Writes to `PH_GR_ESP` are
not supported (prevents accidental corruption — PH_OP_CALL handles ESP
adjustment).

### 5.4 Opcodes

```
0x00 NOP
0x01 LOADI    dst, imm                    -- dst = imm32
0x02 MOV      dst, a                      -- dst = a
0x03 ADD      dst, a, b
0x04 SUB      dst, a, b
0x05 MUL      dst, a, b
0x06 AND/OR/XOR/SHL/SHR/CMP (0x06..0x0B)
0x0C JMP      pc += imm
0x0D JEQ/JNE/JLT/JGT (0x0D..0x10)
0x11 READ1    dst, [a + imm]              -- 1/2/4 bytes of guest mem
0x12 READ2    ...
0x13 READ4    ...
0x14 WRITE1   [a + imm] = b (as 1/2/4)
0x15 WRITE2
0x16 WRITE4
0x17 LOG      a, b                        -- emits log entry (cr3,va,a,b)
0x18 RETCONT                              -- let the original instruction run
0x19 RETSKIP  imm                         -- advance EIP by imm; skip original
0x1A RETRET   imm                         -- simulate `ret imm16`
0x1B HALT                                 -- stop script; default action = SKIP
0x1C CALL     dst=retval, a=funcVA, b=nargs,
              imm = packed 4-byte arg encodings
```

`RETCONT` is the exit that triggers Option 7's flip + single-step.
`RETSKIP` / `RETRET` / `HALT` keep the CPU on the read tree and advance
EIP without ever flipping; useful for pure-override recipes like
"set EAX and return."

### 5.5 PH_OP_CALL (native guest call)

Encoding:
- `dst` = register to receive guest EAX on return (0 = discard)
- `a` = register holding the callee's VA (load with `PH_LOADI` first)
- `b` = nargs (0..4)
- `imm` = 4 bytes of packed operand encodings (byte 0 = arg0, byte 1 = arg1, ...)

Execution semantics:

1. For each arg (right-to-left for cdecl), read the operand value and
   push 4 bytes to `[ESP-4]`, `[ESP-8]`, etc. via `WriteGuestVa`.
2. Push a return address onto the guest stack: `[new_ESP] = TargetVa`.
3. Save the callee's resume state **per-CPU** in `GUEST_STATE`:
   `CallActive=1, CallHookSlot=slot, CallResumePc=pc+1, CallRetValReg=dst,
   CallSavedEsp=original_ESP, CallSavedCr3=guestCr3, CallSavedEip=TargetVa,
   CallSavedScratch[0..15]=scratch[0..15]`.
4. Redirect guest EIP to the callee's VA, set ESP to `new_ESP`.
5. Halt the script with action=SKIP. VMRUN.
6. Guest runs the callee natively. When the callee's `ret` pops the
   return address off the stack, EIP = TargetVa, so the hook fires again
   as an ordinary NPF.
7. `TryDispatchProcessHook` runs the entry. `RunProcessHookScript`
   examines this CPU's `GUEST_STATE`: if `CallActive==1`,
   `CallHookSlot==thisSlot`, `CallSavedCr3==guestCr3`, it's a resume:
   restore scratch, restore ESP, store guest EAX into `CallRetValReg`,
   set pc to `CallResumePc`, clear `CallActive`. Script continues.

Subtleties:

- `CallActive` state is **per-CPU**, not per-hook. If CPU 0 is mid-CALL
  and CPU 1 NPFs on the same TargetVa (unrelated thread), CPU 1 runs the
  script from PC 0 as a normal fire. The CR3 match on resume rejects
  cross-process reuse.
- Nested CALL (another CALL while `CallActive=1` on the same CPU) faults
  with `PH_FAULT_BAD_OPERAND` rather than clobbering saved state. If you
  need nested calls, build a stack in script scratch.
- Max 4 args fits most uses. Functions with more parameters need either
  a wrapper stub in guest memory or a two-insn `CALL`+`CALL_CONT` form
  (future work; see §11).

### 5.6 Script-builder macros (user-mode)

In `host/ao_client.h`:

```c
PH_NOP()
PH_LOADI(dst, imm)
PH_MOV(dst, src)
PH_ADD(dst, a, b)   PH_SUB(...)  PH_MUL(...)  PH_AND(...) ...
PH_CMP(a, b)
PH_JMP(delta)   PH_JEQ(...)  PH_JNE(...)
PH_READ4(dst, a, disp)
PH_WRITE4(a, b, disp)
PH_LOG(a, b)
PH_RETCONT()  PH_RETSKIP(skip_bytes)  PH_RETRET(stacksize)  PH_HALT()
PH_CALL(retval_reg, fn_reg, n_args, a0, a1, a2, a3)
PH_CALL0(retval_reg, fn_reg)                      // zero-arg convenience
PH_CALL1(retval_reg, fn_reg, a0)
PH_CALL2(retval_reg, fn_reg, a0, a1)
PH_CALL3(retval_reg, fn_reg, a0, a1, a2)
PH_CALL4(retval_reg, fn_reg, a0, a1, a2, a3)
```

### 5.7 Budgets

- Script size: `PROCESS_HOOK_SCRIPT_MAX_INSNS = 128` instructions
  (= 1024 bytes).
- Cycle budget: `PROCESS_HOOK_MAX_CYCLES = 512` interpreter steps per
  fire (prevents infinite scripts from hanging the CPU). A fire consumes
  cycles only until it halts; a multi-CALL draw script's "fire" is the
  work between one CALL suspend and the next CALL / RETCONT.
- Scratch registers: 16 UINT64 slots. Cleared between fires. Saved across
  PH_OP_CALL via `CallSavedScratch`.
- Config slots: 16 UINT32 per hook. Persist across fires. User-mode-writable.

### 5.8 Example scripts

**Force EAX to a constant:**
```c
ph_insn s[] = {
    PH_LOADI(PH_R0, 450),
    PH_MOV(PH_GR_EAX, PH_R0),
    PH_RETCONT(),
    PH_HALT(),
};
```

**CFG-driven override:**
```c
ph_insn s[] = {
    PH_LOADI(PH_R0, 0),
    PH_CMP(PH_CFG0 + 0, PH_R0),       // CFG0 = enable
    PH_JEQ(+2),                        // if disabled, skip override
    PH_MOV(PH_GR_EAX, PH_CFG0 + 1),   // EAX = CFG1 (replacement value)
    PH_RETCONT(),
    PH_HALT(),
};
```

**Log every hit:**
```c
ph_insn s[] = {
    PH_LOG(PH_GR_EAX, PH_GR_ECX),
    PH_RETCONT(),
};
```

**Chain native calls:** see `docs/case-studies/<target>.md` for a
real-world example (e.g. the osu! case study documents chaining GL calls
through a `SwapBuffers` hook).

---

## 6. Hypercall ABI

ao exposes a `#UD`-based hypercall channel. User-mode executes `ud2`
with `RAX = (AO_MAGIC << 32) | cmd` and arg registers set per the AMD64
ABI (`RCX, RDX, R8, R9`). ao's `#UD` handler checks the RAX magic and
dispatches.

`AO_MAGIC = 0x56484F41` (little-endian ASCII "AOHV").

### 6.1 Commands

| Cmd | Name                              | In                                | Out                           |
|-----|-----------------------------------|-----------------------------------|-------------------------------|
| 0   | PING                              | —                                 | `0xDEADBEEFDEADBEEF`          |
| 1   | READ_MEM                          | cr3, va, size, buf_va             | bytes read (user buf)         |
| 2   | GET_CR3                           | process_name, skip                | CR3 PA or UINT64_MAX          |
| 3   | VA_TO_PA                          | cr3, va                           | GPA or UINT64_MAX             |
| 11  | LIST_PROCS                        | buf_va, max_procs                 | count                         |
| 12  | GET_PROC_BASE                     | process_name, skip                | base VA                       |
| 13  | WRITE_GPA                         | gpa, buf_va, size                 | bytes written                 |
| 14  | ALLOC_SHADOW                      | —                                 | shadow GPA                    |
| 15  | NPT_HOOK                          | target_gpa                        | shadow GPA                    |
| 17  | FIND_MODULE                       | proc, dll, skip                   | module base or UINT64_MAX     |
| 23  | READ_GPA                          | gpa, buf_va, size                 | bytes                         |
| 30  | CLEAR_HOOKS                       | —                                 | 0                             |
| 40  | PH_REGISTER                       | cr3, va, script_va, insn_count    | slot index or -1              |
| 41  | PH_UNREGISTER                     | slot                              | 0                             |
| 42  | PH_STATUS                         | dst_va                            | 340 (bytes written)           |
| 43  | PH_LOG_READ                       | dst_va, max_count                 | count                         |
| 44  | PH_CLEAR                          | —                                 | 0                             |
| 45-48 | PH_DIAG_WALK/NCR3/HOOKMETA/COUNTERS | diag struct ptr                  | 0                             |
| 49  | PH_SET_CFG                        | slot, cfg_idx, value              | 0 or -1                       |

The `AO_HYPERCALL(cmd, a0..a3)` macro wraps the raw stub with SEH so
that running without the HV present raises `STATUS_ILLEGAL_INSTRUCTION`
→ caught → returns `AO_NOT_PRESENT` (`UINT64_MAX`) instead of crashing
the tool.

### 6.2 Example — install a hook from C

```c
#include "ao_client.h"

uint64_t cr3 = ao_get_process_cr3("target.exe");
uint64_t base = ao_find_module_base("target.exe", "somelib.dll");
// ... resolve VA ...
ph_insn script[] = { PH_LOG(PH_GR_EAX, PH_GR_ECX), PH_RETCONT() };
uint64_t slot = ao_ph_register(cr3, target_va, script, 2);

// drain log:
ph_log_entry buf[256];
uint64_t n = ao_ph_log_read(buf, 256);

// set a CFG slot:
ao_ph_set_cfg((uint32_t)slot, 0, 1);  // CFG0 = 1

// uninstall:
ao_ph_unregister((uint32_t)slot);
```

---

## 7. User-mode tools

### 7.1 hook_tool

`cli/hook_tool.c` — generic CLI for installing hooks and diagnostics.
Commands:

```
hook_tool status              dump hook table (num_active, hits per slot)
hook_tool log                 drain the PH_OP_LOG debug ring
hook_tool clear               mark all PH slots inactive
hook_tool unregister <slot>   remove one hook
hook_tool diag_counters       fine-grained NPF/dispatch counters

hook_tool install <process> <va_hex> <recipe> [args]
    Install a hook at an already-known VA.
hook_tool install_sig <process> <module> <pat_hex> <mask> <offset_hex>
                      <scan_mb> <recipe> [args]
    Sigscan inside <process>'s view of <module>, install at
    <match_va + offset_hex>.
hook_tool sigscan <process> <module> <pattern> <mask> [scan_mb]
    Scan only; print match VA.
```

Built-in recipes: `force_eax`, `force_eax_cont`, `mul_eax`, `add_eax`,
`clamp_eax`, `log_args`, `log_eax_edx`. Add new ones by extending the
`strcmp(recipe, "name") == 0` block near the bottom of hook_tool.c.

### 7.2 syscall_monitor

`cli/syscall_monitor.c` — logs every syscall a target process makes, in
real time, via the ao syscall-log hypercalls. Useful for figuring out
what a binary is doing in the first place before you know where to
hook.

### 7.3 examples/

For teaching demos against test binaries. Nothing target-specific lives
here; downstream tools against real applications live in their own
repos (see `docs/case-studies/` for pointers).

---

## 8. Building

Everything builds with MSVC + EDK2 BaseTools, from a Windows machine
that already has Visual Studio installed.

### 8.1 Prerequisites

- EDK2 (vendored or external), with `BaseTools` compiled.
- Visual Studio 2019+ with the x64 toolchain.
- NASM (for EDK2's assembler pieces).
- `ml64` (ships with MSVC) for the user-mode hypercall stub.

### 8.2 Driver build (EFI)

```bat
rem from driver/
call "C:\Program Files\Microsoft Visual Studio\<version>\Community\VC\Auxiliary\Build\vcvars64.bat"
call <edk2>\edksetup.bat
set EDK_TOOLS_BIN=<edk2>\BaseTools\Bin\Win64
set PATH=%EDK_TOOLS_BIN%;%PATH%
set NASM_PREFIX=<path to nasm bin>
build -t VS2026 -a X64 -b NOOPT -p aoPkg\aoPkg.dsc
```

Output: `Build\aoPkg\NOOPT_VS2026\X64\ao.efi`. Deploy to the ESP
and arrange for firmware to load it before Windows.

A canned `do_build.bat` lives in `driver/aoPkg/tools/` — adjust paths
for your machine, then just run it.

### 8.3 User-mode tools

Each tool uses the same hypercall stub (`host/ao_call.asm`) and includes
`host/ao_client.h`.

```bat
rem from host/
ml64 /nologo /c ao_call.asm

rem then from cli/
cl /nologo /O2 /W3 hook_tool.c ..\host\ao_call.obj /I..\host /link /out:hook_tool.exe
cl /nologo /O2 /W3 syscall_monitor.c ..\host\ao_call.obj /I..\host /link /out:syscall_monitor.exe
```

Eventually `harness run cli-build` will wrap this.

### 8.4 Reload cycle

- **Driver change:** rebuild `.efi`, deploy, reboot. No way around it.
- **Tool change:** rebuild `.exe`, run. Hot-reloadable.

### 8.5 Testing a fresh build

1. `hook_tool status` — confirms HV responds.
2. `hook_tool clear` — clean slate.
3. Install a hook, check `status` for the slot going active and hits
   incrementing.
4. Run in-game / in-target actions, verify behavior matches expectation.
5. If the guest crashes, grab the minidump from `C:\Windows\Minidump\`
   and read the bugcheck fields directly (first 0x60 bytes of the dump
   is the PAGEDU64 header: code at 0x38, params at 0x40, 0x48, 0x50, 0x58).

---

## 9. Case studies

No longer in the core doc. Per-target notes, sigs, and hook recipes live
in `docs/case-studies/<target>.md`. Working code against real target
applications lives in separate downstream repos that depend on ao as a
library.

Current case studies:

- `osu-stable.md` — osu!stable (Windows x86 game, .NET + Eazfuscator +
  native self-protection layer). Downstream repo: `new-era/`.

---

## 10. Known limitations

- **One hook per unique (CR3, VA).** `PH_REGISTER` replaces by match.
- **Max 8 hook slots.** `PROCESS_HOOK_MAX`.
- **Max 8 distinct 1GB GPA regions for hooks.** `NPT_HOOK_1GB_SLOT_COUNT`.
  Bump if you need more — small struct size increase.
- **Max 16 distinct 2MB regions.** `NPT_HOOK_SLOT_COUNT`.
- **128 insns per script.** Enough for ~15 native calls or lots of math.
- **512 interpreter cycles per fire.** Scripts that CALL a lot resume
  between each call so cycle budget is per-segment, not total.
- **4 args max per `PH_OP_CALL`.** Need more? Either sequence multiple
  calls into a wrapper stub in guest memory (adds surface), or extend the
  opcode encoding (option: two-insn form where the follow-up provides 4
  more arg encodings).
- **32-bit cdecl only.** 64-bit guest ABIs (Microsoft x64 / System V)
  need a second code path that passes args in RCX/RDX/R8/R9 + stack
  shadow space. Not hard, maybe 100 LoC in the opcode handler.
- **No kernel-space hooks.** ao can read/write kernel GPA space but the
  PH dispatch matches on `TargetGpa4K` of the fetching page; hooking
  ntoskrnl functions is possible but we haven't done it.
- **Hook install is NOT cross-CPU TLB-flushed via IPI.** Other CPUs pick
  up the new NCr3 on their next VMEXIT via `NCr3UpdatePending`. This is
  generally fine but has a theoretical window if a CPU is holding a
  stale translation. Future hardening: send an IPI on install.
- **No hot-rotate / graceful uninstall.** `ph_unregister` marks the slot
  inactive but leaves the NPT hook page in place (cheap re-use). To
  fully recycle NPT entries, `CLEAR_HOOKS` is heavier.

---

## 11. Future work

### 11.1 64-bit guest ABI

Target: hook into a 64-bit process. Changes:

- Add a `PH_OP_CALL64` opcode OR a flag bit on `PH_OP_CALL`. The
  implementation decides which path based on the CS.L bit of the
  current segment (already available in VMCB).
- Arg marshalling: first 4 args → RCX/RDX/R8/R9; subsequent args →
  `[RSP+0x20]`, `[RSP+0x28]`, etc. Reserve 32 bytes of shadow space
  under RSP for the callee.
- Widen CFG slots to UINT64 (or split a 64-bit value across two slots).
- Widen scratch-register commits to guest regs to 64 bits.
- User-mode: enumerate modules with `EnumProcessModulesEx` without
  `LIST_MODULES_32BIT`.

Estimated ~200-300 LoC. Shadow pages, NPT, Option 7, hypercall ABI all
stay identical.

### 11.2 Process-creation detection

Enable `InterceptCrWrite.Cr3` and cache CR3 → EPROCESS → image name.
Fires on every context switch; use a small LRU to avoid repeating the
EPROCESS walk for a known CR3. Lets a downstream tool auto-install a
hook as soon as its target process starts.

### 11.3 Larger PH_OP_CALL arg counts

Add a `PH_OP_CALL_CONT` follow-up instruction carrying 4 more arg
encodings. Gives us 8-arg calls (enough for `glOrtho`'s 6 doubles,
etc.). Minor encoding work, no state-machine changes.

### 11.4 Kernel code hooks

Would let us intercept `nt!PspCreateProcess`, `nt!NtWriteVirtualMemory`,
syscall entries, and so on. Current limitation is just that we haven't
exercised the kernel-GPA side of `GvaToGpa`.

### 11.5 ESP / in-target spatial overlays

The GL-draw primitive can render anything. For spatial overlays:
resolve the target's in-world coords, convert to NDC, emit vertices.
Case study documents the reference implementation against a specific
target.

---

## 12. File-by-file read order (for a new agent)

If you're reading the code cold, read in this order:

1. `driver/aoPkg/Drivers/ao/ao.h`
   — all the types. Start with `GUEST_STATE`, `SHARED_SVM_DATA`,
   `NPT_HOOK_REGION`, `PROCESS_HOOK_ENTRY`.
2. `host/ao_client.h`
   — user-mode ABI. Look at the hypercall macro, PH operand constants,
   PH opcodes, script-builder macros. (Identical to
   `driver/aoPkg/Drivers/ao/ao_client.h` by contract.)
3. `driver/aoPkg/Drivers/ao/Setup.c`
   — `InstallNptHook` + `NptSplitTo4KB`. How a hook enters the NPT.
4. `driver/aoPkg/Drivers/ao/Host.c`
   — `HandleVmExit` is the big switch. Then `HandleNestedPageFault` for
   the NPF path, `TryDispatchProcessHook` + `RunProcessHookScript` for
   the PH engine, `PhArmExecFlipWithSingleStep` + `HandleDebugException`
   for Option 7, `PhEmulateHookedInstruction` for inline emulation.
5. `cli/hook_tool.c` — see how user-mode talks to it.
6. `docs/case-studies/osu-stable.md` — see a full worked example
   of applying ao to a specific target.

Welcome.
