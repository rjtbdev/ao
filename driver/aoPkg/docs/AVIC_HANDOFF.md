# AVIC Implementation — Handoff Notes

## Context

- **Project**: `shmr` — UEFI-loaded AMD SVM Type-1 hypervisor, forked from
  [tandasat/HelloAmdHvPkg](https://github.com/tandasat/HelloAmdHvPkg).
- **Host hardware**: Ryzen 7 7800X3D (Zen 4, family 19h).
- **Guest**: Windows 11 (single VCPU during the calibration hang we're debugging;
  full SMP works in the non-AVIC baseline).
- **EDK2 build**: `do_build.bat` in `C:\Users\riley\Projects\canopy\edk2\` →
  `Build/aoPkg/NOOPT_VS2026/X64/ao.efi` + `ReadScratch.efi`.
- **Diagnostic**: CMOS-only, no NVRAM/firmware calls. Dump with
  `ReadScratch.efi` from the UEFI shell.

## Why AVIC

The non-AVIC baseline emulates LAPIC writes via NPT — every LAPIC access
takes a nested page fault, instruction decode, software emulate, RIP advance.
At Windows steady state we measured >10k NPFs/sec just from LAPIC traffic,
which dominates VMEXIT cost. AVIC (AMD APM Vol 2 §15.29) lets the hardware
redirect most LAPIC MMIO directly to a per-VCPU backing page with no exit,
so only a small set of "trap" / "fault" classified registers cause exits.

CPUID(8000_000A).EDX on 7800X3D: bit 13 (AVIC) = 1, bit 14 (x2AVIC) = 0.
We run classic AVIC, xAPIC mode only.

## Current state

The non-AVIC baseline boots Windows cleanly. With AVIC enabled:

1. **Initial AVIC attempts**: Windows hangs at LAPIC calibration. Total
   ~18000 VMEXITs, ~88 AVIC fault exits, no NPF on the LAPIC page (i.e.,
   AVIC IS redirecting LAPIC MMIO correctly), but `TIMER: fires=0`,
   `LvtTimer=0x000300FF (masked, periodic, vec 0xFF)`, `Tmict=0xFFFFFFFF`.
   Windows arms the calibration timer once and never makes progress.
2. **After current round of fixes (V_INTR_MASKING set, SPIV/LVT defaults
   changed, TMCCT computed on fault)**: regressed further. The UEFI Shell
   itself freezes seconds after `ao.efi` loads and prints "success".
   CMOS dump shows `unaccel=10`, `T=0`, `F=0` — 10 AVIC unaccel exits
   happened but neither the trap counter nor the fault counter incremented.
   That asymmetry is the puzzle for the next iteration: see "Open
   questions" below.
3. **After reverting SPIV/LVT defaults (last build deployed)**: also
   hangs, per user report. SPIV reverted to `0x000001FF`, LVT defaults
   removed. V_INTR_MASKING and the TMCCT compute kept. Diagnostic dump
   not yet captured for this build.

## What we've tried

Roughly in order. All currently in the tree unless marked **reverted**.

### Configuration

- `VINTR_AVIC_ENABLE` (bit 31) in `VMCB.VIntr`.
- `VINTR_V_INTR_MASKING` (bit 24) in `VMCB.VIntr`. Set per APM §15.29 and
  per KVM `init_vmcb()` behavior (always-on).
- `X2APIC_MODE` (bit 30) — **not** set; 7800X3D lacks x2AVIC.
- `AvicApicBar` = `0xFEE00000` (architectural xAPIC base).
- `AvicApicBackingPagePointer` = per-VCPU 4KB backing page PA.
- `AvicPhysicalTablePointer` = PA of 4KB physical-ID table, low byte =
  `0xFF` (max index, not count, per APM Table 15-21).
- `AvicLogicalTablePointer` = PA of 4KB logical-ID table.
- Physical table entry at `[guest_apic_id]` populated with
  `backing_pa | VALID | RUNNING | host_apic_id_low`. `RUNNING` is also
  toggled in `AvicSetRunning()` around the VMRUN.
- Logical table left zero (single VCPU, no logical IPIs expected during
  boot).
- TLB flush on first VMRUN after AVIC enable (`TlbControl = 1` then `0`).
- `VmcbClean = 0` every VMEXIT (forces hardware to reload everything).
- LAPIC NPT entry kept `Write=1` when AVIC is on (NPT permission walk
  still happens; AVIC redirects after the walk).

### Backing page initialization (`Setup.c` around line 696)

- `APIC_ID` (0x20) = `guest_apic_id << 24`.
- `APIC_VERSION` (0x30) = `0x00050014` (version 0x14, 5 LVT entries — 1).
- `DFR` (0xE0) = `0xFFFFFFFF` (flat model).
- `SPIV` (0xF0) = `0x000001FF` (APIC software-enabled, spurious vec 0xFF).
- **Reverted**: SPIV = `0x000000FF` (architectural reset, software-
  disabled). Broke UEFI shell — firmware had already enabled APIC, our
  software-disabled state in the backing page killed timer-driven events.
- **Reverted**: LVT defaults of `0x00010000` (masked). Was redundant with
  `ZeroMem` already giving `0` for unused slots; concern was that
  `LVT_TIMER = 0` reads as "unmasked vector 0" which could be observed
  before any guest write. Reverted at the same time as SPIV — hadn't
  fully isolated which of the two caused the shell freeze.

### VMEXIT handling

- `VMEXIT_AVIC_INCOMPLETE_IPI` (0x401) — handled, mirrors KVM
  `avic_incomplete_ipi_interception`; replays the ICR write to the
  physical LAPIC for the not-running/invalid-target cases.
- `VMEXIT_AVIC_UNACCEL_ACCESS` (0x402) — main handler at
  `HandleAvicUnaccelAccess()` in `Host.c`.

#### Trap vs Fault classification

Mirrors KVM `is_avic_unaccelerated_access_trap()`. Traps (hardware already
applied the write to backing page, RIP advanced):

```
0x20 (ID), 0xB0 (EOI), 0xC0 (RRR), 0xD0 (LDR), 0xE0 (DFR), 0xF0 (SPIV),
0x280 (ESR), 0x300 (ICR), 0x320..0x370 (LVT*), 0x380 (TMICT), 0x3E0 (TDCR)
```

Everything else (notably 0x90 APR, 0xA0 PPR, 0x390 TMCCT) is fault.

#### Trap path

Hardware already updated backing page; we read the new value back, drive
software side-effects (e.g., arm the timer), and acknowledge. RIP is
already advanced by hardware.

- `0x320` LVT_TIMER → `ApicTimerMaskUpdate()` (preserves counter across
  mask flips — Windows calibration depends on this).
- `0x380` TMICT → `ApicTimerArmFresh()` (fresh counter restart).
- `0x3E0` TDCR → `ApicTimerArmFresh()` (divisor change).
- Others — just acknowledged.

#### Fault path

Hardware did NOT advance RIP. We:

1. Read offset, R/W bit from `ExitInfo1`.
2. Call `DecodeMmioInsnLength()` — minimal x86 decoder reading
   `GuestInstructionBytes` (DecodeAssists). Handles MOV r,r/m;
   MOV r/m,r; MOV r/m,imm. Returns length + dest register index.
3. For reads: emulate the read into the dest GPR via `WriteGuestGpr()`.
4. Advance RIP by decoded length.

For reads we return:
- TMCCT (0x390): `ApicTimerComputeTmcct(Cpu)` — monotonically decreasing
  from `ArmedAtTsc/IntervalTsc/Tmict`.
- Everything else: 0 (APR=0=no priority, PPR=0=no priority, ESR=0=no
  error, etc. — all benign for boot).

### Timer model (`Host.c` ApicTimer* functions)

State in `GUEST_STATE.TimerState`:
- `LvtTimer`, `Tmict`, `Tdcr` — shadow of last written value.
- `NextFireTsc` — when the next timer interrupt should fire (0 = disabled
  or masked).
- `ArmedAtTsc`, `IntervalTsc` — for computing remaining count (TMCCT).

Functions:
- `ApicTimerArmFresh(Cpu)` — fresh arm. Reset `ArmedAtTsc = now`,
  recompute `IntervalTsc`, set `NextFireTsc` (or 0 if masked).
- `ApicTimerMaskUpdate(Cpu)` — preserve `ArmedAtTsc`/`IntervalTsc`,
  just update `NextFireTsc` based on the new mask bit. Critical:
  Windows toggles LVT_TIMER mask while the counter is running; we
  must not reset the counter.
- `ApicTimerComputeTmcct(Cpu)` — returns current TMCCT value
  (proportional to remaining TSC time).
- `ApicTimerCheck(Cpu)` — called every VMEXIT. If `NextFireTsc` passed
  and timer is unmasked, set IRR bit in backing page (AVIC delivers
  on next VMRUN). Periodic mode: rearm fresh. One-shot: disable.

Frequency model: LAPIC bus ~100 MHz, TSC ~4 GHz → 40 TSC ticks per
LAPIC tick. `interval_tsc = tmict * div * 40`. Hardcoded for Zen 4 7800X3D.

### V_TPR sync

After every VMEXIT, before VMRUN, we copy backing[TPR] >> 4 into
`VMCB.VIntr` bits 3:0 (V_TPR). Per the August 2025 KVM patch (Maciej
Szmigiero / Oracle): AVIC accelerates guest TPR writes into the backing
page without VMEXIT, but hardware uses `VIntr[3:0]` (V_TPR) — not the
backing page — to gate virtual interrupt delivery. Without this sync,
the guest's TPR writes "vanish" from hardware's perspective and
interrupts can be over-masked.

### SMP coordination (works in the non-AVIC baseline)

- `IsRunning` toggled in `AvicSetRunning(running)` around each VMRUN.
- INIT signal handling via `VM_CR.R_INIT` redirect to `#SX` (exception
  vector 30) so APs trap to host on INIT.
- SIPI emulation on BSP's ICR writes to the physical LAPIC.

This whole path is currently dormant in the AVIC hang investigation
(single-VCPU calibration happens before APs come up).

### Diagnostics

`Applications/ReadScratch/ReadScratch.c` dumps from CMOS bytes
`0x40-0x77`. Current fields visible on screen:

```
AVIC: CPUID-AVIC=Y CPUID-x2AVIC=n flag=0x01 inc_ipi=N unaccel=N (T=N F=N) cause=N
TIMER: fires=N lvt_writes=N tmict_writes=N
  last LvtTimer=0xNNNNNNNN (vec=N mode=N masked=N)  Tmict=0xNNNNNNNN (N)
NPF: count=N decode_fail=N lapic_mmio=N  last_gpa=0xNNNNNNNN
NPF flags (0x49/0x4A): P=N RW=N US=N RSV=N ID=N  NPT=N
AVIC fault: last_offset=0xNNN  last_tmcct=0xNNNNNNNN     <- added recently
SMP: SX_init=N sipi_emu=N icr_writes=N apsresumed=N
PathBits 0xNN: ...
Crash: unhandled_exit=0xNNNNNNNN host_exc_vec=0xNN
Exits: total=NNNN last_code=0xNN last_rip=0xNNNNNNNNNNNNNNNN
```

CMOS is battery-backed so it survives crashes — useful, but
`aoInitialize()` explicitly clears the diagnostic bytes at boot
(`cmosClear` list in Setup.c around line 1474) so dumps reflect this
boot only.

CMOS layout (key bytes — see `Setup.c` clear list for full set):
- `0x42` AVIC unaccel total count
- `0x43/0x44` last unaccel offset
- `0x4B` unaccel TRAP count
- `0x4C` unaccel FAULT count
- `0x4D` timer fires
- `0x4E/0x4F` LVT_TIMER/TMICT write counts
- `0x56` VMEXIT count low byte; `0x60` = wrap counter (total = wrap << 8 | cnt)
- `0x57` last VMEXIT code (low byte only)
- `0x58-0x5F` last VMEXIT RIP (8 bytes)
- `0x6A/0x6B` last AVIC fault offset (added this round)
- `0x6C-0x6F` last TMCCT value returned (added this round, 4 bytes)
- `0x70-0x77` last LVT_TIMER / TMICT raw values (4 bytes each)
- `0x7D` final AVIC enable flag, `0x7E` CPUID(8000_000A).EDX high byte

## Open questions / unsolved

1. **`unaccel=10, T=0, F=0` asymmetry.** In the second-to-last test
   build, 10 unaccel exits happened but neither the trap nor fault
   counter incremented. The CMOS write order in
   `HandleAvicUnaccelAccess()` is:
   ```
   g_AvicUnaccelCount++;             WriteCmosByte(0x42, ...);
   g_AvicLastUnaccelOffset = offset; WriteCmosByte(0x43/0x44, ...);
   if (isTrap) { g_AvicUnaccelTrapCount++; WriteCmosByte(0x4B, ...); ... }
   else        { g_AvicUnaccelFaultCount++; WriteCmosByte(0x4C, ...); ... }
   ```
   How can the first set of writes execute 10× without the second set
   executing at all? Hypotheses:
   - The handler is being re-entered or the code path is somehow not
     reaching the `if (isTrap)` branch (unlikely — straight-line C).
   - The shell freeze happened *during* the 10th handler invocation
     after `WriteCmosByte(0x42)` but before reaching the branch (some
     hardware-level wedge, maybe related to V_INTR_MASKING).
   - Something is restarting / replaying the unaccel exit before the
     handler completes (NMI? #MC? unlikely on UEFI shell).
   - The `WriteCmosByte` itself is the wedge — but it's just port 0x70/0x71
     I/O which we don't intercept.

2. **Is V_INTR_MASKING actually correct here?** Setting bit 24 changed
   the regression mode from "Windows hang at calibration" to "shell
   freeze immediately." KVM sets V_INTR_MASKING unconditionally in
   `init_vmcb()` and APM §15.29 says it's required with AVIC — but our
   empirical result with it set is worse than without. Could be
   interaction with the SPIV/LVT change (test wasn't isolated). Next
   diagnostic build should isolate V_INTR_MASKING alone.

3. **DecodeAssists reliability on Zen 4 AVIC faults.** The APM
   documents `NumOfBytesFetched` / `GuestInstructionBytes` /
   NRIP_SAVE as unreliable / not guaranteed populated for AVIC_NOACCEL
   faults. KVM works around this by running its full x86 emulator on
   fault, reading the faulting instruction from guest memory at RIP.
   Our `DecodeMmioInsnLength()` trusts DecodeAssists. The handler is
   making progress (88 faults processed in earlier test, no infinite
   re-execution loop), but it's possible some fault paths are decoding
   wrong-length and corrupting RIP — would explain the `last_rip` in
   the screenshots sitting in odd places.

4. **TMCCT compute correctness.** `ApicTimerComputeTmcct()` returns
   `tmict * (interval - elapsed) / interval`. Windows' calibration
   loop requires this to be monotonically decreasing. With `Tmict =
   0xFFFFFFFF`, `div = 2` (TDCR=0 default), `interval ≈ 3.4e11` TSC
   ticks. After my fix the user hasn't been able to capture
   `last_tmcct` because the shell froze before they could re-dump.
   Next test: run ReadScratch quickly after a successful Windows
   boot-and-hang (if we can get back there); expect `last_offset=0x390`
   and `last_tmcct` not equal to `0xFFFFFFFF` or `0`.

5. **Should AVIC be enabled at first VMRUN or activated later?**
   Currently we enable on `PrepareForVmrun()` (the very first VMRUN).
   KVM has a notion of "activate AVIC after some warmup" via inhibits
   — APICV_INHIBIT_REASON_*. We don't track inhibits; if any of them
   would apply (e.g., Hyper-V SynIC, in-kernel PIT, etc.) we'd silently
   misbehave.

## Files to read for next agent

In `C:\Users\riley\Projects\canopy\edk2\aoPkg\`:

- `Drivers/ao/Setup.c` — VMCB init, AVIC setup (around line 628),
  NPT, `SetupLapicNptIntercept`, `DetectAvicSupport`, `cmosClear`,
  `VirtualizeProcessor`.
- `Drivers/ao/Host.c` — VMEXIT handlers. Key functions:
  `HandleVmExit`, `HandleAvicUnaccelAccess`, `HandleAvicIncompleteIpi`,
  `IsAvicTrap`, `ApicSetIrr`, `ApicTimerArmFresh`,
  `ApicTimerMaskUpdate`, `ApicTimerComputeTmcct`, `ApicTimerCheck`,
  `DecodeMmioInsnLength`, `WriteGuestGpr`, V_TPR sync block at end of
  `HandleVmExit`.
- `Drivers/ao/shmr.h` — `LAPIC_TIMER_STATE`, `GUEST_STATE`,
  `PER_CPU_DATA`.
- `Drivers/ao/Svm.h` — VMCB struct, AVIC bit definitions
  (`VINTR_AVIC_ENABLE`, `VINTR_V_INTR_MASKING`, `AVIC_PHYS_ID_*`).
- `Applications/ReadScratch/ReadScratch.c` — diagnostic format.

External references that informed the implementation:

- AMD APM Vol 2 §15.29 (AVIC) — initialization, trap/fault tables.
- Linux KVM: `arch/x86/kvm/svm/avic.c`, `arch/x86/kvm/lapic.c`.
  Specifically `avic_unaccelerated_access_interception`,
  `avic_unaccel_trap_write`, `is_avic_unaccelerated_access_trap`,
  `avic_init_backing_page`, `kvm_apic_write_nodecode`,
  `apic_get_tmcct`, `__apic_update_ppr`, `kvm_lapic_reset`.
- KVM August 2025 V_TPR sync patch by Maciej Szmigiero (Oracle).
- HelloAmdHvPkg upstream — non-AVIC baseline we forked from.

## Suggested next steps

1. **Isolate the regression.** Three independent variables changed in
   the last round (V_INTR_MASKING, SPIV, LVT defaults). The shell
   freeze build had all three. The current revert has only V_INTR_MASKING
   and TMCCT-compute. Test one variable at a time:
   - Build A: revert V_INTR_MASKING too. Keep only TMCCT-compute +
     diagnostics. Confirm: matches the "Windows hang at calibration,
     shell works" baseline, plus a `last_tmcct` we can read.
   - Build B: Build A + V_INTR_MASKING. Does shell freeze return?
2. **Capture `last_offset` / `last_tmcct` on the Windows hang.** This
   is the highest-information experiment we haven't actually completed —
   the last build that printed the new diagnostic line was the broken
   one that froze the shell. The diagnostic tells us *which* fault
   register Windows is polling, which immediately narrows the root cause.
3. **Replace `DecodeMmioInsnLength` with NRip-based advance for faults.**
   Try `Rip = ControlArea.NRip`. If it works on Zen 4 (APM says
   unreliable, but Zen 4 may populate it for AVIC faults), this is way
   simpler than the decoder. If it doesn't work, fall back to reading
   guest memory and running a small emulator (KVM-style).
4. **Mirror physical LAPIC state into backing page** at virtualization
   time, instead of guessing defaults. Read the actual `SPIV`, LVT
   registers, etc. from `0xFEE000F0` etc. before switching on AVIC, and
   copy them into the backing page. This avoids the "we picked a
   default that contradicts firmware's existing state" class of bug.

## Test cadence

User flashes new `ao.efi` + `ReadScratch.efi` from
`C:\Users\riley\Projects\canopy\edk2\Build\aoPkg\NOOPT_VS2026\X64\` to
USB (D:), reboots the target machine, boots to UEFI shell, runs
`fs3:`, `ao.efi` (loads the driver), boots Windows. When Windows
hangs / shell freezes, the user power-cycles back to UEFI shell and
runs `ReadScratch.efi` to read CMOS. CMOS survives reset; the
hypervisor clears the diagnostic range at next boot.
