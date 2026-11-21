/**
 * @file Host.c
 *
 * @brief Implements the hypervisor logic.
 *
 * @author Satoshi Tanda
 *
 * @copyright Copyright (c) 2020, Satoshi Tanda. All rights reserved.
 */
#include "ao.h"
#include "Introspect.h"

extern VOID RecordMilestone (IN UINT32 Value);
extern EFI_GUID g_MilestoneGuid;

// Forward declarations (defined further down; used from HandleNestedPageFault).
STATIC VOID PhArmExecFlipWithSingleStep (IN OUT HOST_CONTEXT* Context);
STATIC VOID PhEmulateHookedInstruction   (IN OUT HOST_CONTEXT* Context, IN UINT64 origPagePa, IN UINT64 guestRip);

//
// Bitfield-based "what was reached" tracker. Each call site checks its bit;
// if not yet set, sets it and writes the full bitmask to NVRAM. So flash is
// touched at most once per bit (5 writes max). NVRAM milestone value after a
// run encodes which code paths executed via the low byte:
//   bit 0 (0x01): HandleVmExit was entered
//   bit 1 (0x02): HandleCpuid was called
//   bit 2 (0x04): HandleVmmcall was called
//   bit 3 (0x08): default VMEXIT branch fired
//   bit 4 (0x10): HandleHostException was called
//   bit 5 (0x20): HandleCpuid returned (so RIP advance executed)
//
STATIC volatile UINT32 g_HostProgressBits = 0;
STATIC volatile UINT32 g_LastUnhandledExitLo = 0;
STATIC volatile UINT32 g_LastUnhandledExitHi = 0;
STATIC volatile UINT32 g_LastExceptionVector = 0xFFFFFFFF;

//
// Test-and-set lock serializing all CMOS access. The 0x70 index latch is
// GLOBAL chipset state, not per-CPU, so the select(0x70)+write(0x71) pair must
// be atomic across cores or one CPU's value lands at another CPU's index.
//
STATIC volatile UINT32 g_CmosLock = 0;

//
// Write a byte to CMOS RAM at the given index (0x50-0x7F is "extended" area
// generally not touched by BIOS/RTC). CMOS survives warm reset and most
// power cycles, so it's our persistent diagnostic channel after Windows boot.
// We cannot use gRT->SetVariable from host context: winload calls
// SetVirtualAddressMap very early in Windows boot, which remaps firmware
// runtime services to virtual addresses that don't exist in our host CR3.
// First VMEXIT after SVAM would #PF the host and triple-fault.
//
// Bit 7 of port 0x70 is the NMI disable; preserve clear (NMI-enabled).
//
STATIC
VOID
WriteCmosByte (
    IN UINT8 Index,
    IN UINT8 Value
    )
{
    //
    // Serialize the stateful two-port protocol across all cores. Safe in host
    // context: GIF=0 means no INTR/NMI/SMI can preempt us mid-pair, and every
    // CPU is making forward progress, so this cannot deadlock. Without this,
    // concurrent VMEXITs (the norm under multi-threaded guest scanner) tear every CMOS
    // field and silently corrupt the very logs we use to diagnose the crash.
    //
    while (InterlockedCompareExchange32(&g_CmosLock, 0, 1) != 0)
    {
        CpuPause();
    }
    IoWrite8(0x70, Index & 0x7F);
    IoWrite8(0x71, Value);
    g_CmosLock = 0;
}

//
// Extended CMOS (0x80-0xFF) via ports 0x72/0x73. Uses the same g_CmosLock.
// The NMI-disable bit lives on port 0x70, not 0x72, so no masking needed.
// Allocated slots:
//   0x80  #UD exit total count (saturating low byte)
//   0x81  sentinel-matched count (our hypercalls)
//   0x82  sentinel-missed count (passthrough #UD to guest)
//   0x83  last dispatched command byte
//   0x84  NRip - RIP delta (should be 2 for UD2; 0 = NRip not populated)
//   0x85  last MSR intercept direction (0=RDMSR 1=WRMSR)
//   0x86  last intercepted MSR number [7:0]
//   0x87  last intercepted MSR number [15:8]
//   0x88  last intercepted MSR number [23:16]
//   0x89  last intercepted MSR number [31:24]
//   0x8A  WRMSR EFER with SVME=1 blocked count (saturating byte)
//   0x8B-0x92  g_HvGuardBase [7:0]..[63:56] — ROOT_CONTEXT physical base (8 bytes LE)
//   0x93-0x96  g_HvGuardSize [7:0]..[31:24] — ROOT_CONTEXT alloc size   (4 bytes LE)
//   0x97       NptMode at bad-NPF time (0=read NCr3, 1=exec NCr3)
//   0x98       HookCount at bad-NPF time (number of active NPT hooks)
//
STATIC
VOID
WriteExtCmosByte (
    IN UINT8 Index,
    IN UINT8 Value
    )
{
    while (InterlockedCompareExchange32(&g_CmosLock, 0, 1) != 0)
    {
        CpuPause();
    }
    IoWrite8(0x72, Index);
    IoWrite8(0x73, Value);
    g_CmosLock = 0;
}

//
// CMOS slot map (extended area, 0x50-0x7F):
//   0x50: host progress bitmask (one-shot bits, low byte of g_HostProgressBits)
//   0x51-0x54: last UNHANDLED exit code (low dword, little-endian)
//   0x55: last host exception vector
//   0x56: VMEXIT total counter low byte (wraps at 256)
//   0x57: last exit code low byte (always updates, even handled)
//   0x58-0x5F: PERSISTENT CRASH LOG — never cleared by HV reload. Sentinel 0x58:
//     0xDE=host-exception  0xBA=bad-NPF  0xBC=HV-guard-decode-fail  other=no data
//   0x60: VMEXIT counter wrap count (8-bit; together w/ 0x56 gives 16-bit total)
//   0x61: #SX (INIT) exits seen (low byte)
//
STATIC volatile UINT8 g_VmExitCount = 0;
STATIC volatile UINT8 g_VmExitWrap = 0;
STATIC volatile UINT8 g_LastExitCodeByte = 0;  // last exit code low byte; flushed to CMOS in CpuReset
STATIC volatile UINT8 g_InitCount = 0;
STATIC volatile UINT8 g_InitInterceptCount = 0;
STATIC volatile UINT8 g_IcrWriteCount = 0;
STATIC volatile UINT8 g_SipiEmulatedCount = 0;
STATIC volatile UINT8 g_ApResumedCount = 0;
STATIC volatile UINT8 g_LastIcrDeliveryMode = 0xFF;
STATIC volatile UINT8 g_NpfCount = 0;
STATIC volatile UINT8 g_NpfDecodeFailCount = 0;
STATIC volatile UINT8 g_HvGuardDropCount = 0;  // HV-guard NPF silent drops
STATIC volatile UINT8 g_LapicMmioWriteCount = 0;
// (removed) per-delivery-mode IPI counter: its CMOS slots (0x6A/0x6C/0x6E/0x6F/0x70)
// were never read and mode-6 collided with ICR_LO byte0 at 0x70.
STATIC volatile UINT32 g_LastIcrLow = 0;
STATIC volatile UINT32 g_LastIcrHi = 0;
//
// Per-exit-type histogram (saturating 16-bit) to find what's actually
// generating the VMEXIT overhead. Saturating (not wrapping) so the dominant
// "storm" type pins at 0xFFFF unambiguously while minor types show real counts.
// Dumped to CMOS 0x78-0x7F (free in this build). Read with ReadScratch.
//   0x78-0x79 NPF (LAPIC-page writes)  0x7A-0x7B CPUID
//   0x7C-0x7D MSR                      0x7E-0x7F other
//
STATIC volatile UINT16 g_ExitNpf      = 0;
STATIC volatile UINT16 g_ExitCpuid    = 0;
STATIC volatile UINT16 g_ExitMsr      = 0;
STATIC volatile UINT16 g_ExitOther    = 0;
STATIC volatile UINT32 g_HistThrottle = 0;
STATIC volatile UINT8  g_EferSvmeBlocked = 0;  // #GP(0) injections for WRMSR EFER with SVME=1
//
// LAPIC-page un-protect (perf). The LAPIC MMIO page is NPT-write-protected
// ONLY to catch SIPI writes during AP bringup. Once all APs are up, that
// protection is pure overhead — every EOI/IPI write becomes an NPF VMEXIT
// (the LAPIC storm). After bringup completes we flip the page back to writable
// so those writes go native to the real LAPIC, and flag every CPU to flush its
// NPT TLB once (per-CPU flag so even an idle/HLTed CPU flushes when it next
// exits — a global window would miss it).
//
STATIC volatile UINT8 g_LapicUnprotected = 0;
//
// Ring buffer of the last 8 unhandled exit codes (low byte each).
// CMOS 0x40 = write index (increments), 0x41-0x48 = slots (newest last).
// Survives warm reset. Read with ReadScratch to see the crash sequence.
//
STATIC volatile UINT8 g_ExitRingIdx = 0;

//
// Breadcrumb for diagnosing host #GP. Set immediately before any host-context
// operation that can fault on guest-controlled input (currently the WRMSR/RDMSR
// passthrough in HandleMsr). If the host takes a #GP, HandleHostException dumps
// this value to CMOS 0x4E so a post-mortem ReadScratch pins the faulting op:
//   0x00 = none      0xA1 = before WRMSR   0xA2 = WRMSR survived
//   0xA3 = before RDMSR   0xA4 = RDMSR survived
//
STATIC volatile UINT8 g_LastRiskyOp = 0;

UINT64 g_HvGuardBase = 0;
UINT64 g_HvGuardSize = 0;

//
// Split-page hook exec-flip counter (CMOS 0x6A) and switch-read counter (0x6C).
// g_ReadNcr3Pa / g_ExecNcr3Pa are defined in Setup.c and extern'd in shmr.h.
//
STATIC volatile UINT8 g_NpfExecFlipCount = 0;
STATIC volatile UINT8 g_NcrSwitchReadCount = 0;

//
// Fine-grained PH NPF diagnostic counters (read via PH_DIAG_COUNTERS hypercall).
// Not persisted to CMOS; live memory only, 32-bit wide so they don't wrap during
// a test run. Reset by ao load (zero-init).
//
//   g_PhNpfInstFetchCount : instruction-fetch NPFs the bad-fetch branch entered
//                           (any gpa, not just hooked)
//   g_PhGpaMatchCount     : fetch NPF whose gpa4K matched an active HookMeta entry
//                           (so the page IS hooked, something IS fetching it)
//   g_PhRipMatchCount     : PH entry found whose VA == guestRip
//                           (so the hooked instruction IS the one being fetched)
//   g_PhCr3MatchCount     : PH entry's CR3 also matched guestCr3
//                           (so the right process is executing it)
//   g_PhDispatchCount     : RunProcessHookScript actually ran
//                           (script executed — this is what "hits" counts, too)
//   g_PhStrayCount        : fetch NPF on hooked page but no PH entry claimed it
//                           (stray fetch — exec-flip w/ pending-flip-back)
//   g_PhLastGuestRip      : guestRip of the LAST PH-hook-page fetch NPF
//   g_PhLastGuestCr3      : guestCr3 of the LAST PH-hook-page fetch NPF
//   g_PhLastGpa4K         : gpa4K of the LAST PH-hook-page fetch NPF
//
STATIC volatile UINT32 g_PhNpfInstFetchCount = 0;
STATIC volatile UINT32 g_PhGpaMatchCount     = 0;
STATIC volatile UINT32 g_PhRipMatchCount     = 0;
STATIC volatile UINT32 g_PhCr3MatchCount     = 0;
STATIC volatile UINT32 g_PhDispatchCount     = 0;
STATIC volatile UINT32 g_PhStrayCount        = 0;
STATIC volatile UINT64 g_PhLastGuestRip      = 0;
STATIC volatile UINT64 g_PhLastGuestCr3      = 0;
STATIC volatile UINT64 g_PhLastGpa4K         = 0;

//
// Byte-trap (0xCC) hook metrics (also surfaced by diag_counters).
//   g_PhBpCount       : total #BP intercepts handled
//   g_PhBpOwnedCount  : of those, how many matched a PH entry (ours)
//   g_PhBpReinjectCount: re-injected to guest (native int3)
//
STATIC volatile UINT32 g_PhBpCount          = 0;
STATIC volatile UINT32 g_PhBpOwnedCount     = 0;
STATIC volatile UINT32 g_PhBpReinjectCount  = 0;

//
// Introspection state — populated on the first CPL=0 VMEXIT after the Windows
// kernel has loaded (LSTAR != 0).  g_KernelBase is populated lazily on the
// first GET_CR3 hypercall.  Reads/writes are single-writer (BSP first to CPL=0)
// so no lock is needed; the compiler volatile prevents tear.
//
STATIC volatile UINT64 g_KernelCr3   = 0;  // kernel DirectoryTableBase
STATIC volatile UINT64 g_KernelLstar = 0;  // saved LSTAR (KiSystemCall64 VA)
STATIC volatile UINT64 g_KernelCstar = 0;  // saved CSTAR (KiSystemCall32 VA — WoW64 / 32-bit syscall entry)
STATIC volatile UINT64 g_KernelBase  = 0;  // ntoskrnl.exe image base (lazy)

SYSCALL_LOG* g_SyscallLog = NULL;
PROCESS_HOOK_TABLE* g_ProcessHooks   = NULL;
PROCESS_HOOK_LOG*   g_ProcessHookLog = NULL;

//
// Updates the "always" trackers — counter + last exit code + last RIP.
// Called on every VMEXIT, before the switch. Lets us distinguish
// "stuck in a loop handling exit X" from "stopped firing exits at all".
//
STATIC
VOID
MarkProgress (
    IN UINT32 Bit
    )
{
    if ((g_HostProgressBits & Bit) == 0)
    {
        UINT32 value;
        g_HostProgressBits |= Bit;
        value = 0xA51E0000 | g_HostProgressBits;
        *(volatile UINT32*)0x10000040 = value;
        WriteCmosByte(0x50, (UINT8)g_HostProgressBits);
    }
}

STATIC
VOID
TrackVmExit (
    IN UINT64 ExitCode,
    IN UINT64 GuestRip
    )
{
    g_VmExitCount++;
    if (g_VmExitCount == 0)
    {
        g_VmExitWrap++;
    }
    //
    // Hot path: keep the exit count + last exit code in MEMORY only. These used
    // to hit CMOS on EVERY exit — two slow ISA-port writes per exit (~1us each),
    // badly amplified by guest scanner's CPUID/MSR probe storm. CpuReset() now flushes the
    // count, wrap, and last exit code to CMOS on the single path every fatal exit
    // funnels through; CMOS survives the warm reset so the post-mortem is intact.
    //
    g_LastExitCodeByte = (UINT8)(ExitCode & 0xFF);
    if (ExitCode == VMEXIT_EXCEPTION_SX)
    {
        g_InitCount++;
        WriteCmosByte(0x61, g_InitCount);
    }

    //
    // Per-exit-type histogram (saturating). Counts the cost drivers so we can
    // see what dominates the overhead instead of guessing. CMOS dump is
    // throttled (every 1024th exit) so it doesn't add I/O to the hot path; the
    // last dump before a read is always recent.
    //
    switch (ExitCode)
    {
    case VMEXIT_NPF:            if (g_ExitNpf   < 0xFFFF) g_ExitNpf++;   break;
    case VMEXIT_CPUID:          if (g_ExitCpuid < 0xFFFF) g_ExitCpuid++; break;
    case VMEXIT_MSR:            if (g_ExitMsr   < 0xFFFF) g_ExitMsr++;   break;
    case VMEXIT_EXCEPTION_UD:   if (g_ExitOther < 0xFFFF) g_ExitOther++; break;
    default:                    if (g_ExitOther < 0xFFFF) g_ExitOther++; break;
    }
    if ((++g_HistThrottle & 0x3FF) == 0)
    {
        WriteCmosByte(0x78, (UINT8)(g_ExitNpf   & 0xFF));
        WriteCmosByte(0x79, (UINT8)(g_ExitNpf   >> 8));
        WriteCmosByte(0x7A, (UINT8)(g_ExitCpuid & 0xFF));
        WriteCmosByte(0x7B, (UINT8)(g_ExitCpuid >> 8));
        WriteCmosByte(0x7C, (UINT8)(g_ExitMsr   & 0xFF));
        WriteCmosByte(0x7D, (UINT8)(g_ExitMsr   >> 8));
        WriteCmosByte(0x7E, (UINT8)(g_ExitOther & 0xFF));
        WriteCmosByte(0x7F, (UINT8)(g_ExitOther >> 8));
    }
}

//
// Record the actual ExitCode that hit the default branch.
// CMOS-persisted; no firmware calls (see WriteCmosByte comment).
//
STATIC
VOID
RecordUnhandledExit (
    IN UINT64 ExitCode
    )
{
    UINT32 lo = (UINT32)(ExitCode & 0xFFFFFFFF);
    g_LastUnhandledExitLo = lo;
    g_LastUnhandledExitHi = (UINT32)(ExitCode >> 32);
    WriteCmosByte(0x51, (UINT8)(lo & 0xFF));
    WriteCmosByte(0x52, (UINT8)((lo >> 8) & 0xFF));
    WriteCmosByte(0x53, (UINT8)((lo >> 16) & 0xFF));
    WriteCmosByte(0x54, (UINT8)((lo >> 24) & 0xFF));
}

//
// Push one exit code into the CMOS ring buffer (0x40-0x48).
// Only called for exits that hit the default branch (unhandled).
//
STATIC
VOID
RecordExitRing (
    IN UINT64 ExitCode
    )
{
    UINT8 slot = g_ExitRingIdx & 0x7;   // 8-slot ring
    WriteCmosByte(0x41 + slot, (UINT8)(ExitCode & 0xFF));
    g_ExitRingIdx++;
    WriteCmosByte(0x40, g_ExitRingIdx); // write index (reader uses this to find oldest)
}

//
// Record the host-exception vector (e.g., 0xD = #GP, 0xE = #PF).
//
STATIC
VOID
RecordExceptionVector (
    IN UINT32 Vector
    )
{
    g_LastExceptionVector = Vector;
    WriteCmosByte(0x55, (UINT8)(Vector & 0xFF));
}

#if ENABLE_HOST_MEMORY_LOGGING != 0

//
// DEBUG that logs messages into a memory buffer.
//
#if !defined(MDEPKG_NDEBUG)
#define HOST_DEBUG_INTERNAL(Context, ...)   LogToMemory((Context), ##__VA_ARGS__)
#define HOST_DEBUG(Expression)              HOST_DEBUG_INTERNAL Expression
#else
#define HOST_DEBUG(Expression)
#endif

//
// ASSERT that logs messages into a memory buffer.
//
// Failure path resets the machine instead of CpuDeadLoop'ing. CpuDeadLoop()
// makes the box appear hung, which is indistinguishable from a real lockup
// and makes diagnosis hard. CpuReset gives a visible signal.
//
#if !defined(MDEPKG_NDEBUG)
#define HOST_ASSERT(Expression) \
    do \
    { \
        if (!(Expression)) \
        { \
            LogToMemory(NULL, "ASSERT@%d APIC %d: %a\n", __LINE__, GetApicId(), #Expression); \
            CpuReset(); \
        } \
    } while (FALSE)
#else
#define HOST_ASSERT(Expression)
#endif

#else

//
// ENABLE_HOST_MEMORY_LOGGING is zero. Use the standard logging facility.
//
#define HOST_DEBUG_INTERNAL(Context, ...)   _DEBUG_PRINT(DEBUG_ERROR, __VA_ARGS__)
#define HOST_DEBUG(Expression)              HOST_DEBUG_INTERNAL Expression
#define HOST_ASSERT(Expression)             ASSERT(Expression)

#endif

//
// The layout of the stack address passed to HandleVmExit.
//
typedef struct _HOST_VMEXIT_STACK
{
    GUEST_REGISTERS GuestRegisters;
    HOST_STACK_BASED_PARAMETERS Params;
} HOST_VMEXIT_STACK;

//
// The layout of the stack address passed to HandleHostException.
//
typedef struct _HOST_EXCEPTION_STACK
{
    GUEST_REGISTERS GuestRegisters;
    UINT64 InterruptNumber;
    UINT64 ErrorCode;
    UINT64 Rip;
    UINT64 Cs;
    UINT64 Rflags;
} HOST_EXCEPTION_STACK;

//
// The system global log entry count. Useful for human to follow the order of
// logs across all processors (log buffers).
//
STATIC volatile UINT32 g_LogIndex;

/**
 * @brief Resets the system via the chipset reset register (0xCF9).
 *
 * Direct I/O port write — no firmware runtime-service dependency, so it works
 * from host context where gRT->ResetSystem may be unreachable through our host
 * CR3. Writing 0x0E to port 0xCF9 (FULL_RST | SYS_RST | RST_CPU) triggers an
 * immediate cold reset on all PCH/FCH-compatible chipsets.
 */
STATIC
VOID
CpuReset (
    VOID
    )
{
    //
    // Flush the in-memory diagnostic summary to CMOS now, on the way down. This
    // is the single choke point every fatal exit funnels through (bad NPF, LAPIC
    // decode fail, VMEXIT_SHUTDOWN, VMEXIT_INVALID, host exception), so dumping
    // here replaces the old per-exit CMOS writes with one flush at death. CMOS
    // survives the warm reset; ReadScratch sees the last state post-reboot.
    //   0x56 = VMEXIT count (low byte)   0x60 = wrap count (together: 16-bit)
    //   0x57 = last exit code (low byte)
    //   0x78-0x7F = per-type histogram (NPF / CPUID / MSR / other)
    //
    WriteCmosByte(0x56, g_VmExitCount);
    WriteCmosByte(0x57, g_LastExitCodeByte);
    WriteCmosByte(0x60, g_VmExitWrap);
    WriteCmosByte(0x78, (UINT8)(g_ExitNpf   & 0xFF));
    WriteCmosByte(0x79, (UINT8)(g_ExitNpf   >> 8));
    WriteCmosByte(0x7A, (UINT8)(g_ExitCpuid & 0xFF));
    WriteCmosByte(0x7B, (UINT8)(g_ExitCpuid >> 8));
    WriteCmosByte(0x7C, (UINT8)(g_ExitMsr   & 0xFF));
    WriteCmosByte(0x7D, (UINT8)(g_ExitMsr   >> 8));
    WriteCmosByte(0x7E, (UINT8)(g_ExitOther & 0xFF));
    WriteCmosByte(0x7F, (UINT8)(g_ExitOther >> 8));

    //
    // Standard PCH reset sequence per Intel/AMD platform docs. Some chipsets
    // ignore a one-shot 0x0E and want a 0x02 -> 0x06 transition.
    //
    IoWrite8(0xCF9, 0x02);
    IoWrite8(0xCF9, 0x06);
    IoWrite8(0xCF9, 0x0E);
    //
    // Fall back to the firmware runtime service if PCH reset somehow failed.
    //
    if (g_ResetSystemPhys != NULL)
    {
        g_ResetSystemPhys(EfiResetCold, EFI_ABORTED, 0, NULL);
    }
    CpuDeadLoop();
}

/**
 * @brief Stores the log message to the provided buffer.
 *
 * @details This function is not safe to call concurrently against the same buffer.
 */
STATIC
VOID
LogToMemory (
    IN OUT HOST_CONTEXT* Context OPTIONAL,
    IN CONST CHAR8* FormatString,
    ...
    )
{
    UINT32 index;
    VA_LIST args;
    MEMORY_LOGS* logs;

    logs = (Context == NULL) ? g_GlobalLogBuffer : &Context->Cpu->Logs;

    //
    // Pick up the index of log buffer to write to. The index go back to zero
    // if it overflows.
    //
    index = InterlockedIncrement(&logs->NextPosition) - 1;
    if (index >= ARRAY_SIZE(logs->Entries))
    {
        logs->NextPosition = 0;
        index = 0;
    }

    //
    // Take the system global index.
    //
    logs->Entries[index].GlobalIndex = InterlockedIncrement(&g_LogIndex);

    //
    // Zero out the current log entry instead of leaving old data if any. Then,
    // write the log message into it.
    //
    ZeroMem(logs->Entries[index].Message, sizeof(logs->Entries[index].Message));

    VA_START(args, FormatString);
    AsciiVSPrint(logs->Entries[index].Message,
                 sizeof(logs->Entries[index].Message),
                 FormatString,
                 args);
    VA_END(args);

    //
    // If EFI variables are usable, write back the whole 4KB log buffer to it.
    //
    if (g_SetVariablePhys != NULL)
    {
        EFI_STATUS status;
        CHAR16 variableName[16];
        UINT32 processorNumber;

        processorNumber = (Context == NULL) ? 0 : Context->Cpu->States.Guest.ProcessorNumber;
        UnicodeSPrint(variableName, sizeof(variableName), L"Log#%d", processorNumber);
        status = g_SetVariablePhys(variableName,
                                   &g_LogGuid,
                                   EFI_VARIABLE_NON_VOLATILE |
                                   EFI_VARIABLE_BOOTSERVICE_ACCESS |
                                   EFI_VARIABLE_RUNTIME_ACCESS,
                                   sizeof(*logs),
                                   logs);
        if (EFI_ERROR(status))
        {
            CpuDeadLoop();
            CpuReset();
        }
    }
}

/**
 * @brief Handles CPUID.
 */
STATIC
VOID
HandleCpuid (
    IN OUT HOST_CONTEXT* Context
    )
{
    UINT32 registers[4];   // EAX, EBX, ECX, and EDX
    UINT32 leaf;
    UINT32 subLeaf;

    MarkProgress(0x02);

    //
    // Execute CPUID as requested.
    //
    leaf = (UINT32)Context->Cpu->States.Guest.Registers->Rax;
    subLeaf = (UINT32)Context->Cpu->States.Guest.Registers->Rcx;
    AsmCpuidEx(leaf, subLeaf, &registers[0], &registers[1], &registers[2], &registers[3]);

    switch (leaf)
    {
    case CPUID_VERSION_INFO:
        //
        // Clear the Hypervisor Present bit (ECX[31]). Windows reads this at
        // boot to set HalpHypervisorPresent and guest scanner re-checks it directly.
        // Leaving it set is the single most visible HV indicator.
        //
        registers[2] &= ~BIT31;
        break;

    case CPUID_EXTENDED_CPU_SIG:
        //
        // Hide SVM support so the guest doesn't try to enable its own SVM.
        //
        registers[2] &= ~CPUID_EXTENDED_CPU_SIG_ECX_SVM;
        break;

    case 0x8000000AU:
        //
        // SVM feature leaf. Since we clear the SVM bit in 0x80000001 ECX[2],
        // returning real SVM revision/ASID data here is a detectable inconsistency.
        // Return all zeros — matches what a non-SVM-capable CPU would return.
        //
        registers[0] = 0;
        registers[1] = 0;
        registers[2] = 0;
        registers[3] = 0;
        break;

    default:
        //
        // For any unhandled leaf in the hypervisor-reserved CPUID range
        // (0x40000000-0x4FFFFFFF), return all zeros instead of whatever
        // native CPUID produces. Native silicon's behavior for those leaves
        // is implementation-defined and can leak garbage, which trips up
        // OS-level HV consistency checks (Windows queries multiple HV leaves
        // during boot — Hv version, features, etc. — and expects consistent
        // "no support" responses).
        //
        if (leaf >= 0x40000000 && leaf <= 0x4FFFFFFF)
        {
            registers[0] = 0;
            registers[1] = 0;
            registers[2] = 0;
            registers[3] = 0;
        }
        break;
    }

    //
    // Update guest's GPRs with results.
    //
    Context->Cpu->States.Guest.Registers->Rax = registers[0];
    Context->Cpu->States.Guest.Registers->Rbx = registers[1];
    Context->Cpu->States.Guest.Registers->Rcx = registers[2];
    Context->Cpu->States.Guest.Registers->Rdx = registers[3];

    Context->Cpu->GuestVmcb.StateSaveArea.Rip = Context->Cpu->GuestVmcb.ControlArea.NRip;
    MarkProgress(0x20);
}

/**
 * @brief Handles VMEXIT_INIT by resetting AP guest to architectural INIT state
 *      then PARKING this AP in WAIT_FOR_SIPI. Returns only after BSP's SIPI
 *      emulation flips this CPU's ApState back to RUNNING (and has rewritten
 *      our VMCB CS:RIP to point at the SIPI vector).
 *
 *      Why we can spin safely here: we're in host context post-VMEXIT, so
 *      GIF=0 — no INTR/NMI/SMI will arrive on this CPU. The only event that
 *      can release us is BSP writing AP_STATE_RUNNING to our state field.
 *      x86 TSO ensures BSP's VMCB stores (made before the state-change store)
 *      are visible to us when we observe the state change.
 *
 *      WARNING: if BSP never sends SIPI, we spin forever. Acceptable because
 *      Windows always follows INIT with SIPI; if it doesn't, the system is
 *      already in a stuck state.
 */
STATIC
VOID
HandleInitSignal (
    IN OUT HOST_CONTEXT* Context
    )
{
    IA32_CR0 oldCr0;
    IA32_CR0 newCr0;
    CPUID_VERSION_INFO_EAX cpuEax;

    MarkProgress(0x80);
    oldCr0.UintN = Context->Cpu->GuestVmcb.StateSaveArea.Cr0;
    newCr0.UintN = 0;
    newCr0.Bits.ET = 1;
    newCr0.Bits.CD = oldCr0.Bits.CD;
    newCr0.Bits.NW = oldCr0.Bits.NW;

    AsmCpuid(CPUID_VERSION_INFO, &cpuEax.Uint32, NULL, NULL, NULL);

    Context->Cpu->GuestVmcb.StateSaveArea.Cr0    = newCr0.UintN;
    Context->Cpu->GuestVmcb.StateSaveArea.Cr2    = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.Cr3    = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.Cr4    = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.Rflags = BIT1;
    Context->Cpu->GuestVmcb.StateSaveArea.Efer   = EFER_SVME;
    Context->Cpu->GuestVmcb.StateSaveArea.Rip    = 0xfff0;
    Context->Cpu->GuestVmcb.StateSaveArea.CsSelector = 0xf000;
    Context->Cpu->GuestVmcb.StateSaveArea.CsBase    = 0xffff0000;
    Context->Cpu->GuestVmcb.StateSaveArea.CsLimit   = 0xffff;
    Context->Cpu->GuestVmcb.StateSaveArea.CsAttrib  = 0x9b;
    Context->Cpu->GuestVmcb.StateSaveArea.DsSelector = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.DsBase     = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.DsLimit    = 0xffff;
    Context->Cpu->GuestVmcb.StateSaveArea.DsAttrib   = 0x93;
    Context->Cpu->GuestVmcb.StateSaveArea.EsSelector = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.EsBase     = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.EsLimit    = 0xffff;
    Context->Cpu->GuestVmcb.StateSaveArea.EsAttrib   = 0x93;
    Context->Cpu->GuestVmcb.StateSaveArea.SsSelector = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.SsBase     = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.SsLimit    = 0xffff;
    Context->Cpu->GuestVmcb.StateSaveArea.SsAttrib   = 0x93;
    Context->Cpu->GuestVmcb.StateSaveArea.FsSelector = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.FsBase     = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.FsLimit    = 0xffff;
    Context->Cpu->GuestVmcb.StateSaveArea.FsAttrib   = 0x93;
    Context->Cpu->GuestVmcb.StateSaveArea.GsSelector = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.GsBase     = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.GsLimit    = 0xffff;
    Context->Cpu->GuestVmcb.StateSaveArea.GsAttrib   = 0x93;
    Context->Cpu->GuestVmcb.StateSaveArea.LdtrSelector = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.LdtrBase     = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.LdtrLimit    = 0xffff;
    Context->Cpu->GuestVmcb.StateSaveArea.LdtrAttrib   = 0x82;
    Context->Cpu->GuestVmcb.StateSaveArea.TrSelector = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.TrBase     = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.TrLimit    = 0xffff;
    Context->Cpu->GuestVmcb.StateSaveArea.TrAttrib   = 0x8b;
    Context->Cpu->GuestVmcb.StateSaveArea.GdtrBase   = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.GdtrLimit  = 0xffff;
    Context->Cpu->GuestVmcb.StateSaveArea.IdtrBase   = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.IdtrLimit  = 0xffff;
    Context->Cpu->GuestVmcb.StateSaveArea.Rsp        = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.Cpl        = 0;
    Context->Cpu->States.Guest.Registers->Rax        = 0;
    Context->Cpu->States.Guest.Registers->Rdx        = cpuEax.Uint32;
    Context->Cpu->States.Guest.Registers->Rbx        = 0;
    Context->Cpu->States.Guest.Registers->Rcx        = 0;
    Context->Cpu->GuestVmcb.StateSaveArea.Dr6        = 0xffff0ff0;
    Context->Cpu->GuestVmcb.StateSaveArea.Dr7        = 0x400;

    //
    // Drop any pending event injection and interrupt shadow so the freshly-reset
    // AP starts cleanly at the reset vector with GIF=1.
    //
    Context->Cpu->GuestVmcb.ControlArea.EventInj        = 0;
    Context->Cpu->GuestVmcb.ControlArea.ExitIntInfo     = 0;
    Context->Cpu->GuestVmcb.ControlArea.InterruptShadow = 0;
    Context->Cpu->GuestVmcb.ControlArea.TlbControl      = 1;
    Context->Cpu->GuestVmcb.ControlArea.VmcbClean       = 0;

    //
    // Park this AP. BSP's HandleIcrWrite -> EmulateSipiDelivery will, when
    // Windows writes SIPI to LAPIC ICR, overwrite our CS:RIP for the SIPI
    // vector and flip ApState back to RUNNING.
    //
    Context->Cpu->States.Guest.ApState = AP_STATE_WAIT_FOR_SIPI;

    // Log this AP's stored APIC ID so ReadScratch can verify they match what
    // Windows sends in ICR_HI. CMOS 0x4D=AP1, 0x4E=AP2, 0x4F=AP3 (procNum 1-3).
    {
        UINT32 pn = Context->Cpu->States.Guest.ProcessorNumber;
        if (pn >= 1 && pn <= 3)
        {
            WriteCmosByte((UINT8)(0x4C + pn), (UINT8)(Context->Cpu->States.Guest.ApicId & 0xFF));
        }
    }

    g_InitInterceptCount++;
    WriteCmosByte(0x62, g_InitInterceptCount);

    //
    // Spin forever waiting for BSP's SIPI emulation to flip our state to
    // RUNNING and write the SIPI vector into our VMCB CS:RIP. Per barevisor
    // pattern — no timeout. If we ever escape this loop with garbage state
    // we'd triple-fault at the reset vector silently; better to stay parked
    // and have the CPU visibly stuck (debuggable) than silently dead.
    //
    while (Context->Cpu->States.Guest.ApState != AP_STATE_RUNNING)
    {
        CpuPause();
    }

    g_ApResumedCount++;
    WriteCmosByte(0x66, g_ApResumedCount);
}

//
// x2APIC ICR layout (Intel SDM Vol 3 §10.12; AMD inherits). 64-bit MSR 0x830.
//
//   [7:0]    Vector (for SIPI: AP starts at vector<<12)
//   [10:8]   Delivery mode  000=Fixed 010=SMI 100=NMI 101=INIT 110=SIPI 111=ExtINT
//   [11]     Destination mode (0=physical APIC ID, 1=logical)
//   [12]     Delivery status (read-only)
//   [14]     Level (1=assert; INIT-deassert uses level=0)
//   [15]     Trigger mode (0=edge, 1=level)
//   [19:18]  Destination shorthand  00=no shorthand  01=self  10=all incl  11=all excl self
//   [63:32]  Destination APIC ID (full 32-bit in x2APIC mode)
//
#define ICR_DELIVERY_FIXED  0u
#define ICR_DELIVERY_SMI    2u
#define ICR_DELIVERY_NMI    4u
#define ICR_DELIVERY_INIT   5u
#define ICR_DELIVERY_SIPI   6u
#define ICR_DELIVERY_EXTINT 7u

#define ICR_DEST_SHORT_NONE     0u
#define ICR_DEST_SHORT_SELF     1u
#define ICR_DEST_SHORT_ALL      2u
#define ICR_DEST_SHORT_ALL_BUT  3u

/**
 * @brief Returns the PER_CPU_DATA for the given guest APIC ID, or NULL if no
 *      virtualized CPU matches. APIC IDs are populated in States.Guest.ApicId
 *      during PrepareForVmrun via the LocalApicLib query.
 */
STATIC
PER_CPU_DATA*
FindCpuByApicId (
    IN ROOT_CONTEXT* Root,
    IN UINT32 ApicId
    )
{
    UINT32 count = Root->HostX64.ProcessorCount;
    for (UINT32 i = 0; i < count; ++i)
    {
        if (Root->Cpus[i].States.Guest.ApicId == ApicId)
        {
            return &Root->Cpus[i];
        }
    }
    return NULL;
}

/**
 * @brief Emulates a SIPI delivery to the target AP. Caller has already
 *      verified delivery mode == ICR_DELIVERY_SIPI. The target AP is
 *      expected to be spinning in HandleVmExit with ApState == WAIT_FOR_SIPI
 *      (set by HandleInit when the prior INIT was delivered). We modify the
 *      target's VMCB state-save area to set CS:RIP to (vector<<8):0 in real
 *      mode (AMD APM SIPI behavior), then flip ApState to RUNNING so the
 *      target AP's spin loop exits and VMRUN proceeds.
 *
 *      x86 TSO guarantees the VMCB stores are observed by the target before
 *      the ApState=RUNNING store (which is the last store from BSP and the
 *      only one the target polls on). No explicit fence needed.
 */
STATIC
VOID
EmulateSipiDelivery (
    IN OUT PER_CPU_DATA* TargetCpu,
    IN UINT8 Vector
    )
{
    if (TargetCpu->States.Guest.ApState != AP_STATE_WAIT_FOR_SIPI)
    {
        // SIPI to a CPU not in wait-for-SIPI is ignored (AMD APM §15.21.7).
        // Common case: Windows sends INIT-SIPI-SIPI; the second SIPI lands
        // here because the AP already woke on the first.
        return;
    }

    //
    // Per AMD APM "SIPI": CS.base = vector<<12, CS.selector = vector<<8,
    // CS.limit = 0xFFFF, real-mode CS attributes, RIP = 0. Other segments
    // and CR0/EFER were already set to architectural INIT values in HandleInit.
    //
    TargetCpu->GuestVmcb.StateSaveArea.CsSelector = ((UINT16)Vector) << 8;
    TargetCpu->GuestVmcb.StateSaveArea.CsBase     = ((UINT64)Vector) << 12;
    TargetCpu->GuestVmcb.StateSaveArea.CsLimit    = 0xFFFF;
    TargetCpu->GuestVmcb.StateSaveArea.CsAttrib   = 0x9B;
    TargetCpu->GuestVmcb.StateSaveArea.Rip        = 0;

    // Invalidate VMCB clean bits so hardware reloads everything on VMRUN.
    TargetCpu->GuestVmcb.ControlArea.VmcbClean = 0;
    TargetCpu->GuestVmcb.ControlArea.TlbControl = 1;  // flush this guest's TLB

    TargetCpu->States.Guest.SipiVector = Vector;
    // Last store — x86 TSO ensures the VMCB writes above are visible first.
    TargetCpu->States.Guest.ApState = AP_STATE_RUNNING;

    g_SipiEmulatedCount++;
    WriteCmosByte(0x63, g_SipiEmulatedCount);
}

/**
 * @brief Handles a guest write to x2APIC ICR (MSR 0x830). The ICR value is in
 *      EDX:EAX (per wrmsr ABI). Decodes the delivery mode:
 *
 *        - INIT (5):  pass-through. The actual wrmsr writes the hardware
 *                      LAPIC, which delivers INIT to the target AP. The
 *                      target AP intercepts (InterceptMisc1.INIT) and its
 *                      HandleInit clears state and enters WAIT_FOR_SIPI.
 *
 *        - SIPI (6):  emulate. Don't write hardware (we don't want hardware
 *                      SIPI delivery — AP isn't in architectural
 *                      wait-for-SIPI). Instead, manually modify the target
 *                      AP's VMCB and flip its state.
 *
 *        - Other:     pass-through. Fixed/NMI/SMI IPIs are normal Windows
 *                      operation; let hardware deliver them.
 *
 *      Destination shorthand is supported for self/all/all-but-self.
 *      Returns whether the write was passed through to hardware.
 */
STATIC
BOOLEAN
HandleIcrWrite (
    IN OUT HOST_CONTEXT* Context,
    IN UINT64 IcrValue
    )
{
    UINT8 vector;
    UINT8 deliveryMode;
    UINT8 destShorthand;
    UINT32 destApicId;
    BOOLEAN passThrough;

    vector        = (UINT8)(IcrValue & 0xFF);
    deliveryMode  = (UINT8)((IcrValue >> 8) & 0x7);
    destShorthand = (UINT8)((IcrValue >> 18) & 0x3);
    destApicId    = (UINT32)(IcrValue >> 32);

    g_IcrWriteCount++;
    WriteCmosByte(0x64, g_IcrWriteCount);
    g_LastIcrDeliveryMode = deliveryMode;
    WriteCmosByte(0x65, deliveryMode);

    passThrough = TRUE;

    if (deliveryMode == ICR_DELIVERY_SIPI)
    {
        //
        // Emulate SIPI to either a specific AP or a broadcast subset.
        //
        passThrough = FALSE;
        if (destShorthand == ICR_DEST_SHORT_NONE)
        {
            PER_CPU_DATA* target = FindCpuByApicId(Context->Root, destApicId);
            if (target != NULL && target != Context->Cpu)
            {
                EmulateSipiDelivery(target, vector);
            }
        }
        else if (destShorthand == ICR_DEST_SHORT_ALL ||
                 destShorthand == ICR_DEST_SHORT_ALL_BUT)
        {
            UINT32 count = Context->Root->HostX64.ProcessorCount;
            for (UINT32 i = 0; i < count; ++i)
            {
                PER_CPU_DATA* target = &Context->Root->Cpus[i];
                if (destShorthand == ICR_DEST_SHORT_ALL_BUT &&
                    target == Context->Cpu)
                {
                    continue;
                }
                EmulateSipiDelivery(target, vector);
            }
        }
        // self-shorthand for SIPI is meaningless; ignore.
    }

    return passThrough;
}

/**
 * @brief Handles VMEXIT_MSR. With our current MSRPM, this fires only for
 *      x2APIC ICR writes (MSR 0x830). We special-case ICR; everything else
 *      shouldn't reach us. If it does (defensive), pass through.
 */
STATIC
VOID
HandleMsr (
    IN OUT HOST_CONTEXT* Context
    )
{
    UINT32 msr;
    BOOLEAN isWrite;
    UINT64 value;
    BOOLEAN passThrough;

    msr = (UINT32)Context->Cpu->States.Guest.Registers->Rcx;
    isWrite = (Context->Cpu->GuestVmcb.ControlArea.ExitInfo1 != 0);
    passThrough = TRUE;

    if (msr == 0xC0000080UL && !isWrite)
    {
        //
        // RDMSR IA32_EFER: return the guest's VMCB Efer value with SVME=0.
        // VMRUN requires SVME=1 in the VMCB, but the guest must not see it —
        // guest scanner reads EFER from ring-0 and treats SVME=1 as proof of a hypervisor.
        //
        UINT64 efer = Context->Cpu->GuestVmcb.StateSaveArea.Efer & ~(UINT64)EFER_SVME;
        Context->Cpu->States.Guest.Registers->Rax = (UINT32)(efer & 0xFFFFFFFF);
        Context->Cpu->States.Guest.Registers->Rdx = (UINT32)(efer >> 32);
    }
    else if ((msr >= 0xC0010114UL && msr <= 0xC0010117UL) && isWrite)
    {
        // WRMSR to any SVM MSR: bare metal with SVME=0 #GPs on these.
        // Without this intercept the write hits real HW (SVME=1) and
        // succeeds — detectable by guest scanner as proof of a hypervisor.
        Context->Cpu->GuestVmcb.ControlArea.EventInj =
            (1ULL << 31) | (1ULL << 11) | (3ULL << 8) | 13ULL;  // #GP(0)
        return;
    }
    else if ((msr == 0xC0010115UL || msr == 0xC0010116UL) && !isWrite)
    {
        // RDMSR SVM_IGNNE / SVM_SMM_CTL: #GP on bare metal with SVME=0.
        Context->Cpu->GuestVmcb.ControlArea.EventInj =
            (1ULL << 31) | (1ULL << 11) | (3ULL << 8) | 13ULL;  // #GP(0)
        return;
    }
    else if (msr == 0xC0000080UL && isWrite)
    {
        //
        // WRMSR EFER: present a "BIOS-disabled SVM" picture (SVMDIS=1+LOCK=1).
        // Any attempt to set SVME=1 #GPs, exactly as silicon does when SVMDIS=1.
        // For valid writes (no SVME), update the VMCB directly — SVME is forced
        // back on by line 2412 so VMRUN stays consistent.
        //
        UINT64 newEfer = ((UINT64)(UINT32)Context->Cpu->States.Guest.Registers->Rdx << 32) |
                         (UINT64)(UINT32)Context->Cpu->States.Guest.Registers->Rax;
        if (newEfer & EFER_SVME)
        {
            if (g_EferSvmeBlocked < 0xFF) ++g_EferSvmeBlocked;
            WriteExtCmosByte(0x8A, g_EferSvmeBlocked);
            Context->Cpu->GuestVmcb.ControlArea.EventInj =
                (1ULL << 31) | (1ULL << 11) | (3ULL << 8) | 13ULL;  // #GP(0)
            return;
        }
        Context->Cpu->GuestVmcb.StateSaveArea.Efer = newEfer | EFER_SVME;
    }
    else if (msr == SVM_MSR_VM_CR && !isWrite)
    {
        //
        // RDMSR VM_CR: simulate a BIOS-disabled-SVM system. Real hardware has
        // SVMDIS=0 (SVM available to OS) and LOCK=0, which contradicts EFER.SVME=0
        // and gives the HV away. Return SVMDIS=1+LOCK=1 to match a system where
        // the BIOS locked off SVM before Windows booted. Also hide R_INIT.
        //
        UINT64 vmCr = AsmReadMsr64(SVM_MSR_VM_CR);
        vmCr &= ~(UINT64)VM_CR_R_INIT;
        vmCr |= VM_CR_SVMDIS | VM_CR_LOCK;
        Context->Cpu->States.Guest.Registers->Rax = (UINT32)(vmCr & 0xFFFFFFFF);
        Context->Cpu->States.Guest.Registers->Rdx = (UINT32)(vmCr >> 32);
    }
    else if (msr == 0xC0010117UL && !isWrite)
    {
        //
        // RDMSR VM_HSAVE_PA: inject #GP(0). AMD APM: reading SVM MSRs with
        // SVME=0 causes #GP. guest scanner structured-exception-handles this RDMSR and
        // expects a #GP on bare metal; returning 0 instead is detectable.
        //
        Context->Cpu->GuestVmcb.ControlArea.EventInj =
            (1ULL << 31) | (1ULL << 11) | (3ULL << 8) | 13ULL;  // #GP(0)
        return;
    }
    else if (msr == 0x830 && isWrite)
    {
        //
        // x2APIC ICR write. THIS is the guest scanner-init crash: guest scanner writes MSR 0x830
        // directly (not via the xAPIC MMIO path Windows uses) with values that
        // #GP on real hardware, as an anti-VM / anti-tamper probe. On bare metal
        // that #GP is delivered to the GUEST and guest scanner handles it. If we blindly
        // AsmWriteMsr64() the guest value in HOST context, the host LAPIC #GPs
        // *us* and the machine hard-resets (the black screen). So we replicate
        // hardware's #GP decision here and inject #GP(0) into the guest instead
        // of ever executing a faulting WRMSR.
        //
        // WRMSR 0x830 #GPs when:
        //   (a) x2APIC mode is not enabled (IA32_APIC_BASE[10] == 0) — any
        //       access to the 0x800-0x8FF MSR range #GPs; OR
        //   (b) a reserved bit is set in the ICR; OR
        //   (c) the delivery mode field is reserved (011b).
        // Valid x2APIC ICR low-32 bits: vector[7:0], delivery mode[10:8],
        // dest mode[11], level[14], trigger[15], dest shorthand[19:18].
        //
        value = ((UINT64)(UINT32)Context->Cpu->States.Guest.Registers->Rdx << 32) |
                (UINT64)(UINT32)Context->Cpu->States.Guest.Registers->Rax;

        {
            UINT64  apicBase     = AsmReadMsr64(0x1B);              // IA32_APIC_BASE
            BOOLEAN x2Enabled    = (apicBase & (1ULL << 10)) != 0;
            UINT8   deliveryMode = (UINT8)((value >> 8) & 0x7);
            UINT32  validLowMask = 0x000CCFFFu;
            BOOLEAN reservedSet  = ((UINT32)value & ~validLowMask) != 0;
            //
            // Valid x2APIC ICR delivery modes per Intel SDM §10.6.1 and AMD APM
            // §16.5.1: Fixed(0), SMI(2), NMI(4), INIT(5), SIPI(6).
            // Lowest-Priority(1) and ExtINT(7) are NOT supported for ICR WRMSR in
            // x2APIC mode on either Intel or AMD — they #GP on real hardware.
            // guest scanner deliberately sends mode-1 or mode-7 IPIs as an anti-HV probe:
            // it expects a #GP delivered to the GUEST, not a host-mode #GP that
            // cold-resets the machine. Filter them here like mode-3.
            //
            BOOLEAN validMode    = (deliveryMode == 0 || deliveryMode == 2 ||
                                    deliveryMode == 4 || deliveryMode == 5 ||
                                    deliveryMode == 6);

            if (!x2Enabled || !validMode || reservedSet)
            {
                // Would #GP on hardware -> reflect to guest.
                Context->Cpu->GuestVmcb.ControlArea.EventInj =
                    (1ULL << 31) | (1ULL << 11) | (3ULL << 8) | 13ULL;  // #GP(0)
                return;
            }

            // Architecturally legal write. SIPI we fully emulate (no hardware
            // write); everything else is a real IPI we let hardware deliver.
            passThrough = HandleIcrWrite(Context, value);
        }
    }

    // Intentionally do NOT passthrough WRMSR 0x830 to host hardware. Executing
    // AsmWriteMsr64(0x830) in host context sends a real IPI to other cores that
    // are currently running host code. Those cores have no handler for arbitrary
    // interrupt vectors, so the IPI fires the default IDT stub -> HandleHostException
    // -> CpuReset. The guest sees the write as successful (NRip advances) which is
    // correct: after bringup the MSRPM intercept is cleared anyway, so Windows
    // x2APIC IPI traffic reaches hardware directly without going through us.

    Context->Cpu->GuestVmcb.StateSaveArea.Rip = Context->Cpu->GuestVmcb.ControlArea.NRip;
}

//
// Magic sentinel in RAX[63:32] that identifies a ao UD2 hypercall.
// Lower 32 bits are the command number.  Must match ao_client.h.
//
#define AO_HYPERCALL_MAGIC    0x56484F41UL    // "AOHV"
#define AO_CMD_PING           0UL
#define AO_CMD_READ_MEM       1UL
#define AO_CMD_GET_CR3        2UL
#define AO_CMD_VA_TO_PA       3UL
// Diagnostic commands — each returns one UINT64 of internal HV state.
#define AO_CMD_DIAG_CR3       4UL   // g_KernelCr3   (0 = not captured yet)
#define AO_CMD_DIAG_LSTAR     5UL   // g_KernelLstar  (0 = not captured yet)
#define AO_CMD_DIAG_BASE      6UL   // g_KernelBase (triggers FindKernelBase; ~0 = failed)
#define AO_CMD_DIAG_PSYS      7UL   // PsInitialSystemProcess VA  (~0 = not found)
#define AO_CMD_DIAG_PEOFF     8UL   // e_lfanew | (optMagic << 32)
#define AO_CMD_DIAG_EXPDIR    9UL   // export dir RVA | (size << 32)
#define AO_CMD_DIAG_NNAMES   10UL   // NumberOfNames in export directory
#define AO_CMD_LIST_PROCS    11UL   // walk EPROCESS list → write entries to caller buf
#define AO_CMD_GET_PROC_BASE 12UL   // find process by name → return SectionBaseAddress
#define AO_CMD_WRITE_GPA     13UL   // write bytes from caller VA to a guest physical addr
#define AO_CMD_ALLOC_SHADOW  14UL   // reserve next shadow page; returns its GPA
#define AO_CMD_NPT_HOOK         15UL   // install split-page hook at target GPA
#define AO_CMD_NCR3_SWITCH_READ 16UL   // from within shadow code: switch back to read NCr3
#define AO_CMD_FIND_MODULE      17UL   // find DllBase of a named module in a named process
#define AO_CMD_READ_GPA         23UL   // read bytes from a guest physical addr into caller VA
#define AO_CMD_SYSCALL_LOG_START        24UL  // SAFE: alloc ring buffer, don't install NPT hook
#define AO_CMD_SYSCALL_LOG_STOP         25UL  // stop syscall logging, uninstall hook if active
#define AO_CMD_SYSCALL_LOG_READ         26UL  // drain log entries to caller buffer
#define AO_CMD_SYSCALL_LOG_START_UNSAFE 27UL  // UNSAFE: install NPT hook with TF single-step flip-back
#define AO_CMD_SYSCALL_LOG_STATUS       28UL  // return live hook/log state (see SYSCALL_LOG_STATUS struct)
#define AO_CMD_CLEAR_HOOKS              30UL  // tear down all NPT hooks, reset shadow pool, switch CPUs to read NCr3
#define AO_CMD_PH_REGISTER              40UL  // install a process hook + script (R10=args struct VA)
#define AO_CMD_PH_UNREGISTER            41UL  // uninstall a process hook by slot index (RCX=index)
#define AO_CMD_PH_STATUS                42UL  // fill a caller-provided status struct with hook table state
#define AO_CMD_PH_LOG_READ              43UL  // drain debug-log entries into caller buf
#define AO_CMD_PH_CLEAR                 44UL  // mark all process hooks inactive (keeps NPT page hooks)
#define AO_CMD_PH_DIAG_WALK             45UL  // walk active NPT tree for (cr3, va); return entries at each level
#define AO_CMD_PH_DIAG_NCR3             46UL  // return NCr3 state (g_*/VMCB)
#define AO_CMD_PH_DIAG_HOOKMETA         47UL  // dump SHARED_SVM_DATA.HookMeta.Hooks[]
#define AO_CMD_PH_DIAG_COUNTERS         48UL  // dump fine-grained NPF/dispatch counters
#define AO_CMD_PH_SET_CFG               49UL  // write a PH_CFG slot: RCX=slot_idx, RDX=cfg_idx, R8=value
#define AO_CMD_PH_GET_CFG               50UL  // read  a PH_CFG slot: RCX=slot_idx, RDX=cfg_idx ; RAX = value or -1

//
// #UD channel diagnostics — read via ReadScratch (ext CMOS 0x80-0x84).
//
STATIC volatile UINT8 g_UdExitCount  = 0;  // 0x80: total #UD exits
STATIC volatile UINT8 g_UdMatchCount = 0;  // 0x81: sentinel matched (our calls)
STATIC volatile UINT8 g_UdMissCount  = 0;  // 0x82: sentinel missed (passthrough)
STATIC volatile UINT8 g_UdLastCmd    = 0;  // 0x83: last dispatched command
STATIC volatile UINT8 g_UdNripDelta  = 0;  // 0x84: NRip-RIP delta (expect 2)

/**
 * @brief Handles VMEXIT_EXCEPTION_UD (#UD).
 *
 * If the faulting instruction is our UD2 hypercall sentinel (RAX[63:32] ==
 * AO_HYPERCALL_MAGIC), dispatch the call and advance RIP via NRip.
 * Otherwise inject #UD into the guest unchanged.
 *
 * ABI: RAX = (AO_HYPERCALL_MAGIC << 32) | cmd
 *      RCX / RDX / R8 / R9 = args
 *      Return value in RAX.
 */
STATIC
VOID
HandleUdHypercall (
    IN OUT HOST_CONTEXT* Context
    )
{
    UINT64 rax;
    UINT32 cmd;
    UINT8  delta;

    // Count every #UD exit, saturating.
    if (g_UdExitCount < 0xFF) g_UdExitCount++;
    WriteExtCmosByte(0x80, g_UdExitCount);

    rax = Context->Cpu->States.Guest.Registers->Rax;

    if ((UINT32)(rax >> 32) != AO_HYPERCALL_MAGIC)
    {
        // Not our hypercall — forward #UD into the guest.
        if (g_UdMissCount < 0xFF) g_UdMissCount++;
        WriteExtCmosByte(0x82, g_UdMissCount);
        Context->Cpu->GuestVmcb.ControlArea.EventInj =
            (1ULL << 31) |  // valid
            (3ULL << 8)  |  // type = exception
            6ULL;           // #UD
        return;
    }

    MarkProgress(0x04);

    if (g_UdMatchCount < 0xFF) g_UdMatchCount++;
    WriteExtCmosByte(0x81, g_UdMatchCount);

    // Log first instruction byte — should be 0x0F for UD2 (0F 0B).
    // NumOfBytesFetched is populated when DecodeAssists is supported.
    delta = (Context->Cpu->GuestVmcb.ControlArea.NumOfBytesFetched > 0)
              ? Context->Cpu->GuestVmcb.ControlArea.GuestInstructionBytes[0]
              : 0xFF;
    g_UdNripDelta = delta;
    WriteExtCmosByte(0x84, delta);

    cmd = (UINT32)(rax & 0xFFFFFFFFULL);
    g_UdLastCmd = (UINT8)cmd;
    WriteExtCmosByte(0x83, g_UdLastCmd);

    switch (cmd)
    {
    case AO_CMD_PING:
        Context->Cpu->States.Guest.Registers->Rax = 0xdeadbeefdeadbeefULL;
        break;

    case AO_CMD_VA_TO_PA:
    {
        //
        // AO_CMD_VA_TO_PA: translate a guest virtual address to physical.
        //   RCX = cr3  (0 = use caller's current CR3)
        //   RDX = va
        //   Returns: physical address, or INVALID_PHYS_ADDR on failure.
        //
        UINT64 cr3 = Context->Cpu->States.Guest.Registers->Rcx;
        UINT64 va  = Context->Cpu->States.Guest.Registers->Rdx;
        if (cr3 == 0)
        {
            cr3 = Context->Cpu->GuestVmcb.StateSaveArea.Cr3 & ~0xFFFULL;
        }
        Context->Cpu->States.Guest.Registers->Rax = GvaToGpa(cr3, va);
        break;
    }

    case AO_CMD_READ_MEM:
    {
        //
        // AO_CMD_READ_MEM: read up to INTROSPECT_MAX_READ bytes from any
        // guest virtual address space and place them in the caller's buffer.
        //   RCX = target_cr3  (0 = caller's current CR3)
        //   RDX = target_va
        //   R8  = byte count  (capped at INTROSPECT_MAX_READ)
        //   R9  = out_buf_va  (in caller's address space)
        //   Returns: bytes actually copied (0 on failure).
        //
        UINT64 targetCr3 = Context->Cpu->States.Guest.Registers->Rcx;
        UINT64 targetVa  = Context->Cpu->States.Guest.Registers->Rdx;
        UINT64 size      = Context->Cpu->States.Guest.Registers->R8;
        UINT64 outBufVa  = Context->Cpu->States.Guest.Registers->R9;
        UINT64 callerCr3 = Context->Cpu->GuestVmcb.StateSaveArea.Cr3 & ~0xFFFULL;
        UINT64 copied, remaining, srcVa, dstVa;

        if (targetCr3 == 0) targetCr3 = callerCr3;
        if (size > INTROSPECT_MAX_READ) size = INTROSPECT_MAX_READ;

        copied    = 0;
        remaining = size;
        srcVa     = targetVa;
        dstVa     = outBufVa;

        while (remaining > 0)
        {
            UINT64 srcOff   = srcVa & 0xFFFULL;
            UINT64 dstOff   = dstVa & 0xFFFULL;
            UINT64 chunk    = remaining;
            UINT64 srcChunk = SIZE_4KB - srcOff;
            UINT64 dstChunk = SIZE_4KB - dstOff;
            UINT64 srcPa, dstPa;

            if (chunk > srcChunk) chunk = srcChunk;
            if (chunk > dstChunk) chunk = dstChunk;

            srcPa = GvaToGpa(targetCr3, srcVa);
            dstPa = GvaToGpa(callerCr3, dstVa);
            if (srcPa == INVALID_PHYS_ADDR || dstPa == INVALID_PHYS_ADDR) break;

            CopyMem((VOID *)(UINTN)dstPa, (VOID *)(UINTN)srcPa, (UINTN)chunk);

            copied    += chunk;
            srcVa     += chunk;
            dstVa     += chunk;
            remaining -= chunk;
        }
        Context->Cpu->States.Guest.Registers->Rax = copied;
        break;
    }

    case AO_CMD_GET_CR3:
    {
        //
        // AO_CMD_GET_CR3: find a process by name and return its kernel CR3.
        //   RCX = name_va    (pointer to null-terminated ASCII string in caller's VA)
        //   RDX = skip_count (0 = first match, 1 = second, …)
        //   Returns: DirectoryTableBase of the Nth match, or INVALID_PHYS_ADDR.
        //
        UINT64 nameVa    = Context->Cpu->States.Guest.Registers->Rcx;
        UINT32 skipCount = (UINT32)Context->Cpu->States.Guest.Registers->Rdx;
        UINT64 callerCr3 = Context->Cpu->GuestVmcb.StateSaveArea.Cr3 & ~0xFFFULL;
        CHAR8  name[16];

        ZeroMem(name, sizeof(name));
        if (!ReadGuestVa(callerCr3, nameVa, 15, name))
        {
            Context->Cpu->States.Guest.Registers->Rax = INVALID_PHYS_ADDR;
            break;
        }
        name[15] = '\0';

        if (g_KernelCr3 == 0 && Context->Cpu->GuestVmcb.StateSaveArea.LStar != 0)
        {
            g_KernelCr3   = callerCr3;
            g_KernelLstar = Context->Cpu->GuestVmcb.StateSaveArea.LStar;
        }

        if (g_KernelBase == 0 && g_KernelCr3 != 0 && g_KernelLstar != 0)
            g_KernelBase = FindKernelBase(g_KernelCr3, g_KernelLstar);

        if (g_KernelCr3 == 0 || g_KernelBase == 0 || g_KernelBase == INVALID_PHYS_ADDR)
        {
            Context->Cpu->States.Guest.Registers->Rax = INVALID_PHYS_ADDR;
            break;
        }

        Context->Cpu->States.Guest.Registers->Rax =
            FindProcessCr3(g_KernelCr3, g_KernelBase, name, skipCount);
        break;
    }

    case AO_CMD_DIAG_CR3:
        Context->Cpu->States.Guest.Registers->Rax = g_KernelCr3;
        break;

    case AO_CMD_DIAG_LSTAR:
        Context->Cpu->States.Guest.Registers->Rax = g_KernelLstar;
        break;

    case AO_CMD_DIAG_BASE:
        // Trigger FindKernelBase lazily if prerequisites are met.
        if (g_KernelBase == 0 && g_KernelCr3 != 0 && g_KernelLstar != 0)
            g_KernelBase = FindKernelBase(g_KernelCr3, g_KernelLstar);
        Context->Cpu->States.Guest.Registers->Rax = g_KernelBase;
        break;

    case AO_CMD_DIAG_PSYS:
        // Trigger lazy base computation then return PsInitialSystemProcess VA.
        if (g_KernelBase == 0 && g_KernelCr3 != 0 && g_KernelLstar != 0)
            g_KernelBase = FindKernelBase(g_KernelCr3, g_KernelLstar);
        if (g_KernelCr3 != 0 && g_KernelBase != 0 && g_KernelBase != INVALID_PHYS_ADDR)
            Context->Cpu->States.Guest.Registers->Rax =
                FindExport(g_KernelCr3, g_KernelBase, "PsInitialSystemProcess");
        else
            Context->Cpu->States.Guest.Registers->Rax = INVALID_PHYS_ADDR;
        break;

    case AO_CMD_LIST_PROCS:
    {
        //   RCX = dest_buf_va  (caller-allocated, in caller's address space)
        //   RDX = max_procs    (cap at 512)
        // Returns: number of entries written (each PROC_ENTRY_SIZE = 24 bytes)
        UINT64 destVa   = Context->Cpu->States.Guest.Registers->Rcx;
        UINT64 maxProcs = Context->Cpu->States.Guest.Registers->Rdx;
        UINT64 callerCr3 = Context->Cpu->GuestVmcb.StateSaveArea.Cr3 & ~0xFFFULL;

        if (maxProcs > 512) maxProcs = 512;

        // Self-initializing: trigger lazy base computation if needed.
        if (g_KernelBase == 0 && g_KernelCr3 != 0 && g_KernelLstar != 0)
            g_KernelBase = FindKernelBase(g_KernelCr3, g_KernelLstar);

        if (g_KernelCr3 == 0 || g_KernelBase == 0 || g_KernelBase == INVALID_PHYS_ADDR)
        {
            Context->Cpu->States.Guest.Registers->Rax = 0;
            break;
        }

        Context->Cpu->States.Guest.Registers->Rax =
            ListProcesses(g_KernelCr3, g_KernelBase, callerCr3, destVa, maxProcs);
        break;
    }

    case AO_CMD_GET_PROC_BASE:
    {
        //
        // AO_CMD_GET_PROC_BASE: find a process by name and return its image base VA.
        //   RCX = name_va    (pointer to null-terminated ASCII string in caller's VA)
        //   RDX = skip_count (0 = first match, 1 = second, …)
        //   Returns: EPROCESS.SectionBaseAddress of the Nth match, or INVALID_PHYS_ADDR.
        //
        UINT64 nameVa        = Context->Cpu->States.Guest.Registers->Rcx;
        UINT32 skipCount     = (UINT32)Context->Cpu->States.Guest.Registers->Rdx;
        UINT64 callerCr3Base = Context->Cpu->GuestVmcb.StateSaveArea.Cr3 & ~0xFFFULL;
        CHAR8  name[16];

        ZeroMem(name, sizeof(name));
        if (!ReadGuestVa(callerCr3Base, nameVa, 15, name))
        {
            Context->Cpu->States.Guest.Registers->Rax = INVALID_PHYS_ADDR;
            break;
        }
        name[15] = '\0';

        if (g_KernelBase == 0 && g_KernelCr3 != 0 && g_KernelLstar != 0)
            g_KernelBase = FindKernelBase(g_KernelCr3, g_KernelLstar);

        if (g_KernelCr3 == 0 || g_KernelBase == 0 || g_KernelBase == INVALID_PHYS_ADDR)
        {
            Context->Cpu->States.Guest.Registers->Rax = INVALID_PHYS_ADDR;
            break;
        }

        Context->Cpu->States.Guest.Registers->Rax =
            FindProcessBase(g_KernelCr3, g_KernelBase, name, skipCount);
        break;
    }

    case AO_CMD_DIAG_PEOFF:
    {
        UINT32 peOff   = 0;
        UINT16 optMagic = 0;
        if (g_KernelCr3 != 0 && g_KernelBase != 0 && g_KernelBase != INVALID_PHYS_ADDR)
        {
            ReadGuestVa(g_KernelCr3, g_KernelBase + 0x3CUL, 4, &peOff);
            ReadGuestVa(g_KernelCr3, g_KernelBase + peOff + 24, 2, &optMagic);
        }
        Context->Cpu->States.Guest.Registers->Rax = (UINT64)peOff | ((UINT64)optMagic << 32);
        break;
    }

    case AO_CMD_DIAG_EXPDIR:
    {
        UINT32 peOff  = 0;
        UINT32 expRva = 0;
        UINT32 expSz  = 0;
        if (g_KernelCr3 != 0 && g_KernelBase != 0 && g_KernelBase != INVALID_PHYS_ADDR)
        {
            ReadGuestVa(g_KernelCr3, g_KernelBase + 0x3CUL, 4, &peOff);
            ReadGuestVa(g_KernelCr3, g_KernelBase + peOff + 24 + 0x70, 4, &expRva);
            ReadGuestVa(g_KernelCr3, g_KernelBase + peOff + 24 + 0x74, 4, &expSz);
        }
        Context->Cpu->States.Guest.Registers->Rax = (UINT64)expRva | ((UINT64)expSz << 32);
        break;
    }

    case AO_CMD_DIAG_NNAMES:
    {
        UINT32 peOff    = 0;
        UINT32 expRva   = 0;
        UINT32 numNames = 0;
        if (g_KernelCr3 != 0 && g_KernelBase != 0 && g_KernelBase != INVALID_PHYS_ADDR)
        {
            ReadGuestVa(g_KernelCr3, g_KernelBase + 0x3CUL, 4, &peOff);
            ReadGuestVa(g_KernelCr3, g_KernelBase + peOff + 24 + 0x70, 4, &expRva);
            if (expRva)
                ReadGuestVa(g_KernelCr3, g_KernelBase + expRva + 0x18, 4, &numNames);
        }
        Context->Cpu->States.Guest.Registers->Rax = numNames;
        break;
    }

    case AO_CMD_ALLOC_SHADOW:
    {
        // Return GPA of the next free shadow page, or -1 if pool is full.
        // Does NOT increment ShadowUsed — call NPT_HOOK to commit it.
        SHARED_SVM_DATA* svm = &Context->Root->Svm;
        if (svm->HookMeta.ShadowUsed < NPT_SHADOW_COUNT)
        {
            Context->Cpu->States.Guest.Registers->Rax =
                (UINT64)(UINTN)&svm->ShadowPages[svm->HookMeta.ShadowUsed][0];
        }
        else
        {
            Context->Cpu->States.Guest.Registers->Rax = (UINT64)-1;
        }
        break;
    }

    case AO_CMD_WRITE_GPA:
    {
        // RCX = dest GPA (within host identity map, e.g. a shadow page)
        // RDX = src VA  (in caller's address space)
        // R8  = size    (max SIZE_4KB)
        // Returns 0 on success, -1/-2 on bad args/unmapped src.
        UINT64 destGpa   = Context->Cpu->States.Guest.Registers->Rcx;
        UINT64 srcVa     = Context->Cpu->States.Guest.Registers->Rdx;
        UINT64 size      = Context->Cpu->States.Guest.Registers->R8;
        UINT64 callerCr3 = Context->Cpu->GuestVmcb.StateSaveArea.Cr3 & ~0xFFFULL;
        UINT64 srcPa;

        if (size == 0 || size > SIZE_4KB)
        {
            Context->Cpu->States.Guest.Registers->Rax = (UINT64)-1;
            break;
        }
        srcPa = GvaToGpa(callerCr3, srcVa);
        if (srcPa == INVALID_PHYS_ADDR)
        {
            Context->Cpu->States.Guest.Registers->Rax = (UINT64)-2;
            break;
        }
        CopyMem((VOID*)(UINTN)destGpa, (VOID*)(UINTN)srcPa, (UINTN)size);
        Context->Cpu->States.Guest.Registers->Rax = 0;
        break;
    }

    case AO_CMD_NPT_HOOK:
    {
        // RCX = target GPA (must be 4KB-aligned)
        // Returns shadow page GPA on success (caller patches hook bytes there
        // via WRITE_GPA), or -1 on bad alignment / table full.
        UINT64 targetGpa4K = Context->Cpu->States.Guest.Registers->Rcx;
        SHARED_SVM_DATA* svm = &Context->Root->Svm;
        UINT64 shadowGpa;
        UINT32 nCpus, i;

        if ((targetGpa4K & 0xFFF) != 0 ||
            svm->HookMeta.HookCount >= NPT_MAX_HOOKS)
        {
            Context->Cpu->States.Guest.Registers->Rax = (UINT64)-1;
            break;
        }
        shadowGpa = InstallNptHook(svm, targetGpa4K);
        if (shadowGpa == 0)
        {
            Context->Cpu->States.Guest.Registers->Rax = (UINT64)-1;
            break;
        }
        // Switch all CPUs to ReadNCr3 so exec NPFs fire on the hooked page.
        // Own CPU: update VMCB + NptMode directly (safe — own host context).
        // Other CPUs: set a pending flag; each CPU applies it on its next VMexit.
        nCpus = Context->Root->HostX64.ProcessorCount;
        for (i = 0; i < nCpus; i++)
        {
            UINT64 readNcr3 = (g_ShadowNcr3Pa != 0) ? g_ShadowNcr3Pa : g_ReadNcr3Pa;
            if (&Context->Root->Cpus[i] == Context->Cpu)
            {
                Context->Cpu->GuestVmcb.ControlArea.NCr3      = readNcr3;
                Context->Cpu->GuestVmcb.ControlArea.TlbControl = 1;
                Context->Cpu->GuestVmcb.ControlArea.VmcbClean  = 0;
                Context->Cpu->States.Guest.NptMode = 0;
            }
            else
            {
                Context->Root->Cpus[i].States.Guest.NCr3PendingValue  = readNcr3;
                Context->Root->Cpus[i].States.Guest.NCr3UpdatePending  = 1;
            }
        }
        Context->Cpu->States.Guest.Registers->Rax = shadowGpa;
        break;
    }

    case AO_CMD_NCR3_SWITCH_READ:
    {
        // Called from shadow payload to switch back to read NCr3 and resume
        // at the original function past the hook bytes.
        // R10 = resume GVA (present_va + N, where N = original bytes we executed).
        // Setting Rip overrides the +2 applied above so we land in the
        // original page at the right spot, not inside the shadow page.
        if (g_ReadNcr3Pa != 0)
        {
            UINT64 targetRip = Context->Cpu->States.Guest.Registers->R10;
            UINT64 switchReadNcr3 = (g_ShadowNcr3Pa != 0) ? g_ShadowNcr3Pa : g_ReadNcr3Pa;
            Context->Cpu->GuestVmcb.ControlArea.NCr3      = switchReadNcr3;
            Context->Cpu->GuestVmcb.ControlArea.TlbControl = 1;
            Context->Cpu->GuestVmcb.ControlArea.VmcbClean  = 0;
            Context->Cpu->States.Guest.NptMode = 0;
            if (targetRip != 0)
                Context->Cpu->GuestVmcb.StateSaveArea.Rip = targetRip;
            if (g_NcrSwitchReadCount < 0xFF) g_NcrSwitchReadCount++;
            WriteCmosByte(0x6C, g_NcrSwitchReadCount);
        }
        Context->Cpu->States.Guest.Registers->Rax = 0;
        break;
    }

    case AO_CMD_FIND_MODULE:
    {
        //   RCX = proc_name_va  (ASCII, ≤15 chars, in caller VA space)
        //   RDX = dll_name_va   (ASCII, ≤64 chars, in caller VA space)
        // Returns: DllBase VA of the named module, or INVALID_PHYS_ADDR.
        UINT64 procNameVa = Context->Cpu->States.Guest.Registers->Rcx;
        UINT64 dllNameVa  = Context->Cpu->States.Guest.Registers->Rdx;
        UINT32 skipCount  = (UINT32)Context->Cpu->States.Guest.Registers->R8;
        UINT64 callerCr3  = Context->Cpu->GuestVmcb.StateSaveArea.Cr3 & ~0xFFFULL;
        CHAR8  procName[16];
        CHAR8  dllName[66];

        ZeroMem(procName, sizeof(procName));
        ZeroMem(dllName,  sizeof(dllName));

        if (!ReadGuestVa(callerCr3, procNameVa, 15, procName) ||
            !ReadGuestVa(callerCr3, dllNameVa,  64, dllName))
        {
            Context->Cpu->States.Guest.Registers->Rax = INVALID_PHYS_ADDR;
            break;
        }
        procName[15] = '\0';
        dllName[64]  = '\0';

        if (g_KernelBase == 0 && g_KernelCr3 != 0 && g_KernelLstar != 0)
            g_KernelBase = FindKernelBase(g_KernelCr3, g_KernelLstar);

        if (g_KernelCr3 == 0 || g_KernelBase == 0 || g_KernelBase == INVALID_PHYS_ADDR)
        {
            Context->Cpu->States.Guest.Registers->Rax = INVALID_PHYS_ADDR;
            break;
        }

        Context->Cpu->States.Guest.Registers->Rax =
            FindModuleBase(g_KernelCr3, g_KernelBase, procName, skipCount, dllName);
        break;
    }

    case AO_CMD_READ_GPA:
    {
        // RCX = src GPA  (physical address to read from)
        // RDX = dest VA  (in caller's address space)
        // R8  = size     (max SIZE_4KB)
        // Returns 0 on success, -1 on bad size, -2 on unmapped dest.
        UINT64 srcGpa    = Context->Cpu->States.Guest.Registers->Rcx;
        UINT64 destVa    = Context->Cpu->States.Guest.Registers->Rdx;
        UINT64 size      = Context->Cpu->States.Guest.Registers->R8;
        UINT64 callerCr3 = Context->Cpu->GuestVmcb.StateSaveArea.Cr3 & ~0xFFFULL;
        UINT64 destPa;

        if (size == 0 || size > SIZE_4KB)
        {
            Context->Cpu->States.Guest.Registers->Rax = (UINT64)-1;
            break;
        }
        destPa = GvaToGpa(callerCr3, destVa);
        if (destPa == INVALID_PHYS_ADDR)
        {
            Context->Cpu->States.Guest.Registers->Rax = (UINT64)-2;
            break;
        }
        CopyMem((VOID*)(UINTN)destPa, (VOID*)(UINTN)srcGpa, (UINTN)size);
        Context->Cpu->States.Guest.Registers->Rax = 0;
        break;
    }

    case AO_CMD_CLEAR_HOOKS:
    {
        // Tear down every NPT hook:
        //   1. Restore PDPT entries (NestedPageTables, g_ShadowPdpt0, NptExec) to
        //      1GB identity leaves so the NPT walk is clean for all GPAs.
        //   2. Clear HookMeta — zeroes HookCount, ShadowUsed, and all Hooks[].
        //   3. Switch all CPUs back to read NCr3 (NptMode=0) so exec NCr3 is no
        //      longer active, allowing a fresh hook install on next loader run.
        SHARED_SVM_DATA* clearSvm = &Context->Root->Svm;
        UINT32 hi;

        for (hi = 0; hi < clearSvm->HookMeta.HookCount; hi++)
        {
            if (!clearSvm->HookMeta.Hooks[hi].Active)
                continue;

            UINT64 gpa4k  = clearSvm->HookMeta.Hooks[hi].Gpa4K;
            UINT32 pml4i  = (UINT32)((gpa4k >> 39) & 0x1FF);
            UINT32 pdpti  = (UINT32)((gpa4k >> 30) & 0x1FF);
            UINT64 leaf1g = (((UINT64)pml4i << 39) | ((UINT64)pdpti << 30)) | 0x87ULL;

            // Restore read NCr3 (NestedPageTables).
            clearSvm->NestedPageTables.Pdpt[pml4i][pdpti].Uint64 = leaf1g;

            // Restore shadow NCr3 (g_ShadowPdpt0 covers PML4[0] only).
            if (pml4i == 0 && g_ShadowNcr3Pa != 0 && g_ShadowPdpt0 != NULL)
                g_ShadowPdpt0[pdpti] = leaf1g;

            // Restore exec NCr3 (NptExec).
            if (g_ExecNcr3Pa != 0)
                clearSvm->NptExec.Pdpt[pml4i][pdpti].Uint64 = leaf1g;
        }

        ZeroMem(&clearSvm->HookMeta, sizeof(NPT_HOOK_META));

        // Switch all CPUs back to read NCr3 and flush their NPT TLBs.
        {
            UINT64 readNcr3 = (g_ShadowNcr3Pa != 0) ? g_ShadowNcr3Pa : g_ReadNcr3Pa;
            UINT32 nCpus = Context->Root->HostX64.ProcessorCount;
            UINT32 ci;
            for (ci = 0; ci < nCpus; ci++)
            {
                if (&Context->Root->Cpus[ci] == Context->Cpu)
                {
                    Context->Cpu->GuestVmcb.ControlArea.NCr3      = readNcr3;
                    Context->Cpu->GuestVmcb.ControlArea.TlbControl = 1;
                    Context->Cpu->GuestVmcb.ControlArea.VmcbClean  = 0;
                    Context->Cpu->States.Guest.NptMode = 0;
                }
                else
                {
                    Context->Root->Cpus[ci].States.Guest.NCr3PendingValue  = readNcr3;
                    Context->Root->Cpus[ci].States.Guest.NCr3UpdatePending  = 1;
                    Context->Root->Cpus[ci].States.Guest.NptMode = 0;
                }
            }
        }
        Context->Cpu->States.Guest.Registers->Rax = 0;
        break;
    }

    case AO_CMD_SYSCALL_LOG_START:
    {
        // SAFE MODE: allocate ring buffer and record state, but do NOT install
        // the NPT hook yet. The hook path has an unresolved flip-back issue
        // (shadow page is a verbatim copy of KiSystemCall64 with no UD2 to
        // call back into the HV, so after flipping to exec NCr3 we never
        // flip back). This causes system lockup. Keep the control plane
        // working while the hook mechanism is redesigned.
        //
        // In this mode: START succeeds, READ returns 0 entries, STOP works,
        // and nothing dangerous happens to the system.
        UINT64 filterCr3 = Context->Cpu->States.Guest.Registers->Rcx;
        UINT64 lstarVa   = g_KernelLstar;
        UINT64 kernCr3   = g_KernelCr3;
        UINT64 syscallGpa = 0;

        if (lstarVa != 0 && kernCr3 != 0)
        {
            syscallGpa = GvaToGpa(kernCr3, lstarVa);
            if (syscallGpa == INVALID_PHYS_ADDR)
                syscallGpa = 0;
            else
                syscallGpa &= ~(UINT64)0xFFF;
        }

        if (g_SyscallLog == NULL)
        {
            // Pre-allocated at init. If NULL here, init-time allocation
            // failed (OOM). Can't recover post-ExitBootServices — can't
            // call AllocateReservedPages here or we'd crash the machine.
            Context->Cpu->States.Guest.Registers->Rax = (UINT64)-4;
            break;
        }

        g_SyscallLog->FilterCr3    = filterCr3;
        g_SyscallLog->SyscallGpa64 = syscallGpa;
        g_SyscallLog->SyscallGpa32 = 0;
        g_SyscallLog->Head         = 0;
        g_SyscallLog->Count        = 0;
        g_SyscallLog->Dropped      = 0;
        g_SyscallLog->Active     = 0;  // keep OFF — hook not installed

        // Return 1 to signal "safe mode, hook not installed, but control
        // plane is live". 0 was reserved for "hook installed and active".
        Context->Cpu->States.Guest.Registers->Rax = 1;
        break;
    }

    case AO_CMD_SYSCALL_LOG_STOP:
    {
        // Disarm logging. The NPT hook stays installed; use CLEAR_HOOKS for
        // a full teardown. CPUs that already flipped to exec NCr3 stay there.
        if (g_SyscallLog != NULL)
            g_SyscallLog->Active = 0;
        Context->Cpu->States.Guest.Registers->Rax = 0;
        break;
    }

    case AO_CMD_SYSCALL_LOG_READ:
    {
        UINT64 dstVa    = Context->Cpu->States.Guest.Registers->Rcx;
        UINT32 maxCount = (UINT32)Context->Cpu->States.Guest.Registers->Rdx;
        UINT64 callerCr3 = Context->Cpu->GuestVmcb.StateSaveArea.Cr3;
        UINT32 avail, toCopy, i;

        if (g_SyscallLog == NULL || dstVa == 0 || maxCount == 0)
        {
            Context->Cpu->States.Guest.Registers->Rax = 0;
            break;
        }

        avail  = g_SyscallLog->Count;
        toCopy = (avail < maxCount) ? avail : maxCount;

        for (i = 0; i < toCopy; i++)
        {
            UINT32 idx = (g_SyscallLog->Head + i) % SYSCALL_LOG_CAPACITY;
            UINT64 dstEntryVa = dstVa + (UINT64)i * sizeof(SYSCALL_LOG_ENTRY);
            UINT64 dstPa      = GvaToGpa(callerCr3, dstEntryVa);
            if (dstPa == INVALID_PHYS_ADDR)
                break;
            CopyMem((VOID*)(UINTN)dstPa,
                    &g_SyscallLog->Entries[idx],
                    sizeof(SYSCALL_LOG_ENTRY));
        }

        g_SyscallLog->Head  = (g_SyscallLog->Head + i) % SYSCALL_LOG_CAPACITY;
        g_SyscallLog->Count -= i;

        // Auto re-arm: our NPF one-shot flips each CPU to exec NCr3 after
        // its first syscall after arm. Without this, all CPUs flip within
        // milliseconds (kernel background threads syscall constantly) and
        // the filtered target process never gets caught. By re-arming all
        // CPUs on each READ poll, we keep giving the NPF a fresh chance
        // to catch the target. This makes capture statistical rather than
        // complete, but it's correct and doesn't crash.
        //
        // Only re-arm if logging is Active AND the hook is installed (SyscallGpa64 != 0).
        if (g_SyscallLog->Active && g_SyscallLog->SyscallGpa64 != 0)
        {
            UINT64 readNcr3 = (g_ShadowNcr3Pa != 0) ? g_ShadowNcr3Pa : g_ReadNcr3Pa;
            UINT32 nCpus = Context->Root->HostX64.ProcessorCount;
            UINT32 ci;
            for (ci = 0; ci < nCpus; ci++)
            {
                if (&Context->Root->Cpus[ci] == Context->Cpu)
                {
                    // Self: apply directly.
                    if (Context->Cpu->States.Guest.NptMode != 0)
                    {
                        Context->Cpu->GuestVmcb.ControlArea.NCr3      = readNcr3;
                        Context->Cpu->GuestVmcb.ControlArea.TlbControl = 1;
                        Context->Cpu->GuestVmcb.ControlArea.VmcbClean  = 0;
                        Context->Cpu->States.Guest.NptMode             = 0;
                    }
                }
                else
                {
                    // Other CPUs: queue via NCr3Pending. They'll pick it up
                    // on their next VMEXIT (which fires constantly on every CPU).
                    if (Context->Root->Cpus[ci].States.Guest.NptMode != 0)
                    {
                        Context->Root->Cpus[ci].States.Guest.NCr3PendingValue = readNcr3;
                        Context->Root->Cpus[ci].States.Guest.NCr3UpdatePending = 1;
                    }
                }
            }
        }

        Context->Cpu->States.Guest.Registers->Rax = (UINT64)i;
        break;
    }

    case AO_CMD_SYSCALL_LOG_START_UNSAFE:
    {
        // UNSAFE: installs NPT hooks on KiSystemCall64 AND KiSystemCall32 (if
        // CSTAR has been captured). One-shot per CPU per syscall-entry page.
        //
        // Preconditions (any failure returns negative without touching state):
        //   - g_SyscallLog != NULL (set at DXE init)
        //   - g_KernelLstar, g_KernelCr3 populated (watchdog capture)
        //   - KiSystemCall64 VA resolves to a valid GPA
        //
        // CSTAR (32-bit entry) is best-effort: if g_KernelCstar hasn't been
        // seen yet or its VA fails to translate, the 64-bit hook still goes
        // in and the call returns success with a flag indicating 32-bit was
        // skipped.
        //
        // Return value:
        //   0  = both hooks installed
        //   1  = only 64-bit hook installed (CSTAR unavailable)
        //  <0  = failure, no hook installed
        SHARED_SVM_DATA* svm = &Context->Root->Svm;
        UINT64 filterCr3 = Context->Cpu->States.Guest.Registers->Rcx;
        UINT64 lstarVa   = g_KernelLstar;
        UINT64 cstarVa   = g_KernelCstar;
        UINT64 kernCr3   = g_KernelCr3;
        UINT64 syscallGpa64;
        UINT64 syscallGpa32 = 0;
        UINT64 shadow64, shadow32;
        UINT64 retValue = 0;

        if (g_SyscallLog == NULL)
        { Context->Cpu->States.Guest.Registers->Rax = (UINT64)-4; break; }
        if (lstarVa == 0 || kernCr3 == 0)
        { Context->Cpu->States.Guest.Registers->Rax = (UINT64)-2; break; }

        syscallGpa64 = GvaToGpa(kernCr3, lstarVa);
        if (syscallGpa64 == INVALID_PHYS_ADDR)
        { Context->Cpu->States.Guest.Registers->Rax = (UINT64)-3; break; }
        syscallGpa64 &= ~(UINT64)0xFFF;

        // Try to resolve CSTAR. Only fail soft — missing CSTAR shouldn't
        // block 64-bit logging.
        if (cstarVa != 0)
        {
            UINT64 g = GvaToGpa(kernCr3, cstarVa);
            if (g != INVALID_PHYS_ADDR)
                syscallGpa32 = g & ~(UINT64)0xFFF;
        }

        // Install the 64-bit hook first.
        shadow64 = InstallNptHook(svm, syscallGpa64);
        if (shadow64 == 0)
        { Context->Cpu->States.Guest.Registers->Rax = (UINT64)-5; break; }

        // Install the 32-bit hook if we have a valid GPA AND it's not the
        // same 4KB page we just hooked (LSTAR and CSTAR usually live on
        // different pages, but a double-install of the same page would
        // waste a hook slot and confuse the NPF matcher).
        if (syscallGpa32 != 0 && syscallGpa32 != syscallGpa64)
        {
            shadow32 = InstallNptHook(svm, syscallGpa32);
            if (shadow32 == 0)
            {
                // 32-bit hook failed to install; keep the 64-bit hook live
                // and return with the "32-bit unavailable" status so the
                // caller knows WoW64 won't be intercepted on the compat path.
                syscallGpa32 = 0;
                retValue = 1;
            }
        }
        else if (syscallGpa32 == 0)
        {
            retValue = 1;  // CSTAR not available
        }

        g_SyscallLog->FilterCr3    = filterCr3;
        g_SyscallLog->SyscallGpa64 = syscallGpa64;
        g_SyscallLog->SyscallGpa32 = syscallGpa32;
        g_SyscallLog->Head         = 0;
        g_SyscallLog->Count        = 0;
        g_SyscallLog->Dropped      = 0;
        g_SyscallLog->Active       = 1;

        // CRITICAL: flush NPT TLB on ALL CPUs. Without this, each CPU keeps
        // its cached TLB entry marking the syscall page as executable (what
        // it was before the NPT edit), and no NPF ever fires. Reload the
        // active NCr3 on every CPU with TlbControl=1 to force a fresh walk
        // of the modified NPT.
        {
            UINT64 readNcr3 = (g_ShadowNcr3Pa != 0) ? g_ShadowNcr3Pa : g_ReadNcr3Pa;
            UINT32 nCpus = Context->Root->HostX64.ProcessorCount;
            UINT32 i;
            for (i = 0; i < nCpus; i++)
            {
                if (&Context->Root->Cpus[i] == Context->Cpu)
                {
                    Context->Cpu->GuestVmcb.ControlArea.NCr3      = readNcr3;
                    Context->Cpu->GuestVmcb.ControlArea.TlbControl = 1;
                    Context->Cpu->GuestVmcb.ControlArea.VmcbClean  = 0;
                    Context->Cpu->States.Guest.NptMode             = 0;
                }
                else
                {
                    Context->Root->Cpus[i].States.Guest.NCr3PendingValue  = readNcr3;
                    Context->Root->Cpus[i].States.Guest.NCr3UpdatePending = 1;
                    Context->Root->Cpus[i].States.Guest.NptMode           = 0;
                }
            }
        }

        Context->Cpu->States.Guest.Registers->Rax = retValue;
        break;
    }

    case AO_CMD_SYSCALL_LOG_STATUS:
    {
        // Fill a caller-provided SYSCALL_LOG_STATUS struct with live state.
        //   RCX = dst VA in caller's address space
        // Returns 0 on success, -1 if caller buffer can't be translated.
        UINT64 dstVa    = Context->Cpu->States.Guest.Registers->Rcx;
        UINT64 callerCr3 = Context->Cpu->GuestVmcb.StateSaveArea.Cr3;
        SYSCALL_LOG_STATUS status;
        UINT64 dstPa;
        UINT32 ci;

        ZeroMem(&status, sizeof(status));
        status.LogAllocated  = (g_SyscallLog != NULL) ? 1 : 0;
        status.KernelLstar   = g_KernelLstar;
        status.KernelCstar   = g_KernelCstar;
        status.KernelCr3     = g_KernelCr3;
        status.HookCount     = Context->Root->Svm.HookMeta.HookCount;
        status.ExecFlipCount = g_NpfExecFlipCount;
        status.NCpus         = Context->Root->HostX64.ProcessorCount;
        for (ci = 0; ci < status.NCpus; ci++)
        {
            if (Context->Root->Cpus[ci].States.Guest.NptMode != 0)
                status.NCpusOnExecNcr3++;
        }
        if (g_SyscallLog != NULL)
        {
            status.Active       = g_SyscallLog->Active;
            status.Count        = g_SyscallLog->Count;
            status.Dropped      = g_SyscallLog->Dropped;
            status.FilterCr3    = g_SyscallLog->FilterCr3;
            status.SyscallGpa64 = g_SyscallLog->SyscallGpa64;
            status.SyscallGpa32 = g_SyscallLog->SyscallGpa32;
        }

        if (dstVa == 0)
        { Context->Cpu->States.Guest.Registers->Rax = (UINT64)-1; break; }
        dstPa = GvaToGpa(callerCr3, dstVa);
        if (dstPa == INVALID_PHYS_ADDR)
        { Context->Cpu->States.Guest.Registers->Rax = (UINT64)-1; break; }
        CopyMem((VOID*)(UINTN)dstPa, &status, sizeof(status));
        Context->Cpu->States.Guest.Registers->Rax = 0;
        break;
    }

    case AO_CMD_PH_REGISTER:
    {
        // Install a process hook with an embedded script.
        //   RCX = target CR3 (0 = match any)
        //   RDX = target VA (RIP-exact match)
        //   R8  = pointer to array of PROCESS_HOOK_INSN in caller VA space
        //   R9  = insn count (1..PROCESS_HOOK_SCRIPT_MAX_INSNS)
        // Returns slot index (0..PROCESS_HOOK_MAX-1) or -1 on error.
        UINT64 tgtCr3   = Context->Cpu->States.Guest.Registers->Rcx;
        UINT64 tgtVa    = Context->Cpu->States.Guest.Registers->Rdx;
        UINT64 scriptVa = Context->Cpu->States.Guest.Registers->R8;
        UINT64 insnCnt  = Context->Cpu->States.Guest.Registers->R9;
        UINT64 callerCr3 = Context->Cpu->GuestVmcb.StateSaveArea.Cr3;
        SHARED_SVM_DATA* svm = &Context->Root->Svm;
        UINT32 slot;
        PROCESS_HOOK_ENTRY* entry = NULL;
        UINT64 gpa4K;
        UINT32 i;

        if (g_ProcessHooks == NULL ||
            insnCnt == 0 || insnCnt > PROCESS_HOOK_SCRIPT_MAX_INSNS ||
            tgtVa == 0 || scriptVa == 0)
        { Context->Cpu->States.Guest.Registers->Rax = (UINT64)-1; break; }

        // Find a free slot (or an existing one at the same VA → replace its script).
        for (slot = 0; slot < PROCESS_HOOK_MAX; ++slot)
        {
            if (g_ProcessHooks->Entries[slot].Active &&
                g_ProcessHooks->Entries[slot].TargetVa == tgtVa &&
                g_ProcessHooks->Entries[slot].TargetCr3 == tgtCr3)
            { entry = &g_ProcessHooks->Entries[slot]; break; }
        }
        if (entry == NULL)
        {
            for (slot = 0; slot < PROCESS_HOOK_MAX; ++slot)
            {
                if (!g_ProcessHooks->Entries[slot].Active)
                { entry = &g_ProcessHooks->Entries[slot]; break; }
            }
        }
        if (entry == NULL)
        { Context->Cpu->States.Guest.Registers->Rax = (UINT64)-1; break; }

        // Resolve target VA to GPA (4KB aligned) in the target CR3 (or caller's if 0).
        gpa4K = GvaToGpa(tgtCr3 ? tgtCr3 : callerCr3, tgtVa) & ~0xFFFULL;
        if ((gpa4K + 0x1000) <= 0x1000)
        { Context->Cpu->States.Guest.Registers->Rax = (UINT64)-1; break; }

        // Copy the script bytes from caller VA. Each insn is 8B; total ≤ 512B.
        if (!ReadGuestVa(callerCr3, scriptVa,
                         insnCnt * sizeof(PROCESS_HOOK_INSN),
                         entry->Script))
        { Context->Cpu->States.Guest.Registers->Rax = (UINT64)-1; break; }

        // Install the shadow-page NPT hook if we don't already have one on this page.
        {
            BOOLEAN havePage = FALSE;
            UINT64  shadowPfn_ = 0;
            for (i = 0; i < svm->HookMeta.HookCount; ++i)
            {
                if (svm->HookMeta.Hooks[i].Active &&
                    svm->HookMeta.Hooks[i].Gpa4K == gpa4K)
                { havePage = TRUE; shadowPfn_ = svm->HookMeta.Hooks[i].ShadowPfn; break; }
            }
            if (!havePage)
            {
                UINT64 sh = InstallNptHook(svm, gpa4K);
                if (sh == 0)
                { Context->Cpu->States.Guest.Registers->Rax = (UINT64)-1; break; }
                // InstallNptHook appended at index [HookCount-1]; its shadow PFN
                // is what we patch below.
                shadowPfn_ = svm->HookMeta.Hooks[svm->HookMeta.HookCount - 1].ShadowPfn;
                // Flip all CPUs to read NCr3 so exec NPFs can fire on this page.
                {
                    UINT32 nCpus = Context->Root->HostX64.ProcessorCount;
                    UINT64 readNcr3 = (g_ShadowNcr3Pa != 0) ? g_ShadowNcr3Pa : g_ReadNcr3Pa;
                    for (i = 0; i < nCpus; ++i)
                    {
                        if (&Context->Root->Cpus[i] == Context->Cpu)
                        {
                            Context->Cpu->GuestVmcb.ControlArea.NCr3      = readNcr3;
                            Context->Cpu->GuestVmcb.ControlArea.TlbControl = 1;
                            Context->Cpu->GuestVmcb.ControlArea.VmcbClean  = 0;
                            Context->Cpu->States.Guest.NptMode = 0;
                        }
                        else
                        {
                            Context->Root->Cpus[i].States.Guest.NCr3PendingValue  = readNcr3;
                            Context->Root->Cpus[i].States.Guest.NCr3UpdatePending  = 1;
                        }
                    }
                }
            }

            //
            // Option 7 (single-step flip-back): shadow page stays byte-identical
            // to the original. Dispatch is NPF-based (RIP==TargetVa triggers the
            // script); the stray-flip path and the CONTINUE path both set TF=1
            // and arm ExpectDbForFlipBack so the exec-tree exposure window is
            // exactly ONE guest instruction. See HandleDebugException.
            //
            (void)shadowPfn_;
        }

        entry->TargetCr3        = tgtCr3;
        entry->TargetVa         = tgtVa;
        entry->TargetGpa4K      = gpa4K;
        entry->InsnCount        = (UINT32)insnCnt;
        entry->HitCount         = 0;
        entry->LastFaultPc      = 0;
        entry->LastFaultReason  = PH_FAULT_NONE;
        // NOTE: CALL suspend state is per-CPU now (lives in GUEST_STATE), so
        // there is nothing to zero on the entry itself.
        // NOTE: Config[] is intentionally NOT zeroed here — usermode may want
        // to set config BEFORE registering the script, or the user may
        // re-register a script with the same (cr3, va) to swap draw modes
        // while preserving menu state. Zero it with CMD_PH_CLEAR if needed.
        if (!entry->Active)
        {
            entry->Active = 1;
            g_ProcessHooks->NumActive++;
        }

        Context->Cpu->States.Guest.Registers->Rax = (UINT64)slot;
        break;
    }

    case AO_CMD_PH_UNREGISTER:
    {
        // RCX = slot index (0..PROCESS_HOOK_MAX-1). We mark it inactive but
        // leave the NPT page hook in place (cheap to reuse on next register).
        UINT64 idx = Context->Cpu->States.Guest.Registers->Rcx;
        if (g_ProcessHooks == NULL || idx >= PROCESS_HOOK_MAX)
        { Context->Cpu->States.Guest.Registers->Rax = (UINT64)-1; break; }
        if (g_ProcessHooks->Entries[idx].Active)
        {
            g_ProcessHooks->Entries[idx].Active = 0;
            if (g_ProcessHooks->NumActive > 0) g_ProcessHooks->NumActive--;
        }
        Context->Cpu->States.Guest.Registers->Rax = 0;
        break;
    }

    case AO_CMD_PH_CLEAR:
    {
        UINT32 i;
        if (g_ProcessHooks == NULL)
        { Context->Cpu->States.Guest.Registers->Rax = (UINT64)-1; break; }
        for (i = 0; i < PROCESS_HOOK_MAX; ++i)
            g_ProcessHooks->Entries[i].Active = 0;
        g_ProcessHooks->NumActive = 0;
        Context->Cpu->States.Guest.Registers->Rax = 0;
        break;
    }

    case AO_CMD_PH_SET_CFG:
    {
        // RCX = slot_idx (0..PROCESS_HOOK_MAX-1), RDX = cfg_idx (0..CFG_SLOTS-1),
        // R8  = value (UINT32).
        UINT64 slot = Context->Cpu->States.Guest.Registers->Rcx;
        UINT64 cfg  = Context->Cpu->States.Guest.Registers->Rdx;
        UINT64 val  = Context->Cpu->States.Guest.Registers->R8;
        if (g_ProcessHooks == NULL ||
            slot >= PROCESS_HOOK_MAX ||
            cfg  >= PROCESS_HOOK_CFG_SLOTS)
        { Context->Cpu->States.Guest.Registers->Rax = (UINT64)-1; break; }
        g_ProcessHooks->Entries[slot].Config[cfg] = (UINT32)val;
        Context->Cpu->States.Guest.Registers->Rax = 0;
        break;
    }

    case AO_CMD_PH_GET_CFG:
    {
        // Mirror of AO_CMD_PH_SET_CFG.
        //   RCX = slot_idx, RDX = cfg_idx.
        // Returns the UINT32 cfg value in RAX. Returns (UINT64)-1 on error
        // (hooks not initialized or slot/cfg out of range).
        UINT64 slot = Context->Cpu->States.Guest.Registers->Rcx;
        UINT64 cfg  = Context->Cpu->States.Guest.Registers->Rdx;
        if (g_ProcessHooks == NULL ||
            slot >= PROCESS_HOOK_MAX ||
            cfg  >= PROCESS_HOOK_CFG_SLOTS)
        { Context->Cpu->States.Guest.Registers->Rax = (UINT64)-1; break; }
        Context->Cpu->States.Guest.Registers->Rax =
            (UINT64)g_ProcessHooks->Entries[slot].Config[cfg];
        break;
    }

    case AO_CMD_PH_STATUS:
    {
        // RCX = dst VA in caller's address space (size: PROCESS_HOOK_TABLE
        // header + per-entry summary). We write a compact packed status:
        //   UINT32 num_active, UINT64 dispatch_count, UINT64 fault_count,
        //   then PROCESS_HOOK_MAX × { UINT32 active, UINT64 cr3, UINT64 va,
        //                             UINT64 hits, UINT32 insn_count,
        //                             UINT32 last_fault_reason, UINT32 last_fault_pc }
        // Total: 4 + 8 + 8 + 8*(4+8+8+8+4+4+4) = 20 + 8*40 = 340 bytes.
        UINT64 dstVa = Context->Cpu->States.Guest.Registers->Rcx;
        UINT64 callerCr3 = Context->Cpu->GuestVmcb.StateSaveArea.Cr3;
        UINT8 buf[340];
        UINT32 off = 0;
        UINT32 i;
        if (g_ProcessHooks == NULL || dstVa == 0)
        { Context->Cpu->States.Guest.Registers->Rax = (UINT64)-1; break; }

        ZeroMem(buf, sizeof(buf));
        *(UINT32*)(buf + off) = g_ProcessHooks->NumActive;      off += 4;
        *(UINT64*)(buf + off) = g_ProcessHooks->DispatchCount;  off += 8;
        *(UINT64*)(buf + off) = g_ProcessHooks->FaultCount;     off += 8;
        for (i = 0; i < PROCESS_HOOK_MAX; ++i)
        {
            PROCESS_HOOK_ENTRY* e = &g_ProcessHooks->Entries[i];
            *(UINT32*)(buf + off) = e->Active;           off += 4;
            *(UINT64*)(buf + off) = e->TargetCr3;        off += 8;
            *(UINT64*)(buf + off) = e->TargetVa;         off += 8;
            *(UINT64*)(buf + off) = e->HitCount;         off += 8;
            *(UINT32*)(buf + off) = e->InsnCount;        off += 4;
            *(UINT32*)(buf + off) = e->LastFaultReason;  off += 4;
            *(UINT32*)(buf + off) = (UINT32)e->LastFaultPc; off += 4;
        }
        if (!WriteGuestVa(callerCr3, dstVa, off, buf))
        { Context->Cpu->States.Guest.Registers->Rax = (UINT64)-1; break; }
        Context->Cpu->States.Guest.Registers->Rax = off;
        break;
    }

    case AO_CMD_PH_LOG_READ:
    {
        // RCX = dst VA, RDX = max_count. Drains the debug log ring.
        UINT64 dstVa    = Context->Cpu->States.Guest.Registers->Rcx;
        UINT64 maxCount = Context->Cpu->States.Guest.Registers->Rdx;
        UINT64 callerCr3 = Context->Cpu->GuestVmcb.StateSaveArea.Cr3;
        UINT32 n = 0;

        if (g_ProcessHookLog == NULL || dstVa == 0 || maxCount == 0)
        { Context->Cpu->States.Guest.Registers->Rax = 0; break; }

        while (g_ProcessHookLog->Count > 0 && n < maxCount)
        {
            PROCESS_HOOK_LOG_ENTRY* e = &g_ProcessHookLog->Entries[g_ProcessHookLog->Head];
            UINT64 chunkVa = dstVa + (UINT64)n * sizeof(PROCESS_HOOK_LOG_ENTRY);
            if (!WriteGuestVa(callerCr3, chunkVa, sizeof(*e), e))
                break;
            g_ProcessHookLog->Head = (g_ProcessHookLog->Head + 1) % PROCESS_HOOK_LOG_CAPACITY;
            g_ProcessHookLog->Count--;
            n++;
        }
        Context->Cpu->States.Guest.Registers->Rax = n;
        break;
    }

    case AO_CMD_PH_DIAG_WALK:
    {
        // RCX = target_cr3 (0 = use caller's), RDX = target_va, R8 = dst VA for ph_diag_walk (64B).
        // Walks the REAL active NCr3 (computed, since VMCB.NCr3 at this point is
        // the decoy g_DecoyPagePa; the real NCr3 is restored at the end of HandleVmExit).
        UINT64 tgtCr3 = Context->Cpu->States.Guest.Registers->Rcx;
        UINT64 tgtVa  = Context->Cpu->States.Guest.Registers->Rdx;
        UINT64 dstVa  = Context->Cpu->States.Guest.Registers->R8;
        UINT64 callerCr3 = Context->Cpu->GuestVmcb.StateSaveArea.Cr3;
        UINT64 activeReadNcr3 = (g_ShadowNcr3Pa != 0) ? g_ShadowNcr3Pa : g_ReadNcr3Pa;
        UINT64 activeNcr3 = ((Context->Cpu->States.Guest.NptMode == 0)
                             ? activeReadNcr3 : g_ExecNcr3Pa) & ~0xFFFULL;
        UINT64 gpa4K;

        struct {
            UINT64 gpa4k;
            UINT64 pml4e;
            UINT64 pdpte;
            UINT64 pde;
            UINT64 pte;
            UINT32 stop_level;
            UINT32 pml4_idx;
            UINT32 pdpt_idx;
            UINT32 pd_idx;
            UINT32 pt_idx;
            UINT32 pad;
        } out;
        ZeroMem(&out, sizeof(out));

        if (dstVa == 0)
        { Context->Cpu->States.Guest.Registers->Rax = (UINT64)-1; break; }

        // Resolve GPA from target CR3 (so we're asking about the right page).
        gpa4K = GvaToGpa(tgtCr3 ? tgtCr3 : (callerCr3 & ~0xFFFULL), tgtVa) & ~0xFFFULL;
        out.gpa4k   = gpa4K;
        out.pml4_idx = (UINT32)((gpa4K >> 39) & 0x1FFULL);
        out.pdpt_idx = (UINT32)((gpa4K >> 30) & 0x1FFULL);
        out.pd_idx   = (UINT32)((gpa4K >> 21) & 0x1FFULL);
        out.pt_idx   = (UINT32)((gpa4K >> 12) & 0x1FFULL);

        // Walk NPT by hand. NPT entries live in host-identity-mapped memory,
        // so the physical address == host virtual address.
        {
            UINT64* pml4 = (UINT64*)(UINTN)activeNcr3;
            UINT64 e;
            e = pml4[out.pml4_idx];
            out.pml4e = e;
            if (!(e & 0x1)) { out.stop_level = 1; goto diag_walk_done; }

            {
                UINT64* pdpt = (UINT64*)(UINTN)(e & 0x000FFFFFFFFFF000ULL);
                e = pdpt[out.pdpt_idx];
                out.pdpte = e;
                if (!(e & 0x1)) { out.stop_level = 1; goto diag_walk_done; }
                if (e & 0x80)  { out.stop_level = 2; goto diag_walk_done; }  // 1GB leaf

                {
                    UINT64* pd = (UINT64*)(UINTN)(e & 0x000FFFFFFFFFF000ULL);
                    e = pd[out.pd_idx];
                    out.pde = e;
                    if (!(e & 0x1)) { out.stop_level = 1; goto diag_walk_done; }
                    if (e & 0x80)  { out.stop_level = 3; goto diag_walk_done; }  // 2MB leaf

                    {
                        UINT64* pt = (UINT64*)(UINTN)(e & 0x000FFFFFFFFFF000ULL);
                        e = pt[out.pt_idx];
                        out.pte = e;
                        out.stop_level = 4;
                    }
                }
            }
        }
diag_walk_done:
        if (!WriteGuestVa(callerCr3, dstVa, sizeof(out), &out))
        { Context->Cpu->States.Guest.Registers->Rax = (UINT64)-1; break; }
        Context->Cpu->States.Guest.Registers->Rax = sizeof(out);
        break;
    }

    case AO_CMD_PH_DIAG_NCR3:
    {
        // RCX = dst VA for ph_diag_ncr3.
        UINT64 dstVa = Context->Cpu->States.Guest.Registers->Rcx;
        UINT64 callerCr3 = Context->Cpu->GuestVmcb.StateSaveArea.Cr3;
        UINT32 cpuIdx;
        struct {
            UINT64 shadow_ncr3_pa;
            UINT64 read_ncr3_pa;
            UINT64 exec_ncr3_pa;
            UINT64 vmcb_ncr3;
            UINT32 npt_mode;
            UINT32 cpu_index;
            UINT32 ncr3_update_pending;
            UINT32 pad;
            UINT64 ncr3_pending_value;
        } out;

        if (dstVa == 0)
        { Context->Cpu->States.Guest.Registers->Rax = (UINT64)-1; break; }

        cpuIdx = 0;
        for (UINT32 i = 0; i < Context->Root->HostX64.ProcessorCount; ++i)
        {
            if (&Context->Root->Cpus[i] == Context->Cpu) { cpuIdx = i; break; }
        }

        {
            // VMCB.NCr3 inside HandleVmExit holds the DECOY (g_DecoyPagePa).
            // Report the real NCr3 that will be loaded before VMRUN instead.
            UINT64 activeReadNcr3_ = (g_ShadowNcr3Pa != 0) ? g_ShadowNcr3Pa : g_ReadNcr3Pa;
            UINT64 realNcr3_ = (Context->Cpu->States.Guest.NptMode == 0)
                               ? activeReadNcr3_ : g_ExecNcr3Pa;
            out.vmcb_ncr3 = realNcr3_;
        }
        out.shadow_ncr3_pa      = g_ShadowNcr3Pa;
        out.read_ncr3_pa        = g_ReadNcr3Pa;
        out.exec_ncr3_pa        = g_ExecNcr3Pa;
        out.npt_mode            = Context->Cpu->States.Guest.NptMode;
        out.cpu_index           = cpuIdx;
        out.ncr3_update_pending = Context->Cpu->States.Guest.NCr3UpdatePending;
        out.pad                 = 0;
        out.ncr3_pending_value  = Context->Cpu->States.Guest.NCr3PendingValue;

        if (!WriteGuestVa(callerCr3, dstVa, sizeof(out), &out))
        { Context->Cpu->States.Guest.Registers->Rax = (UINT64)-1; break; }
        Context->Cpu->States.Guest.Registers->Rax = sizeof(out);
        break;
    }

    case AO_CMD_PH_DIAG_HOOKMETA:
    {
        // RCX = dst VA for ph_diag_hookmeta (16 + 32*32 = 1040 bytes).
        UINT64 dstVa = Context->Cpu->States.Guest.Registers->Rcx;
        UINT64 callerCr3 = Context->Cpu->GuestVmcb.StateSaveArea.Cr3;
        SHARED_SVM_DATA* dsvm = &Context->Root->Svm;
        struct {
            UINT32 hook_count;
            UINT32 shadow_used;
            UINT64 pad;
            struct {
                UINT64 gpa4k;
                UINT64 original_pfn;
                UINT64 shadow_pfn;
                UINT32 active;
                UINT32 pad;
            } entries[32];
        } out;
        UINT32 n;

        if (dstVa == 0)
        { Context->Cpu->States.Guest.Registers->Rax = (UINT64)-1; break; }

        ZeroMem(&out, sizeof(out));
        out.hook_count  = dsvm->HookMeta.HookCount;
        out.shadow_used = dsvm->HookMeta.ShadowUsed;

        n = dsvm->HookMeta.HookCount;
        if (n > 32) n = 32;
        for (UINT32 i = 0; i < n; ++i)
        {
            out.entries[i].gpa4k        = dsvm->HookMeta.Hooks[i].Gpa4K;
            out.entries[i].original_pfn = dsvm->HookMeta.Hooks[i].OriginalPfn;
            out.entries[i].shadow_pfn   = dsvm->HookMeta.Hooks[i].ShadowPfn;
            out.entries[i].active       = dsvm->HookMeta.Hooks[i].Active ? 1 : 0;
        }

        if (!WriteGuestVa(callerCr3, dstVa, sizeof(out), &out))
        { Context->Cpu->States.Guest.Registers->Rax = (UINT64)-1; break; }
        Context->Cpu->States.Guest.Registers->Rax = sizeof(out);
        break;
    }

    case AO_CMD_PH_DIAG_COUNTERS:
    {
        // RCX = dst VA for ph_diag_counters (60 bytes: 9*u32 + 3*u64).
        UINT64 dstVa = Context->Cpu->States.Guest.Registers->Rcx;
        UINT64 callerCr3 = Context->Cpu->GuestVmcb.StateSaveArea.Cr3;
        struct {
            UINT32 npf_inst_fetch;
            UINT32 gpa_match;
            UINT32 rip_match;
            UINT32 cr3_match;
            UINT32 dispatch;
            UINT32 stray;
            UINT32 bp_count;
            UINT32 bp_owned;
            UINT32 bp_reinject;
            UINT32 pad;
            UINT64 last_guest_rip;
            UINT64 last_guest_cr3;
            UINT64 last_gpa4k;
        } out;

        if (dstVa == 0)
        { Context->Cpu->States.Guest.Registers->Rax = (UINT64)-1; break; }

        out.npf_inst_fetch  = g_PhNpfInstFetchCount;
        out.gpa_match       = g_PhGpaMatchCount;
        out.rip_match       = g_PhRipMatchCount;
        out.cr3_match       = g_PhCr3MatchCount;
        out.dispatch        = g_PhDispatchCount;
        out.stray           = g_PhStrayCount;
        out.bp_count        = g_PhBpCount;
        out.bp_owned        = g_PhBpOwnedCount;
        out.bp_reinject     = g_PhBpReinjectCount;
        out.pad             = 0;
        out.last_guest_rip  = g_PhLastGuestRip;
        out.last_guest_cr3  = g_PhLastGuestCr3;
        out.last_gpa4k      = g_PhLastGpa4K;

        if (!WriteGuestVa(callerCr3, dstVa, sizeof(out), &out))
        { Context->Cpu->States.Guest.Registers->Rax = (UINT64)-1; break; }
        Context->Cpu->States.Guest.Registers->Rax = sizeof(out);
        break;
    }

    default:
        Context->Cpu->States.Guest.Registers->Rax = (UINT64)-1;
        break;
    }

    // UD2 = 0F 0B = 2 bytes. #UD is fault-type so NRip is NOT populated by
    // hardware for exception intercepts — advance manually.
    Context->Cpu->GuestVmcb.StateSaveArea.Rip += 2;
}

/**
 * @brief Returns a pointer to the guest GPR identified by an x86 register
 *      index (0..15). The index follows the x86 ModR/M / REX encoding:
 *        0=RAX 1=RCX 2=RDX 3=RBX 4=RSP 5=RBP 6=RSI 7=RDI 8..15=R8..R15
 *
 *      RAX and RSP need special handling — RAX comes from VMCB save-state
 *      (already mirrored to HostStack->GuestRegisters.Rax before our
 *      switch), and RSP also comes from VMCB. The rest live in our saved
 *      GPR struct.
 */
STATIC
UINT64
ReadGuestGpr (
    IN HOST_CONTEXT* Context,
    IN UINT8 RegIdx
    )
{
    GUEST_REGISTERS* gprs = Context->Cpu->States.Guest.Registers;
    switch (RegIdx)
    {
    case 0:  return gprs->Rax;
    case 1:  return gprs->Rcx;
    case 2:  return gprs->Rdx;
    case 3:  return gprs->Rbx;
    case 4:  return Context->Cpu->GuestVmcb.StateSaveArea.Rsp;
    case 5:  return gprs->Rbp;
    case 6:  return gprs->Rsi;
    case 7:  return gprs->Rdi;
    case 8:  return gprs->R8;
    case 9:  return gprs->R9;
    case 10: return gprs->R10;
    case 11: return gprs->R11;
    case 12: return gprs->R12;
    case 13: return gprs->R13;
    case 14: return gprs->R14;
    case 15: return gprs->R15;
    default: return 0;
    }
}

/**
 * @brief Minimal x86 decoder for the MOV variants Windows uses to write
 *      MMIO. We only need to extract the VALUE BEING WRITTEN — the
 *      destination effective address is already given to us as the faulting
 *      GPA (VMCB.ExitInfo2). VMCB.GuestInstructionBytes contains the actual
 *      instruction (DecodeAssists feature; required CPUID 8000_000A.EDX[7]).
 *
 *      Handles:
 *        MOV r/m32, r32     (opcode 0x89 /r)   — most common (32-bit MMIO write)
 *        MOV r/m16, r16     (66 89 /r)
 *        MOV r/m64, r64     (REX.W 89 /r)
 *        MOV r/m32, imm32   (opcode 0xC7 /0 id)
 *
 *      Returns TRUE if decoded successfully; *ValueOut = value being
 *      written, *SizeOut = byte size of write (1, 2, 4, 8), *InsnLenOut =
 *      length of decoded instruction (for RIP advance).
 *
 *      Anything else (MOVNTI, string ops, locked variants, etc.) returns
 *      FALSE and the caller leaves the guest stalled (default branch).
 */
STATIC
BOOLEAN
DecodeMmioWriteInstruction (
    IN HOST_CONTEXT* Context,
    OUT UINT64* ValueOut,
    OUT UINT8* SizeOut,
    OUT UINT8* InsnLenOut
    )
{
    UINT8* bytes;
    UINT8 numBytes;
    UINT8 pos = 0;
    UINT8 rexW = 0;
    UINT8 rexR = 0;
    UINT8 rexX = 0;
    UINT8 rexB = 0;
    BOOLEAN opSize16 = FALSE;
    UINT8 opcode;
    UINT8 modrm;
    UINT8 mod;
    UINT8 reg;
    UINT8 rm;
    UINT8 operandSize;
    UINT64 value;

    bytes = Context->Cpu->GuestVmcb.ControlArea.GuestInstructionBytes;
    numBytes = Context->Cpu->GuestVmcb.ControlArea.NumOfBytesFetched;

    if (numBytes == 0)
    {
        return FALSE;
    }

    //
    // Skip legacy prefixes. 0x66 = operand size override (16-bit), 0x67 =
    // address size override (ignored — we have ExitInfo2 with the EA),
    // segment/lock/rep prefixes are also skipped. Stop at REX or opcode.
    //
    while (pos < numBytes)
    {
        UINT8 b = bytes[pos];
        if (b == 0x66) { opSize16 = TRUE; pos++; }
        else if (b == 0x67 || b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
                 b == 0x64 || b == 0x65 || b == 0xF0 || b == 0xF2 || b == 0xF3) { pos++; }
        else { break; }
    }

    // REX prefix?
    if (pos < numBytes && (bytes[pos] & 0xF0) == 0x40)
    {
        UINT8 rex = bytes[pos++];
        rexW = (rex >> 3) & 1;
        rexR = (rex >> 2) & 1;
        rexX = (rex >> 1) & 1;
        rexB = (rex >> 0) & 1;
    }

    if (pos >= numBytes) return FALSE;
    opcode = bytes[pos++];

    // Operand size: REX.W = 64-bit, else 66 = 16-bit, else 32-bit
    if (rexW) operandSize = 8;
    else if (opSize16) operandSize = 2;
    else operandSize = 4;

    // All ModRM-encoded r/m,r write-class opcodes follow the same encoding:
    //   01=ADD  09=OR  11=ADC  19=SBB  21=AND  29=SUB  31=XOR  39=CMP(skip)
    //   89=MOV  87=XCHG
    // We decode these uniformly: skip ModRM+SIB+displacement to get instruction
    // length, and report the source register value. Callers that only drop the
    // write (HvGuard) ignore the value; callers that need the exact written value
    // should only use MOV (0x89).
    if (opcode == 0x89 || opcode == 0x01 || opcode == 0x09 || opcode == 0x11 ||
        opcode == 0x19 || opcode == 0x21 || opcode == 0x29 || opcode == 0x31 ||
        opcode == 0x87)
    {
        // MOV/ADD/OR/ADC/SBB/AND/SUB/XOR/XCHG r/m, r — source in ModR/M.reg
        if (pos >= numBytes) return FALSE;
        modrm = bytes[pos++];
        mod = (modrm >> 6) & 3;
        reg = ((modrm >> 3) & 7) | (rexR << 3);
        rm  = (modrm & 7);

        if (mod == 3)
        {
            // Register-direct — not an MMIO write
            return FALSE;
        }
        // Skip SIB byte if r/m == 4 and mod != 3
        if (rm == 4 && mod != 3)
        {
            if (pos >= numBytes) return FALSE;
            pos++;  // SIB
        }
        // Skip displacement (we don't need it — ExitInfo2 has the EA)
        if (mod == 1) pos++;
        else if (mod == 2) pos += 4;
        else if (mod == 0 && rm == 5) pos += 4;  // [RIP+disp32] addressing

        value = ReadGuestGpr(Context, reg);
        if (operandSize == 2) value &= 0xFFFF;
        else if (operandSize == 4) value &= 0xFFFFFFFF;

        *ValueOut = value;
        *SizeOut = operandSize;
        *InsnLenOut = pos;
        return TRUE;
    }
    else if (opcode == 0xC7)
    {
        // MOV r/m, imm — destination from ModR/M, source from immediate
        if (pos >= numBytes) return FALSE;
        modrm = bytes[pos++];
        mod = (modrm >> 6) & 3;
        // For 0xC7, reg field is a /digit opcode extension; only /0 is MOV
        if (((modrm >> 3) & 7) != 0) return FALSE;
        rm = (modrm & 7);

        if (mod == 3) return FALSE;
        if (rm == 4 && mod != 3)
        {
            if (pos >= numBytes) return FALSE;
            pos++;  // SIB
        }
        if (mod == 1) pos++;
        else if (mod == 2) pos += 4;
        else if (mod == 0 && rm == 5) pos += 4;

        // Immediate: 16-bit if opSize16, else 32-bit (sign-extended to 64
        // if REX.W). Size of immediate is 32 even for 64-bit operand (the
        // 32-bit immediate is sign-extended by hardware).
        if (operandSize == 2)
        {
            if (pos + 2 > numBytes) return FALSE;
            value = bytes[pos] | (bytes[pos+1] << 8);
            pos += 2;
        }
        else
        {
            if (pos + 4 > numBytes) return FALSE;
            value = (UINT32)(bytes[pos] | (bytes[pos+1] << 8) |
                             (bytes[pos+2] << 16) | (bytes[pos+3] << 24));
            if (operandSize == 8 && (value & 0x80000000)) value |= 0xFFFFFFFF00000000ULL;
            pos += 4;
        }

        *ValueOut = value;
        *SizeOut = operandSize;
        *InsnLenOut = pos;
        return TRUE;
    }

    return FALSE;
}

/**
 * @brief Handles a guest write to LAPIC MMIO (xAPIC mode). Mirror of
 *      HandleIcrWrite from the x2APIC MSR path, but the value comes from the
 *      instruction operand (decoded via DecodeAssists) and the register
 *      target comes from the offset within the LAPIC page.
 *
 *      ICR layout in xAPIC: low dword at offset 0x300, high dword at 0x310.
 *      Software writes ICR_HI first (sets destination APIC ID in bits 24-31
 *      of the high dword), then ICR_LOW (which triggers the IPI). We capture
 *      ICR_HI when we see a write to 0x310 (just stash the destination), and
 *      do the actual emulation on the ICR_LOW write at 0x300.
 *
 *      Returns TRUE if the write should be passed through to hardware (so
 *      hardware delivers an actual IPI), FALSE if we fully emulated.
 */

STATIC volatile UINT32 g_PendingIcrDestApicId = 0;

STATIC
BOOLEAN
HandleLapicMmioWrite (
    IN OUT HOST_CONTEXT* Context,
    IN UINT32 Offset,
    IN UINT64 Value,
    IN UINT8 Size
    )
{
    BOOLEAN passThrough = TRUE;
    UINT32 v32;

    g_LapicMmioWriteCount++;
    WriteCmosByte(0x67, g_LapicMmioWriteCount);

    if (Size != 4)
    {
        // LAPIC registers are all 32-bit. Anything else is suspicious; just
        // pass through and let hardware deal with it.
        return TRUE;
    }
    v32 = (UINT32)Value;

    if (Offset == 0x310)
    {
        // ICR_HI: bits 24-31 = destination APIC ID (xAPIC physical).
        g_PendingIcrDestApicId = (v32 >> 24) & 0xFF;
        g_LastIcrHi = v32;
        WriteCmosByte(0x74, (UINT8)(v32 & 0xFF));
        WriteCmosByte(0x75, (UINT8)((v32 >> 8) & 0xFF));
        WriteCmosByte(0x76, (UINT8)((v32 >> 16) & 0xFF));
        WriteCmosByte(0x77, (UINT8)((v32 >> 24) & 0xFF));
        return TRUE;
    }

    if (Offset == 0x300)
    {
        // ICR_LOW write — IPI delivery trigger.
        UINT8 vector = (UINT8)(v32 & 0xFF);
        UINT8 deliveryMode = (UINT8)((v32 >> 8) & 0x7);
        UINT8 destShorthand = (UINT8)((v32 >> 18) & 0x3);

        g_IcrWriteCount++;
        WriteCmosByte(0x64, g_IcrWriteCount);
        g_LastIcrDeliveryMode = deliveryMode;
        WriteCmosByte(0x65, deliveryMode);
        g_LastIcrLow = v32;
        WriteCmosByte(0x70, (UINT8)(v32 & 0xFF));
        WriteCmosByte(0x71, (UINT8)((v32 >> 8) & 0xFF));
        WriteCmosByte(0x72, (UINT8)((v32 >> 16) & 0xFF));
        WriteCmosByte(0x73, (UINT8)((v32 >> 24) & 0xFF));

        if (deliveryMode == ICR_DELIVERY_SIPI)
        {
            passThrough = FALSE;
            if (destShorthand == ICR_DEST_SHORT_NONE)
            {
                // CMOS 0x49 = ProcessorCount, 0x4A = dest APIC ID being looked up,
                // 0x4B = result (0=null,1=found+notWaiting,2=found+wouldWake,3=self),
                // 0x4C = target's ApState at lookup time (0xFF if null).
                WriteCmosByte(0x49, (UINT8)(Context->Root->HostX64.ProcessorCount & 0xFF));
                WriteCmosByte(0x4A, (UINT8)(g_PendingIcrDestApicId & 0xFF));
                PER_CPU_DATA* target = FindCpuByApicId(Context->Root, g_PendingIcrDestApicId);
                if (target == NULL)
                {
                    WriteCmosByte(0x4B, 0);
                    WriteCmosByte(0x4C, 0xFF);
                }
                else if (target == Context->Cpu)
                {
                    WriteCmosByte(0x4B, 3);
                    WriteCmosByte(0x4C, (UINT8)(target->States.Guest.ApState & 0xFF));
                }
                else
                {
                    WriteCmosByte(0x4C, (UINT8)(target->States.Guest.ApState & 0xFF));
                    WriteCmosByte(0x4B,
                        (target->States.Guest.ApState == AP_STATE_WAIT_FOR_SIPI) ? 2 : 1);
                    EmulateSipiDelivery(target, vector);
                }
            }
            else if (destShorthand == ICR_DEST_SHORT_ALL ||
                     destShorthand == ICR_DEST_SHORT_ALL_BUT)
            {
                UINT32 count = Context->Root->HostX64.ProcessorCount;
                for (UINT32 i = 0; i < count; ++i)
                {
                    PER_CPU_DATA* target = &Context->Root->Cpus[i];
                    if (destShorthand == ICR_DEST_SHORT_ALL_BUT &&
                        target == Context->Cpu)
                    {
                        continue;
                    }
                    EmulateSipiDelivery(target, vector);
                }
            }
            // self-shorthand for SIPI is meaningless; ignore.
        }
        // INIT, Fixed, NMI, SMI: pass through. Hardware delivers to target;
        // for INIT specifically, target intercepts via InterceptMisc1.INIT
        // and our HandleInitSignal runs there.
    }

    return passThrough;
}

//
// ============================================================================
// Process-hook script interpreter.
// ============================================================================
//
// RunProcessHookScript is called from the NPF handler after an RIP-exact
// match against a PROCESS_HOOK_ENTRY. It executes the script's bytecode
// against the guest's register file / memory and returns one of:
//
//   PH_ACTION_CONTINUE = fall through: let original instruction run from
//                        the shadow (NCr3 is flipped to exec).
//   PH_ACTION_SKIP     = original does NOT run; EIP has been advanced by
//                        the script (or left alone if the script did RETRET).
//
// On any fault the script returns CONTINUE with LastFaultReason populated —
// the goal is to never crash the guest.
//

#define PH_ACTION_CONTINUE  0u
#define PH_ACTION_SKIP      1u

// Decode A/B operand to UINT64 value from the live register file.
STATIC
UINT64
PhReadOperand (
    IN UINT8                       sel,
    IN CONST UINT64*               scratch,        // 16 slots
    IN CONST GUEST_REGISTERS*      g,
    IN UINT64                      guestEip,
    IN UINT64                      guestEflags,
    IN UINT64                      guestEsp,
    IN CONST UINT32*               shadowArgs,     // 8 slots
    IN CONST UINT32*               configSlots     // 16 slots
    )
{
    if (sel <= PH_R15)
        return scratch[sel];
    switch (sel)
    {
    case PH_GR_EAX:    return (UINT32)g->Rax;
    case PH_GR_ECX:    return (UINT32)g->Rcx;
    case PH_GR_EDX:    return (UINT32)g->Rdx;
    case PH_GR_EBX:    return (UINT32)g->Rbx;
    case PH_GR_ESP:    return (UINT32)guestEsp;
    case PH_GR_EBP:    return (UINT32)g->Rbp;
    case PH_GR_ESI:    return (UINT32)g->Rsi;
    case PH_GR_EDI:    return (UINT32)g->Rdi;
    case PH_GR_EIP:    return guestEip;
    case PH_GR_EFLAGS: return guestEflags;
    default: break;
    }
    if (sel >= PH_GR_ARG1 && sel <= PH_GR_ARG8)
        return shadowArgs[sel - PH_GR_ARG1];
    if (sel >= PH_CFG0 && sel <= PH_CFG15)
        return configSlots[sel - PH_CFG0];
    return 0;
}

// Write a UINT64 into the destination register slot. ESP/EIP/EFLAGS go into
// the VMCB on commit; we stage into pending slots during execution. Returns
// FALSE if the destination is a read-only register.
STATIC
BOOLEAN
PhWriteOperand (
    IN     UINT8           sel,
    IN OUT UINT64*         scratch,
    IN OUT GUEST_REGISTERS* g,
    IN OUT UINT64*         pendingEip,
    IN OUT UINT64*         pendingEflags,
    IN OUT BOOLEAN*        eipDirty,
    IN OUT UINT32*         shadowArgs,
    IN OUT BOOLEAN*        argDirty,            // per-arg dirty (bit i)
    IN     UINT64          value
    )
{
    if (sel <= PH_R15) { scratch[sel] = value; return TRUE; }
    switch (sel)
    {
    case PH_GR_EAX: g->Rax = (g->Rax & 0xFFFFFFFF00000000ULL) | (UINT32)value; return TRUE;
    case PH_GR_ECX: g->Rcx = (g->Rcx & 0xFFFFFFFF00000000ULL) | (UINT32)value; return TRUE;
    case PH_GR_EDX: g->Rdx = (g->Rdx & 0xFFFFFFFF00000000ULL) | (UINT32)value; return TRUE;
    case PH_GR_EBX: g->Rbx = (g->Rbx & 0xFFFFFFFF00000000ULL) | (UINT32)value; return TRUE;
    case PH_GR_EBP: g->Rbp = (g->Rbp & 0xFFFFFFFF00000000ULL) | (UINT32)value; return TRUE;
    case PH_GR_ESI: g->Rsi = (g->Rsi & 0xFFFFFFFF00000000ULL) | (UINT32)value; return TRUE;
    case PH_GR_EDI: g->Rdi = (g->Rdi & 0xFFFFFFFF00000000ULL) | (UINT32)value; return TRUE;
    case PH_GR_EIP: *pendingEip = value; *eipDirty = TRUE; return TRUE;
    case PH_GR_EFLAGS: *pendingEflags = value; return TRUE;
    case PH_GR_ESP: return FALSE;   // ESP mutation only via RETRET for safety
    default: break;
    }
    if (sel >= PH_GR_ARG1 && sel <= PH_GR_ARG8)
    {
        UINT8 idx = sel - PH_GR_ARG1;
        shadowArgs[idx] = (UINT32)value;
        *argDirty = TRUE;
        return TRUE;
    }
    return FALSE;
}

// Push one entry to the debug log ring. Non-blocking; drops on overflow.
STATIC
VOID
PhLogAppend (
    IN UINT64 Cr3,
    IN UINT64 Va,
    IN UINT64 A,
    IN UINT64 B
    )
{
    PROCESS_HOOK_LOG* log = g_ProcessHookLog;
    UINT32 slot;
    if (log == NULL) return;
    if (log->Count >= PROCESS_HOOK_LOG_CAPACITY) { log->Dropped++; return; }
    slot = (log->Head + log->Count) % PROCESS_HOOK_LOG_CAPACITY;
    log->Entries[slot].Cr3 = Cr3;
    log->Entries[slot].Va  = Va;
    log->Entries[slot].A   = A;
    log->Entries[slot].B   = B;
    log->Count++;
}

STATIC
UINT32
RunProcessHookScript (
    IN OUT HOST_CONTEXT*        Context,
    IN OUT PROCESS_HOOK_ENTRY*  entry,
    IN     UINT64               guestCr3
    )
{
    GUEST_REGISTERS* g = Context->Cpu->States.Guest.Registers;
    UINT64 scratch[PROCESS_HOOK_SCRATCH_REGS] = {0};
    UINT32 shadowArgs[8] = {0};
    BOOLEAN argDirty = FALSE;
    UINT64 guestEsp = Context->Cpu->GuestVmcb.StateSaveArea.Rsp;
    UINT64 pendingEip = Context->Cpu->GuestVmcb.StateSaveArea.Rip;
    UINT64 pendingEflags = Context->Cpu->GuestVmcb.StateSaveArea.Rflags;
    UINT64 pendingEsp = guestEsp;
    BOOLEAN eipDirty = FALSE;
    BOOLEAN espDirty = FALSE;
    INT64 flagLt = 0, flagEq = 1, flagGt = 0;   // start neutral
    UINT32 action = PH_ACTION_CONTINUE;
    UINT32 cycles = 0;
    UINT32 pc = 0;
    BOOLEAN halted = FALSE;

    // ---- Resume path for PH_OP_CALL (per-CPU state) ----
    // If THIS CPU is mid-CALL for THIS hook slot AND the CR3 matches what we
    // captured at CALL time, this NPF is the callee returning to TargetVa.
    // Any other combination (different CPU, different hook slot, different
    // CR3) is NOT our resume — it's a fresh fire on a different thread, and
    // the script runs from PC=0 as usual.
    {
        GUEST_STATE* cs = &Context->Cpu->States.Guest;
        UINT32 thisSlot = (UINT32)(entry - g_ProcessHooks->Entries);
        if (cs->CallActive && cs->CallHookSlot == thisSlot &&
            cs->CallSavedCr3 == guestCr3)
        {
            for (UINT32 i = 0; i < PROCESS_HOOK_SCRATCH_REGS; ++i)
                scratch[i] = cs->CallSavedScratch[i];
            // Restore ESP to pre-CALL value (we pushed args+retaddr; the simplest
            // cleanup is to restore the exact pre-call ESP).
            pendingEsp = cs->CallSavedEsp;
            espDirty = TRUE;
            // Stash guest EAX into CallRetValReg if requested.
            if (cs->CallRetValReg != 0)
            {
                UINT64 eax = (UINT32)g->Rax;
                (VOID)PhWriteOperand(cs->CallRetValReg, scratch, g,
                                     &pendingEip, &pendingEflags, &eipDirty,
                                     shadowArgs, &argDirty, eax);
            }
            pc = cs->CallResumePc;
            cs->CallActive = 0;
            // Use the restored ESP to preload the shadow args.
            guestEsp = pendingEsp;
        }
    }

    // Preload stack arg shadow slots (ARG1..ARG8 = [ESP+4..ESP+32] in 32-bit).
    for (UINT32 i = 0; i < 8; ++i)
    {
        UINT32 val = 0;
        UINT64 argVa = guestEsp + 4 + (4 * i);
        (VOID)ReadGuestVa(guestCr3, argVa, sizeof(val), &val);
        shadowArgs[i] = val;
    }

    while (!halted && cycles < PROCESS_HOOK_MAX_CYCLES && pc < entry->InsnCount)
    {
        CONST PROCESS_HOOK_INSN* in = &entry->Script[pc];
        UINT64 aV, bV, rV;
        BOOLEAN ok;

        cycles++;

        switch (in->Op)
        {
        case PH_OP_NOP:
            break;

        case PH_OP_LOADI:
            if (!PhWriteOperand(in->Dst, scratch, g, &pendingEip, &pendingEflags,
                                &eipDirty, shadowArgs, &argDirty, (UINT64)in->Imm))
                { entry->LastFaultReason = PH_FAULT_WRITE_RO_REG; entry->LastFaultPc = pc; halted = TRUE; action = PH_ACTION_CONTINUE; }
            break;

        case PH_OP_MOV:
            aV = PhReadOperand(in->A, scratch, g, pendingEip, pendingEflags, guestEsp, shadowArgs, entry->Config);
            if (!PhWriteOperand(in->Dst, scratch, g, &pendingEip, &pendingEflags,
                                &eipDirty, shadowArgs, &argDirty, aV))
                { entry->LastFaultReason = PH_FAULT_WRITE_RO_REG; entry->LastFaultPc = pc; halted = TRUE; action = PH_ACTION_CONTINUE; }
            break;

        case PH_OP_ADD: case PH_OP_SUB: case PH_OP_MUL:
        case PH_OP_AND: case PH_OP_OR:  case PH_OP_XOR:
            aV = PhReadOperand(in->A, scratch, g, pendingEip, pendingEflags, guestEsp, shadowArgs, entry->Config);
            bV = PhReadOperand(in->B, scratch, g, pendingEip, pendingEflags, guestEsp, shadowArgs, entry->Config);
            switch (in->Op)
            {
            case PH_OP_ADD: rV = aV + bV; break;
            case PH_OP_SUB: rV = aV - bV; break;
            case PH_OP_MUL: rV = aV * bV; break;
            case PH_OP_AND: rV = aV & bV; break;
            case PH_OP_OR:  rV = aV | bV; break;
            default:        rV = aV ^ bV; break;
            }
            ok = PhWriteOperand(in->Dst, scratch, g, &pendingEip, &pendingEflags,
                                &eipDirty, shadowArgs, &argDirty, rV);
            if (!ok) { entry->LastFaultReason = PH_FAULT_WRITE_RO_REG; entry->LastFaultPc = pc; halted = TRUE; action = PH_ACTION_CONTINUE; }
            break;

        case PH_OP_SHL:
            aV = PhReadOperand(in->A, scratch, g, pendingEip, pendingEflags, guestEsp, shadowArgs, entry->Config);
            rV = aV << (in->Imm & 63);
            if (!PhWriteOperand(in->Dst, scratch, g, &pendingEip, &pendingEflags,
                                &eipDirty, shadowArgs, &argDirty, rV))
                { entry->LastFaultReason = PH_FAULT_WRITE_RO_REG; entry->LastFaultPc = pc; halted = TRUE; action = PH_ACTION_CONTINUE; }
            break;

        case PH_OP_SHR:
            aV = PhReadOperand(in->A, scratch, g, pendingEip, pendingEflags, guestEsp, shadowArgs, entry->Config);
            rV = aV >> (in->Imm & 63);
            if (!PhWriteOperand(in->Dst, scratch, g, &pendingEip, &pendingEflags,
                                &eipDirty, shadowArgs, &argDirty, rV))
                { entry->LastFaultReason = PH_FAULT_WRITE_RO_REG; entry->LastFaultPc = pc; halted = TRUE; action = PH_ACTION_CONTINUE; }
            break;

        case PH_OP_CMP:
            aV = PhReadOperand(in->A, scratch, g, pendingEip, pendingEflags, guestEsp, shadowArgs, entry->Config);
            bV = PhReadOperand(in->B, scratch, g, pendingEip, pendingEflags, guestEsp, shadowArgs, entry->Config);
            flagLt = (aV <  bV);
            flagEq = (aV == bV);
            flagGt = (aV >  bV);
            break;

        case PH_OP_JMP:
            pc = (UINT32)((INT32)pc + (INT32)in->Imm);
            continue;
        case PH_OP_JEQ:
            if (flagEq) { pc = (UINT32)((INT32)pc + (INT32)in->Imm); continue; }
            break;
        case PH_OP_JNE:
            if (!flagEq) { pc = (UINT32)((INT32)pc + (INT32)in->Imm); continue; }
            break;
        case PH_OP_JLT:
            if (flagLt) { pc = (UINT32)((INT32)pc + (INT32)in->Imm); continue; }
            break;
        case PH_OP_JGT:
            if (flagGt) { pc = (UINT32)((INT32)pc + (INT32)in->Imm); continue; }
            break;

        case PH_OP_READ1: case PH_OP_READ2: case PH_OP_READ4:
            aV = PhReadOperand(in->A, scratch, g, pendingEip, pendingEflags, guestEsp, shadowArgs, entry->Config);
            {
                UINT64 addr = (UINT32)aV + (INT32)in->Imm;
                UINT8 sz = (in->Op == PH_OP_READ1) ? 1 : (in->Op == PH_OP_READ2) ? 2 : 4;
                UINT32 tmp = 0;
                if (!ReadGuestVa(guestCr3, addr, sz, &tmp))
                {
                    entry->LastFaultReason = PH_FAULT_READ_FAILED;
                    entry->LastFaultPc = pc;
                    tmp = 0;    // fail-safe zero; script decides
                }
                if (!PhWriteOperand(in->Dst, scratch, g, &pendingEip, &pendingEflags,
                                    &eipDirty, shadowArgs, &argDirty, tmp))
                    { entry->LastFaultReason = PH_FAULT_WRITE_RO_REG; entry->LastFaultPc = pc; halted = TRUE; action = PH_ACTION_CONTINUE; }
            }
            break;

        case PH_OP_WRITE1: case PH_OP_WRITE2: case PH_OP_WRITE4:
            aV = PhReadOperand(in->A, scratch, g, pendingEip, pendingEflags, guestEsp, shadowArgs, entry->Config);
            bV = PhReadOperand(in->B, scratch, g, pendingEip, pendingEflags, guestEsp, shadowArgs, entry->Config);
            {
                UINT64 addr = (UINT32)aV + (INT32)in->Imm;
                UINT8 sz = (in->Op == PH_OP_WRITE1) ? 1 : (in->Op == PH_OP_WRITE2) ? 2 : 4;
                UINT32 tmp = (UINT32)bV;
                if (!WriteGuestVa(guestCr3, addr, sz, &tmp))
                {
                    entry->LastFaultReason = PH_FAULT_WRITE_FAILED;
                    entry->LastFaultPc = pc;
                    // continue script — write-failures aren't fatal to us
                }
            }
            break;

        case PH_OP_LOG:
            aV = PhReadOperand(in->A, scratch, g, pendingEip, pendingEflags, guestEsp, shadowArgs, entry->Config);
            bV = PhReadOperand(in->B, scratch, g, pendingEip, pendingEflags, guestEsp, shadowArgs, entry->Config);
            PhLogAppend(guestCr3, entry->TargetVa, aV, bV);
            break;

        case PH_OP_RETCONT:
            action = PH_ACTION_CONTINUE;
            halted = TRUE;
            break;

        case PH_OP_RETSKIP:
            pendingEip = (UINT32)(entry->TargetVa + (INT32)in->Imm);
            eipDirty = TRUE;
            action = PH_ACTION_SKIP;
            halted = TRUE;
            break;

        case PH_OP_RETRET:
            {
                UINT32 retAddr = 0;
                if (ReadGuestVa(guestCr3, guestEsp, 4, &retAddr))
                {
                    pendingEip = retAddr;
                    eipDirty = TRUE;
                    guestEsp += 4 + (UINT64)in->Imm;
                    Context->Cpu->GuestVmcb.StateSaveArea.Rsp = guestEsp;
                    Context->Cpu->GuestVmcb.ControlArea.VmcbClean = 0;
                    action = PH_ACTION_SKIP;
                }
                else
                {
                    entry->LastFaultReason = PH_FAULT_READ_FAILED;
                    entry->LastFaultPc = pc;
                    action = PH_ACTION_CONTINUE;
                }
                halted = TRUE;
            }
            break;

        case PH_OP_HALT:
            action = PH_ACTION_SKIP;
            halted = TRUE;
            break;

        case PH_OP_CALL:
            {
                // Dst = retval reg (0 to discard)
                // A   = register holding function VA
                // B   = nargs (0..4)
                // Imm = 4 bytes, each an operand encoding for one arg
                UINT32 nargs = (UINT32)in->B;
                UINT64 funcVa = PhReadOperand(in->A, scratch, g, pendingEip,
                                              pendingEflags, pendingEsp, shadowArgs, entry->Config);
                if (nargs > 4)
                {
                    entry->LastFaultReason = PH_FAULT_BAD_OPERAND;
                    entry->LastFaultPc = pc;
                    halted = TRUE;
                    action = PH_ACTION_CONTINUE;
                    break;
                }
                UINT64 newEsp = pendingEsp;
                // Push args right-to-left for cdecl.
                for (INT32 ai = (INT32)nargs - 1; ai >= 0; --ai)
                {
                    UINT8 argSel = (UINT8)((in->Imm >> (ai * 8)) & 0xFF);
                    UINT64 argVal = PhReadOperand(argSel, scratch, g, pendingEip,
                                                  pendingEflags, pendingEsp, shadowArgs, entry->Config);
                    newEsp -= 4;
                    UINT32 argVal32 = (UINT32)argVal;
                    if (!WriteGuestVa(guestCr3, newEsp, 4, &argVal32))
                    {
                        entry->LastFaultReason = PH_FAULT_WRITE_FAILED;
                        entry->LastFaultPc = pc;
                        halted = TRUE;
                        action = PH_ACTION_CONTINUE;
                        goto call_fail;
                    }
                }
                // Push return address = TargetVa so callee's `ret` lands back
                // on our hook VA. The NPF path will recognize CallActive and
                // resume the script at CallResumePc.
                newEsp -= 4;
                UINT32 retAddr32 = (UINT32)entry->TargetVa;
                if (!WriteGuestVa(guestCr3, newEsp, 4, &retAddr32))
                {
                    entry->LastFaultReason = PH_FAULT_WRITE_FAILED;
                    entry->LastFaultPc = pc;
                    halted = TRUE;
                    action = PH_ACTION_CONTINUE;
                    goto call_fail;
                }
                // Snapshot script state for resume — PER-CPU, not per-entry.
                // If this CPU was already mid-CALL (nested call attempt),
                // treat as a fault; nested CALLs aren't supported.
                {
                    GUEST_STATE* cs = &Context->Cpu->States.Guest;
                    if (cs->CallActive)
                    {
                        entry->LastFaultReason = PH_FAULT_BAD_OPERAND;
                        entry->LastFaultPc = pc;
                        halted = TRUE;
                        action = PH_ACTION_CONTINUE;
                        goto call_fail;
                    }
                    for (UINT32 ri = 0; ri < PROCESS_HOOK_SCRATCH_REGS; ++ri)
                        cs->CallSavedScratch[ri] = scratch[ri];
                    cs->CallSavedEsp  = pendingEsp;      // pre-CALL ESP
                    cs->CallSavedCr3  = guestCr3;        // scope resume to this CR3
                    cs->CallSavedEip  = entry->TargetVa;
                    cs->CallResumePc  = pc + 1;
                    cs->CallRetValReg = in->Dst;
                    cs->CallHookSlot  = (UINT32)(entry - g_ProcessHooks->Entries);
                    cs->CallActive    = 1;
                }
                // Set guest EIP = funcVa, ESP = newEsp; skip the original insn.
                pendingEip = funcVa;
                eipDirty = TRUE;
                pendingEsp = newEsp;
                espDirty = TRUE;
                action = PH_ACTION_SKIP;
                halted = TRUE;
            }
        call_fail:
            break;

        default:
            entry->LastFaultReason = PH_FAULT_BAD_OPCODE;
            entry->LastFaultPc = pc;
            halted = TRUE;
            action = PH_ACTION_CONTINUE;
            break;
        }

        pc++;
    }

    if (cycles >= PROCESS_HOOK_MAX_CYCLES && !halted)
    {
        entry->LastFaultReason = PH_FAULT_CYCLE_LIMIT;
        entry->LastFaultPc = pc;
        action = PH_ACTION_CONTINUE;
    }

    // Commit staged VMCB fields.
    if (eipDirty)
    {
        Context->Cpu->GuestVmcb.StateSaveArea.Rip = (UINT32)pendingEip;
        Context->Cpu->GuestVmcb.ControlArea.VmcbClean = 0;
    }
    if (espDirty)
    {
        Context->Cpu->GuestVmcb.StateSaveArea.Rsp = (UINT32)pendingEsp;
        Context->Cpu->GuestVmcb.ControlArea.VmcbClean = 0;
    }
    if (pendingEflags != Context->Cpu->GuestVmcb.StateSaveArea.Rflags)
    {
        Context->Cpu->GuestVmcb.StateSaveArea.Rflags = pendingEflags;
        Context->Cpu->GuestVmcb.ControlArea.VmcbClean = 0;
    }
    if (argDirty)
    {
        for (UINT32 i = 0; i < 8; ++i)
        {
            UINT64 argVa = guestEsp + 4 + (4 * i);
            (VOID)WriteGuestVa(guestCr3, argVa, sizeof(shadowArgs[i]), &shadowArgs[i]);
        }
    }

    entry->HitCount++;
    g_ProcessHooks->DispatchCount++;
    if (entry->LastFaultReason != PH_FAULT_NONE)
        g_ProcessHooks->FaultCount++;

    return action;
}

// Try to dispatch a process hook for the current NPF. Returns TRUE if a
// script fired and the NPF should be considered handled (either SKIP or
// CONTINUE). The caller handles NCr3 flip for CONTINUE.
STATIC
BOOLEAN
TryDispatchProcessHook (
    IN OUT HOST_CONTEXT* Context,
    IN     UINT64        gpa4K,
    OUT    UINT32*       OutAction
    )
{
    UINT64 guestRip;
    UINT64 guestCr3;
    UINT32 i;

    if (g_ProcessHooks == NULL || g_ProcessHooks->NumActive == 0)
        return FALSE;

    guestRip = Context->Cpu->GuestVmcb.StateSaveArea.Rip;
    guestCr3 = Context->Cpu->GuestVmcb.StateSaveArea.Cr3 & ~0xFFFULL;

    // Record the fetch we're being asked to dispatch so diag_counters can
    // show the last attempt's (gpa, rip, cr3) — critical for triaging a
    // "hits=0 but hook installed" case.
    g_PhLastGpa4K    = gpa4K;
    g_PhLastGuestRip = guestRip;
    g_PhLastGuestCr3 = guestCr3;

    for (i = 0; i < PROCESS_HOOK_MAX; ++i)
    {
        PROCESS_HOOK_ENTRY* e = &g_ProcessHooks->Entries[i];
        if (!e->Active) continue;
        if (e->TargetGpa4K != gpa4K) continue;
        if (g_PhGpaMatchCount < 0xFFFFFFFFUL) g_PhGpaMatchCount++;
        if (e->TargetVa != guestRip) continue;
        if (g_PhRipMatchCount < 0xFFFFFFFFUL) g_PhRipMatchCount++;
        if (e->TargetCr3 != 0 && (e->TargetCr3 & ~0xFFFULL) != guestCr3) continue;
        if (g_PhCr3MatchCount < 0xFFFFFFFFUL) g_PhCr3MatchCount++;
        *OutAction = RunProcessHookScript(Context, e, guestCr3);
        if (g_PhDispatchCount < 0xFFFFFFFFUL) g_PhDispatchCount++;
        return TRUE;
    }
    return FALSE;
}

// Returns TRUE if any active hook (process hook or syscall-log hook) lives
// in the same 1GB region as `Gpa`. Used to short-circuit the "NPT corruption
// repair" and "lazy NPT recovery" paths before they rewrite a PDPT entry
// that's actually a legitimate split-page hook pointer. Without this gate,
// those repair paths will silently disarm hooks by restoring a 1GB identity
// leaf or by clearing the NX bit.
STATIC
BOOLEAN
IsAnyHookIn1Gb (
    IN SHARED_SVM_DATA* Svm,
    IN UINT64           Gpa
    )
{
    UINT64 oneGbBase = Gpa & ~(UINT64)0x3FFFFFFF;
    UINT32 i;
    if (Svm->HookMeta.HookCount == 0) return FALSE;
    for (i = 0; i < Svm->HookMeta.HookCount; ++i)
    {
        if (!Svm->HookMeta.Hooks[i].Active) continue;
        if ((Svm->HookMeta.Hooks[i].Gpa4K & ~(UINT64)0x3FFFFFFF) == oneGbBase)
            return TRUE;
    }
    return FALSE;
}

/**
 * @brief Handle a #DB (debug exception) intercept.
 *
 *   The Option-7 single-step flip-back primitive: the NPF handler flips this
 *   CPU to exec NCr3 and sets EFLAGS.TF=1 so the guest executes exactly ONE
 *   instruction from the shadow page before the CPU raises #DB (single-step
 *   trap). Here we flip back to read NCr3, clear the TF we set, and resume.
 *
 *   The exec-tree exposure window is thus one guest instruction wide; a
 *   data read of the hook page from any other CPU almost certainly lands
 *   while we're on read NCr3 and sees the original (unmodified) bytes.
 *
 *   #DBs we didn't initiate (hardware-breakpoint traps set by a guest
 *   debugger via DR0..DR7, or TF=1 the guest itself set) are re-injected
 *   so native debugging behavior is preserved.
 */
STATIC
VOID
HandleDebugException (
    IN OUT HOST_CONTEXT* Context
    )
{
    if (g_PhBpCount < 0xFFFFFFFFUL) g_PhBpCount++;

    if (Context->Cpu->States.Guest.ExpectDbForFlipBack != 0)
    {
        //
        // Ours. Flip back to read NCr3, clear the TF we set, drop the flag.
        // The guest's original EFLAGS.TF (saved in GuestSavedRflagsTf) is
        // restored so the guest never sees we touched it.
        //
        UINT64 readNcr3 = (g_ShadowNcr3Pa != 0) ? g_ShadowNcr3Pa : g_ReadNcr3Pa;
        UINT64 rflags   = Context->Cpu->GuestVmcb.StateSaveArea.Rflags;

        Context->Cpu->GuestVmcb.ControlArea.NCr3       = readNcr3;
        Context->Cpu->GuestVmcb.ControlArea.TlbControl = 1;
        Context->Cpu->GuestVmcb.ControlArea.VmcbClean  = 0;
        Context->Cpu->States.Guest.NptMode             = 0;
        Context->Cpu->States.Guest.NCr3UpdatePending   = 0;

        // ALWAYS clear TF. Critical invariant: never leak TF into guest
        // user mode, or an unhandled STATUS_SINGLE_STEP (0x80000004) kills
        // the process. Accept the behavioral loss for a guest-TF debugger
        // (very rare target scenario).
        rflags &= ~(1ULL << 8);

        // Restore guest IF. We cleared it in PhArmExecFlipWithSingleStep to
        // guarantee interrupt-free single-step; restore to what guest had.
        if (Context->Cpu->States.Guest.GuestSavedRflagsIf)
            rflags |= (1ULL << 9);
        else
            rflags &= ~(1ULL << 9);

        Context->Cpu->GuestVmcb.StateSaveArea.Rflags = rflags;

        Context->Cpu->States.Guest.ExpectDbForFlipBack = 0;
        Context->Cpu->States.Guest.GuestSavedRflagsTf  = 0;
        Context->Cpu->States.Guest.GuestSavedRflagsIf  = 0;

        if (g_PhBpOwnedCount < 0xFFFFFFFFUL) g_PhBpOwnedCount++;
        return;
    }

    //
    // Not ours — guest's own #DB (hardware-breakpoint hit, or TF=1 set by
    // guest debugger). Re-inject.
    //
    Context->Cpu->GuestVmcb.ControlArea.EventInj =
        (1ULL << 31) | (3ULL << 8) | 1ULL;  // TYPE=exception, VECTOR=1
    if (g_PhBpReinjectCount < 0xFFFFFFFFUL) g_PhBpReinjectCount++;
}

//
// Helper: flip this CPU to exec NCr3 for the next guest instruction, armed
// to flip back via #DB. Caller sets NptMode via the VMCB write below; we also
// preserve the guest's EFLAGS.TF so restoring it on #DB is observationally
// invisible.
//
STATIC
VOID
PhArmExecFlipWithSingleStep (
    IN OUT HOST_CONTEXT* Context
    )
{
    UINT64 rflags = Context->Cpu->GuestVmcb.StateSaveArea.Rflags;

    // Snapshot guest's current TF and IF bits so HandleDebugException can
    // restore both correctly.
    Context->Cpu->States.Guest.GuestSavedRflagsTf =
        (UINT8)((rflags >> 8) & 1ULL);
    Context->Cpu->States.Guest.GuestSavedRflagsIf =
        (UINT8)((rflags >> 9) & 1ULL);

    // Flip to exec NCr3 and flush TLB.
    Context->Cpu->GuestVmcb.ControlArea.NCr3       = g_ExecNcr3Pa;
    Context->Cpu->GuestVmcb.ControlArea.TlbControl = 1;
    Context->Cpu->GuestVmcb.ControlArea.VmcbClean  = 0;
    Context->Cpu->States.Guest.NptMode             = 1;

    //
    // Set TF so the next guest instruction raises #DB after one step.
    //
    // Clear IF (bit 9). If IF stays set, an external interrupt arriving
    // between VMRUN and our instruction causes the CPU to service the
    // interrupt FIRST, which pushes EFLAGS (with TF=1) onto the kernel
    // stack and clears TF in the live state. By the time iret restores
    // it, many instructions may have executed including the hooked VA's
    // `ret` which would run natively from shadow (no NPF, no dispatch,
    // no hook). Clearing IF holds off interrupts until our single-step
    // completes and we're back on read tree.
    //
    // Clear RF (bit 16). RF is set automatically by hardware on faults
    // (including the NPF that got us here) and suppresses the first
    // #DB after VMRUN. Clearing it guarantees our TF-driven #DB fires
    // on the FIRST instruction, not the second.
    //
    rflags |=  (1ULL << 8);    // set TF
    rflags &= ~(1ULL << 9);    // clear IF (guest interrupts off for this instr)
    rflags &= ~(1ULL << 16);   // clear RF
    Context->Cpu->GuestVmcb.StateSaveArea.Rflags = rflags;

    // Arm the flip-back flag the #DB handler keys off of.
    Context->Cpu->States.Guest.ExpectDbForFlipBack = 1;
}

//
// Emulate the original guest instruction at the hooked VA without ever
// executing from the shadow page for that specific instruction. Called
// from the NPF-dispatch CONTINUE path. Reads the original byte(s) via
// the host-identity-mapped physical address and re-implements the needed
// semantics so the CPU stays on the read NCr3 tree the entire time.
//
// For any opcode this function doesn't recognize, it falls back to the
// Option-7 single-step path (which exposes one instruction of shadow —
// still invisible with overwhelming probability for one-shot scanners).
//
STATIC
VOID
PhEmulateHookedInstruction (
    IN OUT HOST_CONTEXT* Context,
    IN     UINT64        origPagePa,
    IN     UINT64        guestRip
    )
{
    BOOLEAN is64 = ((Context->Cpu->GuestVmcb.StateSaveArea.CsAttrib & 0x200) != 0);
    UINT64  callerCr3 = Context->Cpu->GuestVmcb.StateSaveArea.Cr3;
    UINT8   origByte  = *(volatile UINT8*)(UINTN)(origPagePa + (guestRip & 0xFFFULL));

    switch (origByte)
    {
    case 0xC3:  // near RET (no imm16)
    {
        if (is64)
        {
            UINT64 rsp    = Context->Cpu->GuestVmcb.StateSaveArea.Rsp;
            UINT64 newRip = 0;
            if (!ReadGuestVa(callerCr3, rsp, 8, &newRip)) goto fallback;
            Context->Cpu->GuestVmcb.StateSaveArea.Rsp = rsp + 8;
            Context->Cpu->GuestVmcb.StateSaveArea.Rip = newRip;
        }
        else
        {
            UINT32 esp    = (UINT32)Context->Cpu->GuestVmcb.StateSaveArea.Rsp;
            UINT32 newEip = 0;
            if (!ReadGuestVa(callerCr3, (UINT64)esp, 4, &newEip)) goto fallback;
            Context->Cpu->GuestVmcb.StateSaveArea.Rsp = (UINT64)(esp + 4);
            Context->Cpu->GuestVmcb.StateSaveArea.Rip = (UINT64)newEip;
        }
        Context->Cpu->GuestVmcb.StateSaveArea.Rax =
            Context->Cpu->States.Guest.Registers->Rax;
        return;
    }

    case 0x89:  // MOV r/m32, r32 (32-bit guest only)
    {
        //
        // Decode ModR/M for the common 32-bit "MOV [reg+disp], r32" store.
        // We support the exact forms a compiler emits for struct-field writes:
        //
        //   mod=00 r/m=rrr   -> [reg]                 (no disp, no SIB, no r/m=100/101)
        //   mod=01 r/m=rrr   -> [reg + disp8]         (1-byte disp)
        //   mod=10 rrr=rrr   -> [reg + disp32]        (4-byte disp)
        //   mod=11           -> reg,reg (unsupported — fall back)
        //
        // r/m=100 (SIB) and r/m=101 (disp32-only at mod=00) are less common
        // for field stores, but not our hooked pattern (89 46 1C uses esi).
        // Unsupported ModR/M encodings fall through to single-step.
        //
        // Instruction bytes live on the SAME host-identity-mapped original
        // page, so we can read the disp inline from origPagePa.
        //
        UINT8  pageBase  = (UINT8)(guestRip & 0xFFFULL);
        UINT8  modrm;
        UINT32 mod_, reg_, rm_;
        UINT32 regValue;
        UINT64 effAddr;
        UINT32 insnLen = 2;   // opcode + ModR/M by default

        if (is64) goto fallback;

        // Ensure ModR/M byte is still on the same 4KB page as the opcode.
        if (pageBase == 0xFFF) goto fallback;
        modrm = *(volatile UINT8*)(UINTN)(origPagePa + pageBase + 1);

        mod_ = (UINT32)((modrm >> 6) & 0x3);
        reg_ = (UINT32)((modrm >> 3) & 0x7);
        rm_  = (UINT32)( modrm       & 0x7);

        if (mod_ == 3) goto fallback;        // reg,reg form unsupported
        if (rm_  == 4) goto fallback;        // SIB form unsupported
        if (mod_ == 0 && rm_ == 5) goto fallback;  // disp32-only unsupported

        regValue = (UINT32)ReadGuestGpr(Context, (UINT8)reg_);
        effAddr  = (UINT32)ReadGuestGpr(Context, (UINT8)rm_);

        if (mod_ == 1)
        {
            // disp8 — must be on same page
            INT8 disp;
            if (pageBase + 1 >= 0xFFF) goto fallback;
            disp = (INT8)(*(volatile UINT8*)(UINTN)(origPagePa + pageBase + 2));
            effAddr = (UINT32)(effAddr + (INT32)disp);
            insnLen = 3;
        }
        else if (mod_ == 2)
        {
            // disp32 — 4 bytes, must all be on same page
            INT32 disp;
            if (pageBase > 0xFFC) goto fallback;
            disp = *(volatile INT32*)(UINTN)(origPagePa + pageBase + 2);
            effAddr = (UINT32)(effAddr + disp);
            insnLen = 6;
        }
        // mod==0: effAddr is just the register value; insnLen stays 2.

        // Script may have updated reg_ (commonly EAX) via Registers->Rax or
        // scratch; the current regValue read above is live. Perform the store
        // in the GUEST's address space using WriteGuestVa.
        if (!WriteGuestVa(callerCr3, effAddr, 4, &regValue)) goto fallback;

        // Advance RIP past the emulated MOV.
        Context->Cpu->GuestVmcb.StateSaveArea.Rip += insnLen;

        // Mirror RAX back in case the script wrote to EAX before the store.
        Context->Cpu->GuestVmcb.StateSaveArea.Rax =
            Context->Cpu->States.Guest.Registers->Rax;
        return;
    }

    default:
        goto fallback;
    }

fallback:
    // Unsupported opcode or unsafe decode: fall back to the single-step
    // shadow-exec path. Exec-tree exposure is one instruction wide and the
    // shadow is byte-identical, so cross-CPU reads see the same bytes.
    PhArmExecFlipWithSingleStep(Context);
}

/**
 * @brief VMEXIT_NPF handler. Fires when the guest accesses a page our NPT
 *      has marked as having insufficient permissions. We use it specifically
 *      to catch xAPIC LAPIC MMIO writes (NPT R/W=0 on the LAPIC 4KB page).
 *      Anything else hitting NPF is unexpected — probably a guest GPA
 *      outside the 256TB identity map, which means we'd want to investigate.
 */
STATIC
VOID
HandleNestedPageFault (
    IN OUT HOST_CONTEXT* Context
    )
{
    UINT64 gpa;
    UINT32 offset;
    UINT64 value;
    UINT8 size;
    UINT8 insnLen;
    BOOLEAN passThrough;

    g_NpfCount++;
    WriteCmosByte(0x68, g_NpfCount);

    gpa = Context->Cpu->GuestVmcb.ControlArea.ExitInfo2;

    if (g_LapicBasePa != 0 && gpa >= g_LapicBasePa && gpa < g_LapicBasePa + SIZE_4KB)
    {
        // LAPIC MMIO write
        offset = (UINT32)(gpa - g_LapicBasePa);

        if (!DecodeMmioWriteInstruction(Context, &value, &size, &insnLen))
        {
            g_NpfDecodeFailCount++;
            WriteCmosByte(0x69, g_NpfDecodeFailCount);
            // Couldn't decode — fall through and let default handler reset.
            RecordUnhandledExit(Context->Cpu->GuestVmcb.ControlArea.ExitCode);
            CpuReset();
            return;
        }

        passThrough = HandleLapicMmioWrite(Context, offset, value, size);

        if (passThrough)
        {
            // Mirror the write to the actual hardware LAPIC. Host CR3
            // identity-maps the LAPIC page (it's within 512GB), so direct
            // dereference works.
            switch (size)
            {
            case 1:
                *(volatile UINT8*)(UINTN)(g_LapicBasePa + offset) = (UINT8)value;
                break;
            case 2:
                *(volatile UINT16*)(UINTN)(g_LapicBasePa + offset) = (UINT16)value;
                break;
            case 4:
                *(volatile UINT32*)(UINTN)(g_LapicBasePa + offset) = (UINT32)value;
                break;
            case 8:
                *(volatile UINT64*)(UINTN)(g_LapicBasePa + offset) = value;
                break;
            }
        }

        // Advance RIP past the emulated MOV. AMD provides NextRIP for
        // most exits; NPF gives us... actually for NPF, NRip is NOT
        // populated, so use the decoded length.
        Context->Cpu->GuestVmcb.StateSaveArea.Rip += insnLen;
        return;
    }

    // Split-page hook: instruction fetch (ExitInfo1 bit 4) on a page marked NX
    // in the read NCr3.  Switch this CPU to the exec NCr3 so the shadow page
    // executes instead of the original.  Re-entering VMRUN re-executes the
    // faulting instruction from the shadow page.
    //
    // Only acts when NptMode == 0 (read NCr3 is active) and exec NCr3 is set up.
    // In exec NCr3 mode no hooked page has NX=1, so this branch can't fire then.
    if ((Context->Cpu->GuestVmcb.ControlArea.ExitInfo1 & (1ULL << 4)) != 0 &&
        Context->Cpu->States.Guest.NptMode == 0 &&
        g_ExecNcr3Pa != 0)
    {
        SHARED_SVM_DATA* svm = &Context->Root->Svm;
        UINT64 gpa4K = gpa & ~(UINT64)0xFFF;
        UINT32 hkIdx;

        if (g_PhNpfInstFetchCount < 0xFFFFFFFFUL) g_PhNpfInstFetchCount++;

        for (hkIdx = 0; hkIdx < svm->HookMeta.HookCount; ++hkIdx)
        {
            if (svm->HookMeta.Hooks[hkIdx].Active &&
                svm->HookMeta.Hooks[hkIdx].Gpa4K == gpa4K)
            {
                // Did any owner of this hooked page claim this fetch?
                // - A process-hook dispatch at the exact VA (claimed via CONTINUE or SKIP).
                // - A syscall-log hook whose RIP matches LSTAR/CSTAR.
                // We ONLY flip to exec NCr3 when ownership is claimed. Otherwise this is
                // a stray fetch on a non-hooked instruction within the same 4KB page
                // (e.g., the function's prologue when the hook target is a later
                // instruction in the same function). If we flipped on stray fetches,
                // the CPU would stay in exec NCr3 permanently and never re-NPF on the
                // real hook VA, silently disarming the hook.
                BOOLEAN phDispatched = FALSE;
                UINT32  phAction     = PH_ACTION_CONTINUE;
                if (TryDispatchProcessHook(Context, gpa4K, &phAction))
                {
                    phDispatched = TRUE;
                    if (phAction == PH_ACTION_SKIP)
                    {
                        // Script already set EIP (RETSKIP/RETRET/HALT).
                        // Stay on read NCr3; original instruction never runs.
                        return;
                    }
                    // CONTINUE: fall through to flip-to-exec below so the
                    // original instruction executes once from the shadow page.
                }

                BOOLEAN is64Hook = (g_SyscallLog != NULL &&
                                    g_SyscallLog->Active &&
                                    g_SyscallLog->SyscallGpa64 != 0 &&
                                    gpa4K == g_SyscallLog->SyscallGpa64);
                BOOLEAN is32Hook = (g_SyscallLog != NULL &&
                                    g_SyscallLog->Active &&
                                    g_SyscallLog->SyscallGpa32 != 0 &&
                                    gpa4K == g_SyscallLog->SyscallGpa32);

                BOOLEAN syscallRipOk = FALSE;
                if (is64Hook || is32Hook)
                {
                    UINT64 guestRip = Context->Cpu->GuestVmcb.StateSaveArea.Rip;
                    syscallRipOk = (is64Hook && guestRip == g_KernelLstar) ||
                                   (is32Hook && guestRip == g_KernelCstar);

                    if (syscallRipOk)
                    {
                        UINT64 guestCr3 = Context->Cpu->GuestVmcb.StateSaveArea.Cr3 & ~0xFFFULL;
                        BOOLEAN matchesFilter = (g_SyscallLog->FilterCr3 == 0 ||
                                                 guestCr3 == (g_SyscallLog->FilterCr3 & ~0xFFFULL));
                        if (matchesFilter && g_SyscallLog->Count < SYSCALL_LOG_CAPACITY)
                        {
                            UINT32 slot = (g_SyscallLog->Head + g_SyscallLog->Count) % SYSCALL_LOG_CAPACITY;
                            g_SyscallLog->Entries[slot].Cr3        = guestCr3;
                            g_SyscallLog->Entries[slot].SyscallNum = (UINT32)Context->Cpu->States.Guest.Registers->Rax;
                            g_SyscallLog->Entries[slot].CpuIndex   = (UINT16)Context->Cpu->States.Guest.ProcessorNumber;
                            g_SyscallLog->Entries[slot].Flags      = is32Hook ? SYSCALL_LOG_FLAG_32BIT : 0;
                            g_SyscallLog->Entries[slot].RetAddr    = Context->Cpu->States.Guest.Registers->Rcx;
                            g_SyscallLog->Entries[slot].Arg1       = Context->Cpu->States.Guest.Registers->R10;
                            g_SyscallLog->Count++;
                        }
                    }
                }

                //
                // Dispatch decision:
                //
                //   phDispatched (RIP == hook VA, script ran, CONTINUE)
                //     -> Emulate the hooked instruction IN HV. This CPU
                //        stays on read NCr3 the whole time, so a cross-CPU
                //        scanner reading the hook page always sees original
                //        bytes. Zero shadow exposure at the hook VA itself —
                //        the exact location an anti-cheat is most likely to
                //        inspect.
                //
                //   syscallRipOk (syscall-log hook, no script):
                //   Stray fetch (RIP in same 4KB page but != hook VA):
                //     -> Flip to exec NCr3 and arm pending flip-back on the
                //        next VMEXIT. These paths execute byte-identical
                //        shadow, so the only observable difference from read
                //        tree is the GPA/PFN — and even that only matters to
                //        scanners that chase page-table walks, which we are
                //        not currently defending against.
                //
                //
                // Pure Option 7:
                //   phDispatched => HV-emulate hooked instruction (no shadow exec, zero exposure)
                //   stray / syscallRipOk => single-step from shadow (1-instruction exec window)
                //
                if (phDispatched)
                {
                    PhEmulateHookedInstruction(
                        Context,
                        svm->HookMeta.Hooks[hkIdx].Gpa4K,
                        Context->Cpu->GuestVmcb.StateSaveArea.Rip);
                    return;
                }

                if (g_NpfExecFlipCount < 0xFF) g_NpfExecFlipCount++;
                WriteCmosByte(0x6A, g_NpfExecFlipCount);
                if (!syscallRipOk && g_PhStrayCount < 0xFFFFFFFFUL)
                    g_PhStrayCount++;

                PhArmExecFlipWithSingleStep(Context);
                return;
            }
        }
        // Instruction-fetch NPF on a page we don't have a hook for: fall through
        // to the bad-NPF handler below.
    }

    // HV-guard page write: guest (guest scanner/kernel) is writing to a physical page that
    // belongs to the hypervisor (host stacks, VMCBs, paging structures).
    // Silently drop by decoding the write and advancing RIP past it — the write
    // is discarded and the guest never knows it failed.
    if (g_HvGuardBase != 0 &&
        gpa >= g_HvGuardBase &&
        gpa < g_HvGuardBase + g_HvGuardSize)
    {
        if (DecodeMmioWriteInstruction(Context, &value, &size, &insnLen))
        {
            g_HvGuardDropCount++;
            WriteCmosByte(0x6B, g_HvGuardDropCount);
            Context->Cpu->GuestVmcb.StateSaveArea.Rip += insnLen;
            return;
        }
        // Decode failed: advance by a conservative estimate (7 bytes covers the
        // common 64-bit store with REX+opcode+ModRM+SIB+disp8) to avoid both
        // infinite NPF loops and BSOD from injecting an exception at CPL=0.
        // The write is silently dropped (shadow data unchanged). Log to CMOS.
        {
            UINT64 faultGpa2 = gpa;
            WriteCmosByte(0x59, (UINT8)(faultGpa2 & 0xFF));
            WriteCmosByte(0x5A, (UINT8)((faultGpa2 >> 8)  & 0xFF));
            WriteCmosByte(0x5B, (UINT8)((faultGpa2 >> 16) & 0xFF));
            WriteCmosByte(0x5C, (UINT8)((faultGpa2 >> 24) & 0xFF));
            WriteCmosByte(0x5D, (UINT8)((faultGpa2 >> 32) & 0xFF));
            WriteCmosByte(0x5E, (UINT8)((faultGpa2 >> 40) & 0xFF));
            WriteCmosByte(0x5F, 0);
            WriteCmosByte(0x58, 0xBC);  // 0xBC = HV-guard write, decode failed
        }
        Context->Cpu->GuestVmcb.StateSaveArea.Rip += 7;
        return;
    }

    // NPF outside LAPIC and outside HV-guard. Log the faulting GPA to CMOS
    // 0x49-0x4F so ReadScratch can show it, then inject #GP(0).
    {
        UINT64 faultGpa = Context->Cpu->GuestVmcb.ControlArea.ExitInfo2;
        UINT64 faultInfo1 = Context->Cpu->GuestVmcb.ControlArea.ExitInfo1;

        // guest scanner NPT corruption repair: guest scanner locates our shadow NCr3 from the VMCB
        // while the guest is running and uses a physical-write primitive to corrupt
        // a shadow PDPT entry.  It may set NX=1 (P stays 1, causing a protection
        // NPF: P=1+ID=1) or fully zero the entry (P=0, causing a not-present NPF:
        // P=0+ID=1).  Both appear as instruction-fetch NPFs under read NCr3.
        // Detect: ID=1 (instruction fetch) under read NCr3 (nptMode=0), any P value.
        // Repair the corrupted level(s) and let the guest retry the instruction.
        //
        // GATE: skip this repair if any legitimate hook lives in the same 1GB —
        // the "corrupted" entry is likely our own split-page PD pointer, and
        // restoring a 1GB identity leaf here would disarm the hook.
        if ((faultInfo1 & 0x10ULL) != 0 &&                // ID=1: instruction fetch NPF
            Context->Cpu->States.Guest.NptMode == 0 &&     // read NCr3 active
            !IsAnyHookIn1Gb(&Context->Root->Svm, faultGpa))
        {
            UINT32 rPml4Idx = (UINT32)((faultGpa >> 39) & 0x1FF);
            UINT32 rPdptIdx = (UINT32)((faultGpa >> 30) & 0x1FF);

            // guest scanner corrupts shadow (or real) PDPT entries via physical-write: it
            // sets NX=1 or clears P to block the guest's instruction fetches.
            // Repair is unconditional — don't read-then-check-then-write.
            // The previous check-first approach had a TOCTOU race on SMP: CPU A
            // fixes the entry, CPU B reads it as valid (already fixed), sees
            // repaired=FALSE, and falls through to the #GP injection that BSODs.
            // Writing the correct value is idempotent so the race is harmless.
            //
            // pml4Flags must NOT be copied from the real PML4[0] — that entry
            // can be zero (guest scanner also corrupts the real NCr3) and copying it would
            // write P=0 into the shadow PML4, immediately re-breaking the walk.
            // Hardcode P+W+U (0x07) which is always correct for a PML4→PDPT ptr.
            BOOLEAN hasShadow = (g_ShadowNcr3Pa != 0 && g_ShadowNcr3Pa != g_ReadNcr3Pa);

            if (hasShadow && rPml4Idx == 0 && g_ShadowPdpt0 != NULL)
            {
                UINT64* sPml4 = (UINT64*)(UINTN)g_ShadowNcr3Pa;
                sPml4[0] = ((UINT64)(UINTN)g_ShadowPdpt0 & ~0xFFFULL) | 0x07ULL;
                g_ShadowPdpt0[rPdptIdx] = ((UINT64)rPdptIdx << 30) | 0x87ULL;
            }
            else
            {
                UINT64 pdptPa = (UINT64)(UINTN)&Context->Root->Svm.NestedPageTables.Pdpt[rPml4Idx][0];
                Context->Root->Svm.NestedPageTables.Pml4[rPml4Idx].Uint64 = pdptPa | 0x07ULL;
                UINT64 pa = ((UINT64)rPml4Idx << 39) | ((UINT64)rPdptIdx << 30);
                Context->Root->Svm.NestedPageTables.Pdpt[rPml4Idx][rPdptIdx].Uint64 = pa | 0x87ULL;
            }
            // Flush the NPT TLB so the next VMRUN walks fresh entries, not
            // the stale (NX=1) entry that was cached before the repair.
            Context->Cpu->GuestVmcb.ControlArea.TlbControl = 1;
            return;  // NPT restored; hardware retries the faulting instruction.
        }

        // Exec NCr3 lazy sync: NptExec is initialized before Windows boot and
        // lacks regions lazily added to NestedPageTables during OS runtime.
        // When the stub runs in exec NCr3 and accesses game memory (camobj write,
        // stack, caller code pages) not in NptExec, P=0 NPFs land here.
        // Fix: copy the matching 1GB PDPT leaf from NestedPageTables into NptExec.
        // Skip split entries (Valid=1, PS=0 = non-leaf PD pointer) — they own the
        // shadow page and must not be overwritten with an identity leaf.
        if (Context->Cpu->States.Guest.NptMode == 1 &&
            (faultInfo1 & 0x1ULL) == 0 &&               // P=0: not present in exec NCr3
            g_ExecNcr3Pa != 0)
        {
            SHARED_SVM_DATA* lazyExecSvm = &Context->Root->Svm;
            UINT32 lePml4 = (UINT32)((faultGpa >> 39) & 0x1FF);
            UINT32 lePdpt = (UINT32)((faultGpa >> 30) & 0x1FF);
            UINT64 curExecPdpte = lazyExecSvm->NptExec.Pdpt[lePml4][lePdpt].Uint64;
            BOOLEAN isSplitExec = ((curExecPdpte & 0x81ULL) == 0x01ULL); // Valid=1, PS=0
            if (!isSplitExec)
            {
                UINT64 srcPdpte = lazyExecSvm->NestedPageTables.Pdpt[lePml4][lePdpt].Uint64;
                BOOLEAN srcIsNonLeaf = ((srcPdpte & 0x81ULL) == 0x01ULL);
                // SAFETY: if the read-tree PDPT entry is a non-leaf PD pointer, it
                // was installed by a process-hook NPT split into HookRead's PD.
                // Blindly copying that pointer into the exec tree would make the
                // exec tree walk through HookRead's PD — wrong for exec semantics
                // and potentially a 1GB of wrong PFNs. Instead, synthesize a fresh
                // identity 1GB leaf for the exec tree. The exec-side split is
                // installed separately by InstallNptHook into HookExec.
                if (srcIsNonLeaf)
                {
                    srcPdpte = (((UINT64)lePml4 << 39) | ((UINT64)lePdpt << 30)) | 0x87ULL;
                }
                else if (srcPdpte == 0)
                {
                    // NestedPageTables also missing: CPUs stuck in exec NCr3 never
                    // trigger the read-NCr3 lazy-fill path, so new physical regions
                    // (from a fresh game launch) never get populated there.
                    // Synthesize the identity 1GB leaf directly (same formula as the
                    // normal lazy-PDPT fill) and backfill NestedPageTables too.
                    srcPdpte = (((UINT64)lePml4 << 39) | ((UINT64)lePdpt << 30)) | 0x87ULL;
                    lazyExecSvm->NestedPageTables.Pdpt[lePml4][lePdpt].Uint64 = srcPdpte;
                }
                lazyExecSvm->NptExec.Pdpt[lePml4][lePdpt].Uint64 = srcPdpte;
                Context->Cpu->GuestVmcb.ControlArea.TlbControl = 1;
                return;
            }
        }

        WriteCmosByte(0x49, (UINT8)(faultGpa & 0xFF));
        WriteCmosByte(0x4A, (UINT8)((faultGpa >> 8)  & 0xFF));
        WriteCmosByte(0x4B, (UINT8)((faultGpa >> 16) & 0xFF));
        WriteCmosByte(0x4C, (UINT8)((faultGpa >> 24) & 0xFF));
        WriteCmosByte(0x4D, (UINT8)((faultGpa >> 32) & 0xFF));
        WriteCmosByte(0x4E, (UINT8)(faultInfo1 & 0xFF)); // RW/P/etc bits
        WriteCmosByte(0x4F, 0xBA);                       // 0xBA = "bad NPF" sentinel
        // Persistent crash log (0x58-0x5F): survives HV reload. Sentinel last.
        WriteCmosByte(0x59, (UINT8)(faultInfo1 & 0xFF));
        WriteCmosByte(0x5A, (UINT8)(faultGpa & 0xFF));
        WriteCmosByte(0x5B, (UINT8)((faultGpa >> 8)  & 0xFF));
        WriteCmosByte(0x5C, (UINT8)((faultGpa >> 16) & 0xFF));
        WriteCmosByte(0x5D, (UINT8)((faultGpa >> 24) & 0xFF));
        WriteCmosByte(0x5E, (UINT8)((faultGpa >> 32) & 0xFF));
        WriteCmosByte(0x5F, (UINT8)((faultGpa >> 40) & 0xFF));
        WriteCmosByte(0x58, 0xBA);  // 0xBA = bad-NPF outside LAPIC+HV-guard
        // 0x6D-0x6F: NPT entries for the faulting GPA.
        //   0x6D  PDPE[7:0]   — V/W/U/WT/CD/A/D/PS bits of faulting 1GB PDPT entry
        //   0x6E  PDPE[63:56] — high byte; bit7 = NX (execute-disable)
        //   0x6F  ExitInfo1[39:32] (bit1=guestPTwalk; bit2=guestNX)
        // ExtCMOS 0x97/0x98: nptMode/hookCnt. 0x99/0x9A: PML4 low/high byte.
        {
            UINT32 fPml4Idx = (UINT32)((faultGpa >> 39) & 0x1FF);
            UINT32 fPdptIdx = (UINT32)((faultGpa >> 30) & 0x1FF);
            UINT64 pdpeRaw  = Context->Root->Svm.NestedPageTables.Pdpt[fPml4Idx][fPdptIdx].Uint64;
            UINT64 pml4Raw  = Context->Root->Svm.NestedPageTables.Pml4[fPml4Idx].Uint64;
            WriteCmosByte(0x6D, (UINT8)pdpeRaw);
            WriteCmosByte(0x6E, (UINT8)(pdpeRaw >> 56));
            WriteCmosByte(0x6F, (UINT8)((faultInfo1 >> 32) & 0xFF));
            WriteExtCmosByte(0x97, (UINT8)Context->Cpu->States.Guest.NptMode);
            WriteExtCmosByte(0x98, (UINT8)Context->Root->Svm.HookMeta.HookCount);
            WriteExtCmosByte(0x99, (UINT8)pml4Raw);
            WriteExtCmosByte(0x9A, (UINT8)(pml4Raw >> 56));
            // Guest RIP at time of bad NPF — low 16 bits. Lets ReadScratch confirm
            // whether this fires while the guest is inside MmGetVirtualForPhysical.
            UINT64 badNpfRip = Context->Cpu->GuestVmcb.StateSaveArea.Rip;
            WriteExtCmosByte(0x9B, (UINT8)(badNpfRip & 0xFF));
            WriteExtCmosByte(0x9C, (UINT8)((badNpfRip >> 8) & 0xFF));
            WriteExtCmosByte(0x9D, (UINT8)((badNpfRip >> 16) & 0xFF));
            WriteExtCmosByte(0x9E, (UINT8)((badNpfRip >> 24) & 0xFF));
        }
        // Lazy NPT recovery: never inject #GP for an unhandled NPF.
        // Injecting #GP at an arbitrary kernel RIP causes KMODE_EXCEPTION_NOT_HANDLED.
        // If P=0: the GPA has no NPT entry at all — add a 1:1 1GB identity map and retry.
        // If P=1: the entry exists but has wrong permissions — fix them in-place and retry.
        // CMOS 0xB0=0xAA → lazy-map added; 0xB0=0xBB → permission-fixed.
        //
        // GATE: if any hook lives in the same 1GB, skip the destructive
        // PDPT-rewrite paths. We'd rather NPF-loop (safe, slow) than clobber a
        // hook's split PD pointer with a 1GB identity leaf or clear its NX.
        {
            UINT32 lazyPml4 = (UINT32)((faultGpa >> 39) & 0x1FF);
            UINT32 lazyPdpt = (UINT32)((faultGpa >> 30) & 0x1FF);
            UINT64 gpaBase1G = ((UINT64)lazyPml4 << 39) | ((UINT64)lazyPdpt << 30);
            BOOLEAN hookIn1Gb = IsAnyHookIn1Gb(&Context->Root->Svm, faultGpa);

            if (hookIn1Gb)
            {
                WriteExtCmosByte(0xB0, 0xCC);  // 0xCC = skipped lazy recovery due to hook
                WriteExtCmosByte(0xB1, (UINT8)lazyPdpt);
                Context->Cpu->GuestVmcb.ControlArea.TlbControl = 1;
                return;
            }

            if ((faultInfo1 & 0x01ULL) == 0)
            {
                // P=0: add a lazy 1:1 1GB identity-map entry.
                if ((Context->Root->Svm.NestedPageTables.Pml4[lazyPml4].Uint64 & 1) == 0)
                {
                    UINT64 pdptPaL = (UINT64)(UINTN)&Context->Root->Svm.NestedPageTables.Pdpt[lazyPml4][0];
                    Context->Root->Svm.NestedPageTables.Pml4[lazyPml4].Uint64 = pdptPaL | 0x07ULL;
                }
                Context->Root->Svm.NestedPageTables.Pdpt[lazyPml4][lazyPdpt].Uint64 = gpaBase1G | 0x87ULL;
                // Mirror into shadow pages when this is PML4[0].
                if (g_ShadowNcr3Pa != 0 && g_ShadowNcr3Pa != g_ReadNcr3Pa &&
                    lazyPml4 == 0 && g_ShadowPdpt0 != NULL)
                {
                    UINT64* sPml4L = (UINT64*)(UINTN)g_ShadowNcr3Pa;
                    sPml4L[0] = ((UINT64)(UINTN)g_ShadowPdpt0 & ~0xFFFULL) | 0x07ULL;
                    g_ShadowPdpt0[lazyPdpt] = gpaBase1G | 0x87ULL;
                }
                WriteExtCmosByte(0xB0, 0xAA);
                WriteExtCmosByte(0xB1, (UINT8)lazyPdpt);
            }
            else
            {
                // P=1: entry present but wrong permissions. Clear NX, set W=1.
                UINT64 cur = Context->Root->Svm.NestedPageTables.Pdpt[lazyPml4][lazyPdpt].Uint64;
                cur |=  0x02ULL;
                cur &= ~(1ULL << 63);
                Context->Root->Svm.NestedPageTables.Pdpt[lazyPml4][lazyPdpt].Uint64 = cur;
                // Mirror into shadow pages too.
                if (g_ShadowNcr3Pa != 0 && g_ShadowNcr3Pa != g_ReadNcr3Pa &&
                    lazyPml4 == 0 && g_ShadowPdpt0 != NULL)
                {
                    UINT64 sCur = g_ShadowPdpt0[lazyPdpt];
                    sCur |=  0x02ULL;
                    sCur &= ~(1ULL << 63);
                    g_ShadowPdpt0[lazyPdpt] = sCur;
                }
                WriteExtCmosByte(0xB0, 0xBB);
                WriteExtCmosByte(0xB1, (UINT8)lazyPdpt);
            }
            // Flush the NPT TLB — same requirement as the repair path above.
            Context->Cpu->GuestVmcb.ControlArea.TlbControl = 1;
            // Always return and let the hardware retry. Never inject #GP here.
        }
    }
}

/**
 * @brief Handles #VMEXIT.
 */
VOID
HandleVmExit (
    IN OUT HOST_VMEXIT_STACK* HostStack
    )
{
    HOST_CONTEXT context;

    // On the BSP's very first VMEXIT each boot, zero our CMOS scratch area
    // (0x40-0x7F) so ReadScratch only shows data from this run — not stale
    // values from previous boots. Persistent exceptions (survive power-off):
    //   0x58-0x5F  general crash log (sentinel + GPA + info1)
    //   0x6D-0x6F  bad-NPF mode diagnostics (NptMode / HookCount / info1_hi)
    STATIC volatile UINT8 g_CmosCleared = 0;
    if (!g_CmosCleared && HostStack->Params.ProcessorNumber == 0)
    {
        for (UINT8 cmosIdx = 0x40; cmosIdx <= 0x7F; cmosIdx++)
        {
            if ((cmosIdx >= 0x58 && cmosIdx <= 0x5F) ||
                (cmosIdx >= 0x6D && cmosIdx <= 0x6F))
            {
                continue;
            }
            WriteCmosByte(cmosIdx, 0);
        }
        g_CmosCleared = 1;
    }

    MarkProgress(0x01);

    //
    // Detect if stack has an unexpected value. This is a typical programming error.
    //
    HOST_ASSERT(HostStack->Params.Reserved1 == MAX_UINT32);

    //
    // Capture relevant information to handle #VMEXIT into the single structure.
    //
    context.Root = HostStack->Params.SharedContext;
    context.Cpu = &context.Root->Cpus[HostStack->Params.ProcessorNumber];
    context.Cpu->States.Guest.Registers = &HostStack->GuestRegisters;

    //
    // Reflect the guest RAX from VMCB to the register pointer. The following
    // VMLOAD is actually redundant and meaningless because this project does
    // not use registers updated by this instruction.
    //
    HostStack->GuestRegisters.Rax = context.Cpu->GuestVmcb.StateSaveArea.Rax;
    __svm_vmload((UINTN)&context.Cpu->HostVmcb);

    //
    // VmcbClean = 0 = "everything dirty, hardware must reload all VMCB
    // fields". Trying this as the agent's recommended diagnostic — if any
    // fixup we do (TR busy, LDTR null, MSR handler updating Efer) hits a
    // clean-bit-cached field we forgot to invalidate, hardware would use the
    // cached old value and the guest sees stale state. Forcing full reload
    // eliminates that whole class of bug. Cost: a few hundred extra cycles
    // per VMRUN, negligible.
    //
    context.Cpu->GuestVmcb.ControlArea.TlbControl = 0;
    context.Cpu->GuestVmcb.ControlArea.VmcbClean = 0;
    //
    // AMD hardware does NOT clear EventInj.VALID after successfully delivering
    // an injected event. If we leave it set, the next VMRUN re-injects the
    // same event spuriously — a #GP landing at an arbitrary guest RIP, which
    // is exactly the MmGetVirtualForPhysical+0x18 BSOD we see when guest scanner forces
    // a VM_HSAVE_PA or x2APIC RDMSR and we inject #GP(0).
    // Clear it unconditionally here; every handler that needs an injection
    // writes EventInj fresh before returning.
    //
    context.Cpu->GuestVmcb.ControlArea.EventInj = 0;

    //
    // Physical-memory decoy: guest is now suspended; overwrite VMCB.NCr3 and
    // VMCB.MsrpmBasePa with the zero decoy page. A scanner reading VMCB right
    // now sees an empty NPT root and no MSR intercepts — no hypervisor
    // signature. We restore the real values at the bottom of this function,
    // before control returns to the assembly VMRUN stub.
    //
    if (g_DecoyPagePa != 0)
    {
        // NCr3/MSRPM: point to zero page — scanner sees empty NPT and no intercepts.
        context.Cpu->GuestVmcb.ControlArea.NCr3        = g_DecoyPagePa;
        context.Cpu->GuestVmcb.ControlArea.MsrpmBasePa = g_DecoyPagePa;
        // Intercept bitmaps / ASID / NpEnable: zero them out. Scanner sees a
        // VMCB with no intercepts, ASID=0, and nested paging off — no hypervisor
        // signature. All restored to real values at the bottom of this function.
        context.Cpu->GuestVmcb.ControlArea.InterceptMisc1         = 0;
        context.Cpu->GuestVmcb.ControlArea.InterceptMisc2         = 0;
        context.Cpu->GuestVmcb.ControlArea.InterceptException      = 0;
        context.Cpu->GuestVmcb.ControlArea.GuestAsid              = 0;
        context.Cpu->GuestVmcb.ControlArea.NpEnable               = 0;
        context.Cpu->GuestVmcb.ControlArea.LbrVirtualizationEnable = 0;
    }

    //
    // One-time: once all APs have come up, drop the LAPIC-page write-protection
    // (it was only there to catch SIPI during bringup). This ends the LAPIC NPF
    // storm — EOI/IPI writes now go straight to the real LAPIC. Late SIPIs to an
    // already-running CPU are architecturally ignored, so this is safe post-boot.
    //
    if (g_LapicUnprotected == 0 &&
        g_LapicBasePa != 0 &&
        g_ApResumedCount >= (context.Root->HostX64.ProcessorCount - 1))
    {
        UINT32 ptIdx = (UINT32)((g_LapicBasePa >> 12) & 0x1FF);
        UINT32 n     = context.Root->HostX64.ProcessorCount;
        context.Root->Svm.LapicRegion.Pt[ptIdx].Bits.Write = 1;   // un-protect
        // Flag every CPU to flush its NPT TLB once (TSO: this store is ordered
        // after the PT write above, so a CPU that sees the flag also sees the
        // now-writable entry when it re-walks).
        for (UINT32 i = 0; i < n; ++i)
        {
            context.Root->Cpus[i].States.Guest.LapicFlushPending = 1;
        }
        // Drop WRMSR 0x830 intercept now that all APs are running. The intercept
        // was only needed for SIPI delivery during bringup. After this point any
        // ICR writes (including guest scanner anti-VM probes) go straight to hardware:
        // invalid modes #GP the guest exactly as bare metal would; valid IPIs are
        // delivered normally. No more VMEXIT_MSR exits = no more crash vector.
        context.Root->Svm.Msrpm[0x20C] &= ~0x02u;
        g_LapicUnprotected = 1;
    }
    //
    // Per-CPU one-shot NPT TLB flush after un-protect.
    //
    if (context.Cpu->States.Guest.LapicFlushPending != 0)
    {
        context.Cpu->GuestVmcb.ControlArea.TlbControl = 1;
        context.Cpu->States.Guest.LapicFlushPending = 0;
    }
    //
    // Deferred NCr3 update: another CPU installed an NPT hook and flagged us
    // to switch to ReadNCr3. We do it here in our own host context rather than
    // letting the installer write our VMCB directly (which is unsafe while we
    // are mid-VMRUN or mid-shim). TlbControl=1 flushes our guest TLB so the
    // new NCr3's NX bits take effect immediately on the next VMRUN.
    //
    if (context.Cpu->States.Guest.NCr3UpdatePending != 0)
    {
        context.Cpu->GuestVmcb.ControlArea.NCr3      = context.Cpu->States.Guest.NCr3PendingValue;
        context.Cpu->GuestVmcb.ControlArea.TlbControl = 1;
        context.Cpu->GuestVmcb.ControlArea.VmcbClean  = 0;
        context.Cpu->States.Guest.NptMode             = 0;
        context.Cpu->States.Guest.NCr3UpdatePending   = 0;
    }

    //
    // Option-7 flip-back safety net. If we're exiting due to anything OTHER
    // than the #DB we armed, the single-stepped instruction raised something
    // first (page fault, intercepted MSR access, interrupt, etc.) and the
    // #DB will never fire. We MUST flip this CPU back to read NCr3 anyway,
    // otherwise the next guest code runs on exec NCr3 with TF still set,
    // which cascades into a different #DB landing in HandleDebugException
    // and leaks shadow-page exposure to arbitrary code.
    //
    // ExitCode==VMEXIT_EXCEPTION_DB is already handled fully by
    // HandleDebugException (which clears ExpectDbForFlipBack itself).
    //
    if (context.Cpu->States.Guest.ExpectDbForFlipBack != 0 &&
        context.Cpu->GuestVmcb.ControlArea.ExitCode != VMEXIT_EXCEPTION_DB)
    {
        UINT64 readNcr3_ = (g_ShadowNcr3Pa != 0) ? g_ShadowNcr3Pa : g_ReadNcr3Pa;
        UINT64 rflags_   = context.Cpu->GuestVmcb.StateSaveArea.Rflags;

        context.Cpu->GuestVmcb.ControlArea.NCr3       = readNcr3_;
        context.Cpu->GuestVmcb.ControlArea.TlbControl = 1;
        context.Cpu->GuestVmcb.ControlArea.VmcbClean  = 0;
        context.Cpu->States.Guest.NptMode             = 0;

        // ALWAYS clear TF, ALWAYS restore guest IF. Same invariants as
        // HandleDebugException (see comments there).
        rflags_ &= ~(1ULL << 8);
        if (context.Cpu->States.Guest.GuestSavedRflagsIf)
            rflags_ |=  (1ULL << 9);
        else
            rflags_ &= ~(1ULL << 9);
        context.Cpu->GuestVmcb.StateSaveArea.Rflags = rflags_;

        context.Cpu->States.Guest.ExpectDbForFlipBack = 0;
        context.Cpu->States.Guest.GuestSavedRflagsTf  = 0;
        context.Cpu->States.Guest.GuestSavedRflagsIf  = 0;
    }

    //
    // Always-updated diagnostic trackers (CMOS 0x56-0x5F). MarkProgress is
    // one-shot; this gives us the LAST exit before crash and a VMEXIT count
    // so we can tell "stuck in a loop" from "stopped exiting altogether".
    //
    TrackVmExit(context.Cpu->GuestVmcb.ControlArea.ExitCode,
                context.Cpu->GuestVmcb.StateSaveArea.Rip);

    //
    // Capture the kernel CR3 once: first exit after the NT kernel has set LSTAR
    // (indicating it is running, not early firmware).
    //
    // AMD CPUs are not Meltdown-vulnerable, so Windows does NOT enable KPTI on
    // AMD.  Every process has a single CR3 that maps both user and kernel VA
    // space — the same value Windows calls DirectoryTableBase.  We do NOT need
    // to wait for a CPL=0 exit; a ring-3 UD2 from trigger.exe carries the same
    // full-mapping CR3 we need to walk EPROCESS and kernel structures.
    //
    if (g_KernelCr3 == 0 &&
        context.Cpu->GuestVmcb.StateSaveArea.LStar != 0)
    {
        g_KernelCr3   = context.Cpu->GuestVmcb.StateSaveArea.Cr3 & ~0xFFFULL;
        g_KernelLstar = context.Cpu->GuestVmcb.StateSaveArea.LStar;
    }
    // CSTAR is the compat-mode syscall target (KiSystemCall32 on Windows).
    // Captured separately — may be populated at a different time than LSTAR.
    if (g_KernelCstar == 0 &&
        context.Cpu->GuestVmcb.StateSaveArea.CStar != 0)
    {
        g_KernelCstar = context.Cpu->GuestVmcb.StateSaveArea.CStar;
    }

    //
    // Handle #VMEXIT.
    //
    switch (context.Cpu->GuestVmcb.ControlArea.ExitCode)
    {
    case VMEXIT_CPUID:
        HandleCpuid(&context);
        break;

    case VMEXIT_EXCEPTION_UD:
        HandleUdHypercall(&context);
        break;

    case VMEXIT_EXCEPTION_DB:
        HandleDebugException(&context);
        break;

    case VMEXIT_EXCEPTION_SX:
        //
        // AP received INIT (redirected to #SX via VM_CR.R_INIT). Reset to
        // architectural INIT state, park in WAIT_FOR_SIPI, spin until BSP's
        // SIPI emulation wakes us. INIT doesn't advance RIP architecturally;
        // RIP after VMRUN is whatever HandleInitSignal wrote (reset vector
        // OR, once SIPI lands, vector<<12 from EmulateSipiDelivery).
        //
        HandleInitSignal(&context);
        break;

    case VMEXIT_MSR:
        HandleMsr(&context);
        break;

    case VMEXIT_NPF:
        HandleNestedPageFault(&context);
        break;

    case VMEXIT_VMMCALL:
        // VMMCALL with SVME=0 is architecturally #UD at any CPL.
        // At CPL>0 the #UD propagates through Windows user-mode SEH — safe.
        // At CPL=0 (kernel driver) there may be no .pdata handler → BSOD 0x1E.
        // Emulate as a no-op for CPL=0: NRip is valid for instruction VMEXITs.
        if (context.Cpu->GuestVmcb.StateSaveArea.Cpl != 0)
        {
            context.Cpu->GuestVmcb.ControlArea.EventInj =
                (1ULL << 31) | (3ULL << 8) | 6ULL;  // #UD — ring-3, SEH handles it
        }
        else
        {
            context.Cpu->GuestVmcb.StateSaveArea.Rip =
                context.Cpu->GuestVmcb.ControlArea.NRip;  // no-op, advance past insn
        }
        break;

    case VMEXIT_VMRUN:
    case VMEXIT_VMLOAD:
    case VMEXIT_VMSAVE:
    case VMEXIT_STGI:
    case VMEXIT_CLGI:
    case VMEXIT_SKINIT:
    case VMEXIT_INVLPGA:
        // CPL>0: #GP(0) — correct bare-metal behaviour, caught by ring-3 SEH.
        // CPL=0: injecting #UD here causes KMODE_EXCEPTION_NOT_HANDLED if the
        // kernel driver (guest scanner) has no .pdata handler at that RIP.  Emulate as
        // no-op instead: NRip is always valid for instruction VMEXITs.
        if (context.Cpu->GuestVmcb.StateSaveArea.Cpl != 0)
        {
            context.Cpu->GuestVmcb.ControlArea.EventInj =
                (1ULL << 31) | (1ULL << 11) | (3ULL << 8) | 13ULL;  // #GP(0)
        }
        else
        {
            context.Cpu->GuestVmcb.StateSaveArea.Rip =
                context.Cpu->GuestVmcb.ControlArea.NRip;  // no-op, advance past insn
        }
        break;

    // #SX (VMEXIT_EXCEPTION_SX) case removed — we no longer redirect INIT
    // via VM_CR.R_INIT, so #SX shouldn't fire. If it does (e.g., LOCK was
    // set by firmware and we couldn't clear R_INIT), it'll hit the default
    // branch and we'll see exit code 0x5E in CMOS.

    case VMEXIT_INVD:
        // Absorb INVD as a no-op: advance RIP and return. INVD would discard
        // all dirty cache lines without writeback — including dirty HV data —
        // which could silently corrupt in-flight host writes. Windows never
        // issues INVD in normal operation; emulating it as a no-op is safe.
        context.Cpu->GuestVmcb.StateSaveArea.Rip = context.Cpu->GuestVmcb.ControlArea.NRip;
        break;

    case VMEXIT_SHUTDOWN:
        // Guest triple-faulted — unrecoverable, reset now.
        MarkProgress(0x08);
        RecordUnhandledExit(context.Cpu->GuestVmcb.ControlArea.ExitCode);
        RecordExitRing(context.Cpu->GuestVmcb.ControlArea.ExitCode);
        CpuReset();
        break;

    default:
        MarkProgress(0x08);
        RecordUnhandledExit(context.Cpu->GuestVmcb.ControlArea.ExitCode);
        RecordExitRing(context.Cpu->GuestVmcb.ControlArea.ExitCode);
        if (context.Cpu->GuestVmcb.ControlArea.ExitCode == VMEXIT_INVALID)
        {
            // VMRUN consistency check failed — VMCB is corrupt, can't continue.
            CpuReset();
        }
        else
        {
            // Unknown exit: inject #UD so the guest sees a clean fault instead
            // of a hard reset. The HV stays alive; run ReadScratch after the
            // game crashes to see which exit code was in the ring buffer.
            context.Cpu->GuestVmcb.ControlArea.EventInj =
                (1ULL << 31) |  // valid
                (3ULL << 8)  |  // type = exception
                6ULL;           // #UD
        }
    }

    //
    // Reflect back RAX to the VMCB in case the handler updated it.
    //
    context.Cpu->GuestVmcb.StateSaveArea.Rax = HostStack->GuestRegisters.Rax;

    //
    // Force EFER.SVME=1 in the guest VMCB. We don't intercept MSR writes
    // anymore (matching barevisor), so if Windows writes EFER explicitly
    // (e.g., to set NXE/LME) and the value happens to not have SVME set, the
    // next VMRUN consistency check would fail (VMEXIT_INVALID) and triple-
    // fault. Forcing the bit here is a safety net. Windows may observe a
    // slight EFER inconsistency on RDMSR, but practical experience says it
    // doesn't bugcheck on this.
    //
    context.Cpu->GuestVmcb.StateSaveArea.Efer |= EFER_SVME;

    //
    // Restore the real NCr3 and MSRPM before VMRUN. NCr3 picks the active
    // NPT (read vs exec depending on NptMode). Both fields were zeroed to
    // the decoy page at entry above.
    //
    if (g_DecoyPagePa != 0)
    {
        UINT64 activeReadNcr3 = (g_ShadowNcr3Pa != 0) ? g_ShadowNcr3Pa : g_ReadNcr3Pa;
        UINT64 realNcr3 = (context.Cpu->States.Guest.NptMode == 0)
                          ? activeReadNcr3 : g_ExecNcr3Pa;
        context.Cpu->GuestVmcb.ControlArea.NCr3        = realNcr3;
        context.Cpu->GuestVmcb.ControlArea.MsrpmBasePa = g_MsrpmPa;
        context.Cpu->GuestVmcb.ControlArea.InterceptMisc1         = g_VmcbSavedMisc1;
        context.Cpu->GuestVmcb.ControlArea.InterceptMisc2         = g_VmcbSavedMisc2;
        context.Cpu->GuestVmcb.ControlArea.InterceptException      = g_VmcbSavedException;
        context.Cpu->GuestVmcb.ControlArea.GuestAsid              = g_VmcbSavedGuestAsid;
        context.Cpu->GuestVmcb.ControlArea.NpEnable               = g_VmcbSavedNpEnable;
        context.Cpu->GuestVmcb.ControlArea.LbrVirtualizationEnable = g_VmcbSavedLbrVirt;
    }

    //
    // Persistent injection log — written to ExtCMOS (0x80+) which is NOT
    // touched by the new-boot clearing loop, so it survives a forced reboot.
    // After crash -> reboot -> ReadScratch, this shows the LAST event we
    // injected before the BSOD: which VMEXIT exit code caused it, what vector
    // we injected, and the guest RIP at that point.
    //
    //   ExtCMOS 0xA0 : exit code [7:0]  (0x7C=MSR, 0x00+0xA7=0x04 → NPF 0x400)
    //   ExtCMOS 0xA1 : event vector      (13=GP, 6=UD, 14=PF …)
    //   ExtCMOS 0xA2 : guest RIP [7:0]
    //   ExtCMOS 0xA3 : guest RIP [15:8]
    //   ExtCMOS 0xA4 : guest RIP [23:16]
    //   ExtCMOS 0xA5 : guest RIP [31:24]
    //   ExtCMOS 0xA6 : rolling injection counter (wraps at 255)
    //   ExtCMOS 0xA7 : exit code [15:8]
    //
    {
        UINT64 ei = context.Cpu->GuestVmcb.ControlArea.EventInj;
        if (ei & (1ULL << 31))
        {
            UINT64 injRip  = context.Cpu->GuestVmcb.StateSaveArea.Rip;
            UINT64 exitCode = context.Cpu->GuestVmcb.ControlArea.ExitCode;
            STATIC volatile UINT8 s_InjCount = 0;
            ++s_InjCount;
            WriteExtCmosByte(0xA0, (UINT8)(exitCode & 0xFF));
            WriteExtCmosByte(0xA1, (UINT8)(ei & 0xFF));
            WriteExtCmosByte(0xA2, (UINT8)(injRip));
            WriteExtCmosByte(0xA3, (UINT8)(injRip >> 8));
            WriteExtCmosByte(0xA4, (UINT8)(injRip >> 16));
            WriteExtCmosByte(0xA5, (UINT8)(injRip >> 24));
            WriteExtCmosByte(0xA6, s_InjCount);
            WriteExtCmosByte(0xA7, (UINT8)((exitCode >> 8) & 0xFF));
        }
    }

}

/**
 * @brief Handles exception occurred during execution of the host by simply
 *      halting the execution of the processor.
 */
VOID
HandleHostException (
    IN CONST HOST_EXCEPTION_STACK* Stack
    )
{
    MarkProgress(0x10);
    RecordExceptionVector((UINT32)Stack->InterruptNumber);

    //
    // Post-mortem dump to CMOS 0x49-0x4F.
    //
    // 0x49-0x4C: signed delta from HandleHostException to the faulting RIP,
    //   stored little-endian as INT32. Both addresses are in the same PE image,
    //   so imageBase cancels: delta = fault_RVA - HandleHostException_RVA.
    //   ReadScratch computes section_offset = delta + 0x3FC0 (HandleHostException
    //   section offset) which maps directly to ao.map.
    //   (NOTE: 0x49-0x4C are NOT written by HandleInitSignal, so they survive
    //    concurrent AP HandleInitSignal calls cleanly.)
    //
    // 0x4D: rcxLo (RCX at fault, e.g. MSR number for WRMSR).
    //   RACE WARNING: HandleInitSignal writes CMOS 0x4C+pn for pn=1,2,3;
    //   AP1 writes 0x4D, so rcxLo may be overwritten by AP1's APIC ID.
    //
    // 0x4E: g_LastRiskyOp (which guarded op was mid-flight).
    //   RACE WARNING: AP2 writes 0x4E; may overwrite op breadcrumb.
    //
    // 0x72-0x73: backup copies of rcxLo/op in slots HandleInitSignal never
    //   touches (normally ICR_LO bytes 2-3, irrelevant after a crash).
    //
    // 0x4F: 0xEE sentinel (last write; AP3 writes 0x4F so tiny race exists,
    //   but AP3's APIC ID != 0xEE so mismatch is detectable).
    //
    {
        INT64  signedDelta = (INT64)Stack->Rip -
                             (INT64)(UINT64)(UINTN)HandleHostException;
        UINT32 rawDelta    = (UINT32)(INT32)signedDelta;

        // Persistent crash log (0x58-0x5F): not cleared by HV reload.
        // Sentinel (0x58) written last so ReadScratch sees a consistent snapshot.
        WriteCmosByte(0x59, (UINT8)g_LastExceptionVector);
        WriteCmosByte(0x5A, (UINT8)(rawDelta & 0xFF));
        WriteCmosByte(0x5B, (UINT8)((rawDelta >> 8)  & 0xFF));
        WriteCmosByte(0x5C, (UINT8)((rawDelta >> 16) & 0xFF));
        WriteCmosByte(0x5D, (UINT8)((rawDelta >> 24) & 0xFF));
        WriteCmosByte(0x5E, g_LastRiskyOp);
        WriteCmosByte(0x5F, (UINT8)(Stack->GuestRegisters.Rcx & 0xFF));
        WriteCmosByte(0x58, 0xDE);  // 0xDE = host-exception persistent sentinel

        WriteCmosByte(0x49, (UINT8)(rawDelta & 0xFF));
        WriteCmosByte(0x4A, (UINT8)((rawDelta >> 8)  & 0xFF));
        WriteCmosByte(0x4B, (UINT8)((rawDelta >> 16) & 0xFF));
        WriteCmosByte(0x4C, (UINT8)((rawDelta >> 24) & 0xFF));

        //
        // Capture the faulting opcode bytes -> 0x74-0x77. This is the decisive
        // datum for a #UD: it tells us the exact instruction that faulted
        //   0F 01 DA = VMLOAD   0F 01 D8 = VMRUN   0F 01 DB = VMSAVE
        //   0F 01 DC = STGI     0F 01 DD = CLGI    0F 0B    = UD2
        //   anything else       = wild jump / corrupted control flow.
        // 0x70 is a status marker:
        //   0xC0 = opcode bytes valid (RIP was within +/-256KB of our image)
        //   0xC1 = RIP too far from image to deref safely (wild jump confirmed)
        // We ONLY dereference when |delta| < 0x40000 so a non-canonical/unmapped
        // wild RIP can't trigger a nested #PF and loop the exception handler.
        //
        if (signedDelta > -0x40000 && signedDelta < 0x40000)
        {
            CONST UINT8* code = (CONST UINT8*)(UINTN)Stack->Rip;
            WriteCmosByte(0x70, 0xC0);
            WriteCmosByte(0x74, code[0]);
            WriteCmosByte(0x75, code[1]);
            WriteCmosByte(0x76, code[2]);
            WriteCmosByte(0x77, code[3]);
        }
        else
        {
            WriteCmosByte(0x70, 0xC1);   // wild RIP — not dereferenced
        }
    }
    WriteCmosByte(0x4D, (UINT8)(Stack->GuestRegisters.Rcx & 0xFF));
    WriteCmosByte(0x4E, g_LastRiskyOp);
    WriteCmosByte(0x72, (UINT8)(Stack->GuestRegisters.Rcx & 0xFF));  // backup rcxLo
    WriteCmosByte(0x73, g_LastRiskyOp);                               // backup op
    WriteCmosByte(0x4F, 0xEE);

    CpuReset();
}
