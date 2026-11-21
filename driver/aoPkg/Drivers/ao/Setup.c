/**
 * @file Setup.c
 *
 * @brief Implements the entry point of the module and logic to start the hypervisor.
 *
 * @author Satoshi Tanda
 *
 * @copyright Copyright (c) 2020, Satoshi Tanda. All rights reserved.
 */
#include "ao.h"

/**
 * @brief The array of the default host exception handlers.
 */
VOID
AsmDefaultExceptionHandlers (
    VOID
    );

/**
 * @brief Returns the return address from this function.
 */
UINTN
AsmReadInstructionPointer (
    VOID
    );

/**
 * @brief Returns the current value of RSP.
 */
UINTN
AsmReadStackPointer (
    VOID
    );

/**
 * @brief Enters the loop that executes the guest and handles #VMEXIT.
 */
VOID
AsmLaunchVm (
    IN VOID* HostRsp
    );

//
// The segment attributes required for VMCB.
//
typedef union _SEGMENT_ATTRIBUTE
{
    struct
    {
        UINT16 Type : 4;        // [0:3]
        UINT16 System : 1;      // [4]
        UINT16 Dpl : 2;         // [5:6]
        UINT16 Present : 1;     // [7]
        UINT16 Avl : 1;         // [8]
        UINT16 LongMode : 1;    // [9]
        UINT16 DefaultBit : 1;  // [10]
        UINT16 Granularity : 1; // [11]
        UINT16 Reserved1 : 4;   // [12:15]
    } Bits;
    UINT16 Uint16;
} SEGMENT_ATTRIBUTE;
STATIC_ASSERT(sizeof(SEGMENT_ATTRIBUTE) == 2, "Unexpected size");

//
// Context that is needed to feed to VMCB for the guest.
//
typedef struct _GUEST_CONTEXT
{
    IA32_DESCRIPTOR Gdtr;
    IA32_DESCRIPTOR Idtr;

    UINT16 SegCs;
    UINT16 SegDs;
    UINT16 SegEs;
    UINT16 SegSs;

    UINT64 Efer;
    UINT64 GPat;
    UINT64 Cr0;
    UINT64 Cr2;
    UINT64 Cr3;
    UINT64 Cr4;
    UINT64 Rflags;
    UINT64 Rsp;
    UINT64 Rip;
} GUEST_CONTEXT;

//
// Fills in the GUEST_CONTEXT. This must be a macro (ie, not a function) so that
// AsmReadStackPointer does not capture the address whose contents can be
// overwritten in the later step.
//
#define CAPTURE_CONTEXT(ContextRecord)                      \
    AsmReadGdtr(&(ContextRecord)->Gdtr);                    \
    AsmReadIdtr(&(ContextRecord)->Idtr);                    \
    (ContextRecord)->SegCs = AsmReadCs();                   \
    (ContextRecord)->SegDs = AsmReadDs();                   \
    (ContextRecord)->SegEs = AsmReadEs();                   \
    (ContextRecord)->SegSs = AsmReadSs();                   \
    (ContextRecord)->Efer = AsmReadMsr64(MSR_IA32_EFER);    \
    (ContextRecord)->GPat = AsmReadMsr64(MSR_IA32_PAT);     \
    (ContextRecord)->Cr0 = AsmReadCr0();                    \
    (ContextRecord)->Cr2 = AsmReadCr2();                    \
    (ContextRecord)->Cr3 = AsmReadCr3();                    \
    (ContextRecord)->Cr4 = AsmReadCr4();                    \
    (ContextRecord)->Rflags = AsmReadEflags();              \
    (ContextRecord)->Rsp = AsmReadStackPointer();           \
    (ContextRecord)->Rip = AsmReadInstructionPointer()

//
// The physical address of the ResetSystem runtime service.
//
EFI_RESET_SYSTEM g_ResetSystemPhys;

//
// The physical address of the SetVariable runtime service, and the GUID for log.
//
EFI_SET_VARIABLE g_SetVariablePhys;

EFI_GUID g_LogGuid =
{
    0x212d9932,
    0x0138,
    0x4104,
    { 0xb0, 0x41, 0xfb, 0x74, 0xd0, 0xe8, 0xa6, 0x75, },
};

//
// Cached LAPIC base physical address. Determined at ao init from
// IA32_APIC_BASE. The xAPIC NPF handler in Host.c compares the faulting
// GPA against this.
//
UINT64 g_LapicBasePa  = 0;
UINT64 g_ReadNcr3Pa   = 0;   // populated by SetupNptExec
UINT64 g_ExecNcr3Pa   = 0;   // populated by SetupNptExec
UINT64 g_ShadowNcr3Pa = 0;   // populated by aoInitialize — what VMCB.NCr3 holds during VMRUN
UINT64* g_ShadowPdpt0 = NULL; // populated by aoInitialize — shadow PDPT[0] page
UINT64 g_MsrpmPa      = 0;   // populated by VirtualizeProcessor
UINT64 g_DecoyPagePa  = 0;   // populated by aoInitialize
UINT32 g_VmcbSavedMisc1      = 0;
UINT32 g_VmcbSavedMisc2      = 0;
UINT32 g_VmcbSavedException  = 0;
UINT32 g_VmcbSavedGuestAsid  = 0;
UINT64 g_VmcbSavedNpEnable   = 0;
UINT64 g_VmcbSavedLbrVirt    = 0;

//
// Log buffer to use for assertion.
//
MEMORY_LOGS* g_GlobalLogBuffer;

//
// MP protocol.
//
STATIC EFI_MP_SERVICES_PROTOCOL* g_MpServices;

//
// GUID under which diagnostic milestones are stored in NVRAM. Any UUID will do
// — just needs to be unique to ao so ReadScratch can find it.
//
EFI_GUID g_MilestoneGuid = {
    0x7E5C0A2B, 0x4D1F, 0x4623,
    { 0xB9, 0x18, 0x3E, 0x7A, 0x2C, 0x88, 0x4F, 0x91 }
};

/**
 * @brief Records a milestone value to NVRAM. Safe to call from firmware
 *      context; do NOT call after CR3 has been swapped to the host page tables
 *      (the firmware's variable services depend on mappings the host CR3 may
 *      not have).
 */
VOID
RecordMilestone (
    IN UINT32 Value
    )
{
    if (gRT != NULL && gRT->SetVariable != NULL)
    {
        gRT->SetVariable(L"aoMilestone",
                         &g_MilestoneGuid,
                         EFI_VARIABLE_NON_VOLATILE |
                         EFI_VARIABLE_BOOTSERVICE_ACCESS |
                         EFI_VARIABLE_RUNTIME_ACCESS,
                         sizeof(Value),
                         &Value);
    }
}

/**
 * @brief Returns the current processor number. 0 for BSP.
 */
STATIC
UINT32
GetCurrentProcessorNumber (
    VOID
    )
{
    EFI_STATUS status;
    UINTN processorNumber;

    status = g_MpServices->WhoAmI(g_MpServices, &processorNumber);
    ASSERT_EFI_ERROR(status);

    return (UINT32)processorNumber;
}

/**
 * @brief Returns the number of active processors.
 */
STATIC
UINT32
GetActiveProcessorCount (
    VOID
    )
{
    EFI_STATUS status;
    UINTN numberOfProcessors;
    UINTN numberOfEnabledProcessors;

    status = g_MpServices->GetNumberOfProcessors(g_MpServices,
                                                 &numberOfProcessors,
                                                 &numberOfEnabledProcessors);
    ASSERT_EFI_ERROR(status);

    return (UINT32)numberOfEnabledProcessors;
}

/**
 * @brief Executes the function on all processors one by one.
 */
STATIC
VOID
RunOnAllProcessors (
    IN EFI_AP_PROCEDURE Callback,
    IN VOID* Context
    )
{
    EFI_STATUS status;

    Callback(Context);
    if (GetActiveProcessorCount() == 1)
    {
        return;
    }

    //
    // Execute the callback one by one. Multi-threading make logs look unreadable
    // and can even crashes the system because of some of logging function calls.
    //
    status = g_MpServices->StartupAllAPs(g_MpServices,
                                         Callback,
                                         TRUE,
                                         NULL,
                                         0,
                                         Context,
                                         NULL);
    ASSERT_EFI_ERROR(status);
}

/**
 * @brief Initializes globals used by the host.
 */
STATIC
VOID
InitializeHostDebugFacility (
    IN ROOT_CONTEXT* Context
    )
{
    UINT32 activeProcessorCount;

    ASSERT(g_ResetSystemPhys == NULL);
    g_ResetSystemPhys = gRT->ResetSystem;

    ASSERT(g_GlobalLogBuffer == NULL);
    g_GlobalLogBuffer = &Context->Cpus[0].Logs;

#if ENABLE_EXPERIMENTAL_HOST_EFI_VAR_LOGGING != 0
    //
    // Make sure EFI variables are usable to store log buffers for all processors
    // by writing zero-filled 4KB log buffers. If not, leave g_SetVariablePhys
    // as NULL to indicate EFI variable are not usable.
    //
    ASSERT(g_SetVariablePhys == NULL);
    g_SetVariablePhys = gRT->SetVariable;
    activeProcessorCount = GetActiveProcessorCount();
    for (UINT32 i = 0; i < activeProcessorCount; ++i)
    {
        EFI_STATUS status;
        CHAR16 variableName[16];

        UnicodeSPrint(variableName, sizeof(variableName), L"Log#%d", i);
        status = gRT->SetVariable(variableName,
                                  &g_LogGuid,
                                  EFI_VARIABLE_NON_VOLATILE |
                                  EFI_VARIABLE_BOOTSERVICE_ACCESS |
                                  EFI_VARIABLE_RUNTIME_ACCESS,
                                  sizeof(Context->Cpus[i].Logs),
                                  &Context->Cpus[i].Logs);
        if (EFI_ERROR(status))
        {
            DEBUG((DEBUG_ERROR,
                   "SetVariable failed for %s : %r\n",
                   variableName,
                   status));
            g_SetVariablePhys = NULL;
            break;
        }
    }
#else
    activeProcessorCount = 0;
#endif
}

/**
 * @brief Switches the current execution environment to the given environment.
 *
 * Per barevisor's docs: "the current IDT, GDT, TSS and paging structures are
 * destroyed as the system transitions to the runtime-phase. Thus, the host
 * cannot depend on them and needs its own data structures." So we MUST swap.
 *
 * Diagnostic-instrumented to find exactly which write crashes on this board.
 * Writes a milestone byte to physical 0x10000050 between each step.
 */
STATIC
VOID
SwitchToHostContext (
    IN CONST SHARED_HOST_DATA* SharedHostData,
    IN CONST HOST_DATA* HostData
    )
{
    // CRITICAL ORDERING: write CR3 and GDT first (firmware's IDT is still
    // active — safe). Then CLGI to mask ALL interrupts (INTR + NMI + SMI),
    // then load IDT LAST.
    //
    // CLI alone is insufficient: SetVariable triggers SMI to write SPI flash,
    // and SMI bypasses IF entirely. Only CLGI masks SMI (requires SVM, which
    // we already enabled via EFER.SVME=1). After CLGI, no interrupts of any
    // kind reach the CPU until STGI or until VMRUN/VMEXIT cycle restores it.
    RecordMilestone(0xA51E0026);
    AsmWriteCr3(SharedHostData->Cr3);
    RecordMilestone(0xA51E0027);
    AsmWriteGdtr(&HostData->Gdtr);
    RecordMilestone(0xA51E0028);
    __svm_clgi();  // SVM-mask all interrupts (CLI doesn't catch SMI)
    AsmWriteIdtr(&SharedHostData->Idtr);
    // NO NVRAM writes past this point; nothing that could STGI either.
}

/**
 * @brief Initializes the per-processor host environment data structures.
 */
STATIC
VOID
InitializeHostData (
    OUT HOST_DATA* HostData,
    IN CONST SHARED_HOST_DATA* SharedHostData
    )
{
    IA32_DESCRIPTOR gdtr;

    ZeroMem(HostData, sizeof(*HostData));

    //
    // Read the current GDTR and make sure buffer to have a copy of this is large
    // enough to clone the current GDT.
    //
    AsmReadGdtr(&gdtr);
    ASSERT(sizeof(HostData->Gdt) >= gdtr.Limit + 1);

    //
    // Initialize the per processor host data structures.
    //
    HostData->Shared = SharedHostData;
    CopyMem(HostData->Gdt, (VOID*)gdtr.Base, gdtr.Limit + 1);
    HostData->Gdtr.Base = (UINT64)&HostData->Gdt[0];
    HostData->Gdtr.Limit = gdtr.Limit;
}

/**
 * @brief Returns the access right value required for VMCB for the specified segment.
 */
#define RPL_MASK        3
STATIC
UINT16
GetSegmentAccessRight (
    IN UINT16 SegmentSelector,
    IN UINT64 GdtBase
    )
{
    IA32_SEGMENT_DESCRIPTOR* descriptor;
    SEGMENT_ATTRIBUTE attribute;

    //
    // Get a segment descriptor corresponds to the specified segment selector.
    //
    descriptor = (IA32_SEGMENT_DESCRIPTOR*)(
                                        GdtBase + (SegmentSelector & ~RPL_MASK));

    //
    // Extract all attribute fields in the segment descriptor to a structure
    // that describes only attributes (as opposed to the segment descriptor
    // consists of multiple other fields).
    //
    attribute.Bits.Type = (UINT16)descriptor->Bits.Type;
    attribute.Bits.System = (UINT16)descriptor->Bits.S;
    attribute.Bits.Dpl = (UINT16)descriptor->Bits.DPL;
    attribute.Bits.Present = (UINT16)descriptor->Bits.P;
    attribute.Bits.Avl = (UINT16)descriptor->Bits.AVL;
    attribute.Bits.LongMode = (UINT16)descriptor->Bits.L;
    attribute.Bits.DefaultBit = (UINT16)descriptor->Bits.DB;
    attribute.Bits.Granularity = (UINT16)descriptor->Bits.G;
    attribute.Bits.Reserved1 = 0;

    return attribute.Uint16;
}

/**
 * @brief Prepares the system for virtualization.
 *
 * @details This function first fills in the gust VMCS with the provided guest
 *      context object, populates data to pass to the host in its stack,
 *      initializes other this-project defined state fields, register local APIC
 *      access intercept, then switches the x64 data structures to ones prepared
 *      for the host.
 */
STATIC
VOID
PrepareForVmrun (
    IN OUT ROOT_CONTEXT* SharedContext,
    IN UINT32 ProcessorNumber,
    IN CONST GUEST_CONTEXT* ContextRecord
    )
{
    PER_CPU_DATA* cpu;

    //
    // Disable interrupts before we swap to our IDT. Otherwise any hardware
    // interrupt fired by firmware (APIC timer, USB controller, etc.) would
    // route through our IDT — and every entry is a "panic and reset" stub.
    // Mirrors barevisor's `x86::irq::disable()` at host main entry.
    //
    // The guest's RFLAGS.IF was captured before this in CAPTURE_CONTEXT, so
    // VMRUN will restore the guest with IF=1 (or whatever firmware had).
    //
    DisableInterrupts();

    cpu = &SharedContext->Cpus[ProcessorNumber];

    // CPUID: NOT intercepted. On this Zen 3, CPUID.1.ECX[31]=0 natively (no
    // hypervisor-present bit to mask). CPUID.80000001h.ECX[2]=1 and
    // CPUID.8000000Ah return hardware-accurate values — consistent with the
    // "BIOS-disabled SVM" narrative; masking would create a detectable
    // inconsistency. AMD APM §15.20: CPUID has no exception conditions.
    cpu->GuestVmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_MSR_PROT;
    // RDPMC: no longer intercepted. Returning 0 for all PMC reads is clearly
    // wrong (bare metal has real counter values) and is a straightforward
    // detection vector. Let the real hardware counter through instead.
    cpu->GuestVmcb.ControlArea.InterceptMisc2 |= SVM_INTERCEPT_MISC2_VMRUN;
    // LBR virtualization: save/restore guest LBR state (DebugCtlMsr,
    // LastBranchFrom/To, LastExcpFrom/To) on VMRUN/VMEXIT. Without this,
    // host execution during VMEXIT handling pollutes the guest's branch
    // records with HV code addresses — readable by guest scanner via RDMSR.
    cpu->GuestVmcb.ControlArea.LbrVirtualizationEnable = 1;
    // All SVM instructions that would #UD on bare metal with SVME=0.
    // We force EFER.SVME=1 in the VMCB (required for SVM to function), so
    // without these intercepts the guest executes VMLOAD/VMSAVE/STGI/CLGI
    // instead of #UD-ing — a direct detection vector. Handlers inject #UD.
    cpu->GuestVmcb.ControlArea.InterceptMisc2 |= SVM_INTERCEPT_MISC2_VMMCALL;
    cpu->GuestVmcb.ControlArea.InterceptMisc2 |= SVM_INTERCEPT_MISC2_VMLOAD;
    cpu->GuestVmcb.ControlArea.InterceptMisc2 |= SVM_INTERCEPT_MISC2_VMSAVE;
    cpu->GuestVmcb.ControlArea.InterceptMisc2 |= SVM_INTERCEPT_MISC2_STGI;
    cpu->GuestVmcb.ControlArea.InterceptMisc2 |= SVM_INTERCEPT_MISC2_CLGI;
    cpu->GuestVmcb.ControlArea.InterceptMisc2 |= SVM_INTERCEPT_MISC2_SKINIT;
    // INVLPGA requires SVME=1; bare metal SVME=0 yields #UD.
    cpu->GuestVmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_INVLPGA;
    // INVD: intercept and absorb (emulate as no-op). INVD discards ALL dirty
    // cache lines without writeback — including any dirty HV data. A guest that
    // executes INVD can therefore corrupt in-flight host writes. Windows never
    // issues INVD in normal operation but an adversarial guest could. Intercept
    // and silently advance RIP; the guest thinks its cache was invalidated,
    // which is a benign lie for a pass-through HV. AMD APM §15.13 / offset 00Ch bit 22.
    cpu->GuestVmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_INVD;
    // #SX (vector 0x1E = bit 30) for the R_INIT-redirected INIT path.
    // #UD (vector 6 = bit 6) for the UD2-based hypercall channel.
    // #DB (vector 1 = bit 1) for the Option-7 single-step flip-back path.
    //    Intercepted unconditionally; non-hook #DBs (hardware-breakpoint
    //    traps in the guest) are re-injected with no RIP adjustment, matching
    //    native trap semantics for debug traps.
    cpu->GuestVmcb.ControlArea.InterceptException |= (1U << 30);
    cpu->GuestVmcb.ControlArea.InterceptException |= SVM_INTERCEPT_EXCEPTION_UD;
    cpu->GuestVmcb.ControlArea.InterceptException |= (1U << 1);

    //
    // Wire MSRPM into VMCB. MSR_PROT above enables MSRPM; specific MSRs
    // are gated by bits in SharedContext->Svm.Msrpm (see InitializeSharedContext).
    //
    cpu->GuestVmcb.ControlArea.MsrpmBasePa = (UINT64)&SharedContext->Svm.Msrpm[0];
    g_MsrpmPa = (UINT64)&SharedContext->Svm.Msrpm[0];

    //
    // INIT handling: redirect to #SX via VM_CR.R_INIT (AMD-recommended,
    // matches barevisor exactly). Comment from barevisor guest.rs:445-446:
    //   "One cannot simply intercept #INIT because even if we do, #INIT is
    //    still pending and will be delivered anyway."
    //
    // The R_INIT pathway converts a hardware INIT signal into a #SX
    // (vector 0x1E) exception which IS interceptable. The AP's CPU
    // architecturally enters wait-for-SIPI state, allowing Windows's BSP
    // to send the SIPI (which we then catch via NPT on LAPIC writes and
    // emulate by waking the parked AP).
    //
    AsmMsrOr64(SVM_MSR_VM_CR, VM_CR_R_INIT);

    //
    // (Removed MSR_PROT intercept + MSRPM. barevisor doesn't intercept any
    // MSRs and survives Windows boot; our EFER intercept was creating
    // Windows-visible read/write inconsistencies. Simpler = better.)
    //

    //
    // Same hard-coded ASID for all processors. No need to use different ones as
    // this project only have the single guest.
    //
    cpu->GuestVmcb.ControlArea.GuestAsid = 1;

    //
    // Enable NTPs.
    //
    cpu->GuestVmcb.ControlArea.NpEnable |= SVM_NP_ENABLE_NP_ENABLE;
    cpu->GuestVmcb.ControlArea.NCr3 = (g_ShadowNcr3Pa != 0) ? g_ShadowNcr3Pa : g_ReadNcr3Pa;
    // Snapshot static intercept/config fields for the VMEXIT decoy swap.
    g_VmcbSavedMisc1     = cpu->GuestVmcb.ControlArea.InterceptMisc1;
    g_VmcbSavedMisc2     = cpu->GuestVmcb.ControlArea.InterceptMisc2;
    g_VmcbSavedException = cpu->GuestVmcb.ControlArea.InterceptException;
    g_VmcbSavedGuestAsid = cpu->GuestVmcb.ControlArea.GuestAsid;
    g_VmcbSavedNpEnable  = cpu->GuestVmcb.ControlArea.NpEnable;
    g_VmcbSavedLbrVirt   = cpu->GuestVmcb.ControlArea.LbrVirtualizationEnable;

    //
    // Set up the guest state using the captured context.
    //
    cpu->GuestVmcb.StateSaveArea.GdtrBase = ContextRecord->Gdtr.Base;
    cpu->GuestVmcb.StateSaveArea.GdtrLimit = ContextRecord->Gdtr.Limit;
    cpu->GuestVmcb.StateSaveArea.IdtrBase = ContextRecord->Idtr.Base;
    cpu->GuestVmcb.StateSaveArea.IdtrLimit = ContextRecord->Idtr.Limit;

    cpu->GuestVmcb.StateSaveArea.CsLimit = (UINT32)__segmentlimit(ContextRecord->SegCs);
    cpu->GuestVmcb.StateSaveArea.DsLimit = (UINT32)__segmentlimit(ContextRecord->SegDs);
    cpu->GuestVmcb.StateSaveArea.EsLimit = (UINT32)__segmentlimit(ContextRecord->SegEs);
    cpu->GuestVmcb.StateSaveArea.SsLimit = (UINT32)__segmentlimit(ContextRecord->SegSs);
    cpu->GuestVmcb.StateSaveArea.CsSelector = ContextRecord->SegCs;
    cpu->GuestVmcb.StateSaveArea.DsSelector = ContextRecord->SegDs;
    cpu->GuestVmcb.StateSaveArea.EsSelector = ContextRecord->SegEs;
    cpu->GuestVmcb.StateSaveArea.SsSelector = ContextRecord->SegSs;
    cpu->GuestVmcb.StateSaveArea.CsAttrib = GetSegmentAccessRight(ContextRecord->SegCs, ContextRecord->Gdtr.Base);
    cpu->GuestVmcb.StateSaveArea.DsAttrib = GetSegmentAccessRight(ContextRecord->SegDs, ContextRecord->Gdtr.Base);
    cpu->GuestVmcb.StateSaveArea.EsAttrib = GetSegmentAccessRight(ContextRecord->SegEs, ContextRecord->Gdtr.Base);
    cpu->GuestVmcb.StateSaveArea.SsAttrib = GetSegmentAccessRight(ContextRecord->SegSs, ContextRecord->Gdtr.Base);

    //
    // Sanitize captured firmware state before handing it to the VMCB. UEFI on
    // some boards (notably Gigabyte AGESA) can leak bits that AMD's VMRUN
    // consistency check treats as MBZ on pre-Zen4 silicon, which manifests as
    // a silent VMEXIT_INVALID and an apparent hang.
    //   * CR4: clear CET (bit 23) and LASS (bit 27) which are MBZ on most
    //     Ryzen parts. CR4 high bits MBZ too.
    //   * EFER: only bits [14:0] are defined. Mask the rest.
    //   * CR0: enforce !(CD=0 && NW=1) — AMD requires CD>=NW.
    //   * RFLAGS: bit 1 reserved-must-be-1; bits 3, 5, 15 reserved-must-be-0.
    //
    {
        UINT64 cr0 = ContextRecord->Cr0;
        UINT64 cr4 = ContextRecord->Cr4;
        UINT64 efer = ContextRecord->Efer;
        UINT64 rflags = ContextRecord->Rflags;

        if ((cr0 & BIT30 /* CD */) == 0 && (cr0 & BIT29 /* NW */) != 0)
        {
            cr0 &= ~(UINT64)BIT29;
        }
        cr0 &= 0xFFFFFFFFULL;

        cr4 &= ~((UINT64)BIT23 | (UINT64)BIT27);
        cr4 &= 0xFFFFFFFFULL;

        efer &= 0xFFFFULL;

        rflags |= BIT1;
        rflags &= ~((UINT64)BIT3 | (UINT64)BIT5 | (UINT64)BIT15);

        cpu->GuestVmcb.StateSaveArea.Efer = efer;
        cpu->GuestVmcb.StateSaveArea.GPat = ContextRecord->GPat;
        cpu->GuestVmcb.StateSaveArea.Cr0 = cr0;
        cpu->GuestVmcb.StateSaveArea.Cr2 = ContextRecord->Cr2;
        cpu->GuestVmcb.StateSaveArea.Cr3 = ContextRecord->Cr3;
        cpu->GuestVmcb.StateSaveArea.Cr4 = cr4;
        cpu->GuestVmcb.StateSaveArea.Rflags = rflags;
    }
    cpu->GuestVmcb.StateSaveArea.Rsp = ContextRecord->Rsp;
    cpu->GuestVmcb.StateSaveArea.Rip = ContextRecord->Rip;

    //
    // Architectural reset values for DR6/DR7. AMD APM specifies certain
    // reserved bits must be 1 (DR6 bits 0..3 should be 0, bits 4..11 should
    // be 1, bit 12 should be 0, bit 13..15 should be 1, bit 16..31 should be 1).
    // The canonical reset value is 0xFFFF0FF0 for DR6 and 0x400 for DR7.
    // Leaving them zero would fail VMRUN's consistency check.
    //
    cpu->GuestVmcb.StateSaveArea.Dr6 = 0xFFFF0FF0;
    cpu->GuestVmcb.StateSaveArea.Dr7 = 0x400;

    __svm_vmsave((UINTN)&cpu->GuestVmcb);

    //
    // Fixup: VMSAVE captured TR with Type=9 ("64-bit TSS available"), but the
    // TR is actually loaded. AMD's VMRUN consistency check requires Type=B
    // ("64-bit TSS busy") for a running long-mode guest, so force the busy
    // bit. The Type field lives at attr[3:0]; bit 1 of that nibble is the
    // busy flag. Confirmed culprit from a live VMCB dump on the test board.
    //
    cpu->GuestVmcb.StateSaveArea.TrAttrib |= 0x0002;

    //
    // Per AMD APM Vol 2 §15.5.1: "For NULL segments, set all attribute bits to
    // zero." VMSAVE captured attr=0x82 (P=1, Type=2) with sel=0 which is
    // architecturally invalid — null segments must have attr=0. Apply the fix.
    //
    if (cpu->GuestVmcb.StateSaveArea.LdtrSelector == 0)
    {
        cpu->GuestVmcb.StateSaveArea.LdtrAttrib = 0;
        cpu->GuestVmcb.StateSaveArea.LdtrLimit = 0;
        cpu->GuestVmcb.StateSaveArea.LdtrBase = 0;
    }

    //
    // Pass values to the host through the host stack address.
    //
    cpu->HostStack.Layout.Params.GuestVmcbPa = (UINT64)&cpu->GuestVmcb;
    cpu->HostStack.Layout.Params.SharedContext = SharedContext;
    cpu->HostStack.Layout.Params.ProcessorNumber = ProcessorNumber;
    cpu->HostStack.Layout.Params.Reserved1 = MAX_UINT32;

    //
    // Configure VM_HSAVE_PA MSR. See "15.30.4 VM_HSAVE_PA MSR (C001_0117h)""
    //
    AsmWriteMsr64(SVM_MSR_VM_HSAVE_PA, (UINT64)&cpu->HostStateArea[0]);

    //
    // Initialize state variables.
    //
    cpu->States.Guest.ProcessorNumber = ProcessorNumber;
    cpu->States.Guest.ApicId = GetApicId();

    DEBUG((DEBUG_VERBOSE,
           "CPU %d, APIC ID %d, Log @ %p\n",
           ProcessorNumber,
           cpu->States.Guest.ApicId,
           &cpu->Logs));

    //
    // Milestone recording is via EFI NVRAM variables, which survive reset and
    // OS-boot transitions. Tests with the prior low-memory scratch slot at
    // physical 0x100020 produced only garbage, consistent with the firmware
    // marking the first 1MB as not-present for null-pointer trapping.
    //
    RecordMilestone(0xA51E0010);

    //
    // Sanity-check write at 8MB to validate that scratch memory CAN be written
    // in firmware context. If this faults, the diagnostic infrastructure itself
    // is broken and we need to revisit.
    //
    *(volatile UINT32*)0x800000 = 0xCAFEF00D;

    //
    // Switch the current execution environment for the host.
    //
    DEBUG((DEBUG_INFO, "[M2] Calling InitializeHostData\n"));
    InitializeHostData(&cpu->HostX64Data, &SharedContext->HostX64);
    RecordMilestone(0xA51E0020);

    DEBUG((DEBUG_INFO, "[M3] Calling SwitchToHostContext (CR3 swap)\n"));
    RecordMilestone(0xA51E0025);
    SwitchToHostContext(&SharedContext->HostX64, &cpu->HostX64Data);

    //
    // SwitchToHostContext did __svm_clgi internally before loading the IDT.
    // After CLGI we MUST NOT call any firmware functions (DEBUG console,
    // gRT->SetVariable, etc.) — those may need SMI / IPI for completion and
    // hang under GIF=0. Only SVM instructions and direct memory ops are
    // safe between here and VMRUN.
    //
    __svm_vmsave((UINTN)&cpu->HostVmcb);
}

//
// Per-CPU flag used by VirtualizeProcessor to break out of the
// pre/post-VMRUN recursion. Memory-based instead of CPUID-based so we can
// keep the CPUID hypervisor leaves silent (stealth: guest software scans
// 0x40000000 and shouldn't see anything). Guest reads this flag via NPT
// identity-mapped host memory, same as host.
//
STATIC volatile UINT8 g_PerCpuVirtualized[256] = {0};

/**
 * @brief Virtualizes the current processor.
 */
STATIC
VOID
EFIAPI
VirtualizeProcessor (
    IN OUT VOID* Context
    )
{
    GUEST_CONTEXT guestContext;

    //
    // Enable SVM and capture the current context, which will be resumed on the
    // VMRUN.
    //
    AsmMsrOr64(MSR_IA32_EFER, EFER_SVME);
    CAPTURE_CONTEXT(&guestContext);

    //
    // On the first run, g_PerCpuVirtualized[procNum] is 0. We set it to 1
    // and proceed to VMRUN. After VMRUN, the guest resumes at the
    // captured RIP — which is the line right after CAPTURE_CONTEXT, i.e.,
    // here. On that second iteration we observe the flag is now 1 and
    // return cleanly, exiting the function. No CPUID-based self-detection
    // (keeps the standard HV CPUID leaves at zero for stealth).
    //
    {
        UINT32 procNum = GetCurrentProcessorNumber();
        if (g_PerCpuVirtualized[procNum] == 0)
        {
            ROOT_CONTEXT* context = (ROOT_CONTEXT*)Context;
            DEBUG((DEBUG_INFO, "Virtualizing the processor %u\n", procNum));

            PrepareForVmrun(context, procNum, &guestContext);

            //
            // Set the flag BEFORE VMRUN. On the next iteration (after VMRUN
            // resumes guest), the flag will be 1 and we'll fall through
            // and return.
            //
            g_PerCpuVirtualized[procNum] = 1;

            //
            // NO RecordMilestone or DEBUG console calls between PrepareForVmrun
            // (which loaded our IDT) and AsmLaunchVm (which VMRUNs with GIF=0).
            //
            AsmLaunchVm(&context->Cpus[procNum].HostStack.Layout.Params);
            ASSERT(FALSE);
            CpuDeadLoop();
        }
    }
    DEBUG((DEBUG_INFO, "Virtualized the processor\n"));
}

/**
 * @brief Initializes the paging structures by building identically mapped
 *      translations.
 *
 * @details This function assumes that PA0 of the PAT register is configured for
 *      the write-back memory type and does not set PAT, PCD or PWT bits.
 */
STATIC
VOID
SetupIdentityMapping (
    OUT PAGING_STRUCTURES* PagingStructures,
    IN BOOLEAN NestedPageTables
    )
{
    BOOLEAN userAccessible;
    UINT64 pa;

    ZeroMem(PagingStructures, sizeof(*PagingStructures));

    //
    // NPT entries must be user-accessible (AMD APM §15.25.5). Host paging
    // structures use supervisor-only.
    //
    userAccessible = (NestedPageTables != FALSE);

    //
    // Fill all 512 PML4 entries. Each points to a per-PML4 PDPT, each PDPT
    // entry is a 1GB page (PS=1). Total coverage: 512 * 512 * 1GB = 256TB.
    //
    pa = 0;
    for (UINT32 pml4Index = 0; pml4Index < PAGE_TABLE_ENTRY_COUNT; ++pml4Index)
    {
        PML4_ENTRY_2MB* pml4 = &PagingStructures->Pml4[pml4Index];
        PDP_ENTRY_1GB* pdpt = PagingStructures->Pdpt[pml4Index];

        // PML4[256..511] covers GPAs >128TB — no physical RAM or MMIO lives
        // there on current hardware. Marking those entries supervisor-only
        // (User=0) matches the Windows kernel PML4 layout and avoids the
        // all-User=1 signature that a physical-memory scanner would flag.
        BOOLEAN entryUser = userAccessible && (pml4Index < 256);

        pml4->Bits.Valid = TRUE;
        pml4->Bits.Write = TRUE;
        pml4->Bits.User = entryUser;
        pml4->Bits.PageFrameNumber = (UINT64)pdpt >> EFI_PAGE_SHIFT;

        for (UINT32 pdptIndex = 0; pdptIndex < PAGE_TABLE_ENTRY_COUNT; ++pdptIndex)
        {
            pdpt[pdptIndex].Bits.Valid = TRUE;
            pdpt[pdptIndex].Bits.Write = TRUE;
            pdpt[pdptIndex].Bits.User = entryUser;
            pdpt[pdptIndex].Bits.LargePage = TRUE;
            // PFN occupies bits [30:51] of the entry; PA / 1GB.
            pdpt[pdptIndex].Bits.PageFrameNumber = pa >> 30;
            pa += SIZE_1GB;
        }
    }
}

/**
 * @brief Split any 1GB PDPT leaf down to 4KB granularity around TargetGpa4K
 *      in the supplied NPT, using Region for the intermediate PD and PT.
 *      All 4KB pages outside the target are identity-mapped with R/W=1.
 *      OverridePfn (if non-zero) replaces the target page's physical frame.
 *      NoExecute controls the NX bit on the target 4KB page only.
 *      Idempotent: rebuilds the same PT/PD tables on repeat calls.
 */
STATIC
BOOLEAN
NptSplitTo4KB (
    IN OUT PAGING_STRUCTURES*   Npt,
    IN OUT NPT_HOOK_REGION*     Region,
    IN     UINT64               TargetGpa4K,
    IN     UINT64               OverridePfn,
    IN     BOOLEAN              NoExecute
    )
{
    ADDRESS_TRANSLATION_HELPER helper;
    UINT32 pml4Idx, pdptIdx, pdIdx, ptIdx;
    UINT64 oneGbBase, twoMbBase;
    UINT64 pa;
    PT_ENTRY_4KB *Pt;
    PML4_ENTRY_2MB *Pd;
    UINT32 ptSlot, gbSlot;
    BOOLEAN newGbSlot;

    helper.AsUInt64 = TargetGpa4K;
    pml4Idx  = (UINT32)helper.AsIndex.Pml4;
    pdptIdx  = (UINT32)helper.AsIndex.Pdpt;
    pdIdx    = (UINT32)helper.AsIndex.Pd;
    ptIdx    = (UINT32)helper.AsIndex.Pt;
    oneGbBase = TargetGpa4K & ~(UINT64)0x3FFFFFFF;
    twoMbBase = TargetGpa4K & ~(UINT64)0x1FFFFF;

    // Find or allocate a 1GB Pd slot for this 1GB region. Each 1GB range
    // needs its own PD because PDEs describe 2MB leaves within exactly ONE
    // 1GB range. Sharing a PD across 1GBs caused the multi-hook BSOD.
    //
    // Encoding note: a slot is "free" when OneGbBase==UINT64_MAX (sentinel);
    // zero is a valid 1GB base. ZeroMem in SetupNptExec etc. leaves these
    // as 0, so we treat 0 as also-free on first touch — it's fine since the
    // first hook to bind to oneGbBase==0 claims the slot cleanly.
    gbSlot = NPT_HOOK_1GB_SLOT_COUNT;
    newGbSlot = FALSE;
    for (UINT32 s = 0; s < NPT_HOOK_1GB_SLOT_COUNT; s++) {
        if (Region->OneGbBase[s] == (oneGbBase | 1ULL)) {  // tagged occupied
            gbSlot = s; break;
        }
    }
    if (gbSlot == NPT_HOOK_1GB_SLOT_COUNT) {
        for (UINT32 s = 0; s < NPT_HOOK_1GB_SLOT_COUNT; s++) {
            if ((Region->OneGbBase[s] & 1ULL) == 0) {  // low bit clear = free
                gbSlot = s;
                // Store oneGbBase tagged with low bit=1 to mark occupied.
                // oneGbBase is 1GB-aligned so bit 0 is always 0 in the real value.
                Region->OneGbBase[s] = oneGbBase | 1ULL;
                newGbSlot = TRUE;
                break;
            }
        }
    }
    if (gbSlot == NPT_HOOK_1GB_SLOT_COUNT) {
        // Out of 1GB slots. Fail closed.
        return FALSE;
    }
    Pd = Region->Pd[gbSlot];

    // Find or allocate a PT slot for this 2MB region.
    ptSlot = NPT_HOOK_SLOT_COUNT;
    for (UINT32 s = 0; s < NPT_HOOK_SLOT_COUNT; s++) {
        if (Region->TwoMbBase[s] == twoMbBase) { ptSlot = s; break; }
    }
    if (ptSlot == NPT_HOOK_SLOT_COUNT) {
        for (UINT32 s = 0; s < NPT_HOOK_SLOT_COUNT; s++) {
            if (Region->TwoMbBase[s] == 0) {
                ptSlot = s;
                Region->TwoMbBase[s] = twoMbBase;
                break;
            }
        }
    }
    if (ptSlot == NPT_HOOK_SLOT_COUNT) {
        // Out of slots. Fail closed — DO NOT clobber an existing slot:
        // the clobbered slot's previously-hooked 2MB region would then walk
        // through the wrong PT and the CPU would access stale PFNs → BSOD.
        if (newGbSlot) Region->OneGbBase[gbSlot] = 0;  // roll back (clears tag bit)
        return FALSE;
    }
    Pt = Region->PtArr[ptSlot];

    // Build 4KB PT for this 2MB region: identity for all pages, then patch target.
    // Single 8-byte store per entry — multi-step zero+set creates a window where
    // the entry is transiently invalid while CPUs may be walking this PT.
    // PTE bits: Valid(0) | Write(1) | User(2) | PFN[51:12].
    pa = twoMbBase;
    for (UINT32 i = 0; i < PAGE_TABLE_ENTRY_COUNT; ++i)
    {
        UINT64 newPte = 0x7ULL | (pa & 0x000FFFFFFFFFF000ULL);  // Valid|Write|User|PFN
        ((volatile PT_ENTRY_4KB*)&Pt[i])->Uint64 = newPte;
        pa += SIZE_4KB;
    }
    // Patch the target entry in one store: override PFN and set NoExecute.
    // NoExecute = bit 63. PFN replaces bits [51:12].
    {
        UINT64 pfn     = (OverridePfn != 0) ? OverridePfn : (TargetGpa4K >> EFI_PAGE_SHIFT);
        UINT64 nx      = NoExecute ? (1ULL << 63) : 0ULL;
        UINT64 newPte  = 0x7ULL | (pfn << EFI_PAGE_SHIFT) | nx;
        ((volatile PT_ENTRY_4KB*)&Pt[ptIdx])->Uint64 = newPte;
    }

    // Point Pd[pdIdx] (the 1GB-slot's PD) to this slot's PT. Single 8-byte store —
    // live CPUs may be walking this Pd when a second hook is installed into the
    // same 1GB range. Multi-step zero+set was leaving a window with an invalid
    // (Present=0) entry.
    {
        UINT64 newPde = 0x7ULL  // Valid | Write | User
                      | (((UINT64)(UINTN)Pt) & 0x000FFFFFFFFFF000ULL);
        // LargePage (bit 7) stays 0: this is a PT pointer.
        ((volatile PML4_ENTRY_2MB*)&Pd[pdIdx])->Uint64 = newPde;
    }

    // If this is a NEW 1GB slot, fill all 512 entries of the PD as 2MB identity
    // leaves for THIS 1GB range (except pdIdx which we just set). On repeat
    // installs into the same 1GB slot we only need to preserve existing
    // non-leaf PDEs (other hooks' PT pointers) within this same 1GB.
    //
    // Either way, we iterate all 512 and skip any already-valid non-leaf entry.
    pa = oneGbBase;
    for (UINT32 i = 0; i < PAGE_TABLE_ENTRY_COUNT; ++i)
    {
        if (i != pdIdx)
        {
            UINT64 existing = Pd[i].Uint64;
            BOOLEAN alreadyNonLeaf = (BOOLEAN)((existing & 0x1) && !((existing >> 7) & 0x1));
            if (!alreadyNonLeaf)
            {
                // 2MB leaf: Valid | Write | User | LargePage | PA[51:21]
                UINT64 newLeaf = 0x87ULL | (pa & 0x000FFFFFFFE00000ULL);
                ((volatile PML4_ENTRY_2MB*)&Pd[i])->Uint64 = newLeaf;
            }
        }
        pa += SIZE_2MB;
    }

    // Replace the 1GB PDPT leaf with a pointer to this 1GB-slot's PD
    // (idempotent for same 1GB; distinct PD per different 1GB).
    {
        UINT64 newPdpe = 0x7ULL  // Valid | Write | User
                       | (((UINT64)(UINTN)&Pd[0]) & 0x000FFFFFFFFFF000ULL);
        // LargePage (bit 7) stays 0: points to PD, not a 1GB leaf.
        ((volatile PDP_ENTRY_1GB*)&Npt->Pdpt[pml4Idx][pdptIdx])->Uint64 = newPdpe;
    }
    return TRUE;
}

/**
 * @brief Copy the fully-configured read NPT (NestedPageTables) into NptExec
 *      so both share the same identity map, LAPIC intercept, and HV-guard
 *      modifications.  Record the physical addresses of each NCr3 root.
 *      Must be called AFTER SetupHvNptProtect so HvGuard PDPT patch is
 *      included in the copy.
 */
STATIC
VOID
SetupNptExec (
    IN OUT SHARED_SVM_DATA* Svm
    )
{
    UINT32 i;

    CopyMem(&Svm->NptExec, &Svm->NestedPageTables, sizeof(PAGING_STRUCTURES));

    // CopyMem copies the PML4 entries verbatim, so NptExec.Pml4[i].PFN still
    // points into NestedPageTables.Pdpt — the two trees share the same PDPT.
    // Redirect each valid PML4 entry to NptExec's own Pdpt row so the trees
    // are independent and NptSplitTo4KB modifications don't bleed across.
    for (i = 0; i < PAGE_TABLE_ENTRY_COUNT; i++)
    {
        if (Svm->NptExec.Pml4[i].Bits.Valid)
        {
            Svm->NptExec.Pml4[i].Bits.PageFrameNumber =
                (UINT64)(UINTN)Svm->NptExec.Pdpt[i] >> EFI_PAGE_SHIFT;
        }
    }

    Svm->HookMeta.ReadNcr3Pa = (UINT64)(UINTN)&Svm->NestedPageTables.Pml4[0];
    Svm->HookMeta.ExecNcr3Pa = (UINT64)(UINTN)&Svm->NptExec.Pml4[0];
    g_ReadNcr3Pa = Svm->HookMeta.ReadNcr3Pa;
    g_ExecNcr3Pa = Svm->HookMeta.ExecNcr3Pa;
}

/**
 * @brief Install a split-page hook at TargetGpa4K.
 *      Read NCr3: hooked page -> original PFN, NX=1 (exec causes NPF).
 *      Exec NCr3: hooked page -> shadow PFN, NX=0 (exec sees hook code).
 *      Shadow page is a copy of the original; caller patches it AFTER this
 *      returns using the returned shadow GPA + WRITE_GPA hypercall.
 *      Returns shadow page GPA, or 0 on failure (table full).
 */
UINT64
InstallNptHook (
    IN OUT SHARED_SVM_DATA* Svm,
    IN     UINT64           TargetGpa4K
    )
{
    UINT32 idx;
    UINT64 shadowPfn;
    UINT64 shadowGpa;
    NPT_HOOK_ENTRY* entry;

    if (Svm->HookMeta.HookCount  >= NPT_MAX_HOOKS)    return 0;
    if (Svm->HookMeta.ShadowUsed >= NPT_SHADOW_COUNT) return 0;

    idx       = Svm->HookMeta.ShadowUsed;
    shadowGpa = (UINT64)(UINTN)&Svm->ShadowPages[idx][0];
    shadowPfn = shadowGpa >> EFI_PAGE_SHIFT;

    // Copy original page into shadow so it's valid the instant any CPU flips
    // to exec NCr3 and fetches from it.  Caller writes hook code on top of
    // this copy AFTER we return, via WRITE_GPA to the returned shadowGpa.
    CopyMem((VOID*)(UINTN)shadowGpa,
            (VOID*)(UINTN)TargetGpa4K,
            SIZE_4KB);

    // Publish HookMeta entry BEFORE modifying the NPT.
    // The NPF handler matches on HookMeta.Hooks[].Gpa4K up to HookCount.
    // If NPT were modified first there would be a window where a CPU NPFs
    // on the newly-NX page but finds no matching entry and falls through to
    // bad-NPF, injecting #GP into the guest. Publishing first closes that
    // window: the handler matches the new GPA as soon as the NPT makes it
    // faultable. HookCount++ is the publication fence — all entry fields
    // are written before the count is incremented.
    entry = &Svm->HookMeta.Hooks[Svm->HookMeta.HookCount];
    entry->Gpa4K       = TargetGpa4K;
    entry->OriginalPfn = TargetGpa4K >> EFI_PAGE_SHIFT;
    entry->ShadowPfn   = shadowPfn;
    entry->Active      = TRUE;
    Svm->HookMeta.ShadowUsed++;
    Svm->HookMeta.HookCount++;   // visible to NPF handler from this point

    // Now modify the NPT — any NPF that fires from here on finds the entry.
    // Read NCr3: original PFN, NX=1 so execution faults.
    if (!NptSplitTo4KB(&Svm->NestedPageTables, &Svm->HookRead,
                       TargetGpa4K, 0 /*identity PFN*/, TRUE /*NX*/))
    {
        // Read-side slot exhaustion. Un-publish the HookMeta entry.
        Svm->HookMeta.HookCount--;
        Svm->HookMeta.ShadowUsed--;
        entry->Active = FALSE;
        return 0;
    }

    // g_ShadowNcr3Pa is the active NCr3 for all guest CPUs (not g_ReadNcr3Pa).
    // It redirects PML4[0] to g_ShadowPdpt0 (a separate page from NestedPageTables.Pdpt[0]).
    // NptSplitTo4KB patched NestedPageTables.Pdpt[0][pdptIdx] to a PD pointer — but CPUs
    // walking g_ShadowNcr3Pa follow g_ShadowPdpt0 instead, bypassing that change.
    // Mirror the updated PDPE into g_ShadowPdpt0 so the NX is actually visible.
    if (g_ShadowNcr3Pa != 0 && g_ShadowPdpt0 != NULL)
    {
        ADDRESS_TRANSLATION_HELPER hookHelper;
        hookHelper.AsUInt64 = TargetGpa4K;
        if ((UINT32)hookHelper.AsIndex.Pml4 == 0)
        {
            UINT32 pdptI = (UINT32)hookHelper.AsIndex.Pdpt;
            g_ShadowPdpt0[pdptI] =
                Svm->NestedPageTables.Pdpt[0][pdptI].Uint64;
        }
    }

    // Exec NCr3: shadow PFN, NX=0 so hook code executes.
    if (!NptSplitTo4KB(&Svm->NptExec, &Svm->HookExec,
                       TargetGpa4K, shadowPfn, FALSE /*NX*/))
    {
        // Exec-side slot exhaustion. The read-side split is left in place
        // (the page is now NX under read NCr3 but has no shadow for exec).
        // Any exec on this page will NPF but the HookMeta entry has been
        // un-published, so the handler falls through to its default path.
        // This leaves one slot occupied in the read region without a matching
        // exec slot — acceptable tradeoff vs. trying to walk back the read
        // split which has already been loaded by other CPUs.
        Svm->HookMeta.HookCount--;
        Svm->HookMeta.ShadowUsed--;
        entry->Active = FALSE;
        return 0;
    }

    return shadowGpa;
}

/**
 * @brief Builds a fine-grained 4KB-granular region in the NPT around the
 *      LAPIC MMIO page, and patches the 1GB NPT entry containing it to
 *      reference this finer region. With R/W=0 set on the single 4KB LAPIC
 *      page, guest writes to LAPIC MMIO cause VMEXIT_NPF, which the Host.c
 *      NPF handler decodes (using DecodeAssists) and emulates.
 *
 *      Reads pass through transparently (R/W only intercepts writes).
 *
 *      Idempotent: callable once at ao init. LAPIC base is read from
 *      IA32_APIC_BASE MSR and cached in g_LapicBasePa.
 */
STATIC
VOID
SetupLapicNptIntercept (
    IN OUT PAGING_STRUCTURES* NestedPageTables,
    IN OUT NPT_LAPIC_REGION* Region
    )
{
    UINT64 apicBaseMsr;
    UINT64 lapicBase;
    UINT64 oneGbBase;       // 1GB-aligned base containing LAPIC
    UINT64 twoMbBase;       // 2MB-aligned base containing LAPIC
    UINT32 pml4Idx;
    UINT32 pdptIdx;
    UINT32 pdIdx;
    UINT32 ptIdx;
    UINT64 pa;

    //
    // Read LAPIC base from MSR. Bits 12+ are the physical address. Mask
    // to 4KB. Default architectural value is 0xFEE00000 but firmware may
    // remap (we observe whatever's actually programmed).
    //
    apicBaseMsr = AsmReadMsr64(0x1B);
    lapicBase = apicBaseMsr & ~(UINT64)0xFFF;
    g_LapicBasePa = lapicBase;

    //
    // Compute NPT indices for the LAPIC page.
    //   PML4 covers 512GB each (bits 39-47), PDPT 1GB (bits 30-38),
    //   PD 2MB (bits 21-29), PT 4KB (bits 12-20).
    //
    pml4Idx  = (UINT32)((lapicBase >> 39) & 0x1FF);
    pdptIdx  = (UINT32)((lapicBase >> 30) & 0x1FF);
    pdIdx    = (UINT32)((lapicBase >> 21) & 0x1FF);
    ptIdx    = (UINT32)((lapicBase >> 12) & 0x1FF);
    oneGbBase = lapicBase & ~(UINT64)0x3FFFFFFF;
    twoMbBase = lapicBase & ~(UINT64)0x1FFFFF;

    ZeroMem(Region, sizeof(*Region));

    //
    // Build the 4KB PT covering twoMbBase..twoMbBase+2MB. Default is identity
    // with R/W=1 (passthrough). The single PT entry for the LAPIC page gets
    // R/W=0 to cause NPF on writes.
    //
    pa = twoMbBase;
    for (UINT32 i = 0; i < PAGE_TABLE_ENTRY_COUNT; ++i)
    {
        Region->Pt[i].Bits.Valid = TRUE;
        Region->Pt[i].Bits.Write = TRUE;
        Region->Pt[i].Bits.User = TRUE;
        Region->Pt[i].Bits.PageFrameNumber = pa >> EFI_PAGE_SHIFT;
        pa += SIZE_4KB;
    }
    Region->Pt[ptIdx].Bits.Write = FALSE;  // catch LAPIC writes

    //
    // Build the 2MB PD covering oneGbBase..oneGbBase+1GB. Default entries
    // are 2MB pages (PS=1). The one containing LAPIC is special — points
    // to our 4KB PT (PS=0).
    //
    pa = oneGbBase;
    for (UINT32 i = 0; i < PAGE_TABLE_ENTRY_COUNT; ++i)
    {
        if (i == pdIdx)
        {
            // Points to the 4KB PT, not a 2MB leaf
            Region->Pd[i].Bits.Valid = TRUE;
            Region->Pd[i].Bits.Write = TRUE;
            Region->Pd[i].Bits.User = TRUE;
            Region->Pd[i].Bits.PageFrameNumber = (UINT64)&Region->Pt[0] >> EFI_PAGE_SHIFT;
            // bit 7 (LargePage on PDP) MUST be 0 for "points to PT" — handled
            // by the union layout: this PML4_ENTRY_2MB has no LargePage bit
        }
        else
        {
            // Regular 2MB-page leaf. Reuse PD_ENTRY_2MB layout to set PS=1.
            PD_ENTRY_2MB* pde = (PD_ENTRY_2MB*)&Region->Pd[i];
            pde->Uint64 = 0;
            pde->Bits.Valid = TRUE;
            pde->Bits.Write = TRUE;
            pde->Bits.User = TRUE;
            pde->Bits.LargePage = TRUE;
            pde->Bits.PageFrameNumber = pa >> 21;
        }
        pa += SIZE_2MB;
    }

    //
    // Replace the 1GB PDPT entry containing LAPIC with a pointer to our PD.
    // This drops the 1GB leaf in favor of 512 2MB pages (one of which is
    // further split into 4KB), giving 4KB granularity right at LAPIC.
    //
    {
        PDP_ENTRY_1GB* pdpe = &NestedPageTables->Pdpt[pml4Idx][pdptIdx];
        pdpe->Uint64 = 0;
        pdpe->Bits.Valid = TRUE;
        pdpe->Bits.Write = TRUE;
        pdpe->Bits.User = TRUE;
        pdpe->Bits.LargePage = FALSE;  // not a leaf
        // PageFrameNumber field is at bits [30:51]; for a directory pointer
        // we want bits [12:51]. The bits coincide with the entry's natural
        // bit positions, so we just shift by EFI_PAGE_SHIFT and place into
        // the 22-bit PFN field — but that loses the low 18 bits of the PFN.
        // Bypass: write the raw value.
        pdpe->Uint64 |= ((UINT64)&Region->Pd[0]) & 0x000FFFFFFFFFF000ULL;
    }
}

/**
 * @brief Host-only identity mapping: 512GB low + 512GB high-canonical mirror
 *      using 2MB pages. The high-canonical mirror (PML4[256..511]) is
 *      necessary because firmware on some boards keeps its stack and runtime
 *      data at high-canonical VAs (kernel-half), and host code returns to
 *      those VAs via RET after the CR3 swap. Without the mirror, RET #PFs.
 *      All 512 PML4 entries point at the SAME single PDPT — both low and high
 *      canonical VAs translate to the same identity PA mapping (0-512GB).
 */
STATIC
VOID
SetupHostIdentityMapping (
    OUT HOST_PAGING_STRUCTURES* PagingStructures
    )
{
    UINT64 pa;

    ZeroMem(PagingStructures, sizeof(*PagingStructures));

    // All 512 PML4 entries point to the same single PDPT. So low canonical
    // addresses (PML4 index 0..255) and high canonical (256..511) both
    // translate to identity in 0-512GB.
    for (UINT32 pml4Index = 0; pml4Index < PAGE_TABLE_ENTRY_COUNT; ++pml4Index)
    {
        PagingStructures->Pml4[pml4Index].Bits.Valid = TRUE;
        PagingStructures->Pml4[pml4Index].Bits.Write = TRUE;
        PagingStructures->Pml4[pml4Index].Bits.PageFrameNumber =
            (UINT64)&PagingStructures->Pdpt[0] >> EFI_PAGE_SHIFT;
    }

    // PDPT[i] -> Pd[i]
    pa = 0;
    for (UINT32 pdptIndex = 0; pdptIndex < PAGE_TABLE_ENTRY_COUNT; ++pdptIndex)
    {
        PML4_ENTRY_2MB* pdpte = &PagingStructures->Pdpt[pdptIndex];
        pdpte->Bits.Valid = TRUE;
        pdpte->Bits.Write = TRUE;
        pdpte->Bits.PageFrameNumber =
            (UINT64)&PagingStructures->Pd[pdptIndex][0] >> EFI_PAGE_SHIFT;

        // Each PD entry maps a 2MB large page.
        for (UINT32 pdIndex = 0; pdIndex < PAGE_TABLE_ENTRY_COUNT; ++pdIndex)
        {
            PD_ENTRY_2MB* pde = &PagingStructures->Pd[pdptIndex][pdIndex];
            pde->Bits.Valid = TRUE;
            pde->Bits.Write = TRUE;
            pde->Bits.LargePage = TRUE;
            pde->Bits.PageFrameNumber = pa >> 21;  // PFN at bits [21:51]
            pa += SIZE_2MB;
        }
    }
}

/**
 * @brief Initialize the system global host environment object.
 */
STATIC
VOID
InitializeHostSharedData (
    OUT SHARED_HOST_DATA* SharedHostData
    )
{
    UINT64 handlerBase;

    SharedHostData->ProcessorCount = GetActiveProcessorCount();

    //
    // Setup the identically page tables for the host.
    //
    SetupHostIdentityMapping(&SharedHostData->PagingStructures);
    SharedHostData->Cr3 = (UINT64)&SharedHostData->PagingStructures.Pml4[0];

    //
    // Get the beginning of the AsmDefaultExceptionHandlers to index.
    // Fill out all IDT entries.
    //
    handlerBase = (UINT64)&AsmDefaultExceptionHandlers;
    for (UINT32 i = 0; i < IDT_ENTRY_COUNT; ++i)
    {
        UINT64 sizeOfHandler;
        UINT64 handlerAddress;

        //
        // Compute the address of AsmDefaultExceptionHandlers[i]. Each stub
        // function is 9 bytes up to 0x7f, and 12 bytes after that.
        //
        if (i < 0x80)
        {
            sizeOfHandler = 9;
        }
        else
        {
            sizeOfHandler = 12;
        }
        handlerAddress = (handlerBase + i * sizeOfHandler);

        //
        // Fill out the IDT entry. The type is 32-bit Interrupt gate: 0x8E
        //  P=1, DPL=00b, S=0, type=1110b => type_attr=1000_1110b=0x8E)
        //
        SharedHostData->Idt[i].Bits.OffsetLow = (UINT16)handlerAddress;
        SharedHostData->Idt[i].Bits.OffsetHigh = (UINT16)(handlerAddress >> 16);
        SharedHostData->Idt[i].Bits.OffsetUpper = (UINT32)(handlerAddress >> 32);
        SharedHostData->Idt[i].Bits.Selector = AsmReadCs();
        SharedHostData->Idt[i].Bits.GateType = 0x8E;
    }

    SharedHostData->Idtr.Base = (UINT64)&SharedHostData->Idt[0];
    SharedHostData->Idtr.Limit = sizeof(SharedHostData->Idt) - 1;
}

/**
 * @brief Write-protects the hypervisor's own physical pages in the NPT so that
 *      guest writes to those pages (e.g., guest scanner kernel driver scanning/writing
 *      physical memory) cause VMEXIT_NPF instead of silently corrupting host
 *      stacks, VMCBs, or NPT tables.
 *
 *      HOST writes to these pages are unaffected — AMD-V NPT only gates guest
 *      physical accesses; host accesses bypass the NPT entirely.
 *
 *      On NPF for a write to a protected page, HandleNestedPageFault's existing
 *      "bad NPF" path injects #GP(0) into the guest. guest scanner handles the #GP and
 *      continues; the host stack is untouched.
 *
 *      Assumes ProtectBase..ProtectBase+ProtectSize fits within one 1GB region.
 */
STATIC
VOID
SetupHvNptProtect (
    IN OUT PAGING_STRUCTURES*   Npt,
    IN OUT NPT_HV_GUARD_REGION* Guard,
    IN     UINT64               ProtectBase,
    IN     UINT64               ProtectSize
    )
{
    UINT32 pml4Idx = (UINT32)((ProtectBase >> 39) & 0x1FF);
    UINT32 pdptIdx = (UINT32)((ProtectBase >> 30) & 0x1FF);
    UINT64 gbBase  = ((UINT64)pml4Idx << 39) | ((UINT64)pdptIdx << 30);
    UINT64 protectEnd = ProtectBase + ProtectSize;
    UINT32 ptSlot  = 0;
    UINT64 pa;

    //
    // Build a 2MB PD covering the full 1GB region (replacing the 1GB leaf entry).
    // For each 2MB slot: if it overlaps [ProtectBase, protectEnd), split it into
    // a 4KB PT with Write=0 on protected pages; otherwise make it a passthrough
    // 2MB identity leaf.
    //
    pa = gbBase;
    for (UINT32 pdIdx = 0; pdIdx < PAGE_TABLE_ENTRY_COUNT; ++pdIdx)
    {
        UINT64 slotEnd = pa + SIZE_2MB;

        if (pa < protectEnd && slotEnd > ProtectBase && ptSlot < HV_GUARD_MAX_PTS)
        {
            //
            // This 2MB overlaps the protected range. Build a 4KB PT.
            //
            PT_ENTRY_4KB* pt = Guard->Pt[ptSlot];
            UINT64 pa4k = pa;
            for (UINT32 i = 0; i < PAGE_TABLE_ENTRY_COUNT; ++i)
            {
                BOOLEAN protect = (pa4k >= ProtectBase && pa4k < protectEnd);
                pt[i].Bits.Valid           = TRUE;
                pt[i].Bits.Write           = !protect;   // R/O for HV pages
                pt[i].Bits.User            = TRUE;
                pt[i].Bits.PageFrameNumber = pa4k >> EFI_PAGE_SHIFT;
                pa4k += SIZE_4KB;
            }
            // PD entry points to this PT (non-leaf: LargePage/PS stays 0).
            Guard->Pd[pdIdx].Uint64 = 0;
            Guard->Pd[pdIdx].Bits.Valid           = TRUE;
            Guard->Pd[pdIdx].Bits.Write           = TRUE;
            Guard->Pd[pdIdx].Bits.User            = TRUE;
            Guard->Pd[pdIdx].Bits.PageFrameNumber = (UINT64)pt >> EFI_PAGE_SHIFT;
            ptSlot++;
        }
        else
        {
            // Passthrough 2MB leaf — identity-mapped, R/W=1.
            PD_ENTRY_2MB* pde = (PD_ENTRY_2MB*)&Guard->Pd[pdIdx];
            pde->Uint64               = 0;
            pde->Bits.Valid           = TRUE;
            pde->Bits.Write           = TRUE;
            pde->Bits.User            = TRUE;
            pde->Bits.LargePage       = TRUE;
            pde->Bits.PageFrameNumber = pa >> 21;
        }
        pa += SIZE_2MB;
    }

    //
    // Patch the 1GB PDPT entry to point to our PD instead of being a 1GB leaf.
    //
    {
        PDP_ENTRY_1GB* pdpe = &Npt->Pdpt[pml4Idx][pdptIdx];
        pdpe->Uint64 = 0;
        pdpe->Bits.Valid     = TRUE;
        pdpe->Bits.Write     = TRUE;
        pdpe->Bits.User      = TRUE;
        pdpe->Bits.LargePage = FALSE;   // non-leaf: points to PD
        pdpe->Uint64 |= (UINT64)Guard->Pd & 0x000FFFFFFFFFF000ULL;
    }
}

/**
 * @brief Initialize the root context object.
 */
STATIC
VOID
InitializeSharedContext (
    OUT ROOT_CONTEXT* Context
    )
{
    DEBUG((DEBUG_VERBOSE, "Root context at %p\n", Context));

    InitializeHostSharedData(&Context->HostX64);
    SetupIdentityMapping(&Context->Svm.NestedPageTables, TRUE);
    SetupLapicNptIntercept(&Context->Svm.NestedPageTables, &Context->Svm.LapicRegion);

    //
    // Build the MSR Permission Map. We only intercept x2APIC ICR writes
    // (MSR 0x830) so we can emulate INIT/SIPI delivery and bring APs up
    // properly. Everything else passes through.
    //
    // MSRPM layout (AMD APM Vol 2 §15.11):
    //   bytes 0x0000-0x07FF -> MSRs 0x00000000-0x00001FFF (section 1)
    //   bytes 0x0800-0x0FFF -> MSRs 0xC0000000-0xC0001FFF (section 2)
    //   bytes 0x1000-0x17FF -> MSRs 0xC0010000-0xC0011FFF (section 3)
    // Each MSR has 2 bits: bit 2*N+0 = read, 2*N+1 = write, within its byte.
    //
    // For MSR 0x830 in section 1:
    //   byte offset = 0x830 / 4    = 0x20C
    //   bit position for write     = (0x830 % 4) * 2 + 1 = 1
    //   so set bit 1 of byte 0x20C = 0x02
    //
    ZeroMem(Context->Svm.Msrpm, sizeof(Context->Svm.Msrpm));
    Context->Svm.Msrpm[0x20C] |= 0x02;   // x2APIC ICR (0x830) write intercept
    //
    // IA32_EFER (0xC0000080) read intercept. VMRUN requires EFER.SVME=1 in the
    // guest VMCB, so the guest would see SVME=1 via RDMSR and know a hypervisor
    // is present. We intercept the read and return the real EFER with SVME=0.
    //   Section 2 (0xC0000000-0xC0001FFF) starts at MSRPM byte 0x800.
    //   Index 0x80 within section: byte = 0x80/4 = 0x20 → abs byte 0x820.
    //   Read bit = (0x80 % 4) * 2 = 0 → bit 0.
    //
    Context->Svm.Msrpm[0x820] |= 0x03;   // IA32_EFER (0xC0000080) read+write intercept
    //
    // VM_CR (0xC0010114) read intercept. ao sets VM_CR.R_INIT=1 to redirect
    // INIT to #SX; on bare metal R_INIT=0. guest scanner can RDMSR this from ring-0 and
    // see the bit set. Section 3 (0xC0010000-0xC0011FFF) starts at byte 0x1000.
    //   Index 0x114: byte = 0x114/4 = 0x45 → abs 0x1045, bit = (0x114%4)*2 = 0.
    //
    // All four SVM MSRs (0xC0010114-0xC0010117) share byte 0x1045 in the MSRPM.
    // On bare metal with SVME=0 every access to these MSRs #GPs. Setting 0xFF
    // intercepts all four (VM_CR / IGNNE / SMM_CTL / VM_HSAVE_PA) for both
    // reads and writes so we can inject #GP rather than letting writes hit real
    // hardware (where SVME=1 — the write would silently succeed, which is
    // detectable). VM_CR and VM_HSAVE_PA reads are handled specially in
    // HandleMsr; everything else gets #GP(0).
    //   0x01/0x02 = VM_CR r/w  0x04/0x08 = IGNNE r/w
    //   0x10/0x20 = SMM_CTL r/w  0x40/0x80 = VM_HSAVE_PA r/w
    //
    Context->Svm.Msrpm[0x1045] = 0xFF;
}

/**
 * @brief Prevents the platform from relocating the image at boot-to-runtime
 *      transition.
 *
 * @details EDK2 relocates PE images of the runtime drivers based on their
 *      relocation information when prior to transition to runtime. This can
 *      host code as it never runs with the runtime page table and instead
 *      runs with the page tables that is equivalent to that of boot-time. This
 *      brokage can be observed as #PF on assertion failure in the host for
 *      example. This function nullifies the NT header to make the platform fail
 *      to find relocation information of this module. For why this works, see
 *      RuntimeDriverSetVirtualAddressMap in the EDK2 repo.
 */
STATIC
VOID
SuppressImageRelocation (
    IN UINT64 ImageBase
    )
{
    EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION hdr;
    EFI_IMAGE_DOS_HEADER* dosHdr;

    dosHdr = (EFI_IMAGE_DOS_HEADER*)ImageBase;
    ASSERT(dosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE);

    hdr.Pe32Plus = (EFI_IMAGE_NT_HEADERS64*)(((CHAR8*)dosHdr) + dosHdr->e_lfanew);
    ASSERT(hdr.Pe32Plus->Signature == EFI_IMAGE_NT_SIGNATURE);

    //
    // Zero the relocation directory entry in the PE optional header. This
    // tells UEFI's SetVirtualAddressMap path "no base relocations to apply".
    // Without this, when Windows boot loader transitions to virtual mode,
    // UEFI would patch our driver's code in-place, corrupting the running
    // host code (which keeps using physical-mode addresses via our own page
    // tables). Mirrors barevisor's zap_relocation_table.
    //
    // (Previously zeroed the entire PE signature — too aggressive; UEFI may
    // bail on broken PE rather than just skip relocation.)
    //
    hdr.Pe32Plus->OptionalHeader.DataDirectory[
        EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
    hdr.Pe32Plus->OptionalHeader.DataDirectory[
        EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
}

/**
 * @brief Checks whether the system is compatible with this project.
 */
STATIC
BOOLEAN
IsSystemCompatible (
    VOID
    )
{
    UINT32 regEbx;
    UINT32 regEcx;
    UINT32 regEdx;
    CPUID_AMD_EXTENDED_CPU_SIG_ECX extendedSig;
    MSR_IA32_PAT_REGISTER pat;

    //
    // Test if the current processor is AMD one. An AMD processor should return
    // "AuthenticAMD" from CPUID function 0. See "Function 0h-Maximum Standard
    // Function Number and Vendor String".
    //
    AsmCpuid(CPUID_SIGNATURE, NULL, &regEbx, &regEcx, &regEdx);
    if ((regEbx != CPUID_SIGNATURE_AUTHENTIC_AMD_EBX) ||
        (regEcx != CPUID_SIGNATURE_AUTHENTIC_AMD_ECX) ||
        (regEdx != CPUID_SIGNATURE_AUTHENTIC_AMD_EDX))
    {
        DEBUG((DEBUG_ERROR, "Not an AMD processor\n"));
        return FALSE;
    }

    //
    // Test if the SVM feature is supported by the current processor. See
    // "Enabling SVM" and "CPUID Fn8000_0001_ECX Feature Identifiers".
    //
    AsmCpuid(CPUID_EXTENDED_CPU_SIG, NULL, NULL, &extendedSig.Uint32, NULL);
    if (extendedSig.Bits.SVM == 0)
    {
        DEBUG((DEBUG_ERROR, "AMD-V not supported\n"));
        return FALSE;
    }

    //
    // Test if the Nested Page Tables and Next-RIP-Save features are supported by
    // the current processor. NRIPS is required because VMMCALL and CPUID handlers
    // advance RIP using ControlArea.NRip. See "Enabling Nested Paging" and "CPUID
    // Fn8000_000A_EDX SVM Feature Identification".
    //
    AsmCpuid(CPUID_SVM_FEATURES, NULL, NULL, NULL, &regEdx);
    if ((regEdx & CPUID_SVM_FEATURES_EDX_NP) == 0)
    {
        DEBUG((DEBUG_ERROR, "Nested page tables not supported\n"));
        return FALSE;
    }
    if ((regEdx & CPUID_SVM_FEATURES_EDX_NRIPS) == 0)
    {
        DEBUG((DEBUG_ERROR, "NRIPS not supported\n"));
        return FALSE;
    }

    //
    // Test if the SVM feature can be enabled. When VM_CR.SVMDIS is set,
    // EFER.SVME cannot be 1; therefore, SVM cannot be enabled. We deliberately
    // set VM_CR.R_INIT=1 ourselves later (INIT -> #SX redirect pattern), so
    // it's fine if firmware already has it set.
    //
    {
        UINT64 vmCr = AsmReadMsr64(SVM_MSR_VM_CR);
        if ((vmCr & VM_CR_SVMDIS) != 0)
        {
            DEBUG((DEBUG_ERROR, "AMD-V cannot be enabled\n"));
            return FALSE;
        }
    }

    //
    // This project expects the PAT register to have the default value,
    // specifically that PA0 indicates the write-back type. This is solely to
    // simplify page table structures setup. See "7.8.2 PAT Indexing".
    //
    pat.Uint64 = AsmReadMsr64(MSR_IA32_PAT);
    if (pat.Bits.PA0 != MTRR_CACHE_WRITE_BACK)
    {
        DEBUG((DEBUG_ERROR, "PAT register#0 is not configured for write back\n"));
        return FALSE;
    }

    return TRUE;
}

/**
 * @brief Find the image base address of the given address.
 */
STATIC
UINT64
GetImageBase (
    IN UINT64 SearchBaseAddress
    )
{
    UINT64 base;

    base = SearchBaseAddress & ~EFI_PAGE_MASK;
    for (UINT32 i = 0; i < 0x100; ++i)
    {
        if (*(UINT16*)base == EFI_IMAGE_DOS_SIGNATURE)
        {
            return base;
        }

        base -= SIZE_4KB;
    }
    return 0;
}

/**
 * @brief The entry point of this driver.
 */
EFI_STATUS
EFIAPI
aoInitialize (
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE* SystemTable
    )
{
    EFI_STATUS status;
    UINT64 imageBase;
    UINT64 allocBytes;
    ROOT_CONTEXT* context;

    context = NULL;

    //
    // Find the image base address and debug print it. This is useful for debugging.
    //
    imageBase = GetImageBase((UINT64)&aoInitialize);
    ASSERT(imageBase != 0);

    DEBUG((DEBUG_VERBOSE, "Loading the driver at %llx\n", imageBase));

    //
    // Clear stale diagnostic NVRAM so this boot's data is distinguishable
    // from previous boots. RecordMilestone with 0 sets aoMilestone=0; we
    // also explicitly clear aoProgress and aoException by writing zeros.
    //
    {
        UINT32 zero32 = 0;
        UINT64 zero64 = 0;
        if (gRT != NULL && gRT->SetVariable != NULL)
        {
            gRT->SetVariable(L"aoProgress", &g_MilestoneGuid,
                             EFI_VARIABLE_NON_VOLATILE |
                             EFI_VARIABLE_BOOTSERVICE_ACCESS |
                             EFI_VARIABLE_RUNTIME_ACCESS,
                             sizeof(zero32), &zero32);
            gRT->SetVariable(L"aoExitCode", &g_MilestoneGuid,
                             EFI_VARIABLE_NON_VOLATILE |
                             EFI_VARIABLE_BOOTSERVICE_ACCESS |
                             EFI_VARIABLE_RUNTIME_ACCESS,
                             sizeof(zero64), &zero64);
            gRT->SetVariable(L"aoException", &g_MilestoneGuid,
                             EFI_VARIABLE_NON_VOLATILE |
                             EFI_VARIABLE_BOOTSERVICE_ACCESS |
                             EFI_VARIABLE_RUNTIME_ACCESS,
                             sizeof(zero32), &zero32);
        }
    }

    //
    // Make sure the system has supported hardware and system configurations.
    //
    if (IsSystemCompatible() == FALSE)
    {
        status = EFI_UNSUPPORTED;
        goto Exit;
    }

    //
    // Make the MP protocol available for use.
    //
    status = gBS->LocateProtocol(&gEfiMpServiceProtocolGuid,
                                 NULL,
                                 (VOID**)&g_MpServices);
    if (EFI_ERROR(status))
    {
        DEBUG((DEBUG_ERROR, "MP protocol unsupported : %r\n", status));
        goto Exit;
    }

    //
    // Allocate and initialize the global context object, then virtualize all
    // processors.
    //
    allocBytes = sizeof(ROOT_CONTEXT) + GetActiveProcessorCount() * sizeof(PER_CPU_DATA);
    context = AllocateReservedPages(EFI_SIZE_TO_PAGES(allocBytes));
    if (context == NULL)
    {
        status = EFI_OUT_OF_RESOURCES;
        goto Exit;
    }
    ZeroMem(context, allocBytes);
    InitializeSharedContext(context);

    //
    // Allocate a zero decoy page. At every VMEXIT we point VMCB.NCr3 and
    // VMCB.MsrpmBasePa here (guest is suspended, so no functional impact).
    // A physical-memory scanner reading the VMCB mid-VMEXIT sees a bare
    // zero NPT and empty MSRPM instead of our real structures. Restored to
    // real values just before VMRUN.
    //
    {
        VOID* decoyPage = AllocateReservedPages(1);
        if (decoyPage != NULL)
        {
            ZeroMem(decoyPage, SIZE_4KB);
            g_DecoyPagePa = (UINT64)(UINTN)decoyPage;
        }
    }

    //
    // Allocate the syscall ring buffer here, during DXE init, while boot
    // services are still available. AllocateReservedPages cannot be called
    // from the VMEXIT handler (post-ExitBootServices → immediate crash),
    // so we pre-allocate it even if the user never enables syscall logging.
    //
    {
        UINTN pages = EFI_SIZE_TO_PAGES(sizeof(SYSCALL_LOG));
        g_SyscallLog = (SYSCALL_LOG*)AllocateReservedPages(pages);
        if (g_SyscallLog != NULL)
            ZeroMem(g_SyscallLog, sizeof(SYSCALL_LOG));
    }

    //
    // Process-hook table + debug log. Same story: must be allocated here
    // (boot-services alive). Both are optional; failure just means the
    // register-hook hypercall will refuse until next boot.
    //
    {
        UINTN pages;
        pages = EFI_SIZE_TO_PAGES(sizeof(PROCESS_HOOK_TABLE));
        g_ProcessHooks = (PROCESS_HOOK_TABLE*)AllocateReservedPages(pages);
        if (g_ProcessHooks != NULL)
            ZeroMem(g_ProcessHooks, sizeof(PROCESS_HOOK_TABLE));

        pages = EFI_SIZE_TO_PAGES(sizeof(PROCESS_HOOK_LOG));
        g_ProcessHookLog = (PROCESS_HOOK_LOG*)AllocateReservedPages(pages);
        if (g_ProcessHookLog != NULL)
            ZeroMem(g_ProcessHookLog, sizeof(PROCESS_HOOK_LOG));
    }

    //
    // Write-protect the hypervisor's own physical pages in the NPT. Any guest
    // write to these pages (e.g., guest scanner's kernel driver scanning/patching physical
    // memory) will VMEXIT_NPF instead of silently corrupting host stacks or
    // VMCBs. HandleNestedPageFault's bad-NPF path injects #GP(0) to the guest.
    //
    SetupHvNptProtect(
        &context->Svm.NestedPageTables,
        &context->Svm.HvGuard,
        (UINT64)(UINTN)context,
        (UINT64)allocBytes
    );
    g_HvGuardBase = (UINT64)(UINTN)context;
    g_HvGuardSize = (UINT64)allocBytes;

    // Log ROOT_CONTEXT physical base+size to ExtCMOS 0x8B-0x96 for ReadScratch.
    // Single-threaded init path — no lock needed, write directly to port 0x72/0x73.
    for (UINT8 i = 0; i < 8; i++) {
        IoWrite8(0x72, (UINT8)(0x8B + i));
        IoWrite8(0x73, (UINT8)(g_HvGuardBase >> (i * 8)));
    }
    for (UINT8 i = 0; i < 4; i++) {
        IoWrite8(0x72, (UINT8)(0x93 + i));
        IoWrite8(0x73, (UINT8)(g_HvGuardSize >> (i * 8)));
    }

    // Build exec NCr3 as a copy of the now-final read NCr3 (LAPIC + HvGuard
    // PDPT patches are included in the copy).  g_ReadNcr3Pa / g_ExecNcr3Pa
    // are set here so HandleNestedPageFault can use them immediately.
    SetupNptExec(&context->Svm);

    //
    // Shadow NCr3: use the NcShadowPml4/NcShadowPdpt0 pages embedded in
    // SHARED_SVM_DATA as the shadow PML4+PDPT[0] that VMCB.NCr3 will point to
    // during VMRUN.  guest scanner reads VMCB.NCr3, walks the shadow, and tries to corrupt
    // shadow entries (e.g. set NX=1 on PDPT[0][4]).  Because both pages are inside
    // ROOT_CONTEXT, SetupHvNptProtect has already marked their NPT entries W=0;
    // guest write NPFs to these pages are silently dropped by HandleNestedPageFault
    // rather than landing on the real NestedPageTables or triggering a BSOD.
    // Host (VMM) writes bypass the NPT and are unaffected.
    //
    {
        UINT64* sPml4  = context->Svm.NcShadowPml4;
        UINT64* sPdpt0 = context->Svm.NcShadowPdpt0;

        // Copy the real PML4 as the base; shadow PML4[i] initially points to
        // the real PDPT[i] pages (which are also HvGuard-protected).
        CopyMem(sPml4, context->Svm.NestedPageTables.Pml4, SIZE_4KB);

        // Copy real PDPT[0] into the shadow — guest scanner walks here to find PDPT[0][4].
        // Guest writes to this shadow page are dropped by HvGuard.
        CopyMem(sPdpt0, context->Svm.NestedPageTables.Pdpt[0], SIZE_4KB);

        // Redirect shadow PML4[0] to the shadow PDPT[0] page.
        UINT64 sPdpt0Pa  = (UINT64)(UINTN)sPdpt0;
        UINT64 pml4Flags = sPml4[0] & 0xFFFULL;   // keep P/RW/US/etc from real entry
        sPml4[0] = (sPdpt0Pa & ~0xFFFULL) | pml4Flags;

        g_ShadowNcr3Pa = (UINT64)(UINTN)sPml4;
        g_ShadowPdpt0  = sPdpt0;
    }

    InitializeHostDebugFacility(context);

    RunOnAllProcessors(VirtualizeProcessor, context);

    //
    // Finally, prevent from relocation happening.
    //
    SuppressImageRelocation(imageBase);
    status = EFI_SUCCESS;

Exit:
    if (EFI_ERROR(status))
    {
        if (context != NULL)
        {
            FreePages(context, EFI_SIZE_TO_PAGES(allocBytes));
        }
    }
    return status;
}
