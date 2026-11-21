/**
 * @file ao.h
 *
 * @brief The header to be included from all complation units (global definitions).
 *
 * @author Satoshi Tanda
 *
 * @copyright Copyright (c) 2020, Satoshi Tanda. All rights reserved.
 */
#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/IoLib.h>
#include <Library/LocalApicLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/MtrrLib.h>
#include <Library/PrintLib.h>
#include <Library/SynchronizationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiRuntimeLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Pi/PiMultiPhase.h>
#include <Protocol/MpService.h>
#include <Register/Amd/Cpuid.h>
#include <Register/Amd/Msr.h>
#include <Register/Intel/Cpuid.h>
#include <Register/Intel/LocalApic.h>
#include "Svm.h"

//
// Compile time customizations.
//
#define ENABLE_HOST_MEMORY_LOGGING                  1
#define ENABLE_EXPERIMENTAL_HOST_EFI_VAR_LOGGING    0

//
// MSVC intrinsics.
//
VOID __svm_clgi(VOID);
VOID __svm_invlpga(IN VOID* VirtualAddress, IN UINT32 Asid);
VOID __svm_skinit(IN UINT32 SlbPhysicalAddress);
VOID __svm_stgi(VOID);
VOID __svm_vmload(IN UINTN VmcbPhysicalAddress);
VOID __svm_vmrun(IN UINTN VmcbPhysicalAddress);
VOID __svm_vmsave(IN UINTN VmcbPhysicalAddress);
unsigned long __segmentlimit(IN unsigned long SegmentSelector);

//
// General architectural CPUID and MSR(s).
//
#define EFER_SVME                                   (1UL << 12)
#define CPUID_SVM_FEATURES                          0x8000000a
#define CPUID_SVM_FEATURES_EDX_NP                   BIT0
#define CPUID_SVM_FEATURES_EDX_NRIPS                BIT3
#define CPUID_EXTENDED_CPU_SIG_ECX_SVM              BIT2
#define CPUID_FN0000_0001_ECX_HYPERVISOR_PRESENT    (1UL << 31)

//
// Hyper-V Hypervisor Top-Level Functional Specification (TLFS) related.
//
#define CPUID_HV_VENDOR_AND_MAX_FUNCTIONS   ((UINT32)0x40000000)
#define CPUID_HV_INTERFACE                  ((UINT32)0x40000001)
#define CPUID_HV_MAX                        CPUID_HV_INTERFACE

//
// The entry count in the single paging structure table.
//
#define PAGE_TABLE_ENTRY_COUNT     512

//
// The helper union to split the 64bit value into indexes used to select page
// table entries.
//
typedef union _ADDRESS_TRANSLATION_HELPER
{
    struct
    {
        UINT64 Unused : 12;         //< [11:0]
        UINT64 Pt : 9;              //< [20:12]
        UINT64 Pd : 9;              //< [29:21]
        UINT64 Pdpt : 9;            //< [38:30]
        UINT64 Pml4 : 9;            //< [47:39]
    } AsIndex;
    UINT64 AsUInt64;
} ADDRESS_TRANSLATION_HELPER;

//
// See "2-Mbyte PML4E-Long Mode" and "2-Mbyte PDPE-Long Mode".
//
typedef union _PML4_ENTRY_2MB
{
    struct
    {
        UINT64 Valid : 1;               // [0]
        UINT64 Write : 1;               // [1]
        UINT64 User : 1;                // [2]
        UINT64 WriteThrough : 1;        // [3]
        UINT64 CacheDisable : 1;        // [4]
        UINT64 Accessed : 1;            // [5]
        UINT64 Reserved1 : 3;           // [6:8]
        UINT64 Avl : 3;                 // [9:11]
        UINT64 PageFrameNumber : 40;    // [12:51]
        UINT64 Reserved2 : 11;          // [52:62]
        UINT64 NoExecute : 1;           // [63]
    } Bits;
    UINT64 Uint64;
} PML4_ENTRY_2MB, *PPML4_ENTRY_2MB,
  PDP_ENTRY_2MB, *PPDP_ENTRY_2MB;
STATIC_ASSERT(sizeof(PML4_ENTRY_2MB) == 8, "PML4_ENTRY_1GB Size Mismatch");

//
// See "2-Mbyte PDE-Long Mode".
//
typedef union _PD_ENTRY_2MB
{
    struct
    {
        UINT64 Valid : 1;               // [0]
        UINT64 Write : 1;               // [1]
        UINT64 User : 1;                // [2]
        UINT64 WriteThrough : 1;        // [3]
        UINT64 CacheDisable : 1;        // [4]
        UINT64 Accessed : 1;            // [5]
        UINT64 Dirty : 1;               // [6]
        UINT64 LargePage : 1;           // [7]
        UINT64 Global : 1;              // [8]
        UINT64 Avl : 3;                 // [9:11]
        UINT64 Pat : 1;                 // [12]
        UINT64 Reserved1 : 8;           // [13:20]
        UINT64 PageFrameNumber : 31;    // [21:51]
        UINT64 Reserved2 : 11;          // [52:62]
        UINT64 NoExecute : 1;           // [63]
    } Bits;
    UINT64 Uint64;
} PD_ENTRY_2MB, *PPD_ENTRY_2MB;
STATIC_ASSERT(sizeof(PD_ENTRY_2MB) == 8, "PDE_ENTRY_2MB Size Mismatch");

//
// See "4-Kbyte PTE—Long Mode".
//
typedef union _PT_ENTRY_4KB
{
    struct
    {
        UINT64 Valid : 1;               // [0]
        UINT64 Write : 1;               // [1]
        UINT64 User : 1;                // [2]
        UINT64 WriteThrough : 1;        // [3]
        UINT64 CacheDisable : 1;        // [4]
        UINT64 Accessed : 1;            // [5]
        UINT64 Dirty : 1;               // [6]
        UINT64 Pat : 1;                 // [7]
        UINT64 Global : 1;              // [8]
        UINT64 Avl : 3;                 // [9:11]
        UINT64 PageFrameNumber : 40;    // [12:51]
        UINT64 Reserved2 : 11;          // [52:62]
        UINT64 NoExecute : 1;           // [63]
    } Bits;
    UINT64 Uint64;
} PT_ENTRY_4KB;
STATIC_ASSERT(sizeof(PT_ENTRY_4KB) == 8, "PT_ENTRY_4KB Size Mismatch");

//
// 1GB-page PDPT entry. PFN occupies bits [30:51] because each entry maps a
// 1GB region. PS bit (LargePage, bit 7) marks this as a leaf instead of a
// pointer to a PD. See AMD APM Vol 2 "1GB PDPE" layout.
//
typedef union _PDP_ENTRY_1GB
{
    struct
    {
        UINT64 Valid : 1;               // [0]
        UINT64 Write : 1;               // [1]
        UINT64 User : 1;                // [2]
        UINT64 WriteThrough : 1;        // [3]
        UINT64 CacheDisable : 1;        // [4]
        UINT64 Accessed : 1;            // [5]
        UINT64 Dirty : 1;               // [6]
        UINT64 LargePage : 1;           // [7] must be 1 for 1GB page
        UINT64 Global : 1;              // [8]
        UINT64 Avl : 3;                 // [9:11]
        UINT64 Pat : 1;                 // [12]
        UINT64 Reserved1 : 17;          // [13:29]
        UINT64 PageFrameNumber : 22;    // [30:51]
        UINT64 Reserved2 : 11;          // [52:62]
        UINT64 NoExecute : 1;           // [63]
    } Bits;
    UINT64 Uint64;
} PDP_ENTRY_1GB;
STATIC_ASSERT(sizeof(PDP_ENTRY_1GB) == 8, "PDP_ENTRY_1GB Size Mismatch");

//
// NPT paging structures: 256TB coverage with 1GB pages. Needed because real
// motherboards place PCIe MMIO BARs at very high physical addresses
// (~992GB observed on the test board); a 512GB-only mapping NPFs there.
// Memory: 4KB PML4 + 512 * 4KB PDPTs = ~2MB.
//
typedef struct _PAGING_STRUCTURES
{
    PML4_ENTRY_2MB Pml4[PAGE_TABLE_ENTRY_COUNT];
    PDP_ENTRY_1GB Pdpt[PAGE_TABLE_ENTRY_COUNT][PAGE_TABLE_ENTRY_COUNT];
} PAGING_STRUCTURES;
STATIC_ASSERT((OFFSET_OF(PAGING_STRUCTURES, Pdpt) % SIZE_4KB) == 0, "Must be 4KB aligned");

//
// Fine-grained NPT region for catching writes to the LAPIC MMIO page in
// xAPIC mode. We split one PDPT entry (the 1GB containing LAPIC, normally
// at 3-4GB so PDPT[0][3]) into 512 2MB pages (Pd), then one of those into
// 512 4KB pages (Pt). The 4KB page containing LAPIC (typically 0xFEE00000)
// gets R/W=0 so writes cause VMEXIT_NPF; all other entries in this region
// remain identity-mapped with R/W=1 (transparent passthrough). Memory: 8KB.
//
typedef struct _NPT_LAPIC_REGION
{
    PT_ENTRY_4KB Pt[PAGE_TABLE_ENTRY_COUNT];
    PML4_ENTRY_2MB Pd[PAGE_TABLE_ENTRY_COUNT];
} NPT_LAPIC_REGION;
STATIC_ASSERT((OFFSET_OF(NPT_LAPIC_REGION, Pt) % SIZE_4KB) == 0, "Must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(NPT_LAPIC_REGION, Pd) % SIZE_4KB) == 0, "Must be 4KB aligned");

//
// Split-page hook infrastructure.
// Two NPT contexts (read and exec) allow the same GPA to map different PFNs
// depending on whether the access is a data read or an instruction fetch.
// Read NCr3 (default): hooked page -> original PFN, NX=1 (execute causes NPF).
// Exec NCr3 (shadow):  hooked page -> shadow PFN, NX=0 (execute sees hook code).
// On exec NPF: switch VMCB.NCr3 to exec NCr3, re-execute.
// On AO_CMD_NCR3_SWITCH_READ hypercall: switch back to read NCr3.
// Supports up to NPT_MAX_HOOKS hooks, spanning up to 2 distinct 2MB regions per
// NPT_HOOK_REGION (one PT slot each).
// Shadow pages are pre-allocated at HV init; caller initialises their content.
//
#define NPT_MAX_HOOKS       8
#define NPT_SHADOW_COUNT    8

typedef struct _NPT_HOOK_ENTRY
{
    UINT64  Gpa4K;          // 4KB-aligned guest physical address that is hooked
    UINT64  OriginalPfn;    // PFN of the original guest page
    UINT64  ShadowPfn;      // PFN of the pre-allocated shadow page
    BOOLEAN Active;
    UINT8   Pad[7];
} NPT_HOOK_ENTRY;
STATIC_ASSERT(sizeof(NPT_HOOK_ENTRY) == 32, "NPT_HOOK_ENTRY must be 32 bytes");

//
// Fine-grained NPT region supporting up to NPT_HOOK_SLOT_COUNT hooked 4KB
// pages in different 2MB regions within one 1GB PDPT entry. Pd covers the
// full 1GB with 2MB leaves; each hooked 2MB region gets its own PT slot.
// TwoMbBase[s] records which 2MB-aligned GPA range each slot covers; 0 means
// unused.
//
#define NPT_HOOK_SLOT_COUNT 16
// How many DISTINCT 1GB GPA regions can be hooked at once. Each 1GB region
// needs its own 4KB PD because PDEs describe 2MB leaves within exactly ONE
// 1GB range; if we tried to share a PD across 1GBs, the second install's
// 2MB-leaf fill would overwrite the first 1GB's PFNs. See multi-hook BSOD
// root-cause notes in project memory.
#define NPT_HOOK_1GB_SLOT_COUNT 8
typedef struct _NPT_HOOK_REGION
{
    PT_ENTRY_4KB   PtArr[NPT_HOOK_SLOT_COUNT][PAGE_TABLE_ENTRY_COUNT];       // 16 × 4KB  (one PT per 2MB slot)
    PML4_ENTRY_2MB Pd   [NPT_HOOK_1GB_SLOT_COUNT][PAGE_TABLE_ENTRY_COUNT];   //  8 × 4KB  (one PD per 1GB slot)
    UINT64         TwoMbBase[NPT_HOOK_SLOT_COUNT];                            // 16 × 8 =  128 B
    UINT64         OneGbBase[NPT_HOOK_1GB_SLOT_COUNT];                        //  8 × 8 =   64 B
    // The slot metadata total is 128 + 64 = 192 B; pad up to a whole page.
    UINT8          Pad[SIZE_4KB - (NPT_HOOK_SLOT_COUNT + NPT_HOOK_1GB_SLOT_COUNT) * sizeof(UINT64)];
} NPT_HOOK_REGION;
STATIC_ASSERT(sizeof(NPT_HOOK_REGION) ==
              (NPT_HOOK_SLOT_COUNT + NPT_HOOK_1GB_SLOT_COUNT + 1) * SIZE_4KB,
              "NPT_HOOK_REGION size");
STATIC_ASSERT((OFFSET_OF(NPT_HOOK_REGION, PtArr) % SIZE_4KB) == 0, "NPT_HOOK_REGION.PtArr 4KB");
STATIC_ASSERT((OFFSET_OF(NPT_HOOK_REGION, Pd)    % SIZE_4KB) == 0, "NPT_HOOK_REGION.Pd 4KB");

//
// Single 4KB page of hook metadata: hook entries, counters, NCr3 PAs.
// Stored inside SHARED_SVM_DATA so it's host-accessible via identity map.
//
typedef struct _NPT_HOOK_META
{
    UINT32          HookCount;                          // number of active hooks
    UINT32          ShadowUsed;                         // shadow pages allocated
    UINT64          ReadNcr3Pa;                         // = &NestedPageTables.Pml4
    UINT64          ExecNcr3Pa;                         // = &NptExec.Pml4
    NPT_HOOK_ENTRY  Hooks[NPT_MAX_HOOKS];               // 8 × 32 = 256 bytes
    UINT8           Reserved[SIZE_4KB - 4 - 4 - 8 - 8 - NPT_MAX_HOOKS * 32];
} NPT_HOOK_META;
STATIC_ASSERT(sizeof(NPT_HOOK_META) == SIZE_4KB, "NPT_HOOK_META must be 4KB");

//
// Host paging structures: identical layout to barevisor's PagingStructuresRaw.
// Only PML4[0] used -> 1 PDPT -> 512 PDs with 2MB pages. Total coverage:
// 512GB. Memory: 4KB PML4 + 4KB PDPT + 512 * 4KB PDs = 2MB + 8KB. The
// host code/data all lives well within 512GB (driver image low, allocated
// runtime memory low), so 512GB is enough for host paging. Mirroring
// barevisor's exact layout maximizes chance of working on hardware where
// our 256TB / 1GB-page layout doesn't.
//
typedef struct _HOST_PAGING_STRUCTURES
{
    PML4_ENTRY_2MB Pml4[PAGE_TABLE_ENTRY_COUNT];
    PML4_ENTRY_2MB Pdpt[PAGE_TABLE_ENTRY_COUNT];
    PD_ENTRY_2MB Pd[PAGE_TABLE_ENTRY_COUNT][PAGE_TABLE_ENTRY_COUNT];
} HOST_PAGING_STRUCTURES;
STATIC_ASSERT((OFFSET_OF(HOST_PAGING_STRUCTURES, Pdpt) % SIZE_4KB) == 0, "Must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(HOST_PAGING_STRUCTURES, Pd) % SIZE_4KB) == 0, "Must be 4KB aligned");

//
// Single memory log entry.
//
typedef struct _MEMORY_LOG_ENTRY
{
    UINT32 GlobalIndex;
    CHAR8 Message[60];
} MEMORY_LOG_ENTRY;

//
// 4KB memory log entry buffer allocated for each processor.
//
typedef struct _MEMORY_LOGS
{
    volatile UINT32 NextPosition;
    UINT8 Reserved1[12];
    MEMORY_LOG_ENTRY Entries[(SIZE_4KB - 16) / sizeof(MEMORY_LOG_ENTRY)];
    UINT8 Reserved2[48];
} MEMORY_LOGS;
STATIC_ASSERT(sizeof(MEMORY_LOGS) == SIZE_4KB, "Must be 4KB aligned");

//
// The layout of the variables stored in the host stack.
//
typedef struct _HOST_STACK_BASED_PARAMETERS
{
    UINT64 GuestVmcbPa;
    struct _ROOT_CONTEXT* SharedContext;
    UINT32 ProcessorNumber;
    UINT32 Reserved1;
} HOST_STACK_BASED_PARAMETERS;

//
// The layout of the whole host stack where the size is defined by HOST_STACK_SIZE.
//
#define HOST_STACK_SIZE   SIZE_8KB
typedef union _HOST_STACK
{
    //
    //  Low     HostStackLimit[0]                      StackLimit
    //  ^       ...
    //  ^       HostStackLimit[HOST_STACK_SIZE - 2]    StackBase
    //  High    HostStackLimit[HOST_STACK_SIZE - 1]    StackBase
    //
    UINT8 HostStackLimit[HOST_STACK_SIZE];
    struct
    {
        //
        // Available for the hypervisor to freely use.
        //
        UINT8 AvailableAsStack[HOST_STACK_SIZE - sizeof(HOST_STACK_BASED_PARAMETERS)];

        //
        // Set up by the kernel-mode code before starting the hypervisor.
        // The hypervisor never overwrites this contents.
        //
        HOST_STACK_BASED_PARAMETERS Params;
    } Layout;
} HOST_STACK;
STATIC_ASSERT(sizeof(HOST_STACK) == HOST_STACK_SIZE, "Must be 4KB aligned");

//
// Guest General Purpose Registers (GPRs) created on VM-exit from the guest
// state and write back to the guest on VM-entry.
//
typedef struct _GUEST_REGISTERS
{
    UINT64 R15;
    UINT64 R14;
    UINT64 R13;
    UINT64 R12;
    UINT64 R11;
    UINT64 R10;
    UINT64 R9;
    UINT64 R8;
    UINT64 Rdi;
    UINT64 Rsi;
    UINT64 Rbp;
    UINT64 Rbx;
    UINT64 Rdx;
    UINT64 Rcx;
    UINT64 Rax;
} GUEST_REGISTERS;

//
// SMP coordination state. APs cycle through these as Windows brings them
// up via INIT-SIPI-SIPI. With InterceptMisc1.INIT and x2APIC ICR MSR
// interception, we drive this state machine manually.
//
//   RUNNING       — normal: VMRUN normally
//   WAIT_FOR_SIPI — INIT was received and processed; this AP is parked
//                    in HandleVmExit spinning, waiting for BSP to write
//                    SIPI to LAPIC ICR (which our MSR handler catches
//                    and translates to a VMCB modification + state flip)
//
#define AP_STATE_RUNNING            0u
#define AP_STATE_WAIT_FOR_SIPI      1u

//
// Collection of book keeping state variables the virtual processor.
//
typedef struct _GUEST_STATE
{
    UINT32 ProcessorNumber;
    UINT32 ApicId;
    GUEST_REGISTERS* Registers;
    volatile UINT32 ApState;        // AP_STATE_*
    volatile UINT32 SipiVector;     // Set by BSP's SIPI handler before flipping ApState
    volatile UINT32 LapicFlushPending; // Set when LAPIC page is un-protected; this
                                       // CPU flushes its NPT TLB once, then clears.
    UINT8 NptMode;                  // 0 = read NCr3 (default), 1 = exec NCr3 (hook active)
    volatile UINT8  NCr3UpdatePending; // 1 = apply NCr3PendingValue on next VMexit
    UINT8           ExpectDbForFlipBack; // 1 = next #DB on this CPU is ours (Option-7 flip-back)
    UINT8           GuestSavedRflagsTf;  // Snapshot of guest EFLAGS.TF at PhArmExecFlipWithSingleStep
    UINT8           GuestSavedRflagsIf;  // Snapshot of guest EFLAGS.IF (we clear it during single-step)
    UINT8           Pad[4];             // keep NCr3PendingValue UINT64-aligned
    volatile UINT64 NCr3PendingValue;  // NCr3 PA to load when NCr3UpdatePending fires

    // ---- Per-CPU PH_OP_CALL suspend/resume state -----------------------------
    // When this CPU issues a PH_OP_CALL, these fields hold the state needed to
    // resume the script after the callee's `ret` re-enters our hook VA.
    // Keeping them PER-CPU (not per-hook-entry) prevents one CPU's mid-call
    // state from being clobbered by a different CPU dispatching the same hook
    // for an unrelated thread. The matching hook slot is identified by
    // CallHookSlot; a CPU with CallActive=0 is not mid-call.
    UINT32          CallActive;        // 1 = this CPU is suspended mid-CALL
    UINT32          CallHookSlot;      // which PROCESS_HOOK_ENTRY index issued the CALL
    UINT32          CallResumePc;      // next script insn to execute on resume
    UINT8           CallRetValReg;     // where to store guest EAX on resume (0 = discard)
    UINT8           CallPad[3];
    UINT64          CallSavedEsp;      // pre-CALL ESP (restored before resume)
    UINT64          CallSavedCr3;      // CR3 at CALL time (resume rejected if different)
    UINT64          CallSavedEip;      // = TargetVa (sanity)
    UINT64          CallSavedScratch[16];  // frozen scratch[0..15]
} GUEST_STATE;

typedef struct _CONTEXT_COLLECTION
{
    GUEST_STATE Guest;
    UINT8 Reserved1[SIZE_4KB - sizeof(GUEST_STATE)];
} CONTEXT_COLLECTION;
STATIC_ASSERT((sizeof(CONTEXT_COLLECTION) % SIZE_4KB) == 0, "Must be 4KB aligned");

//
// The entry count within the IDT.
//
#define IDT_ENTRY_COUNT     256

//
// Data structures used for host execution environemnt across all processors.
//
typedef struct _SHARED_HOST_DATA
{
    HOST_PAGING_STRUCTURES PagingStructures;
    IA32_IDT_GATE_DESCRIPTOR Idt[IDT_ENTRY_COUNT];
    IA32_DESCRIPTOR Idtr;
    UINT8 Reserved2[2];
    UINT32 ProcessorCount;
    UINT64 Cr3;
    UINT8 Reserved1[SIZE_4KB - sizeof(IA32_DESCRIPTOR) - sizeof(UINT8[2]) - sizeof(UINT32) - sizeof(UINT64)];
} SHARED_HOST_DATA;
STATIC_ASSERT((sizeof(SHARED_HOST_DATA) % SIZE_4KB) == 0, "Must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(SHARED_HOST_DATA, Idt) % SIZE_4KB) == 0, "Must be 4KB aligned");

//
// Data structures used for host execution environemnt for each processor.
//
typedef struct _HOST_DATA
{
    CONST SHARED_HOST_DATA* Shared;
    IA32_SEGMENT_DESCRIPTOR Gdt[16];
    IA32_DESCRIPTOR Gdtr;
    IA32_TASK_STATE_SEGMENT Tss;
    UINT8 Reserved1[SIZE_4KB - sizeof(SHARED_HOST_DATA*) - sizeof(IA32_SEGMENT_DESCRIPTOR) * 16 - sizeof(IA32_DESCRIPTOR) - sizeof(IA32_TASK_STATE_SEGMENT)];
} HOST_DATA;
STATIC_ASSERT((sizeof(HOST_DATA) % SIZE_4KB) == 0, "Must be 4KB aligned");

//
// The collection of data structures allocated for each processors.
//
typedef struct _PER_CPU_DATA
{
    MEMORY_LOGS Logs;
    CONTEXT_COLLECTION States;

    VMCB GuestVmcb;
    VMCB HostVmcb;
    HOST_STACK HostStack;
    UINT8 HostStateArea[SIZE_4KB];
    HOST_DATA HostX64Data;
} PER_CPU_DATA;
STATIC_ASSERT((sizeof(PER_CPU_DATA) % SIZE_4KB) == 0, "Must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(PER_CPU_DATA, GuestVmcb) % SIZE_4KB) == 0, "Must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(PER_CPU_DATA, HostVmcb) % SIZE_4KB) == 0, "Must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(PER_CPU_DATA, HostStack) % SIZE_4KB) == 0, "Must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(PER_CPU_DATA, HostStateArea) % SIZE_4KB) == 0, "Must be 4KB aligned");

//
// NPT guard region that write-protects the hypervisor's own physical pages
// (host stacks, VMCBs, NPT tables, etc.) from guest writes. ROOT_CONTEXT is
// ~4-5MB and always fits within one 1GB physical region, so we need one PD
// (to replace the 1GB PDPT leaf) and up to 4 PTs (one per 2MB sub-region
// that overlaps ROOT_CONTEXT). Total: 1×4KB + 4×4KB = 20KB.
//
// On a guest write to a protected 4KB page: VMEXIT_NPF fires, HandleNPF
// injects #GP(0) to the guest (same path as any non-LAPIC bad NPF). The
// host stack is untouched; the guest's exception handler deals with it.
//
#define HV_GUARD_MAX_PTS 4
typedef struct _NPT_HV_GUARD_REGION
{
    PML4_ENTRY_2MB  Pd[PAGE_TABLE_ENTRY_COUNT];               // 4KB: 512×2MB entries
    PT_ENTRY_4KB    Pt[HV_GUARD_MAX_PTS][PAGE_TABLE_ENTRY_COUNT]; // 16KB: 4×512×4KB entries
} NPT_HV_GUARD_REGION;
STATIC_ASSERT((sizeof(NPT_HV_GUARD_REGION) % SIZE_4KB) == 0, "Must be 4KB aligned");

//
// Data structures related to SVM and used for all processors.
//
// Offset map (all 4KB-aligned):
//   0x000000  NestedPageTables  (read NCr3)   2MB+4KB = 0x201000
//   0x201000  Msrpm                           8KB     = 0x002000
//   0x203000  LapicRegion                     8KB     = 0x002000
//   0x205000  HvGuard                         20KB    = 0x005000
//   0x20A000  NptExec           (exec NCr3)   2MB+4KB = 0x201000
//   0x40B000  HookRead          (read NPT split region)    16KB
//   0x40F000  HookExec          (exec NPT split region)    16KB
//   0x413000  ShadowPages       (NPT_SHADOW_COUNT×4KB)    32KB
//   0x41B000  HookMeta          4KB
//   0x41C000  NcShadowPml4      (shadow NCr3 PML4, HvGuard-protected)    4KB
//   0x41D000  NcShadowPdpt0     (shadow NCr3 PDPT[0], HvGuard-protected) 4KB
//   0x41E000  end
//
typedef struct _SHARED_SVM_DATA
{
    PAGING_STRUCTURES   NestedPageTables;                       // 0x000000
    UINT8               Msrpm[SIZE_8KB];                        // 0x201000
    NPT_LAPIC_REGION    LapicRegion;                            // 0x203000
    NPT_HV_GUARD_REGION HvGuard;                                // 0x205000
    PAGING_STRUCTURES   NptExec;                                // 0x20A000
    NPT_HOOK_REGION     HookRead;                               // 0x40B000
    NPT_HOOK_REGION     HookExec;                               // 0x40F000
    UINT8               ShadowPages[NPT_SHADOW_COUNT][SIZE_4KB];// 0x413000
    NPT_HOOK_META       HookMeta;                               // 0x41B000
    // Shadow NCr3 pages: inside ROOT_CONTEXT so HvGuard (W=0 in NPT) intercepts
    // and drops any guest writes (e.g. guest scanner zeroing/NX-setting PDPT entries).
    // Host writes from the VMM bypass NPT and are unaffected.
    UINT64              NcShadowPml4[512];                      // 0x41C000
    UINT64              NcShadowPdpt0[512];                     // 0x41D000
} SHARED_SVM_DATA;
STATIC_ASSERT((sizeof(SHARED_SVM_DATA) % SIZE_4KB) == 0, "Must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(SHARED_SVM_DATA, Msrpm)         % SIZE_4KB) == 0, "MSRPM must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(SHARED_SVM_DATA, LapicRegion)   % SIZE_4KB) == 0, "LapicRegion must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(SHARED_SVM_DATA, HvGuard)       % SIZE_4KB) == 0, "HvGuard must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(SHARED_SVM_DATA, NptExec)       % SIZE_4KB) == 0, "NptExec must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(SHARED_SVM_DATA, HookRead)      % SIZE_4KB) == 0, "HookRead must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(SHARED_SVM_DATA, HookExec)      % SIZE_4KB) == 0, "HookExec must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(SHARED_SVM_DATA, ShadowPages)   % SIZE_4KB) == 0, "ShadowPages must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(SHARED_SVM_DATA, HookMeta)      % SIZE_4KB) == 0, "HookMeta must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(SHARED_SVM_DATA, NcShadowPml4)  % SIZE_4KB) == 0, "NcShadowPml4 must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(SHARED_SVM_DATA, NcShadowPdpt0) % SIZE_4KB) == 0, "NcShadowPdpt0 must be 4KB aligned");

extern UINT64 g_LapicBasePa;
extern UINT64 g_HvGuardBase;
extern UINT64 g_HvGuardSize;
extern UINT64 g_ReadNcr3Pa;    // physical addr of NestedPageTables.Pml4 (real read NCr3 — internal use only)
extern UINT64 g_ExecNcr3Pa;    // physical addr of NptExec.Pml4 (exec NCr3)
extern UINT64 g_ShadowNcr3Pa;  // physical addr of shadow PML4 — what VMCB.NCr3 holds during VMRUN
extern UINT64* g_ShadowPdpt0;  // pointer to shadow PDPT[0] page (identity map for GPA [0, 512GB))
extern UINT64 g_MsrpmPa;       // physical addr of SharedContext->Svm.Msrpm[0]
extern UINT64 g_DecoyPagePa;   // zero page; swapped into VMCB.NCr3/MsrpmBasePa at VMEXIT
// Saved VMCB intercept/config fields — zeroed during VMEXIT, restored before VMRUN.
extern UINT32 g_VmcbSavedMisc1;
extern UINT32 g_VmcbSavedMisc2;
extern UINT32 g_VmcbSavedException;
extern UINT32 g_VmcbSavedGuestAsid;
extern UINT64 g_VmcbSavedNpEnable;
extern UINT64 g_VmcbSavedLbrVirt;

//
// Install a split-page hook: read NCr3 marks TargetGpa4K NX=1 (exec NPF),
// exec NCr3 maps it to a pre-allocated shadow page (NX=0). Copies original
// page content into the shadow page as a transparent starting point.
// Returns shadow page GPA (caller patches hook bytes there), or 0 on failure.
// Must be called from host context (hypercall or HV init).
//
UINT64
InstallNptHook (
    IN OUT SHARED_SVM_DATA* Svm,
    IN     UINT64           TargetGpa4K
    );

//
// Syscall log: ring buffer of syscall events captured via NPT hook on KiSystemCall64.
// Allocated separately from SHARED_SVM_DATA to avoid changing its layout.
//
#define SYSCALL_LOG_CAPACITY  4096

typedef struct _SYSCALL_LOG_ENTRY
{
    UINT64 Cr3;         // guest CR3 at time of syscall
    UINT32 SyscallNum;  // RAX low 32 bits (syscall number)
    UINT16 CpuIndex;    // which vCPU
    UINT16 Flags;       // bit 0: 0 = 64-bit syscall path, 1 = 32-bit (CSTAR) syscall path
    UINT64 RetAddr;     // RCX (usermode return address)
    UINT64 Arg1;        // R10 (1st arg — Windows moves RCX→R10 before SYSCALL)
} SYSCALL_LOG_ENTRY;
STATIC_ASSERT(sizeof(SYSCALL_LOG_ENTRY) == 32, "SYSCALL_LOG_ENTRY must be 32 bytes");

#define SYSCALL_LOG_FLAG_32BIT  0x0001

#pragma pack(push, 1)
typedef struct _SYSCALL_LOG_STATUS
{
    UINT32 LogAllocated;      // 1 = ring buffer exists (DXE init succeeded)
    UINT32 Active;             // 1 = logging armed (one of the START variants called)
    UINT32 Count;              // entries currently buffered (not yet drained)
    UINT32 Dropped;            // entries discarded (buffer full)
    UINT64 FilterCr3;          // 0 = all processes
    UINT64 KernelLstar;        // captured LSTAR (0 if never seen)
    UINT64 KernelCstar;        // captured CSTAR (0 if never seen)
    UINT64 KernelCr3;          // captured kernel CR3 (0 if never seen)
    UINT64 SyscallGpa64;       // 4KB-aligned GPA hooked for KiSystemCall64 (0 if not installed)
    UINT64 SyscallGpa32;       // 4KB-aligned GPA hooked for KiSystemCall32 (0 if not installed)
    UINT32 HookCount;          // Svm->HookMeta.HookCount (total NPT hooks live)
    UINT32 ExecFlipCount;      // NPF exec-flip counter (how many times an NPF caused a flip to exec NCr3)
    UINT32 NCpus;              // total vCPUs
    UINT32 NCpusOnExecNcr3;    // vCPUs currently on exec NCr3 (should be 0 at idle after re-arm)
} SYSCALL_LOG_STATUS;
#pragma pack(pop)
STATIC_ASSERT(sizeof(SYSCALL_LOG_STATUS) == 80, "SYSCALL_LOG_STATUS layout mismatch");

typedef struct _SYSCALL_LOG
{
    volatile UINT32 Head;        // next write index (wraps at SYSCALL_LOG_CAPACITY)
    volatile UINT32 Count;       // entries written since last drain (saturates at capacity)
    volatile UINT32 Dropped;     // entries dropped (buffer full, not draining fast enough)
    UINT32          Active;      // 1 = logging enabled
    UINT64          FilterCr3;   // 0 = log all processes; else only matching CR3
    UINT64          SyscallGpa64;// 4KB-aligned GPA of KiSystemCall64 (64-bit syscall entry)
    UINT64          SyscallGpa32;// 4KB-aligned GPA of KiSystemCall32 (compat-mode / WoW64 entry); 0 if unavailable
    SYSCALL_LOG_ENTRY Entries[SYSCALL_LOG_CAPACITY];
} SYSCALL_LOG;

extern SYSCALL_LOG* g_SyscallLog;

//
// ============================================================================
// Process-hook script engine.
// ============================================================================
//
// A process hook fires when the guest executes an instruction at a specific
// (CR3, VA) pair. When it fires, a tiny bytecode interpreter runs a script
// that was registered from usermode. The script has read/write access to
// guest GPRs and guest memory in the hooked process's address space.
//
// Shadow-page NPT hook mechanics are identical to the syscall logger: the
// hooked 4KB page is NX in read NCr3 and executable (verbatim copy) in exec
// NCr3. From a UM scanner's view the function's bytes never change.
//
// Each instruction is 8 bytes. Max 64 instructions per script -> 512 bytes.
//

#define PROCESS_HOOK_MAX                 8
#define PROCESS_HOOK_SCRIPT_MAX_INSNS    128
#define PROCESS_HOOK_SCRATCH_REGS        16
#define PROCESS_HOOK_CFG_SLOTS           16
#define PROCESS_HOOK_MAX_CYCLES          512   // interpreter instruction budget

//
// Operand encoding. The low 5 bits select which register; high bits are
// zero. 0..15 = scratch R0..R15, 16..31 = guest regs (see PH_GR_*), 32+ = reserved.
//
#define PH_R0     0x00
#define PH_R15    0x0F
#define PH_GR_EAX     0x10
#define PH_GR_ECX     0x11
#define PH_GR_EDX     0x12
#define PH_GR_EBX     0x13
#define PH_GR_ESP     0x14
#define PH_GR_EBP     0x15
#define PH_GR_ESI     0x16
#define PH_GR_EDI     0x17
#define PH_GR_EIP     0x18
#define PH_GR_EFLAGS  0x19
// PH_GR_ARGn reads [ESP + 4*n] at script-start time into a shadow slot and
// writes-back on commit. ARG1..ARG8 covers typical 32-bit stdcall / cdecl.
#define PH_GR_ARG1    0x20
#define PH_GR_ARG8    0x27
// PH_CFG0..PH_CFG15 — per-hook config slots, written via AO_CMD_PH_SET_CFG
// from usermode, read-only from inside the script. Backed by entry->Config[].
#define PH_CFG0       0x30
#define PH_CFG15      0x3F

//
// Opcodes.
//
#define PH_OP_NOP        0x00
#define PH_OP_LOADI      0x01   // dst = imm32 (zero-extended)
#define PH_OP_MOV        0x02   // dst = a
#define PH_OP_ADD        0x03   // dst = a + b
#define PH_OP_SUB        0x04   // dst = a - b
#define PH_OP_MUL        0x05   // dst = a * b
#define PH_OP_AND        0x06   // dst = a & b
#define PH_OP_OR         0x07   // dst = a | b
#define PH_OP_XOR        0x08   // dst = a ^ b
#define PH_OP_SHL        0x09   // dst = a << imm
#define PH_OP_SHR        0x0A   // dst = a >> imm
#define PH_OP_CMP        0x0B   // sets internal LT/EQ/GT flags from a vs b
#define PH_OP_JMP        0x0C   // pc += (INT32)imm (relative)
#define PH_OP_JEQ        0x0D
#define PH_OP_JNE        0x0E
#define PH_OP_JLT        0x0F
#define PH_OP_JGT        0x10
#define PH_OP_READ1      0x11   // dst = *(u8  guest) a + imm
#define PH_OP_READ2      0x12   // dst = *(u16 guest) a + imm
#define PH_OP_READ4      0x13   // dst = *(u32 guest) a + imm
#define PH_OP_WRITE1     0x14   // *(u8  guest) a + imm = src(b)
#define PH_OP_WRITE2     0x15   // *(u16 guest) a + imm = src(b)
#define PH_OP_WRITE4     0x16   // *(u32 guest) a + imm = src(b)
#define PH_OP_LOG        0x17   // emit a 2-value log entry (a, b)
#define PH_OP_RETCONT    0x18   // let the original instruction run
#define PH_OP_RETSKIP    0x19   // EIP += imm; original does NOT run
#define PH_OP_RETRET     0x1A   // simulate `ret imm16`: EIP=[ESP]; ESP+=4+imm
#define PH_OP_HALT       0x1B   // stop interpreter (defaults action = SKIP)
#define PH_OP_CALL       0x1C   // Call a cdecl function in guest at VA = (A).
                                // Dst = register to receive guest EAX on return
                                //       (0 = discard).
                                // B   = nargs (0..4).
                                // Imm = 4 bytes, each a PH_* register encoding
                                //       for an argument (byte 0 = arg0, etc).
                                // Script suspends; on callee's ret, EIP = TargetVa
                                // which the NPF dispatch recognizes as a CALL
                                // return and resumes the script at PC+1.

//
// Per-instruction layout (8 bytes). Little-endian.
//
typedef struct _PROCESS_HOOK_INSN
{
    UINT8  Op;      // PH_OP_*
    UINT8  Dst;     // PH_R* / PH_GR_*
    UINT8  A;       // operand A (register encoding)
    UINT8  B;       // operand B (register encoding)
    UINT32 Imm;     // immediate (also used as memory displacement, jump delta)
} PROCESS_HOOK_INSN;
STATIC_ASSERT(sizeof(PROCESS_HOOK_INSN) == 8, "PROCESS_HOOK_INSN must be 8 bytes");

//
// A single installable hook.
//
typedef struct _PROCESS_HOOK_ENTRY
{
    UINT32            Active;                      // 1 = live
    UINT32            InsnCount;                   // valid insns in Script[]
    UINT64            TargetCr3;                   // 0 = any process
    UINT64            TargetVa;                    // RIP-exact match
    UINT64            TargetGpa4K;                 // page we NPT-hooked
    UINT64            HitCount;                    // bumped every dispatch
    UINT64            LastFaultPc;                 // last script PC on fault (debug)
    UINT32            LastFaultReason;             // last script fault code
    UINT32            Reserved;
    // Config slots written from usermode via AO_CMD_PH_SET_CFG, read by
    // the script as the PH_CFG0..PH_CFG15 operand class. Treat as read-only
    // from inside the script.
    UINT32            Config[PROCESS_HOOK_CFG_SLOTS];
    UINT32            CfgPad;
    // NOTE: PH_OP_CALL suspend state used to live here. It is now stored
    // per-CPU inside GUEST_STATE (CallActive / CallHookSlot / CallSavedEsp /
    // CallSavedCr3 / CallSavedEip / CallSavedScratch / CallResumePc /
    // CallRetValReg). Keeping that state per-hook was unsafe across CPUs.
    PROCESS_HOOK_INSN Script[PROCESS_HOOK_SCRIPT_MAX_INSNS];
} PROCESS_HOOK_ENTRY;
STATIC_ASSERT((sizeof(PROCESS_HOOK_ENTRY) & 7) == 0, "PROCESS_HOOK_ENTRY must be 8-byte aligned");

//
// Script fault reasons (stored in LastFaultReason, also loggable).
//
#define PH_FAULT_NONE            0
#define PH_FAULT_BAD_OPCODE      1
#define PH_FAULT_BAD_OPERAND     2
#define PH_FAULT_READ_FAILED     3
#define PH_FAULT_WRITE_FAILED    4
#define PH_FAULT_CYCLE_LIMIT     5
#define PH_FAULT_BAD_JUMP        6
#define PH_FAULT_WRITE_RO_REG    7

//
// Shared table of installed hooks. One page so it fits inside the HV
// allocator cleanly. g_ProcessHooks is set at DXE init alongside g_SyscallLog.
//
typedef struct _PROCESS_HOOK_TABLE
{
    UINT32              NumActive;
    UINT32              Reserved;
    UINT64              DispatchCount;   // total script invocations
    UINT64              FaultCount;      // scripts that aborted via fault
    PROCESS_HOOK_ENTRY  Entries[PROCESS_HOOK_MAX];
} PROCESS_HOOK_TABLE;

//
// Debug ring for PH_OP_LOG. Separate from syscall ring so the two don't fight.
//
#define PROCESS_HOOK_LOG_CAPACITY 1024

typedef struct _PROCESS_HOOK_LOG_ENTRY
{
    UINT64 Cr3;
    UINT64 Va;
    UINT64 A;
    UINT64 B;
} PROCESS_HOOK_LOG_ENTRY;
STATIC_ASSERT(sizeof(PROCESS_HOOK_LOG_ENTRY) == 32, "PROCESS_HOOK_LOG_ENTRY must be 32 bytes");

typedef struct _PROCESS_HOOK_LOG
{
    volatile UINT32        Head;
    volatile UINT32        Count;
    volatile UINT32        Dropped;
    UINT32                 Reserved;
    PROCESS_HOOK_LOG_ENTRY Entries[PROCESS_HOOK_LOG_CAPACITY];
} PROCESS_HOOK_LOG;

extern PROCESS_HOOK_TABLE* g_ProcessHooks;
extern PROCESS_HOOK_LOG*   g_ProcessHookLog;

//
// This is the structure that is holds all information for the entire hypervisor
// and virtual processors. This is allocated at the runtime-memory only once and
// made up of per-PER_CPU_DATA,
//
typedef struct _ROOT_CONTEXT
{
    SHARED_SVM_DATA Svm;
    SHARED_HOST_DATA HostX64;
    PER_CPU_DATA Cpus[0];
} ROOT_CONTEXT;
STATIC_ASSERT((sizeof(ROOT_CONTEXT) % SIZE_4KB) == 0, "Must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(ROOT_CONTEXT, HostX64) % SIZE_4KB) == 0, "Must be 4KB aligned");
STATIC_ASSERT((OFFSET_OF(ROOT_CONTEXT, Cpus) % SIZE_4KB) == 0, "Must be 4KB aligned");
// Catch any struct regression that would silently shrink the HV-guard coverage.
STATIC_ASSERT(sizeof(ROOT_CONTEXT) > 0x600000, "ROOT_CONTEXT unexpectedly small — check SHARED_SVM_DATA / SHARED_HOST_DATA");

//
// The collection of data structures to handle #VMEXIT.
//
typedef struct _HOST_CONTEXT
{
    PER_CPU_DATA* Cpu;
    ROOT_CONTEXT* Root;
} HOST_CONTEXT;

//
// The physical address of the ResetSystem runtime service.
//
extern EFI_RESET_SYSTEM g_ResetSystemPhys;

//
// The physical address of the SetVariable runtime service, and the GUID for log.
//
extern EFI_SET_VARIABLE g_SetVariablePhys;
extern EFI_GUID g_LogGuid;

//
// Log buffer used when the host context is not specified.
//
extern MEMORY_LOGS* g_GlobalLogBuffer;
