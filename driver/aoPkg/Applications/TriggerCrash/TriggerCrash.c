/**
 * @file TriggerCrash.c
 * @brief Fires the WRMSR 0x830 patterns that crash ao under EAC.
 *
 * Run from the UEFI shell AFTER ao.efi is loaded. Each pattern sends a
 * burst of VMEXIT_MSR exits through HandleMsr; the host crashes on whichever
 * pattern has the bug. After the reboot, run ReadScratch.efi to read 0x58.
 *
 * Since MSRPM only intercepts WRMSR 0x830 (write bit only), every exit here
 * is exactly VMEXIT_MSR with isWrite=TRUE, msr=0x830 — the same path EAC hits.
 *
 * Pattern guide:
 *   [A] Invalid delivery mode (mode=1 LP, mode=3 rsvd, mode=7 ExtINT)
 *       -> HV should inject #GP to guest (NOT execute WRMSR in host context).
 *       If HV executes WRMSR in host context instead, host #GPs -> triple fault.
 *   [B] Valid delivery mode, various destinations
 *       -> HV passthroughs AsmWriteMsr64 in host context.
 *       If host stack is corrupted during HandleMsr, wild jump -> #UD crash.
 *   [C] Rapid-fire storm of both
 *       -> Stress-tests the SMP path (8 cores taking exits concurrently).
 */
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/BaseLib.h>
#include <Library/IoLib.h>

#define X2APIC_ICR      0x830UL
#define X2APIC_BASE_MSR 0x1BDUL

// ICR delivery modes
#define MODE_FIXED  0u
#define MODE_LP     1u  // Lowest Priority  — INVALID, #GPs on real HW
#define MODE_SMI    2u
#define MODE_RSVD3  3u  // Reserved         — INVALID
#define MODE_NMI    4u
#define MODE_INIT   5u
#define MODE_SIPI   6u
#define MODE_EXTINIT 7u // ExtINT           — INVALID in x2APIC

#define ICR_SELF_SHORTHAND (2u << 18)

static UINT8 ReadCmos(UINT8 idx) {
    IoWrite8(0x70, idx & 0x7F);
    return IoRead8(0x71);
}

static VOID PrintCrashSentinel(VOID) {
    UINT8 s = ReadCmos(0x58);
    if (s == 0xDE)
        Print(L"  [CMOS] 0x58=0xDE HOST EXCEPTION  vec=0x%02x op=0x%02x rcxLo=0x%02x\n",
              ReadCmos(0x59), ReadCmos(0x5E), ReadCmos(0x5F));
    else if (s == 0xBA)
        Print(L"  [CMOS] 0x58=0xBA BAD NPF\n");
    else
        Print(L"  [CMOS] 0x58=0x%02x (no crash recorded this boot)\n", s);
}

EFI_STATUS EFIAPI UefiMain(
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable
)
{
    UINT64  apicBase;
    BOOLEAN x2Enabled;
    UINTN   i;

    Print(L"\n=== shmr TriggerCrash ===\n");
    PrintCrashSentinel();

    apicBase  = AsmReadMsr64(X2APIC_BASE_MSR);
    x2Enabled = (apicBase & (1ULL << 10)) != 0;
    Print(L"IA32_APIC_BASE=0x%lx  x2APIC=%d\n\n", apicBase, (UINT32)x2Enabled);

    if (!x2Enabled) {
        Print(L"[!] x2APIC is OFF. WRMSR 0x830 will #GP on hardware.\n");
        Print(L"    HV must intercept and inject #GP to guest — NOT execute it.\n");
        Print(L"    If host crashes on pattern [A], that IS the bug.\n\n");
    }

    // ------------------------------------------------------------------
    // Pattern A: invalid delivery modes — HV must reflect #GP, not execute
    // ------------------------------------------------------------------
    Print(L"[A] Invalid-mode WRMSRs (LP/rsvd/ExtINT) x30...\n");
    for (i = 0; i < 10; i++) {
        AsmWriteMsr64(X2APIC_ICR, (UINT64)(MODE_LP     << 8) | 0xFF);
        AsmWriteMsr64(X2APIC_ICR, (UINT64)(MODE_RSVD3  << 8) | 0xFF);
        AsmWriteMsr64(X2APIC_ICR, (UINT64)(MODE_EXTINIT << 8) | 0xFF);
    }
    Print(L"    survived [A]\n");

    // ------------------------------------------------------------------
    // Pattern B: valid delivery modes that passthrough to AsmWriteMsr64
    //   NMI self: (mode=4, self-shorthand) — valid, no dest needed
    //   INIT self: (mode=5, self-shorthand) — valid
    //   Fixed self vec 0: (mode=0, self-shorthand)
    // ------------------------------------------------------------------
    Print(L"[B] Valid-mode passthrough WRMSRs x300...\n");
    for (i = 0; i < 100; i++) {
        AsmWriteMsr64(X2APIC_ICR, (UINT64)(MODE_FIXED << 8) | ICR_SELF_SHORTHAND | 0x20);
        AsmWriteMsr64(X2APIC_ICR, (UINT64)(MODE_NMI   << 8) | ICR_SELF_SHORTHAND);
        AsmWriteMsr64(X2APIC_ICR, (UINT64)(MODE_INIT  << 8) | ICR_SELF_SHORTHAND);
    }
    Print(L"    survived [B]\n");

    // ------------------------------------------------------------------
    // Pattern C: interleaved valid+invalid at high rate (stress SMP path)
    // ------------------------------------------------------------------
    Print(L"[C] Mixed storm x500...\n");
    for (i = 0; i < 500; i++) {
        if (i & 1)
            AsmWriteMsr64(X2APIC_ICR, (UINT64)(MODE_LP << 8) | 0x44);
        else
            AsmWriteMsr64(X2APIC_ICR, (UINT64)(MODE_NMI << 8) | ICR_SELF_SHORTHAND);
    }
    Print(L"    survived [C]\n");

    // ------------------------------------------------------------------
    // Pattern D: reserved-bits-set ICR (another #GP trigger on real HW)
    // ------------------------------------------------------------------
    Print(L"[D] Reserved-bits-set ICR x50...\n");
    for (i = 0; i < 50; i++) {
        // bit 13 is reserved in ICR_LOW — hardware #GPs if set
        AsmWriteMsr64(X2APIC_ICR, (UINT64)(MODE_FIXED << 8) | (1u << 13) | 0x20);
    }
    Print(L"    survived [D]\n");

    Print(L"\nAll patterns survived — HV did not crash on any of them.\n");
    Print(L"Check ReadScratch for any recorded crash from a previous boot.\n");
    PrintCrashSentinel();

    return EFI_SUCCESS;
}
