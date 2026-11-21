/**
 * @file ReadScratch.c
 * @brief Compact shmr diagnostic reader.
 */
#include <Uefi.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/IoLib.h>

STATIC EFI_GUID g_MilestoneGuid = {
    0x7E5C0A2B, 0x4D1F, 0x4623,
    { 0xB9, 0x18, 0x3E, 0x7A, 0x2C, 0x88, 0x4F, 0x91 }
};

STATIC UINT8 ReadCmosByte (IN UINT8 Index) {
    IoWrite8(0x70, Index & 0x7F);
    return IoRead8(0x71);
}

STATIC UINT8 ReadExtCmosByte (IN UINT8 Index) {
    IoWrite8(0x72, Index);
    return IoRead8(0x73);
}

EFI_STATUS EFIAPI UefiMain (
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable
    )
{
    // ---- CMOS core counters ----
    UINT8 progress    = ReadCmosByte(0x50);
    UINT8 ec0         = ReadCmosByte(0x51);
    UINT8 ec1         = ReadCmosByte(0x52);
    UINT8 ec2         = ReadCmosByte(0x53);
    UINT8 ec3         = ReadCmosByte(0x54);
    UINT8 excVec      = ReadCmosByte(0x55);
    UINT8 exitCnt     = ReadCmosByte(0x56);
    UINT8 lastExitLo  = ReadCmosByte(0x57);
    UINT8 wrap        = ReadCmosByte(0x60);
    UINT8 initCnt     = ReadCmosByte(0x61);
    UINT8 initIcept   = ReadCmosByte(0x62);
    UINT8 sipiEmu     = ReadCmosByte(0x63);
    UINT8 icrCnt      = ReadCmosByte(0x64);
    UINT8 lastMode    = ReadCmosByte(0x65);
    UINT8 apResumed   = ReadCmosByte(0x66);
    UINT8 lapicMmio   = ReadCmosByte(0x67);
    UINT8 npfCnt      = ReadCmosByte(0x68);
    UINT8 npfFail     = ReadCmosByte(0x69);
    UINT8 hvgDrop     = ReadCmosByte(0x6B);  // HV-guard silent drop count
    UINT32 lastExit   = ((UINT32)ec3<<24)|((UINT32)ec2<<16)|((UINT32)ec1<<8)|ec0;
    UINT32 totalExits = ((UINT32)wrap<<8)|exitCnt;

    UINT8 lo0=ReadCmosByte(0x70), lo1=ReadCmosByte(0x71),
          lo2=ReadCmosByte(0x72), lo3=ReadCmosByte(0x73);
    UINT8 hi0=ReadCmosByte(0x74), hi1=ReadCmosByte(0x75),
          hi2=ReadCmosByte(0x76), hi3=ReadCmosByte(0x77);
    UINT32 icrLow = ((UINT32)lo3<<24)|((UINT32)lo2<<16)|((UINT32)lo1<<8)|lo0;
    UINT32 icrHi  = ((UINT32)hi3<<24)|((UINT32)hi2<<16)|((UINT32)hi1<<8)|hi0;

    UINT16 hNpf   = ((UINT16)ReadCmosByte(0x79)<<8)|ReadCmosByte(0x78);
    UINT16 hCpuid = ((UINT16)ReadCmosByte(0x7B)<<8)|ReadCmosByte(0x7A);
    UINT16 hMsr   = ((UINT16)ReadCmosByte(0x7D)<<8)|ReadCmosByte(0x7C);
    UINT16 hOther = ((UINT16)ReadCmosByte(0x7F)<<8)|ReadCmosByte(0x7E);

    // ---- Persistent crash log (0x58-0x5F — survives HV reload) ----
    UINT8 cl_s   = ReadCmosByte(0x58);  // sentinel
    UINT8 cl_59  = ReadCmosByte(0x59);
    UINT8 cl_5A  = ReadCmosByte(0x5A);
    UINT8 cl_5B  = ReadCmosByte(0x5B);
    UINT8 cl_5C  = ReadCmosByte(0x5C);
    UINT8 cl_5D  = ReadCmosByte(0x5D);
    UINT8 cl_5E  = ReadCmosByte(0x5E);
    UINT8 cl_5F  = ReadCmosByte(0x5F);

    // ---- SIPI diagnostics / NPF-outside-LAPIC diagnostics (share 0x49-0x4F) ----
    UINT8 d49 = ReadCmosByte(0x49);
    UINT8 d4A = ReadCmosByte(0x4A);
    UINT8 d4B = ReadCmosByte(0x4B);
    UINT8 d4C = ReadCmosByte(0x4C);
    UINT8 d4D = ReadCmosByte(0x4D);
    UINT8 d4E = ReadCmosByte(0x4E);
    UINT8 d4F = ReadCmosByte(0x4F);
    BOOLEAN badNpf  = (d4F == 0xBA);
    BOOLEAN hostExc = (d4F == 0xEE);

    // ---- Ring buffer ----
    UINT8 widx  = ReadCmosByte(0x40);
    UINT8 rcount = (widx > 8) ? 8 : widx;

    // ---- #UD hypercall channel diagnostics (ext CMOS 0x80-0x84) ----
    UINT8 udTotal = ReadExtCmosByte(0x80);
    UINT8 udMatch = ReadExtCmosByte(0x81);
    UINT8 udMiss  = ReadExtCmosByte(0x82);
    UINT8 udCmd   = ReadExtCmosByte(0x83);
    UINT8 udDelta = ReadExtCmosByte(0x84);

    // ---- MSR intercept diagnostics (ext CMOS 0x85-0x8A) ----
    UINT8  msrDir  = ReadExtCmosByte(0x85);
    UINT32 lastMsr = ((UINT32)ReadExtCmosByte(0x89) << 24) |
                     ((UINT32)ReadExtCmosByte(0x88) << 16) |
                     ((UINT32)ReadExtCmosByte(0x87) <<  8) |
                      (UINT32)ReadExtCmosByte(0x86);
    UINT8  sB      = ReadExtCmosByte(0x8A);

    // ---- HV guard region (ext CMOS 0x8B-0x96) ----
    UINT64 hvBase = 0;
    UINT32 hvSize = 0;
    for (UINT8 i = 0; i < 8; i++)
        hvBase |= ((UINT64)ReadExtCmosByte((UINT8)(0x8B + i))) << (i * 8);
    for (UINT8 i = 0; i < 4; i++)
        hvSize |= ((UINT32)ReadExtCmosByte((UINT8)(0x93 + i))) << (i * 8);

    // ---- Print ----
    Print(L"=== shmr diag ===\n");
    Print(L"prog:0x%02x  exits:%d  lastExit:0x%08x  hostExc:0x%02x\n",
          progress, totalExits, lastExit, excVec);

    Print(L"\n-- Crash Log (persistent) --\n");
    if (cl_s == 0xDE) {
        UINT32 clRaw = ((UINT32)cl_5D<<24)|((UINT32)cl_5C<<16)|((UINT32)cl_5B<<8)|cl_5A;
        UINT32 clSec = (UINT32)((INT32)0x4490 + (INT32)clRaw);
        Print(L"  HOST EXC: vec:0x%02x  RVA:0x%04x  op:0x%02x  rcxLo:0x%02x\n",
              cl_59, clSec + 0x1000, cl_5E, cl_5F);
    } else if (cl_s == 0xBA) {
        UINT64 clGpa = ((UINT64)cl_5F<<40)|((UINT64)cl_5E<<32)|
                       ((UINT32)cl_5D<<24)|((UINT32)cl_5C<<16)|
                       ((UINT16)cl_5B<<8)|cl_5A;
        UINT8 npfPdpeLo  = ReadCmosByte(0x6D);
        UINT8 npfPdpeHi  = ReadCmosByte(0x6E);
        UINT8 npfInfo1Hi = ReadCmosByte(0x6F);
        UINT8 npfNptMode = ReadExtCmosByte(0x97);
        UINT8 npfHookCnt = ReadExtCmosByte(0x98);
        UINT8 npfPml4Lo  = ReadExtCmosByte(0x99);
        UINT8 npfPml4Hi  = ReadExtCmosByte(0x9A);
        Print(L"  BAD NPF: GPA=0x%012lx  info1_lo=0x%02x\n", clGpa, cl_59);
        Print(L"  P=%d W=%d US=%d ID=%d  guestPTwalk:%d  nptMode:%d  hookCnt:%d\n",
              cl_59 & 1, (cl_59>>1)&1, (cl_59>>2)&1, (cl_59>>4)&1,
              (npfInfo1Hi>>1)&1, npfNptMode, npfHookCnt);
        Print(L"  PML4: V=%d W=%d U=%d NX=%d  [7:0]=0x%02x [63:56]=0x%02x\n",
              npfPml4Lo&1, (npfPml4Lo>>1)&1, (npfPml4Lo>>2)&1, (npfPml4Hi>>7)&1,
              npfPml4Lo, npfPml4Hi);
        Print(L"  PDPE: V=%d W=%d U=%d PS=%d NX=%d  [7:0]=0x%02x [63:56]=0x%02x\n",
              npfPdpeLo&1, (npfPdpeLo>>1)&1, (npfPdpeLo>>2)&1, (npfPdpeLo>>7)&1,
              (npfPdpeHi>>7)&1, npfPdpeLo, npfPdpeHi);
    } else if (cl_s == 0xBC) {
        UINT64 clGpa = ((UINT64)cl_5E<<40)|((UINT64)cl_5D<<32)|
                       ((UINT32)cl_5C<<24)|((UINT32)cl_5B<<16)|
                       ((UINT16)cl_5A<<8)|cl_59;
        Print(L"  HV-GUARD FAIL: GPA=0x%012lx\n", clGpa);
    } else {
        Print(L"  no crash data (sentinel=0x%02x)\n", cl_s);
    }

    Print(L"\n-- Live 0x49-0x4F --\n");
    if (hostExc) {
        UINT32 rawDelta   = ((UINT32)d4C << 24) | ((UINT32)d4B << 16) |
                            ((UINT32)d4A << 8) | (UINT32)d49;
        UINT32 sectionOff = (UINT32)((INT32)0x4490 + (INT32)rawDelta);
        UINT8 opStatus = ReadCmosByte(0x70);
        UINT8 op0 = hi0, op1 = hi1, op2 = hi2, op3 = hi3;
        Print(L"HOST EXC: RVA:0x%04x  rcxLo:0x%02x  op:0x%02x\n",
              sectionOff + 0x1000, d4D, d4E);
        if (opStatus == 0xC0) {
            Print(L"  opcode: %02x %02x %02x %02x", op0, op1, op2, op3);
            if (op0==0x0F && op1==0x01 && op2==0xDA)      Print(L" (VMLOAD)\n");
            else if (op0==0x0F && op1==0x01 && op2==0xD8) Print(L" (VMRUN)\n");
            else if (op0==0x0F && op1==0x0B)               Print(L" (UD2)\n");
            else                                            Print(L" (other/wild jump)\n");
        } else if (opStatus == 0xC1) {
            Print(L"  WILD JUMP (RIP out of image)\n");
        }
    } else if (badNpf) {
        UINT64 badGpa = ((UINT64)d4D << 32) | ((UINT32)d4C << 24) |
                        ((UINT32)d4B << 16) | ((UINT32)d4A << 8) | d49;
        UINT8 npfPdpeLo  = ReadCmosByte(0x6D);
        UINT8 npfPdpeHi  = ReadCmosByte(0x6E);
        UINT8 npfInfo1Hi = ReadCmosByte(0x6F);
        UINT8 npfNptMode = ReadExtCmosByte(0x97);
        UINT8 npfHookCnt = ReadExtCmosByte(0x98);
        UINT8 npfPml4Lo  = ReadExtCmosByte(0x99);
        UINT8 npfPml4Hi  = ReadExtCmosByte(0x9A);
        Print(L"BAD NPF: GPA=0x%010lx  info1_lo=0x%02x\n", badGpa, d4E);
        Print(L"  P=%d W=%d US=%d ID=%d  guestPTwalk:%d  nptMode:%d  hookCnt:%d\n",
              d4E & 1, (d4E>>1)&1, (d4E>>2)&1, (d4E>>4)&1,
              (npfInfo1Hi>>1)&1, npfNptMode, npfHookCnt);
        Print(L"  PML4: V=%d W=%d U=%d NX=%d  [7:0]=0x%02x [63:56]=0x%02x\n",
              npfPml4Lo&1, (npfPml4Lo>>1)&1, (npfPml4Lo>>2)&1, (npfPml4Hi>>7)&1,
              npfPml4Lo, npfPml4Hi);
        Print(L"  PDPE: V=%d W=%d U=%d PS=%d NX=%d  [7:0]=0x%02x [63:56]=0x%02x\n",
              npfPdpeLo&1, (npfPdpeLo>>1)&1, (npfPdpeLo>>2)&1, (npfPdpeLo>>7)&1,
              (npfPdpeHi>>7)&1, npfPdpeLo, npfPdpeHi);
    } else if (d49 == 0) {
        Print(L"  (not written this boot)\n");
    } else {
        Print(L"SIPI: procs:%d  dest:0x%02x  result:%d  AP IDs:%02x %02x %02x\n",
              d49, d4A, d4B, d4D, d4E, d4F);
    }

    // SMP + NPF + histogram on 2 lines
    Print(L"\nAP:%d SIPI:%d ICR:%d  NPF:%d fail:%d hvgDrop:%d  hist(NPF:%d MSR:%d UD:%d)\n",
          apResumed, sipiEmu, icrCnt, npfCnt, npfFail, hvgDrop, hNpf, hMsr, hOther);

    // Ring: only show if non-empty
    if (rcount > 0) {
        Print(L"Ring(%d):", rcount);
        for (UINT8 i = 0; i < rcount; ++i) {
            UINT8 slot = (UINT8)((widx - rcount + i) & 0x7);
            Print(L" 0x%02x", ReadCmosByte(0x41 + slot));
        }
        Print(L"\n");
    }

    // #UD channel
    Print(L"#UD: exits:%d  matched:%d  lastCmd:0x%02x\n", udTotal, udMatch, udCmd);

    // MSR: commented out — not relevant to NPF crash
    // CONST CHAR16 *msrName = L"";
    // if (lastMsr == 0xC0000080UL) msrName = L"(EFER)";
    // Print(L"MSR: last:0x%08x%s  dir:%s  svmeBlocked:%d\n",
    //       lastMsr, msrName, (msrDir==0)?L"RD":L"WR", sB);
    (VOID)msrDir; (VOID)lastMsr; (VOID)sB; (VOID)udMiss; (VOID)udDelta;
    (VOID)lastExitLo; (VOID)icrLow; (VOID)icrHi; (VOID)hCpuid;
    (VOID)initCnt; (VOID)initIcept; (VOID)lastMode; (VOID)lapicMmio;

    // HV guard + crash GPA check
    if (hvBase == 0) {
        Print(L"HVguard: (not logged)\n");
    } else {
        UINT64 crashGpa = 0x1174F3000ULL;
        Print(L"HVguard: base=0x%llx  size=0x%x\n", hvBase, hvSize);
        Print(L"crashGPA 0x%llx: %s\n", crashGpa,
              (crashGpa >= hvBase && crashGpa < hvBase + hvSize)
              ? L"INSIDE guard" : L"outside guard");
    }

    return EFI_SUCCESS;
}
