/**
 * @file Introspect.c
 *
 * @brief Guest memory introspection for ao: GVA→GPA walks, kernel/process
 *        discovery, and arbitrary guest virtual-memory reads.
 *
 * All page-table operations rely on the identity-mapped NPT: GPA == host VA,
 * so physical addresses returned by GvaToGpa can be dereferenced directly.
 *
 * Win11 25H2 (build 26200) EPROCESS offsets — verified via Vergilius:
 *   +0x028  DirectoryTableBase  (in KPROCESS, stable since Vista)
 *   +0x1D8  ActiveProcessLinks.Flink  (was 0x448 on Win10/early Win11)
 *   +0x338  ImageFileName[15]         (was 0x5A8 on Win10/early Win11)
 */
#include "ao.h"
#include "Introspect.h"
#include <Library/BaseLib.h>

// Page-table entry bit masks — common across PML4/PDPT/PD/PT.
#define PTE_PRESENT     0x1ULL
#define PTE_LARGE_PAGE  0x80ULL
#define PTE_PFN_MASK    0x000FFFFFFFFFF000ULL

// Virtual-address decomposition (standard x86-64 4-level paging).
#define VA_PML4_IDX(va)  (((va) >> 39) & 0x1FFULL)
#define VA_PDPT_IDX(va)  (((va) >> 30) & 0x1FFULL)
#define VA_PD_IDX(va)    (((va) >> 21) & 0x1FFULL)
#define VA_PT_IDX(va)    (((va) >> 12) & 0x1FFULL)
#define VA_OFFSET_4K(va) ((va) & 0xFFFULL)

// EPROCESS field offsets — Win11 25H2 (build 26200).
// DTB lives in KPROCESS (embedded at EPROCESS+0), stable since Vista.
// ActiveProcessLinks and ImageFileName moved significantly from Win10 layouts.
// All offsets below were shifted by -0x270 from the Win10/early-Win11 layout
// (LINKS: 0x448→0x1D8, NAME: 0x5A8→0x338, SECTIONBASE: 0x520→0x2B0, PEB: 0x550→0x2E0).
#define EPROCESS_DTB          0x028ULL
#define EPROCESS_LINKS        0x1D8ULL
#define EPROCESS_SECTIONBASE  0x2B0ULL
#define EPROCESS_PEB_OFF      0x2E0ULL   // PEB pointer (in EPROCESS, points to user-space PEB)
#define EPROCESS_NAME         0x338ULL

// PEB / LDR_DATA_TABLE_ENTRY layout (64-bit, stable across Win10/11).
#define PEB_LDR         0x018ULL   // PEB.Ldr  → _PEB_LDR_DATA*
#define LDR_INMEMORDER  0x020ULL   // _PEB_LDR_DATA.InMemoryOrderModuleList (sentinel LIST_ENTRY)
#define LDR_ENTRY_LINK  0x010ULL   // InMemoryOrderLinks offset within LDR_DATA_TABLE_ENTRY
#define LDR_DLLBASE     0x030ULL   // LDR_DATA_TABLE_ENTRY.DllBase
#define LDR_NAME_LEN    0x058ULL   // BaseDllName.Length (USHORT, byte count of WCHAR string)
#define LDR_NAME_BUF    0x060ULL   // BaseDllName.Buffer (PWSTR)

/**
 * @brief Translate a guest virtual address to a guest physical address.
 *
 * Walks the 4-level x86-64 page table rooted at Cr3.  Handles 1GB and 2MB
 * large pages.  Because the hypervisor uses an identity-mapped NPT (GPA == HPA),
 * the returned physical address is also a valid host pointer.
 *
 * @return Physical address, or INVALID_PHYS_ADDR if any level is not present.
 */
UINT64
GvaToGpa (
    IN UINT64 Cr3,
    IN UINT64 Va
    )
{
    UINT64 *table;
    UINT64  entry;

    // PML4
    table = (UINT64 *)(UINTN)(Cr3 & PTE_PFN_MASK);
    entry = table[VA_PML4_IDX(Va)];
    if (!(entry & PTE_PRESENT)) return INVALID_PHYS_ADDR;

    // PDPT — may terminate as a 1GB leaf
    table = (UINT64 *)(UINTN)(entry & PTE_PFN_MASK);
    entry = table[VA_PDPT_IDX(Va)];
    if (!(entry & PTE_PRESENT)) return INVALID_PHYS_ADDR;
    if (entry & PTE_LARGE_PAGE)
    {
        // 1GB page: PA = entry[51:30] | Va[29:0]
        return (entry & 0x000FFFFFC0000000ULL) | (Va & 0x3FFFFFFFULL);
    }

    // PD — may terminate as a 2MB leaf
    table = (UINT64 *)(UINTN)(entry & PTE_PFN_MASK);
    entry = table[VA_PD_IDX(Va)];
    if (!(entry & PTE_PRESENT)) return INVALID_PHYS_ADDR;
    if (entry & PTE_LARGE_PAGE)
    {
        // 2MB page: PA = entry[51:21] | Va[20:0]
        return (entry & 0x000FFFFFFFE00000ULL) | (Va & 0x1FFFFFULL);
    }

    // PT — 4KB leaf
    table = (UINT64 *)(UINTN)(entry & PTE_PFN_MASK);
    entry = table[VA_PT_IDX(Va)];
    if (!(entry & PTE_PRESENT)) return INVALID_PHYS_ADDR;

    return (entry & PTE_PFN_MASK) | VA_OFFSET_4K(Va);
}

/**
 * @brief Read Size bytes from a guest virtual address into a host buffer.
 *
 * Handles page-boundary crossings by walking one page at a time.
 *
 * @return TRUE if all bytes were read; FALSE if any page was not present.
 */
BOOLEAN
ReadGuestVa (
    IN  UINT64 Cr3,
    IN  UINT64 Va,
    IN  UINT64 Size,
    OUT VOID   *HostBuf
    )
{
    UINT64  remaining = Size;
    UINT64  va        = Va;
    UINT8  *dst       = (UINT8 *)HostBuf;

    while (remaining > 0)
    {
        UINT64 pageOff  = va & 0xFFFULL;
        UINT64 chunk    = SIZE_4KB - pageOff;
        UINT64 pa;

        if (chunk > remaining) chunk = remaining;

        pa = GvaToGpa(Cr3, va);
        if (pa == INVALID_PHYS_ADDR) return FALSE;

        CopyMem(dst, (VOID *)(UINTN)pa, (UINTN)chunk);

        dst       += chunk;
        va        += chunk;
        remaining -= chunk;
    }
    return TRUE;
}

/**
 * @brief Find ntoskrnl's base by scanning backwards from IA32_LSTAR.
 *
 * LSTAR points into ntoskrnl's .text.  We walk backwards in 4KB steps looking
 * for an MZ header validated by the PE signature at offset [e_lfanew+0].
 * Searches up to 64MB back — ample for any ntoskrnl image.
 *
 * @return Base virtual address of ntoskrnl, or INVALID_PHYS_ADDR.
 */
UINT64
FindKernelBase (
    IN UINT64 GuestCr3,
    IN UINT64 GuestLstar
    )
{
    UINT64 candidate;
    UINT8  hdr[4];
    UINT32 peOff;
    UINT32 i;

    candidate = GuestLstar & ~0xFFFULL;

    for (i = 0; i < 0x4000; ++i, candidate -= SIZE_4KB)
    {
        if (!ReadGuestVa(GuestCr3, candidate, 2, hdr)) continue;
        if (hdr[0] != 'M' || hdr[1] != 'Z') continue;

        // Validate: read e_lfanew and check PE\0\0 signature
        if (!ReadGuestVa(GuestCr3, candidate + 0x3C, 4, &peOff)) continue;
        if (peOff > 0x1000) continue;   // sanity — PE header shouldn't be far
        if (!ReadGuestVa(GuestCr3, candidate + peOff, 4, hdr)) continue;
        if (hdr[0] == 'P' && hdr[1] == 'E' && hdr[2] == 0 && hdr[3] == 0)
        {
            UINT16 optMagic;
            UINT32 sizeOfImage;

            // Must be PE32+ (x64).
            if (!ReadGuestVa(GuestCr3, candidate + peOff + 24, 2, &optMagic)) continue;
            if (optMagic != 0x020B) continue;

            // LSTAR must fall within [candidate, candidate+SizeOfImage).
            // This rejects embedded sub-image stubs inside ntoskrnl that also
            // carry MZ+PE headers but whose SizeOfImage doesn't reach LSTAR.
            // SizeOfImage is at OptionalHeader+0x38.
            if (!ReadGuestVa(GuestCr3, candidate + peOff + 24 + 0x38, 4, &sizeOfImage)) continue;
            if (GuestLstar < candidate || GuestLstar >= candidate + sizeOfImage) continue;

            return candidate;
        }
    }
    return INVALID_PHYS_ADDR;
}

/**
 * @brief Find the virtual address of a named export in a PE image.
 *
 * Walks the IMAGE_EXPORT_DIRECTORY.  The image must be PE32+ (x64).
 * Only exact name matches (null-terminated) are returned.
 *
 * @return Export VA, or INVALID_PHYS_ADDR if not found.
 */
UINT64
FindExport (
    IN UINT64       GuestCr3,
    IN UINT64       KernelBase,
    IN CONST CHAR8 *Name
    )
{
    UINT32 peOff;
    UINT16 optMagic;
    UINT32 expDirRva;
    UINT32 numNames;
    UINT32 funcsRva;
    UINT32 namesRva;
    UINT32 ordinalsRva;
    UINT64 expBase;
    UINT32 nameLen;
    UINT32 i;
    CHAR8  nameBuf[64];

    nameLen = (UINT32)AsciiStrLen(Name);
    if (nameLen == 0 || nameLen >= sizeof(nameBuf)) return INVALID_PHYS_ADDR;

    if (!ReadGuestVa(GuestCr3, KernelBase + 0x3C, 4, &peOff)) return INVALID_PHYS_ADDR;

    // Verify optional header magic (must be PE32+ = 0x020B for x64)
    if (!ReadGuestVa(GuestCr3, KernelBase + peOff + 24, 2, &optMagic)) return INVALID_PHYS_ADDR;
    if (optMagic != 0x020B) return INVALID_PHYS_ADDR;

    // IMAGE_OPTIONAL_HEADER64: DataDirectory[0] (export) at offset +0x70 from start
    // OptHeader starts at pe+24; DataDirectory at pe+24+0x70 = pe+0x88
    if (!ReadGuestVa(GuestCr3, KernelBase + peOff + 24 + 0x70, 4, &expDirRva)) return INVALID_PHYS_ADDR;
    if (expDirRva == 0) return INVALID_PHYS_ADDR;

    expBase = KernelBase + expDirRva;

    // IMAGE_EXPORT_DIRECTORY field offsets:
    //   +0x18  NumberOfNames (DWORD)
    //   +0x1C  AddressOfFunctions (RVA)
    //   +0x20  AddressOfNames (RVA)
    //   +0x24  AddressOfNameOrdinals (RVA)
    if (!ReadGuestVa(GuestCr3, expBase + 0x18, 4, &numNames))    return INVALID_PHYS_ADDR;
    if (!ReadGuestVa(GuestCr3, expBase + 0x1C, 4, &funcsRva))    return INVALID_PHYS_ADDR;
    if (!ReadGuestVa(GuestCr3, expBase + 0x20, 4, &namesRva))    return INVALID_PHYS_ADDR;
    if (!ReadGuestVa(GuestCr3, expBase + 0x24, 4, &ordinalsRva)) return INVALID_PHYS_ADDR;

    if (numNames > 65536) return INVALID_PHYS_ADDR;   // sanity bound

    for (i = 0; i < numNames; ++i)
    {
        UINT32 nameRva;
        UINT16 ordinal;
        UINT32 funcRva;

        if (!ReadGuestVa(GuestCr3, KernelBase + namesRva + i * 4, 4, &nameRva)) continue;

        // Read name (length + null terminator) and compare
        if (!ReadGuestVa(GuestCr3, KernelBase + nameRva, nameLen + 1, nameBuf)) continue;
        if (AsciiStrnCmp(nameBuf, Name, nameLen) != 0) continue;
        if (nameBuf[nameLen] != '\0') continue;

        if (!ReadGuestVa(GuestCr3, KernelBase + ordinalsRva + i * 2,  2, &ordinal)) return INVALID_PHYS_ADDR;
        if (!ReadGuestVa(GuestCr3, KernelBase + funcsRva + ordinal * 4, 4, &funcRva)) return INVALID_PHYS_ADDR;

        return KernelBase + funcRva;
    }
    return INVALID_PHYS_ADDR;
}

/**
 * @brief Find the DirectoryTableBase (kernel CR3) of a named Windows process.
 *
 * Walks PsInitialSystemProcess → EPROCESS.ActiveProcessLinks, comparing
 * EPROCESS.ImageFileName[15] against Name.  Returns the full kernel CR3
 * (DirectoryTableBase, EPROCESS+0x028) of the first match, with PCID bits
 * cleared.  Returns INVALID_PHYS_ADDR if not found or if prerequisites are
 * missing (g_KernelCr3 / g_KernelBase not yet populated).
 *
 * @param KernelCr3   Kernel DirectoryTableBase (maps all of kernel VA space).
 * @param KernelBase  ntoskrnl.exe image base VA.
 * @param Name        Process image name to find (max 15 chars, case-insensitive).
 * @return CR3 of the matching process, or INVALID_PHYS_ADDR.
 */

STATIC CHAR8
ToLower (CHAR8 c)
{
    return (c >= 'A' && c <= 'Z') ? (CHAR8)(c + ('a' - 'A')) : c;
}

STATIC BOOLEAN
AsciiStrniEq (IN CONST CHAR8 *a, IN CONST CHAR8 *b, IN UINT32 n)
{
    UINT32 i;
    for (i = 0; i < n; ++i)
        if (ToLower(a[i]) != ToLower(b[i])) return FALSE;
    return TRUE;
}

UINT64
FindProcessCr3 (
    IN UINT64       KernelCr3,
    IN UINT64       KernelBase,
    IN CONST CHAR8 *Name,
    IN UINT32       SkipCount
    )
{
    UINT64 psInitSysProc;
    UINT64 psInitPtr;
    UINT64 current;
    UINT64 flink;
    CHAR8  imgName[16];
    UINT32 nameLen;
    UINT32 guard;
    UINT32 matched;

    nameLen = (UINT32)AsciiStrLen(Name);
    if (nameLen == 0 || nameLen > 15) return INVALID_PHYS_ADDR;

    // PsInitialSystemProcess is an exported PEPROCESS* — dereference to get System EPROCESS
    psInitSysProc = FindExport(KernelCr3, KernelBase, "PsInitialSystemProcess");
    if (psInitSysProc == INVALID_PHYS_ADDR) return INVALID_PHYS_ADDR;

    if (!ReadGuestVa(KernelCr3, psInitSysProc, 8, &psInitPtr)) return INVALID_PHYS_ADDR;
    if (psInitPtr == 0) return INVALID_PHYS_ADDR;

    current = psInitPtr;
    guard   = 0;
    matched = 0;

    do {
        if (++guard > 1024) break;

        ZeroMem(imgName, sizeof(imgName));
        if (ReadGuestVa(KernelCr3, current + EPROCESS_NAME, 15, imgName))
        {
            imgName[15] = '\0';
            if (AsciiStrniEq(imgName, Name, nameLen))
            {
                if (matched == SkipCount)
                {
                    UINT64 dtb;
                    if (!ReadGuestVa(KernelCr3, current + EPROCESS_DTB, 8, &dtb))
                        return INVALID_PHYS_ADDR;
                    return dtb & ~0xFFFULL;
                }
                matched++;
            }
        }

        if (!ReadGuestVa(KernelCr3, current + EPROCESS_LINKS, 8, &flink) || flink == 0) break;
        current = flink - EPROCESS_LINKS;

    } while (current != psInitPtr);

    return INVALID_PHYS_ADDR;
}

UINT64
FindProcessBase (
    IN UINT64       KernelCr3,
    IN UINT64       KernelBase,
    IN CONST CHAR8 *Name,
    IN UINT32       SkipCount
    )
{
    UINT64 psInitSysProc;
    UINT64 psInitPtr;
    UINT64 current;
    UINT64 flink;
    CHAR8  imgName[16];
    UINT32 nameLen;
    UINT32 guard;
    UINT32 matched;

    nameLen = (UINT32)AsciiStrLen(Name);
    if (nameLen == 0 || nameLen > 15) return INVALID_PHYS_ADDR;

    psInitSysProc = FindExport(KernelCr3, KernelBase, "PsInitialSystemProcess");
    if (psInitSysProc == INVALID_PHYS_ADDR) return INVALID_PHYS_ADDR;

    if (!ReadGuestVa(KernelCr3, psInitSysProc, 8, &psInitPtr) || psInitPtr == 0)
        return INVALID_PHYS_ADDR;

    current = psInitPtr;
    guard   = 0;
    matched = 0;

    do {
        if (++guard > 1024) break;

        ZeroMem(imgName, sizeof(imgName));
        if (ReadGuestVa(KernelCr3, current + EPROCESS_NAME, 15, imgName))
        {
            imgName[15] = '\0';
            if (AsciiStrniEq(imgName, Name, nameLen))
            {
                if (matched == SkipCount)
                {
                    UINT64 base;
                    if (!ReadGuestVa(KernelCr3, current + EPROCESS_SECTIONBASE, 8, &base))
                        return INVALID_PHYS_ADDR;
                    return base;
                }
                matched++;
            }
        }

        if (!ReadGuestVa(KernelCr3, current + EPROCESS_LINKS, 8, &flink) || flink == 0) break;
        current = flink - EPROCESS_LINKS;

    } while (current != psInitPtr);

    return INVALID_PHYS_ADDR;
}

BOOLEAN
WriteGuestVa (
    IN UINT64 Cr3,
    IN UINT64 Va,
    IN UINT64 Size,
    IN VOID  *HostBuf
    )
{
    UINT64  remaining = Size;
    UINT64  va        = Va;
    UINT8  *src       = (UINT8 *)HostBuf;

    while (remaining > 0)
    {
        UINT64 pageOff = va & 0xFFFULL;
        UINT64 chunk   = SIZE_4KB - pageOff;
        UINT64 pa;

        if (chunk > remaining) chunk = remaining;

        pa = GvaToGpa(Cr3, va);
        if (pa == INVALID_PHYS_ADDR) return FALSE;

        CopyMem((VOID *)(UINTN)pa, src, (UINTN)chunk);

        src       += chunk;
        va        += chunk;
        remaining -= chunk;
    }
    return TRUE;
}

UINT64
ListProcesses (
    IN UINT64 KernelCr3,
    IN UINT64 KernelBase,
    IN UINT64 CallerCr3,
    IN UINT64 DestVa,
    IN UINT64 MaxProcs
    )
{
    UINT64 psInitSysProc;
    UINT64 psInitPtr;
    UINT64 current;
    UINT64 flink;
    UINT64 count;
    UINT32 guard;
    CHAR8  entry[PROC_ENTRY_SIZE];

    if (MaxProcs == 0 || MaxProcs > 1024) return 0;

    psInitSysProc = FindExport(KernelCr3, KernelBase, "PsInitialSystemProcess");
    if (psInitSysProc == INVALID_PHYS_ADDR) return 0;

    if (!ReadGuestVa(KernelCr3, psInitSysProc, 8, &psInitPtr) || psInitPtr == 0) return 0;

    current = psInitPtr;
    count   = 0;
    guard   = 0;

    do {
        if (++guard > 1024) break;

        ZeroMem(entry, sizeof(entry));

        // Read name (first 15 bytes + forced null at [15])
        ReadGuestVa(KernelCr3, current + EPROCESS_NAME, 15, entry);
        entry[15] = '\0';

        // Read DTB into bytes [16..23]
        ReadGuestVa(KernelCr3, current + EPROCESS_DTB, 8, entry + 16);

        // Write entry into caller's buffer
        if (!WriteGuestVa(CallerCr3, DestVa + count * PROC_ENTRY_SIZE, PROC_ENTRY_SIZE, entry))
            break;

        count++;
        if (count >= MaxProcs) break;

        if (!ReadGuestVa(KernelCr3, current + EPROCESS_LINKS, 8, &flink) || flink == 0) break;
        current = flink - EPROCESS_LINKS;

    } while (current != psInitPtr);

    return count;
}

UINT64
FindModuleBase (
    IN UINT64       KernelCr3,
    IN UINT64       KernelBase,
    IN CONST CHAR8 *ProcessName,
    IN UINT32       SkipCount,
    IN CONST CHAR8 *DllName
    )
{
    UINT64  psInitSysProc;
    UINT64  psInitPtr;
    UINT64  current;
    UINT64  flink;
    CHAR8   imgName[16];
    UINT32  pNameLen;
    UINT32  dNameLen;
    UINT32  procGuard;
    UINT32  matched;

    pNameLen = (UINT32)AsciiStrLen(ProcessName);
    dNameLen = (UINT32)AsciiStrLen(DllName);
    if (pNameLen == 0 || pNameLen > 15 || dNameLen == 0 || dNameLen > 64)
        return INVALID_PHYS_ADDR;

    psInitSysProc = FindExport(KernelCr3, KernelBase, "PsInitialSystemProcess");
    if (psInitSysProc == INVALID_PHYS_ADDR) return INVALID_PHYS_ADDR;

    if (!ReadGuestVa(KernelCr3, psInitSysProc, 8, &psInitPtr) || psInitPtr == 0)
        return INVALID_PHYS_ADDR;

    current   = psInitPtr;
    procGuard = 0;
    matched   = 0;

    do {
        if (++procGuard > 512) return INVALID_PHYS_ADDR;

        ZeroMem(imgName, sizeof(imgName));
        if (ReadGuestVa(KernelCr3, current + EPROCESS_NAME, 15, imgName))
        {
            imgName[15] = '\0';
            if (AsciiStrniEq(imgName, ProcessName, pNameLen))
            {
                if (matched < SkipCount) { matched++; goto proc_next; }
                matched++;
                {
                UINT64 procDtb;
                UINT64 pebVa;
                UINT64 ldrVa;
                UINT64 listHead;
                UINT64 eFlink;
                UINT32 modGuard;

                if (!ReadGuestVa(KernelCr3, current + EPROCESS_DTB, 8, &procDtb))
                    return INVALID_PHYS_ADDR;
                procDtb &= ~0xFFFULL;

                if (!ReadGuestVa(KernelCr3, current + EPROCESS_PEB_OFF, 8, &pebVa) || pebVa == 0)
                    return INVALID_PHYS_ADDR;

                if (!ReadGuestVa(procDtb, pebVa + PEB_LDR, 8, &ldrVa) || ldrVa == 0)
                    return INVALID_PHYS_ADDR;

                // listHead is the VA of the sentinel LIST_ENTRY (InMemoryOrderModuleList)
                listHead = ldrVa + LDR_INMEMORDER;
                if (!ReadGuestVa(procDtb, listHead, 8, &eFlink))
                    return INVALID_PHYS_ADDR;

                modGuard = 0;
                while (eFlink != listHead)
                {
                    UINT64  entryBase;
                    UINT16  wLen;
                    UINT64  wBufPtr;
                    UINT64  dllBase;
                    UINT8   wbuf[130];
                    UINT32  i;
                    BOOLEAN nameMatch;

                    if (++modGuard > 256) break;

                    entryBase = eFlink - LDR_ENTRY_LINK;
                    wLen      = 0;
                    wBufPtr   = 0;
                    dllBase   = 0;
                    ZeroMem(wbuf, sizeof(wbuf));

                    if (!ReadGuestVa(procDtb, entryBase + LDR_NAME_LEN, 2, &wLen))
                        goto mod_next;
                    // wLen is byte count; number of chars = wLen/2
                    if ((UINT32)(wLen / 2) != dNameLen)
                        goto mod_next;
                    if (!ReadGuestVa(procDtb, entryBase + LDR_NAME_BUF, 8, &wBufPtr) || wBufPtr == 0)
                        goto mod_next;
                    if (!ReadGuestVa(procDtb, wBufPtr, (UINT64)wLen, wbuf))
                        goto mod_next;

                    nameMatch = TRUE;
                    for (i = 0; i < dNameLen; i++) {
                        if (ToLower((CHAR8)wbuf[i * 2]) != ToLower(DllName[i])) {
                            nameMatch = FALSE;
                            break;
                        }
                    }

                    if (nameMatch) {
                        if (!ReadGuestVa(procDtb, entryBase + LDR_DLLBASE, 8, &dllBase))
                            return INVALID_PHYS_ADDR;
                        return dllBase;
                    }

                mod_next:
                    if (!ReadGuestVa(procDtb, eFlink, 8, &eFlink))
                        break;
                }
                return INVALID_PHYS_ADDR;
                } // end matched block
            }
        }

proc_next:
        if (!ReadGuestVa(KernelCr3, current + EPROCESS_LINKS, 8, &flink) || flink == 0)
            return INVALID_PHYS_ADDR;
        current = flink - EPROCESS_LINKS;

    } while (current != psInitPtr);

    return INVALID_PHYS_ADDR;
}
