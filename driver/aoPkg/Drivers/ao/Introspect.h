#pragma once
#include <Uefi.h>

#define INVALID_PHYS_ADDR   (~0ULL)
#define INTROSPECT_MAX_READ SIZE_4KB    // max bytes per READ_MEM call

// EPROCESS field offsets for Win11 25H2 (build 26200), shifted -0x270 from Win10.
// PEB: Win10 was 0x550; 0x550 − 0x270 = 0x2E0.
#define EPROCESS_PEB    0x2E0ULL

//
// Translate a guest virtual address to a guest physical address using the
// supplied CR3.  In an identity-mapped host (NPT) the returned PA is also
// a valid host pointer.  Returns INVALID_PHYS_ADDR if any page-table level
// is not present.
//
UINT64
GvaToGpa (
    IN UINT64 Cr3,
    IN UINT64 Va
    );

//
// Read Size bytes from guest virtual address Va (in the address space
// identified by Cr3) into HostBuf.  Handles page-boundary crossings.
// Returns TRUE if all bytes were read successfully.
//
BOOLEAN
ReadGuestVa (
    IN  UINT64 Cr3,
    IN  UINT64 Va,
    IN  UINT64 Size,
    OUT VOID*  HostBuf
    );

//
// Scan backwards from GuestLstar (IA32_LSTAR as saved in the guest VMCB)
// to locate ntoskrnl's MZ/PE header.  Returns the base virtual address or
// INVALID_PHYS_ADDR on failure.
//
UINT64
FindKernelBase (
    IN UINT64 GuestCr3,
    IN UINT64 GuestLstar
    );

//
// Walk ntoskrnl's export table (from KernelBase) and return the virtual
// address of the named export, or INVALID_PHYS_ADDR if not found.
//
UINT64
FindExport (
    IN UINT64       GuestCr3,
    IN UINT64       KernelBase,
    IN CONST CHAR8* Name
    );

//
// Walk PsInitialSystemProcess → ActiveProcessLinks to find the EPROCESS
// whose ImageFileName matches Name.  SkipCount skips that many matches
// before returning.  Returns DirectoryTableBase or INVALID_PHYS_ADDR.
//
UINT64
FindProcessCr3 (
    IN UINT64       KernelCr3,
    IN UINT64       KernelBase,
    IN CONST CHAR8* Name,
    IN UINT32       SkipCount
    );

//
// Write Size bytes from HostBuf into the guest virtual address Va (in the
// address space identified by Cr3).  Handles page-boundary crossings.
// Returns TRUE if all bytes were written successfully.
//
BOOLEAN
WriteGuestVa (
    IN UINT64 Cr3,
    IN UINT64 Va,
    IN UINT64 Size,
    IN VOID*  HostBuf
    );

//
// Walk PsInitialSystemProcess → ActiveProcessLinks to find the EPROCESS
// whose ImageFileName matches Name.  SkipCount skips that many matches
// before returning (0 = first match, 1 = second, etc.).
// Returns SectionBaseAddress of the Nth match, or INVALID_PHYS_ADDR.
//
UINT64
FindProcessBase (
    IN UINT64       KernelCr3,
    IN UINT64       KernelBase,
    IN CONST CHAR8* Name,
    IN UINT32       SkipCount
    );

//
// Walk PsInitialSystemProcess → ActiveProcessLinks and write up to MaxProcs
// entries into a caller-provided guest buffer at DestVa.  Each entry is
// PROC_ENTRY_SIZE bytes: ImageFileName[16] followed by DirectoryTableBase[8].
// Returns the number of entries written (0 on error).
//
#define PROC_ENTRY_SIZE  24ULL   // 16 (name) + 8 (dtb)

UINT64
ListProcesses (
    IN UINT64 KernelCr3,
    IN UINT64 KernelBase,
    IN UINT64 CallerCr3,
    IN UINT64 DestVa,
    IN UINT64 MaxProcs
    );

//
// Walk PsInitialSystemProcess → EPROCESS for ProcessName → PEB.Ldr →
// InMemoryOrderModuleList to find DllName (case-insensitive, e.g. "dxgi.dll").
// Returns DllBase VA of the first matching module, or INVALID_PHYS_ADDR.
//
UINT64
FindModuleBase (
    IN UINT64       KernelCr3,
    IN UINT64       KernelBase,
    IN CONST CHAR8 *ProcessName,
    IN UINT32       SkipCount,
    IN CONST CHAR8 *DllName
    );
