; ao_call.asm — x64 UD2 hypercall stub for ao HV
; Assemble with: ml64 /c ao_call.asm
;
; uint64_t ao_call(uint32_t cmd, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3);
;
; Windows x64 ABI in:   RCX=cmd  RDX=a0  R8=a1  R9=a2  [RSP+28h]=a3
; HV expects:           RAX=magic|cmd  RCX=a0  RDX=a1  R8=a2  R9=a3
; HV returns result in RAX.

AO_MAGIC EQU 56484F41h    ; "AOHV" (little-endian: A O H V)

.code

ao_call PROC
    ; Build RAX = (AO_MAGIC << 32) | cmd
    mov     eax, ecx                    ; cmd (zero-extends to 64-bit)
    mov     rcx, AO_MAGIC
    shl     rcx, 32
    or      rax, rcx

    ; Shuffle args: a0→RCX  a1→RDX  a2→R8  a3→R9
    mov     rcx, rdx                    ; a0
    mov     rdx, r8                     ; a1
    mov     r8,  r9                     ; a2
    mov     r9,  [rsp + 28h]            ; a3

    ud2                                 ; VMEXIT → HV handles, sets RAX
    ret
ao_call ENDP

END
