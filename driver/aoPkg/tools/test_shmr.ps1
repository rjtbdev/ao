# Test whether the shmr hypervisor is running underneath this Windows session.
# Issues CPUID 0x40000000 (the hypervisor vendor leaf) and checks for "ao".

$ErrorActionPreference = 'Stop'

$cs = @"
using System;
using System.Runtime.InteropServices;

public static class Cpuid {
    [DllImport("kernel32")]
    static extern IntPtr VirtualAlloc(IntPtr addr, UIntPtr size, uint type, uint protect);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate void CpuidFn(uint leaf, IntPtr outputs);

    static IntPtr s_code = IntPtr.Zero;
    static CpuidFn s_fn = null;

    public static int[] Get(uint leaf) {
        if (s_code == IntPtr.Zero) {
            // x64 shellcode:
            //   push rbx
            //   push rsi
            //   mov  rsi, rdx        ; save output pointer
            //   mov  eax, ecx        ; eax = leaf
            //   xor  ecx, ecx        ; subleaf = 0
            //   cpuid
            //   mov  [rsi+0], eax
            //   mov  [rsi+4], ebx
            //   mov  [rsi+8], ecx
            //   mov  [rsi+12], edx
            //   pop  rsi
            //   pop  rbx
            //   ret
            byte[] code = new byte[] {
                0x53, 0x56, 0x48, 0x89, 0xD6, 0x89, 0xC8, 0x31,
                0xC9, 0x0F, 0xA2, 0x89, 0x06, 0x89, 0x5E, 0x04,
                0x89, 0x4E, 0x08, 0x89, 0x56, 0x0C, 0x5E, 0x5B,
                0xC3
            };
            s_code = VirtualAlloc(IntPtr.Zero, (UIntPtr)code.Length, 0x3000, 0x40);
            if (s_code == IntPtr.Zero) throw new Exception("VirtualAlloc failed");
            Marshal.Copy(code, 0, s_code, code.Length);
            s_fn = (CpuidFn)Marshal.GetDelegateForFunctionPointer(s_code, typeof(CpuidFn));
        }
        int[] result = new int[4];
        GCHandle h = GCHandle.Alloc(result, GCHandleType.Pinned);
        try {
            s_fn(leaf, h.AddrOfPinnedObject());
        } finally {
            h.Free();
        }
        return result;
    }
}
"@

Add-Type -TypeDefinition $cs

$r = [Cpuid]::Get(0x40000000)
$eax = $r[0]; $ebx = $r[1]; $ecx = $r[2]; $edx = $r[3]

function ToHex32([int]$v) { '0x' + ('{0:X8}' -f ($v -band 0xFFFFFFFF)) }

Write-Host ('CPUID(0x40000000):')
Write-Host ('  EAX = ' + (ToHex32 $eax))
Write-Host ('  EBX = ' + (ToHex32 $ebx))
Write-Host ('  ECX = ' + (ToHex32 $ecx))
Write-Host ('  EDX = ' + (ToHex32 $edx))

# Reconstruct vendor string from EBX|ECX|EDX (little-endian)
$bytes = New-Object 'byte[]' 12
for ($i = 0; $i -lt 4; $i++) {
    $bytes[$i]    = ($ebx -shr ($i * 8)) -band 0xFF
    $bytes[$i+4]  = ($ecx -shr ($i * 8)) -band 0xFF
    $bytes[$i+8]  = ($edx -shr ($i * 8)) -band 0xFF
}
$vendor = [System.Text.Encoding]::ASCII.GetString($bytes)
Write-Host ('  Vendor = "' + $vendor + '"')
Write-Host ''

if ($vendor.StartsWith('ao')) {
    Write-Host '*** shmr hypervisor DETECTED ***' -ForegroundColor Green
    exit 0
}
if ($eax -eq 0 -and $ebx -eq 0 -and $ecx -eq 0 -and $edx -eq 0) {
    Write-Host 'No hypervisor present (CPUID returned zero).' -ForegroundColor Yellow
    exit 1
}
Write-Host ('A different hypervisor is present: "' + $vendor + '"') -ForegroundColor Yellow
exit 2
