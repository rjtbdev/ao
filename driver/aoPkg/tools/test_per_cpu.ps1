# Pins to each CPU and runs CPUID(0x40000000). Tells us which CPUs are
# still virtualized by shmr (return "ao") vs unvirtualized (return zeros).

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
        try { s_fn(leaf, h.AddrOfPinnedObject()); } finally { h.Free(); }
        return result;
    }
}
"@
Add-Type -TypeDefinition $cs

$proc = [System.Diagnostics.Process]::GetCurrentProcess()
$origAffinity = $proc.ProcessorAffinity
$cpuCount = [System.Environment]::ProcessorCount

Write-Host ("Testing $cpuCount CPUs:")
$anyShmr = $false
for ($cpu = 0; $cpu -lt $cpuCount; $cpu++) {
    $mask = [IntPtr]([long]1 -shl $cpu)
    try {
        $proc.ProcessorAffinity = $mask
        Start-Sleep -Milliseconds 50
        $r = [Cpuid]::Get(0x40000000)
        $eax = $r[0]; $ebx = $r[1]; $ecx = $r[2]; $edx = $r[3]
        $bytes = New-Object 'byte[]' 12
        for ($i = 0; $i -lt 4; $i++) {
            $bytes[$i]   = ($ebx -shr ($i * 8)) -band 0xFF
            $bytes[$i+4] = ($ecx -shr ($i * 8)) -band 0xFF
            $bytes[$i+8] = ($edx -shr ($i * 8)) -band 0xFF
        }
        $vendor = [System.Text.Encoding]::ASCII.GetString($bytes)
        $tag = if ($vendor.StartsWith('ao')) { '*** SHMR ***'; $anyShmr = $true }
               elseif ($eax -eq 0 -and $ebx -eq 0) { '(none)' }
               else { "other: $vendor" }
        Write-Host ("  CPU {0}: EAX=0x{1:X8} EBX=0x{2:X8} {3}" -f $cpu, ($eax -band 0xFFFFFFFF), ($ebx -band 0xFFFFFFFF), $tag)
    } catch {
        Write-Host ("  CPU {0}: pin failed: {1}" -f $cpu, $_.Exception.Message)
    }
}
$proc.ProcessorAffinity = $origAffinity

Write-Host ''
if ($anyShmr) {
    Write-Host 'shmr is alive on at least one CPU.' -ForegroundColor Green
} else {
    Write-Host 'shmr appears unloaded on every CPU.' -ForegroundColor Yellow
}
