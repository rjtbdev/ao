# Read shmr diagnostic NVRAM variables from Windows.
# Run from an admin PowerShell with SeSystemEnvironmentPrivilege granted.

$ErrorActionPreference = 'Stop'

$cs = @"
using System;
using System.Runtime.InteropServices;

public static class Native {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern uint GetFirmwareEnvironmentVariableW(
        string lpName, string lpGuid, byte[] pValue, uint nSize);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr h, uint desired, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool LookupPrivilegeValue(string sys, string name, out long luid);

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES {
        public uint PrivilegeCount;
        public long Luid;
        public uint Attributes;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(IntPtr h, bool disableAll,
        ref TOKEN_PRIVILEGES newState, uint bufLen, IntPtr prev, IntPtr retLen);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
}
"@

Add-Type -TypeDefinition $cs

$tok = [IntPtr]::Zero
[void][Native]::OpenProcessToken([Native]::GetCurrentProcess(), 0x28, [ref] $tok)
$luid = [long]0
[void][Native]::LookupPrivilegeValue($null, 'SeSystemEnvironmentPrivilege', [ref] $luid)
$tp = New-Object Native+TOKEN_PRIVILEGES
$tp.PrivilegeCount = 1
$tp.Luid = $luid
$tp.Attributes = 2
[void][Native]::AdjustTokenPrivileges($tok, $false, [ref] $tp, 0, [IntPtr]::Zero, [IntPtr]::Zero)
$adjErr = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
if ($adjErr -eq 1300) {
    Write-Host 'SeSystemEnvironmentPrivilege not in token. Grant it via:' -ForegroundColor Yellow
    Write-Host '  secpol.msc -> User Rights Assignment -> Modify firmware environment values -> add your user'
    Write-Host '  then log out and back in.'
    exit 1
}

$guid = '{7E5C0A2B-4D1F-4623-B918-3E7A2C884F91}'

function Read-Var($name, $size) {
    $buf = New-Object byte[] $size
    $n = [Native]::GetFirmwareEnvironmentVariableW($name, $guid, $buf, $buf.Length)
    if ($n -eq 0) { return $null }
    return $buf
}

Write-Host '=== shmr diagnostic NVRAM dump ===' -ForegroundColor Cyan
Write-Host ''

# shmrMilestone — last pre-VMRUN milestone from Setup.c
$ms = Read-Var 'shmrMilestone' 4
if ($ms) {
    $v = [BitConverter]::ToUInt32($ms, 0)
    Write-Host ('shmrMilestone:  0x{0:X8}' -f $v)
} else {
    Write-Host 'shmrMilestone:  <not set>'
}

# shmrProgress — host-side code path bitfield
$pr = Read-Var 'shmrProgress' 4
if ($pr) {
    $v = [BitConverter]::ToUInt32($pr, 0)
    Write-Host ('shmrProgress:   0x{0:X8}' -f $v)
    $bits = $v -band 0xFF
    if ($bits -band 0x01) { Write-Host '  bit 0: HandleVmExit entered' }
    if ($bits -band 0x02) { Write-Host '  bit 1: HandleCpuid called' }
    if ($bits -band 0x04) { Write-Host '  bit 2: HandleVmmcall called' }
    if ($bits -band 0x08) { Write-Host '  bit 3: default VMEXIT branch (UNHANDLED EXIT)' -ForegroundColor Yellow }
    if ($bits -band 0x10) { Write-Host '  bit 4: HandleHostException (HOST CRASH)' -ForegroundColor Red }
    if ($bits -band 0x20) { Write-Host '  bit 5: HandleCpuid returned' }
    if ($bits -band 0x40) { Write-Host '  bit 6: HandleMsr called' }
    if ($bits -band 0x80) { Write-Host '  bit 7: HandleInitSignal called' }
} else {
    Write-Host 'shmrProgress:   <not set>  (no VMEXIT happened, or NVRAM write hung)'
}

# shmrExitCode — last unhandled VMEXIT code
$ec = Read-Var 'shmrExitCode' 8
if ($ec) {
    $v = [BitConverter]::ToUInt64($ec, 0)
    Write-Host ('shmrExitCode:   0x{0:X16}' -f $v)
    $lo = $v -band 0xFFFFFFFF
    switch ($lo) {
        0x80   { Write-Host '  -> VMEXIT_VMRUN (guest tried VMRUN)' }
        0x7C   { Write-Host '  -> VMEXIT_MSR (MSR access intercept fired)' }
        0x7B   { Write-Host '  -> VMEXIT_IOIO (port I/O)' }
        0x400  { Write-Host '  -> VMEXIT_NPF (nested page fault - NPT did not map an address)' }
        0x7F   { Write-Host '  -> VMEXIT_SHUTDOWN (guest triple-faulted)' }
        0xFFFFFFFF { Write-Host '  -> VMEXIT_INVALID (VMRUN consistency check failed)' }
        default { Write-Host ('  -> see AMD APM Vol 2 App C for code 0x{0:X}' -f $lo) }
    }
}

# shmrException — host exception vector if HandleHostException fired
$ex = Read-Var 'shmrException' 4
if ($ex) {
    $v = [BitConverter]::ToUInt32($ex, 0)
    Write-Host ('shmrException:  vector 0x{0:X2}' -f $v)
    switch ($v) {
        6  { Write-Host '  -> #UD (invalid opcode)' }
        8  { Write-Host '  -> #DF (double fault)' }
        13 { Write-Host '  -> #GP (general protection)' }
        14 { Write-Host '  -> #PF (page fault)' }
    }
}
