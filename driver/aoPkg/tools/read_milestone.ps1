# Read the shmr diagnostic milestone from EFI NVRAM.
# Run from an admin PowerShell.

$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host 'Must be run as administrator (need SeSystemEnvironmentPrivilege).'
    Write-Host 'Start menu -> right-click PowerShell -> Run as administrator, then re-run.'
    exit 1
}

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

# Enable SE_SYSTEM_ENVIRONMENT_NAME
$tok = [IntPtr]::Zero
$ok = [Native]::OpenProcessToken([Native]::GetCurrentProcess(), 0x28, [ref] $tok)
if (-not $ok) {
    $e = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw ('OpenProcessToken failed: error ' + $e)
}
Write-Host '[ok] OpenProcessToken'

$luid = [long]0
$ok = [Native]::LookupPrivilegeValue($null, 'SeSystemEnvironmentPrivilege', [ref] $luid)
if (-not $ok) {
    $e = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw ('LookupPrivilegeValue failed: error ' + $e)
}
Write-Host ('[ok] LookupPrivilegeValue -> LUID=' + $luid)

$tp = New-Object Native+TOKEN_PRIVILEGES
$tp.PrivilegeCount = 1
$tp.Luid = $luid
$tp.Attributes = 2
$ok = [Native]::AdjustTokenPrivileges($tok, $false, [ref] $tp, 0, [IntPtr]::Zero, [IntPtr]::Zero)
$adjErr = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
Write-Host ('[..] AdjustTokenPrivileges -> ok=' + $ok + ' lastError=' + $adjErr + ' (0=enabled, 1300=ERROR_NOT_ALL_ASSIGNED -- privilege not in token)')

if ($adjErr -eq 1300) {
    Write-Host ''
    Write-Host 'The token does not contain SeSystemEnvironmentPrivilege. Check:'
    Write-Host '  whoami /priv | findstr SystemEnvironment'
    Write-Host 'If absent, this PowerShell is not actually elevated despite "Run as admin".'
    exit 1
}

# Read the variable
$buf = New-Object byte[] 4
$n = [Native]::GetFirmwareEnvironmentVariableW(
    'shmrMilestone',
    '{7E5C0A2B-4D1F-4623-B918-3E7A2C884F91}',
    $buf, $buf.Length)

if ($n -eq 0) {
    $e = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Host ("GetFirmwareEnvironmentVariable failed: Win32 error {0}" -f $e)
    Write-Host '  (203 = ERROR_ENVVAR_NOT_FOUND -- ao never wrote the variable)'
    exit 1
}

$value = [BitConverter]::ToUInt32($buf, 0)
$hex = '0x' + $value.ToString('X8')
Write-Host ('shmrMilestone = ' + $hex)

$lo = $value -band 0xFFFF
$hi = ($value -shr 16) -band 0xFFFF

if ($lo -eq 0x0090) {
    $vec = $hi
    Write-Host ('  -> HOST EXCEPTION fired, vector 0x' + $vec.ToString('X') + ' (#UD=6, #DF=8, #GP=13, #PF=14)')
}
elseif ($value -eq 0xA51E0010) { Write-Host '  -> post-print, before InitializeHostData' }
elseif ($value -eq 0xA51E0020) { Write-Host '  -> after InitializeHostData, before CR3 swap' }
elseif ($value -eq 0xA51E0025) { Write-Host '  -> right BEFORE SwitchToHostContext' }
elseif ($value -eq 0xA51E0030) { Write-Host '  -> RETURNED from SwitchToHostContext' }
elseif ($value -eq 0xA51E0040) { Write-Host '  -> after HostVmcb VMSAVE' }
elseif ($value -eq 0xA51E0050) { Write-Host '  -> control returned to VirtualizeProcessor' }
elseif ($value -eq 0xA51E0060) { Write-Host '  -> about to call AsmLaunchVm (VMRUN)' }
elseif ($value -eq 0xA51E0070) { Write-Host '  -> AsmLaunchVm RETURNED' }
elseif ($value -eq 0xA51E0080) { Write-Host '  -> *** HandleVmExit was entered *** VMRUN came back' }
else { Write-Host '  -> unrecognized milestone' }
