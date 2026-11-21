param(
  [string]$ProcName = "httest",
  [uint64]$Addr     = 0x40100B,
  [uint32]$Len      = 16
)

$src = @"
using System;
using System.Runtime.InteropServices;

public static class Native {
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool ReadProcessMemory(IntPtr h, UIntPtr addr, byte[] buf, UIntPtr size, out UIntPtr got);

  [DllImport("kernel32.dll")]
  public static extern bool CloseHandle(IntPtr h);
}
"@
Add-Type -TypeDefinition $src

$p = Get-Process -Name $ProcName -ErrorAction Stop | Select-Object -First 1
Write-Host ("pid = {0}" -f $p.Id)
$h = [Native]::OpenProcess(0x10, $false, [uint32]$p.Id)
if ($h -eq [IntPtr]::Zero) {
  $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
  throw "OpenProcess failed ($err). Run elevated."
}

$buf = New-Object byte[] $Len
$got = [UIntPtr]::Zero
$ok  = [Native]::ReadProcessMemory($h, [UIntPtr]::new([uint64]$Addr), $buf, [UIntPtr]::new([uint64]$Len), [ref]$got)
[Native]::CloseHandle($h) | Out-Null

if (-not $ok) {
  $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
  throw "ReadProcessMemory failed ($err)"
}

$hex = ($buf | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
Write-Host ("0x{0:X8}: {1}" -f $Addr, $hex)

$firstByte = $buf[0]
if ($firstByte -eq 0xC3) {
  Write-Host "[OK] first byte = 0xC3 (ret) -- HOOK IS INVISIBLE TO GUEST READS" -ForegroundColor Green
} elseif ($firstByte -eq 0xCC) {
  Write-Host "[!!] first byte = 0xCC (int3) -- HOOK IS VISIBLE TO GUEST READS" -ForegroundColor Red
} else {
  Write-Host ("[??] unexpected first byte = 0x{0:X2}" -f $firstByte) -ForegroundColor Yellow
}
