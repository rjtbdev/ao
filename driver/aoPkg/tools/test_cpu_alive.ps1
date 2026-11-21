# Spawns one busy-loop job per logical CPU, pinned to that CPU only.
# Uses Start-ThreadJob (ships with PS 5.1+ via PowerShellGet).
$ErrorActionPreference = 'Stop'

if (-not (Get-Command Start-ThreadJob -ErrorAction SilentlyContinue)) {
    Write-Host "ThreadJob module not available; falling back to Start-Job (slower)."
    $startCmd = 'Start-Job'
} else {
    $startCmd = 'Start-ThreadJob'
}

$cpuCount = [System.Environment]::ProcessorCount
Write-Host ("Spawning $cpuCount pinned jobs via $startCmd, ~1s of work each...")

$jobs = @()
for ($i = 0; $i -lt $cpuCount; $i++) {
    $j = & $startCmd -ArgumentList $i -ScriptBlock {
        param($cpuIdx)
        Add-Type -Name K -Namespace S -MemberDefinition @'
            [System.Runtime.InteropServices.DllImport("kernel32")]
            public static extern System.IntPtr GetCurrentThread();
            [System.Runtime.InteropServices.DllImport("kernel32")]
            public static extern System.UIntPtr SetThreadAffinityMask(System.IntPtr h, System.UIntPtr m);
'@
        $h = [S.K]::GetCurrentThread()
        [void][S.K]::SetThreadAffinityMask($h, [UIntPtr]([uint64]1 -shl $cpuIdx))
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $x = 0
        for ($k = 0; $k -lt 20000000; $k++) { $x = $x + $k; if ($x -gt 1e18) { $x = 0 } }
        $sw.Stop()
        [pscustomobject]@{ Cpu = $cpuIdx; Seconds = $sw.Elapsed.TotalSeconds }
    }
    $jobs += @{ Cpu = $i; Job = $j }
}

# Wait up to 20 seconds total
Wait-Job -Job ($jobs | ForEach-Object { $_.Job }) -Timeout 20 | Out-Null

Write-Host ""
$missing = @()
foreach ($entry in $jobs) {
    $j = $entry.Job
    if ($j.State -eq 'Completed') {
        $r = Receive-Job -Job $j -Keep
        Write-Host ("  CPU {0}: {1:F2}s" -f $r.Cpu, $r.Seconds)
    } else {
        Write-Host ("  CPU {0}: STATE={1} (likely STUCK)" -f $entry.Cpu, $j.State) -ForegroundColor Red
        $missing += $entry.Cpu
    }
    Remove-Job -Job $j -Force -ErrorAction SilentlyContinue
}
Write-Host ""
if ($missing.Count -eq 0) {
    Write-Host "All CPUs executed work - SMP is genuinely live." -ForegroundColor Green
} else {
    Write-Host ("$($missing.Count) CPU(s) did not respond: " + ($missing -join ',')) -ForegroundColor Red
}
