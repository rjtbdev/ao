# Spawns N child powershell.exe processes, each pinned to one specific CPU
# via `start /AFFINITY` (works reliably outside of PowerShell's threadjob model).
# Each child writes its own marker file when done. 5-minute timeout.

$ErrorActionPreference = 'Stop'
$cpuCount = [System.Environment]::ProcessorCount
$tmpDir = Join-Path $env:TEMP "shmr-cpu-test-$(Get-Random)"
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

Write-Host ("Spawning $cpuCount processes (one per CPU), output dir: $tmpDir")
Write-Host "Each does a small amount of work. Up to 5 minutes total."
Write-Host ""

for ($i = 0; $i -lt $cpuCount; $i++) {
    $mask = "{0:X}" -f ([uint64]1 -shl $i)
    $marker = Join-Path $tmpDir "cpu$i.done"
    $cmd = "for(`$k=0;`$k -lt 1000000;`$k++){}; Set-Content -Path '$marker' -Value done"
    Start-Process -FilePath cmd.exe -ArgumentList ('/c', 'start', '/AFFINITY', $mask, '/B', '/MIN', 'powershell', '-NoProfile', '-Command', $cmd) -WindowStyle Hidden
}

$deadline = (Get-Date).AddSeconds(300)
$reportedDone = @{}
while ((Get-Date) -lt $deadline) {
    for ($i = 0; $i -lt $cpuCount; $i++) {
        if (-not $reportedDone.ContainsKey($i)) {
            $marker = Join-Path $tmpDir "cpu$i.done"
            if (Test-Path $marker) {
                $elapsed = ((Get-Date) - $deadline.AddSeconds(-300)).TotalSeconds
                Write-Host ("  CPU {0}: done at +{1:F1}s" -f $i, $elapsed)
                $reportedDone[$i] = $true
            }
        }
    }
    if ($reportedDone.Count -eq $cpuCount) { break }
    Start-Sleep -Milliseconds 250
}

Write-Host ""
$missing = @()
for ($i = 0; $i -lt $cpuCount; $i++) {
    if (-not $reportedDone.ContainsKey($i)) {
        Write-Host ("  CPU {0}: NEVER COMPLETED" -f $i) -ForegroundColor Red
        $missing += $i
    }
}
Write-Host ""
if ($missing.Count -eq 0) {
    Write-Host "All CPUs ran code successfully." -ForegroundColor Green
} else {
    Write-Host ("$($missing.Count) CPU(s) did not respond after 5 minutes: " + ($missing -join ','))
}
Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
