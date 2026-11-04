<#
    run_debugger_test.ps1 -- Cheat Engine's own debugger on the Turing-HV hypervisor, end to end, against
    antidebug-lab's adbg_target (a protected-game stand-in running ~40 anti-debug detectors the whole time).

    The Lua driver (zz_turinghv_dbg.lua, copied into bin\autorun for the run and removed after) selects the Turing-HV
    debugger, sets a breakpoint on hot_target, steps into / over, edits a register, continues, removes it, then does
    the same in snapshot mode on cold_target, and checks the decoded call stack. The target's own detectors report
    what they saw (DEBUGGER / INTEGRITY must stay 0; a parked thread shows in TIMING by design).

    Needs: administrator, a rev149+ image (rev149b for reliable steps), thvbridge.exe trusted, a built
    bin\cheatengine-x86_64-thv.exe (or -Exe), C:\projs\antidebug-lab\target\adbg_target.exe.

        powershell -ExecutionPolicy Bypass -File "Cheat Engine\turinghv\tests\run_debugger_test.ps1"
#>
param([string]$Work = (Join-Path $env:TEMP 'thvdbgtest'),
      [string]$Exe = 'cheatengine-x86_64-thv.exe',
      [string]$Target = 'C:\projs\antidebug-lab\target\adbg_target.exe')
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$bin = (Resolve-Path (Join-Path $here '..\..\bin')).Path
Remove-Item $Work -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $Work | Out-Null

# the target, its bait addresses read from its first lines
$psi = New-Object Diagnostics.ProcessStartInfo $Target
$psi.Arguments = "--seconds 75 --out `"$Work\adbg_result.txt`""
$psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.CreateNoWindow = $true
$tp = [Diagnostics.Process]::Start($psi)
$bait = $null
for ($i = 0; $i -lt 50 -and -not $bait; $i++) {
    $line = $tp.StandardOutput.ReadLine()
    if ($line -match 'hot_target=([0-9A-Fa-f]+) cold_target=([0-9A-Fa-f]+)') { $bait = $matches }
}
if (-not $bait) { $tp.Kill(); throw 'adbg_target printed no bait line' }
# keep draining its stdout so it never blocks
$null = $tp.StandardOutput.ReadToEndAsync()
"pid=$('{0:x}' -f $tp.Id)`nhot=$($bait[1])`ncold=$($bait[2])" | Out-File -Encoding ascii "$Work\target.txt"
Write-Host "adbg_target pid $($tp.Id), hot_target $($bait[1]), cold_target $($bait[2])"

$driver = Join-Path $bin 'autorun\zz_turinghv_dbg.lua'
Copy-Item (Join-Path $here 'zz_turinghv_dbg.lua') $driver -Force
try {
    $env:THVDBG_DIR = $Work
    $ce = Start-Process (Join-Path $bin $Exe) -PassThru
    if (-not $ce.WaitForExit(240000)) {
        Write-Warning 'Cheat Engine did not finish in 4 minutes; its windows:'
        & (Join-Path $here 'winlist.ps1') -ProcessId $ce.Id
        Stop-Process $ce -Force
    }
} finally {
    Remove-Item $driver -Force -ErrorAction SilentlyContinue
    $env:THVDBG_DIR = $null
}
$res = if (Test-Path "$Work\results.txt") { Get-Content "$Work\results.txt" } else { @('(no results.txt: Cheat Engine did not run the driver)') }
$res
# the target's own verdict (it writes it when its time is up)
if (-not $tp.WaitForExit(90000)) { $tp.Kill() }
$verdict = ''
if (Test-Path "$Work\adbg_result.txt") {
    Write-Host "`n--- what adbg_target detected while Cheat Engine's Turing-HV debugger worked on it:"
    Get-Content "$Work\adbg_result.txt" | Where-Object { $_ -match '^RESULT \S+ (DEBUGGER|INTEGRITY|TIMING|ENVIRONMENT) [1-9]' -or $_ -match '^SUMMARY' }
    $verdict = (Get-Content "$Work\adbg_result.txt" | Where-Object { $_ -match '^SUMMARY' } | Select-Object -First 1)
}
# exit 0 only when every check passed and the target saw no debugger / integrity trace
$sum = ($res | Where-Object { $_ -match '^SUMMARY pass=(\d+) fail=(\d+)' } | Select-Object -First 1)
$ok = $sum -and ($sum -match 'fail=0') -and ($verdict -match 'DEBUGGER=0 INTEGRITY=0')
if (-not $ok) { Write-Host "run_debugger_test: FAIL ($sum; target: $verdict)"; exit 1 }
Write-Host "run_debugger_test: PASS ($sum; target: $verdict)"
exit 0
