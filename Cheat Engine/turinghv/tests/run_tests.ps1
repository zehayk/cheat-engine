<#
    run_tests.ps1 -- end-to-end test of Cheat Engine's Turing-HV backend against the LIVE hypervisor.

    Builds two test targets (64-bit and 32-bit, with known memory), starts them, starts Cheat Engine with a Lua
    driver in bin\autorun that exercises the backend through Cheat Engine's own code paths (open, read, write, AOB
    scan, memory scan, modules, exports, symbols, disassembly, threads, write watch, token mode, the CR3 ladder,
    read-only writes with the Windows fallback, auto assembler, target exit, the status window, kernel reads), and
    prints the results.  The driver is removed from autorun afterwards.

    Needs: run as administrator, turinghv.efi running, thvbridge.exe trusted (read + write), clang + Visual Studio
    C++ build tools (for the targets), and a built cheatengine-x86_64.exe.

        powershell -ExecutionPolicy Bypass -File "Cheat Engine\turinghv\tests\run_tests.ps1"
#>
param([string]$Work = (Join-Path $env:TEMP 'thvtest'), [string]$Exe = 'cheatengine-x86_64.exe')
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$bin = (Resolve-Path (Join-Path $here '..\..\bin')).Path
New-Item -ItemType Directory -Force $Work | Out-Null

function Import-VsEnv($bat) {
    cmd /c "`"$bat`" >nul 2>&1 && set" | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process') }
    }
}
$vsroot = 'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build'
$t64exe = Join-Path $Work 'thvtarget.exe'
$t32exe = Join-Path $Work 'thvtarget32.exe'
$src = Get-Item (Join-Path $here 'thvtarget.c')
if ((Test-Path $t64exe) -and (Get-Item $t64exe).LastWriteTime -lt $src.LastWriteTime) { Remove-Item $t64exe -Force }
if ((Test-Path $t32exe) -and (Get-Item $t32exe).LastWriteTime -lt $src.LastWriteTime) { Remove-Item $t32exe -Force }
if (-not (Test-Path $t64exe)) {
    Import-VsEnv "$vsroot\vcvars64.bat"
    & clang -O1 -D_CRT_SECURE_NO_WARNINGS (Join-Path $here 'thvtarget.c') '-Wl,/INCREMENTAL:NO' -o $t64exe   # no ILT: &bump is bump itself, not a jmp thunk
}
if (-not (Test-Path $t32exe)) {
    cmd /c "`"$vsroot\vcvars32.bat`" >nul 2>&1 && clang -m32 -O1 -D_CRT_SECURE_NO_WARNINGS `"$(Join-Path $here 'thvtarget.c')`" -Wl,/INCREMENTAL:NO -o `"$t32exe`""
}

$run = Join-Path $Work 'run'
Remove-Item $run -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force "$run\32", "$run\victim" | Out-Null
$targets = @(
    (Start-Process $t64exe -ArgumentList "`"$run`"" -PassThru -WindowStyle Hidden),
    (Start-Process $t32exe -ArgumentList "`"$run\32`"" -PassThru -WindowStyle Hidden),
    (Start-Process $t64exe -ArgumentList "`"$run\victim`"" -PassThru -WindowStyle Hidden)
)
Start-Sleep -Milliseconds 800

$driver = Join-Path $bin 'autorun\zz_turinghv_test.lua'
Copy-Item (Join-Path $here 'zz_turinghv_test.lua') $driver -Force
try {
    $env:THVTEST_DIR = $run
    $ce = Start-Process (Join-Path $bin $Exe) -PassThru
    if (-not $ce.WaitForExit(300000)) {
        Write-Warning 'Cheat Engine did not finish in 5 minutes; its windows:'
        & (Join-Path $here 'winlist.ps1') -ProcessId $ce.Id
        Stop-Process $ce -Force
    }
} finally {
    Remove-Item $driver -Force -ErrorAction SilentlyContinue
    $targets | ForEach-Object { Stop-Process $_ -Force -ErrorAction SilentlyContinue }
}
Get-Content (Join-Path $run 'results.txt')
