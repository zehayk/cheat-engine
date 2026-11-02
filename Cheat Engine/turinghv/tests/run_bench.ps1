<#
    run_bench.ps1 -- measures Cheat Engine's Turing-HV backend against the LIVE hypervisor on a game-shaped target
    (thvbig.c: ~8000 regions, a busy page): the memory map, a frozen value, the disassembler, the watches, each with
    the bridge calls it cost.  Same needs as run_tests.ps1.  Prints bench.txt.

        powershell -ExecutionPolicy Bypass -File "Cheat Engine\turinghv\tests\run_bench.ps1"
#>
param([string]$Work = (Join-Path $env:TEMP 'thvbench'))
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$bin = (Resolve-Path (Join-Path $here '..\..\bin')).Path
New-Item -ItemType Directory -Force $Work | Out-Null

$exe = Join-Path $Work 'thvbig.exe'
if (-not (Test-Path $exe) -or ((Get-Item $exe).LastWriteTime -lt (Get-Item (Join-Path $here 'thvbig.c')).LastWriteTime)) {
    $vsroot = 'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build'
    cmd /c "`"$vsroot\vcvars64.bat`" >nul 2>&1 && clang -O1 -D_CRT_SECURE_NO_WARNINGS `"$(Join-Path $here 'thvbig.c')`" -o `"$exe`""
}
$run = Join-Path $Work 'run'
Remove-Item $run -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $run | Out-Null
$target = Start-Process $exe -ArgumentList "`"$run`"" -PassThru -WindowStyle Hidden
$deadline = (Get-Date).AddSeconds(30)
while (-not (Test-Path (Join-Path $run 'thvbig.info')) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 200 }

$driver = Join-Path $bin 'autorun\zz_turinghv_bench.lua'
Copy-Item (Join-Path $here 'zz_turinghv_bench.lua') $driver -Force
try {
    $env:THVBENCH_DIR = $run
    $ce = Start-Process (Join-Path $bin 'cheatengine-x86_64.exe') -PassThru
    if (-not $ce.WaitForExit(300000)) {
        Write-Warning 'Cheat Engine did not finish in 5 minutes; its windows:'
        & (Join-Path $here 'winlist.ps1') -ProcessId $ce.Id
        Stop-Process $ce -Force
    }
} finally {
    Remove-Item $driver -Force -ErrorAction SilentlyContinue
    Stop-Process $target -Force -ErrorAction SilentlyContinue
}
Get-Content (Join-Path $run 'bench.txt')
