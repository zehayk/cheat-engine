<#
    build_thvbridge.ps1 -- build Cheat Engine's turing-hv broker, thvbridge.exe, into "Cheat Engine\bin",
    and put the matching turinghv.dll beside it.

    -Sdk   the turing-hv SDK folder (include\turinghv.h, lib\turinghv.lib, bin\turinghv.dll).  Default: the
           hypervisor tree's own build output, so the DLL always matches the running turinghv.efi.  The header and
           import library are also vendored in turinghv\sdk for building without that tree (the DLL is not: it
           must come from the same build as the .efi).

    The C runtime is linked statically (clang's default for windows-msvc): a vcruntime DLL is neither Windows' own
    nor trusted, and the hypervisor's caller gate would refuse the broker for it.

    Every rebuild changes what the hypervisor measures: trust the new thvbridge.exe again afterwards.
#>
param(
    [string]$Sdk = 'C:\projs\turing-hv\build\out\sdk',
    [string]$OutDir = (Join-Path $PSScriptRoot '..\bin')
)
$ErrorActionPreference = 'Stop'

# clang links against the MSVC runtime/SDK libraries: bring in a VS developer environment when none is active.
if (-not $env:LIB -or -not ($env:LIB -match 'MSVC')) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    $vcvars = $null
    if (Test-Path $vswhere) {
        $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($vs) { $vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat' }
    }
    if (-not $vcvars -or -not (Test-Path $vcvars)) {
        $vcvars = 'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat'
    }
    if (-not (Test-Path $vcvars)) { throw "no Visual Studio C++ build tools found (vcvars64.bat)" }
    cmd /c "`"$vcvars`" >nul 2>&1 && set" | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process') }
    }
}

$clang = (Get-Command clang -ErrorAction SilentlyContinue).Source
if (-not $clang) { $clang = 'C:\Program Files\LLVM\bin\clang.exe' }
if (-not (Test-Path $clang)) { throw "clang not found" }

$inc = Join-Path $Sdk 'include'
$lib = Join-Path $Sdk 'lib\turinghv.lib'
$dll = Join-Path $Sdk 'bin\turinghv.dll'
if (-not (Test-Path (Join-Path $inc 'turinghv.h'))) { $inc = Join-Path $PSScriptRoot 'sdk\include' }
if (-not (Test-Path $lib)) { $lib = Join-Path $PSScriptRoot 'sdk\lib\turinghv.lib' }

$OutDir = (New-Item -ItemType Directory -Force $OutDir).FullName
$src = Join-Path $PSScriptRoot 'thvbridge\thvbridge.c'
$exe = Join-Path $OutDir 'thvbridge.exe'

$cflags = @('-std=c11', '-O2', '-Wall', '-Wextra', '-D_CRT_SECURE_NO_WARNINGS')
Write-Host "CC  thvbridge.c"
& $clang @cflags "-I$inc" "-I$(Join-Path $PSScriptRoot 'thvbridge')" $src $lib -o $exe
if ($LASTEXITCODE -ne 0) { throw "thvbridge build failed" }

if (Test-Path $dll) {
    Copy-Item -LiteralPath $dll -Destination (Join-Path $OutDir 'turinghv.dll') -Force
    Write-Host "OK  -> $(Join-Path $OutDir 'turinghv.dll')"
} else {
    Write-Warning "no turinghv.dll at $dll -- copy the one built with the running turinghv.efi next to thvbridge.exe"
}
Write-Host "OK  -> $exe ($((Get-Item $exe).Length) bytes)"
