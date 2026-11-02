<#
    use_rev147_bridge.ps1 -- put the rev147 thvbridge.exe + turinghv.dll (bin\turinghv-rev147) in place of the ones in
    bin, and ask the hypervisor to trust the new thvbridge.exe (read + write), as an administrator does it in UMBRA.

    Run it AFTER installing the turing-hv rev147 image and restarting: the hypervisor accepts its SDK DLL only from its
    own build, so the new turinghv.dll is refused by an older image (and the old one by the new image).
    Close Cheat Engine first (its bridge holds the files open). The old files are kept as *.before-rev147.

        powershell -ExecutionPolicy Bypass -File "Cheat Engine\turinghv\use_rev147_bridge.ps1"     (as administrator)
#>
$ErrorActionPreference = 'Stop'
$bin = (Resolve-Path (Join-Path $PSScriptRoot '..\bin')).Path
$stage = Join-Path $bin 'turinghv-rev147'
$trustreq = 'C:\projs\turing-hv\tools\trust\trustreq.exe'

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'run this as administrator (the trust request must be elevated)' }
if (Get-Process thvbridge -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$bin\*" }) {
    throw 'Cheat Engine is still running (its thvbridge.exe holds the files): close it first'
}
foreach ($f in 'thvbridge.exe', 'turinghv.dll') {
    if (-not (Test-Path (Join-Path $stage $f))) { throw "missing $stage\$f" }
}
foreach ($f in 'thvbridge.exe', 'turinghv.dll') {
    $cur = Join-Path $bin $f
    if (Test-Path $cur) { Copy-Item $cur "$cur.before-rev147" -Force }
    Copy-Item (Join-Path $stage $f) $cur -Force
    Write-Host "OK  $cur"
}
& $trustreq request (Join-Path $bin 'thvbridge.exe') --write
if ($LASTEXITCODE -ne 0) { throw "trustreq failed ($LASTEXITCODE): trust bin\thvbridge.exe in UMBRA > Trusted programs instead" }
& (Join-Path $bin 'thvbridge.exe') --selftest
