<#
    use_rev150_bridge.ps1 -- put the rev150 thvbridge.exe + turinghv.dll (bin\turinghv-rev150) in place of the ones in
    bin, and ask the hypervisor to trust the new thvbridge.exe (read + write), as an administrator does it in UMBRA.

    rev150 adds the native trace (Break and Trace > "Turing-HV native trace": the thread never stops) and carries
    rev149b's parking-breakpoint fixes (a held thread could get away after a step; step over `call [rip+x]`).
    The bridge is REBUILT (two new commands: arm / read a native trace), so it must be trusted again -- this script
    asks for that; the DLL is the rev150 image's own (setup.exe = the -VIommu image). Run it AFTER installing the turing-hv rev150 image and
    restarting: the hypervisor accepts its SDK DLL only from its own build, so the new turinghv.dll is refused by an
    older image (and the old one by the new image). Close Cheat Engine first (its bridge holds the files open). The old
    files are kept as *.before-rev150.

    Right-click > Run with PowerShell is fine: it asks for administrator itself, and it always waits for Enter at the
    end so what happened stays on screen.

        powershell -ExecutionPolicy Bypass -File "Cheat Engine\turinghv\use_rev150_bridge.ps1"
#>
$ErrorActionPreference = 'Stop'

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    Write-Host 'Asking for administrator (the trust request must be elevated)...'
    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    } catch {
        Write-Host "Could not start as administrator: $($_.Exception.Message)" -ForegroundColor Red
        Read-Host 'Press Enter to close'
    }
    exit
}

try {
    $bin = (Resolve-Path (Join-Path $PSScriptRoot '..\bin')).Path
    $stage = Join-Path $bin 'turinghv-rev150'
    $trustreq = 'C:\projs\turing-hv\tools\trust\trustreq.exe'
    if (Get-Process thvbridge -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$bin\*" }) {
        throw 'Cheat Engine is still running (its thvbridge.exe holds the files): close it first, then run this again'
    }
    foreach ($f in 'thvbridge.exe', 'turinghv.dll') {
        if (-not (Test-Path (Join-Path $stage $f))) { throw "missing $stage\$f" }
    }
    $same = $true
    foreach ($f in 'thvbridge.exe', 'turinghv.dll') {
        $cur = Join-Path $bin $f
        $new = Join-Path $stage $f
        if ((Test-Path $cur) -and (Get-FileHash -Algorithm MD5 $cur).Hash -eq (Get-FileHash -Algorithm MD5 $new).Hash) {
            Write-Host "already in place: $cur"
            continue
        }
        $same = $false
        if (Test-Path $cur) { Copy-Item $cur "$cur.before-rev150" -Force }
        Copy-Item $new $cur -Force
        Write-Host "OK  $cur"
    }
    if ($same) {
        Write-Host 'Both files were already the rev150 ones: no new trust request. If Cheat Engine cannot connect, trust bin\thvbridge.exe in UMBRA > Trusted programs.'
    } else {
        & $trustreq request (Join-Path $bin 'thvbridge.exe') --write
        if ($LASTEXITCODE -ne 0) { throw "trustreq failed ($LASTEXITCODE): trust bin\thvbridge.exe in UMBRA > Trusted programs instead" }
    }
    & (Join-Path $bin 'thvbridge.exe') --selftest
    Write-Host 'Done.' -ForegroundColor Green
} catch {
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Read-Host 'Press Enter to close'
}
