<#
    use_rev150e_bridge.ps1 -- put the rev150e thvbridge.exe + turinghv.dll (bin\turinghv-rev150e) in place of the ones in
    bin, and ask the hypervisor to trust the new thvbridge.exe (read + write), as an administrator does it in UMBRA.

    rev150e = rev150e + a held thread no longer let go by the hypervisor's own re-arm (the second step that landed
    where it started), one watch per page, and the breakpoint's diagnostics. Also puts the updated Cheat Engine in
    place (thread list without a Windows handle on the game's threads). The bridge itself is unchanged; the
    DLL is the rev150e image's own (setup.exe = the -VIommu image), so the bridge is trusted again with it. Run it AFTER
    installing the turing-hv rev150e image and restarting: the hypervisor accepts its SDK DLL only from its own build.
    Close Cheat Engine first (its bridge holds the files open). The old files are kept as *.before-rev150e.

    Right-click > Run with PowerShell is fine: it asks for administrator itself, and it always waits for Enter at the
    end so what happened stays on screen.

        powershell -ExecutionPolicy Bypass -File "Cheat Engine\turinghv\use_rev150e_bridge.ps1"
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
    $stage = Join-Path $bin 'turinghv-rev150e'
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
        if (Test-Path $cur) { Copy-Item $cur "$cur.before-rev150e" -Force }
        Copy-Item $new $cur -Force
        Write-Host "OK  $cur"
    }
    if ($same) {
        Write-Host 'Both files were already the rev150e ones: no new trust request. If Cheat Engine cannot connect, trust bin\thvbridge.exe in UMBRA > Trusted programs.'
    } else {
        & $trustreq request (Join-Path $bin 'thvbridge.exe') --write
        if ($LASTEXITCODE -ne 0) { throw "trustreq failed ($LASTEXITCODE): trust bin\thvbridge.exe in UMBRA > Trusted programs instead" }
    }
    # an updated Cheat Engine built while yours was open (bin\cheatengine-x86_64-new.exe): put it in place now
    $newCe = Join-Path $bin 'cheatengine-x86_64-new.exe'
    $ce = Join-Path $bin 'cheatengine-x86_64.exe'
    if (Test-Path $newCe) {
        if (Get-Process cheatengine-x86_64 -ErrorAction SilentlyContinue) { throw 'Cheat Engine is still running: close it first, then run this again' }
        if (Test-Path $ce) { Copy-Item $ce "$ce.before-rev150e" -Force }
        Move-Item $newCe $ce -Force
        Write-Host "OK  $ce (updated Cheat Engine; the old one kept as cheatengine-x86_64.exe.before-rev150e)"
    }
    & (Join-Path $bin 'thvbridge.exe') --selftest
    Write-Host 'Done.' -ForegroundColor Green
} catch {
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Read-Host 'Press Enter to close'
}
