param([switch]$SkipXsim)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Workspace = Split-Path -Parent (Split-Path -Parent $Root)
$Golden = Join-Path (Split-Path -Parent $Root) 'golden_reference'
$Zig = Join-Path $Workspace 'work\toolchain\zig-x86_64-windows-0.16.0\zig.exe'
$Python = 'C:\Users\bomin\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
$DriverBuild = Join-Path $Workspace 'work\driver-build'

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Golden 'build_and_run.ps1')
if ($LASTEXITCODE -ne 0) { throw 'Golden C reference failed' }
& $Python (Join-Path $Golden 'verify_with_python.py')
if ($LASTEXITCODE -ne 0) { throw 'Python cross-check failed' }

$env:ZIG_GLOBAL_CACHE_DIR = Join-Path $Workspace 'work\zig-cache\global'
$env:ZIG_LOCAL_CACHE_DIR = Join-Path $Workspace 'work\zig-cache\driver'
New-Item -ItemType Directory -Force $DriverBuild | Out-Null
Push-Location (Join-Path $Root 'ps_driver')
try {
    foreach ($Source in @('aead_hw.c','mlkem_decaps_hw.c','secure_channel_hw.c')) {
        $Object = Join-Path $DriverBuild ([IO.Path]::ChangeExtension($Source,'.obj'))
        & $Zig cc -std=c99 -Wall -Wextra -Werror -c $Source -o $Object
        if ($LASTEXITCODE -ne 0) { throw "$Source failed strict C compilation" }
    }
}
finally { Pop-Location }

if (!$SkipXsim) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'run_xsim.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'Vivado XSim regression failed' }
}
Write-Host 'ALL BOARDLESS CHECKS PASSED'
