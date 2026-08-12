$ErrorActionPreference = 'Stop'

$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$workspaceDir = Split-Path -Parent (Split-Path -Parent $projectDir)
$zig = Join-Path $workspaceDir 'work\toolchain\zig-x86_64-windows-0.16.0\zig.exe'
$mlkem = Join-Path $projectDir 'third_party\mlkem-native\mlkem'
$monocypher = Join-Path $projectDir 'third_party\monocypher'
$output = Join-Path $projectDir 'golden_reference.exe'
$env:ZIG_GLOBAL_CACHE_DIR = Join-Path $workspaceDir 'work\zig-cache\global'
$env:ZIG_LOCAL_CACHE_DIR = Join-Path $workspaceDir 'work\zig-cache\local'

if (!(Test-Path $zig)) { throw "Zig compiler not found: $zig" }
if (!(Test-Path $mlkem)) { throw "mlkem-native not found: $mlkem" }
if (!(Test-Path $monocypher)) { throw "Monocypher not found: $monocypher" }

& $zig cc `
    -std=c99 `
    -O2 `
    -Wall `
    -Wextra `
    -DMLK_CONFIG_PARAMETER_SET=512 `
    -DMLK_CONFIG_NAMESPACE_PREFIX=mlkem `
    -DMLK_CONFIG_NO_RANDOMIZED_API `
    -I $mlkem `
    -I $monocypher `
    (Join-Path $projectDir 'golden_reference.c') `
    (Join-Path $mlkem 'mlkem_native.c') `
    (Join-Path $monocypher 'monocypher.c') `
    -o $output

if ($LASTEXITCODE -ne 0) { throw "C build failed with exit code $LASTEXITCODE" }

Push-Location $projectDir
try {
    & $output
    if ($LASTEXITCODE -ne 0) { throw "Golden reference failed with exit code $LASTEXITCODE" }
}
finally {
    Pop-Location
}
