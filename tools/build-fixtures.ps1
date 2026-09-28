<#
.SYNOPSIS
  Builds the Android fixture shared libraries used by raxdbg's test suites.

.DESCRIPTION
  Prefers `zig cc` (single self-contained toolchain) and falls back to the
  Android NDK. The resulting .so files are committed under fixtures/prebuilt/
  so that `cargo test` never requires a cross toolchain.

.EXAMPLE
  pwsh tools/build-fixtures.ps1
  pwsh tools/build-fixtures.ps1 -Ndk E:\Android\Sdk\ndk\26.2.11394342
#>
[CmdletBinding()]
param(
    [string]$Ndk,
    [string]$NdkApi = "21",
    [switch]$Thumb
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$srcDir = Join-Path $root "fixtures/src"
$outRoot = Join-Path $root "fixtures/prebuilt"

function Find-Zig {
    $cmd = Get-Command zig -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Find-Ndk {
    param([string]$Explicit)
    if ($Explicit) {
        if (-not (Test-Path $Explicit)) { throw "NDK path not found: $Explicit" }
        return $Explicit
    }
    if ($env:ANDROID_NDK_HOME -and (Test-Path $env:ANDROID_NDK_HOME)) { return $env:ANDROID_NDK_HOME }
    if ($env:ANDROID_NDK_ROOT -and (Test-Path $env:ANDROID_NDK_ROOT)) { return $env:ANDROID_NDK_ROOT }
    foreach ($sdkVar in @($env:ANDROID_SDK_ROOT, $env:ANDROID_HOME)) {
        if (-not $sdkVar) { continue }
        $ndkDir = Join-Path $sdkVar "ndk"
        if (Test-Path $ndkDir) {
            $candidate = Get-ChildItem $ndkDir -Directory | Sort-Object Name -Descending | Select-Object -First 1
            if ($candidate) { return $candidate.FullName }
        }
    }
    return $null
}

$zig = Find-Zig
$ndkPath = $null
if (-not $zig) { $ndkPath = Find-Ndk -Explicit $Ndk }
if (-not $zig -and -not $ndkPath) {
    throw @"
No cross toolchain found. Install either:
  * zig (https://ziglang.org/download/) and put `zig` on PATH, or
  * the Android NDK and set ANDROID_NDK_HOME (or pass -Ndk <path>).
"@
}

# abi -> @{ triple = <zig target>; ndk = <clang prefix>; march = <extra flags> }
$targets = @(
    @{ Abi = "arm64-v8a";   Zig = "aarch64-linux-android";  Ndk = "aarch64-linux-android$NdkApi"; March = @() },
    @{ Abi = "armeabi-v7a"; Zig = "arm-linux-androideabi";  Ndk = "armv7a-linux-androideabi$NdkApi"; March = @("-march=armv7-a", "-mfloat-abi=softfp", "-mfpu=vfpv3-d16") }
)

$libs = @("jnitest", "ctest", "hooktest")

foreach ($t in $targets) {
    $outDir = Join-Path $outRoot $t.Abi
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    foreach ($lib in $libs) {
        $src = Join-Path $srcDir "$lib.c"
        $out = Join-Path $outDir "lib$lib.so"
        $extra = $t.March
        if ($Thumb -and $t.Abi -eq "armeabi-v7a") { $extra += "-mthumb" }
        if ($zig) {
            $args = @("cc", "-target", $t.Zig, "-shared", "-fPIC", "-O2", "-o", $out, $src) + $extra
            Write-Host "zig $($args -join ' ')"
            & $zig @args
        } else {
            $clang = Join-Path $ndkPath "toolchains/llvm/prebuilt/windows-x86_64/bin/$($t.Ndk)-clang.cmd"
            if (-not (Test-Path $clang)) { throw "NDK clang not found: $clang" }
            $args = @("-shared", "-fPIC", "-O2", "-o", $out, $src) + $extra
            Write-Host "$clang $($args -join ' ')"
            & $clang @args
        }
        if ($LASTEXITCODE -ne 0) { throw "failed to build $out" }
    }
}

Write-Host "fixtures built under $outRoot"
