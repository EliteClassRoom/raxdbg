<#
.SYNOPSIS
  Populates `libs/` from the unidbg submodule's bundled Android resources.

.DESCRIPTION
  raxdbg bundles the same AOSP/hook-engine binaries unidbg ships so that
  emulation works offline. This script mirrors the resource layout of
  `reference/unidbg/unidbg-android/src/main/resources/` into `libs/`, which is
  what `AndroidResolver` looks up at runtime:

    /android/sdk<sdk>/{lib,lib64}/<name with '+' replaced by 'p'>
    /android/lib/<abi>/<hook engine>.so
    /android/sdk<sdk>/<guest path>            (zoneinfo, __properties__, proc/stat)

  iOS-only artifacts (libwhale.so) are skipped. Re-run after updating the
  submodule; the copied files are committed.

.EXAMPLE
  pwsh tools/fetch-libs.ps1
#>
[CmdletBinding()]
param(
    [string]$Reference = "reference/unidbg",
    [string]$Out = "libs"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$res = Join-Path $root "$Reference/unidbg-android/src/main/resources"
if (-not (Test-Path $res)) {
    throw "unidbg resources not found at $res - run 'git submodule update --init' first"
}
$outRoot = Join-Path $root $Out

$files = @(
    # hook engines (Android only; libwhale.so is iOS-only and is skipped)
    "android/lib/arm64-v8a/libdobby.so"
    "android/lib/arm64-v8a/libhookzz.so"
    "android/lib/arm64-v8a/libxhook.so"
    "android/lib/armeabi-v7a/libdobby.so"
    "android/lib/armeabi-v7a/libhookzz.so"
    "android/lib/armeabi-v7a/libxhook.so"
    # sdk19 (arm32)
    "android/sdk19/dev/__properties__"
    "android/sdk19/lib/libc.so"
    "android/sdk19/lib/libcrypto.so"
    "android/sdk19/lib/libdl.so"
    "android/sdk19/lib/liblog.so"
    "android/sdk19/lib/libm.so"
    "android/sdk19/lib/libssl.so"
    "android/sdk19/lib/libstdcpp.so"
    "android/sdk19/lib/libz.so"
    "android/sdk19/system/usr/share/zoneinfo/tzdata"
    # sdk23 (arm32 + arm64)
    "android/sdk23/dev/__properties__"
    "android/sdk23/lib/libc.so"
    "android/sdk23/lib/libcpp.so"
    "android/sdk23/lib/libcrypto.so"
    "android/sdk23/lib/libdl.so"
    "android/sdk23/lib/liblog.so"
    "android/sdk23/lib/libm.so"
    "android/sdk23/lib/libssl.so"
    "android/sdk23/lib/libstdcpp.so"
    "android/sdk23/lib/libz.so"
    "android/sdk23/lib64/libc.so"
    "android/sdk23/lib64/libcpp.so"
    "android/sdk23/lib64/libcrypto.so"
    "android/sdk23/lib64/libdl.so"
    "android/sdk23/lib64/liblog.so"
    "android/sdk23/lib64/libm.so"
    "android/sdk23/lib64/libssl.so"
    "android/sdk23/lib64/libstdcpp.so"
    "android/sdk23/lib64/libz.so"
    "android/sdk23/proc/stat"
    "android/sdk23/system/usr/share/zoneinfo/tzdata"
)

$copied = 0
$total = 0
foreach ($rel in $files) {
    $src = Join-Path $res $rel
    if (-not (Test-Path $src)) { throw "missing resource: $src" }
    $dst = Join-Path $outRoot $rel
    $dir = Split-Path -Parent $dst
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Copy-Item $src $dst -Force
    $total += (Get-Item $dst).Length
    $copied++
}

Write-Host ("copied {0} files ({1:N1} MiB) into {2}" -f $copied, ($total / 1MB), $outRoot)
