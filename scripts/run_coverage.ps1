# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

param(
    [ValidateSet('lcov', 'html')]
    [string]$Mode = 'lcov',
    [string]$PythonBin = $(if ($env:PYO3_PYTHON) { $env:PYO3_PYTHON } else { 'python3.12' }),
    [string]$RustflagsValue = $(if ($env:RUSTFLAGS) { $env:RUSTFLAGS } else { '' })
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-Tool {
    param([Parameter(Mandatory = $true)][string]$ToolName)

    $command = Get-Command $ToolName -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $sysroot = (& rustc --print sysroot).Trim()
    $hostLine = (& rustc -Vv | Select-String '^host:\s+').Line
    if (-not $hostLine) {
        throw 'Unable to determine rust host triple.'
    }

    $rustHost = ($hostLine -split '\s+', 2)[1]
    return Join-Path $sysroot "lib\rustlib\$rustHost\bin\$ToolName.exe"
}

function Set-OpenSslEnvironment {
    $candidates = @(
        'C:\Program Files\OpenSSL-Win64',
        'C:\Program Files\OpenSSL',
        'C:\OpenSSL-Win64'
    )

    $opensslDir = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $opensslDir) {
        return $null
    }

    $libDir = if (Test-Path (Join-Path $opensslDir 'lib\VC\x64\MD')) {
        Join-Path $opensslDir 'lib\VC\x64\MD'
    } else {
        Join-Path $opensslDir 'lib'
    }

    $includeDir = Join-Path $opensslDir 'include'

    return @{
        OPENSSL_DIR = $opensslDir
        OPENSSL_LIB_DIR = $libDir
        OPENSSL_INCLUDE_DIR = $includeDir
    }
}

$previousShadiKeychainTests = $env:SHADI_KEYCHAIN_TESTS
$previousPython = $env:PYO3_PYTHON
$hadRustflags = Test-Path Env:RUSTFLAGS
$previousRustflags = $env:RUSTFLAGS
$previousLlvmCov = $env:LLVM_COV
$previousLlvmProfdata = $env:LLVM_PROFDATA
$previousOpenSslDir = $env:OPENSSL_DIR
$previousOpenSslLibDir = $env:OPENSSL_LIB_DIR
$previousOpenSslIncludeDir = $env:OPENSSL_INCLUDE_DIR
$previousGitConfigGlobal = $env:GIT_CONFIG_GLOBAL
$temporaryGitConfig = $null

try {
    New-Item -ItemType Directory -Path coverage -Force | Out-Null

    $llvmCov = Resolve-Tool 'llvm-cov'
    $llvmProfdata = Resolve-Tool 'llvm-profdata'

    $formatArgs = switch ($Mode) {
        'lcov' { @('--lcov', '--output-path', 'coverage/lcov.info') }
        'html' { @('--html', '--output-dir', 'coverage/html') }
        default { throw "unsupported coverage mode: $Mode" }
    }

    $env:SHADI_KEYCHAIN_TESTS = if ($env:SHADI_KEYCHAIN_TESTS) { $env:SHADI_KEYCHAIN_TESTS } else { '1' }
    $env:PYO3_PYTHON = $PythonBin
    $env:LLVM_COV = $llvmCov
    $env:LLVM_PROFDATA = $llvmProfdata

    $gitUserName = (& git config --global --get user.name 2>$null).Trim()
    if ([string]::IsNullOrWhiteSpace($gitUserName)) {
        $gitUserName = 'SHADI Test User'
    }

    $gitUserEmail = (& git config --global --get user.email 2>$null).Trim()
    if ([string]::IsNullOrWhiteSpace($gitUserEmail)) {
        $gitUserEmail = 'shadi-tests@example.invalid'
    }

    $temporaryGitConfig = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
    @(
        '[user]',
        "    name = $gitUserName",
        "    email = $gitUserEmail",
        '[commit]',
        '    gpgsign = false',
        '[tag]',
        '    gpgsign = false'
    ) | Set-Content -Path $temporaryGitConfig
    $env:GIT_CONFIG_GLOBAL = $temporaryGitConfig

    $opensslEnv = Set-OpenSslEnvironment
    if ($opensslEnv) {
        $env:OPENSSL_DIR = $opensslEnv.OPENSSL_DIR
        $env:OPENSSL_LIB_DIR = $opensslEnv.OPENSSL_LIB_DIR
        $env:OPENSSL_INCLUDE_DIR = $opensslEnv.OPENSSL_INCLUDE_DIR
    }

    if ([string]::IsNullOrEmpty($RustflagsValue)) {
        Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
    } else {
        $env:RUSTFLAGS = $RustflagsValue
    }

    & cargo llvm-cov --workspace --features coverage @formatArgs --ignore-filename-regex '/rustc-[^/]+'

    if ($Mode -eq 'lcov') {
        $lcov = Get-Command lcov -ErrorAction SilentlyContinue
        if ($lcov) {
            & $lcov.Source --summary coverage/lcov.info
        } else {
            Write-Host 'lcov not found; skipping coverage summary'
        }
    }
}
finally {
    if ($null -eq $previousShadiKeychainTests) {
        Remove-Item Env:SHADI_KEYCHAIN_TESTS -ErrorAction SilentlyContinue
    } else {
        $env:SHADI_KEYCHAIN_TESTS = $previousShadiKeychainTests
    }

    if ($null -eq $previousPython) {
        Remove-Item Env:PYO3_PYTHON -ErrorAction SilentlyContinue
    } else {
        $env:PYO3_PYTHON = $previousPython
    }

    if ($hadRustflags) {
        $env:RUSTFLAGS = $previousRustflags
    } else {
        Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
    }

    if ($null -eq $previousLlvmCov) {
        Remove-Item Env:LLVM_COV -ErrorAction SilentlyContinue
    } else {
        $env:LLVM_COV = $previousLlvmCov
    }

    if ($null -eq $previousLlvmProfdata) {
        Remove-Item Env:LLVM_PROFDATA -ErrorAction SilentlyContinue
    } else {
        $env:LLVM_PROFDATA = $previousLlvmProfdata
    }

    if ($null -eq $previousOpenSslDir) {
        Remove-Item Env:OPENSSL_DIR -ErrorAction SilentlyContinue
    } else {
        $env:OPENSSL_DIR = $previousOpenSslDir
    }

    if ($null -eq $previousOpenSslLibDir) {
        Remove-Item Env:OPENSSL_LIB_DIR -ErrorAction SilentlyContinue
    } else {
        $env:OPENSSL_LIB_DIR = $previousOpenSslLibDir
    }

    if ($null -eq $previousOpenSslIncludeDir) {
        Remove-Item Env:OPENSSL_INCLUDE_DIR -ErrorAction SilentlyContinue
    } else {
        $env:OPENSSL_INCLUDE_DIR = $previousOpenSslIncludeDir
    }

    if ($null -eq $previousGitConfigGlobal) {
        Remove-Item Env:GIT_CONFIG_GLOBAL -ErrorAction SilentlyContinue
    } else {
        $env:GIT_CONFIG_GLOBAL = $previousGitConfigGlobal
    }

    if ($temporaryGitConfig -and (Test-Path $temporaryGitConfig)) {
        Remove-Item $temporaryGitConfig -Force -ErrorAction SilentlyContinue
    }
}