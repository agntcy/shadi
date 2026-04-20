# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'

$rootDir = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

if (-not $env:SHADI_TMP_DIR) {
	$env:SHADI_TMP_DIR = Join-Path $rootDir '.tmp'
}
if (-not $env:SLIM_ENDPOINT) {
	$env:SLIM_ENDPOINT = '127.0.0.1:47357'
}

Set-Location $rootDir
cargo run -p agntcy-shadi-cli -- slim start-node