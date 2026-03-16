$ErrorActionPreference = 'Stop'

$rootDir = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

if (-not $env:SHADI_TMP_DIR) {
	$env:SHADI_TMP_DIR = Join-Path $rootDir '.tmp'
}
if (-not $env:SLIM_ENDPOINT) {
	$env:SLIM_ENDPOINT = '127.0.0.1:47357'
}

$configPath = Join-Path $env:SHADI_TMP_DIR 'shadi-slim-mtls/server-config.yaml'

slimctl slim start --config $configPath