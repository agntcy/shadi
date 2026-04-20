# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'

function Get-OnePasswordSecret {
	param(
		[Parameter(Mandatory = $true)][string]$ItemName,
		[Parameter(Mandatory = $true)][string]$Vault,
		[Parameter(Mandatory = $true)][string]$Account
	)

	$itemJson = op item get $ItemName --vault $Vault --account $Account --format json 2>$null
	if (-not $itemJson) {
		throw "failed to read 1Password item '$ItemName' from vault '$Vault' account '$Account'"
	}

	$data = $itemJson | ConvertFrom-Json
	$field = $data.fields | Where-Object { $_.id -eq 'notesPlain' } | Select-Object -First 1
	if (-not $field -or -not $field.value) {
		throw "missing notesPlain field in 1Password item '$ItemName'"
	}

	return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($field.value))
}