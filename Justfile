set shell := ["bash", "-uc"]
set windows-shell := ["pwsh", "-NoLogo", "-Command"]
set dotenv-load := true
set dotenv-filename := ".just.env"

import 'just/vars.just'
import 'just/platform.just'
import 'just/core.just'

[default]
[doc('List available tasks grouped by area.')]
help:
	@just --justfile "{{justfile()}}" --working-directory "{{justfile_directory()}}" --list
