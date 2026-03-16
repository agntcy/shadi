[group('demos')]
[doc('Run the tourist demo entrypoint with the demo policy.')]
demo-tourist:
  {{ if os() == "windows" {
    "$env:AGENTIC_APPS_PATH = \"" + AGENTIC_APPS_PATH + "\"; $env:TOURIST_CMD = \"" + TOURIST_CMD + "\"; $env:SHADI_POLICY_PATH = \"policies/demo/tourist.json\"; " + demo_python + " agents/adk_demo/run_tourist_demo.py"
  } else {
    "AGENTIC_APPS_PATH=\"" + AGENTIC_APPS_PATH + "\" TOURIST_CMD=\"" + TOURIST_CMD + "\" SHADI_POLICY_PATH=policies/demo/tourist.json " + demo_python + " agents/adk_demo/run_tourist_demo.py"
  } }}

[group('demos')]
[doc('Launch the local SLIM node.')]
launch-slim:
  {{ if os() == "windows" {
    ".\\scripts\\launch_slim.ps1"
  } else {
    "./scripts/launch_slim.sh"
  } }}

[group('demos')]
[doc('Launch SLIM with example local environment values.')]
launch-slim-example:
  {{ if os() == "windows" {
    "$env:SHADI_TMP_DIR = \"./.tmp\"; .\\scripts\\launch_slim.ps1"
  } else {
    "SHADI_TMP_DIR=\"./.tmp\" ./scripts/launch_slim.sh"
  } }}

[group('demos')]
[doc('Launch the SecOps A2A server.')]
launch-secops-a2a:
  {{ if os() == "windows" {
    ".\\scripts\\launch_secops_a2a.ps1"
  } else {
    "./scripts/launch_secops_a2a.sh"
  } }}

[group('demos')]
[doc('Import demo secrets and launch the SecOps A2A example flow.')]
launch-secops-a2a-example:
  {{ if os() == "windows" {
    "$env:SHADI_TMP_DIR = \"./.tmp\"; $env:SHADI_AGENT_ID = \"secops-a\"; $env:SHADI_OPERATOR_PRESENTATION = \"local-operator\"; .\\scripts\\import_secops_secrets.ps1"
  } else {
    "SHADI_TMP_DIR=\"./.tmp\" SHADI_AGENT_ID=\"secops-a\" SHADI_OPERATOR_PRESENTATION=\"local-operator\" ./scripts/import_secops_secrets.sh"
  } }}
  {{ if os() == "windows" {
    "$env:SHADI_TMP_DIR = \"./.tmp\"; $env:SHADI_AGENT_ID = \"secops-a\"; $env:SHADI_OPERATOR_PRESENTATION = \"local-operator\"; .\\scripts\\launch_secops_a2a.ps1"
  } else {
    "SHADI_TMP_DIR=\"./.tmp\" SHADI_AGENT_ID=\"secops-a\" SHADI_OPERATOR_PRESENTATION=\"local-operator\" ./scripts/launch_secops_a2a.sh"
  } }}

[group('demos')]
[doc('Import demo secrets from 1Password and launch the SecOps A2A example flow.')]
launch-secops-a2a-example-op:
  {{ if os() == "windows" {
    "$env:SHADI_SECRET_BACKEND = \"onepassword\"; $env:SHADI_TMP_DIR = \"./.tmp\"; $env:SHADI_AGENT_ID = \"secops-a\"; $env:SHADI_OPERATOR_PRESENTATION = \"local-operator\"; .\\scripts\\import_secops_secrets.ps1"
  } else {
    "SHADI_SECRET_BACKEND=onepassword SHADI_TMP_DIR=\"./.tmp\" SHADI_AGENT_ID=\"secops-a\" SHADI_OPERATOR_PRESENTATION=\"local-operator\" ./scripts/import_secops_secrets.sh"
  } }}
  {{ if os() == "windows" {
    "$env:SHADI_SECRET_BACKEND = \"onepassword\"; $env:SHADI_TMP_DIR = \"./.tmp\"; $env:SHADI_AGENT_ID = \"secops-a\"; $env:SHADI_OPERATOR_PRESENTATION = \"local-operator\"; .\\scripts\\launch_secops_a2a.ps1"
  } else {
    "SHADI_SECRET_BACKEND=onepassword SHADI_TMP_DIR=\"./.tmp\" SHADI_AGENT_ID=\"secops-a\" SHADI_OPERATOR_PRESENTATION=\"local-operator\" ./scripts/launch_secops_a2a.sh"
  } }}

[group('demos')]
[doc('Launch the Avatar agent.')]
launch-avatar:
  {{ if os() == "windows" {
    ".\\scripts\\launch_avatar.ps1"
  } else {
    "./scripts/launch_avatar.sh"
  } }}

[group('demos')]
[doc('Launch the interactive Avatar agent (foreground REPL).')]
demo-avatar:
  {{ if os() == "windows" {
    "$env:SHADI_TMP_DIR = \"./.tmp\"; $env:SHADI_AGENT_ID = \"avatar-1\"; $env:SHADI_OPERATOR_PRESENTATION = \"local-operator\"; .\\scripts\\launch_avatar.ps1"
  } else {
    "SHADI_TMP_DIR=\"./.tmp\" SHADI_AGENT_ID=\"avatar-1\" SHADI_OPERATOR_PRESENTATION=\"local-operator\" ./scripts/launch_avatar.sh"
  } }}

[group('demos')]
[doc('Launch Avatar with 1Password as the secret backend.')]
demo-avatar-op:
  {{ if os() == "windows" {
    "$opAccount = \"{{SHADI_OP_ACCOUNT}}\"; op vault list --account $opAccount | Out-Null; $env:SHADI_SECRET_BACKEND = \"onepassword\"; $env:SHADI_OP_ACCOUNT = $opAccount; $env:SHADI_TMP_DIR = \"./.tmp\"; $env:SHADI_AGENT_ID = \"avatar-1\"; $env:SHADI_OPERATOR_PRESENTATION = \"local-operator\"; .\\scripts\\launch_avatar.ps1"
  } else {
    "OP_ACCOUNT=\"{{SHADI_OP_ACCOUNT}}\"; op vault list --account \"$OP_ACCOUNT\" >/dev/null 2>&1 || { echo \"ERROR: 1Password not unlocked for $OP_ACCOUNT. Open the 1Password app and authenticate (Touch ID) first.\"; exit 1; }; SHADI_SECRET_BACKEND=onepassword SHADI_OP_ACCOUNT=\"{{SHADI_OP_ACCOUNT}}\" SHADI_TMP_DIR=\"./.tmp\" SHADI_AGENT_ID=\"avatar-1\" SHADI_OPERATOR_PRESENTATION=\"local-operator\" ./scripts/launch_avatar.sh"
  } }}

[group('demos')]
[doc('Tail the background SLIM and SecOps A2A logs.')]
demo-logs:
  {{ if os() == "windows" {
    "Get-Content -Path .tmp/slim.log, .tmp/secops-a2a.log -Wait"
  } else {
    "tail -f .tmp/slim.log .tmp/secops-a2a.log"
  } }}