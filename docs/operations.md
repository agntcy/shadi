# Operations

This guide is for running SHADI as an actual agent host instead of treating the
repository as a CLI demo. It pulls together the pages you need for execution,
troubleshooting, and the example workloads shipped with the repository.

## Overview

Use this page as the operator entry point. It does not replace the detailed
guides. It tells you which page to open next and in what order.

## Operating Model

In a normal SHADI run, the operator does four things:

1. Resolve a sandbox policy and choose the right launcher profile.
2. Ensure secrets and identity material are available before launch.
3. Start the runtime components in the correct order.
4. Verify outputs, reports, and runtime health when an agent action fails.

The detailed references still live in the underlying pages; this guide is the
entry point that tells you where to go and in what order.

!!! note

	If you are completely new to the project, start with [Getting Started](getting_started.md)
	first and come back here once the local launcher path is working.

## Choose a Workflow

=== "Sandboxed Execution"

	Use [Sandbox and Policies](sandbox.md) when you need to:

	- choose between `strict`, `balanced`, and `connected`
	- combine JSON policy with CLI overrides
	- broker secrets into the process environment before sandboxing
	- reason about the enforcement boundary on macOS and Windows

=== "Local Demo"

	Use [Demo Walkthrough](demo.md) when you want to run the local multi-agent demo.
	That page covers:

	- starting the local SLIM node
	- seeding shared secrets into SHADI
	- launching SecOps A2A servers
	- launching Avatar and sending operator requests
	- using the optional 1Password backend safely

=== "Demo Runbooks"

	Use [SecOps Demo](secops_agent.md) when you need a concrete example of a
	SHADI-hosted workload with GitHub, SLIM/A2A, and remediation logic.

	- configure the GitHub allowlist and required SHADI keys
	- run scans and remediation mode
	- understand the difference between dependency edits and container guidance
	- inspect memory, reports, and pending PR artifacts
	- run the focused Python test suite and skill scan

## Suggested Operator Flow

For the current demo workflows, this is the practical order:

1. Review [Sandbox and Policies](sandbox.md) and print the resolved policy you intend to run.
2. Load secrets and identity material required by the chosen agent.
3. Start transport dependencies from [Demo Walkthrough](demo.md).
4. Launch the sandboxed agent process.
5. Inspect outputs such as policy, Git snapshot artifacts, report files, memory state, and queued PR artifacts.

!!! info

	The most common operator failure mode is not a code bug. It is a mismatch
	between policy, secret availability, launch order, or shared transport configuration.

## Troubleshooting Map

Start from the symptom, then jump to the right page:

- Sandbox launch or path access issue: [Sandbox and Policies](sandbox.md)
- Git-backed sandbox snapshot or working-tree audit issue: [Sandbox and Policies](sandbox.md) and [CLI Reference](cli.md)
- Avatar or SLIM handshake issue: [Demo Walkthrough](demo.md)
- Demo workload or remediation behavior issue: [SecOps Demo](secops_agent.md)
- Identity, DID, or secret access issue: [API Guide](api_integration.md) and [CLI Reference](cli.md)

## Operational References

Keep these pages close when running the system:

- [CLI Reference](cli.md) for `shadictl` flags and memory commands
- [Sandbox and Policies](sandbox.md) for snapshot capture, launcher profiles, and enforcement boundaries
- [Security Notes](security.md) for threat-model boundaries and backend caveats
- [Architecture](architecture.md) for the control-plane versus runtime split

## Scope of This Page

This page does not repeat every command from the detailed guides. It exists so
operators have a stable route through the docs instead of jumping between long,
flat pages with no execution order.