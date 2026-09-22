# Embedding AgentBridge With Mediation

`agentbridge::executor::AgentBridgeExecutor` is the same A2A executor used by the
CLI, now available to embedding hosts. The host may install a
`shadi_mas::mediation::MediationHook` using `with_mediation` on both:

- `LiveA2ATaskAdapter`: before DID signing and any transport publication;
- `AgentBridgeExecutor`: after destination/DID proof verification, before the
  adapter executes the request. The hook also gates special handoff packets.

The hook returns `Allow {}` or `Deny { reason }`. An installed hook is mandatory:
the common gate imposes a five-second deadline and fails closed on any error.
There is no policy-service implementation or IoC dependency in SHADi. Hosts own
authentication, payload-export policy, telemetry, and transport of the decision.
Existing callers without a hook retain their existing behavior.

Sender events contain metadata only. Receiver events contain the verified
plaintext and proven sender DID. `peer` at the sender is the intended recipient,
not a verified remote identity. Correlation metadata is useful for telemetry,
not authenticated authority for policy. Message IDs stay stable across transport
retries; an authentication retry with changed content gets a new evaluation.

Receiver policy denials become stored `Rejected` tasks, while hook failures
become stored `Failed` tasks. Failed/rejected responses propagate as errors to
the live sender adapter. The existing DID admission gate still handles unsigned
and forged requests before mediation is consulted.

`GenericStdioAdapter::from_streams` permits attaching a child launched using
`shadi_sandbox::spawn_sandboxed`. The embedding host must retain and reap the
child. Installing a hook alone does not prevent an agent with separate network
access or credentials from using a different transport. Hosts must isolate
untrusted children and keep their own secrets and policy configuration private.

These hooks cover A2A request admission/dispatch only. They do not intercept
responses, arbitrary network traffic or direct SLIM publishers outside these
paths. Hooks evaluate again on duplicate delivery; they are not an exactly-once
execution mechanism. The CLI does not implicitly load a hook from environment
variables, plugins or global registration.
