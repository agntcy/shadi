// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! `shadictl slim controller` — a client for a SLIM node's controller
//! endpoint (`ControllerService.OpenControlChannel`), letting SHADI securely
//! push connections/routes (== subscriptions, see below) to a local node, or
//! introspect what's already configured.
//!
//! This is local-operator infrastructure, not a coding-agent identity: only
//! mTLS is used here (the same cert conventions as everywhere else in
//! shadictl), no DID/JWT `auth_provider` — the DID-only policy governs agent
//! identities (claude-code/codex/copilot/cursor-agent), not this channel.
//!
//! "Routes" and "subscriptions" are the same concept at two layers: setting a
//! `Route{name, link_id}` here causes the target node's controller to
//! translate it into a real `Subscribe` message on its datapath.

use slim_config::client::ClientConfig as CoreClientConfig;
use slim_config::grpc::client::TransportChannel;
use slim_config::tls::client::TlsClientConfig as CoreTlsClientConfig;
use slim_config::tls::common::{CaSource, Config as CoreTlsConfig, TlsSource};
use slim_proto::controller::proto::v1::{
    control_message, controller_service_client::ControllerServiceClient, Connection,
    ConnectionDirection, ConnectionListRequest, ConnectionListResponse, ConfigurationCommand,
    ControlMessage, Route, RouteListRequest, RouteListResponse,
};
use slim_proto::dataplane::proto::v1::{Name as ProtoName, NameId};
use tokio::runtime::Builder as TokioRuntimeBuilder;

use crate::cli_types::{SlimControllerConnectArgs, SlimControllerListArgs};
use crate::slim_shell::resolve_client_tls_material_for_agent;

pub(crate) fn run_controller_connect(args: SlimControllerConnectArgs) -> Result<(), String> {
    let output = run_controller_connect_once(&args)?;
    println!("{output}");
    Ok(())
}

pub(crate) fn run_controller_list_routes(args: SlimControllerListArgs) -> Result<(), String> {
    let output = run_controller_list_routes_once(&args)?;
    println!("{output}");
    Ok(())
}

pub(crate) fn run_controller_list_connections(args: SlimControllerListArgs) -> Result<(), String> {
    let output = run_controller_list_connections_once(&args)?;
    println!("{output}");
    Ok(())
}

fn run_controller_connect_once(args: &SlimControllerConnectArgs) -> Result<String, String> {
    let mut command = ConfigurationCommand::default();

    for entry in &args.create_connection {
        let (link_id, endpoint) = split_pair(entry, "--create-connection", "LINK_ID@ENDPOINT")?;
        let target = CoreClientConfig::with_endpoint(&endpoint);
        let config_data = serde_json::to_string(&target)
            .map_err(|err| format!("failed to serialize connection config: {err}"))?;
        command.connections_to_create.push(Connection {
            link_id,
            config_data,
        });
    }
    for link_id in &args.delete_connection {
        command.connections_to_delete.push(link_id.clone());
    }
    for entry in &args.set_route {
        let (name, link_id) = split_pair(entry, "--set-route", "NAME@LINK_ID")?;
        command.routes_to_set.push(route(&name, &link_id)?);
    }
    for entry in &args.delete_route {
        let (name, link_id) = split_pair(entry, "--delete-route", "NAME@LINK_ID")?;
        command.routes_to_delete.push(route(&name, &link_id)?);
    }

    if command.connections_to_create.is_empty()
        && command.connections_to_delete.is_empty()
        && command.routes_to_set.is_empty()
        && command.routes_to_delete.is_empty()
    {
        return Err(
            "at least one of --create-connection/--delete-connection/--set-route/--delete-route is required"
                .to_string(),
        );
    }

    let request = ControlMessage {
        message_id: uuid::Uuid::new_v4().to_string(),
        payload: Some(control_message::Payload::ConfigCommand(command)),
    };

    let response = send_and_await(&args.endpoint, args.timeout_seconds, request)?;
    match response.payload {
        Some(control_message::Payload::ConfigCommandAck(ack)) => Ok(format_config_command_ack(&ack)),
        Some(other) => Err(format!("unexpected response payload: {other:?}")),
        None => Err("controller returned an empty response".to_string()),
    }
}

fn run_controller_list_routes_once(args: &SlimControllerListArgs) -> Result<String, String> {
    let request = ControlMessage {
        message_id: uuid::Uuid::new_v4().to_string(),
        payload: Some(control_message::Payload::RouteListRequest(RouteListRequest {})),
    };
    let response = send_and_await(&args.endpoint, args.timeout_seconds, request)?;
    match response.payload {
        Some(control_message::Payload::RouteListResponse(list)) => Ok(format_route_list(&list)),
        Some(other) => Err(format!("unexpected response payload: {other:?}")),
        None => Err("controller returned an empty response".to_string()),
    }
}

fn run_controller_list_connections_once(args: &SlimControllerListArgs) -> Result<String, String> {
    let request = ControlMessage {
        message_id: uuid::Uuid::new_v4().to_string(),
        payload: Some(control_message::Payload::ConnectionListRequest(
            ConnectionListRequest {},
        )),
    };
    let response = send_and_await(&args.endpoint, args.timeout_seconds, request)?;
    match response.payload {
        Some(control_message::Payload::ConnectionListResponse(list)) => {
            Ok(format_connection_list(&list))
        }
        Some(other) => Err(format!("unexpected response payload: {other:?}")),
        None => Err("controller returned an empty response".to_string()),
    }
}

/// Open `OpenControlChannel`, send one `ControlMessage`, and return the first
/// message the controller sends back.
fn send_and_await(
    endpoint: &str,
    timeout_seconds: u64,
    request: ControlMessage,
) -> Result<ControlMessage, String> {
    let runtime = TokioRuntimeBuilder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("failed to create tokio runtime: {err}"))?;

    // rustls needs a process-level CryptoProvider installed once. Use
    // slim_config's own installer (aws-lc-rs, `Once`-guarded) rather than
    // installing a different backend ourselves — the rest of the SLIM stack
    // assumes aws-lc-rs, and having two backends racing to install first can
    // break other rustls-based connections elsewhere in the same process.
    slim_config::tls::provider::initialize_crypto_provider();

    runtime.block_on(async move {
        let client_config = build_core_client_config(endpoint)?;
        let channel = match client_config
            .to_channel()
            .await
            .map_err(|err| format!("failed to build controller channel: {err}"))?
        {
            TransportChannel::Grpc(channel) => channel,
            TransportChannel::Websocket(_) => {
                return Err("controller endpoint must be a gRPC endpoint".to_string())
            }
        };

        let mut client = ControllerServiceClient::new(channel);
        let outbound = futures::stream::once(async move { request });
        let mut inbound = client
            .open_control_channel(outbound)
            .await
            .map_err(|err| format!("failed to open control channel: {err}"))?
            .into_inner();

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_seconds),
            futures::StreamExt::next(&mut inbound),
        )
        .await
        .map_err(|_| format!("timed out after {timeout_seconds}s waiting for controller response"))?
        .ok_or_else(|| "controller closed the stream without a response".to_string())?
        .map_err(|status| format!("controller returned an error: {status}"))?;

        Ok(response)
    })
}

fn build_core_client_config(endpoint: &str) -> Result<CoreClientConfig, String> {
    let tls = resolve_client_tls_material_for_agent(None)?;
    let endpoint = if endpoint.contains("://") {
        endpoint.to_string()
    } else {
        format!("https://{endpoint}")
    };
    Ok(CoreClientConfig::with_endpoint(&endpoint).with_tls_setting(CoreTlsClientConfig {
        config: CoreTlsConfig {
            source: TlsSource::File {
                cert: tls.cert.display().to_string(),
                key: tls.key.display().to_string(),
            },
            ca_source: CaSource::File {
                path: tls.ca.display().to_string(),
            },
            include_system_ca_certs_pool: false,
            tls_version: "tls1.3".to_string(),
            reload_interval: None,
        },
        insecure: false,
        insecure_skip_verify: false,
    }))
}

fn split_pair(entry: &str, flag: &str, shape: &str) -> Result<(String, String), String> {
    entry
        .split_once('@')
        .map(|(a, b)| (a.trim().to_string(), b.trim().to_string()))
        .filter(|(a, b)| !a.is_empty() && !b.is_empty())
        .ok_or_else(|| format!("{flag} expects {shape}, got {entry:?}"))
}

/// Parse a route name: `org/ns/agent` or `org/ns/agent/id`, where `id` is
/// `NULL_COMPONENT`, a UUID, or a plain integer (all valid `NameId` forms —
/// see `NameId::try_from(String)` in `agntcy-slim-proto`, extended here to
/// also accept a bare integer for convenience).
fn route(name: &str, link_id: &str) -> Result<Route, String> {
    let parts: Vec<&str> = name.splitn(4, '/').collect();
    if parts.len() < 3 || parts[..3].iter().any(|p| p.is_empty()) {
        return Err(format!(
            "route name must be org/ns/agent or org/ns/agent/id, got {name:?}"
        ));
    }
    let mut proto_name = ProtoName::from_strings([parts[0], parts[1], parts[2]]);
    if let Some(id) = parts.get(3).filter(|s| !s.is_empty()) {
        proto_name = proto_name.with_id(parse_name_id(id)?);
    }
    Ok(Route {
        name: Some(proto_name),
        link_id: Some(link_id.to_string()),
        direction: Some(ConnectionDirection::Outgoing as i32),
    })
}

fn parse_name_id(id: &str) -> Result<u128, String> {
    if let Ok(value) = id.parse::<u128>() {
        return Ok(value);
    }
    NameId::try_from(id.to_string())
        .map(u128::from)
        .map_err(|err| format!("invalid route instance id {id:?}: {err}"))
}

fn format_config_command_ack(
    ack: &slim_proto::controller::proto::v1::ConfigurationCommandAck,
) -> String {
    let mut lines = vec![format!(
        "config command {} acknowledged",
        ack.original_message_id
    )];
    for status in &ack.connections_status {
        lines.push(format!(
            "  connection {}: {}",
            status.link_id,
            if status.success {
                "ok".to_string()
            } else {
                format!("failed ({})", status.error_msg)
            }
        ));
    }
    for status in &ack.routes_status {
        let name = status
            .route
            .as_ref()
            .and_then(|route| route.name.as_ref())
            .map(describe_proto_name)
            .unwrap_or_else(|| "<unknown>".to_string());
        lines.push(format!(
            "  route {}: {}",
            name,
            if status.success {
                "ok".to_string()
            } else {
                format!("failed ({})", status.error_msg)
            }
        ));
    }
    lines.join("\n")
}

fn format_route_list(list: &RouteListResponse) -> String {
    if list.entries.is_empty() {
        return "no routes".to_string();
    }
    list.entries
        .iter()
        .map(|entry| {
            let name = entry
                .name
                .as_ref()
                .map(describe_proto_name)
                .unwrap_or_else(|| "<unknown>".to_string());
            let conns = entry
                .connections
                .iter()
                .map(|c| c.id.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            format!("{name} -> connections [{conns}]")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_connection_list(list: &ConnectionListResponse) -> String {
    if list.entries.is_empty() {
        return "no connections".to_string();
    }
    list.entries
        .iter()
        .map(|entry| {
            format!(
                "id={} type={:?} direction={:?} link_id={}",
                entry.id,
                entry.connection_type,
                entry.direction,
                entry.link_id.clone().unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn describe_proto_name(name: &ProtoName) -> String {
    let Some(s) = name.str_name.as_ref() else {
        return "<encoded-name>".to_string();
    };
    let base = format!(
        "{}/{}/{}",
        s.str_component_0, s.str_component_1, s.str_component_2
    );
    match name.name.as_ref().map(|encoded| encoded.id()) {
        Some(id) if id != NameId::NULL_COMPONENT => format!("{base}/{id}"),
        _ => base,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_pair_parses_valid_entries() {
        assert_eq!(
            split_pair("link-1@127.0.0.1:1234", "--create-connection", "LINK_ID@ENDPOINT").unwrap(),
            ("link-1".to_string(), "127.0.0.1:1234".to_string())
        );
    }

    #[test]
    fn split_pair_rejects_malformed_entries() {
        assert!(split_pair("no-at-sign", "--set-route", "NAME@LINK_ID").is_err());
        assert!(split_pair("@link", "--set-route", "NAME@LINK_ID").is_err());
        assert!(split_pair("name@", "--set-route", "NAME@LINK_ID").is_err());
    }

    #[test]
    fn route_requires_three_name_components() {
        assert!(route("org/ns", "link-1").is_err());
        let r = route("org/ns/agent", "link-1").unwrap();
        assert_eq!(r.link_id.as_deref(), Some("link-1"));
        assert_eq!(
            r.direction,
            Some(ConnectionDirection::Outgoing as i32)
        );
        let name = r.name.unwrap();
        let str_name = name.str_name.unwrap();
        assert_eq!(str_name.str_component_0, "org");
        assert_eq!(str_name.str_component_1, "ns");
        assert_eq!(str_name.str_component_2, "agent");
        // No 4th segment => NULL_COMPONENT (no specific instance targeted).
        assert_eq!(name.name.unwrap().id(), NameId::NULL_COMPONENT);
    }

    #[test]
    fn route_accepts_integer_instance_id() {
        let r = route("org/ns/agent/7", "link-1").unwrap();
        let name = r.name.unwrap();
        assert_eq!(describe_proto_name(&name), "org/ns/agent/7");
        assert_eq!(name.name.unwrap().id(), 7u128);
    }

    #[test]
    fn route_accepts_uuid_instance_id() {
        let uuid = uuid::Uuid::new_v4();
        let r = route(&format!("org/ns/agent/{uuid}"), "link-1").unwrap();
        assert_eq!(r.name.unwrap().name.unwrap().id(), uuid.as_u128());
    }

    #[test]
    fn route_accepts_explicit_null_component() {
        let r = route("org/ns/agent/NULL_COMPONENT", "link-1").unwrap();
        assert_eq!(r.name.unwrap().name.unwrap().id(), NameId::NULL_COMPONENT);
    }

    #[test]
    fn route_rejects_invalid_instance_id() {
        assert!(route("org/ns/agent/not-an-id", "link-1").is_err());
    }

    #[test]
    fn describe_proto_name_omits_null_component() {
        let name = ProtoName::from_strings(["org", "ns", "agent"]);
        assert_eq!(describe_proto_name(&name), "org/ns/agent");
    }

    #[test]
    fn describe_proto_name_shows_real_instance_id() {
        let name = ProtoName::from_strings(["org", "ns", "agent"]).with_id(42u128);
        assert_eq!(describe_proto_name(&name), "org/ns/agent/42");
    }
}
