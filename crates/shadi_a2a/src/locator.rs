// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Official A2A bindings and the locator that points at one.
//!
//! The DID is the portable name (local aliases: tool name, SLIM channel).
//! A locator is `{binding, url}` and can change when the agent moves —
//! look the DID up again. SLIM's locator is the local node (`slim://host:port`);
//! gRPC / JSON-RPC / HTTP+JSON locators are the listen URL.

use std::fmt;
use std::str::FromStr;

use a2a::{
    TRANSPORT_PROTOCOL_GRPC, TRANSPORT_PROTOCOL_HTTP_JSON, TRANSPORT_PROTOCOL_JSONRPC,
    TRANSPORT_PROTOCOL_SLIMRPC,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Official A2A protocol bindings, including SLIMRPC.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum A2ABinding {
    Slim,
    #[default]
    Grpc,
    Jsonrpc,
    HttpJson,
}

impl A2ABinding {
    /// A2A `protocolBinding` string: `SLIMRPC`, `GRPC`, `JSONRPC`, or `HTTP+JSON`.
    pub fn as_protocol_binding(self) -> &'static str {
        match self {
            Self::Slim => TRANSPORT_PROTOCOL_SLIMRPC,
            Self::Grpc => TRANSPORT_PROTOCOL_GRPC,
            Self::Jsonrpc => TRANSPORT_PROTOCOL_JSONRPC,
            Self::HttpJson => TRANSPORT_PROTOCOL_HTTP_JSON,
        }
    }

    /// Locator URI scheme used in `list --local` and `--a2a-url` overrides.
    pub fn uri_scheme(self) -> &'static str {
        match self {
            Self::Slim => "slim",
            Self::Grpc => "grpc",
            Self::Jsonrpc => "jsonrpc",
            Self::HttpJson => "http+json",
        }
    }

    pub fn is_unicast(self) -> bool {
        !matches!(self, Self::Slim)
    }

    /// Bindings that `--a2a-listen` / `--a2a-binding` may name. SLIM uses
    /// `--slim-endpoint` (the locator is the local node).
    pub fn parse_unicast(raw: &str) -> Result<Self, String> {
        let parsed = Self::parse(raw)?;
        if parsed.is_unicast() {
            Ok(parsed)
        } else {
            Err(
                "SLIM uses --slim-endpoint (locator is the local node), not --a2a-binding"
                    .to_string(),
            )
        }
    }

    pub fn parse(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        if trimmed.eq_ignore_ascii_case("slim")
            || trimmed.eq_ignore_ascii_case("slimrpc")
            || trimmed.eq_ignore_ascii_case(TRANSPORT_PROTOCOL_SLIMRPC)
        {
            return Ok(Self::Slim);
        }
        if trimmed.eq_ignore_ascii_case("grpc")
            || trimmed.eq_ignore_ascii_case(TRANSPORT_PROTOCOL_GRPC)
        {
            return Ok(Self::Grpc);
        }
        if trimmed.eq_ignore_ascii_case("jsonrpc")
            || trimmed.eq_ignore_ascii_case(TRANSPORT_PROTOCOL_JSONRPC)
        {
            return Ok(Self::Jsonrpc);
        }
        if trimmed.eq_ignore_ascii_case("http+json")
            || trimmed.eq_ignore_ascii_case("http-json")
            || trimmed.eq_ignore_ascii_case("httpjson")
            || trimmed.eq_ignore_ascii_case("rest")
            || trimmed.eq_ignore_ascii_case(TRANSPORT_PROTOCOL_HTTP_JSON)
        {
            return Ok(Self::HttpJson);
        }
        Err(format!(
            "unknown A2A binding '{raw}' (expected slim, grpc, jsonrpc, or http+json)"
        ))
    }
}

impl FromStr for A2ABinding {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for A2ABinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.uri_scheme())
    }
}

impl Serialize for A2ABinding {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_protocol_binding())
    }
}

impl<'de> Deserialize<'de> for A2ABinding {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        if raw.is_empty() {
            return Ok(Self::Grpc);
        }
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// How to reach one agent on an official A2A binding.
///
/// For SLIM, `url` is the local node (`slim://127.0.0.1:47357`). For unicast,
/// `url` is an HTTP(S) origin. The binding says which protocol to speak.
/// Two agents can share one locator (same SLIM node, or the same listen URL).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2ALocator {
    pub binding: A2ABinding,
    pub url: String,
}

impl A2ALocator {
    pub fn new(binding: A2ABinding, url: impl Into<String>) -> Self {
        let raw = url.into();
        let url = if binding == A2ABinding::Slim {
            slim_node_uri(&raw)
        } else {
            normalize_http_url(&raw)
        };
        Self { binding, url }
    }

    /// SLIM locator: the local node, not the channel name.
    pub fn slim(node: impl AsRef<str>) -> Self {
        Self::new(A2ABinding::Slim, node.as_ref())
    }

    /// Parse a locator URI or a bare HTTP(S) URL.
    ///
    /// - `slim://host:port` → SLIM at that local node (path is stripped)
    /// - `grpc://host:port` → gRPC at `http://host:port`
    /// - `jsonrpc://host:port` → JSON-RPC at `http://host:port`
    /// - `http+json://host:port` → HTTP+JSON at `http://host:port`
    /// - `http://…` / `https://…` → `hint` (default gRPC) at that URL
    pub fn parse(raw: &str) -> Result<Self, String> {
        Self::parse_with_hint(raw, None)
    }

    pub fn parse_with_hint(raw: &str, hint: Option<A2ABinding>) -> Result<Self, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("A2A locator is empty".to_string());
        }
        if let Some(rest) = strip_scheme_ci(trimmed, "slim://") {
            return Ok(Self::slim(rest));
        }
        if let Some(rest) = strip_scheme_ci(trimmed, "grpc://") {
            return Ok(Self::new(A2ABinding::Grpc, http_origin(rest, false)));
        }
        if let Some(rest) = strip_scheme_ci(trimmed, "jsonrpc://") {
            return Ok(Self::new(A2ABinding::Jsonrpc, http_origin(rest, false)));
        }
        if let Some(rest) = strip_scheme_ci(trimmed, "http+json://") {
            return Ok(Self::new(A2ABinding::HttpJson, http_origin(rest, false)));
        }
        if let Some(rest) = strip_scheme_ci(trimmed, "http-json://") {
            return Ok(Self::new(A2ABinding::HttpJson, http_origin(rest, false)));
        }
        if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            return Ok(Self::new(hint.unwrap_or(A2ABinding::Grpc), trimmed));
        }
        if let Some(binding) = hint {
            return Ok(Self::new(binding, trimmed));
        }
        Err(format!(
            "unrecognized A2A locator '{raw}' (expected slim://, grpc://, jsonrpc://, http+json://, or http(s)://)"
        ))
    }

    /// Host:port of a SLIM node locator (`slim://127.0.0.1:47357` → `127.0.0.1:47357`).
    pub fn slim_node(&self) -> String {
        strip_slim_scheme(&self.url).to_string()
    }

    /// `slim://127.0.0.1:47357` / `grpc://127.0.0.1:50051` on plaintext.
    /// HTTPS keeps the `https://` URL and prefixes the protocol binding
    /// (`JSONRPC https://example.test:443`) so we do not invent `jsonrpcs://`.
    pub fn display_uri(&self) -> String {
        if self.binding == A2ABinding::Slim {
            return slim_node_uri(&self.url);
        }
        if self.url.starts_with("https://") {
            format!("{} {}", self.binding.as_protocol_binding(), self.url)
        } else {
            format!(
                "{}://{}",
                self.binding.uri_scheme(),
                strip_http_scheme(&self.url)
            )
        }
    }
}

impl fmt::Display for A2ALocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display_uri())
    }
}

impl FromStr for A2ALocator {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

fn strip_scheme_ci<'a>(raw: &'a str, scheme: &str) -> Option<&'a str> {
    if raw.len() < scheme.len() {
        return None;
    }
    if raw.get(..scheme.len())?.eq_ignore_ascii_case(scheme) {
        Some(&raw[scheme.len()..])
    } else {
        None
    }
}

fn strip_http_scheme(url: &str) -> &str {
    url.strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url)
}

fn strip_slim_scheme(url: &str) -> &str {
    let rest = url
        .strip_prefix("slim://")
        .or_else(|| url.strip_prefix("SLIM://"))
        .unwrap_or(url);
    rest.split('/').next().unwrap_or(rest)
}

fn slim_node_uri(raw: &str) -> String {
    let node = strip_slim_scheme(raw.trim());
    let node = node
        .strip_prefix("https://")
        .or_else(|| node.strip_prefix("http://"))
        .unwrap_or(node);
    format!("slim://{node}")
}

fn http_origin(host: &str, https: bool) -> String {
    let host = host.trim_start_matches('/');
    if host.starts_with("http://") || host.starts_with("https://") {
        return host.to_string();
    }
    if https {
        format!("https://{host}")
    } else {
        format!("http://{host}")
    }
}

fn normalize_http_url(url: &str) -> String {
    let trimmed = url.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return trimmed.trim_end_matches('/').to_string();
    }
    format!("http://{}", trimmed.trim_end_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_binding_names() {
        assert_eq!(A2ABinding::parse("grpc").unwrap(), A2ABinding::Grpc);
        assert_eq!(A2ABinding::parse("GRPC").unwrap(), A2ABinding::Grpc);
        assert_eq!(A2ABinding::parse("jsonrpc").unwrap(), A2ABinding::Jsonrpc);
        assert_eq!(A2ABinding::parse("JSONRPC").unwrap(), A2ABinding::Jsonrpc);
        assert_eq!(A2ABinding::parse("http+json").unwrap(), A2ABinding::HttpJson);
        assert_eq!(A2ABinding::parse("HTTP+JSON").unwrap(), A2ABinding::HttpJson);
        assert_eq!(A2ABinding::parse("rest").unwrap(), A2ABinding::HttpJson);
        assert_eq!(A2ABinding::parse("slimrpc").unwrap(), A2ABinding::Slim);
        assert_eq!(A2ABinding::parse("SLIMRPC").unwrap(), A2ABinding::Slim);
        assert!(A2ABinding::parse_unicast("slim").is_err());
    }

    #[test]
    fn parse_locator_uris() {
        let grpc = A2ALocator::parse("grpc://127.0.0.1:50051").unwrap();
        assert_eq!(grpc.binding, A2ABinding::Grpc);
        assert_eq!(grpc.url, "http://127.0.0.1:50051");
        assert_eq!(grpc.display_uri(), "grpc://127.0.0.1:50051");

        let jsonrpc = A2ALocator::parse("jsonrpc://127.0.0.1:8080").unwrap();
        assert_eq!(jsonrpc.binding, A2ABinding::Jsonrpc);
        assert_eq!(jsonrpc.url, "http://127.0.0.1:8080");
        assert_eq!(jsonrpc.display_uri(), "jsonrpc://127.0.0.1:8080");

        let rest = A2ALocator::parse("http+json://127.0.0.1:8080/").unwrap();
        assert_eq!(rest.binding, A2ABinding::HttpJson);
        assert_eq!(rest.url, "http://127.0.0.1:8080");
        assert_eq!(rest.display_uri(), "http+json://127.0.0.1:8080");

        let slim = A2ALocator::parse("slim://127.0.0.1:47357/agntcy/shadi/copilot-a2a").unwrap();
        assert_eq!(slim.binding, A2ABinding::Slim);
        assert_eq!(slim.url, "slim://127.0.0.1:47357");
        assert_eq!(slim.slim_node(), "127.0.0.1:47357");
        assert_eq!(slim.display_uri(), "slim://127.0.0.1:47357");
    }

    #[test]
    fn bare_http_defaults_to_grpc_unless_hinted() {
        let grpc = A2ALocator::parse("http://127.0.0.1:50051").unwrap();
        assert_eq!(grpc.binding, A2ABinding::Grpc);
        let jsonrpc = A2ALocator::parse_with_hint(
            "http://127.0.0.1:8080",
            Some(A2ABinding::Jsonrpc),
        )
        .unwrap();
        assert_eq!(jsonrpc.binding, A2ABinding::Jsonrpc);
        assert_eq!(jsonrpc.url, "http://127.0.0.1:8080");
        let https = A2ALocator::parse_with_hint(
            "https://example.test:443",
            Some(A2ABinding::HttpJson),
        )
        .unwrap();
        assert_eq!(https.binding, A2ABinding::HttpJson);
        assert_eq!(https.url, "https://example.test:443");
        assert_eq!(
            https.display_uri(),
            "HTTP+JSON https://example.test:443"
        );
    }

    #[test]
    fn slim_locator_is_the_local_node() {
        let by_hint = A2ALocator::parse_with_hint("127.0.0.1:47357", Some(A2ABinding::Slim)).unwrap();
        assert_eq!(by_hint, A2ALocator::slim("127.0.0.1:47357"));
        assert_eq!(by_hint.display_uri(), "slim://127.0.0.1:47357");
    }

    #[test]
    fn serde_roundtrip_uses_protocol_binding() {
        let value = serde_json::to_value(A2ABinding::HttpJson).unwrap();
        assert_eq!(value, serde_json::Value::String("HTTP+JSON".to_string()));
        let back: A2ABinding = serde_json::from_value(value).unwrap();
        assert_eq!(back, A2ABinding::HttpJson);
        let empty: A2ABinding = serde_json::from_str("\"\"").unwrap();
        assert_eq!(empty, A2ABinding::Grpc);
        let slim = serde_json::to_value(A2ABinding::Slim).unwrap();
        assert_eq!(slim, serde_json::Value::String("SLIMRPC".to_string()));
    }

    #[test]
    fn binding_from_str_display_and_unknown() {
        assert_eq!("grpc".parse::<A2ABinding>().unwrap(), A2ABinding::Grpc);
        assert_eq!(A2ABinding::Slim.to_string(), "slim");
        assert_eq!(
            A2ABinding::Slim.as_protocol_binding(),
            TRANSPORT_PROTOCOL_SLIMRPC
        );
        let err = A2ABinding::parse("ftp").unwrap_err();
        assert!(err.contains("unknown A2A binding"), "{err}");
    }

    #[test]
    fn locator_from_str_display_errors_and_http_origin() {
        let loc: A2ALocator = "grpc://127.0.0.1:9".parse().unwrap();
        assert_eq!(loc.to_string(), "grpc://127.0.0.1:9");
        assert!(A2ALocator::parse("").unwrap_err().contains("empty"));
        assert!(A2ALocator::parse("not-a-locator")
            .unwrap_err()
            .contains("unrecognized A2A locator"));
        let hyphen = A2ALocator::parse("http-json://127.0.0.1:8080").unwrap();
        assert_eq!(hyphen.binding, A2ABinding::HttpJson);
        let nested = A2ALocator::parse("grpc://https://example.test:443").unwrap();
        assert_eq!(nested.url, "https://example.test:443");
        assert_eq!(
            http_origin("https://example.test", true),
            "https://example.test"
        );
        assert_eq!(http_origin("example.test", true), "https://example.test");
        let bare = A2ALocator::new(A2ABinding::Grpc, "127.0.0.1:9");
        assert_eq!(bare.url, "http://127.0.0.1:9");
        assert!(strip_scheme_ci("g", "grpc://").is_none());
    }
}
