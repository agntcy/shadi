// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformSandboxProfile {
    Compatibility,
    Minimal,
}

impl PlatformSandboxProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Compatibility => "compatibility",
            Self::Minimal => "minimal",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    allow_read: Vec<PathBuf>,
    allow_write: Vec<PathBuf>,
    deny: Vec<PathBuf>,
    net_allow: Vec<String>,
    net_block: bool,
    platform_profile: PlatformSandboxProfile,
    allow_local_unix_sockets: bool,
    /// When set, the kernel sandbox restricts outbound TCP to this loopback
    /// port only (the userspace proxy port), leaving domain-level enforcement
    /// to the proxy.
    net_proxy_port: Option<u16>,
}

/// The named launch profiles offered by `shadictl --profile` and the desktop
/// sandbox panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SandboxProfile {
    /// Read and write confined to the working directory, network off.
    Strict,
    /// Working directory writable, wider reads where the platform sandbox
    /// gives them for free, network off.
    Balanced,
    /// Balanced, with the network left on.
    Connected,
}

/// The four axes a named profile fixes. A caller layers its own paths and
/// allowlists on top; everything else a profile could set is empty in all of
/// them, which is why only these four live here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileDefaults {
    pub allow: Vec<String>,
    pub read: Vec<String>,
    pub write: Vec<String>,
    pub net_block: bool,
}

impl SandboxProfile {
    /// Parse the profile names accepted on the command line.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "strict" => Some(Self::Strict),
            "balanced" => Some(Self::Balanced),
            "connected" => Some(Self::Connected),
            _ => None,
        }
    }

    /// The name this profile is spelled with on the command line.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Balanced => "balanced",
            Self::Connected => "connected",
        }
    }

    pub fn defaults(self) -> ProfileDefaults {
        // macOS Seatbelt and Linux Landlock both give a readable root without
        // it costing anything, so only the platforms without that need "/"
        // spelled out.
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        let wide_read: Vec<String> = Vec::new();
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let wide_read: Vec<String> = vec!["/".to_string()];

        match self {
            Self::Strict => ProfileDefaults {
                allow: vec![".".to_string()],
                read: vec![".".to_string()],
                write: Vec::new(),
                net_block: true,
            },
            Self::Balanced => ProfileDefaults {
                allow: vec![".".to_string()],
                read: wide_read,
                write: Vec::new(),
                net_block: true,
            },
            Self::Connected => ProfileDefaults {
                allow: vec![".".to_string()],
                read: wide_read,
                write: Vec::new(),
                net_block: false,
            },
        }
    }
}

impl SandboxPolicy {
    pub fn new() -> Self {
        Self {
            allow_read: Vec::new(),
            allow_write: Vec::new(),
            deny: Vec::new(),
            net_allow: Vec::new(),
            net_block: false,
            platform_profile: PlatformSandboxProfile::Compatibility,
            allow_local_unix_sockets: false,
            net_proxy_port: None,
        }
    }

    pub fn allow_read_path(mut self, path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        if !self.allow_read.contains(&path) {
            self.allow_read.push(path);
        }
        self
    }

    pub fn allow_write_path(mut self, path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        if !self.allow_write.contains(&path) {
            self.allow_write.push(path);
        }
        self
    }

    /// Subtract this path from compiled platform defaults and caller allows.
    /// Seatbelt emits the deny first (first match wins). Landlock drops the
    /// matching allow root because it cannot carve a hole in a parent grant.
    pub fn deny_path(mut self, path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        if !self.deny.contains(&path) {
            self.deny.push(path);
        }
        self
    }

    pub fn deny(&self) -> &[PathBuf] {
        &self.deny
    }

    pub fn path_is_denied(&self, path: &Path) -> bool {
        self.deny
            .iter()
            .any(|denied| path == denied || path.starts_with(denied))
    }

    pub fn block_network(mut self, value: bool) -> Self {
        self.net_block = value;
        self
    }

    pub fn allow_network_destination(mut self, destination: impl Into<String>) -> Self {
        let destination = destination.into();
        if !self.net_allow.contains(&destination) {
            self.net_allow.push(destination);
        }
        self
    }

    pub fn with_network_destinations(mut self, destinations: Vec<String>) -> Self {
        let mut unique = Vec::new();
        for dest in destinations {
            if !unique.contains(&dest) {
                unique.push(dest);
            }
        }
        self.net_allow = unique;
        self
    }

    pub fn use_minimal_platform_profile(mut self) -> Self {
        self.platform_profile = PlatformSandboxProfile::Minimal;
        self
    }

    pub fn allow_local_unix_sockets(mut self) -> Self {
        self.allow_local_unix_sockets = true;
        self
    }

    pub fn allow_read(&self) -> &[PathBuf] {
        &self.allow_read
    }

    pub fn allow_write(&self) -> &[PathBuf] {
        &self.allow_write
    }

    pub fn net_blocked(&self) -> bool {
        self.net_block
    }

    pub fn net_allow(&self) -> &[String] {
        &self.net_allow
    }

    pub fn platform_profile(&self) -> PlatformSandboxProfile {
        self.platform_profile
    }

    pub fn local_unix_sockets_allowed(&self) -> bool {
        self.allow_local_unix_sockets
    }

    /// Configure the kernel sandbox to allow outbound TCP only to
    /// `127.0.0.1:<port>` (the userspace proxy port).
    pub fn with_net_proxy_port(mut self, port: u16) -> Self {
        self.net_proxy_port = Some(port);
        self
    }

    /// Returns the proxy port if proxy-mode enforcement is active.
    pub fn net_proxy_port(&self) -> Option<u16> {
        self.net_proxy_port
    }
}

/// A TCP port the kernel lets through while the network is restricted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KernelNetPort {
    pub(crate) port: u16,
    /// Direct connects to any host on this port.
    pub(crate) any_host: bool,
    /// Direct connects to loopback on this port.
    pub(crate) loopback: bool,
}

impl SandboxPolicy {
    /// The ports `net_allow` opens in the kernel; each also allows bind and inbound.
    ///
    /// Seatbelt matches a remote host only as `localhost` or `*`, and Landlock
    /// matches ports alone, so the kernel enforces an entry per port. In proxy
    /// mode only loopback entries connect directly and the proxy checks the
    /// rest by name. An entry without a port has no kernel form, so outside
    /// proxy mode it is an error rather than a silent allow or deny.
    pub(crate) fn kernel_net_ports(&self) -> Result<Vec<KernelNetPort>, String> {
        let proxy = self.net_proxy_port.is_some();
        let mut ports: Vec<KernelNetPort> = Vec::new();
        for entry in &self.net_allow {
            let Some((host, port)) = split_host_port(entry)? else {
                if proxy {
                    continue;
                }
                return Err(format!(
                    "--net-allow {entry} has no port; without --watch-policy the allow-list is \
                     enforced per port, so add one (for example {entry}:443) or use --watch-policy"
                ));
            };
            let loopback = is_loopback_host(host);
            let slot = match ports.iter().position(|p| p.port == port) {
                Some(index) => &mut ports[index],
                None => {
                    ports.push(KernelNetPort {
                        port,
                        any_host: false,
                        loopback: false,
                    });
                    ports.last_mut().expect("just pushed")
                }
            };
            slot.loopback |= loopback;
            slot.any_host |= !loopback && !proxy;
        }
        Ok(ports)
    }
}

/// Split `host:port` or `[v6]:port`; `Ok(None)` when the entry names no port.
fn split_host_port(entry: &str) -> Result<Option<(&str, u16)>, String> {
    let (host, port) = if let Some(rest) = entry.strip_prefix('[') {
        match rest.split_once("]:") {
            Some(split) => split,
            None => return Ok(None),
        }
    } else {
        match entry.split_once(':') {
            Some((host, port)) if !port.contains(':') => (host, port),
            _ => return Ok(None),
        }
    };
    if host.is_empty() {
        return Err(format!("--net-allow {entry} has no host"));
    }
    match port.parse::<u16>() {
        Ok(port) if port != 0 => Ok(Some((host, port))),
        _ => Err(format!("--net-allow {entry} has an invalid port")),
    }
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root() -> String {
        std::env::var("SHADI_TMP_DIR").unwrap_or_else(|_| "./.tmp".to_string())
    }

    #[test]
    fn policy_collects_paths_and_network_flag() {
        let tmp_dir = tmp_root();
        let policy = SandboxPolicy::new()
            .allow_read_path(&tmp_dir)
            .allow_write_path(&tmp_dir)
            .block_network(true);

        assert!(policy.allow_read().iter().any(|p| p == Path::new(&tmp_dir)));
        assert!(policy.allow_write().iter().any(|p| p == Path::new(&tmp_dir)));
        assert!(policy.net_blocked());
        assert_eq!(policy.platform_profile(), PlatformSandboxProfile::Compatibility);
    }

    #[test]
    fn policy_can_collect_network_destinations() {
        let policy = SandboxPolicy::new()
            .allow_network_destination("1.1.1.1:80")
            .allow_network_destination("api.github.com");

        assert_eq!(policy.net_allow(), &["1.1.1.1:80".to_string(), "api.github.com".to_string()]);
    }

    #[test]
    fn policy_can_replace_network_destinations() {
        let policy = SandboxPolicy::new()
            .allow_network_destination("1.1.1.1:80")
            .with_network_destinations(vec!["2.2.2.2:443".to_string()]);

        assert_eq!(policy.net_allow(), &["2.2.2.2:443".to_string()]);
    }

    #[test]
    fn policy_deduplicates_duplicate_paths_and_network_destinations() {
        let tmp_dir = tmp_root();
        let policy = SandboxPolicy::new()
            .allow_read_path(&tmp_dir)
            .allow_read_path(&tmp_dir)
            .allow_write_path(&tmp_dir)
            .allow_write_path(&tmp_dir)
            .deny_path(&tmp_dir)
            .deny_path(&tmp_dir)
            .allow_network_destination("api.github.com")
            .allow_network_destination("api.github.com")
            .with_network_destinations(vec!["1.1.1.1:80".to_string(), "1.1.1.1:80".to_string()]);

        assert_eq!(policy.allow_read().iter().filter(|p| **p == PathBuf::from(&tmp_dir)).count(), 1);
        assert_eq!(policy.allow_write().iter().filter(|p| **p == PathBuf::from(&tmp_dir)).count(), 1);
        assert_eq!(policy.deny().iter().filter(|p| **p == PathBuf::from(&tmp_dir)).count(), 1);
        assert_eq!(policy.net_allow(), &["1.1.1.1:80".to_string()]);
    }

    #[test]
    fn policy_can_switch_to_minimal_platform_profile() {
        let policy = SandboxPolicy::new().use_minimal_platform_profile();
        assert_eq!(policy.platform_profile(), PlatformSandboxProfile::Minimal);
    }

    #[test]
    fn policy_can_allow_local_unix_sockets() {
        let policy = SandboxPolicy::new().allow_local_unix_sockets();
        assert!(policy.local_unix_sockets_allowed());
    }

    fn ports(policy: SandboxPolicy) -> Vec<KernelNetPort> {
        policy.kernel_net_ports().expect("valid net_allow")
    }

    fn blocked(entries: &[&str]) -> SandboxPolicy {
        let mut policy = SandboxPolicy::new().block_network(true);
        for entry in entries {
            policy = policy.allow_network_destination(*entry);
        }
        policy
    }

    #[test]
    fn loopback_entries_open_only_loopback() {
        for entry in ["127.0.0.1:47357", "localhost:47357", "[::1]:47357"] {
            assert_eq!(
                ports(blocked(&[entry])),
                [KernelNetPort {
                    port: 47357,
                    any_host: false,
                    loopback: true
                }],
                "{entry}"
            );
        }
    }

    #[test]
    fn other_entries_open_their_port_to_any_host() {
        assert_eq!(
            ports(blocked(&[
                "api.github.com:443",
                "*.example.com:8443",
                "1.1.1.1:80"
            ])),
            [
                KernelNetPort {
                    port: 443,
                    any_host: true,
                    loopback: false
                },
                KernelNetPort {
                    port: 8443,
                    any_host: true,
                    loopback: false
                },
                KernelNetPort {
                    port: 80,
                    any_host: true,
                    loopback: false
                },
            ]
        );
    }

    #[test]
    fn one_port_named_twice_merges() {
        assert_eq!(
            ports(blocked(&["127.0.0.1:443", "api.github.com:443"])),
            [KernelNetPort {
                port: 443,
                any_host: true,
                loopback: true
            }]
        );
    }

    #[test]
    fn an_entry_without_a_port_is_an_error_without_the_proxy() {
        for entry in [
            "api.anthropic.com",
            "127.0.0.1",
            "::1",
            "[::1]",
            "*.github.com",
        ] {
            let err = blocked(&[entry]).kernel_net_ports().unwrap_err();
            assert!(
                err.contains("has no port") && err.contains("--watch-policy"),
                "{entry}: {err}"
            );
        }
    }

    #[test]
    fn invalid_ports_and_hosts_are_errors() {
        for (entry, want) in [
            ("host:0", "invalid port"),
            ("host:65536", "invalid port"),
            ("host:", "invalid port"),
            ("host:http", "invalid port"),
            (":443", "no host"),
        ] {
            let err = blocked(&[entry]).kernel_net_ports().unwrap_err();
            assert!(err.contains(want), "{entry}: {err}");
        }
    }

    #[test]
    fn the_proxy_connects_only_loopback_directly() {
        let policy = blocked(&["127.0.0.1:47357", "api.github.com:443", "github.com"])
            .with_net_proxy_port(1080);
        assert_eq!(
            ports(policy),
            [
                KernelNetPort {
                    port: 47357,
                    any_host: false,
                    loopback: true
                },
                KernelNetPort {
                    port: 443,
                    any_host: false,
                    loopback: false
                },
            ],
            "a port-less name is the proxy's to enforce, and a remote port opens bind only"
        );
    }
}

#[cfg(test)]
mod profile_tests {
    use super::*;

    #[test]
    fn profile_names_round_trip_and_reject_the_rest() {
        assert_eq!(SandboxProfile::from_name("strict"), Some(SandboxProfile::Strict));
        assert_eq!(SandboxProfile::from_name("balanced"), Some(SandboxProfile::Balanced));
        assert_eq!(SandboxProfile::from_name("connected"), Some(SandboxProfile::Connected));
        // The CLI accepts these case-insensitively, so the library must too.
        assert_eq!(SandboxProfile::from_name("STRICT"), Some(SandboxProfile::Strict));
        assert_eq!(SandboxProfile::from_name("paranoid"), None);
        assert_eq!(SandboxProfile::from_name(""), None);
    }

    #[test]
    fn only_connected_leaves_the_network_on() {
        assert!(SandboxProfile::Strict.defaults().net_block);
        assert!(SandboxProfile::Balanced.defaults().net_block);
        assert!(!SandboxProfile::Connected.defaults().net_block);
    }

    #[test]
    fn every_profile_grants_the_working_directory_and_no_blanket_write() {
        for profile in [
            SandboxProfile::Strict,
            SandboxProfile::Balanced,
            SandboxProfile::Connected,
        ] {
            let d = profile.defaults();
            assert_eq!(d.allow, vec![".".to_string()], "{profile:?}");
            assert!(d.write.is_empty(), "{profile:?} must not grant a blanket write");
        }
    }

    #[test]
    fn strict_confines_reads_where_the_others_do_not() {
        assert_eq!(SandboxProfile::Strict.defaults().read, vec![".".to_string()]);
        // Seatbelt and Landlock give a readable root for free; elsewhere it is
        // spelled out, so the two cases differ by platform, not by profile.
        assert_eq!(
            SandboxProfile::Balanced.defaults().read,
            SandboxProfile::Connected.defaults().read
        );
    }
}
