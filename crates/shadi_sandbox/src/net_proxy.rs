// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Userspace SOCKS5 and HTTP proxy for dynamic DNS-name-based network
//! enforcement.
//!
//! ## Role in the enforcement chain
//!
//! The proxy is **the exit gate** — not optional middleware.  The kernel
//! sandbox (Landlock on Linux, Seatbelt on macOS) is configured to allow
//! outbound TCP to **only** `127.0.0.1:<proxy_port>`.  Every outbound TCP
//! connection the child makes must therefore go through this proxy.
//!
//! ```text
//!  ┌────────────────────────────────────────────────────────────────────┐
//!  │  sandboxed child                                                    │
//!  │                                                                     │
//!  │  ALL_PROXY = socks5h://127.0.0.1:<port>                            │
//!  │                                                                     │
//!  │  app ──SOCKS5 hostname:port──► proxy ──allowlist──► upstream       │
//!  └────────────────────────────────────────────────────────────────────┘
//!         ▲                              ▲
//!  kernel forces all TCP here    DNS name checked here (pre-resolution)
//! ```
//!
//! ## Why SOCKS5 instead of HTTP CONNECT
//!
//! HTTP CONNECT is only used for HTTPS tunnelling.  A plain
//! `curl http://…` with `HTTP_PROXY` set sends a `GET` with an absolute URI
//! — not CONNECT — so an HTTP-CONNECT-only proxy cannot gate it.  SOCKS5 is
//! protocol-agnostic: it tunnels arbitrary TCP regardless of the application
//! layer, making it the correct primitive for a universal enforcement gate.
//!
//! The same listener also speaks HTTP for `HTTP_PROXY`/`HTTPS_PROXY`, since
//! some clients (Python's urllib, `requests` without extras) cannot use a
//! SOCKS5 proxy. It handles `CONNECT` and absolute-URI requests, which both
//! name the destination before DNS, and checks them against the same list.
//! The first byte tells the protocols apart: SOCKS5 starts with `0x05`.
//!
//! 1. The proxy binds to `127.0.0.1:0` (OS picks a port).
//! 2. The kernel sandbox allows outbound TCP solely to `127.0.0.1:<port>`.
//!    Any direct `connect()` to any other address is rejected by the kernel —
//!    even if the process ignores the proxy env vars.  The proxy is the only
//!    exit.
//! 3. The child uses SOCKS5 with `ATYP=0x03` (domain name).  The hostname is
//!    delivered **before DNS resolution**, so the allowlist check operates on
//!    DNS names — not on IPs.
//! 4. When the control socket receives a network policy patch the shared
//!    `NetAllowlist` is updated in-place (`Arc<RwLock<Vec<String>>>`).  The
//!    next connection sees the new policy immediately — no child restart needed.
//!
//! ## Port-pinning constraint
//!
//! The proxy port is compiled into the kernel sandbox rule at child spawn time:
//! - **macOS**: Seatbelt profile contains `(remote tcp "localhost:<port>")` —
//!   immutable for the lifetime of that child process.
//! - **Linux**: Landlock ruleset contains `NetPort::new(<port>, ConnectTcp)` —
//!   same immutability.
//!
//! Consequence: **if the proxy must restart, it must rebind to the same port**.
//! `NetProxy::restart` does this.
//!
//! ## What is and is not covered
//!
//! | Traffic type | Enforcement |
//! |---|---|
//! | TCP via SOCKS5-aware client (curl, reqwest, …) | DNS-name allowlist ✓ |
//! | HTTP(S) via an `http://` proxy client (Python urllib, requests, …) | DNS-name allowlist ✓ |
//! | TCP via raw `connect()` bypassing env vars | Kernel blocks it outright ✓ |
//! | UDP (DNS over UDP, custom protocols) | **Not filtered** — Landlock ConnectTcp / Seatbelt `remote tcp` do not cover UDP |
//!
//! ## Platform notes
//!
//! | Platform | Kernel channel enforcement | DNS-name filtering |
//! |---|---|---|
//! | Linux ≥ 5.19 | Landlock `ConnectTcp` to proxy port | Proxy allowlist ✓ |
//! | macOS | Seatbelt `(remote tcp "localhost:<port>")` | Proxy allowlist ✓ |
//! | Windows | **No unprivileged kernel equivalent** (WFP requires admin); proxy env vars only | Proxy allowlist, bypassable |

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, RwLock};
use std::thread;

use tracing::{debug, warn};

/// Shared, dynamically-updatable allowlist for the proxy.
///
/// An empty list means **all outbound is blocked** (net_block mode).
/// `None` means the proxy is not active (no network filtering via proxy).
#[derive(Clone, Debug)]
pub struct NetAllowlist(Arc<RwLock<Vec<String>>>);

impl NetAllowlist {
    /// Create an allowlist with an initial set of allowed destinations.
    pub fn new(initial: Vec<String>) -> Self {
        Self(Arc::new(RwLock::new(initial)))
    }

    /// Replace the allowlist contents atomically.
    pub fn update(&self, new_list: Vec<String>) {
        if let Ok(mut guard) = self.0.write() {
            *guard = new_list;
        }
    }

    /// Return a snapshot of the current list.
    pub fn snapshot(&self) -> Vec<String> {
        self.0.read().map(|g| g.clone()).unwrap_or_default()
    }

    /// Check whether `host:port` is permitted by the current list.
    ///
    /// An entry with a port (`example.com:443`, `[::1]:443`) allows only that
    /// port; one without allows any. Matching is case-insensitive, and a
    /// single `*` entry allows everything.
    pub fn is_allowed(&self, host: &str, port: u16) -> bool {
        let guard = match self.0.read() {
            Ok(g) => g,
            Err(_) => return false,
        };
        is_host_allowed(host, port, &guard)
    }

    /// Check whether a literal `ip` is permitted by the current list.
    ///
    /// Unlike [`Self::is_allowed`] this also matches an allowlisted hostname
    /// that resolves to `ip`, so it can perform DNS lookups.
    pub fn is_ip_allowed(&self, ip: &str, port: u16) -> bool {
        let guard = match self.0.read() {
            Ok(g) => g,
            Err(_) => return false,
        };
        is_ip_allowed(ip, port, &guard)
    }
}

/// A net-allow entry as the proxy matches it: no scheme or path, lowercase,
/// and its port if it names one. `http://httping.org/` becomes `httping.org`
/// and `HTTPing.org:80` becomes `httping.org:80`.
pub fn normalize_net_allow(dest: &str) -> String {
    let after_scheme = dest.split_once("://").map_or(dest, |(_, rest)| rest);
    let host_port = after_scheme.split('/').next().unwrap_or(after_scheme);
    host_port.trim().to_ascii_lowercase()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryPort {
    Any,
    Only(u16),
    /// A port that doesn't parse: the entry matches nothing.
    Invalid,
}

impl EntryPort {
    fn admits(self, port: u16) -> bool {
        match self {
            Self::Any => true,
            Self::Only(only) => only == port,
            Self::Invalid => false,
        }
    }
}

/// Split an allow-list entry into its host pattern and port.
fn split_entry(entry: &str) -> (&str, EntryPort) {
    let entry = entry.trim();
    let port_of = |tail: &str| match tail.parse() {
        Ok(port) => EntryPort::Only(port),
        Err(_) => EntryPort::Invalid,
    };
    if let Some(rest) = entry.strip_prefix('[') {
        if let Some((host, tail)) = rest.split_once(']') {
            return match tail.strip_prefix(':') {
                Some(port) => (host, port_of(port)),
                None if tail.is_empty() => (host, EntryPort::Any),
                None => (host, EntryPort::Invalid),
            };
        }
    }
    match entry.rsplit_once(':') {
        // A bare IPv6 address has more than one colon and no port.
        Some((host, port)) if !host.contains(':') => (host, port_of(port)),
        _ => (entry, EntryPort::Any),
    }
}

fn is_host_allowed(host: &str, port: u16, list: &[String]) -> bool {
    let host_lc = host.to_ascii_lowercase();
    for pattern in list {
        let (p, entry_port) = split_entry(pattern);
        if !entry_port.admits(port) {
            continue;
        }
        let p = p.to_ascii_lowercase();
        if p == "*" {
            return true;
        }
        // Exact match (covers literal IPs and exact hostnames).
        if p == host_lc {
            return true;
        }
        // Wildcard prefix: *.example.com matches sub.example.com but NOT example.com (apex).
        if let Some(suffix) = p.strip_prefix("*.") {
            if host_lc.ends_with(&format!(".{suffix}")) {
                return true;
            }
        }
    }
    false
}

/// Check whether an IP address (already-resolved by the client) is permitted.
///
/// Called when the SOCKS5 client sends ATYP=0x01/0x04 (the client resolved
/// DNS locally before tunnelling).  The allowlist may contain:
///   - Literal IPs that match directly (handled by `is_host_allowed`).
///   - Hostnames: we resolve each one and accept the IP if it appears in the
///     resolved set.  This makes hostname-based allowlist entries work for
///     all SOCKS5 clients regardless of whether they use remote DNS.
///
/// Note: the DNS lookups happen on the proxy thread serving this connection,
/// so they add latency only when the client sent an IP.  They are not cached;
/// TTL handling is left to the OS resolver.
fn is_ip_allowed(ip_str: &str, port: u16, list: &[String]) -> bool {
    use std::net::ToSocketAddrs;

    // Fast path: literal IP match.
    if is_host_allowed(ip_str, port, list) {
        return true;
    }

    // Parse the incoming IP once.
    let incoming: std::net::IpAddr = match ip_str.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };

    // For each hostname in the allowlist, resolve and compare.
    for pattern in list {
        let (p, entry_port) = split_entry(pattern);
        if !entry_port.admits(port) {
            continue;
        }
        if p == "*" {
            return true;
        }
        // Skip entries that are already IPs — handled by the fast path above.
        if p.parse::<std::net::IpAddr>().is_ok() {
            continue;
        }
        // Skip wildcard patterns — they cannot be resolved to a fixed IP set.
        if p.starts_with("*.") {
            continue;
        }
        // Resolve the hostname.
        if let Ok(addrs) = (p, 0u16).to_socket_addrs() {
            for sock_addr in addrs {
                if sock_addr.ip() == incoming {
                    debug!("net proxy: IP {} matched via DNS resolution of {}", ip_str, p);
                    return true;
                }
            }
        }
    }
    false
}

/// A running proxy instance.  Dropping this struct stops accepting new
/// connections (existing in-flight connections run to completion).
pub struct NetProxy {
    /// The port the proxy is bound to on `127.0.0.1`.
    port: u16,
    /// Signals the accept loop to exit gracefully.
    stop: Arc<std::sync::atomic::AtomicBool>,
    /// Background accept-loop thread.  Kept alive until `Drop` or `restart`.
    thread: thread::JoinHandle<()>,
}

impl NetProxy {
    /// Bind to a random loopback port and start the proxy.
    pub fn start(allowlist: NetAllowlist) -> std::io::Result<Self> {
        Self::bind_and_start(0, allowlist)
    }

    /// Stop the current proxy and restart it **on the same port** with a new
    /// allowlist.
    ///
    /// This is required when the sandboxed child is relaunched on macOS:
    /// the new Seatbelt profile bakes in the proxy port, so the proxy must
    /// rebind to the same port.  We join the accept-loop thread before
    /// rebinding to guarantee the OS releases the port first.
    pub fn restart(self, allowlist: NetAllowlist) -> std::io::Result<Self> {
        use std::mem::ManuallyDrop;
        let port = self.port;
        // Wrap in ManuallyDrop so the normal Drop impl does not run;
        // we signal stop and join the thread ourselves to ensure the
        // TcpListener owned by the thread is dropped (port released)
        // before we try to rebind.
        let this = ManuallyDrop::new(self);
        this.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        // Wake the accept loop out of its blocking accept() call.
        let _ = TcpStream::connect(format!("127.0.0.1:{port}"));
        // Join: after this returns the listen socket is closed and the port
        // is available for SO_REUSEADDR rebind.
        // SAFETY: we own `this` exclusively via ManuallyDrop and never
        // access `thread` again after this read.
        let _ = unsafe { std::ptr::read(&this.thread) }.join();
        // Another test in the same process can bind port 0 in the window
        // between release and rebind and be handed this port (agntcy/shadi#204).
        // Retry a bounded number of times; production restart is not racing
        // other NetProxy::start calls in-process.
        Self::bind_with_retry(port, allowlist)
    }

    fn bind_with_retry(port: u16, allowlist: NetAllowlist) -> std::io::Result<Self> {
        const ATTEMPTS: u32 = 8;
        let mut last_err = None;
        for attempt in 0..ATTEMPTS {
            match Self::bind_and_start(port, allowlist.clone()) {
                Ok(proxy) => return Ok(proxy),
                Err(err) => {
                    last_err = Some(err);
                    thread::sleep(std::time::Duration::from_millis(5 * u64::from(attempt + 1)));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            std::io::Error::other("net proxy restart failed to rebind")
        }))
    }

    fn bind_and_start(port: u16, allowlist: NetAllowlist) -> std::io::Result<Self> {
        let listener = TcpListener::bind(format!("127.0.0.1:{port}"))?;
        let port = listener.local_addr()?.port();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);

        let handle = thread::Builder::new()
            .name("shadi-net-proxy".into())
            .spawn(move || {
                accept_loop(listener, allowlist, stop_clone);
            })?;

        debug!("net proxy listening on 127.0.0.1:{}", port);
        Ok(Self { port, stop, thread: handle })
    }

    /// The TCP port on loopback that the proxy listens on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Build the value to inject as `ALL_PROXY` / `all_proxy`.
    /// SOCKS5 is protocol-agnostic — it gates both HTTP and HTTPS (and any
    /// other TCP protocol) with a single env var, unlike HTTP CONNECT which
    /// only works for HTTPS tunnelling.
    ///
    /// **`socks5h://` not `socks5://`**: the `h` suffix tells curl (and other
    /// SOCKS5-aware clients) to forward the hostname to the proxy for
    /// resolution rather than resolving it locally.  This is essential for
    /// hostname-based allowlist enforcement — with plain `socks5://` the
    /// client resolves the name, sends the raw IP (ATYP=0x01), and the proxy
    /// can only match against IP addresses, breaking `*.example.com` patterns
    /// and any allowlist entry expressed as a hostname.
    pub fn proxy_url(&self) -> String {
        format!("socks5h://127.0.0.1:{}", self.port)
    }

    /// Build the value to inject as `HTTP_PROXY` / `HTTPS_PROXY`: the same
    /// listener, spoken to as an HTTP proxy.
    pub fn http_proxy_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

impl Drop for NetProxy {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        // Wake up the accept loop by connecting to it.
        let _ = TcpStream::connect(format!("127.0.0.1:{}", self.port));
        // Note: we do not join here to avoid blocking Drop callers.
        // The thread will exit shortly after it sees the stop flag.
    }
}

// ---------------------------------------------------------------------------
// Accept loop
// ---------------------------------------------------------------------------

/// Concurrent connection handlers the proxy will run at once.
///
/// One thread per accepted connection is unbounded: anything that can reach
/// the port — the sandboxed process, or any process of the same user — can
/// make the proxy spawn threads and, for IP-mode clients, drive a DNS lookup
/// per allowlist hostname on each one. Past this many the proxy sheds load by
/// closing the connection instead of queuing it, which a SOCKS5 client sees
/// as a failed connect.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 64;

/// Raises the in-flight connection count for as long as it is held.
struct ConnectionPermit(Arc<std::sync::atomic::AtomicUsize>);

impl ConnectionPermit {
    fn acquire(counter: &Arc<std::sync::atomic::AtomicUsize>) -> Self {
        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self(Arc::clone(counter))
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

fn accept_loop(
    listener: TcpListener,
    allowlist: NetAllowlist,
    stop: Arc<std::sync::atomic::AtomicBool>,
) {
    listener.set_nonblocking(false).ok();
    let in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    loop {
        match listener.accept() {
            Ok((stream, _peer)) => {
                if stop.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
                if in_flight.load(std::sync::atomic::Ordering::SeqCst)
                    >= MAX_CONCURRENT_CONNECTIONS
                {
                    warn!(
                        "net proxy: {} connections in flight, shedding",
                        MAX_CONCURRENT_CONNECTIONS
                    );
                    drop(stream);
                    continue;
                }
                let al = allowlist.clone();
                // Held by the handler, so the count falls however the handler
                // ends — including a spawn that never runs it, which drops the
                // closure and the permit with it. A hand-rolled decrement
                // needs a branch per exit and leaks the cap downward if one
                // is missed.
                let permit = ConnectionPermit::acquire(&in_flight);
                thread::Builder::new()
                    .name("shadi-proxy-conn".into())
                    .spawn(move || {
                        let _permit = permit;
                        handle_connection(stream, al);
                    })
                    .ok();
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::ConnectionAborted => continue,
            Err(_) => break,
        }
        if stop.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Per-connection handler (SOCKS5)
// ---------------------------------------------------------------------------
//
// RFC 1928 SOCKS5 handshake:
//   Client → Server: VER=5, NMETHODS=1, METHOD=0 (no-auth)
//   Server → Client: VER=5, METHOD=0
//   Client → Server: VER=5, CMD=1 (CONNECT), RSV=0, ATYP, DST.ADDR, DST.PORT
//     ATYP 0x01 = IPv4 (4 bytes)
//     ATYP 0x03 = domain name (1-byte len + N bytes, pre-resolution)
//     ATYP 0x04 = IPv6 (16 bytes)
//   Server → Client: VER=5, REP, RSV=0, BNDATYP, BND.ADDR, BND.PORT
//     REP 0x00 = success
//     REP 0x02 = not allowed by ruleset
//     REP 0x04 = host unreachable

/// A parsed SOCKS5 CONNECT request. Address allocations are bounded by the
/// RFC 1928 length prefix (at most 255 bytes for a domain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5Connect {
    pub host: String,
    pub port: u16,
    pub is_resolved_ip: bool,
}

/// Why [`parse_socks5_greeting`] or [`parse_socks5_request`] rejected a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks5ParseError {
    Truncated,
    BadVersion,
    NoAcceptableAuth,
    CommandNotSupported,
    BadAddressType,
    InvalidDomain,
}

/// Parse the SOCKS5 greeting (`VER NMETHODS METHODS…`) and accept no-auth.
pub fn parse_socks5_greeting<R: Read>(stream: &mut R) -> Result<(), Socks5ParseError> {
    let mut buf = [0u8; 2];
    stream
        .read_exact(&mut buf)
        .map_err(|_| Socks5ParseError::Truncated)?;
    if buf[0] != 5 {
        return Err(Socks5ParseError::BadVersion);
    }
    let nmethods = buf[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream
        .read_exact(&mut methods)
        .map_err(|_| Socks5ParseError::Truncated)?;
    if !methods.contains(&0x00) {
        return Err(Socks5ParseError::NoAcceptableAuth);
    }
    Ok(())
}

/// Parse a SOCKS5 CONNECT request (`VER CMD RSV ATYP DST.ADDR DST.PORT`).
pub fn parse_socks5_request<R: Read>(stream: &mut R) -> Result<Socks5Connect, Socks5ParseError> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .map_err(|_| Socks5ParseError::Truncated)?;
    if header[0] != 5 || header[1] != 1 {
        return Err(Socks5ParseError::CommandNotSupported);
    }

    let atyp = header[3];
    let (host, is_resolved_ip) = match atyp {
        0x01 => {
            let mut addr = [0u8; 4];
            stream
                .read_exact(&mut addr)
                .map_err(|_| Socks5ParseError::Truncated)?;
            (std::net::Ipv4Addr::from(addr).to_string(), true)
        }
        0x03 => {
            let mut len_byte = [0u8; 1];
            stream
                .read_exact(&mut len_byte)
                .map_err(|_| Socks5ParseError::Truncated)?;
            let mut name = vec![0u8; len_byte[0] as usize];
            stream
                .read_exact(&mut name)
                .map_err(|_| Socks5ParseError::Truncated)?;
            let s = String::from_utf8(name).map_err(|_| Socks5ParseError::InvalidDomain)?;
            (s, false)
        }
        0x04 => {
            let mut addr = [0u8; 16];
            stream
                .read_exact(&mut addr)
                .map_err(|_| Socks5ParseError::Truncated)?;
            (std::net::Ipv6Addr::from(addr).to_string(), true)
        }
        _ => return Err(Socks5ParseError::BadAddressType),
    };

    let mut port_bytes = [0u8; 2];
    stream
        .read_exact(&mut port_bytes)
        .map_err(|_| Socks5ParseError::Truncated)?;
    let port = u16::from_be_bytes(port_bytes);
    Ok(Socks5Connect {
        host,
        port,
        is_resolved_ip,
    })
}

/// Parse a pipelined greeting plus CONNECT request from one buffer.
/// The live proxy still replies to the greeting before reading the request;
/// this helper exists for the `socks5-frame` fuzz target.
pub fn parse_socks5_connect<R: Read>(stream: &mut R) -> Result<Socks5Connect, Socks5ParseError> {
    parse_socks5_greeting(stream)?;
    parse_socks5_request(stream)
}

fn handle_connection(stream: TcpStream, allowlist: NetAllowlist) {
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).ok();
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT)).ok();

    // A SOCKS5 greeting starts with its version byte; an HTTP request with a
    // method name.
    let mut first = [0u8; 1];
    match stream.peek(&mut first) {
        Ok(1) if first[0] == 5 => handle_socks5(stream, allowlist),
        Ok(1) => handle_http(stream, allowlist),
        _ => {}
    }
}

const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Whether `host:port` may be reached, logged either way.
fn admit(allowlist: &NetAllowlist, host: &str, port: u16, is_resolved_ip: bool) -> bool {
    let (allowed, atyp_label) = {
        let guard = allowlist.0.read().unwrap_or_else(|e| e.into_inner());
        if is_resolved_ip {
            (is_ip_allowed(host, port, &guard), "ip")
        } else {
            (is_host_allowed(host, port, &guard), "hostname")
        }
    };
    if allowed {
        debug!("net proxy: ALLOWED {} {}:{}", atyp_label, host, port);
    } else {
        warn!(
            "net proxy: BLOCKED {} {}:{} — not in allowlist",
            atyp_label, host, port
        );
    }
    allowed
}

fn handle_socks5(mut stream: TcpStream, allowlist: NetAllowlist) {
    match parse_socks5_greeting(&mut stream) {
        Ok(()) => {
            if stream.write_all(&[5, 0x00]).is_err() || stream.flush().is_err() {
                return;
            }
        }
        Err(Socks5ParseError::NoAcceptableAuth) => {
            let _ = stream.write_all(&[5, 0xFF]);
            return;
        }
        Err(_) => return,
    }

    let request = match parse_socks5_request(&mut stream) {
        Ok(request) => request,
        Err(Socks5ParseError::CommandNotSupported) => {
            let _ = stream.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
            return;
        }
        Err(_) => return,
    };

    let host = request.host;
    let port = request.port;
    let is_resolved_ip = request.is_resolved_ip;

    // --- Policy check ---
    if !admit(&allowlist, &host, port, is_resolved_ip) {
        // REP=0x02 (connection not allowed by ruleset)
        let _ = stream.write_all(&[5, 2, 0, 1, 0, 0, 0, 0, 0, 0]);
        return;
    }

    // --- Connect upstream ---
    let upstream = match TcpStream::connect((&*host, port)) {
        Ok(s) => s,
        Err(e) => {
            warn!("net proxy: upstream connect to {}:{} failed: {}", host, port, e);
            // REP=0x04 (host unreachable)
            let _ = stream.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]);
            return;
        }
    };

    // --- Success reply ---
    // BND.ADDR = 0.0.0.0, BND.PORT = 0 (we don't expose our local bind address)
    if stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).is_err() || stream.flush().is_err() {
        return;
    }

    debug!("net proxy: tunnel open to {}:{}", host, port);
    pipe_bidirectional(stream, upstream);
}

// ---------------------------------------------------------------------------
// Per-connection handler (HTTP)
// ---------------------------------------------------------------------------
//
// `HTTP_PROXY`/`HTTPS_PROXY` point here, because clients such as Python's
// urllib speak `http://` proxies but not SOCKS5 (agntcy/shadi#431). Both forms
// name the destination before DNS, so they are checked like a SOCKS5 request:
//   CONNECT host:port HTTP/1.1      → tunnel, as SOCKS5 does
//   GET http://host[:port]/path …   → forward that one request, then close

/// Largest HTTP request head the proxy reads before refusing the request.
pub const MAX_HTTP_HEAD: usize = 16 * 1024;

/// A parsed HTTP proxy request head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpProxyRequest {
    pub host: String,
    pub port: u16,
    /// The head to send upstream, rewritten to origin form with
    /// `Connection: close`, or `None` for a `CONNECT` tunnel.
    pub forward: Option<Vec<u8>>,
}

/// Why [`parse_http_proxy_request`] rejected a request head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpParseError {
    Malformed,
    UnsupportedScheme,
}

/// Headers that apply to the hop to the proxy and are not forwarded, along
/// with every `Proxy-*` header.
const HOP_HEADERS: &[&str] = &["host", "connection", "keep-alive"];

/// Parse an HTTP proxy request head, up to and including its blank line.
pub fn parse_http_proxy_request(head: &[u8]) -> Result<HttpProxyRequest, HttpParseError> {
    let head = std::str::from_utf8(head).map_err(|_| HttpParseError::Malformed)?;
    let head = head.strip_suffix("\r\n\r\n").unwrap_or(head);
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(HttpParseError::Malformed)?;
    let headers: Vec<&str> = lines.collect();
    if [request_line]
        .iter()
        .chain(&headers)
        .any(|l| l.is_empty() || l.contains(['\r', '\n', '\0']))
    {
        return Err(HttpParseError::Malformed);
    }
    let bad_name = |h: &&str| {
        h.split_once(':')
            .is_none_or(|(n, _)| n.is_empty() || n.contains([' ', '\t']))
    };
    if headers.iter().any(bad_name) {
        return Err(HttpParseError::Malformed);
    }

    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(HttpParseError::Malformed);
    };
    if method.is_empty() || !version.starts_with("HTTP/1.") {
        return Err(HttpParseError::Malformed);
    }

    if method == "CONNECT" {
        let (host, port) = split_authority(target, None)?;
        return Ok(HttpProxyRequest {
            host,
            port,
            forward: None,
        });
    }

    let Some((scheme, rest)) = target.split_once("://") else {
        return Err(HttpParseError::Malformed);
    };
    if !scheme.eq_ignore_ascii_case("http") {
        return Err(HttpParseError::UnsupportedScheme);
    }
    let path_at = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(path_at);
    let (host, port) = split_authority(authority, Some(80))?;
    let path = match path.split('#').next().unwrap_or("") {
        "" => "/".to_string(),
        p if p.starts_with('?') => format!("/{p}"),
        p => p.to_string(),
    };

    let mut forward = format!("{method} {path} {version}\r\nHost: {authority}\r\n");
    for header in headers {
        let name = header.split(':').next().unwrap_or("").to_ascii_lowercase();
        if !HOP_HEADERS.contains(&name.as_str()) && !name.starts_with("proxy-") {
            forward.push_str(header);
            forward.push_str("\r\n");
        }
    }
    forward.push_str("Connection: close\r\n\r\n");
    Ok(HttpProxyRequest {
        host,
        port,
        forward: Some(forward.into_bytes()),
    })
}

/// Split `host:port`, `[v6]:port` or, with a default port, a bare host.
fn split_authority(
    authority: &str,
    default_port: Option<u16>,
) -> Result<(String, u16), HttpParseError> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']').ok_or(HttpParseError::Malformed)?;
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(HttpParseError::Malformed);
        }
        let port = match after {
            "" => None,
            after => Some(after.strip_prefix(':').ok_or(HttpParseError::Malformed)?),
        };
        (host, port)
    } else {
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        };
        let hostname_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_');
        if host.is_empty() || !host.chars().all(hostname_char) {
            return Err(HttpParseError::Malformed);
        }
        (host, port)
    };
    let port = match port {
        Some(p) => p.parse::<u16>().map_err(|_| HttpParseError::Malformed)?,
        None => default_port.ok_or(HttpParseError::Malformed)?,
    };
    Ok((host.to_string(), port))
}

/// Read up to the end of the request head; returns the head and any bytes
/// the client sent after it.
fn read_http_head(stream: &mut TcpStream) -> Option<(Vec<u8>, Vec<u8>)> {
    let started = std::time::Instant::now();
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while started.elapsed() < HANDSHAKE_TIMEOUT {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        let searched = buf.len().saturating_sub(3);
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf[searched..].windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(searched + i + 4);
            return Some((buf, rest));
        }
        if buf.len() > MAX_HTTP_HEAD {
            return None;
        }
    }
    None
}

fn http_reply(stream: &mut TcpStream, status: &str, body: &str) {
    let reply = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(reply.as_bytes());
}

fn handle_http(mut stream: TcpStream, allowlist: NetAllowlist) {
    let Some((head, rest)) = read_http_head(&mut stream) else {
        http_reply(&mut stream, "400 Bad Request", "");
        return;
    };
    let request = match parse_http_proxy_request(&head) {
        Ok(request) => request,
        Err(_) => {
            http_reply(&mut stream, "400 Bad Request", "");
            return;
        }
    };
    let (host, port) = (request.host, request.port);

    let is_resolved_ip = host.parse::<std::net::IpAddr>().is_ok();
    if !admit(&allowlist, &host, port, is_resolved_ip) {
        let body = format!("{host}:{port} is not in the sandbox's net_allow list\n");
        http_reply(&mut stream, "403 Forbidden", &body);
        return;
    }

    let mut upstream = match TcpStream::connect((&*host, port)) {
        Ok(s) => s,
        Err(e) => {
            warn!(
                "net proxy: upstream connect to {}:{} failed: {}",
                host, port, e
            );
            http_reply(&mut stream, "502 Bad Gateway", "");
            return;
        }
    };
    let sent = match &request.forward {
        Some(forward) => upstream.write_all(forward),
        None => stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n"),
    };
    if sent.is_err() || upstream.write_all(&rest).is_err() {
        return;
    }

    debug!("net proxy: http tunnel open to {}:{}", host, port);
    pipe_bidirectional(stream, upstream);
}

// ---------------------------------------------------------------------------
// Bidirectional byte copy
// ---------------------------------------------------------------------------

fn pipe_bidirectional(client: TcpStream, upstream: TcpStream) {
    // Clear the handshake-phase timeouts before entering relay mode.
    // Streaming responses (SSE) can be idle for arbitrarily long between
    // tokens; a hard deadline here would kill long-running completions.
    client.set_read_timeout(None).ok();
    client.set_write_timeout(None).ok();
    upstream.set_read_timeout(None).ok();
    upstream.set_write_timeout(None).ok();

    // Two threads: client→upstream and upstream→client.
    let client2 = client.try_clone().unwrap_or_else(|_| return_dummy());
    let upstream2 = upstream.try_clone().unwrap_or_else(|_| return_dummy());

    let t1 = thread::Builder::new()
        .name("shadi-proxy-up".into())
        .spawn(move || copy_stream(client, upstream));

    copy_stream(upstream2, client2);
    if let Ok(handle) = t1 {
        let _ = handle.join();
    }
}

fn copy_stream(mut from: TcpStream, mut to: TcpStream) {
    let mut buf = [0u8; 8192];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() || to.flush().is_err() {
                    break;
                }
            }
        }
    }
    let _ = to.shutdown(std::net::Shutdown::Write);
}

// Dummy TcpStream for the `unwrap_or_else` fallback; this path is unreachable
// in practice because `try_clone` only fails if the OS is out of fd handles.
fn return_dummy() -> TcpStream {
    // A loopback connection to ourselves; caller immediately drops it on error.
    TcpStream::connect("127.0.0.1:1").unwrap_or_else(|_| {
        panic!("failed to clone TcpStream and could not create dummy");
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {

    static PORT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock_proxy_ports() -> std::sync::MutexGuard<'static, ()> {
        PORT_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    use super::*;

    #[test]
    fn is_host_allowed_exact() {
        assert!(is_host_allowed(
            "api.openai.com",
            443,
            &["api.openai.com".into()]
        ));
        assert!(!is_host_allowed(
            "evil.com",
            443,
            &["api.openai.com".into()]
        ));
    }

    #[test]
    fn is_host_allowed_wildcard_prefix() {
        let list = vec!["*.openai.com".into()];
        assert!(is_host_allowed("api.openai.com", 443, &list));
        assert!(is_host_allowed("chat.openai.com", 443, &list));
        assert!(!is_host_allowed("openai.com", 443, &list)); // apex excluded
        assert!(!is_host_allowed("evilopenai.com", 443, &list));
    }

    #[test]
    fn is_host_allowed_star_allows_all() {
        let list = vec!["*".into()];
        assert!(is_host_allowed("anything.example.com", 443, &list));
    }

    #[test]
    fn is_host_allowed_case_insensitive() {
        let list = vec!["API.OpenAI.com".into()];
        assert!(is_host_allowed("api.openai.com", 443, &list));
    }

    #[test]
    fn is_host_allowed_empty_list_blocks_all() {
        assert!(!is_host_allowed("api.openai.com", 443, &[]));
        assert!(!NetAllowlist::new(vec![]).is_allowed("api.openai.com", 443));
    }

    fn socks5_ipv4_frame(ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut frame = vec![5, 1, 0, 5, 1, 0, 1];
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&port.to_be_bytes());
        frame
    }

    fn socks5_domain_frame(host: &str, port: u16) -> Vec<u8> {
        let name = host.as_bytes();
        let mut frame = vec![5, 1, 0, 5, 1, 0, 3, name.len() as u8];
        frame.extend_from_slice(name);
        frame.extend_from_slice(&port.to_be_bytes());
        frame
    }

    fn socks5_ipv6_frame(ip: [u8; 16], port: u16) -> Vec<u8> {
        let mut frame = vec![5, 1, 0, 5, 1, 0, 4];
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&port.to_be_bytes());
        frame
    }

    #[test]
    fn parse_socks5_connect_reads_ipv6() {
        let mut loopback = [0u8; 16];
        loopback[15] = 1;
        let mut frame = std::io::Cursor::new(socks5_ipv6_frame(loopback, 8443));
        let parsed = parse_socks5_connect(&mut frame).expect("ipv6");
        assert_eq!(
            parsed,
            Socks5Connect {
                host: "::1".into(),
                port: 8443,
                is_resolved_ip: true,
            }
        );

        // A frame that stops inside the 16-byte address is truncated, not a
        // short address padded with zeroes.
        assert_eq!(
            parse_socks5_connect(&mut std::io::Cursor::new([5u8, 1, 0, 5, 1, 0, 4, 0, 0])),
            Err(Socks5ParseError::Truncated)
        );
    }

    #[test]
    fn parse_socks5_connect_reads_ipv4_and_domain() {
        let mut ipv4 = std::io::Cursor::new(socks5_ipv4_frame([127, 0, 0, 1], 443));
        let parsed = parse_socks5_connect(&mut ipv4).expect("ipv4");
        assert_eq!(
            parsed,
            Socks5Connect {
                host: "127.0.0.1".into(),
                port: 443,
                is_resolved_ip: true,
            }
        );

        let mut domain = std::io::Cursor::new(socks5_domain_frame("api.openai.com", 80));
        let parsed = parse_socks5_connect(&mut domain).expect("domain");
        assert_eq!(
            parsed,
            Socks5Connect {
                host: "api.openai.com".into(),
                port: 80,
                is_resolved_ip: false,
            }
        );
    }

    #[test]
    fn parse_socks5_connect_rejects_truncated_and_invalid_frames() {
        assert_eq!(
            parse_socks5_connect(&mut std::io::Cursor::new([5u8, 1])),
            Err(Socks5ParseError::Truncated)
        );
        assert_eq!(
            parse_socks5_connect(&mut std::io::Cursor::new([4u8, 1, 0])),
            Err(Socks5ParseError::BadVersion)
        );
        assert_eq!(
            parse_socks5_connect(&mut std::io::Cursor::new([5u8, 1, 0x02])),
            Err(Socks5ParseError::NoAcceptableAuth)
        );
        assert_eq!(
            parse_socks5_connect(&mut std::io::Cursor::new([5u8, 1, 0, 5, 2, 0, 1])),
            Err(Socks5ParseError::CommandNotSupported)
        );
        assert_eq!(
            parse_socks5_connect(&mut std::io::Cursor::new([5u8, 1, 0, 5, 1, 0, 0x05])),
            Err(Socks5ParseError::BadAddressType)
        );
        assert_eq!(
            parse_socks5_connect(&mut std::io::Cursor::new([
                5, 1, 0, 5, 1, 0, 3, 2, 0xff, 0xfe, 0, 80
            ])),
            Err(Socks5ParseError::InvalidDomain)
        );
    }

    #[test]
    fn net_allowlist_update_is_visible() {
        let al = NetAllowlist::new(vec!["a.example.com".into()]);
        assert!(al.is_allowed("a.example.com", 443));
        assert!(!al.is_allowed("b.example.com", 443));
        al.update(vec!["b.example.com".into()]);
        assert!(!al.is_allowed("a.example.com", 443));
        assert!(al.is_allowed("b.example.com", 443));
    }

    /// Do a SOCKS5 no-auth handshake + CONNECT to host:port.
    /// Returns the negotiated stream ready for tunnelled bytes.
    fn socks5_connect(proxy_port: u16, host: &str, port: u16) -> std::io::Result<std::net::TcpStream> {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect(format!("127.0.0.1:{proxy_port}"))?;
        s.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();
        // Auth negotiation: VER=5 NMETHODS=1 METHOD=0x00
        s.write_all(&[5, 1, 0])?;
        s.flush()?;
        let mut resp = [0u8; 2];
        s.read_exact(&mut resp)?;
        assert_eq!(resp, [5, 0], "unexpected auth response");
        // Request: VER=5 CMD=1(CONNECT) RSV=0 ATYP=0x03 len name port
        let name = host.as_bytes();
        let mut req = vec![5u8, 1, 0, 3, name.len() as u8];
        req.extend_from_slice(name);
        req.extend_from_slice(&port.to_be_bytes());
        s.write_all(&req)?;
        s.flush()?;
        // Read 10-byte reply
        let mut reply = [0u8; 10];
        s.read_exact(&mut reply)?;
        assert_eq!(reply[0], 5, "unexpected SOCKS5 version in reply");
        Ok(s)
    }

    #[test]
    fn proxy_blocks_host_not_in_allowlist() {
        let _guard = lock_proxy_ports();
        let al = NetAllowlist::new(vec![]);  // block everything
        let proxy = NetProxy::start(al).unwrap();

        let mut s = std::net::TcpStream::connect(format!("127.0.0.1:{}", proxy.port())).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();
        // Send SOCKS5 negotiation
        s.write_all(&[5, 1, 0]).unwrap();
        s.flush().unwrap();
        let mut auth = [0u8; 2];
        s.read_exact(&mut auth).unwrap();
        assert_eq!(auth, [5, 0]);
        // CONNECT evil.example.com:443
        let name = b"evil.example.com";
        let mut req = vec![5u8, 1, 0, 3, name.len() as u8];
        req.extend_from_slice(name);
        req.extend_from_slice(&443u16.to_be_bytes());
        s.write_all(&req).unwrap();
        s.flush().unwrap();
        let mut reply = [0u8; 10];
        s.read_exact(&mut reply).unwrap();
        assert_eq!(reply[0], 5, "SOCKS5 version");
        assert_eq!(reply[1], 2, "expected REP=0x02 (not allowed by ruleset)");
    }

    #[test]
    fn proxy_allows_host_in_allowlist() {
        use std::io::{Read, Write};

        // Start a dummy TCP echo server as the "upstream".
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = upstream.accept() {
                let _ = s.write_all(b"hello");
            }
        });

        // Binds an ephemeral port like the restart test, so it has to take
        // the same lock: this is the sibling that can be handed the port
        // restart just released (agntcy/shadi#204).
        let _guard = lock_proxy_ports();
        let al = NetAllowlist::new(vec!["127.0.0.1".into()]);
        let proxy = NetProxy::start(al).unwrap();

        let mut tunnel = socks5_connect(proxy.port(), "127.0.0.1", upstream_port).unwrap();
        let mut buf = [0u8; 5];
        tunnel.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello");
    }

    /// The exact case of agntcy/shadi#430: `--net-allow example.com:443` must
    /// allow example.com on 443, and only there.
    #[test]
    fn a_port_in_an_entry_allows_only_that_port() {
        let list: Vec<String> = vec![
            "example.com:443".into(),
            "*.api.example.com:8443".into(),
            "[::1]:9000".into(),
            "*:22".into(),
        ];
        assert!(is_host_allowed("example.com", 443, &list));
        assert!(!is_host_allowed("example.com", 80, &list));
        assert!(is_host_allowed("v1.api.example.com", 8443, &list));
        assert!(!is_host_allowed("v1.api.example.com", 443, &list));
        assert!(is_host_allowed("::1", 9000, &list));
        assert!(!is_host_allowed("::1", 9001, &list));
        assert!(is_host_allowed("anything.example.org", 22, &list));
        assert!(!is_host_allowed("anything.example.org", 23, &list));

        // Without a port, an entry allows every port.
        let any: Vec<String> = vec!["example.com".into(), "::1".into(), "[2001:db8::1]".into()];
        for port in [1, 443, 65535] {
            assert!(is_host_allowed("example.com", port, &any));
            assert!(is_host_allowed("::1", port, &any));
            assert!(is_host_allowed("2001:db8::1", port, &any));
        }
    }

    #[test]
    fn an_entry_whose_port_does_not_parse_matches_nothing() {
        let list: Vec<String> = vec![
            "example.com:https".into(),
            "example.com:70000".into(),
            "[::1]:x".into(),
            "[::1]junk".into(),
        ];
        for port in [80, 443] {
            assert!(!is_host_allowed("example.com", port, &list));
            assert!(!is_host_allowed("::1", port, &list));
        }
    }

    #[test]
    fn normalize_net_allow_keeps_the_port_and_drops_scheme_and_path() {
        for (raw, normalized) in [
            ("httping.org", "httping.org"),
            ("http://httping.org/", "httping.org"),
            ("https://httping.org/ping?v=1", "httping.org"),
            ("HTTPing.ORG:80", "httping.org:80"),
            ("https://example.com:8443/path", "example.com:8443"),
            ("[::1]:443", "[::1]:443"),
            (" 192.0.2.1 ", "192.0.2.1"),
        ] {
            assert_eq!(normalize_net_allow(raw), normalized, "{raw}");
        }
    }

    fn socks5_reply_code(proxy_port: u16, host: &str, port: u16) -> u8 {
        let mut s = std::net::TcpStream::connect(format!("127.0.0.1:{proxy_port}")).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .ok();
        s.write_all(&[5, 1, 0]).unwrap();
        let mut auth = [0u8; 2];
        s.read_exact(&mut auth).unwrap();
        let mut req = vec![5u8, 1, 0, 3, host.len() as u8];
        req.extend_from_slice(host.as_bytes());
        req.extend_from_slice(&port.to_be_bytes());
        s.write_all(&req).unwrap();
        let mut reply = [0u8; 10];
        s.read_exact(&mut reply).unwrap();
        reply[1]
    }

    #[test]
    fn the_proxy_enforces_the_port_in_an_entry() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in upstream.incoming().flatten() {
                drop(stream);
            }
        });

        let _guard = lock_proxy_ports();
        let other_port = upstream_port.wrapping_add(1).max(1);
        let al = NetAllowlist::new(vec![format!("127.0.0.1:{upstream_port}")]);
        let proxy = NetProxy::start(al).unwrap();

        assert_eq!(
            socks5_reply_code(proxy.port(), "127.0.0.1", upstream_port),
            0
        );
        assert_eq!(
            socks5_reply_code(proxy.port(), "127.0.0.1", other_port),
            2,
            "a port the entry doesn't name must be refused"
        );
    }

    #[test]
    fn is_ip_allowed_matches_literals_and_denies_by_default() {
        // Only literal IPs and `*` here: a hostname pattern would send
        // is_ip_allowed to the resolver, and a unit test must not do DNS.
        let empty = NetAllowlist::new(vec![]);
        assert!(
            !empty.is_ip_allowed("127.0.0.1", 443),
            "empty list is deny-all"
        );
        assert!(!empty.is_ip_allowed("not-an-ip", 443));

        let literal = NetAllowlist::new(vec!["127.0.0.1".into(), "10.0.0.7".into()]);
        assert!(literal.is_ip_allowed("127.0.0.1", 443));
        assert!(literal.is_ip_allowed("10.0.0.7", 443));
        assert!(!literal.is_ip_allowed("10.0.0.8", 443));

        // `*` short-circuits before the address is parsed, so it allows even
        // a value that is not an address.
        let open = NetAllowlist::new(vec!["*".into()]);
        assert!(open.is_ip_allowed("127.0.0.1", 443));
        assert!(open.is_ip_allowed("not-an-ip", 443));

        // A `*.` pattern cannot be resolved to a fixed address, so it never
        // matches an IP on its own.
        let wildcard = NetAllowlist::new(vec!["*.example.com".into()]);
        assert!(!wildcard.is_ip_allowed("127.0.0.1", 443));
    }

    #[test]
    fn is_ip_allowed_denies_when_the_lock_is_poisoned() {
        // A poisoned allowlist must fail closed, like is_allowed does: a
        // panic while the list was held cannot become permission to connect.
        let list = NetAllowlist::new(vec!["127.0.0.1".into()]);
        assert!(
            list.is_ip_allowed("127.0.0.1", 443),
            "sanity before poisoning"
        );

        let poisoner = list.clone();
        let _ = std::thread::spawn(move || {
            let _held = poisoner.0.write().unwrap();
            panic!("poison the allowlist lock");
        })
        .join();

        assert!(
            list.0.read().is_err(),
            "the lock should be poisoned for this test to mean anything"
        );
        assert!(
            !list.is_ip_allowed("127.0.0.1", 443),
            "a poisoned allowlist allowed a connection"
        );
    }

    #[test]
    fn is_ip_allowed_accepts_ipv6_literals() {
        let list = NetAllowlist::new(vec!["::1".into()]);
        assert!(list.is_ip_allowed("::1", 443));
        assert!(!list.is_ip_allowed("::2", 443));
    }

    #[test]
    fn proxy_sheds_load_past_the_concurrency_cap() {
        let _guard = lock_proxy_ports();
        // Deny everything: handle_connection still reads the greeting, so each
        // held connection occupies a handler thread without needing upstream.
        let proxy = NetProxy::start(NetAllowlist::new(vec![])).unwrap();
        let port = proxy.port();

        // Open the cap's worth of connections and leave them mid-handshake,
        // so every handler thread is parked on a read.
        let mut held = Vec::new();
        for i in 0..MAX_CONCURRENT_CONNECTIONS {
            let conn = std::net::TcpStream::connect(format!("127.0.0.1:{port}"))
                .unwrap_or_else(|e| panic!("proxy refused connection {i} below its own cap: {e}"));
            held.push(conn);
        }

        // Give the accept loop time to spawn a handler for each.
        std::thread::sleep(std::time::Duration::from_millis(200));

        // One more: the proxy accepts the TCP connection (the listener backlog
        // does that) and then closes it without a SOCKS5 reply. A client sees
        // EOF rather than a greeting response.
        let mut extra = std::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .expect("listener still accepts");
        extra.write_all(&[5, 1, 0]).ok();
        extra
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .ok();
        let mut reply = [0u8; 2];
        let read = extra.read(&mut reply);
        assert!(
            matches!(read, Ok(0)) || read.is_err(),
            "a shed connection answered the greeting: {read:?}"
        );

        drop(held);
    }

    #[test]
    fn proxy_restart_rebinds_to_same_port() {
        // Serialize against other tests that bind port 0 so the OS cannot
        // hand this proxy's just-released port to a sibling NetProxy::start
        // (agntcy/shadi#204).
        let _guard = lock_proxy_ports();

        // Start proxy, record port, restart it, verify the new proxy answers
        // on the same port — the macOS Seatbelt constraint.
        let al = NetAllowlist::new(vec![]);
        let proxy = NetProxy::start(al.clone()).unwrap();
        let original_port = proxy.port();

        let proxy2 = proxy.restart(al).unwrap();
        assert_eq!(proxy2.port(), original_port, "restart must reuse the same port");

        // New proxy must actually accept connections on that port.
        let conn = std::net::TcpStream::connect(format!("127.0.0.1:{original_port}"));
        assert!(conn.is_ok(), "restarted proxy not accepting on port {original_port}");
    }

    #[test]
    fn bind_with_retry_fails_when_port_held() {
        let _guard = lock_proxy_ports();
        let holder = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = holder.local_addr().unwrap().port();
        let err = match NetProxy::bind_with_retry(port, NetAllowlist::new(vec![])) {
            Ok(_) => panic!("held port must not rebind"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
        drop(holder);
    }

    #[test]
    fn parse_http_proxy_request_reads_connect() {
        let request = parse_http_proxy_request(
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            (request.host.as_str(), request.port, request.forward),
            ("example.com", 443, None)
        );

        let request = parse_http_proxy_request(b"CONNECT [::1]:8443 HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!((request.host.as_str(), request.port), ("::1", 8443));

        assert_eq!(
            parse_http_proxy_request(b"CONNECT example.com HTTP/1.1\r\n\r\n"),
            Err(HttpParseError::Malformed),
            "CONNECT must name a port"
        );
    }

    #[test]
    fn parse_http_proxy_request_rewrites_an_absolute_uri() {
        let head = b"GET http://Example.com:8080/a?b HTTP/1.1\r\n\
            Host: evil.example\r\n\
            Proxy-Connection: keep-alive\r\n\
            Proxy-Authorization: Basic eDp5\r\n\
            Connection: keep-alive\r\n\
            Accept: */*\r\n\r\n";
        let request = parse_http_proxy_request(head).unwrap();
        assert_eq!((request.host.as_str(), request.port), ("Example.com", 8080));
        assert_eq!(
            String::from_utf8(request.forward.unwrap()).unwrap(),
            "GET /a?b HTTP/1.1\r\nHost: Example.com:8080\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );

        let forward_of = |head: &[u8]| {
            String::from_utf8(parse_http_proxy_request(head).unwrap().forward.unwrap()).unwrap()
        };
        assert!(forward_of(b"GET http://example.com HTTP/1.1\r\n\r\n")
            .starts_with("GET / HTTP/1.1\r\nHost: example.com\r\n"));
        assert!(forward_of(b"HEAD http://example.com?q=1 HTTP/1.0\r\n\r\n")
            .starts_with("HEAD /?q=1 HTTP/1.0\r\n"));
        assert_eq!(
            parse_http_proxy_request(b"GET http://example.com/ HTTP/1.1\r\n\r\n")
                .unwrap()
                .port,
            80
        );
    }

    #[test]
    fn parse_http_proxy_request_rejects_bad_heads() {
        for (head, want) in [
            (&b"GET / HTTP/1.1\r\n\r\n"[..], HttpParseError::Malformed),
            (
                b"GET https://example.com/ HTTP/1.1\r\n\r\n",
                HttpParseError::UnsupportedScheme,
            ),
            (
                b"GET http://user@evil.example/ HTTP/1.1\r\n\r\n",
                HttpParseError::Malformed,
            ),
            (
                b"GET http://example.com:http/ HTTP/1.1\r\n\r\n",
                HttpParseError::Malformed,
            ),
            (
                b"GET http://example.com/ SPDY/3\r\n\r\n",
                HttpParseError::Malformed,
            ),
            (
                b"GET http://example.com/ HTTP/1.1 extra\r\n\r\n",
                HttpParseError::Malformed,
            ),
            (
                b"GET http://example.com/ HTTP/1.1\r\nno-colon\r\n\r\n",
                HttpParseError::Malformed,
            ),
            (
                b"GET http://example.com/ HTTP/1.1\r\nHost : evil.example\r\n\r\n",
                HttpParseError::Malformed,
            ),
            (
                b"GET http://example.com/ HTTP/1.1\r\nX: a\nHost: evil.example\r\n\r\n",
                HttpParseError::Malformed,
            ),
            (
                b"CONNECT [not-v6]:443 HTTP/1.1\r\n\r\n",
                HttpParseError::Malformed,
            ),
            (
                b"CONNECT [::1]443 HTTP/1.1\r\n\r\n",
                HttpParseError::Malformed,
            ),
            (b"\xff\xfe HTTP/1.1\r\n\r\n", HttpParseError::Malformed),
        ] {
            assert_eq!(
                parse_http_proxy_request(head),
                Err(want),
                "{:?}",
                String::from_utf8_lossy(head)
            );
        }
    }

    /// Answers each request with the request line it received as the body.
    fn echo_request_line_server() -> u16 {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = upstream.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for mut stream in upstream.incoming().flatten() {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
                    head.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&head);
                let line = head.lines().next().unwrap_or("");
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{line}",
                    line.len()
                );
                let _ = stream.write_all(reply.as_bytes());
            }
        });
        port
    }

    fn http_exchange(stream: &mut std::net::TcpStream, request: &str) -> String {
        stream.write_all(request.as_bytes()).unwrap();
        let mut reply = Vec::new();
        let _ = stream.read_to_end(&mut reply);
        String::from_utf8_lossy(&reply).into_owned()
    }

    fn proxy_client(proxy_port: u16) -> std::net::TcpStream {
        let s = std::net::TcpStream::connect(format!("127.0.0.1:{proxy_port}")).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .ok();
        s
    }

    #[test]
    fn the_http_proxy_tunnels_connect_and_forwards_absolute_uris() {
        let upstream_port = echo_request_line_server();
        let _guard = lock_proxy_ports();
        let other_port = upstream_port.wrapping_add(1).max(1);
        let proxy = NetProxy::start(NetAllowlist::new(vec![format!(
            "127.0.0.1:{upstream_port}"
        )]))
        .unwrap();

        let mut s = proxy_client(proxy.port());
        s.write_all(format!("CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\n\r\n").as_bytes())
            .unwrap();
        let mut established = [0u8; 39];
        s.read_exact(&mut established).unwrap();
        assert_eq!(&established, b"HTTP/1.1 200 Connection Established\r\n\r\n");
        let reply = http_exchange(&mut s, "GET /through-the-tunnel HTTP/1.1\r\n\r\n");
        assert!(
            reply.ends_with("GET /through-the-tunnel HTTP/1.1"),
            "{reply}"
        );

        let reply = http_exchange(
            &mut proxy_client(proxy.port()),
            &format!("GET http://127.0.0.1:{upstream_port}/forwarded HTTP/1.1\r\nProxy-Connection: keep-alive\r\n\r\n"),
        );
        assert!(reply.ends_with("GET /forwarded HTTP/1.1"), "{reply}");

        for request in [
            format!("CONNECT 127.0.0.1:{other_port} HTTP/1.1\r\n\r\n"),
            format!("GET http://127.0.0.1:{other_port}/ HTTP/1.1\r\n\r\n"),
        ] {
            let reply = http_exchange(&mut proxy_client(proxy.port()), &request);
            assert!(
                reply.starts_with("HTTP/1.1 403 "),
                "{request:?} got {reply}"
            );
        }
        let reply = http_exchange(&mut proxy_client(proxy.port()), "GET / HTTP/1.1\r\n\r\n");
        assert!(reply.starts_with("HTTP/1.1 400 "), "{reply}");
    }
}
