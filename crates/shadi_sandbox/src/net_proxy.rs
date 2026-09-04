// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Userspace SOCKS5 proxy for dynamic DNS-name-based network enforcement.
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
//! | TCP via SOCKS5-aware client (curl, reqwest, Python requests, …) | DNS-name allowlist ✓ |
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

    /// Check whether `host` (without port) is permitted by the current list.
    ///
    /// Matching is case-insensitive.  A single `*` entry allows everything.
    pub fn is_allowed(&self, host: &str) -> bool {
        let guard = match self.0.read() {
            Ok(g) => g,
            Err(_) => return false,
        };
        is_host_allowed(host, &guard)
    }
}

fn is_host_allowed(host: &str, list: &[String]) -> bool {
    let host_lc = host.to_ascii_lowercase();
    for pattern in list {
        let p = pattern.trim().to_ascii_lowercase();
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
fn is_ip_allowed(ip_str: &str, list: &[String]) -> bool {
    use std::net::ToSocketAddrs;

    // Fast path: literal IP match.
    if is_host_allowed(ip_str, list) {
        return true;
    }

    // Parse the incoming IP once.
    let incoming: std::net::IpAddr = match ip_str.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };

    // For each hostname in the allowlist, resolve and compare.
    for pattern in list {
        let p = pattern.trim();
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

fn accept_loop(
    listener: TcpListener,
    allowlist: NetAllowlist,
    stop: Arc<std::sync::atomic::AtomicBool>,
) {
    listener.set_nonblocking(false).ok();
    loop {
        match listener.accept() {
            Ok((stream, _peer)) => {
                if stop.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
                let al = allowlist.clone();
                thread::Builder::new()
                    .name("shadi-proxy-conn".into())
                    .spawn(move || handle_connection(stream, al))
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

fn handle_connection(mut stream: TcpStream, allowlist: NetAllowlist) {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30))).ok();
    stream.set_write_timeout(Some(std::time::Duration::from_secs(30))).ok();

    // --- Auth negotiation ---
    // Read: VER NMETHODS METHOD...
    let mut buf = [0u8; 2];
    if stream.read_exact(&mut buf).is_err() || buf[0] != 5 {
        return;
    }
    let nmethods = buf[1] as usize;
    let mut methods = vec![0u8; nmethods];
    if stream.read_exact(&mut methods).is_err() {
        return;
    }
    // Accept only no-auth (0x00).  Reject everything else.
    if !methods.contains(&0x00) {
        let _ = stream.write_all(&[5, 0xFF]); // no acceptable method
        return;
    }
    if stream.write_all(&[5, 0x00]).is_err() || stream.flush().is_err() {
        return;
    }

    // --- Request ---
    let mut header = [0u8; 4]; // VER CMD RSV ATYP
    if stream.read_exact(&mut header).is_err() {
        return;
    }
    if header[0] != 5 || header[1] != 1 /* CONNECT */ {
        // CMD_NOT_SUPPORTED
        let _ = stream.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
        return;
    }

    let atyp = header[3];
    // `host` is the address to connect to; `is_resolved_ip` is true when the
    // client already resolved DNS and sent a raw IP (ATYP=0x01/0x04).  In that
    // case we use `is_ip_allowed` which falls back to resolving allowlist
    // hostnames so that hostname-based entries still work.
    let (host, is_resolved_ip): (String, bool) = match atyp {
        0x01 => {
            // IPv4
            let mut addr = [0u8; 4];
            if stream.read_exact(&mut addr).is_err() { return; }
            (std::net::Ipv4Addr::from(addr).to_string(), true)
        }
        0x03 => {
            // Domain name: 1-byte length prefix
            let mut len_byte = [0u8; 1];
            if stream.read_exact(&mut len_byte).is_err() { return; }
            let mut name = vec![0u8; len_byte[0] as usize];
            if stream.read_exact(&mut name).is_err() { return; }
            match String::from_utf8(name) {
                Ok(s) => (s, false),
                Err(_) => return,
            }
        }
        0x04 => {
            // IPv6
            let mut addr = [0u8; 16];
            if stream.read_exact(&mut addr).is_err() { return; }
            (std::net::Ipv6Addr::from(addr).to_string(), true)
        }
        _ => return,
    };

    let mut port_bytes = [0u8; 2];
    if stream.read_exact(&mut port_bytes).is_err() { return; }
    let port = u16::from_be_bytes(port_bytes);

    // --- Policy check ---
    let (allowed, atyp_label) = {
        let guard = allowlist.0.read().unwrap_or_else(|e| e.into_inner());
        if is_resolved_ip {
            (is_ip_allowed(&host, &guard), "ip")
        } else {
            (is_host_allowed(&host, &guard), "hostname")
        }
    };
    if !allowed {
        warn!("net proxy: BLOCKED {} {}:{} — not in allowlist", atyp_label, host, port);
        // REP=0x02 (connection not allowed by ruleset)
        let _ = stream.write_all(&[5, 2, 0, 1, 0, 0, 0, 0, 0, 0]);
        return;
    }
    debug!("net proxy: ALLOWED {} {}:{}", atyp_label, host, port);

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
    use super::*;

    #[test]
    fn is_host_allowed_exact() {
        assert!(is_host_allowed("api.openai.com", &["api.openai.com".into()]));
        assert!(!is_host_allowed("evil.com", &["api.openai.com".into()]));
    }

    #[test]
    fn is_host_allowed_wildcard_prefix() {
        let list = vec!["*.openai.com".into()];
        assert!(is_host_allowed("api.openai.com", &list));
        assert!(is_host_allowed("chat.openai.com", &list));
        assert!(!is_host_allowed("openai.com", &list));  // apex excluded
        assert!(!is_host_allowed("evilopenai.com", &list));
    }

    #[test]
    fn is_host_allowed_star_allows_all() {
        let list = vec!["*".into()];
        assert!(is_host_allowed("anything.example.com", &list));
    }

    #[test]
    fn is_host_allowed_case_insensitive() {
        let list = vec!["API.OpenAI.com".into()];
        assert!(is_host_allowed("api.openai.com", &list));
    }

    #[test]
    fn is_host_allowed_empty_list_blocks_all() {
        assert!(!is_host_allowed("api.openai.com", &[]));
    }

    #[test]
    fn net_allowlist_update_is_visible() {
        let al = NetAllowlist::new(vec!["a.example.com".into()]);
        assert!(al.is_allowed("a.example.com"));
        assert!(!al.is_allowed("b.example.com"));
        al.update(vec!["b.example.com".into()]);
        assert!(!al.is_allowed("a.example.com"));
        assert!(al.is_allowed("b.example.com"));
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

        let al = NetAllowlist::new(vec!["127.0.0.1".into()]);
        let proxy = NetProxy::start(al).unwrap();

        let mut tunnel = socks5_connect(proxy.port(), "127.0.0.1", upstream_port).unwrap();
        let mut buf = [0u8; 5];
        tunnel.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello");
    }

    static PORT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock_proxy_ports() -> std::sync::MutexGuard<'static, ()> {
        PORT_LOCK.lock().unwrap_or_else(|e| e.into_inner())
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
}
