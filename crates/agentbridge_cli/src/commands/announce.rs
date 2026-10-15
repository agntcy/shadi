//! Announcing a running `register` to runtime discovery (dir-runtime).
//!
//! With `--dir-announce`, `register` writes a process descriptor into
//! dir-runtime's descriptor directory while it serves, and deletes it when it
//! stops. A crash is covered by dir-runtime's PID check. The descriptor lists
//! where the agent can be reached (its locators), including an HTTP endpoint
//! serving its A2A card, which dir-runtime fetches to learn the agent's name,
//! skills and domains.
//!
//! The descriptor replaces the listener's local lease rather than sitting next
//! to it: it carries the agent DID (`agntcy.dir/identity`) and A2A binding as
//! annotations, so `list` and `delegate --to <name>` find announced listeners
//! through dir-runtime.

use std::fs;
use std::io::Write;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use a2a::AgentCard;
use serde_json::{json, Value};
use shadi_a2a::A2ABinding;

pub use agentbridge::local_registry::DEFAULT_WORKLOADS_DIR;
use agentbridge::local_registry::{
    A2A_BINDING_ANNOTATION, IDENTITY_ANNOTATION, SLIM_ENDPOINT_ANNOTATION,
};

/// Labels dir-runtime's process discovery and A2A resolver act on.
const DISCOVER_LABEL: &str = "org.agntcy/discover";
const AGENT_TYPE_LABEL: &str = "org.agntcy/agent-type";

/// Label naming the OASF record the agent was built from.
pub const AGENT_RECORD_LABEL: &str = "org.agntcy/agent-record";

/// `--dir-announce` settings from the command line.
#[derive(Clone, Debug, Default)]
pub struct AnnounceOptions {
    /// Write the descriptor at all (`--dir-announce`).
    pub enabled: bool,
    /// Descriptor directory (`--dir-announce-dir`).
    pub dir: String,
    /// Address for the HTTP listener that serves the A2A card
    /// (`--card-listen`); a free loopback port when unset.
    pub card_listen: Option<String>,
    /// CID of the OASF record the agent was built from, put on the workload
    /// as `org.agntcy/agent-record`.
    pub source_record: Option<String>,
}

static ANNOUNCE_OPTIONS: OnceLock<AnnounceOptions> = OnceLock::new();

/// Set the announcement settings for this process. Call once, before serving.
pub fn configure(opts: AnnounceOptions) -> anyhow::Result<()> {
    ANNOUNCE_OPTIONS
        .set(opts)
        .map_err(|_| anyhow::anyhow!("announcement settings were already configured"))
}

/// One endpoint the agent can be reached at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Locator {
    pub protocol: String,
    pub url: String,
}

/// A written descriptor. Dropping it deletes the file; a SIGTERM deletes it
/// too, and a crash leaves it to dir-runtime's PID check.
pub struct Announcement {
    path: PathBuf,
}

impl Announcement {
    /// The descriptor, for [`withdraw`] from a thread that outlives this guard.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Announcement {
    fn drop(&mut self) {
        remove_descriptor(&self.path);
    }
}

/// Delete an announcement's descriptor before exiting without unwinding.
pub fn withdraw(path: &Path) {
    remove_descriptor(path);
}

/// Start announcing this `register`, if `--dir-announce` is set.
///
/// `card` builds the agent card that the card listener serves; `locators` are
/// the A2A endpoints the listeners are about to serve. When `serves_card` is
/// false (SLIM and gRPC don't serve `/.well-known/agent-card.json`), an HTTP
/// listener just for the card is started first.
pub fn start(
    agent_id: &str,
    agent_did: Option<&str>,
    slim_endpoint: Option<&str>,
    a2a_binding: Option<A2ABinding>,
    mut locators: Vec<Locator>,
    serves_card: bool,
    card: impl Fn() -> AgentCard + Send + Sync + 'static,
) -> anyhow::Result<Option<Announcement>> {
    let Some(opts) = ANNOUNCE_OPTIONS.get() else {
        return Ok(None);
    };

    // --card-listen works on its own too: a container announces itself with
    // Docker labels, and dir-runtime reads the card from the published port.
    if !opts.enabled {
        if let Some(listen) = opts.card_listen.as_deref() {
            let addr = serve_card(Some(listen), card)?;
            println!(
                "[agentbridge] serving the agent card on http://{addr}/.well-known/agent-card.json"
            );
        }

        return Ok(None);
    }

    if locators.is_empty() {
        anyhow::bail!("--dir-announce needs an A2A listener: pass --slim-endpoint or --a2a-listen");
    }
    if opts.dir.trim().is_empty() {
        anyhow::bail!(
            "the descriptor directory (--dir-announce-dir / DIR_RUNTIME_WORKLOADS_DIR) is empty"
        );
    }

    if !serves_card || opts.card_listen.is_some() {
        let addr = serve_card(opts.card_listen.as_deref(), card)?;
        let url = format!("http://{addr}");
        println!("[agentbridge] serving the agent card on {url}/.well-known/agent-card.json");
        locators.push(Locator {
            protocol: "http".to_string(),
            url,
        });
    }

    let dir = expand_home(&opts.dir);
    let pid = std::process::id();
    let workload_id = workload_id(agent_id, agent_did, pid);
    let descriptor = descriptor(
        agent_id,
        pid,
        &locators,
        &Annotations {
            agent_did,
            slim_endpoint,
            a2a_binding,
            source_record: opts.source_record.as_deref(),
        },
    );
    // Ready to withdraw on SIGTERM before the descriptor is visible, and the
    // slot held while it is published: a SIGTERM meanwhile waits for the path.
    let on_sigterm = on_sigterm();
    let path = {
        let mut slot = on_sigterm.lock().unwrap_or_else(|e| e.into_inner());
        let path = write_descriptor(&dir, &workload_id, &descriptor)?;
        *slot = Some(path.clone());
        path
    };

    println!(
        "[agentbridge] announced to dir-runtime as {workload_id} ({})",
        path.display()
    );

    Ok(Some(Announcement { path }))
}

/// Locators for the listeners `register` starts.
pub fn listener_locators(
    agent_id: &str,
    slim_endpoint: Option<&str>,
    a2a_listen: Option<&str>,
    a2a_binding: A2ABinding,
    advertised_url: impl Fn(&str) -> String,
) -> Vec<Locator> {
    let mut locators = Vec::new();

    if let Some(endpoint) = slim_endpoint {
        locators.push(Locator {
            protocol: "slim".to_string(),
            url: format!("slim://{}/agntcy/shadi/{agent_id}-a2a", slim_node(endpoint)),
        });
    }

    if let Some(listen) = a2a_listen {
        let url = advertised_url(listen);
        let protocol = match a2a_binding {
            A2ABinding::Grpc => "grpc".to_string(),
            _ => url.split("://").next().unwrap_or("http").to_string(),
        };
        locators.push(Locator { protocol, url });
    }

    locators
}

/// Unique per instance: instances of one agent share its DID, so the PID tells
/// them apart.
fn workload_id(agent_id: &str, agent_did: Option<&str>, pid: u32) -> String {
    let did_part = agent_did
        .and_then(|did| did.rsplit(':').next())
        .map(|key| key.chars().rev().take(12).collect::<String>())
        .map(|rev| rev.chars().rev().collect::<String>());

    let mut id = sanitize(agent_id);
    if let Some(part) = did_part {
        id.push('-');
        id.push_str(&sanitize(&part));
    }
    id.push('-');
    id.push_str(&pid.to_string());
    id
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// What the descriptor says about the agent beyond its name and locators.
struct Annotations<'a> {
    agent_did: Option<&'a str>,
    slim_endpoint: Option<&'a str>,
    a2a_binding: Option<A2ABinding>,
    source_record: Option<&'a str>,
}

/// The SLIM node part of an endpoint for a `slim://` locator: without a
/// connection scheme (`https://node:47357`) or trailing slash. The endpoint
/// itself, scheme included, goes into the `org.agntcy/slim-endpoint`
/// annotation, since a scheme-less endpoint means HTTPS to SLIM clients.
fn slim_node(endpoint: &str) -> &str {
    let rest = endpoint.split_once("://").map_or(endpoint, |(_, r)| r);
    rest.trim_end_matches('/')
}

/// Whether `--dir-announce` is on: then the descriptor stands in for the local
/// lease.
pub fn enabled() -> bool {
    ANNOUNCE_OPTIONS.get().is_some_and(|o| o.enabled)
}

fn descriptor(agent_id: &str, pid: u32, locators: &[Locator], about: &Annotations<'_>) -> Value {
    let mut labels = serde_json::Map::new();
    labels.insert(DISCOVER_LABEL.to_string(), json!("true"));
    labels.insert(AGENT_TYPE_LABEL.to_string(), json!("a2a"));

    if let Some(cid) = about.source_record.filter(|c| !c.is_empty()) {
        labels.insert(AGENT_RECORD_LABEL.to_string(), json!(cid));
    }

    let mut annotations = serde_json::Map::new();
    if let Some(did) = about.agent_did.filter(|d| !d.is_empty()) {
        annotations.insert(IDENTITY_ANNOTATION.to_string(), json!(did));
    }
    if let Some(endpoint) = about.slim_endpoint.filter(|e| !e.is_empty()) {
        annotations.insert(SLIM_ENDPOINT_ANNOTATION.to_string(), json!(endpoint));
    }
    if let Some(binding) = about.a2a_binding {
        annotations.insert(
            A2A_BINDING_ANNOTATION.to_string(),
            json!(binding.as_protocol_binding()),
        );
    }

    json!({
        "name": agent_id,
        "pid": pid,
        // When the descriptor was written: dir-runtime treats a process that
        // started later and holds the same PID as a reused PID, not this one.
        "started_at": now_rfc3339(),
        "labels": labels,
        "annotations": annotations,
        "locators": locators
            .iter()
            .map(|l| json!({ "protocol": l.protocol, "url": l.url }))
            .collect::<Vec<_>>(),
    })
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// Write `<dir>/<id>.json` atomically: a hidden temporary file renamed into
/// place, so dir-runtime never reads half a descriptor.
fn write_descriptor(dir: &Path, workload_id: &str, descriptor: &Value) -> anyhow::Result<PathBuf> {
    create_private_dir(dir)?;

    let path = dir.join(format!("{workload_id}.json"));
    let tmp = dir.join(format!(".{workload_id}.json.tmp"));

    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(serde_json::to_string_pretty(descriptor)?.as_bytes())?;
        file.sync_all()?;
    }

    fs::rename(&tmp, &path)?;

    Ok(path)
}

fn create_private_dir(dir: &Path) -> anyhow::Result<()> {
    // Don't probe the directory first: a sandbox that grants writing into it may
    // still deny reading its metadata. Create it, and accept that it exists.
    match fs::create_dir(dir) {
        Ok(()) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
            }

            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // A missing parent: create the ancestors, then this directory.
            if let Some(parent) = dir.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    anyhow::anyhow!("create descriptor directory {}: {e}", dir.display())
                })?;
            }

            create_private_dir(dir)
        }
        Err(e) => Err(anyhow::anyhow!(
            "create descriptor directory {}: {e}",
            dir.display()
        )),
    }
}

fn remove_descriptor(path: &Path) {
    match fs::remove_file(path) {
        Ok(()) => println!("[agentbridge] withdrew the dir-runtime announcement"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => eprintln!("[agentbridge] could not remove {}: {e}", path.display()),
    }
}

fn expand_home(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }

    PathBuf::from(path)
}

/// The descriptor to delete on SIGTERM. The first call registers the handler,
/// which deletes it (and what `--record` provisioned), then exits as SIGTERM
/// would. Ctrl-C (SIGINT) already returns through the listeners, which drops
/// the [`Announcement`]. Returns once the handler is registered, so a SIGTERM
/// right after the descriptor is written still withdraws it.
pub fn on_sigterm() -> &'static Mutex<Option<PathBuf>> {
    static PATH: Mutex<Option<PathBuf>> = Mutex::new(None);
    static HANDLER: OnceLock<()> = OnceLock::new();

    HANDLER.get_or_init(|| {
        #[cfg(unix)]
        {
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return;
                };

                runtime.block_on(async {
                    let term =
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
                    let _ = ready_tx.send(());
                    let Ok(mut term) = term else {
                        return;
                    };

                    if term.recv().await.is_some() {
                        if let Some(p) = PATH.lock().ok().and_then(|mut p| p.take()) {
                            remove_descriptor(&p);
                        }
                        stop_in_flight();
                        super::record::cleanup();

                        std::process::exit(143);
                    }
                });
            });
            // A runtime that can't start never registers a handler; don't wait for it.
            let _ = ready_rx.recv_timeout(std::time::Duration::from_secs(5));
        }
    });

    &PATH
}

type StopHook = Box<dyn Fn() + Send>;

static STOP_HOOKS: Mutex<Vec<StopHook>> = Mutex::new(Vec::new());

/// Run `stop` before SIGTERM exits, as Ctrl-C's shutdown would (e.g. kill the
/// harness running a task), so no child outlives the agent.
pub fn before_sigterm_exit(stop: impl Fn() + Send + 'static) {
    if let Ok(mut hooks) = STOP_HOOKS.lock() {
        hooks.push(Box::new(stop));
    }
}

fn stop_in_flight() {
    if let Ok(hooks) = STOP_HOOKS.lock() {
        for stop in hooks.iter() {
            stop();
        }
    }
}

/// Serve the agent card at `/.well-known/agent-card.json` on its own HTTP
/// listener, for bindings that don't serve it themselves. Returns the bound
/// address. The listener only serves the card, which is public, so plain HTTP
/// on any address is allowed (a container publishes it).
fn serve_card(
    listen: Option<&str>,
    card: impl Fn() -> AgentCard + Send + Sync + 'static,
) -> anyhow::Result<SocketAddr> {
    let chosen = listen.is_some();
    let listen = listen.unwrap_or("127.0.0.1:0");
    let std_listener = TcpListener::bind(listen).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            let hint = if chosen {
                format!("allow it with `shadictl --net-allow {listen}`")
            } else {
                "the SHADI sandbox only allows listed ports, so pick one: \
                 `--card-listen 127.0.0.1:<port>` and `shadictl --net-allow 127.0.0.1:<port>`"
                    .to_string()
            };
            anyhow::anyhow!("binding the card listener {listen} is not permitted; {hint}")
        } else {
            anyhow::anyhow!("bind card listener {listen}: {e}")
        }
    })?;
    std_listener.set_nonblocking(true)?;

    let addr = std_listener.local_addr()?;
    let card = card();

    std::thread::spawn(move || {
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            eprintln!("[agentbridge] card listener: could not start a runtime");
            return;
        };

        runtime.block_on(async move {
            let Ok(listener) = tokio::net::TcpListener::from_std(std_listener) else {
                eprintln!("[agentbridge] card listener: could not adopt the socket");
                return;
            };

            let router = a2a_server::agent_card::agent_card_router(Arc::new(
                a2a_server::StaticAgentCard::new(card),
            ));

            if let Err(e) = axum::serve(listener, router).await {
                eprintln!("[agentbridge] card listener error: {e}");
            }
        });
    });

    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workload_id_tells_instances_of_one_agent_apart() {
        let did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

        assert_eq!(
            workload_id("claude-code", Some(did), 42),
            "claude-code-pbnnEGta2doK-42"
        );
        assert_ne!(
            workload_id("claude-code", Some(did), 42),
            workload_id("claude-code", Some(did), 43)
        );
        assert_eq!(workload_id("generic-stdio", None, 7), "generic-stdio-7");
        assert_eq!(workload_id("my agent/x", None, 7), "my-agent-x-7");
    }

    #[test]
    fn locators_cover_slim_and_unicast_listeners() {
        let locators = listener_locators(
            "codex",
            Some("127.0.0.1:47357"),
            Some("127.0.0.1:50051"),
            A2ABinding::Grpc,
            |l| format!("http://{l}"),
        );

        assert_eq!(
            locators,
            vec![
                Locator {
                    protocol: "slim".into(),
                    url: "slim://127.0.0.1:47357/agntcy/shadi/codex-a2a".into()
                },
                Locator {
                    protocol: "grpc".into(),
                    url: "http://127.0.0.1:50051".into()
                },
            ]
        );

        let http = listener_locators(
            "codex",
            None,
            Some("0.0.0.0:8443"),
            A2ABinding::HttpJson,
            |l| format!("https://{l}"),
        );
        assert_eq!(
            http,
            vec![Locator {
                protocol: "https".into(),
                url: "https://0.0.0.0:8443".into()
            }]
        );
    }

    #[test]
    fn descriptor_carries_labels_locators_and_the_source_record() {
        let locators = vec![Locator {
            protocol: "http".into(),
            url: "http://127.0.0.1:1".into(),
        }];
        let d = descriptor(
            "codex",
            99,
            &locators,
            &Annotations {
                agent_did: Some("did:key:zAgent"),
                slim_endpoint: Some("https://node:47357"),
                a2a_binding: Some(A2ABinding::Jsonrpc),
                source_record: Some("bafy-skill"),
            },
        );

        assert_eq!(d["name"], json!("codex"));
        assert_eq!(d["pid"], json!(99));
        assert_eq!(d["labels"][DISCOVER_LABEL], json!("true"));
        assert_eq!(d["labels"][AGENT_TYPE_LABEL], json!("a2a"));
        assert_eq!(d["labels"][AGENT_RECORD_LABEL], json!("bafy-skill"));
        assert_eq!(
            d["locators"],
            json!([{ "protocol": "http", "url": "http://127.0.0.1:1" }])
        );

        assert_eq!(
            d["annotations"][IDENTITY_ANNOTATION],
            json!("did:key:zAgent")
        );
        assert_eq!(d["annotations"][A2A_BINDING_ANNOTATION], json!("JSONRPC"));
        assert_eq!(
            d["annotations"][SLIM_ENDPOINT_ANNOTATION],
            json!("https://node:47357")
        );
        let started = d["started_at"].as_str().expect("started_at");
        assert!(
            time::OffsetDateTime::parse(started, &time::format_description::well_known::Rfc3339)
                .is_ok(),
            "{started}"
        );

        let bare = descriptor(
            "codex",
            99,
            &locators,
            &Annotations {
                agent_did: None,
                slim_endpoint: None,
                a2a_binding: None,
                source_record: None,
            },
        );
        assert!(bare["labels"].get(AGENT_RECORD_LABEL).is_none());
        assert_eq!(bare["annotations"], json!({}));
    }

    #[test]
    fn descriptor_is_written_atomically_and_removed_on_drop() {
        let dir = std::env::temp_dir().join(format!("agentbridge-announce-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let path = write_descriptor(&dir, "w1", &json!({ "name": "x" })).expect("write");
        assert!(path.is_file());
        assert!(
            !dir.join(".w1.json.tmp").exists(),
            "temporary file must be renamed away"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }

        drop(Announcement { path: path.clone() });
        assert!(!path.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn card_listener_serves_the_well_known_card() {
        let addr = serve_card(None, || AgentCard {
            name: "probe".into(),
            ..test_card()
        })
        .expect("serve");

        let body = reqwest::blocking::get(format!("http://{addr}/.well-known/agent-card.json"))
            .and_then(|r| r.text())
            .expect("fetch card");
        assert!(body.contains("\"probe\""), "{body}");
    }

    fn test_card() -> AgentCard {
        serde_json::from_value(json!({
            "name": "t",
            "description": "t",
            "version": "1",
            "supportedInterfaces": [],
            "capabilities": {},
            "defaultInputModes": [],
            "defaultOutputModes": [],
            "skills": []
        }))
        .expect("card")
    }

    #[test]
    fn home_is_expanded() {
        if let Some(home) = std::env::var_os("HOME") {
            assert_eq!(expand_home("~/x/y"), PathBuf::from(home).join("x/y"));
        }
        assert_eq!(expand_home("/abs"), PathBuf::from("/abs"));
    }

    #[test]
    fn a_slim_locator_names_the_node_without_its_scheme() {
        for endpoint in ["node:47357", "http://node:47357", "https://node:47357/"] {
            let locators =
                listener_locators("codex", Some(endpoint), None, A2ABinding::Grpc, |u| {
                    u.into()
                });
            assert_eq!(
                locators[0].url, "slim://node:47357/agntcy/shadi/codex-a2a",
                "{endpoint}"
            );
        }
    }
}
