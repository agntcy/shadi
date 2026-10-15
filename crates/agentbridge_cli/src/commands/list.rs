use agentbridge::local_registry::{LocalAdapterRecord, LocalAdapterRegistry};
use agentbridge::member_source::{
    A2AAgentSearchSource, CandidateMember, DirLookupOptions, MemberSource, RunningAgentSource,
};
use shadi_a2a::A2ALocator;

/// Where `agentbridge list` looks.
pub struct ListOptions<'a> {
    /// Only this host's listeners (`--local`).
    pub local: bool,
    /// DIR records instead of running agents (`--published`).
    pub published: bool,
    /// OASF skills to filter on (`--skill`, any of them).
    pub skills: &'a [String],
    /// dir-runtimes to ask for running agents (`--runtime`).
    pub runtimes: &'a [String],
    /// The Directory for `--published`.
    pub dir_server: &'a str,
    pub gh_token: Option<&'a str>,
}

/// List agentbridge agents.
///
/// By default, the running ones: this host's listeners (leases under
/// `$SHADI_TMP_DIR`, and listeners announced to dir-runtime) and every agent
/// each `--runtime` lists, merged and de-duplicated. `--local` lists only this
/// host's listeners; `--published` searches DIR records (`register
/// --dir-publish`) instead, which say what was published, not what runs.
pub fn run(opts: &ListOptions<'_>) -> anyhow::Result<()> {
    if opts.local {
        return list_local(&LocalAdapterRegistry::from_env());
    }
    if opts.published {
        return list_published(opts);
    }

    let mut found = Vec::new();
    // Local records carry no skills to filter on, so a skill filter only
    // applies to what runtime discovery reports.
    if opts.skills.is_empty() {
        let leases = LocalAdapterRegistry::from_env()
            .list_live()
            .map_err(|e| anyhow::anyhow!("local discovery failed: {e}"))?;
        found.extend(
            leases
                .iter()
                .map(|r| (r.to_candidate(), LOCAL_SOURCE.to_string())),
        );
    }
    let mut unavailable = Vec::new();
    for runtime in opts.runtimes {
        let source = RunningAgentSource {
            skills: opts.skills.to_vec(),
            runtime: lookup(runtime, opts.gh_token),
        };
        match source.resolve() {
            Ok(candidates) => {
                let label = format!("{RUNTIME_SOURCE} ({runtime})");
                found.extend(candidates.into_iter().map(|c| (c, label.clone())));
            }
            // Runtime discovery is optional: say so after the listing
            // instead of failing or printing the transport error.
            Err(e) => unavailable.push(runtime_note(runtime, &e)),
        }
    }

    let merged = merge(found);
    if merged.is_empty() {
        println!("No running agentbridge agents found.");
        println!("Start one with: agentbridge register --tool <name> --a2a-listen <host:port> [--dir-announce]");
    } else {
        for (c, sources) in &merged {
            println!("{}  [{}]", render_candidate(c), sources.join(", "));
        }
    }
    for note in &unavailable {
        println!("{note}");
    }
    Ok(())
}

/// One sentence on a dir-runtime that couldn't be asked: not running, or a
/// `dirctl` that can't ask it.
fn runtime_note(runtime: &str, error: &str) -> String {
    if error.contains("has no `runtime` command") {
        return format!("Agents announced to dir-runtime aren't listed: {error}.");
    }
    if error.contains("connection refused") || error.contains("Unavailable") {
        return format!(
            "No dir-runtime is running at {runtime}, so agents announced with --dir-announce \
             aren't listed (start one with `dirctl daemon start`)."
        );
    }
    let first = error.lines().next().unwrap_or(error);
    format!("Agents announced to dir-runtime at {runtime} aren't listed: {first}")
}

/// A listener on this host that isn't announced: found through its lease.
const LOCAL_SOURCE: &str = "local";

/// An agent a dir-runtime reported, followed by that runtime's address.
const RUNTIME_SOURCE: &str = "runtime";

fn list_published(opts: &ListOptions<'_>) -> anyhow::Result<()> {
    let server_addr = opts.dir_server;
    println!("Searching Agent Directory ({server_addr}) for published A2A agents...\n");

    let source = A2AAgentSearchSource {
        skills: opts.skills.to_vec(),
        dir: lookup(server_addr, opts.gh_token),
    };
    let candidates = source
        .resolve()
        .map_err(|e| anyhow::anyhow!("DIR search failed: {e}"))?;

    if candidates.is_empty() {
        println!("No A2A agents found in DIR.");
        println!(
            "Register one with: agentbridge register --tool <name> --skill <OASF skill> --dir-publish"
        );
    } else {
        for c in &candidates {
            println!("{}", render_candidate(c));
        }
    }
    Ok(())
}

fn lookup(server_addr: &str, gh_token: Option<&str>) -> DirLookupOptions {
    DirLookupOptions {
        server_addr: server_addr.to_string(),
        gh_token: gh_token.map(str::to_string),
        limit: 20,
    }
}

/// One entry per agent DID and locator, with the sources that reported it. A
/// listener is either leased (`local`) or announced, and then labelled by the
/// dir-runtimes that reported it.
fn merge(found: Vec<(CandidateMember, String)>) -> Vec<(CandidateMember, Vec<String>)> {
    let mut out: Vec<(CandidateMember, Vec<String>)> = Vec::new();
    for (candidate, source) in found {
        let same = |c: &CandidateMember| {
            c.did == candidate.did
                && c.slim_endpoint == candidate.slim_endpoint
                && c.a2a_url == candidate.a2a_url
        };
        match out.iter_mut().find(|(c, _)| same(c)) {
            Some((_, sources)) if !sources.contains(&source) => sources.push(source),
            Some(_) => {}
            None => out.push((candidate, vec![source])),
        }
    }
    out.sort_by(|(a, _), (b, _)| a.name.cmp(&b.name).then(a.did.cmp(&b.did)));
    out
}

fn list_local(registry: &LocalAdapterRegistry) -> anyhow::Result<()> {
    let records = registry
        .list_live()
        .map_err(|e| anyhow::anyhow!("local discovery failed: {e}"))?;
    print!("{}", render_local_listing(&records));
    Ok(())
}

fn render_candidate(candidate: &CandidateMember) -> String {
    render_candidate_line(&candidate.name, &candidate.did, &candidate.locators())
}

fn render_candidate_line(name: &str, did: &str, locators: &[A2ALocator]) -> String {
    let mut line = format!("{name}  did={did}");
    for locator in locators {
        line.push_str(&format!("  {}", locator.display_uri()));
    }
    if locators.is_empty() {
        line.push_str("  (no A2A address)");
    }
    line
}

fn render_local_listing(records: &[LocalAdapterRecord]) -> String {
    if records.is_empty() {
        return concat!(
            "No local agentbridge adapters.\n",
            "Start one with: agentbridge register --tool <name> --slim-endpoint <host:port>\n",
            "            or: agentbridge register --tool <name> --a2a-listen <host:port> [--a2a-binding grpc|jsonrpc|http+json]\n"
        )
        .to_string();
    }
    let mut out = String::from("Local agentbridge adapters:\n");
    for record in records {
        out.push_str(&render_candidate(&record.to_candidate()));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadi_a2a::A2ABinding;

    fn candidate(name: &str, did: &str, url: &str) -> CandidateMember {
        CandidateMember {
            name: name.into(),
            did: did.into(),
            slim_endpoint: None,
            a2a_url: Some(url.into()),
            a2a_binding: Some(shadi_a2a::A2ABinding::HttpJson),
        }
    }

    #[test]
    fn an_unreachable_runtime_is_a_note_not_an_error() {
        let refused = "Error: failed to list workloads: rpc error: code = Unavailable desc = \
                       connection error: dial tcp 127.0.0.1:8888: connect: connection refused";
        assert_eq!(
            runtime_note("localhost:8888", refused),
            "No dir-runtime is running at localhost:8888, so agents announced with \
             --dir-announce aren't listed (start one with `dirctl daemon start`)."
        );
        let old = "/opt/homebrew/bin/dirctl has no `runtime` command; runtime discovery needs \
                   dirctl 1.8.0 or later (set SHADI_DIRCTL_BINARY to point at one)";
        assert!(runtime_note("localhost:8888", old).starts_with(
            "Agents announced to dir-runtime aren't listed: /opt/homebrew/bin/dirctl"
        ));
    }

    #[test]
    fn each_agent_is_labelled_by_where_its_record_is() {
        let local = || LOCAL_SOURCE.to_string();
        let runtime = |addr: &str| format!("{RUNTIME_SOURCE} ({addr})");
        let merged = merge(vec![
            // Leased: only on this host.
            (
                candidate("codex", "did:key:zB", "http://127.0.0.1:2"),
                local(),
            ),
            // Announced, reported by two dir-runtimes.
            (
                candidate("copilot", "did:key:zA", "http://127.0.0.1:1"),
                runtime("localhost:8888"),
            ),
            (
                candidate("copilot", "did:key:zA", "http://127.0.0.1:1"),
                runtime("lab:8888"),
            ),
            // Reported twice by the same runtime: listed once.
            (
                candidate("copilot", "did:key:zA", "http://127.0.0.1:3"),
                runtime("localhost:8888"),
            ),
            (
                candidate("copilot", "did:key:zA", "http://127.0.0.1:3"),
                runtime("localhost:8888"),
            ),
        ]);
        let rows: Vec<(&str, String)> = merged
            .iter()
            .map(|(c, s)| (c.a2a_url.as_deref().unwrap(), s.join(", ")))
            .collect();
        assert_eq!(
            rows,
            vec![
                ("http://127.0.0.1:2", "local".to_string()),
                (
                    "http://127.0.0.1:1",
                    "runtime (localhost:8888), runtime (lab:8888)".to_string()
                ),
                ("http://127.0.0.1:3", "runtime (localhost:8888)".to_string()),
            ]
        );
    }

    #[test]
    fn local_discovery_empty_registry_is_ok() {
        let registry = LocalAdapterRegistry::with_dir(std::path::PathBuf::from(
            "/no/such/agentbridge-local-test-dir",
        ));
        assert!(list_local(&registry).is_ok());
        let rendered = render_local_listing(&[]);
        assert!(rendered.contains("No local agentbridge adapters"));
        assert!(rendered.contains("--a2a-listen"));
    }

    #[test]
    fn local_listing_prints_slim_and_unicast_locators() {
        let records = vec![
            LocalAdapterRecord {
                name: "copilot".to_string(),
                did: "did:key:zLocal".to_string(),
                slim_endpoint: "127.0.0.1:47357".to_string(),
                a2a_url: String::new(),
                a2a_binding: A2ABinding::Grpc,
                pid: 1,
            },
            LocalAdapterRecord {
                name: "codex".to_string(),
                did: "did:key:zGrpc".to_string(),
                slim_endpoint: String::new(),
                a2a_url: "http://127.0.0.1:50051".to_string(),
                a2a_binding: A2ABinding::Grpc,
                pid: 2,
            },
            LocalAdapterRecord {
                name: "goose".to_string(),
                did: "did:key:zJson".to_string(),
                slim_endpoint: String::new(),
                a2a_url: "http://127.0.0.1:8080".to_string(),
                a2a_binding: A2ABinding::Jsonrpc,
                pid: 3,
            },
        ];
        let rendered = render_local_listing(&records);
        assert!(rendered.contains("copilot  did=did:key:zLocal  slim://127.0.0.1:47357"));
        assert!(rendered.contains("codex  did=did:key:zGrpc  grpc://127.0.0.1:50051"));
        assert!(rendered.contains("goose  did=did:key:zJson  jsonrpc://127.0.0.1:8080"));
    }
}
