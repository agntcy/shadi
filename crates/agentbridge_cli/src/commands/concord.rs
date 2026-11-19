// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! `--protocol concord`: negotiate one outcome with CONCORD.
//!
//! `register --protocol concord` turns a harness into a member of the group:
//! it runs a node that answers what the run asks of it. `coordinate
//! --protocol concord` opens a run and reports how it ended. Every member
//! holds its own copy of the run, and they exchange messages over A2A
//! Collaborate on SLIM. See `agentbridge::concord`.

/// A protocol `register` and `coordinate` can run besides their own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Protocol {
    /// Negotiate one outcome that every participant rates above a threshold.
    Concord,
}

#[cfg(feature = "concord")]
pub use enabled::{coordinate, register, CoordinateOptions, MemberOptions};

#[cfg(not(feature = "concord"))]
pub use disabled::{coordinate, register, CoordinateOptions, MemberOptions};

#[cfg(not(feature = "concord"))]
mod disabled {
    const MESSAGE: &str =
        "this agentbridge was built without CONCORD: rebuild with `--features concord`";

    pub struct MemberOptions<'a> {
        pub tool: &'a str,
        pub command: Option<&'a str>,
        pub args: &'a [String],
        pub slim_endpoint: Option<&'a str>,
        pub peers: &'a [String],
        pub verbose: bool,
    }

    pub struct CoordinateOptions<'a> {
        pub goal: &'a str,
        pub tool: Option<&'a str>,
        pub command: Option<&'a str>,
        pub participants: &'a [String],
        pub reject: Option<&'a str>,
        pub ideal: Option<&'a str>,
        pub schema: Option<&'a str>,
        pub threshold: Option<&'a str>,
        pub budget: Option<i64>,
        pub timeout: Option<i64>,
        pub retries: Option<i64>,
        pub slim_endpoint: &'a str,
        pub session: Option<&'a str>,
        pub report: Option<&'a str>,
    }

    pub fn register(_: MemberOptions<'_>) -> anyhow::Result<()> {
        anyhow::bail!(MESSAGE)
    }

    pub fn coordinate(_: CoordinateOptions<'_>) -> anyhow::Result<()> {
        anyhow::bail!(MESSAGE)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn without_the_feature_both_commands_say_how_to_get_it() {
            let error = register(MemberOptions {
                tool: "claude-code",
                command: None,
                args: &[],
                slim_endpoint: Some("127.0.0.1:1"),
                peers: &[],
                verbose: false,
            })
            .unwrap_err()
            .to_string();
            assert!(error.contains("--features concord"), "{error}");
        }
    }
}

#[cfg(feature = "concord")]
mod enabled {
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use agent_transport_slim::client_access::ClientAccess;
    use agentbridge::adapters::generic_stdio::GenericStdioAdapter;
    use agentbridge::concord::initiator::Given;
    use agentbridge::concord::ioc_concord::agent::{Agent, Event};
    use agentbridge::concord::ioc_concord::protocol::Outcome;
    use agentbridge::concord::ioc_concord::report::Report;
    use agentbridge::concord::ioc_concord::tasks::Task;
    use agentbridge::concord::ioc_concord::wire::InitParams;
    use agentbridge::concord::node::{
        ConcordInit, HarnessResponder, Node, NodeConfig, NodeError, Responder,
    };
    use agentbridge::{open_profile_adapter, CliAdapter};
    use anyhow::{anyhow, bail, Context};

    use super::super::concord_channel::{CollaborateChannel, CollaborateConfig};
    use super::super::register::{require_sandbox_enforced, work_dir};

    /// How long one broadcast may take before it is given up.
    const BROADCAST_TIMEOUT: Duration = Duration::from_secs(30);

    /// The agent id the coordinator proves itself as, as for `coordinate`.
    const COORDINATOR: &str = "coordinator";

    pub struct MemberOptions<'a> {
        pub tool: &'a str,
        pub command: Option<&'a str>,
        pub args: &'a [String],
        pub slim_endpoint: Option<&'a str>,
        /// The agent ids of the other members of the group, the coordinator
        /// included.
        pub peers: &'a [String],
        /// Print the whole of every event, not a line of it.
        pub verbose: bool,
    }

    pub struct CoordinateOptions<'a> {
        /// The problem, as every participant reads it.
        pub goal: &'a str,
        /// A harness that writes the parts of the frame the options below
        /// leave out. Without one, they are all required.
        pub tool: Option<&'a str>,
        pub command: Option<&'a str>,
        pub participants: &'a [String],
        pub reject: Option<&'a str>,
        pub ideal: Option<&'a str>,
        /// A JSON Schema, inline or the path of a file that holds it.
        pub schema: Option<&'a str>,
        pub threshold: Option<&'a str>,
        pub budget: Option<i64>,
        pub timeout: Option<i64>,
        pub retries: Option<i64>,
        pub slim_endpoint: &'a str,
        pub session: Option<&'a str>,
        pub report: Option<&'a str>,
    }

    /// How a member joins the group: its connection to the SLIM node and the
    /// identity it proves, as `register` does for its A2A listener.
    fn collaborate_config(
        name_id: &str,
        auth_id: &str,
        endpoint: &str,
        peers: &[String],
    ) -> anyhow::Result<CollaborateConfig> {
        let access = ClientAccess::from_env(Some(auth_id)).map_err(|e| anyhow!("{e}"))?;
        let auth = shadi_identity::require_did_auth_from_env(auth_id)
            .map_err(|e| anyhow!("SLIM auth error: {e}"))?;
        let mut config =
            CollaborateConfig::new(access.client_config(endpoint), auth, name_id, peers);
        config.timeout = Some(BROADCAST_TIMEOUT);
        Ok(config)
    }

    /// The harness for `tool`, as `register` opens it.
    fn open_adapter(
        tool: &str,
        command: Option<&str>,
        args: &[String],
    ) -> anyhow::Result<(String, Arc<dyn CliAdapter>)> {
        if tool == "generic-stdio" {
            let command = command
                .ok_or_else(|| anyhow!("--command is required for tool type 'generic-stdio'"))?;
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            let adapter = GenericStdioAdapter::spawn(tool, command, &args)?;
            return Ok((tool.to_string(), Arc::new(adapter)));
        }
        let spec = format!("{tool}:{}", work_dir(command).display());
        match open_profile_adapter(&spec).map_err(|e| anyhow!("{e}"))? {
            Some((id, adapter)) => Ok((id, Arc::new(adapter))),
            None => bail!("unknown tool type '{tool}'"),
        }
    }

    /// `register --protocol concord`: join the group and take part in the run
    /// that arrives, with the harness as the model. Returns when it ends.
    pub fn register(opts: MemberOptions<'_>) -> anyhow::Result<()> {
        let endpoint = opts
            .slim_endpoint
            .ok_or_else(|| anyhow!("--protocol concord needs --slim-endpoint"))?;
        if opts.peers.is_empty() {
            bail!(
                "--protocol concord needs --peer-agent-ids: the other members of the group, \
                 and the coordinator"
            );
        }
        // The harness reads what the peers write and acts on it, as it does for
        // a task: the same sandbox requirement as the A2A listener.
        require_sandbox_enforced(opts.tool, endpoint).map_err(|e| anyhow!("{e}"))?;
        let (id, adapter) = open_adapter(opts.tool, opts.command, opts.args)?;
        eprintln!(
            "⚠️  What the other members write is read by the local '{id}' CLI tool, as part of \
             its prompt. Only join groups of trusted peers."
        );

        let config = collaborate_config(&id, &id, endpoint, opts.peers)?;
        let channel = CollaborateChannel::connect(config).map_err(|e| anyhow!("{e}"))?;
        println!("Joined the CONCORD group as {id}; waiting for a run. Press Ctrl-C to stop.");
        let mut node = Node::new(
            Agent::new(&id)?,
            channel,
            HarnessResponder::new(Arc::clone(&adapter)),
            NodeConfig::default(),
        );
        node.observe(move |event| log_event(event, opts.verbose));
        stop_on_signal(node.stop_flag(), adapter);
        match node.run() {
            Ok(report) => finish(&report, None),
            Err(NodeError::Stopped) => {
                eprintln!("Stopped before the run ended.");
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// One line on stderr for an event of the run: its name and what it
    /// carries, cut short unless `verbose`.
    fn log_event(event: &Event, verbose: bool) {
        const SHORT: usize = 120;
        let details = serde_json::Value::Object(event.details.clone()).to_string();
        let details = if verbose || details.chars().count() <= SHORT {
            details
        } else {
            let cut: String = details.chars().take(SHORT).collect();
            format!("{cut}…")
        };
        eprintln!("concord: {} {details}", event.event);
    }

    /// On Ctrl-C or SIGTERM, tell the node to stop and kill the harness call
    /// in flight, so that no child outlives the agent.
    fn stop_on_signal(stop: Arc<AtomicBool>, adapter: Arc<dyn CliAdapter>) {
        let on_stop = Arc::clone(&stop);
        let for_adapter = Arc::clone(&adapter);
        let spawned = std::thread::Builder::new()
            .name("concord-signals".into())
            .spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return;
                };
                runtime.block_on(wait_for_signal());
                on_stop.store(true, Ordering::SeqCst);
                for_adapter.kill_in_flight();
            });
        if spawned.is_err() {
            eprintln!("Could not watch for Ctrl-C: the harness may outlive this process.");
        }
    }

    #[cfg(unix)]
    async fn wait_for_signal() {
        use tokio::signal::unix::{signal, SignalKind};
        let Ok(mut term) = signal(SignalKind::terminate()) else {
            let _ = tokio::signal::ctrl_c().await;
            return;
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }

    #[cfg(not(unix))]
    async fn wait_for_signal() {
        let _ = tokio::signal::ctrl_c().await;
    }

    /// An initiator that does not take part has no model to ask.
    struct NoModel;

    impl Responder for NoModel {
        fn respond(&mut self, task: &Task, _prompt: &str) -> Result<String, String> {
            Err(format!(
                "the coordinator is asked for a {} task, which is not its to answer",
                task.kind()
            ))
        }
    }

    /// The candidate schema: inline JSON, or the path of a file that holds it.
    fn read_schema(value: &str) -> anyhow::Result<serde_json::Value> {
        let text = if Path::new(value).is_file() {
            std::fs::read_to_string(value).with_context(|| format!("reading {value}"))?
        } else {
            value.to_string()
        };
        serde_json::from_str(&text)
            .map_err(|e| anyhow!("--schema is neither a JSON Schema nor the path of one: {e}"))
    }

    /// `coordinate --protocol concord`: open a run among `participants`, wait
    /// for it to end, and report how. With a `--tool`, a harness writes the
    /// anchors, the threshold and the shape of a candidate that are not given.
    pub fn coordinate(opts: CoordinateOptions<'_>) -> anyhow::Result<()> {
        if opts.participants.len() < 2 {
            bail!("--protocol concord needs --participants: at least two agent ids");
        }
        let given = Given {
            reject: opts.reject.map(str::to_string),
            ideal: opts.ideal.map(str::to_string),
            schema: opts.schema.map(read_schema).transpose()?,
            threshold: opts.threshold.map(str::to_string),
        };
        if opts.tool.is_none() {
            // nothing writes the frame: the command line has to
            for (flag, present) in [
                ("--reject", given.reject.is_some()),
                ("--ideal", given.ideal.is_some()),
                ("--schema", given.schema.is_some()),
            ] {
                if !present {
                    bail!("--protocol concord needs {flag}, or --tool to have a harness write it");
                }
            }
        }

        // The harness reads what the goal says and the members' replies, and
        // acts on it: the same sandbox requirement as for a member.
        let adapter = match opts.tool {
            Some(tool) => {
                require_sandbox_enforced(tool, opts.slim_endpoint).map_err(|e| anyhow!("{e}"))?;
                let (_, adapter) = open_adapter(tool, opts.command, &[])?;
                Some(adapter)
            }
            None => None,
        };
        let responder: Box<dyn Responder> = match &adapter {
            Some(adapter) => Box::new(HarnessResponder::new(Arc::clone(adapter))),
            None => Box::new(NoModel),
        };

        // The members name this id among their peers to reach the coordinator.
        let id = match opts.session {
            Some(session) => format!("{COORDINATOR}-{session}"),
            None => COORDINATOR.to_string(),
        };
        let config = collaborate_config(&id, COORDINATOR, opts.slim_endpoint, opts.participants)?;
        let channel = CollaborateChannel::connect(config).map_err(|e| anyhow!("{e}"))?;
        let mut node = Node::new(Agent::new(&id)?, channel, responder, NodeConfig::default());
        node.observe(|event| log_event(event, false));
        if let Some(adapter) = adapter {
            stop_on_signal(node.stop_flag(), adapter);
        }

        let frame = if given.is_complete() {
            given
        } else {
            println!("Asking the initiator's harness to write the frame of the run...");
            match node.write_init(opts.goal, opts.participants, &given) {
                Ok(frame) => frame,
                Err(NodeError::Stopped) => {
                    eprintln!("Stopped before the run was opened.");
                    return Ok(());
                }
                Err(error) => return Err(error.into()),
            }
        };
        let (Some(reject), Some(ideal), Some(schema)) = (frame.reject, frame.ideal, frame.schema)
        else {
            bail!("the frame of the run is incomplete");
        };
        println!("Frame of the run:");
        println!("  x_reject:  {reject}");
        println!("  x_ideal:   {ideal}");
        println!("  schema:    {schema}");
        if let Some(threshold) = &frame.threshold {
            println!("  threshold: {threshold}");
        }

        let mut params = InitParams::default();
        if let Some(threshold) = &frame.threshold {
            params = params.satisfaction_threshold(threshold);
        }
        if let Some(budget) = opts.budget {
            params = params.budget(budget);
        }
        if let Some(timeout) = opts.timeout {
            params = params.timeout(timeout);
        }
        if let Some(retries) = opts.retries {
            params = params.retries(retries);
        }
        let init = ConcordInit {
            participants: opts.participants.to_vec(),
            context: opts.goal.to_string(),
            x_reject: reject,
            x_ideal: ideal,
            schema,
            params,
        };

        println!(
            "Opening a CONCORD run as {id} among {}. The members must already be running.",
            opts.participants.join(", ")
        );
        node.start(&init)?;
        match node.run() {
            Ok(report) => finish(&report, opts.report),
            Err(NodeError::Stopped) => {
                eprintln!("Stopped before the run ended.");
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Print the report, write it when asked, and turn an aborted run into an
    /// error.
    fn finish(report: &Report, path: Option<&str>) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(report)?;
        println!("{json}");
        if let Some(path) = path {
            std::fs::write(path, &json).with_context(|| format!("writing {path}"))?;
        }
        if report.outcome == Some(Outcome::Aborted) {
            bail!("the run was aborted: {:?}", report.reason);
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn options<'a>(participants: &'a [String]) -> CoordinateOptions<'a> {
            CoordinateOptions {
                goal: "pick one",
                tool: None,
                command: None,
                participants,
                reject: Some("nothing is decided"),
                ideal: Some("everyone is satisfied"),
                schema: Some(r#"{"type":"string"}"#),
                threshold: None,
                budget: None,
                timeout: None,
                retries: None,
                slim_endpoint: "127.0.0.1:1",
                session: None,
                report: None,
            }
        }

        fn names(ids: &[&str]) -> Vec<String> {
            ids.iter().map(ToString::to_string).collect()
        }

        #[test]
        fn a_schema_is_read_inline_or_from_a_file() {
            let inline = read_schema(r#"{"type":"string","description":"one city"}"#).unwrap();
            assert_eq!(inline["description"], "one city");

            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("schema.json");
            std::fs::write(&path, r#"{"type":"integer"}"#).unwrap();
            let from_file = read_schema(path.to_str().unwrap()).unwrap();
            assert_eq!(from_file["type"], "integer");
        }

        #[test]
        fn a_schema_that_is_neither_is_refused_with_the_reason() {
            let error = read_schema("not json and not a file")
                .unwrap_err()
                .to_string();
            assert!(error.contains("--schema"), "{error}");
        }

        #[test]
        fn a_run_needs_two_participants() {
            let one = names(&["a"]);
            let error = coordinate(options(&one)).unwrap_err().to_string();
            assert!(error.contains("--participants"), "{error}");
        }

        #[test]
        fn the_anchors_and_the_schema_are_required() {
            let two = names(&["a", "b"]);
            for (flag, mut opts) in [
                ("--reject", options(&two)),
                ("--ideal", options(&two)),
                ("--schema", options(&two)),
            ] {
                match flag {
                    "--reject" => opts.reject = None,
                    "--ideal" => opts.ideal = None,
                    _ => opts.schema = None,
                }
                let error = coordinate(opts).unwrap_err().to_string();
                assert!(error.contains(flag), "{flag}: {error}");
            }
        }

        #[test]
        fn a_member_needs_an_endpoint_and_peers_before_anything_else() {
            let peers = names(&["b"]);
            let no_endpoint = register(MemberOptions {
                tool: "claude-code",
                command: None,
                args: &[],
                slim_endpoint: None,
                peers: &peers,
                verbose: false,
            })
            .unwrap_err()
            .to_string();
            assert!(no_endpoint.contains("--slim-endpoint"), "{no_endpoint}");

            let no_peers = register(MemberOptions {
                tool: "claude-code",
                command: None,
                args: &[],
                slim_endpoint: Some("127.0.0.1:1"),
                peers: &[],
                verbose: false,
            })
            .unwrap_err()
            .to_string();
            assert!(no_peers.contains("--peer-agent-ids"), "{no_peers}");
        }
    }
}
