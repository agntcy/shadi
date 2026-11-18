// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! The CONCORD broadcast channel over A2A Collaborate on SLIM.
//!
//! Each member runs two halves, as in `shadictl slim a2a-collaborate`: a
//! listener that receives what the others broadcast, and a group channel that
//! broadcasts its own messages to every peer, one Collaborate call per
//! message. [`CollaborateChannel`] holds
//! both on a thread of its own and gives the node the blocking [`Channel`] it
//! expects.
//!
//! The listener path carries no proven sender, so a message is attributed
//! only by the author it names inside.

use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use a2a::Message;
use agent_secrets::SessionContext;
use agentbridge::concord::binding;
use agentbridge::concord::channel::Channel;
use futures::channel::mpsc as async_mpsc;
use futures::StreamExt;
use shadi_a2a::{register_collaborate, A2AGroupChannelBuilder};
use shadi_identity::SlimAuth;
use slim_bindings::{ClientConfig, Name, Service};
use slim_rpc::Server;
use tokio::runtime::Builder as TokioRuntimeBuilder;

use super::egress;

/// How long to wait, after connecting, for the other members to finish
/// subscribing. The group's invite has no retry, so one that lands before a
/// peer is ready is missed.
const DEFAULT_SETTLE: Duration = Duration::from_secs(2);

/// How long `connect` waits for the channel to come up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// What a member needs to join the group.
pub struct CollaborateConfig {
    /// How this process reaches the SLIM node, with its transport security.
    pub client: ClientConfig,
    /// How this member proves who it is.
    pub auth: SlimAuth,
    /// This member's agent id.
    pub agent_id: String,
    /// The agent ids of the other members.
    pub peers: Vec<String>,
    /// The time limit of the Collaborate call, or none.
    pub timeout: Option<Duration>,
    /// Wait this long before broadcasting, so the peers are listening.
    pub settle: Duration,
}

impl CollaborateConfig {
    pub fn new(client: ClientConfig, auth: SlimAuth, agent_id: &str, peers: &[String]) -> Self {
        Self {
            client,
            auth,
            agent_id: agent_id.to_string(),
            peers: peers.to_vec(),
            timeout: None,
            settle: DEFAULT_SETTLE,
        }
    }
}

/// The SLIM name a member of a CONCORD group answers to: the listener name
/// `register` already uses for the agent.
pub fn member_name(agent_id: &str) -> String {
    if agent_id.contains('/') {
        agent_id.to_string()
    } else {
        format!("agntcy/shadi/{agent_id}-a2a")
    }
}

fn parse_name(raw: &str) -> Result<Name, String> {
    Name::from_string(raw.to_string()).map_err(|e| {
        format!("invalid SLIM name {raw}: {e} (expected organization/namespace/application)")
    })
}

/// One member's end of a CONCORD group.
pub struct CollaborateChannel {
    inbound: mpsc::Receiver<String>,
    outbound: async_mpsc::UnboundedSender<Message>,
}

impl CollaborateChannel {
    /// Join the group. Returns once the listener is up; the group session to
    /// the peers opens after `config.settle`.
    pub fn connect(config: CollaborateConfig) -> Result<Self, String> {
        let (inbound_tx, inbound) = mpsc::channel();
        let (outbound, outbound_rx) = async_mpsc::unbounded();
        let (ready_tx, ready_rx) = mpsc::channel();
        thread::Builder::new()
            .name(format!("concord-{}", config.agent_id))
            .spawn(move || run(config, inbound_tx, outbound_rx, ready_tx))
            .map_err(|e| format!("failed to start the group thread: {e}"))?;
        ready_rx
            .recv_timeout(CONNECT_TIMEOUT)
            .map_err(|_| "the group channel did not come up in time".to_string())??;
        Ok(Self { inbound, outbound })
    }
}

impl Channel for CollaborateChannel {
    fn broadcast(&mut self, text: &str) -> Result<(), String> {
        self.outbound
            .unbounded_send(binding::message(text))
            .map_err(|_| "the group channel is closed".to_string())
    }

    fn recv(&mut self, wait: Duration) -> Result<Option<String>, String> {
        match self.inbound.recv_timeout(wait) {
            Ok(text) => Ok(Some(text)),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err("the group channel is closed".to_string()),
        }
    }
}

/// The thread of a member: connect, listen, and broadcast until the channel
/// is dropped or the group call ends.
fn run(
    config: CollaborateConfig,
    inbound: mpsc::Sender<String>,
    outbound: async_mpsc::UnboundedReceiver<Message>,
    ready: mpsc::Sender<Result<(), String>>,
) {
    let ready_in = ready.clone();
    let result = (|| -> Result<(), String> {
        let CollaborateConfig {
            client,
            auth,
            agent_id,
            peers,
            timeout,
            settle,
        } = config;
        let local = member_name(&agent_id);
        let local_name = Arc::new(parse_name(&local)?);
        let peer_names: Vec<Arc<Name>> = peers
            .iter()
            .map(|p| parse_name(&member_name(p)).map(Arc::new))
            .collect::<Result<_, _>>()?;
        if peer_names.is_empty() {
            return Err("a CONCORD group needs at least one peer".to_string());
        }

        let service = Service::new(format!(
            "agentbridge-concord-{agent_id}-{}",
            std::process::id()
        ));
        let connection_id = service.connect(client).map_err(|e| e.to_string())?;
        let app = shadi_identity::create_app(&service, local_name.clone(), &auth)
            .map_err(|e| e.to_string())?;
        app.subscribe(local_name.clone(), Some(connection_id))
            .map_err(|e| e.to_string())?;

        let runtime = TokioRuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("failed to create a tokio runtime: {e}"))?;
        let mut session = SessionContext::new(&agent_id, "concord-collaborate");
        session.verified = true;
        let (server, channel) = {
            let _enter = runtime.enter();
            let server = Arc::new(Server::new_with_shared_rx_and_connection(
                app.inner(),
                app.name().as_slim_name(),
                None,
                app.notification_receiver(),
                Some(runtime.handle().clone()),
            ));
            register_collaborate(server.as_ref(), move |message| {
                for text in binding::texts(&message) {
                    // the node is gone: nobody to tell
                    let _ = inbound.send(text);
                }
            });
            let channel =
                A2AGroupChannelBuilder::new(app.clone(), peer_names, egress::policy(), session)
                    .connection_id(connection_id)
                    .build()
                    .map_err(|e| format!("failed to build the group channel: {e}"))?;
            (server, channel)
        };

        runtime.block_on(async move {
            let serving = {
                let server = server.clone();
                tokio::spawn(async move { server.serve().await })
            };
            let _ = ready_in.send(Ok(()));
            tokio::time::sleep(settle).await;
            // A listener answers a Collaborate call with an empty reply
            // stream, which ends the call for the sender once every peer has.
            // So a stream that outlives one message cannot work: each
            // broadcast is a call of its own.
            let mut outbound = outbound;
            while let Some(message) = outbound.next().await {
                let call = channel
                    .collaborate(futures::stream::once(async move { message }), timeout)
                    .map_err(|e| format!("failed to open the group: {e}"));
                let replies = match call {
                    Ok(replies) => replies,
                    Err(error) => {
                        tracing::warn!(%error, "concord: a message was not broadcast");
                        continue;
                    }
                };
                futures::pin_mut!(replies);
                while let Some(reply) = replies.next().await {
                    if let Err(error) = reply {
                        tracing::warn!(%error, "concord: the group call reported an error");
                    }
                }
            }
            server.shutdown().await;
            let _ = serving.await;
            Ok::<(), String>(())
        })?;
        let _ = app.unsubscribe(local_name, Some(connection_id));
        let _ = service.disconnect(connection_id);
        let _ = service.shutdown();
        Ok(())
    })();
    if let Err(error) = result {
        // before `ready` was sent this is the reason `connect` fails; after,
        // the node finds the channel closed
        let _ = ready.send(Err(error.clone()));
        tracing::warn!(%error, "concord: the group thread ended");
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::time::Instant;

    const SECRET: &str = "concord-collaborate-test-secret-0123456789";

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    /// A SLIM node in this process, and the config a member uses to reach it.
    pub(crate) fn node() -> (Service, String) {
        slim_config::tls::provider::initialize_crypto_provider();
        let addr = format!("127.0.0.1:{}", free_port());
        let service = Service::new("concord-test-node".to_string());
        service
            .run_server(slim_bindings::new_insecure_server_config(addr.clone()))
            .unwrap();
        std::thread::sleep(Duration::from_millis(300));
        (service, format!("http://{addr}"))
    }

    pub(crate) fn member(
        url: &str,
        id: &str,
        all: &[&str],
        timeout: Option<Duration>,
    ) -> CollaborateChannel {
        let peers: Vec<String> = all
            .iter()
            .filter(|p| **p != id)
            .map(ToString::to_string)
            .collect();
        let mut config = CollaborateConfig::new(
            slim_bindings::new_insecure_client_config(url.to_string()),
            SlimAuth::SharedSecret(SECRET.to_string()),
            id,
            &peers,
        );
        config.timeout = timeout;
        config.settle = Duration::from_secs(1);
        CollaborateChannel::connect(config).unwrap()
    }

    pub(crate) fn recv_within(channel: &mut CollaborateChannel, limit: Duration) -> Option<String> {
        let start = Instant::now();
        while start.elapsed() < limit {
            if let Some(text) = channel.recv(Duration::from_millis(100)).unwrap() {
                return Some(text);
            }
        }
        None
    }

    #[test]
    fn member_names_follow_the_listener_convention() {
        assert_eq!(member_name("claude-code"), "agntcy/shadi/claude-code-a2a");
        assert_eq!(member_name("org/ns/app"), "org/ns/app");
    }

    // Starting a SLIM service installs a process-wide tracing subscriber, and
    // the span tests of `register` in this binary install theirs once too, so
    // the two cannot share a run. Run these alone:
    //   cargo test -p agntcy-agentbridge-cli --features concord -- --ignored concord_channel
    #[test]
    #[ignore = "starts a SLIM node, which sets a global tracing subscriber"]
    fn a_broadcast_reaches_every_other_member_and_not_the_sender() {
        let (_node, url) = node();
        let ids = ["a", "b", "c"];
        let mut a = member(&url, "a", &ids, None);
        let mut b = member(&url, "b", &ids, None);
        let mut c = member(&url, "c", &ids, None);
        std::thread::sleep(Duration::from_secs(2));
        a.broadcast("<concord-init>hello</concord-init>").unwrap();
        let limit = Duration::from_secs(10);
        assert_eq!(
            recv_within(&mut b, limit).as_deref(),
            Some("<concord-init>hello</concord-init>")
        );
        assert_eq!(
            recv_within(&mut c, limit).as_deref(),
            Some("<concord-init>hello</concord-init>")
        );
        assert_eq!(
            recv_within(&mut a, Duration::from_secs(1)),
            None,
            "a must not hear itself"
        );
    }

    #[test]
    #[ignore = "starts a SLIM node, which sets a global tracing subscriber"]
    fn messages_arrive_in_the_order_they_were_sent() {
        let (_node, url) = node();
        let ids = ["a", "b"];
        let mut a = member(&url, "a", &ids, Some(Duration::from_secs(10)));
        let mut b = member(&url, "b", &ids, Some(Duration::from_secs(10)));
        std::thread::sleep(Duration::from_secs(2));
        let start = Instant::now();
        for n in 1..=5 {
            a.broadcast(&format!("m{n}")).unwrap();
        }
        let got: Vec<_> = (0..5)
            .filter_map(|_| recv_within(&mut b, Duration::from_secs(20)))
            .collect();
        println!("PROBE 5 messages in {:?}: {got:?}", start.elapsed());
        assert_eq!(got, ["m1", "m2", "m3", "m4", "m5"]);
    }

    #[test]
    #[ignore = "starts a SLIM node, which sets a global tracing subscriber"]
    fn a_member_can_keep_sending_after_a_long_pause() {
        let (_node, url) = node();
        let ids = ["a", "b"];
        let mut a = member(&url, "a", &ids, Some(Duration::from_secs(10)));
        let mut b = member(&url, "b", &ids, Some(Duration::from_secs(10)));
        std::thread::sleep(Duration::from_secs(2));
        a.broadcast("early").unwrap();
        assert_eq!(
            recv_within(&mut b, Duration::from_secs(10)).as_deref(),
            Some("early")
        );
        std::thread::sleep(Duration::from_secs(12));
        a.broadcast("late").unwrap();
        assert_eq!(
            recv_within(&mut b, Duration::from_secs(10)).as_deref(),
            Some("late")
        );
        b.broadcast("reply").unwrap();
        assert_eq!(
            recv_within(&mut a, Duration::from_secs(10)).as_deref(),
            Some("reply")
        );
    }
}
