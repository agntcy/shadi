// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! The CONCORD broadcast channel over A2A Collaborate on SLIM.
//!
//! Each member runs two halves, as in `shadictl slim a2a-collaborate`: a
//! listener that receives what the others broadcast, and a group channel that
//! broadcasts its own messages to every peer, one Collaborate call per
//! message. [`CollaborateChannel`] holds both on a thread of its own and gives
//! the node the blocking [`Channel`] it expects.
//!
//! The listener path carries no proven sender, so a message is attributed
//! only by the author it names inside.

use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use a2a::Message;
use agentbridge::concord::binding;
use agentbridge::concord::channel::Channel;
use futures::channel::mpsc as async_mpsc;
use futures::StreamExt;
use shadi_a2a::{CollaborateGroup, CollaborateGroupConfig};
use shadi_identity::SlimAuth;
use slim_bindings::ClientConfig;
use tokio::runtime::Builder as TokioRuntimeBuilder;

use super::egress;

/// How long to wait, after connecting, for the other members to finish
/// subscribing. The group's invite has no retry, so one that lands before a
/// peer is ready is missed.
const DEFAULT_SETTLE: Duration = Duration::from_secs(2);

/// How long `connect` waits for the channel to come up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// How long dropping the channel waits for the messages still queued to be
/// sent.
const FLUSH_TIMEOUT: Duration = Duration::from_secs(15);

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

/// One member's end of a CONCORD group.
pub struct CollaborateChannel {
    inbound: mpsc::Receiver<String>,
    outbound: Option<async_mpsc::UnboundedSender<Message>>,
    /// Told when everything queued has been sent.
    drained: mpsc::Receiver<()>,
}

impl CollaborateChannel {
    /// Join the group. Returns once the listener is up; the group session to
    /// the peers opens after `config.settle`.
    pub fn connect(config: CollaborateConfig) -> Result<Self, String> {
        let (inbound_tx, inbound) = mpsc::channel();
        let (outbound, outbound_rx) = async_mpsc::unbounded();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (drained_tx, drained) = mpsc::channel();
        thread::Builder::new()
            .name(format!("concord-{}", config.agent_id))
            .spawn(move || run(config, inbound_tx, outbound_rx, ready_tx, drained_tx))
            .map_err(|e| format!("failed to start the group thread: {e}"))?;
        ready_rx
            .recv_timeout(CONNECT_TIMEOUT)
            .map_err(|_| "the group channel did not come up in time".to_string())??;
        Ok(Self {
            inbound,
            outbound: Some(outbound),
            drained,
        })
    }
}

impl CollaborateChannel {
    /// Close the channel for sending and wait for the messages still queued to
    /// be sent. `false` when they were not all sent in time.
    pub fn flush(&mut self) -> bool {
        // closing the queue lets the thread send what is left and say so
        self.outbound = None;
        self.drained.recv_timeout(FLUSH_TIMEOUT).is_ok()
    }
}

impl Drop for CollaborateChannel {
    /// Send what is still queued before the member goes: a node that ends the
    /// run right after broadcasting its last message (the result, for the
    /// agent that reports it) would otherwise take the message down with its
    /// process, and the others would wait for it forever.
    fn drop(&mut self) {
        if self.outbound.is_some() && !self.flush() {
            tracing::warn!("concord: the last messages may not have been sent");
        }
    }
}

impl Channel for CollaborateChannel {
    fn broadcast(&mut self, text: &str) -> Result<(), String> {
        self.outbound
            .as_ref()
            .ok_or_else(|| "the group channel is closed".to_string())?
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
    drained: mpsc::Sender<()>,
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
        let runtime = TokioRuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("failed to create a tokio runtime: {e}"))?;
        let group = CollaborateGroup::join(
            runtime.handle(),
            CollaborateGroupConfig {
                client,
                auth,
                service_name: format!("agentbridge-concord-{agent_id}-{}", std::process::id()),
                local_name: member_name(&agent_id),
                peers: peers.iter().map(|p| member_name(p)).collect(),
                session_id: "concord-collaborate".to_string(),
                agent_id,
                verifier: egress::policy(),
            },
            move |message| {
                for text in binding::texts(&message) {
                    // the node is gone: nobody to tell
                    let _ = inbound.send(text);
                }
            },
        )?;
        let server = group.server();

        runtime.block_on(async {
            let serving = {
                let server = server.clone();
                tokio::spawn(async move { server.serve().await })
            };
            let _ = ready_in.send(Ok(()));
            tokio::time::sleep(settle).await;
            // One call per broadcast, so the end of the call tells `flush` the
            // message reached the peers. A single call would also deliver
            // every message, but its replies end early and would not say when
            // each was sent.
            let mut outbound = outbound;
            while let Some(message) = outbound.next().await {
                let call = group
                    .channel()
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
            // every queued message has been sent; what follows is teardown
            let _ = drained.send(());
            server.shutdown().await;
            let _ = serving.await;
            Ok::<(), String>(())
        })?;
        group.leave();
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
    use slim_bindings::Service;
    use std::sync::Arc;
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
    fn what_is_queued_when_a_member_closes_is_sent_first() {
        let (_node, url) = node();
        let ids = ["a", "b"];
        let mut a = member(&url, "a", &ids, None);
        let mut b = member(&url, "b", &ids, None);
        std::thread::sleep(Duration::from_secs(2));
        // the last messages of a node, as it ends: the process goes right after
        for n in 1..=3 {
            a.broadcast(&format!("<concord-result>{n}</concord-result>"))
                .unwrap();
        }
        assert!(a.flush(), "the queued messages were not all sent");
        assert!(
            a.broadcast("late").is_err(),
            "a closed channel takes nothing"
        );
        for n in 1..=3 {
            assert_eq!(
                recv_within(&mut b, Duration::from_secs(5)).as_deref(),
                Some(format!("<concord-result>{n}</concord-result>").as_str())
            );
        }
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

    /// A member of a group, driven by the caller: what it receives lands in `got`.
    fn group(
        rt: &tokio::runtime::Runtime,
        url: &str,
        id: &str,
        peer: &str,
        got: Arc<std::sync::Mutex<Vec<String>>>,
    ) -> CollaborateGroup {
        let group = CollaborateGroup::join(
            rt.handle(),
            CollaborateGroupConfig {
                client: slim_bindings::new_insecure_client_config(url.to_string()),
                auth: SlimAuth::SharedSecret(SECRET.to_string()),
                service_name: format!("concord-test-{id}"),
                agent_id: id.to_string(),
                session_id: "concord-test".to_string(),
                local_name: member_name(id),
                peers: vec![member_name(peer)],
                verifier: egress::policy(),
            },
            move |message| got.lock().unwrap().extend(binding::texts(&message)),
        )
        .unwrap();
        let server = group.server();
        rt.spawn(async move {
            let _ = server.serve().await;
        });
        group
    }

    /// Wait for `done`, at most `limit`; the test asserts what it needs after.
    fn wait_until(limit: Duration, done: impl Fn() -> bool) {
        let start = Instant::now();
        while !done() && start.elapsed() < limit {
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The group's calls need a runtime that runs while the test sleeps.
    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    }

    // What the channel relies on in the group call, measured:
    //
    // - a call made before a peer has joined is held until it has, and then
    //   delivers (so no settling time is needed before the first message);
    // - the replies of a call end as soon as the peers have answered, which
    //   does not stop what the call is still sending: a stream that outlives
    //   one message still delivers every message.

    #[test]
    #[ignore = "starts a SLIM node, which sets a global tracing subscriber"]
    fn a_call_made_before_a_peer_joined_is_held_and_then_delivers() {
        let (_node, url) = node();
        let rt = runtime();
        let got = Arc::new(std::sync::Mutex::new(Vec::new()));
        let a = group(&rt, &url, "a", "b", Arc::default());
        let call = a
            .channel()
            .collaborate(
                futures::stream::once(async { binding::message("early") }),
                Some(Duration::from_secs(15)),
            )
            .unwrap();
        let done = rt.spawn(async move { call.collect::<Vec<_>>().await });
        // nobody is there to answer yet; a call that gave up at once would end
        // well within this time
        std::thread::sleep(Duration::from_secs(1));
        assert!(!done.is_finished(), "the call must wait for the peer");
        let _b = group(&rt, &url, "b", "a", got.clone());
        rt.block_on(done).unwrap();
        wait_until(Duration::from_secs(10), || got.lock().unwrap().len() == 1);
        assert_eq!(*got.lock().unwrap(), ["early"]);
    }

    #[test]
    #[ignore = "starts a SLIM node, which sets a global tracing subscriber"]
    fn one_call_delivers_messages_sent_long_after_its_replies_ended() {
        let (_node, url) = node();
        let rt = runtime();
        let got = Arc::new(std::sync::Mutex::new(Vec::new()));
        let _b = group(&rt, &url, "b", "a", got.clone());
        let a = group(&rt, &url, "a", "b", Arc::default());
        let slow = futures::stream::unfold(1u32, |n| async move {
            if n > 4 {
                return None;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            Some((binding::message(&format!("m{n}")), n + 1))
        });
        let replies = rt.block_on(async {
            let replies = a
                .channel()
                .collaborate(slow, Some(Duration::from_secs(15)))
                .unwrap();
            replies.collect::<Vec<_>>().await
        });
        // the replies are over after one answer round, long before m4 was sent
        assert!(replies.len() <= 1);
        wait_until(Duration::from_secs(20), || got.lock().unwrap().len() == 4);
        assert_eq!(*got.lock().unwrap(), ["m1", "m2", "m3", "m4"]);
    }
}
