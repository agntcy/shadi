// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! One member's end of an A2A Collaborate group on SLIM.
//!
//! A group is many-to-many, so every member plays two roles: a listener that
//! receives what the others broadcast ([`register_collaborate`]), and a group
//! channel that broadcasts its own messages to every peer
//! ([`A2AGroupChannel`]). [`CollaborateGroup::join`] sets up both on one SLIM
//! connection, and a caller does the sending and receiving.
//!
//! The caller owns the tokio runtime and runs the listener on it.

use std::ops::Deref;
use std::sync::Arc;

use a2a::Message;
use agent_secrets::{AgentVerifier, SessionContext};
use shadi_identity::SlimAuth;
use slim_bindings::{ClientConfig, Name, Service};
use slim_rpc::Server;
use tokio::runtime::Handle;

use crate::{register_collaborate, A2AGroupChannel, A2AGroupChannelBuilder};

/// What a member needs to join a group.
pub struct CollaborateGroupConfig {
    /// How this process reaches the SLIM node, with its transport security.
    pub client: ClientConfig,
    /// How this member proves who it is.
    pub auth: SlimAuth,
    /// The name of the SLIM service this member starts.
    pub service_name: String,
    /// The agent id the group channel's session is for.
    pub agent_id: String,
    /// The id of that session.
    pub session_id: String,
    /// This member's SLIM name, `organization/namespace/application`.
    pub local_name: String,
    /// The SLIM names of the other members, in the same form.
    pub peers: Vec<String>,
    /// The check every broadcast passes before it leaves.
    pub verifier: Arc<dyn AgentVerifier>,
}

/// A member of a Collaborate group: the SLIM connection, the listener and the
/// channel to the peers.
pub struct CollaborateGroup {
    service: Service,
    app: Arc<slim_bindings::App>,
    connection_id: u64,
    local_name: Arc<Name>,
    server: Arc<Server>,
    channel: A2AGroupChannel,
}

impl CollaborateGroup {
    /// Connect to SLIM, subscribe this member, register `on_message` as the
    /// listener and build the channel to the peers. The listener runs once the
    /// caller serves [`Self::server`].
    ///
    /// The listener and the channel capture the current tokio runtime when
    /// they are built, so they are built on `runtime`.
    pub fn join(
        runtime: &Handle,
        config: CollaborateGroupConfig,
        on_message: impl Fn(Message) + Send + Sync + 'static,
    ) -> Result<Self, String> {
        let CollaborateGroupConfig {
            client,
            auth,
            service_name,
            agent_id,
            session_id,
            local_name,
            peers,
            verifier,
        } = config;
        let local_name = Arc::new(parse_name(&local_name)?);
        let peer_names: Vec<Arc<Name>> = peers
            .iter()
            .map(|peer| parse_name(peer).map(Arc::new))
            .collect::<Result<_, _>>()?;
        if peer_names.is_empty() {
            return Err("a Collaborate group needs at least one peer".to_string());
        }

        // stops the service when a step below fails
        let service = Started::new(Service::new(service_name));
        let connection_id = service.connect(client).map_err(|e| e.to_string())?;
        let app = shadi_identity::create_app(&service, local_name.clone(), &auth)
            .map_err(|e| e.to_string())?;
        app.subscribe(local_name.clone(), Some(connection_id))
            .map_err(|e| e.to_string())?;

        let mut session = SessionContext::new(&agent_id, &session_id);
        session.verified = true;
        let _enter = runtime.enter();
        let server = Arc::new(Server::new_with_shared_rx_and_connection(
            app.inner(),
            app.name().as_slim_name(),
            None,
            app.notification_receiver(),
            Some(runtime.clone()),
        ));
        register_collaborate(server.as_ref(), on_message);
        let channel = A2AGroupChannelBuilder::new(app.clone(), peer_names, verifier, session)
            .connection_id(connection_id)
            .build()
            .map_err(|e| format!("failed to build the group channel: {e}"))?;
        Ok(Self {
            service: service.keep(),
            app,
            connection_id,
            local_name,
            server,
            channel,
        })
    }

    /// The channel that broadcasts to the peers.
    pub fn channel(&self) -> &A2AGroupChannel {
        &self.channel
    }

    /// The listener. Serve it on the runtime (`server.serve().await`) and stop
    /// it with `server.shutdown().await`.
    pub fn server(&self) -> Arc<Server> {
        self.server.clone()
    }

    /// Leave the group: drop the subscription and the connection, and stop
    /// the SLIM service.
    pub fn leave(self) {
        let _ = self
            .app
            .unsubscribe(self.local_name, Some(self.connection_id));
        let _ = self.service.disconnect(self.connection_id);
        let _ = self.service.shutdown();
    }
}

/// A SLIM service that is shut down when dropped, unless it is [kept](Self::keep).
struct Started(Option<Service>);

impl Started {
    fn new(service: Service) -> Self {
        Self(Some(service))
    }

    fn keep(mut self) -> Service {
        self.0.take().expect("the service is taken once")
    }
}

impl Deref for Started {
    type Target = Service;

    fn deref(&self) -> &Service {
        self.0.as_ref().expect("the service is taken once")
    }
}

impl Drop for Started {
    fn drop(&mut self) {
        if let Some(service) = self.0.take() {
            let _ = service.shutdown();
        }
    }
}

fn parse_name(raw: &str) -> Result<Name, String> {
    Name::from_string(raw.to_string()).map_err(|e| {
        format!("invalid SLIM name {raw}: {e} (expected organization/namespace/application)")
    })
}
