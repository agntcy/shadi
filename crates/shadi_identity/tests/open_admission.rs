// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Open admission end to end, over real SLIM sessions.
//!
//! Each test starts an in-process SLIM node on a free loopback port and attaches
//! apps to it. Every app is created through [`create_app`], so the custom identity
//! path is the one exercised: an open listener ([`SlimAuth::did_open`]) and callers
//! pinned to the listener's DID ([`build_did_auth_for_peer`]). The loopback link is
//! plaintext: admission is decided by the DID-JWT each app presents, not by the
//! transport.
//!
//! The tests are synchronous. The SLIM bindings block on their own runtime, which
//! would panic inside a `#[tokio::test]`. Every SLIM call that can wait runs on a
//! worker thread under a deadline, so a stalled session fails the test instead of
//! hanging the run.

use std::collections::HashMap;
use std::future::Future;
use std::net::TcpListener;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use serde_json::{json, Value};
use shadi_identity::{
    build_did_auth_for_peer, create_app, AgentIdentity, DidKeyVerifier, SlimAuth, DID_JWT_AUDIENCE,
};
use slim_auth::traits::Verifier;
use slim_bindings::{
    generate_signature_keys, new_insecure_client_config, new_insecure_server_config, App,
    Direction, IdentityCallbackError, IdentityExport, IdentityProvider, IdentityVerifier,
    MlsSettings, Name, Service, Session, SessionConfig, SessionType, SignatureKeys,
};

/// Deadline for a session that should succeed. A bound against a hang, not a
/// performance expectation.
const SESSION_TIMEOUT: Duration = Duration::from_secs(10);

/// Deadline for a session that should be refused: the refused caller must report an
/// error within it. SLIM does so after about three seconds; still running at this
/// deadline counts as a hang and fails the test.
const REFUSAL_TIMEOUT: Duration = Duration::from_secs(5);

/// Pause after a subscribe or a route change, so the node has learned it before the
/// next session is routed. SLIM has no readiness signal for this; the SLIM tests in
/// other crates settle the same way.
const SETTLE: Duration = Duration::from_millis(300);

const LISTENER_NAME: &str = "agntcy/open-admission/listener";
const CALLER_NAME: &str = "agntcy/open-admission/caller";
const PING: &[u8] = b"ping";
const PONG: &[u8] = b"pong";

static SERVICE_COUNT: AtomicUsize = AtomicUsize::new(0);

/// A SLIM service on this process, with a name unique to this run.
fn new_service(role: &str) -> Service {
    let n = SERVICE_COUNT.fetch_add(1, Ordering::Relaxed);
    Service::new(format!("open-admission-{role}-{}-{n}", std::process::id()))
}

fn name(s: &str) -> Arc<Name> {
    Arc::new(Name::from_string(s.to_string()).expect("valid SLIM name"))
}

/// Point-to-point with MLS, as `agent_transport_slim` configures it. The retry budget
/// is short: a refused session fails after the initial send and two retries a second
/// apart, about three seconds, inside [`REFUSAL_TIMEOUT`]. An honest session completes
/// on loopback well before its first retry is due.
fn session_config() -> SessionConfig {
    SessionConfig {
        session_type: SessionType::PointToPoint,
        mls_settings: Some(MlsSettings::default()),
        max_retries: Some(2),
        interval: Some(Duration::from_secs(1)),
        metadata: HashMap::new(),
    }
}

/// A loopback address with a free port: bind, read, release. Each test asks for its
/// own, so tests can run in parallel.
fn free_loopback_endpoint() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    let endpoint = listener.local_addr().expect("local addr").to_string();
    drop(listener);
    endpoint
}

/// Run `f` on a worker thread and return the receiver for its result. A panic in
/// `f` drops the sender, which [`wait_for`] reports as a panic, not a timeout.
fn spawn_call<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> mpsc::Receiver<T> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx
}

/// The result of a [`spawn_call`], or `None` if it did not finish within `limit`.
fn wait_for<T>(rx: &mpsc::Receiver<T>, limit: Duration) -> Option<T> {
    match rx.recv_timeout(limit) {
        Ok(value) => Some(value),
        Err(RecvTimeoutError::Timeout) => None,
        Err(RecvTimeoutError::Disconnected) => {
            panic!("a SLIM call panicked on its worker thread")
        }
    }
}

/// A SLIM node serving one test on a loopback port. Stopped and shut down on drop.
struct Node {
    service: Service,
    endpoint: String,
}

impl Node {
    fn start(test: &str) -> Self {
        slim_config::tls::provider::initialize_crypto_provider();
        let endpoint = free_loopback_endpoint();
        let service = new_service(&format!("{test}-node"));
        service
            .run_server(new_insecure_server_config(endpoint.clone()))
            .expect("start the SLIM node on loopback");
        thread::sleep(SETTLE);
        Self { service, endpoint }
    }

    /// A service connected to this node, hosting one or more apps.
    fn join(&self, role: &str) -> Host {
        let service = new_service(role);
        let conn = service
            .connect(new_insecure_client_config(format!(
                "http://{}",
                self.endpoint
            )))
            .expect("connect to the SLIM node");
        Host { service, conn }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.service.stop_server(self.endpoint.clone());
        let _ = self.service.shutdown();
    }
}

/// A service connected to the node over connection `conn`.
struct Host {
    service: Service,
    conn: u64,
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.service.disconnect(self.conn);
        let _ = self.service.shutdown();
    }
}

/// The listener at [`LISTENER_NAME`] under `auth`, subscribed on the node so callers
/// can route to it.
fn listener_app(host: &Host, auth: &SlimAuth) -> Arc<App> {
    let app = create_app(&host.service, name(LISTENER_NAME), auth).expect("create the listener");
    app.subscribe(name(LISTENER_NAME), Some(host.conn))
        .expect("subscribe the listener");
    thread::sleep(SETTLE);
    app
}

/// The open listener: any `did:key` may connect.
fn open_listener(host: &Host, listener: &AgentIdentity) -> Arc<App> {
    let auth = SlimAuth::did_open(listener).expect("open admission for the listener");
    listener_app(host, &auth)
}

/// A caller app at [`CALLER_NAME`] that routes to [`LISTENER_NAME`] through the node.
fn caller_app(host: &Host, auth: &SlimAuth) -> Arc<App> {
    let app = create_app(&host.service, name(CALLER_NAME), auth).expect("create the caller");
    app.subscribe(name(CALLER_NAME), Some(host.conn))
        .expect("subscribe the caller");
    app.set_route(name(LISTENER_NAME), host.conn)
        .expect("route to the listener");
    thread::sleep(SETTLE);
    app
}

/// A fresh 32-byte secret, so the caller DID derived from it is one nobody has seen.
fn fresh_seed() -> [u8; 32] {
    AgentIdentity::generate().unwrap().signing_key_bytes()
}

/// Start the listener's accept, then the caller's session, and wait for both. The
/// accept starts first so a session that arrives early is not missed.
fn open_session(listener: &Arc<App>, caller: &Arc<App>) -> (Arc<Session>, Arc<Session>) {
    let accepted = spawn_call({
        let listener = listener.clone();
        move || listener.listen_for_session(Some(SESSION_TIMEOUT))
    });
    let created = spawn_call({
        let caller = caller.clone();
        move || caller.create_session_and_wait(session_config(), name(LISTENER_NAME))
    });
    let caller_session = wait_for(&created, SESSION_TIMEOUT)
        .expect("the caller's session finishes within the deadline")
        .expect("the caller completes a session with the listener");
    let listener_session = wait_for(&accepted, SESSION_TIMEOUT)
        .expect("the listener's accept finishes within the deadline")
        .expect("the listener accepts the session");
    (caller_session, listener_session)
}

/// One message each way over an established session.
fn exchange_one_message_each_way(caller: &Arc<Session>, listener: &Arc<Session>) {
    let inbound = spawn_call({
        let listener = listener.clone();
        move || listener.get_message(Some(SESSION_TIMEOUT))
    });
    let sent = spawn_call({
        let caller = caller.clone();
        move || caller.publish_and_wait(PING.to_vec(), None, None)
    });
    wait_for(&sent, SESSION_TIMEOUT)
        .expect("the caller's publish finishes within the deadline")
        .expect("the caller publishes");
    let got = wait_for(&inbound, SESSION_TIMEOUT)
        .expect("the listener's read finishes within the deadline")
        .expect("the listener receives the caller's message");
    assert_eq!(got.payload, PING, "the listener got the caller's message");

    let reply = spawn_call({
        let caller = caller.clone();
        move || caller.get_message(Some(SESSION_TIMEOUT))
    });
    let sent = spawn_call({
        let listener = listener.clone();
        move || listener.publish_and_wait(PONG.to_vec(), None, None)
    });
    wait_for(&sent, SESSION_TIMEOUT)
        .expect("the listener's publish finishes within the deadline")
        .expect("the listener publishes");
    let got = wait_for(&reply, SESSION_TIMEOUT)
        .expect("the caller's read finishes within the deadline")
        .expect("the caller receives the listener's reply");
    assert_eq!(got.payload, PONG, "the caller got the listener's reply");
}

/// Delete a session, best effort, on the same deadline as the rest of the test.
fn end_session(app: &Arc<App>, session: Arc<Session>) {
    let app = app.clone();
    let _ = wait_for(
        &spawn_call(move || app.delete_session_and_wait(session)),
        SESSION_TIMEOUT,
    );
}

/// One attempt by `caller` to reach `listener`: the caller creates a session and
/// sends one message, and the listener accepts a session and reads one.
///
/// `Ok` is the payload the listener's application received. `Err` names the step that
/// failed: the caller's session or publish, or the listener's accept or read.
///
/// The caller must finish, success or failure, within `deadline`; otherwise the test
/// panics as a hang. The listener's accept and read each get `deadline` too.
///
/// A refused caller returns at once, and the listener's accept then runs out its own
/// deadline in the background. Do not make a second attempt on the same listener
/// until that has happened, or it could take the earlier accept's session.
fn attempt(listener: &Arc<App>, caller: &Arc<App>, deadline: Duration) -> Result<Vec<u8>, String> {
    let listener_side = spawn_call({
        let listener = listener.clone();
        move || -> Result<Vec<u8>, String> {
            let session = listener
                .listen_for_session(Some(deadline))
                .map_err(|e| format!("listener accept: {e}"))?;
            let message = session
                .get_message(Some(deadline))
                .map_err(|e| format!("listener read: {e}"))?;
            Ok(message.payload)
        }
    });
    let caller_side = spawn_call({
        let caller = caller.clone();
        move || -> Result<(), String> {
            let session = caller
                .create_session_and_wait(session_config(), name(LISTENER_NAME))
                .map_err(|e| format!("caller session: {e}"))?;
            session
                .publish_and_wait(PING.to_vec(), None, None)
                .map_err(|e| format!("caller publish: {e}"))
        }
    });
    let caller_result = wait_for(&caller_side, deadline).unwrap_or_else(|| {
        panic!("the caller hung: neither a session nor an error within {deadline:?}")
    });
    // A caller that failed was refused, whatever the listener thinks it saw. The listener
    // side then runs out its own deadline on a background thread.
    caller_result?;
    wait_for(&listener_side, 2 * deadline)
        .unwrap_or_else(|| panic!("the listener hung: no accept or read within {deadline:?}"))
}

// ---------------------------------------------------------------------------
// Positive: an open listener admits a caller it has never seen.
// ---------------------------------------------------------------------------

#[test]
fn open_listener_admits_a_caller_it_has_never_seen() {
    let node = Node::start("stranger");
    let listener_id = AgentIdentity::generate().unwrap();
    let listener_host = node.join("listener");
    let listener = open_listener(&listener_host, &listener_id);

    // A caller the listener was never told about: a fresh seed, pinned to the
    // listener alone.
    let auth = build_did_auth_for_peer(&fresh_seed(), "stranger", &listener_id.did()).unwrap();
    let caller_host = node.join("caller");
    let caller = caller_app(&caller_host, &auth);

    let (caller_session, listener_session) = open_session(&listener, &caller);
    exchange_one_message_each_way(&caller_session, &listener_session);
    end_session(&caller, caller_session);
    end_session(&listener, listener_session);
}

// ---------------------------------------------------------------------------
// Positive: the same open listener admits a second, unrelated caller.
// ---------------------------------------------------------------------------

#[test]
fn open_listener_admits_two_unrelated_callers_in_separate_sessions() {
    let node = Node::start("two-callers");
    let listener_id = AgentIdentity::generate().unwrap();
    let listener_host = node.join("listener");
    let listener = open_listener(&listener_host, &listener_id);

    for agent in ["first-caller", "second-caller"] {
        let auth = build_did_auth_for_peer(&fresh_seed(), agent, &listener_id.did()).unwrap();
        let caller_host = node.join(agent);
        let caller = caller_app(&caller_host, &auth);

        let (caller_session, listener_session) = open_session(&listener, &caller);
        exchange_one_message_each_way(&caller_session, &listener_session);
        end_session(&caller, caller_session);
        end_session(&listener, listener_session);
    }
}

// ---------------------------------------------------------------------------
// Negative: a caller pinned to a different peer cannot reach the listener.
// ---------------------------------------------------------------------------

#[test]
fn caller_pinned_to_another_peer_cannot_reach_the_open_listener() {
    let node = Node::start("pinned-elsewhere");
    let listener_id = AgentIdentity::generate().unwrap();
    let other_id = AgentIdentity::generate().unwrap();
    let listener_host = node.join("listener");
    let listener = open_listener(&listener_host, &listener_id);

    // Control: a caller pinned to the listener reaches it on this same node, so the
    // refusal below is about the allow-list and nothing else.
    let honest_auth = build_did_auth_for_peer(&fresh_seed(), "honest", &listener_id.did()).unwrap();
    let honest_host = node.join("honest");
    let honest = caller_app(&honest_host, &honest_auth);
    assert_eq!(
        attempt(&listener, &honest, SESSION_TIMEOUT),
        Ok(PING.to_vec()),
        "control: a caller pinned to the listener reaches it"
    );

    // Allow-list {other, own}. The listener's DID is not on it, so the caller refuses
    // the DID-JWT the listener presents and the session never completes.
    let pinned_auth = build_did_auth_for_peer(&fresh_seed(), "pinned", &other_id.did()).unwrap();
    let pinned_host = node.join("pinned");
    let pinned = caller_app(&pinned_host, &pinned_auth);
    let result = attempt(&listener, &pinned, REFUSAL_TIMEOUT);
    assert!(
        result.is_err(),
        "a caller that does not trust the listener's DID reached the listener: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Negative: a forged DID-JWT is refused by the open listener.
// ---------------------------------------------------------------------------

/// A DID-JWT for `subject` with the audience and signing key the test chooses. The
/// honest token has `aud` = [`DID_JWT_AUDIENCE`] and is signed by `subject`'s key.
fn did_jwt(subject: &str, signer: &AgentIdentity, aud: &str, pubkey: &[u8]) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs();
    let header = json!({ "alg": "EdDSA", "typ": "JWT", "kid": subject });
    let claims = json!({
        "iss": subject,
        "sub": subject,
        "aud": aud,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "pubkey": STANDARD.encode(pubkey),
    });
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string()),
    );
    let signature = signer.sign_bytes(signing_input.as_bytes());
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

/// A caller identity that presents the DID-JWT the test builds, instead of the one
/// shadi's provider mints. The audience and the signing key are the test's choice.
/// The MLS signature keys are SLIM's own, as in shadi's provider.
struct ForgingProvider {
    subject: String,
    signer: AgentIdentity,
    audience: String,
    keys: Mutex<SignatureKeys>,
}

impl ForgingProvider {
    fn new(subject: &AgentIdentity, signer: AgentIdentity, audience: &str) -> Self {
        Self {
            subject: subject.did(),
            signer,
            audience: audience.to_string(),
            keys: Mutex::new(generate_signature_keys().expect("MLS signature keys")),
        }
    }

    fn keys(&self) -> MutexGuard<'_, SignatureKeys> {
        self.keys.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn failed(message: impl Into<String>) -> IdentityCallbackError {
    IdentityCallbackError::Failed {
        message: message.into(),
    }
}

impl IdentityProvider for ForgingProvider {
    fn initialize<'life0, 'async_trait>(
        &'life0 self,
    ) -> Pin<Box<dyn Future<Output = Result<(), IdentityCallbackError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(std::future::ready(Ok(())))
    }

    fn get_token(&self) -> Result<String, IdentityCallbackError> {
        let public_key = self.keys().public_key.clone();
        Ok(did_jwt(
            &self.subject,
            &self.signer,
            &self.audience,
            &public_key,
        ))
    }

    fn get_id(&self) -> Result<String, IdentityCallbackError> {
        Ok(self.subject.clone())
    }

    fn get_signature_keys(&self) -> Result<SignatureKeys, IdentityCallbackError> {
        Ok(self.keys().clone())
    }

    fn mls_signature_keys_installed(&self) -> Result<bool, IdentityCallbackError> {
        Ok(true)
    }

    fn set_signature_keys(
        &self,
        private_key: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Result<(), IdentityCallbackError> {
        *self.keys() = SignatureKeys {
            secret_key: private_key,
            public_key,
        };
        Ok(())
    }

    fn export_identity(&self) -> Result<Option<IdentityExport>, IdentityCallbackError> {
        Ok(None)
    }

    fn holds_long_term_signing_key(&self) -> Result<bool, IdentityCallbackError> {
        Ok(false)
    }

    fn restore_identity(&self, _identity: IdentityExport) -> Result<(), IdentityCallbackError> {
        Err(failed("the forging provider has no persistence"))
    }
}

/// The verifier a forging caller uses for the listener's tokens. It accepts any
/// `did:key` that proves its key, so the test measures only the listener's check.
struct AnyDidVerifier(DidKeyVerifier);

impl IdentityVerifier for AnyDidVerifier {
    fn initialize<'life0, 'async_trait>(
        &'life0 self,
    ) -> Pin<Box<dyn Future<Output = Result<(), IdentityCallbackError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(std::future::ready(Ok(())))
    }

    fn verify_async<'life0, 'async_trait>(
        &'life0 self,
        token: String,
    ) -> Pin<Box<dyn Future<Output = Result<(), IdentityCallbackError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(std::future::ready(self.verify(token)))
    }

    fn verify(&self, token: String) -> Result<(), IdentityCallbackError> {
        self.0.verify(&token).map_err(|e| failed(e.to_string()))
    }

    fn get_claims(&self, token: String) -> Result<String, IdentityCallbackError> {
        let claims: Value = self
            .0
            .get_claims(&token)
            .map_err(|e| failed(e.to_string()))?;
        Ok(claims.to_string())
    }

    fn get_subject(&self, token: String) -> Result<String, IdentityCallbackError> {
        self.0
            .get_subject(&token)
            .map_err(|e| failed(e.to_string()))
    }

    fn get_public_key(&self, token: String) -> Result<Vec<u8>, IdentityCallbackError> {
        let claims: Value = self
            .0
            .get_claims(&token)
            .map_err(|e| failed(e.to_string()))?;
        let pubkey = claims["pubkey"]
            .as_str()
            .ok_or_else(|| failed("token has no pubkey claim"))?;
        STANDARD
            .decode(pubkey)
            .map_err(|e| failed(format!("bad pubkey claim: {e}")))
    }

    fn verify_key_binding(
        &self,
        token: String,
        public_key: Vec<u8>,
    ) -> Result<(), IdentityCallbackError> {
        self.0
            .verify_key_binding(&token, &public_key)
            .map_err(|e| failed(e.to_string()))
    }
}

/// A caller that presents a forged DID-JWT, built with the given audience and signed
/// by its own key or by another one.
fn forging_caller(node: &Node, audience: &str, signed_by_other_key: bool) -> (Host, Arc<App>) {
    let subject = AgentIdentity::generate().unwrap();
    let signer = if signed_by_other_key {
        AgentIdentity::generate().unwrap()
    } else {
        AgentIdentity::from_signing_key_bytes(&subject.signing_key_bytes())
    };
    let provider = ForgingProvider::new(&subject, signer, audience);
    let verifier = AnyDidVerifier(DidKeyVerifier::any_did_key().unwrap());

    let host = node.join("forger");
    let app = host
        .service
        .create_app_with_custom_identity(
            name(CALLER_NAME),
            Arc::new(provider),
            Arc::new(verifier),
            Direction::Bidirectional,
        )
        .expect("create the forging caller");
    app.subscribe(name(CALLER_NAME), Some(host.conn))
        .expect("subscribe the forging caller");
    app.set_route(name(LISTENER_NAME), host.conn)
        .expect("route to the listener");
    thread::sleep(SETTLE);
    (host, app)
}

#[test]
fn open_listener_refuses_a_did_jwt_with_the_wrong_audience() {
    let node = Node::start("wrong-aud");
    let listener_id = AgentIdentity::generate().unwrap();
    let listener_host = node.join("listener");
    let listener = open_listener(&listener_host, &listener_id);

    // Control: the honest token reaches this listener, so a refusal below is about the
    // audience and nothing else.
    let (_honest_host, honest) = forging_caller(&node, DID_JWT_AUDIENCE, false);
    assert_eq!(
        attempt(&listener, &honest, SESSION_TIMEOUT),
        Ok(PING.to_vec()),
        "control: an honest DID-JWT reaches the open listener"
    );

    let (_forged_host, forged) = forging_caller(&node, "some-other-audience", false);
    let result = attempt(&listener, &forged, REFUSAL_TIMEOUT);
    assert!(
        result.is_err(),
        "a DID-JWT for another audience reached the open listener: {result:?}"
    );
}

#[test]
fn open_listener_refuses_a_did_jwt_signed_by_another_key() {
    let node = Node::start("wrong-key");
    let listener_id = AgentIdentity::generate().unwrap();
    let listener_host = node.join("listener");
    let listener = open_listener(&listener_host, &listener_id);

    let (_honest_host, honest) = forging_caller(&node, DID_JWT_AUDIENCE, false);
    assert_eq!(
        attempt(&listener, &honest, SESSION_TIMEOUT),
        Ok(PING.to_vec()),
        "control: an honest DID-JWT reaches the open listener"
    );

    let (_forged_host, forged) = forging_caller(&node, DID_JWT_AUDIENCE, true);
    let result = attempt(&listener, &forged, REFUSAL_TIMEOUT);
    assert!(
        result.is_err(),
        "a DID-JWT whose subject did not sign it reached the open listener: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Closed-mode regression: an allow-list listener still refuses an unlisted caller.
// ---------------------------------------------------------------------------

#[test]
fn closed_listener_admits_its_member_and_refuses_an_unlisted_caller() {
    let node = Node::start("closed");
    let listener_id = AgentIdentity::generate().unwrap();
    let member_id = AgentIdentity::generate().unwrap();
    let intruder_id = AgentIdentity::generate().unwrap();

    // Closed admission: the allow-list is the listener and the member only.
    let listener_auth = SlimAuth::did(
        &listener_id,
        [listener_id.did().as_str(), member_id.did().as_str()],
    )
    .unwrap();
    let listener_host = node.join("listener");
    let listener = listener_app(&listener_host, &listener_auth);

    let member_auth = SlimAuth::did(
        &member_id,
        [member_id.did().as_str(), listener_id.did().as_str()],
    )
    .unwrap();
    let member_host = node.join("member");
    let member = caller_app(&member_host, &member_auth);
    let (caller_session, listener_session) = open_session(&listener, &member);
    exchange_one_message_each_way(&caller_session, &listener_session);
    end_session(&member, caller_session);
    end_session(&listener, listener_session);

    let intruder_auth = SlimAuth::did(
        &intruder_id,
        [intruder_id.did().as_str(), listener_id.did().as_str()],
    )
    .unwrap();
    let intruder_host = node.join("intruder");
    let intruder = caller_app(&intruder_host, &intruder_auth);
    let result = attempt(&listener, &intruder, REFUSAL_TIMEOUT);
    assert!(
        result.is_err(),
        "an unlisted caller reached the closed listener: {result:?}"
    );
}
