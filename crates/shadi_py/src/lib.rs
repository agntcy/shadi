// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::process::Command;
use std::sync::Mutex;

use agent_secrets::{
    AgentSecretAccess, AgentVerifier, SecretError, SecretPolicy, SecretResult, SecretStore,
    SessionContext,
};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};
use shadi_memory::{MemoryEntry as ShadiMemoryEntry, SqlCipherStore};
use shadi_sandbox::{spawn_sandboxed, SandboxError, SandboxPolicy};
use tracing::{field, info_span};

struct SessionFlagVerifier;

impl AgentVerifier for SessionFlagVerifier {
    fn verify(&self, session: &SessionContext) -> SecretResult<()> {
        if session.verified {
            Ok(())
        } else {
            Err(SecretError::NotAuthorized)
        }
    }
}

#[pyclass]
pub struct ShadiStore {
    store: Mutex<Box<dyn SecretStore>>,
    verifier: SessionFlagVerifier,
    didvc_verifier: Mutex<Option<Py<PyAny>>>,
}

#[pyclass]
pub struct SqlCipherMemoryStore {
    store: SqlCipherStore,
}

#[pyclass]
#[derive(Clone)]
pub struct MemoryEntry {
    #[pyo3(get)]
    id: i64,
    #[pyo3(get)]
    scope: String,
    #[pyo3(get)]
    entry_key: String,
    #[pyo3(get)]
    payload: String,
    #[pyo3(get)]
    created_at: String,
}

impl MemoryEntry {
    fn from_native(entry: ShadiMemoryEntry) -> Self {
        Self {
            id: entry.id,
            scope: entry.scope,
            entry_key: entry.entry_key,
            payload: entry.payload,
            created_at: entry.created_at,
        }
    }
}

#[pyclass]
pub struct SandboxPolicyHandle {
    policy: SandboxPolicy,
}

#[pymethods]
impl ShadiStore {
    #[new]
    fn new() -> Self {
        Self {
            store: Mutex::new(agent_secrets::default_store()),
            verifier: SessionFlagVerifier,
            didvc_verifier: Mutex::new(None),
        }
    }

    fn set_verifier(&self, verifier: PyObject) -> PyResult<()> {
        let mut guard = self
            .didvc_verifier
            .lock()
            .map_err(|_| PyRuntimeError::new_err("lock poisoned"))?;
        *guard = Some(verifier);
        Ok(())
    }

    fn verify_session(
        &self,
        py: Python<'_>,
        session: &Bound<'_, PySessionContext>,
        presentation: &[u8],
    ) -> PyResult<bool> {
        let verifier = {
            let guard = self
                .didvc_verifier
                .lock()
                .map_err(|_| PyRuntimeError::new_err("lock poisoned"))?;
            guard.clone().ok_or_else(|| PyRuntimeError::new_err("verifier not configured"))?
        };

        let (agent_id, session_id, claims) = {
            let session_ref = session.borrow();
            (
                session_ref.agent_id.clone(),
                session_ref.session_id.clone(),
                session_ref.claims.clone(),
            )
        };

        let payload = PyBytes::new_bound(py, presentation);
        let result = verifier.call1(py, (agent_id, session_id, payload, claims))?;
        let is_valid = result.is_truthy(py)?;

        if is_valid {
            let mut session_ref = session.borrow_mut();
            session_ref.verified = true;
        }

        Ok(is_valid)
    }

    fn put(&self, session: &PySessionContext, key: &str, secret: &[u8]) -> PyResult<()> {
        let span = info_span!("shadi.secret.put", secret.key = %key);
        let _guard = span.enter();
        let ctx = session.to_context();
        let guard = self.store.lock().map_err(|_| PyRuntimeError::new_err("lock poisoned"))?;
        let access = AgentSecretAccess::new(guard.as_ref(), &self.verifier);
        access
            .put_for_session(&ctx, key, secret, SecretPolicy::default())
            .map_err(map_secret_error)
    }

    fn get<'py>(
        &self,
        py: Python<'py>,
        session: &PySessionContext,
        key: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let span = info_span!("shadi.secret.get", secret.key = %key);
        let _guard = span.enter();
        let ctx = session.to_context();
        let guard = self.store.lock().map_err(|_| PyRuntimeError::new_err("lock poisoned"))?;
        let access = AgentSecretAccess::new(guard.as_ref(), &self.verifier);
        let secret = access.get_for_session(&ctx, key).map_err(map_secret_error)?;
        let bytes = secret.expose(|data| data.to_vec());
        Ok(PyBytes::new_bound(py, &bytes))
    }

    fn delete(&self, session: &PySessionContext, key: &str) -> PyResult<()> {
        let span = info_span!("shadi.secret.delete", secret.key = %key);
        let _guard = span.enter();
        let ctx = session.to_context();
        let guard = self.store.lock().map_err(|_| PyRuntimeError::new_err("lock poisoned"))?;
        let access = AgentSecretAccess::new(guard.as_ref(), &self.verifier);
        access
            .delete_for_session(&ctx, key)
            .map_err(map_secret_error)
    }

    fn list_keys(&self, session: &PySessionContext) -> PyResult<Vec<String>> {
        let span = info_span!("shadi.secret.list_keys");
        let _guard = span.enter();
        let ctx = session.to_context();
        AgentSecretAccess::require_verified(&ctx).map_err(map_secret_error)?;
        let guard = self.store.lock().map_err(|_| PyRuntimeError::new_err("lock poisoned"))?;
        guard.list_keys().map_err(map_secret_error)
    }
}

#[pymethods]
impl SqlCipherMemoryStore {
    #[new]
    #[pyo3(signature = (db_path, key=None, key_name=None))]
    fn new(db_path: String, key: Option<String>, key_name: Option<String>) -> PyResult<Self> {
        let key = resolve_memory_key(key, key_name.as_deref())?;
        let store = SqlCipherStore::open(db_path.as_ref(), &key)
            .map_err(|err| PyRuntimeError::new_err(err.to_string()))?;
        Ok(Self { store })
    }

    fn put(&self, scope: &str, entry_key: &str, payload: &str) -> PyResult<i64> {
        let span = info_span!("shadi.memory.put", memory.scope = %scope, memory.entry_key = %entry_key);
        let _guard = span.enter();
        self.store
            .put(scope, entry_key, payload)
            .map_err(|err| PyRuntimeError::new_err(err.to_string()))
    }

    fn get_latest(&self, scope: &str, entry_key: &str) -> PyResult<Option<MemoryEntry>> {
        let span = info_span!("shadi.memory.get_latest", memory.scope = %scope, memory.entry_key = %entry_key);
        let _guard = span.enter();
        let entry = self
            .store
            .get_latest(scope, entry_key)
            .map_err(|err| PyRuntimeError::new_err(err.to_string()))?;
        Ok(entry.map(MemoryEntry::from_native))
    }

    #[pyo3(signature = (query, scope=None, limit=10))]
    fn search(&self, query: &str, scope: Option<String>, limit: usize) -> PyResult<Vec<MemoryEntry>> {
        let span = info_span!(
            "shadi.memory.search",
            memory.query = %query,
            memory.scope = %scope.as_deref().unwrap_or(""),
            memory.limit = limit as i64,
        );
        let _guard = span.enter();
        let entries = self
            .store
            .search(scope.as_deref(), query, limit)
            .map_err(|err| PyRuntimeError::new_err(err.to_string()))?;
        Ok(entries
            .into_iter()
            .map(MemoryEntry::from_native)
            .collect())
    }

    #[pyo3(signature = (scope=None, limit=50))]
    fn list(&self, scope: Option<String>, limit: usize) -> PyResult<Vec<MemoryEntry>> {
        let span = info_span!(
            "shadi.memory.list",
            memory.scope = %scope.as_deref().unwrap_or(""),
            memory.limit = limit as i64,
        );
        let _guard = span.enter();
        let entries = self
            .store
            .list(scope.as_deref(), limit)
            .map_err(|err| PyRuntimeError::new_err(err.to_string()))?;
        Ok(entries
            .into_iter()
            .map(MemoryEntry::from_native)
            .collect())
    }

    fn delete(&self, scope: &str, entry_key: &str) -> PyResult<usize> {
        let span = info_span!("shadi.memory.delete", memory.scope = %scope, memory.entry_key = %entry_key);
        let _guard = span.enter();
        self.store
            .delete(scope, entry_key)
            .map_err(|err| PyRuntimeError::new_err(err.to_string()))
    }
}

#[pymethods]
impl SandboxPolicyHandle {
    #[new]
    fn new() -> Self {
        Self {
            policy: SandboxPolicy::new(),
        }
    }

    fn allow_read_path(&mut self, path: &str) {
        self.policy = self.policy.clone().allow_read_path(path);
    }

    fn allow_write_path(&mut self, path: &str) {
        self.policy = self.policy.clone().allow_write_path(path);
    }

    fn block_network(&mut self, value: bool) {
        self.policy = self.policy.clone().block_network(value);
    }
}

#[pyclass]
pub struct PySessionContext {
    agent_id: String,
    session_id: String,
    verified: bool,
    claims: Vec<String>,
}

#[pymethods]
impl PySessionContext {
    #[new]
    fn new(agent_id: String, session_id: String) -> Self {
        Self {
            agent_id,
            session_id,
            verified: false,
            claims: Vec::new(),
        }
    }

    fn set_verified(&mut self, value: bool) {
        self.verified = value;
    }

    fn add_claim(&mut self, claim: String) {
        self.claims.push(claim);
    }
}

impl PySessionContext {
    fn to_context(&self) -> SessionContext {
        SessionContext {
            agent_id: self.agent_id.clone(),
            session_id: self.session_id.clone(),
            verified: self.verified,
            claims: self.claims.clone(),
        }
    }
}

#[pymodule]
fn shadi(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    shadi_telemetry::init("shadi-runtime");
    m.add_class::<ShadiStore>()?;
    m.add_class::<PySessionContext>()?;
    m.add_class::<SqlCipherMemoryStore>()?;
    m.add_class::<MemoryEntry>()?;
    m.add_class::<SandboxPolicyHandle>()?;
    m.add_function(wrap_pyfunction!(run_sandboxed, m)?)?;
    Ok(())
}

fn map_secret_error(err: SecretError) -> PyErr {
    PyRuntimeError::new_err(err.to_string())
}

fn map_sandbox_error(err: SandboxError) -> PyErr {
    PyRuntimeError::new_err(err.to_string())
}

fn resolve_memory_key(key: Option<String>, key_name: Option<&str>) -> PyResult<String> {
    if let Some(key) = key {
        if key.is_empty() {
            return Err(PyRuntimeError::new_err("SHADI_MEMORY_KEY is empty"));
        }
        return Ok(key);
    }

    let name = key_name.unwrap_or("shadi/memory/sqlcipher_key");
    let store = agent_secrets::default_store();
    let secret = store
        .get(name)
        .map_err(|_| PyRuntimeError::new_err(format!("missing SHADI key: {}", name)))?;
    let raw = secret.expose(|bytes| bytes.to_vec());
    String::from_utf8(raw).map_err(|_| PyRuntimeError::new_err("SHADI memory key is not utf-8"))
}

fn inject_keychain_with_store(
    store: &dyn SecretStore,
    command: &mut Command,
    mappings: &[String],
) -> Result<(), String> {
    let span = info_span!("shadi.secrets.inject", secret.count = mappings.len() as i64);
    let _guard = span.enter();
    for mapping in mappings {
        let (key, env) = parse_key_env(mapping)?;
        let secret = store
            .get(key)
            .map_err(|_| format!("keychain lookup failed for {}", key))?;
        let value = secret.expose(|bytes| bytes.to_vec());
        let value = String::from_utf8(value).map_err(|_| "secret is not utf-8".to_string())?;
        command.env(env, value);
    }

    Ok(())
}

fn parse_key_env(value: &str) -> Result<(&str, &str), String> {
    let mut parts = value.splitn(2, '=');
    let key = parts.next().unwrap_or("");
    let env = parts.next().unwrap_or("");
    if key.is_empty() || env.is_empty() {
        return Err("inject-keychain must be in KEY=ENV format".to_string());
    }
    Ok((key, env))
}

#[pyfunction]
#[pyo3(signature = (command, policy, cwd=None, env=None, inject_keychain=None))]
fn run_sandboxed(
    command: Vec<String>,
    policy: &SandboxPolicyHandle,
    cwd: Option<String>,
    env: Option<HashMap<String, String>>,
    inject_keychain: Option<Vec<String>>,
) -> PyResult<i32> {
    if command.is_empty() {
        return Err(PyRuntimeError::new_err("command must not be empty"));
    }

    let cwd_value = cwd.as_deref().unwrap_or("");
    let span = info_span!(
        "shadi.sandbox.run",
        command = %command[0],
        cwd = %cwd_value,
        exit.code = field::Empty,
    );
    let _guard = span.enter();

    let mut cmd = Command::new(&command[0]);
    if command.len() > 1 {
        cmd.args(&command[1..]);
    }
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    if let Some(env_map) = env {
        cmd.envs(env_map);
    }
    if let Some(mappings) = inject_keychain {
        let store = agent_secrets::default_store();
        inject_keychain_with_store(store.as_ref(), &mut cmd, &mappings)
            .map_err(PyRuntimeError::new_err)?;
    }

    let mut child = spawn_sandboxed(&mut cmd, &policy.policy).map_err(map_sandbox_error)?;
    let status = child
        .wait()
        .map_err(|err| PyRuntimeError::new_err(err.to_string()))?;
    span.record("exit.code", &status.code().unwrap_or(-1));
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;
    use std::time::{SystemTime, UNIX_EPOCH};

    static PY_INIT: Once = Once::new();

    fn ensure_python() {
        PY_INIT.call_once(|| {
            pyo3::prepare_freethreaded_python();
        });
    }

    fn unique_key(prefix: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();
        format!("{}-{}-{}", prefix, std::process::id(), nanos)
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn verify_session_sets_verified_flag() {
        ensure_python();
        Python::with_gil(|py| {
            let store = ShadiStore::new();
            let module = PyModule::from_code_bound(
                py,
                "def verify(agent_id, session_id, presentation, claims):\n    return True\n",
                "verifier.py",
                "verifier",
            )
            .unwrap();
            let verifier = module.getattr("verify").unwrap();
            store.set_verifier(verifier.into_py(py)).unwrap();

            let mut base_session = PySessionContext::new("agent".to_string(), "session".to_string());
            base_session.add_claim("did:example:agent".to_string());
            let session = Py::new(py, base_session).unwrap();
            let session_bound = session.bind(py);

            let ok = store.verify_session(py, session_bound, b"presentation").unwrap();
            assert!(ok);
            assert!(session_bound.borrow().verified);
        });
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn verify_session_requires_verifier() {
        ensure_python();
        Python::with_gil(|py| {
            let store = ShadiStore::new();
            let session = Py::new(py, PySessionContext::new("agent".to_string(), "session".to_string())).unwrap();
            let session_bound = session.bind(py);

            let err = store
                .verify_session(py, session_bound, b"presentation")
                .unwrap_err();
            assert!(err.is_instance_of::<PyRuntimeError>(py));
        });
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn put_get_delete_roundtrip_requires_verified() {
        ensure_python();
        Python::with_gil(|py| {
            let store = ShadiStore::new();
            let mut session = PySessionContext::new("agent".to_string(), "session".to_string());
            session.add_claim("role:tourist".to_string());

            let err = store.put(&session, "key", b"value").unwrap_err();
            assert!(err.is_instance_of::<PyRuntimeError>(py));

            session.set_verified(true);
            let key = unique_key("shadi-py");
            let secret = b"secret-value";

            store.put(&session, &key, secret).unwrap();
            let bytes = store.get(py, &session, &key).unwrap();
            assert_eq!(bytes.as_bytes(), secret);
            store.delete(&session, &key).unwrap();
        });
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn list_keys_requires_verified() {
        ensure_python();
        Python::with_gil(|_py| {
            let store = ShadiStore::new();
            let mut session = PySessionContext::new("agent".to_string(), "session".to_string());
            session.add_claim("role:secops".to_string());
            session.set_verified(true);

            let key = unique_key("shadi-py-list");
            store.put(&session, &key, b"value").unwrap();
            let keys = store.list_keys(&session).unwrap();
            assert!(keys.iter().any(|item| item == &key));

            store.delete(&session, &key).unwrap();
        });
    }
}
