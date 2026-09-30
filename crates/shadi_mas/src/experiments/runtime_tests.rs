use super::*;
use crate::mediation::MediationDecision;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct HttpHook {
    client: reqwest::Client,
    url: String,
    runtime_id: tokio::runtime::Id,
}

impl MediationHook for HttpHook {
    fn evaluate<'a>(
        &'a self,
        _request: &'a MediationRequest,
    ) -> Pin<Box<dyn Future<Output = Result<MediationDecision, String>> + Send + 'a>> {
        Box::pin(async move {
            assert_eq!(Handle::current().id(), self.runtime_id);
            self.client
                .get(&self.url)
                .send()
                .await
                .map_err(|e| e.to_string())?
                .json()
                .await
                .map_err(|e| e.to_string())
        })
    }
}

fn adapter(runtime: &Handle, hook: Arc<HttpHook>) -> LiveA2ATaskAdapter {
    LiveA2ATaskAdapter::new(
        LiveA2ATaskAdapterConfig {
            endpoint: "invalid".into(),
            agent_id: "no-credentials".into(),
            local_name: None,
            peer_agent_id: "peer".into(),
            destination: None,
            a2a_url: None,
            a2a_binding: None,
            peer_did: None,
        },
        runtime.clone(),
    )
    .with_mediation(hook)
}

fn assert_denied(adapter: &LiveA2ATaskAdapter) {
    let result = adapter.dispatch(TaskEnvelope {
        task_id: "test-task".into(),
        pattern: crate::PatternKind::Development,
        epoch: crate::Epoch(0),
        correlation_id: None,
        body: b"test".to_vec(),
    });
    // No identity or transport access occurs after the HTTP gate denies.
    assert_eq!(result.unwrap_err(), "mediation denied: test policy");
    assert!(adapter.dispatches().unwrap().is_empty());
}

#[test]
fn host_runtime_keeps_hook_connections_alive_across_adapters_and_concurrent_sends() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let connections = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(AtomicUsize::new(0));
    let server_connections = connections.clone();
    let server_requests = requests.clone();
    let server = runtime.spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            server_connections.fetch_add(1, Ordering::SeqCst);
            let requests = server_requests.clone();
            tokio::spawn(async move {
                // A tiny keep-alive HTTP endpoint makes actual pool reuse observable.
                let mut headers = Vec::new();
                while let Ok(byte) = stream.read_u8().await {
                    headers.push(byte);
                    if !headers.ends_with(b"\r\n\r\n") {
                        continue;
                    }
                    headers.clear();
                    requests.fetch_add(1, Ordering::SeqCst);
                    let body = serde_json::to_string(&MediationDecision::Deny {
                        reason: "test policy".into(),
                    }).unwrap();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    if stream.write_all(response.as_bytes()).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let hook = Arc::new(HttpHook {
        client: reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap(),
        url,
        runtime_id: runtime.handle().id(),
    });

    assert_denied(&adapter(runtime.handle(), hook.clone()));
    // No dispatch is running, but the host runtime must still drive I/O and timers.
    let (done, wait) = std::sync::mpsc::channel();
    runtime.spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        done.send(()).unwrap();
    });
    wait.recv_timeout(Duration::from_secs(2)).unwrap();
    let adapter = adapter(runtime.handle(), hook.clone());
    assert_denied(&adapter);
    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "HTTP connection must be reused"
    );
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| assert_denied(&adapter));
        }
    });
    assert_eq!(requests.load(Ordering::SeqCst), 6);

    drop(adapter);
    drop(hook);
    server.abort();
    runtime.shutdown_timeout(Duration::from_secs(2));
}
