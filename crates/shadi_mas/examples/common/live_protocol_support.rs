use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use shadi_mas::experiments::{
    CommandToolAdapter, CommandToolInvocationRecord, ExperimentExecution, LiveA2ATaskAdapter,
    LiveA2ATaskAdapterConfig, LivePublishedMessageRecord, LiveSlimGroupConfig,
    LiveSlimMessagingAdapter, LiveTaskDispatchRecord, RecordingMessagingAdapter,
    RecordingTaskAdapter,
};
use shadi_mas::{ToolAdapter, ToolProvider, ToolResult};

const DEFAULT_ENDPOINT: &str = "127.0.0.1:47357";
const DEFAULT_SHARED_SECRET: &str = "my_shared_secret_for_testing_purposes_only";
const DEFAULT_LOCAL_AGENT_ID: &str = "avatar";
const DEFAULT_PEER_AGENT_ID: &str = "secops-a";
const DEFAULT_LLM_BACKEND: &str = "vllm";
const DEFAULT_LLM_MODEL: &str = "gemma4";
const DEFAULT_VLLM_ENDPOINT: &str = "http://127.0.0.1:8000/v1/chat/completions";
const DEFAULT_VLLM_API_KEY_ENV: &str = "OPENAI_API_KEY";

pub fn parse_output_dir(default_relative: &str) -> Result<PathBuf, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => Ok(PathBuf::from(default_relative)),
        [value] => Ok(PathBuf::from(value)),
        [flag, value] if flag == "--output-dir" => Ok(PathBuf::from(value)),
        _ => Err("usage: [--output-dir PATH]".to_string()),
    }
}

pub fn repo_root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(|err| format!("failed to resolve repository root: {}", err))
}

pub fn demo_bot_binary(repo_root: &Path) -> Result<PathBuf, String> {
    let mut path = repo_root.join("target").join("debug").join("shadi_demo_bot");
    if cfg!(windows) {
        path.set_extension("exe");
    }
    if path.is_file() {
        Ok(path)
    } else {
        Err(format!(
            "{} is missing; run `cargo build -p shadi_demo_bot` first",
            path.display()
        ))
    }
}

pub fn prepare_live_env(config: &LiveProtocolConfig) {
    std::env::set_var("SHADI_TMP_DIR", &config.shadi_tmp_dir);
    std::env::set_var("SLIM_ENDPOINT", &config.endpoint);
    std::env::set_var("SLIM_SHARED_SECRET", &config.shared_secret);
    std::env::set_var("SHADI_AGENT_ID", &config.local_agent_id);
    std::env::set_var("SHADI_SLIM_LOCAL_NAME", config.slim_local_name());
}

#[derive(Clone)]
pub struct LiveProtocolConfig {
    pub endpoint: String,
    pub shared_secret: String,
    pub local_agent_id: String,
    pub peer_agent_id: String,
    pub llm_backend: String,
    pub llm_model: String,
    pub vllm_endpoint: String,
    pub vllm_api_key_env: String,
    pub shadi_tmp_dir: PathBuf,
}

impl LiveProtocolConfig {
    pub fn from_env() -> Result<Self, String> {
        let repo_root = repo_root()?;
        let shadi_tmp_dir = std::env::var_os("SHADI_TMP_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| repo_root.join(".tmp"));

        Ok(Self {
            endpoint: std::env::var("SHADI_LIVE_ENDPOINT")
                .unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string()),
            shared_secret: std::env::var("SHADI_LIVE_SHARED_SECRET")
                .or_else(|_| std::env::var("SLIM_SHARED_SECRET"))
                .unwrap_or_else(|_| DEFAULT_SHARED_SECRET.to_string()),
            local_agent_id: std::env::var("SHADI_LIVE_AGENT_ID")
                .unwrap_or_else(|_| DEFAULT_LOCAL_AGENT_ID.to_string()),
            peer_agent_id: std::env::var("SHADI_LIVE_PEER_AGENT_ID")
                .unwrap_or_else(|_| DEFAULT_PEER_AGENT_ID.to_string()),
            llm_backend: std::env::var("SHADI_LIVE_LLM_BACKEND")
                .unwrap_or_else(|_| DEFAULT_LLM_BACKEND.to_string())
                .to_lowercase(),
            llm_model: std::env::var("SHADI_LIVE_LLM_MODEL")
                .or_else(|_| std::env::var("SHADI_LIVE_VLLM_MODEL"))
                .or_else(|_| std::env::var("SHADI_LIVE_OLLAMA_MODEL"))
                .unwrap_or_else(|_| DEFAULT_LLM_MODEL.to_string()),
            vllm_endpoint: std::env::var("SHADI_LIVE_VLLM_ENDPOINT")
                .or_else(|_| std::env::var("VLLM_ENDPOINT"))
                .unwrap_or_else(|_| DEFAULT_VLLM_ENDPOINT.to_string()),
            vllm_api_key_env: std::env::var("SHADI_LIVE_VLLM_API_KEY_ENV")
                .unwrap_or_else(|_| DEFAULT_VLLM_API_KEY_ENV.to_string()),
            shadi_tmp_dir,
        })
    }

    pub fn slim_group_channel(&self, phase: &str) -> String {
        format!("agntcy/shadi/{}-slim-group-{}", self.local_agent_id, phase)
    }

    pub fn slim_group_participant_name(&self, phase: &str, participant_index: usize) -> String {
        format!(
            "agntcy/shadi/{}-slim-{}-{}",
            self.peer_agent_id, phase, participant_index
        )
    }

    pub fn slim_local_name(&self) -> String {
        format!("agntcy/shadi/{}", self.local_agent_id)
    }

    pub fn a2a_local_name(&self) -> String {
        format!("agntcy/shadi/{}", self.local_agent_id)
    }

    pub fn a2a_peer_destination(&self) -> String {
        format!("agntcy/shadi/{}", self.peer_agent_id)
    }
}

#[allow(dead_code)]
pub struct LiveCaseResult<R> {
    pub execution: ExperimentExecution<R>,
    pub task_dispatches: Vec<LiveTaskDispatchRecord>,
    pub slim_exchanges: Vec<LivePublishedMessageRecord>,
    pub slim_acknowledgements: Vec<String>,
    pub tool_results: Vec<ToolResult>,
    pub tool_invocations: Vec<CommandToolInvocationRecord>,
    pub a2a_peer_output: String,
    pub slim_peer_output: String,
    pub runtime_ms: f64,
}

pub fn run_live_case<R, F>(
    config: &LiveProtocolConfig,
    demo_bot: &Path,
    output_dir: &Path,
    phase: &str,
    expected_requests: usize,
    expected_messages: usize,
    slim_peer_count: usize,
    run: F,
) -> Result<LiveCaseResult<R>, String>
where
    F: FnOnce(
        &LiveSlimMessagingAdapter,
        &LiveA2ATaskAdapter,
        &[&dyn ToolAdapter],
    ) -> Result<ExperimentExecution<R>, String>,
{
    let peers = LivePeers::spawn(
        config,
        demo_bot,
        output_dir,
        phase,
        expected_requests,
        expected_messages,
        slim_peer_count,
    )?;
    let messaging = if expected_messages > 0 && slim_peer_count > 0 {
        LiveSlimMessagingAdapter::group(LiveSlimGroupConfig {
            endpoint: config.endpoint.clone(),
            agent_id: config.local_agent_id.clone(),
            local_name: config.slim_local_name(),
            shared_secret: config.shared_secret.clone(),
            channel: config.slim_group_channel(phase),
            participants: peers.slim_participants().to_vec(),
            receipt_files: peers.slim_receipt_files().to_vec(),
            receipt_timeout: Duration::from_secs(5),
        })?
    } else {
        LiveSlimMessagingAdapter::disabled()
    };
    let tasks = LiveA2ATaskAdapter::new(LiveA2ATaskAdapterConfig {
        endpoint: config.endpoint.clone(),
        agent_id: config.local_agent_id.clone(),
        local_name: Some(config.a2a_local_name()),
        peer_agent_id: config.peer_agent_id.clone(),
        destination: Some(config.a2a_peer_destination()),
        shared_secret: config.shared_secret.clone(),
    });
    let llm_tool = build_live_tool_adapter(config)?;
    let tools: [&dyn ToolAdapter; 1] = [&llm_tool];
    let started_at = Instant::now();
    let execution = run(&messaging, &tasks, &tools)?;
    let runtime_ms = started_at.elapsed().as_secs_f64() * 1000.0;
    let task_dispatches = tasks.dispatches()?;
    let slim_exchanges = messaging.exchanges()?;
    let slim_acknowledgements = messaging.acknowledgements()?;
    let tool_results = llm_tool.results()?;
    let tool_invocations = llm_tool.invocations()?;
    let (a2a_peer_output, slim_peer_output) = peers.finish()?;

    Ok(LiveCaseResult {
        execution,
        task_dispatches,
        slim_exchanges,
        slim_acknowledgements,
        tool_results,
        tool_invocations,
        a2a_peer_output,
        slim_peer_output,
        runtime_ms,
    })
}

fn build_live_tool_adapter(config: &LiveProtocolConfig) -> Result<CommandToolAdapter, String> {
    match config.llm_backend.as_str() {
        "ollama" => Ok(CommandToolAdapter::ollama(
            ToolProvider::AgentSkills,
            config.llm_model.clone(),
        )),
        "vllm" => {
            let bridge_script = ensure_vllm_bridge_script(&config.shadi_tmp_dir)?;
            Ok(CommandToolAdapter::new(
                ToolProvider::AgentSkills,
                "python3",
                [
                    "-u".to_string(),
                    bridge_script
                        .to_str()
                        .ok_or_else(|| "invalid vLLM bridge script path".to_string())?
                        .to_string(),
                    "--endpoint".to_string(),
                    config.vllm_endpoint.clone(),
                    "--model".to_string(),
                    config.llm_model.clone(),
                    "--api-key-env".to_string(),
                    config.vllm_api_key_env.clone(),
                    "--timeout-seconds".to_string(),
                    "60".to_string(),
                ],
            ))
        }
        other => Err(format!(
            "unsupported SHADI_LIVE_LLM_BACKEND `{}` (expected `vllm` or `ollama`)",
            other
        )),
    }
}

fn ensure_vllm_bridge_script(shadi_tmp_dir: &Path) -> Result<PathBuf, String> {
    fs::create_dir_all(shadi_tmp_dir)
        .map_err(|err| format!("failed to create {}: {}", shadi_tmp_dir.display(), err))?;

    let script_path = shadi_tmp_dir.join("shadi_vllm_bridge.py");
    let script = r#"import argparse
import json
import os
import sys
import urllib.error
import urllib.request


def main() -> int:
    parser = argparse.ArgumentParser(description="SHADI vLLM bridge")
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--api-key-env", default="OPENAI_API_KEY")
    parser.add_argument("--timeout-seconds", type=float, default=60.0)
    args = parser.parse_args()

    prompt = sys.stdin.read()
    if not prompt.strip():
        print("", end="")
        return 0

    payload = {
        "model": args.model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.0,
    }

    headers = {"Content-Type": "application/json"}
    api_key = os.getenv(args.api_key_env, "")
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    request = urllib.request.Request(
        args.endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=args.timeout_seconds) as response:
            response_body = response.read().decode("utf-8")
    except urllib.error.HTTPError as err:
        detail = err.read().decode("utf-8", errors="replace")
        sys.stderr.write(f"vLLM HTTP error {err.code}: {detail}\n")
        return 1
    except urllib.error.URLError as err:
        sys.stderr.write(f"vLLM connection error: {err}\n")
        return 1

    try:
        data = json.loads(response_body)
    except json.JSONDecodeError as err:
        sys.stderr.write(f"vLLM JSON decode error: {err}\n")
        return 1

    choices = data.get("choices") or []
    if not choices:
        sys.stderr.write("vLLM response missing choices\n")
        return 1

    message = choices[0].get("message") or {}
    content = message.get("content", "")

    if isinstance(content, list):
        rendered = []
        for block in content:
            if isinstance(block, dict):
                text = block.get("text")
                if isinstance(text, str):
                    rendered.append(text)
        content = "\n".join(rendered)

    if not isinstance(content, str):
        content = str(content)

    print(content.strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
"#;

    fs::write(&script_path, script)
        .map_err(|err| format!("failed to write {}: {}", script_path.display(), err))?;

    Ok(script_path)
}

pub fn run_with_recording_protocol_counts<R, F>(run: F) -> Result<ExperimentExecution<R>, String>
where
    F: FnOnce(
        &RecordingMessagingAdapter,
        &RecordingTaskAdapter,
    ) -> Result<ExperimentExecution<R>, String>,
{
    let messaging = RecordingMessagingAdapter::default();
    let tasks = RecordingTaskAdapter::default();
    run(&messaging, &tasks)
}

fn phase_listen_timeout_seconds(expected_requests: usize, expected_messages: usize) -> u64 {
    let base_seconds = std::env::var("SHADI_LIVE_PHASE_LISTEN_TIMEOUT_SECONDS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(900);
    let request_budget = (expected_requests as u64)
        .saturating_mul(15)
        .saturating_add(60);
    let message_budget = (expected_messages as u64)
        .saturating_mul(5)
        .saturating_add(60);

    base_seconds.max(request_budget).max(message_budget)
}

fn phase_node_runtime_seconds(phase_listen_timeout_seconds: u64) -> u64 {
    phase_listen_timeout_seconds
        .saturating_mul(4)
        .max(3600)
}

fn start_local_node_enabled() -> bool {
    std::env::var("SHADI_LIVE_START_LOCAL_NODE")
        .ok()
        .map(|raw| {
            let value = raw.trim().to_ascii_lowercase();
            !(value == "0" || value == "false" || value == "no" || value == "off")
        })
        .unwrap_or(true)
}

fn wait_for_file(path: &Path, timeout: Duration) -> Result<(), String> {
    let start = Instant::now();
    while !path.is_file() {
        if start.elapsed() >= timeout {
            return Err(format!("timed out waiting for {}", path.display()));
        }
        thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

fn peer_ready_timeout() -> Duration {
    let seconds = std::env::var("SHADI_LIVE_READY_TIMEOUT_SECONDS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(30);
    Duration::from_secs(seconds)
}

struct LivePeers {
    node: Option<PeerProcess>,
    a2a: Option<PeerProcess>,
    slim: Vec<PeerProcess>,
    slim_participants: Vec<String>,
    slim_receipt_files: Vec<PathBuf>,
}

impl LivePeers {
    fn slim_participants(&self) -> &[String] {
        &self.slim_participants
    }

    fn slim_receipt_files(&self) -> &[PathBuf] {
        &self.slim_receipt_files
    }

    fn spawn(
        config: &LiveProtocolConfig,
        demo_bot: &Path,
        output_dir: &Path,
        phase: &str,
        expected_requests: usize,
        expected_messages: usize,
        slim_peer_count: usize,
    ) -> Result<Self, String> {
        let listen_timeout_seconds = phase_listen_timeout_seconds(expected_requests, expected_messages);
        let node_runtime_seconds = phase_node_runtime_seconds(listen_timeout_seconds);
        let should_start_node = start_local_node_enabled()
            && (expected_requests > 0 || (expected_messages > 0 && slim_peer_count > 0));
        let node_ready = output_dir.join(format!("{}.node.ready", phase));
        let a2a_ready = output_dir.join(format!("{}.a2a.ready", phase));
        let _ = fs::remove_file(&node_ready);
        let _ = fs::remove_file(&a2a_ready);

        let node = if should_start_node {
            let args = vec![
                "slim-node".to_string(),
                "--endpoint".to_string(),
                config.endpoint.clone(),
                "--runtime-seconds".to_string(),
                node_runtime_seconds.to_string(),
                "--ready-file".to_string(),
                node_ready
                    .to_str()
                    .ok_or_else(|| "invalid node ready file path".to_string())?
                    .to_string(),
            ];
            let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
            let process = PeerProcess::spawn("slim-node", demo_bot, &config.shadi_tmp_dir, &arg_refs)?;
            if let Err(err) = wait_for_file(&node_ready, peer_ready_timeout()) {
                let details = process.terminate_and_collect();
                return Err(format!("{}\npeer startup details:\n{}", err, details));
            }
            Some(process)
        } else {
            None
        };

        let mut slim = Vec::new();
        let mut slim_participants = Vec::new();
        let slim_receipt_files = Vec::new();

        if expected_messages > 0 && slim_peer_count > 0 {
            for participant_index in 0..slim_peer_count {
                let participant_agent_id = format!(
                    "{}-slim-{}-{}",
                    config.peer_agent_id, phase, participant_index
                );
                let participant_name = config.slim_group_participant_name(phase, participant_index);
                let slim_ready = output_dir.join(format!("{}.slim.{}.ready", phase, participant_index));
                let _ = fs::remove_file(&slim_ready);

                let args = vec![
                    "slim-echo-peer".to_string(),
                    "--endpoint".to_string(),
                    config.endpoint.clone(),
                    "--agent-id".to_string(),
                    participant_agent_id,
                    "--shared-secret".to_string(),
                    config.shared_secret.clone(),
                    "--listen-timeout-seconds".to_string(),
                    listen_timeout_seconds.to_string(),
                    "--expected-messages".to_string(),
                    expected_messages.to_string(),
                    "--ready-file".to_string(),
                    slim_ready
                        .to_str()
                        .ok_or_else(|| "invalid SLIM ready file path".to_string())?
                        .to_string(),
                ];
                let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
                let process = PeerProcess::spawn(
                    "slim-peer",
                    demo_bot,
                    &config.shadi_tmp_dir,
                    &arg_refs,
                )?;
                if let Err(err) = wait_for_file(&slim_ready, peer_ready_timeout()) {
                    let details = process.terminate_and_collect();
                    return Err(format!(
                        "{}\npeer startup details:\n{}",
                        err, details
                    ));
                }
                slim.push(process);
                slim_participants.push(participant_name);
            }
        }

        let a2a = if expected_requests > 0 {
            let args = vec![
                "a2a-echo-peer".to_string(),
                "--endpoint".to_string(),
                config.endpoint.clone(),
                "--agent-id".to_string(),
                config.peer_agent_id.clone(),
                "--shared-secret".to_string(),
                config.shared_secret.clone(),
                "--listen-timeout-seconds".to_string(),
                listen_timeout_seconds.to_string(),
                "--expected-requests".to_string(),
                expected_requests.to_string(),
                "--ready-file".to_string(),
                a2a_ready
                    .to_str()
                    .ok_or_else(|| "invalid A2A ready file path".to_string())?
                    .to_string(),
            ];
            let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
            let process =
                PeerProcess::spawn("a2a-peer", demo_bot, &config.shadi_tmp_dir, &arg_refs)?;
            if let Err(err) = wait_for_file(&a2a_ready, peer_ready_timeout()) {
                let details = process.terminate_and_collect();
                return Err(format!(
                    "{}\npeer startup details:\n{}",
                    err, details
                ));
            }
            Some(process)
        } else {
            None
        };

        Ok(Self {
            node,
            a2a,
            slim,
            slim_participants,
            slim_receipt_files,
        })
    }

    fn finish(self) -> Result<(String, String), String> {
        let Self { node, a2a, slim, .. } = self;
        let a2a_output = match a2a {
            Some(process) => process.wait()?,
            None => String::new(),
        };
        let slim_output = if slim.is_empty() {
            String::new()
        } else {
            slim
                .into_iter()
                .map(PeerProcess::wait)
                .collect::<Result<Vec<_>, _>>()?
                .join("\n")
        };
        if let Some(node) = node {
            let _ = node.terminate_and_collect();
        }
        Ok((a2a_output, slim_output))
    }
}

struct PeerProcess {
    label: &'static str,
    child: Option<Child>,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

impl PeerProcess {
    fn spawn(
        label: &'static str,
        demo_bot: &Path,
        shadi_tmp_dir: &Path,
        args: &[&str],
    ) -> Result<Self, String> {
        let log_dir = shadi_tmp_dir.join("live-peer-logs");
        fs::create_dir_all(&log_dir)
            .map_err(|err| format!("failed to create {}: {}", log_dir.display(), err))?;
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| format!("failed to compute peer log timestamp: {}", err))?
            .as_nanos();
        let stdout_path = log_dir.join(format!("{}-{}-stdout.log", label, unique));
        let stderr_path = log_dir.join(format!("{}-{}-stderr.log", label, unique));
        let stdout = File::create(&stdout_path)
            .map_err(|err| format!("failed to create {}: {}", stdout_path.display(), err))?;
        let stderr = File::create(&stderr_path)
            .map_err(|err| format!("failed to create {}: {}", stderr_path.display(), err))?;
        let child = Command::new(demo_bot)
            .args(args)
            .env("SHADI_TMP_DIR", shadi_tmp_dir)
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .map_err(|err| format!("failed to start {}: {}", label, err))?;
        Ok(Self {
            label,
            child: Some(child),
            stdout_path,
            stderr_path,
        })
    }

    fn wait(mut self) -> Result<String, String> {
        let output = self
            .child
            .take()
            .ok_or_else(|| format!("{} process already consumed", self.label))?
            .wait()
            .map_err(|err| format!("failed to wait for {}: {}", self.label, err))?;
        let stdout = fs::read_to_string(&self.stdout_path)
            .unwrap_or_else(|_| String::new())
            .trim()
            .to_string();
        let stderr = fs::read_to_string(&self.stderr_path)
            .unwrap_or_else(|_| String::new())
            .trim()
            .to_string();
        if output.success() {
            if stderr.is_empty() {
                Ok(stdout)
            } else if stdout.is_empty() {
                Ok(stderr)
            } else {
                Ok(format!("{}\n{}", stdout, stderr))
            }
        } else {
            Err(format!(
                "{} exited with {}\nstdout:\n{}\nstderr:\n{}",
                self.label, output, stdout, stderr
            ))
        }
    }

    fn terminate_and_collect(mut self) -> String {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }

        let stdout = fs::read_to_string(&self.stdout_path)
            .unwrap_or_else(|_| String::new())
            .trim()
            .to_string();
        let stderr = fs::read_to_string(&self.stderr_path)
            .unwrap_or_else(|_| String::new())
            .trim()
            .to_string();

        format!(
            "{} logs (stdout: {}, stderr: {})\nstdout:\n{}\nstderr:\n{}",
            self.label,
            self.stdout_path.display(),
            self.stderr_path.display(),
            stdout,
            stderr
        )
    }
}

impl Drop for PeerProcess {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}