#!/usr/bin/env python3
"""Simple listener that submits SHADI MAS K8s jobs with managed vars and secrets.

Endpoints:
- POST /submit: submit a job request
- GET /tasks/<task_id>: fetch task state and logs
- GET /healthz: liveness

The listener sources:
- SLIM shared secret from a Kubernetes secret key
- vLLM API key from a vault-synced Kubernetes secret containing a JSON map

It then updates the destination runtime secret in the target namespace and calls
scripts/deploy_mas_experiments_k8s.sh with the requested mode/env values.
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import subprocess
import threading
import uuid
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


def _env(name: str, default: str) -> str:
    value = os.environ.get(name)
    return value if value else default


def _resolve_repo_root() -> Path:
    # Do not resolve symlinks here; ConfigMap mounts use ..data symlinks.
    file_path = Path(__file__).absolute()
    return file_path.parents[1]


def _resolve_deploy_script(repo_root: Path) -> Path:
    override = os.environ.get("SHADI_LISTENER_DEPLOY_SCRIPT", "").strip()
    if override:
        return Path(override)

    script_dir = Path(__file__).absolute().parent
    candidates = [
        script_dir / "deploy_mas_experiments_k8s.sh",
        repo_root / "scripts" / "deploy_mas_experiments_k8s.sh",
        repo_root / "deploy_mas_experiments_k8s.sh",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[0]


REPO_ROOT = _resolve_repo_root()
DEPLOY_SCRIPT = _resolve_deploy_script(REPO_ROOT)

LISTENER_HOST = _env("SHADI_LISTENER_HOST", "127.0.0.1")
LISTENER_PORT = int(_env("SHADI_LISTENER_PORT", "8088"))

DEST_NAMESPACE = _env("SHADI_LISTENER_DEST_NAMESPACE", "lumuscar-jobs")
DEST_SECRET_NAME = _env("SHADI_LISTENER_DEST_SECRET_NAME", "shadi-mas-experiments-secrets")

SLIM_SECRET_NAMESPACE = _env("SHADI_LISTENER_SLIM_SECRET_NAMESPACE", DEST_NAMESPACE)
SLIM_SECRET_NAME = _env("SHADI_LISTENER_SLIM_SECRET_NAME", DEST_SECRET_NAME)
SLIM_SECRET_KEY = _env("SHADI_LISTENER_SLIM_SECRET_KEY", "SLIM_SHARED_SECRET")

VLLM_SECRET_NAMESPACE = _env("SHADI_LISTENER_VLLM_SECRET_NAMESPACE", DEST_NAMESPACE)
VLLM_SECRET_NAME = _env("SHADI_LISTENER_VLLM_SECRET_NAME", "gemma-vllm-api-keys")
VLLM_SECRET_KEY = _env("SHADI_LISTENER_VLLM_SECRET_KEY", "api-key")
VLLM_USERNAME = _env("SHADI_LISTENER_VLLM_USERNAME", "lumuscar@cisco.com")

REQUIRE_AUTH = _env("SHADI_LISTENER_REQUIRE_AUTH", "1").strip().lower() not in {"0", "false", "no", "off"}
AUTH_SECRET_NAMESPACE = _env("SHADI_LISTENER_AUTH_SECRET_NAMESPACE", DEST_NAMESPACE)
AUTH_SECRET_NAME = _env("SHADI_LISTENER_AUTH_SECRET_NAME", "mas-job-listener-api")
AUTH_SECRET_KEY = _env("SHADI_LISTENER_AUTH_SECRET_KEY", "submit-api-key")
AUTH_STATIC_API_KEY = os.environ.get("SHADI_LISTENER_API_KEY", "").strip()

DEFAULT_ENV = {
    "K8S_NAMESPACE": DEST_NAMESPACE,
    "SHADI_MAS_SOURCE_MODE": _env("SHADI_LISTENER_SOURCE_MODE", "local"),
    "SHADI_SKIP_VLLM_PREFLIGHT": _env("SHADI_LISTENER_SKIP_VLLM_PREFLIGHT", "1"),
    "SHADI_LIVE_LLM_BACKEND": _env("SHADI_LISTENER_LLM_BACKEND", "vllm"),
    "SHADI_LIVE_VLLM_BASE_URL": _env("SHADI_LISTENER_VLLM_BASE_URL", "https://vllm.outshift-gls.cisco.com/v1"),
    "SHADI_LIVE_ENDPOINT": _env("SHADI_LISTENER_LIVE_ENDPOINT", "127.0.0.1:47357"),
    "SHADI_MAS_HTTP_PROXY": _env("SHADI_LISTENER_HTTP_PROXY", "http://proxy-wsa.esl.cisco.com:80"),
    "SHADI_MAS_HTTPS_PROXY": _env("SHADI_LISTENER_HTTPS_PROXY", "http://proxy-wsa.esl.cisco.com:80"),
    "SHADI_LIVE_READY_TIMEOUT_SECONDS": _env("SHADI_LISTENER_READY_TIMEOUT_SECONDS", "45"),
}

ALLOWED_MODES = {"spotcheck", "sweep", "suite"}
JOB_NAME_RE = re.compile(r"Job submitted:\s+([^\s]+)")


@dataclass
class TaskState:
    task_id: str
    mode: str
    request: dict[str, Any]
    status: str = "queued"
    job_name: str | None = None
    output: str = ""
    error: str | None = None
    exit_code: int | None = None


TASKS: dict[str, TaskState] = {}
TASKS_LOCK = threading.Lock()
AUTH_TOKENS: tuple[str, ...] = ()


def run_cmd(args: list[str], *, input_text: str | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        input=input_text,
        text=True,
        capture_output=True,
        cwd=str(REPO_ROOT),
        env=env,
        check=False,
    )


def secret_key_value(namespace: str, secret_name: str, key: str) -> str:
    jsonpath = f"{{.data.{key}}}"
    proc = run_cmd(["kubectl", "-n", namespace, "get", "secret", secret_name, "-o", f"jsonpath={jsonpath}"])
    if proc.returncode != 0:
        raise RuntimeError(f"failed to read {namespace}/{secret_name}:{key}: {proc.stderr.strip()}")
    encoded = proc.stdout.strip()
    if not encoded:
        raise RuntimeError(f"missing key {key} in secret {namespace}/{secret_name}")
    decode = run_cmd(["python3", "-c", "import base64,sys;print(base64.b64decode(sys.stdin.read()).decode('utf-8'),end='')"], input_text=encoded)
    if decode.returncode != 0:
        raise RuntimeError(f"failed to decode secret key {key}: {decode.stderr.strip()}")
    return decode.stdout


def resolve_vllm_api_key(username: str) -> str:
    raw = secret_key_value(VLLM_SECRET_NAMESPACE, VLLM_SECRET_NAME, VLLM_SECRET_KEY)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"vLLM key secret is not valid JSON map: {exc}") from exc

    if not isinstance(payload, dict):
        raise RuntimeError("vLLM key secret must decode to a JSON object map")

    value = payload.get(username)
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"no API key found for username {username}")
    return value.strip()


def apply_runtime_secret(slim_shared_secret: str, openai_api_key: str) -> None:
    manifest = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": DEST_SECRET_NAME, "namespace": DEST_NAMESPACE},
        "type": "Opaque",
        "stringData": {
            "SLIM_SHARED_SECRET": slim_shared_secret,
            "OPENAI_API_KEY": openai_api_key,
        },
    }
    proc = run_cmd(["kubectl", "apply", "-f", "-"], input_text=json.dumps(manifest))
    if proc.returncode != 0:
        raise RuntimeError(f"failed to apply runtime secret: {proc.stderr.strip()}")


def load_auth_tokens() -> tuple[str, ...]:
    values: list[str] = []

    if AUTH_STATIC_API_KEY:
        values.append(AUTH_STATIC_API_KEY)

    try:
        secret_token = secret_key_value(AUTH_SECRET_NAMESPACE, AUTH_SECRET_NAME, AUTH_SECRET_KEY).strip()
        if secret_token:
            values.append(secret_token)
    except Exception:
        if REQUIRE_AUTH and not AUTH_STATIC_API_KEY:
            raise

    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            deduped.append(value)
            seen.add(value)

    if REQUIRE_AUTH and not deduped:
        raise RuntimeError(
            "listener auth is required but no API token was loaded "
            f"(secret: {AUTH_SECRET_NAMESPACE}/{AUTH_SECRET_NAME}:{AUTH_SECRET_KEY})"
        )
    return tuple(deduped)


def _extract_api_token(headers: Any) -> str:
    token = headers.get("X-API-Key", "").strip()
    if token:
        return token

    authorization = headers.get("Authorization", "").strip()
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return ""


def _is_authorized(headers: Any) -> bool:
    if not REQUIRE_AUTH:
        return True

    provided = _extract_api_token(headers)
    if not provided:
        return False
    return any(hmac.compare_digest(provided, token) for token in AUTH_TOKENS)


def submit_job(task: TaskState) -> None:
    task.status = "running"
    try:
        slim_secret = secret_key_value(SLIM_SECRET_NAMESPACE, SLIM_SECRET_NAME, SLIM_SECRET_KEY)
        vllm_api_key = resolve_vllm_api_key(task.request.get("vllm_username", VLLM_USERNAME))

        if len(slim_secret) < 32:
            raise RuntimeError(f"SLIM shared secret too short ({len(slim_secret)} bytes), expected >= 32")
        if len(vllm_api_key) < 16:
            raise RuntimeError(f"vLLM API key too short ({len(vllm_api_key)} bytes), expected >= 16")

        apply_runtime_secret(slim_secret, vllm_api_key)

        merged_env = os.environ.copy()
        merged_env.update(DEFAULT_ENV)

        request_env = task.request.get("env", {})
        if not isinstance(request_env, dict):
            raise RuntimeError("request env must be an object map")
        for key, value in request_env.items():
            if isinstance(key, str) and isinstance(value, (str, int, float, bool)):
                merged_env[key] = str(value)

        if "llm_model" in task.request and isinstance(task.request["llm_model"], str):
            merged_env["SHADI_LIVE_LLM_MODEL"] = task.request["llm_model"]

        mode = task.mode
        proc = run_cmd(["bash", str(DEPLOY_SCRIPT), mode], env=merged_env)
        output = (proc.stdout or "") + (proc.stderr or "")
        task.output = output
        task.exit_code = proc.returncode

        match = JOB_NAME_RE.search(output)
        if match:
            task.job_name = match.group(1)

        if proc.returncode != 0:
            task.status = "failed"
            task.error = f"deploy script exited with code {proc.returncode}"
            return

        task.status = "submitted"
    except Exception as exc:  # noqa: BLE001
        task.status = "failed"
        task.error = str(exc)


class ListenerHandler(BaseHTTPRequestHandler):
    server_version = "MasJobListener/0.1"

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            self._send_json(HTTPStatus.OK, {"ok": True})
            return

        if not _is_authorized(self.headers):
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "missing or invalid API token"})
            return

        if self.path.startswith("/tasks/"):
            task_id = self.path.split("/tasks/", 1)[1].strip()
            with TASKS_LOCK:
                task = TASKS.get(task_id)
            if not task:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "task not found"})
                return

            self._send_json(
                HTTPStatus.OK,
                {
                    "task_id": task.task_id,
                    "mode": task.mode,
                    "status": task.status,
                    "job_name": task.job_name,
                    "exit_code": task.exit_code,
                    "error": task.error,
                    "output": task.output[-12000:],
                },
            )
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/submit":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return

        if not _is_authorized(self.headers):
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "missing or invalid API token"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length > 0 else b"{}"

        try:
            payload = json.loads(raw.decode("utf-8") if raw else "{}")
        except json.JSONDecodeError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid JSON body"})
            return

        if not isinstance(payload, dict):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "body must be a JSON object"})
            return

        mode = str(payload.get("mode", "sweep")).strip().lower()
        if mode not in ALLOWED_MODES:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"mode must be one of {sorted(ALLOWED_MODES)}"})
            return

        task_id = str(uuid.uuid4())
        task = TaskState(task_id=task_id, mode=mode, request=payload)

        with TASKS_LOCK:
            TASKS[task_id] = task

        thread = threading.Thread(target=submit_job, args=(task,), daemon=True)
        thread.start()

        self._send_json(
            HTTPStatus.ACCEPTED,
            {
                "task_id": task_id,
                "status": "queued",
                "poll": f"/tasks/{task_id}",
            },
        )

    def log_message(self, format: str, *args: Any) -> None:
        # Keep logs concise and single-line for terminal operation.
        print(f"[{self.address_string()}] {format % args}")


def main() -> int:
    parser = argparse.ArgumentParser(description="SHADI MAS K8s job listener")
    parser.add_argument("--host", default=LISTENER_HOST, help="bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=LISTENER_PORT, help="bind port (default: 8088)")
    args = parser.parse_args()

    if not DEPLOY_SCRIPT.is_file():
        raise SystemExit(f"deploy script not found: {DEPLOY_SCRIPT}")

    global AUTH_TOKENS
    AUTH_TOKENS = load_auth_tokens()

    server = ThreadingHTTPServer((args.host, args.port), ListenerHandler)
    print(f"listening on http://{args.host}:{args.port}")
    print(f"deploy script: {DEPLOY_SCRIPT}")
    print(f"dest secret: {DEST_NAMESPACE}/{DEST_SECRET_NAME}")
    print(f"slim secret source: {SLIM_SECRET_NAMESPACE}/{SLIM_SECRET_NAME}:{SLIM_SECRET_KEY}")
    print(f"vllm secret source: {VLLM_SECRET_NAMESPACE}/{VLLM_SECRET_NAME}:{VLLM_SECRET_KEY} (user: {VLLM_USERNAME})")
    if REQUIRE_AUTH:
        print(f"submit auth: enabled via {AUTH_SECRET_NAMESPACE}/{AUTH_SECRET_NAME}:{AUTH_SECRET_KEY}")
    else:
        print("submit auth: disabled")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
