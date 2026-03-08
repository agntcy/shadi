import base64
import json
import os
import re
import shutil
import subprocess
import tomllib
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from shadi import ShadiStore, PySessionContext, SqlCipherMemoryStore


def load_secops_config():
    config_path = Path(os.getenv("SHADI_SECOPS_CONFIG", "secops.toml"))
    if not config_path.exists():
        return config_path, {}
    with config_path.open("rb") as handle:
        return config_path, tomllib.load(handle)


def _secret_env_var(key_name):
    """Return the env var name that can cache a secret to avoid calling op in background."""
    return "SHADI_SECRET_" + key_name.upper().replace("/", "_").replace("-", "_").replace(".", "_")


def require_shadi_secret(store, session, key_name, label):
    env_val = os.environ.get(_secret_env_var(key_name), "").strip()
    if env_val:
        return env_val.encode("utf-8")
    try:
        return store.get(session, key_name)
    except Exception as exc:
        message = (
            f"Missing {label} in SHADI at key '{key_name}'. "
            "Run: uv run agents/secops/import_secops_secrets.py"
        )
        raise RuntimeError(message) from exc


def create_secops_session():
    store = ShadiStore()
    agent_id = os.getenv("SHADI_OPERATOR_AGENT_ID", "secops_agent")
    presentation = os.getenv("SHADI_OPERATOR_PRESENTATION", "").encode("utf-8")
    if not presentation:
        raise RuntimeError("SHADI_OPERATOR_PRESENTATION must be set")
    session = PySessionContext(agent_id, "secops-session-1")

    def verify_operator(verify_agent_id, session_id, presentation_bytes, claims):
        return verify_agent_id == agent_id and len(presentation_bytes) > 0

    store.set_verifier(verify_operator)
    ok = store.verify_session(session, presentation)
    if not ok:
        raise RuntimeError("SecOps verification failed")
    return store, session


def get_secops_credentials(config, store, session):
    secops_config = config.get("secops", {})
    token_key = secops_config.get("token_key", "secops/github_token")
    workspace_key = secops_config.get("workspace_key", "secops/workspace_dir")
    github_token = require_shadi_secret(store, session, token_key, "GitHub token").decode(
        "utf-8"
    )
    workspace = require_shadi_secret(store, session, workspace_key, "workspace dir").decode(
        "utf-8"
    )
    return github_token, workspace, token_key, workspace_key


def require_shadi_secret_value(store, session, key_name, label):
    value = require_shadi_secret(store, session, key_name, label).decode("utf-8").strip()
    if not value:
        raise RuntimeError(f"Missing {label} in SHADI at key '{key_name}'.")
    return value


def get_optional_shadi_secret_value(store, session, key_name):
    try:
        value = store.get(session, key_name).decode("utf-8").strip()
    except Exception:
        return ""
    return value


def get_human_did(store, session, github_handle):
    key_name = f"github/{github_handle}/did"
    return require_shadi_secret_value(store, session, key_name, "human DID")


def get_llm_settings(config, store=None, session=None, provider_override=None):
    if store is None or session is None:
        store, session = create_secops_session()
    secops_config = config.get("secops", {})
    llm_prefix = secops_config.get("llm_key_prefix", "secops/llm")
    if provider_override:
        provider = provider_override.strip().lower()
    else:
        provider_key = f"{llm_prefix}/provider"
        provider = require_shadi_secret_value(store, session, provider_key, "LLM provider").lower()

    use_openai_proxy = False
    openai_api_key_key = f"{llm_prefix}/openai_api_key"
    if provider in ("google", "anthropic", "claude"):
        if get_optional_shadi_secret_value(store, session, openai_api_key_key):
            model_key = f"{llm_prefix}/openai_model"
            endpoint_key = f"{llm_prefix}/openai_endpoint"
            api_key_key = openai_api_key_key
            api_version_key = None
            use_openai_proxy = True
        elif provider == "google":
            model_key = f"{llm_prefix}/google_model"
            endpoint_key = f"{llm_prefix}/google_endpoint"
            api_key_key = f"{llm_prefix}/google_api_key"
            api_version_key = None
        else:
            model_key = f"{llm_prefix}/claude_model"
            endpoint_key = f"{llm_prefix}/claude_endpoint"
            api_key_key = f"{llm_prefix}/claude_api_key"
            api_version_key = None
    elif provider == "openai":
        model_key = f"{llm_prefix}/openai_model"
        endpoint_key = f"{llm_prefix}/openai_endpoint"
        api_key_key = f"{llm_prefix}/openai_api_key"
        api_version_key = None
    elif provider in ("azure", "azure_openai"):
        model_key = f"{llm_prefix}/azure_openai_deployment_name"
        endpoint_key = f"{llm_prefix}/azure_openai_endpoint"
        api_key_key = f"{llm_prefix}/azure_openai_api_key"
        api_version_key = f"{llm_prefix}/azure_openai_api_version"
    else:
        raise RuntimeError(f"Unsupported LLM provider in SHADI: '{provider}'")

    model_name = require_shadi_secret_value(store, session, model_key, "LLM model")
    if provider == "openai":
        base_url = get_optional_shadi_secret_value(store, session, endpoint_key)
    else:
        base_url = require_shadi_secret_value(store, session, endpoint_key, "LLM endpoint")
    api_key = require_shadi_secret_value(store, session, api_key_key, "LLM API key")
    api_version = ""
    if api_version_key:
        api_version = get_optional_shadi_secret_value(store, session, api_version_key)

    adk_model = model_name
    if (provider == "openai" or use_openai_proxy) and "/" in model_name:
        if not model_name.startswith("openai/"):
            adk_model = f"openai/{model_name}"

    return {
        "provider": provider,
        "model": model_name,
        "adk_model": adk_model,
        "base_url": base_url,
        "api_key": api_key,
        "api_version": api_version,
        "openai_proxy": use_openai_proxy,
    }


def get_alert_severity(alert):
    advisory = alert.get("security_advisory") or {}
    vulnerability = alert.get("security_vulnerability") or {}
    return (advisory.get("severity") or vulnerability.get("severity") or "").lower()


def is_actionable_alert(alert):
    severity = get_alert_severity(alert)
    return severity in ("critical", "high")


def get_patched_version(alert):
    vulnerability = alert.get("security_vulnerability") or {}
    first_patched = vulnerability.get("first_patched_version") or {}
    if isinstance(first_patched, dict):
        identifier = first_patched.get("identifier")
        if identifier:
            return identifier
    return ""


def build_git_auth_header(token):
    encoded = base64.b64encode(f"x-access-token:{token}".encode("utf-8")).decode("utf-8")
    return f"AUTHORIZATION: basic {encoded}"


def run_git(args, cwd, token):
    command = ["git"]
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    if token:
        command.extend(["-c", f"http.extraheader={build_git_auth_header(token)}"])
    command.extend(args)
    return subprocess.run(
        command,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )


def clone_or_update_repo(workspace_path, repo, token):
    repo_dir = workspace_path / repo.replace("/", "__")
    repo_url = f"https://github.com/{repo}.git"
    if repo_dir.exists():
        status = run_git(["status", "--porcelain"], repo_dir, token)
        if status.stdout.strip():
            return repo_dir, "dirty"
        run_git(["fetch", "origin"], repo_dir, token)
        base_ref = run_git(["symbolic-ref", "refs/remotes/origin/HEAD"], repo_dir, token)
        base_branch = base_ref.stdout.strip().rsplit("/", 1)[-1]
        run_git(["checkout", base_branch], repo_dir, token)
        run_git(["reset", "--hard", f"origin/{base_branch}"], repo_dir, token)
        return repo_dir, "updated"
    run_git(["clone", repo_url, str(repo_dir)], workspace_path, token)
    return repo_dir, "cloned"


def update_cargo_manifest(path, package_name, version):
    if not path.exists():
        return False
    updated = False
    lines = path.read_text(encoding="utf-8").splitlines()
    new_lines = []
    pattern_simple = re.compile(rf"^\s*{re.escape(package_name)}\s*=\s*\"[^\"]+\"\s*$")
    pattern_table = re.compile(
        rf"^\s*{re.escape(package_name)}\s*=\s*\{{[^}}]*version\s*=\s*\"[^\"]+\"[^}}]*\}}\s*$"
    )
    for line in lines:
        if pattern_simple.match(line):
            new_lines.append(f"{package_name} = \"{version}\"")
            updated = True
            continue
        if pattern_table.match(line):
            new_line = re.sub(
                r"version\s*=\s*\"[^\"]+\"",
                f"version = \"{version}\"",
                line,
            )
            new_lines.append(new_line)
            updated = True
            continue
        new_lines.append(line)
    if updated:
        path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    return updated


def update_package_json(path, package_name, version):
    if not path.exists():
        return False
    data = json.loads(path.read_text(encoding="utf-8"))
    updated = False
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        if package_name not in deps:
            continue
        current = deps[package_name]
        prefix = ""
        if isinstance(current, str) and current[:1] in ("^", "~"):
            prefix = current[:1]
        deps[package_name] = f"{prefix}{version}"
        updated = True
    if updated:
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return updated


def update_dockerfile_base_image(path, image, version):
    if not path.exists():
        return False
    updated = False
    lines = path.read_text(encoding="utf-8").splitlines()
    new_lines = []
    pattern = re.compile(
        rf"^\s*FROM\s+{re.escape(image)}(?::[^\s]+)?(?P<suffix>\s+AS\s+\S+)?\s*$",
        re.IGNORECASE,
    )
    for line in lines:
        match = pattern.match(line)
        if match:
            suffix = match.group("suffix") or ""
            new_lines.append(f"FROM {image}:{version}{suffix}")
            updated = True
        else:
            new_lines.append(line)
    if updated:
        path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    return updated


def is_conventional_commit(message):
    pattern = re.compile(r"^(feat|fix|chore|docs|refactor|perf|test|build|ci|style|revert)(\([^)]+\))?: .+")
    return bool(pattern.match(message))


def apply_dependency_patch(repo_path, alert):
    dependency = alert.get("dependency") or {}
    package = dependency.get("package") or {}
    ecosystem = (package.get("ecosystem") or "").lower()
    name = package.get("name") or ""
    manifest_path = dependency.get("manifest_path") or ""
    patched_version = get_patched_version(alert)
    if not patched_version:
        return {"status": "no_patch", "dependency": name, "ecosystem": ecosystem}

    if ecosystem == "cargo":
        manifest = repo_path / (manifest_path or "Cargo.toml")
        updated = update_cargo_manifest(manifest, name, patched_version)
        if not updated:
            return {"status": "not_updated", "dependency": name, "ecosystem": ecosystem}
        try:
            run_git(["add", str(manifest)], repo_path, token=None)
            cargo_args = [
                "cargo",
                "update",
                "-p",
                name,
                "--precise",
                patched_version,
                "--manifest-path",
                str(manifest),
            ]
            subprocess.run(cargo_args, cwd=repo_path, check=True, capture_output=True, text=True)
            run_git(["add", "Cargo.lock"], repo_path, token=None)
        except subprocess.CalledProcessError as exc:
            return {
                "status": "update_failed",
                "dependency": name,
                "ecosystem": ecosystem,
                "error": exc.stderr.strip(),
            }
        return {"status": "updated", "dependency": name, "ecosystem": ecosystem, "version": patched_version}

    if ecosystem == "npm":
        manifest = repo_path / (manifest_path or "package.json")
        updated = update_package_json(manifest, name, patched_version)
        if not updated:
            return {"status": "not_updated", "dependency": name, "ecosystem": ecosystem}
        try:
            run_git(["add", str(manifest)], repo_path, token=None)
            npm_cwd = manifest.parent
            subprocess.run(
                ["npm", "install", "--package-lock-only"],
                cwd=npm_cwd,
                check=True,
                capture_output=True,
                text=True,
            )
            lockfile = npm_cwd / "package-lock.json"
            if lockfile.exists():
                run_git(["add", str(lockfile)], repo_path, token=None)
        except subprocess.CalledProcessError as exc:
            return {
                "status": "update_failed",
                "dependency": name,
                "ecosystem": ecosystem,
                "error": exc.stderr.strip(),
            }
        return {"status": "updated", "dependency": name, "ecosystem": ecosystem, "version": patched_version}

    if ecosystem in ("pip", "pip-compile", "python"):
        if not manifest_path.endswith("uv.lock"):
            return {
                "status": "unsupported_manifest",
                "dependency": name,
                "ecosystem": ecosystem,
                "manifest": manifest_path,
            }
        lock_path = repo_path / manifest_path
        if not lock_path.exists():
            return {
                "status": "missing_lockfile",
                "dependency": name,
                "ecosystem": ecosystem,
                "manifest": manifest_path,
            }
        if not shutil.which("uv"):
            return {
                "status": "missing_uv",
                "dependency": name,
                "ecosystem": ecosystem,
            }
        try:
            subprocess.run(
                ["uv", "lock", "--upgrade-package", f"{name}=={patched_version}"],
                cwd=lock_path.parent,
                check=True,
                capture_output=True,
                text=True,
            )
            run_git(["add", str(lock_path)], repo_path, token=None)
        except subprocess.CalledProcessError as exc:
            return {
                "status": "update_failed",
                "dependency": name,
                "ecosystem": ecosystem,
                "error": exc.stderr.strip(),
            }
        return {"status": "updated", "dependency": name, "ecosystem": ecosystem, "version": patched_version}

    if ecosystem in ("docker", "dockerfile"):
        manifest = repo_path / (manifest_path or "Dockerfile")
        updated = update_dockerfile_base_image(manifest, name, patched_version)
        if not updated:
            return {
                "status": "not_updated",
                "dependency": name,
                "ecosystem": ecosystem,
                "manifest": manifest_path,
            }
        run_git(["add", str(manifest)], repo_path, token=None)
        return {"status": "updated", "dependency": name, "ecosystem": ecosystem, "version": patched_version}

    return {"status": "unsupported", "dependency": name, "ecosystem": ecosystem}


def run_gh(args, cwd, token):
    if not shutil.which("gh"):
        raise RuntimeError("gh CLI is required for PR creation")
    env = os.environ.copy()
    env["GH_TOKEN"] = token
    return subprocess.run(
        ["gh"] + args,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )


def ensure_upstream_remote(repo_path, upstream_repo, token):
    upstream_url = f"https://github.com/{upstream_repo}.git"
    try:
        current = run_git(["remote", "get-url", "upstream"], repo_path, token)
        if current.stdout.strip() != upstream_url:
            run_git(["remote", "set-url", "upstream", upstream_url], repo_path, token)
    except subprocess.CalledProcessError:
        run_git(["remote", "add", "upstream", upstream_url], repo_path, token)


def ensure_fork(upstream_repo, fork_owner, token, cwd):
    _, repo_name = upstream_repo.split("/", 1)
    fork_repo = f"{fork_owner}/{repo_name}"
    try:
        run_gh(["api", f"repos/{fork_repo}"], cwd, token)
        return fork_repo
    except subprocess.CalledProcessError:
        pass

    try:
        run_gh(["api", f"repos/{upstream_repo}/forks", "-f", f"owner={fork_owner}"], cwd, token)
    except subprocess.CalledProcessError as exc:
        if "already exists" not in exc.stderr.lower():
            raise

    for _ in range(10):
        try:
            run_gh(["api", f"repos/{fork_repo}"], cwd, token)
            return fork_repo
        except subprocess.CalledProcessError:
            time.sleep(1)

    raise RuntimeError(f"fork not ready for {fork_repo}")


def clone_or_update_fork(workspace_path, upstream_repo, fork_owner, token):
    fork_repo = ensure_fork(upstream_repo, fork_owner, token, workspace_path)
    repo_dir = workspace_path / fork_repo.replace("/", "__")
    repo_url = f"https://github.com/{fork_repo}.git"

    if repo_dir.exists():
        status = run_git(["status", "--porcelain"], repo_dir, token)
        if status.stdout.strip():
            return repo_dir, "dirty", fork_repo, ""
        run_git(["fetch", "origin"], repo_dir, token)
    else:
        run_git(["clone", repo_url, str(repo_dir)], workspace_path, token)

    ensure_upstream_remote(repo_dir, upstream_repo, token)
    run_git(["fetch", "upstream"], repo_dir, token)
    base_ref = run_git(["symbolic-ref", "refs/remotes/upstream/HEAD"], repo_dir, token)
    base_branch = base_ref.stdout.strip().rsplit("/", 1)[-1]
    run_git(["checkout", "-B", base_branch], repo_dir, token)
    run_git(["reset", "--hard", f"upstream/{base_branch}"], repo_dir, token)
    run_git(["push", "origin", base_branch, "--force"], repo_dir, token)

    return repo_dir, "updated", fork_repo, base_branch


def create_remediation_issue(repo, updates, token, cwd):
    issue_title = "SecOps: remediate critical vulnerabilities"
    issue_body_lines = [
        "Automated remediation for critical Dependabot alerts.",
        "",
        "Updates:",
    ]
    for update in updates:
        dep = update.get("dependency") or "unknown"
        version = update.get("version")
        status_line = update.get("status")
        if version:
            issue_body_lines.append(f"- {dep}: {version} ({status_line})")
        else:
            issue_body_lines.append(f"- {dep}: {status_line}")
    issue_body_lines.append("")
    issue_body_lines.append("Generated by SHADI SecOps.")

    issue_body = "\n".join(issue_body_lines)
    response = run_gh(
        [
            "api",
            f"repos/{repo}/issues",
            "-f",
            f"title={issue_title}",
            "-f",
            f"body={issue_body}",
        ],
        cwd,
        token,
    )
    payload = json.loads(response.stdout)
    return payload.get("number"), payload.get("html_url")


def pending_prs_path(workspace_dir):
    return Path(workspace_dir) / "secops_pending_prs.json"


def write_pending_prs(workspace_dir, pending):
    path = pending_prs_path(workspace_dir)
    path.write_text(json.dumps(pending, indent=2) + "\n", encoding="utf-8")
    return path


def load_pending_prs(workspace_dir):
    path = pending_prs_path(workspace_dir)
    if not path.exists():
        return path, {"repos": {}}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        data = {"repos": {}}
    data.setdefault("repos", {})
    return path, data


def remediate_repos(config, github_token, report, workspace_dir, create_prs=True):
    workspace_path = Path(workspace_dir)
    remediation = {}
    pending = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repos": {},
    }
    fork_owner = os.getenv("SHADI_HUMAN_GITHUB", "").strip()
    if not fork_owner:
        raise RuntimeError("SHADI_HUMAN_GITHUB must be set to create forks and PRs")

    for repo, repo_data in report.get("repos", {}).items():
        alerts = repo_data.get("data", {}).get("dependabot", [])
        actionable_alerts = [alert for alert in alerts if is_actionable_alert(alert)]
        if not actionable_alerts:
            remediation[repo] = {"status": "no_actionable_dependabot_alerts"}
            continue

        repo_path, clone_status, fork_repo, base_branch = clone_or_update_fork(
            workspace_path, repo, fork_owner, github_token
        )
        if clone_status == "dirty":
            remediation[repo] = {"status": "skipped_dirty_repo"}
            continue

        if not base_branch:
            remediation[repo] = {"status": "fork_sync_failed"}
            continue
        branch_name = f"secops/remediate-{datetime.now(timezone.utc).strftime('%Y%m%d')}"
        try:
            run_git(["checkout", "-b", branch_name], repo_path, github_token)
        except subprocess.CalledProcessError:
            run_git(["checkout", branch_name], repo_path, github_token)
        run_git(["config", "user.email", "lumuscar@cisco.com"], repo_path, github_token)
        run_git(["config", "user.name", "Luca Muscariello"], repo_path, github_token)

        updates = []
        for alert in actionable_alerts:
            update = apply_dependency_patch(repo_path, alert)
            update["severity"] = get_alert_severity(alert)
            updates.append(update)

        status = run_git(["status", "--porcelain"], repo_path, github_token)
        if not status.stdout.strip():
            remediation[repo] = {
                "status": "no_changes",
                "updates": updates,
            }
            run_git(["checkout", base_branch], repo_path, github_token)
            continue

        commit_message = "chore(secops): remediate critical vulnerabilities"
        if not is_conventional_commit(commit_message):
            raise RuntimeError(f"commit message is not conventional: '{commit_message}'")
        run_git(["add", "-A"], repo_path, github_token)
        run_git(["commit", "-m", commit_message, "--signoff"], repo_path, github_token)
        run_git(["push", "origin", branch_name], repo_path, github_token)

        pr_body_lines = [
            "Automated remediation for critical Dependabot alerts.",
            "",
            "Updates:",
        ]
        for update in updates:
            dep = update.get("dependency") or "unknown"
            version = update.get("version")
            status_line = update.get("status")
            if version:
                pr_body_lines.append(f"- {dep}: {version} ({status_line})")
            else:
                pr_body_lines.append(f"- {dep}: {status_line}")

        issue_number, issue_url = create_remediation_issue(repo, updates, github_token, repo_path)
        if issue_number:
            pr_body_lines.append("")
            pr_body_lines.append(f"Fixes #{issue_number}")
        pr_body = "\n".join(pr_body_lines)
        if not create_prs:
            pending["repos"][repo] = {
                "title": commit_message,
                "head": f"{fork_owner}:{branch_name}",
                "base": base_branch,
                "body": pr_body,
                "updates": updates,
                "issue_number": issue_number,
                "issue_url": issue_url,
                "fork_owner": fork_owner,
            }
            remediation[repo] = {
                "status": "pending_pr_approval",
                "updates": updates,
                "branch": branch_name,
                "fork": fork_repo,
                "issue_url": issue_url,
            }
        else:
            try:
                pr_response = run_gh(
                    [
                        "api",
                        f"repos/{repo}/pulls",
                        "-f",
                        f"title={commit_message}",
                        "-f",
                        f"head={fork_owner}:{branch_name}",
                        "-f",
                        f"base={base_branch}",
                        "-f",
                        f"body={pr_body}",
                    ],
                    repo_path,
                    github_token,
                )
                pr = json.loads(pr_response.stdout)
                remediation[repo] = {
                    "status": "pr_created",
                    "updates": updates,
                    "pr_url": pr.get("html_url"),
                    "branch": branch_name,
                    "fork": fork_repo,
                    "issue_url": issue_url,
                }
            except (RuntimeError, subprocess.CalledProcessError, ValueError) as exc:
                remediation[repo] = {
                    "status": "pr_failed",
                    "updates": updates,
                    "error": str(exc),
                    "branch": branch_name,
                    "fork": fork_repo,
                    "issue_url": issue_url,
                }

        run_git(["checkout", base_branch], repo_path, github_token)

    if pending["repos"]:
        write_pending_prs(workspace_dir, pending)
    return remediation


def approve_pending_prs(config, github_token, workspace_dir):
    path, pending = load_pending_prs(workspace_dir)
    results = {}
    remaining = {"generated_at": pending.get("generated_at"), "repos": {}}

    for repo, pr in pending.get("repos", {}).items():
        try:
            pr_response = run_gh(
                [
                    "api",
                    f"repos/{repo}/pulls",
                    "-f",
                    f"title={pr['title']}",
                    "-f",
                    f"head={pr['head']}",
                    "-f",
                    f"base={pr['base']}",
                    "-f",
                    f"body={pr['body']}",
                ],
                Path(workspace_dir),
                github_token,
            )
            pr_payload = json.loads(pr_response.stdout)
            results[repo] = {
                "status": "pr_created",
                "pr_url": pr_payload.get("html_url"),
                "branch": pr.get("head"),
                "issue_url": pr.get("issue_url"),
            }
        except (RuntimeError, subprocess.CalledProcessError, ValueError) as exc:
            results[repo] = {
                "status": "pr_failed",
                "error": str(exc),
                "branch": pr.get("head"),
                "issue_url": pr.get("issue_url"),
            }
            remaining["repos"][repo] = pr

    if remaining["repos"]:
        path.write_text(json.dumps(remaining, indent=2) + "\n", encoding="utf-8")
    else:
        if path.exists():
            path.unlink()
    return results


def github_get_json(api_base, token, path, query=""):
    url = f"{api_base.rstrip('/')}{path}{query}"
    request = Request(url)
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("User-Agent", "shadi-secops-agent")
    request.add_header("X-GitHub-Api-Version", "2022-11-28")
    with urlopen(request, timeout=30) as response:
        payload = response.read()
    return json.loads(payload.decode("utf-8"))


def fetch_dependabot_alerts(api_base, token, repo):
    owner, name = repo.split("/", 1)
    path = f"/repos/{owner}/{name}/dependabot/alerts"
    return github_get_json(api_base, token, path, "?state=open")


def fetch_security_issues(api_base, token, repo, label):
    owner, name = repo.split("/", 1)
    path = f"/repos/{owner}/{name}/issues"
    query = f"?state=open&labels={label}"
    return github_get_json(api_base, token, path, query)


def collect_security_report(config, github_token, allowlisted_repos, labels):
    api_base = config.get("github", {}).get("api_base", "https://api.github.com")
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repos": {},
        "skill_trace": [
            {
                "skill": "collect_security_issues",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ],
    }
    total_alerts = 0
    total_issues = 0

    for repo in allowlisted_repos:
        repo_entry = {"dependabot": [], "issues": {}}
        try:
            alerts = fetch_dependabot_alerts(api_base, github_token, repo)
            repo_entry["dependabot"] = alerts
            total_alerts += len(alerts)
        except (HTTPError, URLError, ValueError) as exc:
            repo_entry["dependabot_error"] = str(exc)

        for label in labels:
            try:
                issues = fetch_security_issues(api_base, github_token, repo, label)
                repo_entry["issues"][label] = issues
                total_issues += len(issues)
            except (HTTPError, URLError, ValueError) as exc:
                repo_entry["issues"][label] = {"error": str(exc), "items": []}

        report["repos"][repo] = {
            "dependabot_count": len(repo_entry.get("dependabot", [])),
            "issue_counts": {
                label: len(items) if isinstance(items, list) else 0
                for label, items in repo_entry["issues"].items()
            },
            "data": repo_entry,
        }

    return report, total_alerts, total_issues


def generate_llm_markdown(report, total_alerts, total_issues, llm_settings):
    try:
        from openai import AzureOpenAI, OpenAI
    except ImportError as exc:
        raise RuntimeError("openai is required for LLM reports") from exc

    prompt = (
        "You are a SecOps assistant. Generate a Markdown report with these sections:\n"
        "1) Executive summary (2-4 bullets).\n"
        "2) Critical vulnerabilities only (Dependabot or issues).\n"
        "3) Remediation plan per repo (actionable steps).\n"
        "   - If a patch is available, propose code updates and a PR summary.\n"
        "   - If a patch is not available, state that remediation is blocked and list next steps.\n"
        "4) Risk notes if no critical findings.\n\n"
        "Use concise language and include repository names.\n\n"
        "Input JSON follows.\n"
    )
    payload = {
        "generated_at": report.get("generated_at"),
        "total_dependabot_alerts": total_alerts,
        "total_labeled_issues": total_issues,
        "repos": report.get("repos", {}),
    }
    prompt = f"{prompt}{json.dumps(payload, indent=2)}"

    provider = llm_settings["provider"]
    api_key = llm_settings["api_key"]
    base_url = llm_settings["base_url"]
    model_name = llm_settings["model"]
    api_version = llm_settings.get("api_version")

    if provider in ("azure", "azure_openai", "openai") and api_version:
        client = AzureOpenAI(
            api_key=api_key,
            azure_endpoint=base_url,
            api_version=api_version,
        )
    else:
        client = OpenAI(
            api_key=api_key,
            base_url=base_url,
        )
    timeout_seconds = float(os.getenv("SHADI_LLM_TIMEOUT", "60"))
    try:
        response = client.chat.completions.create(
            model=model_name,
            messages=[{"role": "user", "content": prompt}],
            timeout=timeout_seconds,
        )
    except Exception as exc:
        raise RuntimeError(
            f"LLM report generation failed for provider '{provider}' and model '{model_name}'. "
            "Verify the secops/llm secrets for provider, endpoint, model, and API key."
        ) from exc
    choices = getattr(response, "choices", None) or []
    if choices:
        message = getattr(choices[0], "message", None)
        content = getattr(message, "content", None)
        if content:
            return content.strip()
    raise RuntimeError("LLM response did not contain text")


def write_report(report, workspace_dir, filename, total_alerts, total_issues, llm_settings):
    workspace_path = Path(workspace_dir)
    workspace_path.mkdir(parents=True, exist_ok=True)
    report_path = workspace_path / filename
    markdown = generate_llm_markdown(report, total_alerts, total_issues, llm_settings)
    report_path.write_text(markdown, encoding="utf-8")
    return report_path


def resolve_tmp_dir(agent_id_envs=None):
    base = os.getenv("SHADI_TMP_DIR", "./.tmp")
    agent_id = os.getenv("SHADI_AGENT_ID")
    if not agent_id and agent_id_envs:
        for env_name in agent_id_envs:
            value = os.getenv(env_name)
            if value:
                agent_id = value
                break
    if agent_id:
        return os.path.join(base, agent_id)
    return base


def record_secops_memory(config, summary):
    secops_config = config.get("secops", {})
    tmp_dir = resolve_tmp_dir(("SHADI_OPERATOR_AGENT_ID", "SHADI_SECOPS_AGENT_ID"))
    default_db = os.path.join(tmp_dir, "shadi-secops", "secops_memory.db")
    db_path = (
        os.getenv("SHADI_SECOPS_MEMORY_DB")
        or os.getenv("SHADI_MEMORY_DB")
        or secops_config.get("memory_db")
        or default_db
    )

    memory_key = secops_config.get("memory_key", "secops/memory_key")
    scope = secops_config.get("memory_scope", "secops")

    payload = json.dumps(summary, indent=2)
    report_day = summary.get("report_day") or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    entry_keys = [
        "security_report",
        f"security_report_{report_day}",
    ]
    try:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        store = SqlCipherMemoryStore(db_path, None, memory_key)
        results = []
        for entry_key in entry_keys:
            record_id = store.put(scope, entry_key, payload)
            results.append(str(record_id))
    except Exception as exc:
        return {
            "status": "error",
            "stderr": str(exc),
        }

    results = [item for item in results if item]
    if results:
        return {"status": "saved", "result": results}
    return {"status": "saved"}


def skill_collect_security_issues(
    labels="security,cve,vulnerability",
    report_name="secops_security_report.md",
    provider=None,
    remediate=False,
    create_prs=False,
    human_github_handle=None,
):
    config_path, config = load_secops_config()
    secops_config = config.get("secops", {})
    allowlisted_repos = secops_config.get("allowlist", [])
    store, session = create_secops_session()
    github_token, workspace, _, _ = get_secops_credentials(config, store, session)
    llm_settings = get_llm_settings(config, store, session, provider_override=provider)

    human_did = ""
    if human_github_handle:
        human_did = get_human_did(store, session, human_github_handle)

    label_list = [item.strip() for item in labels.split(",") if item.strip()]
    report, total_alerts, total_issues = collect_security_report(
        config, github_token, allowlisted_repos, label_list
    )
    if human_did:
        report["human"] = {
            "github_handle": human_github_handle,
            "did": human_did,
        }
    remediation = None
    if remediate or secops_config.get("auto_remediate"):
        allow_prs = create_prs or secops_config.get("auto_pr", False)
        remediation = remediate_repos(config, github_token, report, workspace, create_prs=allow_prs)
        report["remediation"] = remediation

    report_path = write_report(report, workspace, report_name, total_alerts, total_issues, llm_settings)

    summary = {
        "generated_at": report["generated_at"],
        "report_day": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "dependabot_alerts": total_alerts,
        "labeled_issues": total_issues,
        "repos": allowlisted_repos,
        "report_path": str(report_path),
        "model": llm_settings["model"],
        "provider": llm_settings["provider"],
        "remediation": remediation,
        "human_github_handle": human_github_handle,
        "human_did": human_did,
    }
    memory_status = record_secops_memory(config, summary)

    return {
        "status": "success",
        "config": str(config_path),
        "report_path": str(report_path),
        "dependabot_alerts": total_alerts,
        "labeled_issues": total_issues,
        "repos": allowlisted_repos,
        "memory": memory_status,
        "remediation": remediation,
        "human_github_handle": human_github_handle,
        "human_did": human_did,
    }
