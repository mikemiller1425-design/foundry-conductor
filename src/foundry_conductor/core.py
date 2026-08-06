from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


AGENT_BINARIES = {
    "codex": "codex",
    "claude": "claude",
    "cursor": "cursor-agent",
}

ALLOWED_READ_ONLY_PERMISSIONS = {
    "repositoryWrite": False,
    "nasAccess": False,
    "push": False,
}


class ConductorError(RuntimeError):
    pass


@dataclass(frozen=True)
class RepoFingerprint:
    head: str
    branch: str
    tree: str
    status_sha256: str
    status_entries: int


@dataclass(frozen=True)
class AgentCommand:
    name: str
    executable: str
    argv: list[str]


def resolve_binary(agent: str) -> str | None:
    binary = AGENT_BINARIES[agent]
    resolved = shutil.which(binary)
    if resolved:
        return resolved
    if agent == "cursor":
        candidate = Path.home() / ".local" / "bin" / "cursor-agent"
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    if agent == "codex":
        candidates = [
            Path("/Applications/ChatGPT.app/Contents/Resources/codex"),
            Path("/Applications/Codex.app/Contents/Resources/codex"),
        ]
        for candidate in candidates:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
    return None


def authentication_status(agent: str, executable: str) -> tuple[bool, str]:
    if agent == "codex":
        argv = [executable, "login", "status"]
    elif agent == "claude":
        argv = [executable, "auth", "status"]
    else:
        argv = [executable, "status"]
    completed = run_command(argv, cwd=Path.cwd(), timeout_seconds=15, check=False)
    output = (completed.stdout + completed.stderr).decode("utf-8", errors="replace")
    lowered = output.lower()
    if agent == "claude":
        try:
            logged_in = bool(json.loads(completed.stdout).get("loggedIn"))
        except (json.JSONDecodeError, AttributeError):
            logged_in = False
    elif agent == "cursor":
        logged_in = "not logged in" not in lowered and "logged in" in lowered
    else:
        logged_in = completed.returncode == 0 and "logged in" in lowered
    return logged_in, "logged_in" if logged_in else "not_logged_in"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def run_command(
    argv: Iterable[str],
    *,
    cwd: Path,
    timeout_seconds: int = 60,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            list(argv),
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=check,
        )
    except subprocess.TimeoutExpired as exc:
        raise ConductorError(f"command timed out after {timeout_seconds}s: {argv}") from exc
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode("utf-8", errors="replace").strip()
        raise ConductorError(f"command failed ({exc.returncode}): {argv}\n{stderr}") from exc


def git(repo: Path, *args: str, check: bool = True) -> bytes:
    return run_command(["git", *args], cwd=repo, check=check).stdout


def fingerprint_repo(repo: Path) -> RepoFingerprint:
    if not repo.is_dir():
        raise ConductorError(f"source repository does not exist: {repo}")
    head = git(repo, "rev-parse", "HEAD").decode().strip()
    branch = git(repo, "branch", "--show-current").decode().strip()
    tree = git(repo, "rev-parse", "HEAD^{tree}").decode().strip()
    status = git(repo, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    entries = len([item for item in status.split(b"\0") if item])
    return RepoFingerprint(
        head=head,
        branch=branch,
        tree=tree,
        status_sha256=sha256_bytes(status),
        status_entries=entries,
    )


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConductorError(f"cannot read JSON file {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ConductorError(f"expected a JSON object in {path}")
    return value


def validate_task(task: dict[str, Any]) -> None:
    required = {
        "schemaVersion",
        "id",
        "mode",
        "sourceRepository",
        "expectedBranch",
        "expectedHead",
        "permissions",
        "agents",
        "prompt",
        "timeoutSeconds",
    }
    missing = sorted(required - task.keys())
    if missing:
        raise ConductorError(f"task is missing required fields: {', '.join(missing)}")
    if task["schemaVersion"] != 1:
        raise ConductorError("only task schemaVersion 1 is supported")
    if task["mode"] != "read_only":
        raise ConductorError("this conductor version accepts read_only tasks only")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,63}", str(task["id"])):
        raise ConductorError("task id must be a lowercase slug")
    permissions = task["permissions"]
    if not isinstance(permissions, dict):
        raise ConductorError("permissions must be an object")
    for key, expected in ALLOWED_READ_ONLY_PERMISSIONS.items():
        if permissions.get(key) is not expected:
            raise ConductorError(f"read_only task requires permissions.{key}=false")
    if not isinstance(permissions.get("liveModelCalls"), bool):
        raise ConductorError("permissions.liveModelCalls must be boolean")
    agents = task["agents"]
    if not isinstance(agents, list) or not agents:
        raise ConductorError("agents must be a non-empty list")
    unknown = sorted(set(agents) - AGENT_BINARIES.keys())
    if unknown:
        raise ConductorError(f"unknown agents: {', '.join(unknown)}")
    if len(agents) != len(set(agents)):
        raise ConductorError("agents must not contain duplicates")
    if not isinstance(task["timeoutSeconds"], int) or not 1 <= task["timeoutSeconds"] <= 3600:
        raise ConductorError("timeoutSeconds must be between 1 and 3600")


def verify_baseline(task: dict[str, Any], actual: RepoFingerprint) -> None:
    if actual.head != task["expectedHead"]:
        raise ConductorError(
            f"baseline mismatch: expected {task['expectedHead']}, observed {actual.head}"
        )
    if actual.branch != task["expectedBranch"]:
        raise ConductorError(
            f"branch mismatch: expected {task['expectedBranch']}, observed {actual.branch}"
        )


def create_tracked_snapshot(source_repo: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    archive = run_command(
        ["git", "archive", "--format=tar", "HEAD"],
        cwd=source_repo,
        timeout_seconds=120,
    ).stdout
    with tempfile.NamedTemporaryFile(prefix="foundry-snapshot-", suffix=".tar") as handle:
        handle.write(archive)
        handle.flush()
        with tarfile.open(handle.name, mode="r:") as bundle:
            root = destination.resolve()
            for member in bundle.getmembers():
                target = (destination / member.name).resolve()
                if target != root and root not in target.parents:
                    raise ConductorError(f"unsafe archive member: {member.name}")
            bundle.extractall(destination, filter="data")
    git(destination, "init", "-q")
    git(destination, "add", "-A")
    run_command(
        [
            "git",
            "-c",
            "user.name=Foundry Conductor",
            "-c",
            "user.email=conductor@localhost",
            "commit",
            "-qm",
            "Disposable tracked snapshot",
        ],
        cwd=destination,
        timeout_seconds=120,
    )


def snapshot_is_clean(snapshot: Path) -> bool:
    return git(snapshot, "status", "--porcelain=v1", "-z", "--untracked-files=all") == b""


def build_agent_command(
    agent: str,
    *,
    snapshot: Path,
    prompt: str,
    response_schema: Path,
) -> AgentCommand:
    executable = resolve_binary(agent)
    if executable is None:
        executable = AGENT_BINARIES[agent]
    if agent == "codex":
        argv = [
            executable,
            "exec",
            "--sandbox",
            "read-only",
            "--ephemeral",
            "--json",
            "--cd",
            str(snapshot),
            "--output-schema",
            str(response_schema),
            "-c",
            'approval_policy="never"',
            prompt,
        ]
    elif agent == "claude":
        schema_value = load_json(response_schema)
        # Claude Code validates the schema body but currently rejects the
        # draft-2020-12 metadata URI itself. The constraint body is unchanged.
        schema_value.pop("$schema", None)
        schema = json.dumps(schema_value, separators=(",", ":"))
        argv = [
            executable,
            "-p",
            "--output-format",
            "json",
            "--permission-mode",
            "plan",
            "--tools",
            "Read,Glob,Grep",
            "--max-turns",
            "5",
            "--no-session-persistence",
            "--json-schema",
            schema,
            prompt,
        ]
    else:
        argv = [
            executable,
            "-p",
            "--output-format",
            "json",
            "--mode",
            "plan",
            "--sandbox",
            "enabled",
            "--workspace",
            str(snapshot),
            "--trust",
            prompt,
        ]
    return AgentCommand(name=agent, executable=executable, argv=argv)


def validate_agent_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConductorError("agent result is not an object")
    required = {"status", "summary", "findings", "requiresHuman"}
    if set(value) != required:
        raise ConductorError("agent result fields do not match the response schema")
    if value["status"] not in {"pass", "fail", "blocked"}:
        raise ConductorError("agent result has an invalid status")
    if not isinstance(value["summary"], str) or not value["summary"]:
        raise ConductorError("agent result summary must be a non-empty string")
    if not isinstance(value["requiresHuman"], bool):
        raise ConductorError("agent result requiresHuman must be boolean")
    if not isinstance(value["findings"], list):
        raise ConductorError("agent result findings must be an array")
    for finding in value["findings"]:
        if not isinstance(finding, dict) or set(finding) != {"severity", "message"}:
            raise ConductorError("agent finding fields do not match the response schema")
        if finding["severity"] not in {"info", "warning", "error"}:
            raise ConductorError("agent finding has an invalid severity")
        if not isinstance(finding["message"], str) or not finding["message"]:
            raise ConductorError("agent finding message must be a non-empty string")
    return value


def _json_values_from_text(text: str) -> Iterable[Any]:
    stripped = text.strip()
    if not stripped:
        return
    try:
        yield json.loads(stripped)
    except json.JSONDecodeError:
        pass
    decoder = json.JSONDecoder()
    for match in re.finditer(r"[\{\[]", text):
        try:
            value, _ = decoder.raw_decode(text[match.start() :])
            yield value
        except json.JSONDecodeError:
            continue
    for match in re.finditer(r"```(?:json)?\s*(.*?)```", text, flags=re.DOTALL | re.IGNORECASE):
        try:
            yield json.loads(match.group(1).strip())
        except json.JSONDecodeError:
            continue


def _result_candidates(value: Any) -> Iterable[Any]:
    if isinstance(value, dict):
        if {"status", "summary", "findings", "requiresHuman"}.issubset(value):
            yield value
        for key in ("structured_output", "result", "content", "text", "message", "item"):
            if key in value:
                yield from _result_candidates(value[key])
    elif isinstance(value, list):
        for item in value:
            yield from _result_candidates(item)
    elif isinstance(value, str):
        for decoded in _json_values_from_text(value):
            yield from _result_candidates(decoded)


def parse_agent_result(stdout: bytes) -> dict[str, Any]:
    text = stdout.decode("utf-8", errors="replace")
    documents = list(_json_values_from_text(text))
    if not documents:
        for line in text.splitlines():
            try:
                documents.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    for document in reversed(documents):
        for candidate in _result_candidates(document):
            try:
                return validate_agent_result(candidate)
            except ConductorError:
                continue
    raise ConductorError("no schema-valid agent result found in stdout")


def redact_command(command: AgentCommand) -> dict[str, Any]:
    argv = command.argv.copy()
    if argv:
        argv[-1] = "<task-prompt>"
    return {"agent": command.name, "executable": command.executable, "argv": argv}


class AppendOnlyLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            raise ConductorError(f"refusing to reuse append-only log: {path}")

    def append(self, event: str, **details: Any) -> None:
        record = {"at": utc_now(), "event": event, **details}
        encoded = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
        descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(descriptor, encoded)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def write_once(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, value)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def make_run_id(task_id: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{task_id}-{uuid.uuid4().hex[:8]}"


def doctor(task: dict[str, Any]) -> dict[str, Any]:
    validate_task(task)
    source_repo = Path(task["sourceRepository"]).expanduser().resolve()
    actual = fingerprint_repo(source_repo)
    checks: list[dict[str, Any]] = []
    try:
        verify_baseline(task, actual)
        checks.append({"check": "baseline", "status": "pass", "observed": actual.head})
    except ConductorError as exc:
        checks.append({"check": "baseline", "status": "fail", "detail": str(exc)})
    for agent in task["agents"]:
        resolved = resolve_binary(agent)
        checks.append(
            {
                "check": f"binary:{agent}",
                "status": "pass" if resolved else "fail",
                "observed": resolved,
            }
        )
        if resolved:
            logged_in, detail = authentication_status(agent, resolved)
            checks.append(
                {
                    "check": f"authentication:{agent}",
                    "status": "pass" if logged_in else "fail",
                    "observed": detail,
                }
            )
    checks.append(
        {
            "check": "source-mode",
            "status": "pass",
            "observed": "tracked git archive snapshot; agents never use sourceRepository as cwd",
        }
    )
    return {
        "ok": all(item["status"] == "pass" for item in checks),
        "source": asdict(actual),
        "checks": checks,
    }


def execute_task(
    *,
    root: Path,
    task_path: Path,
    live: bool,
    live_confirmed: bool,
) -> dict[str, Any]:
    task = load_json(task_path)
    validate_task(task)
    if live and not task["permissions"]["liveModelCalls"]:
        raise ConductorError("task policy forbids live model calls")
    if live and not live_confirmed:
        raise ConductorError("live execution requires --confirm-live-models")

    source_repo = Path(task["sourceRepository"]).expanduser().resolve()
    before = fingerprint_repo(source_repo)
    verify_baseline(task, before)

    run_id = make_run_id(task["id"])
    run_dir = root / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    log = AppendOnlyLog(run_dir / "events.jsonl")
    log.append("run_started", runId=run_id, taskId=task["id"], live=live)
    write_once(run_dir / "task.json", json.dumps(task, indent=2, sort_keys=True).encode() + b"\n")
    write_once(run_dir / "source-before.json", json.dumps(asdict(before), indent=2).encode() + b"\n")

    snapshot = run_dir / "snapshot"
    create_tracked_snapshot(source_repo, snapshot)
    log.append("snapshot_created", tree=before.tree)

    response_schema = root / "schemas" / "agent-result.schema.json"
    commands = [
        build_agent_command(
            agent,
            snapshot=snapshot,
            prompt=task["prompt"],
            response_schema=response_schema,
        )
        for agent in task["agents"]
    ]
    write_once(
        run_dir / "plan.json",
        json.dumps([redact_command(command) for command in commands], indent=2).encode() + b"\n",
    )

    results: list[dict[str, Any]] = []
    if live:
        for command in commands:
            if resolve_binary(command.name) is None:
                log.append("agent_blocked", agent=command.name, reason="binary_missing")
                results.append({"agent": command.name, "status": "blocked", "reason": "binary_missing"})
                continue
            log.append("agent_started", agent=command.name)
            started = time.monotonic()
            completed = run_command(
                command.argv,
                cwd=snapshot,
                timeout_seconds=task["timeoutSeconds"],
                check=False,
            )
            duration_ms = int((time.monotonic() - started) * 1000)
            response_path = run_dir / "responses" / f"{command.name}.stdout"
            error_path = run_dir / "responses" / f"{command.name}.stderr"
            write_once(response_path, completed.stdout)
            write_once(error_path, completed.stderr)
            clean = snapshot_is_clean(snapshot)
            response_valid = False
            response_error: str | None = None
            normalized: dict[str, Any] | None = None
            if completed.returncode == 0:
                try:
                    normalized = parse_agent_result(completed.stdout)
                    response_valid = True
                    write_once(
                        run_dir / "responses" / f"{command.name}.normalized.json",
                        json.dumps(normalized, indent=2, sort_keys=True).encode() + b"\n",
                    )
                except ConductorError as exc:
                    response_error = str(exc)
            if not clean or completed.returncode != 0 or not response_valid:
                status = "fail"
            else:
                status = normalized["status"]
            result = {
                "agent": command.name,
                "status": status,
                "exitCode": completed.returncode,
                "snapshotClean": clean,
                "responseValid": response_valid,
                "durationMs": duration_ms,
                "stdoutSha256": sha256_bytes(completed.stdout),
                "stderrSha256": sha256_bytes(completed.stderr),
            }
            if normalized is not None:
                result["agentResultStatus"] = normalized["status"]
                result["agentSummary"] = normalized["summary"]
                result["requiresHuman"] = normalized["requiresHuman"]
            if response_error is not None:
                result["responseError"] = response_error
            results.append(result)
            log.append("agent_finished", **result)
            if not clean:
                log.append("run_stopped", reason="snapshot_mutated", agent=command.name)
                break
    else:
        results = [
            {"agent": command.name, "status": "planned", "command": redact_command(command)}
            for command in commands
        ]
        log.append("dry_run_planned", agents=task["agents"])

    after = fingerprint_repo(source_repo)
    write_once(run_dir / "source-after.json", json.dumps(asdict(after), indent=2).encode() + b"\n")
    unchanged = before == after
    log.append("source_verified", unchanged=unchanged, before=asdict(before), after=asdict(after))
    if not unchanged:
        raise ConductorError("source repository changed during conductor run")

    summary = {
        "runId": run_id,
        "runDirectory": str(run_dir),
        "live": live,
        "sourceUnchanged": unchanged,
        "snapshotClean": snapshot_is_clean(snapshot),
        "results": results,
    }
    write_once(run_dir / "summary.json", json.dumps(summary, indent=2, sort_keys=True).encode() + b"\n")
    log.append("run_finished", sourceUnchanged=unchanged, live=live)
    return summary
