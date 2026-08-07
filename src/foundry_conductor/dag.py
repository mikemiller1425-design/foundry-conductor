from __future__ import annotations

import fnmatch
import json
import os
import re
import shutil
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .core import (
    AGENT_BINARIES, AppendOnlyLog, ConductorError,
    create_tracked_snapshot, fingerprint_repo, git, load_json, make_run_id,
    parse_structured_response, redact_command, resolve_binary, run_command,
    sha256_bytes, snapshot_is_clean, verify_baseline, write_once,
)
from .providers import build_provider_command


DEFAULT_PROVIDERS = {
    "backend": "claude", "general": "claude", "implementation": "claude",
    "frontend": "cursor", "contract": "cursor", "contract_dependency": "cursor",
    "governance": "codex", "security": "codex", "review": "codex", "integration": "codex",
}
AGENT_STAGE_TYPES = {"reconnaissance", "implementation", "review", "repair"}
WRITE_STAGE_TYPES = {"implementation", "repair", "commit"}
HIGH_RISK_PERMISSIONS = {"push", "nasAccess", "externalActions", "spending", "destructive", "productionExecution"}
CURSOR_WRITE_FORBIDDEN = "Cursor may only run read-only reconnaissance or review stages"
RECOVERY_MODES = {"reject", "validate", "completion-prompt"}


def validate_stage_result(value: Any) -> dict[str, Any]:
    fields = {"status", "handoffSha256", "workStarted", "summary", "findings", "requiresHuman"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ConductorError("generic stage result fields do not match the schema")
    if value["status"] not in {"pass", "fail", "blocked"}:
        raise ConductorError("generic stage status is invalid")
    if not isinstance(value["handoffSha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["handoffSha256"]):
        raise ConductorError("generic stage handoffSha256 is invalid")
    if value["workStarted"] is not True:
        raise ConductorError("generic stage must explicitly acknowledge that work started")
    if not isinstance(value["summary"], str) or not value["summary"]:
        raise ConductorError("generic stage summary is invalid")
    if not isinstance(value["findings"], list) or not isinstance(value["requiresHuman"], bool):
        raise ConductorError("generic stage findings or requiresHuman is invalid")
    for finding in value["findings"]:
        if not isinstance(finding, dict) or set(finding) != {"severity", "message"}:
            raise ConductorError("generic stage finding fields are invalid")
        if finding["severity"] not in {"info", "warning", "error"} or not isinstance(finding["message"], str) or not finding["message"]:
            raise ConductorError("generic stage finding is invalid")
    if value["status"] == "pass" and (value["findings"] or value["requiresHuman"]):
        raise ConductorError("generic stage pass requires zero findings and requiresHuman=false")
    if value["status"] == "fail" and not value["findings"]:
        raise ConductorError("generic stage fail requires actionable findings")
    return value


def validate_manifest(value: Any) -> dict[str, Any]:
    required = {"schemaVersion", "workflow", "id", "sourceRepository", "expectedBranch", "expectedHead", "permissions", "stages"}
    if not isinstance(value, dict) or not required.issubset(value):
        raise ConductorError("generic manifest is missing required fields")
    if value["schemaVersion"] != 1 or value["workflow"] != "generic_dag":
        raise ConductorError("unsupported generic manifest schema or workflow")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,63}", str(value["id"])):
        raise ConductorError("generic manifest id is invalid")
    permissions = value["permissions"]
    if not isinstance(permissions, dict):
        raise ConductorError("generic permissions must be an object")
    for key in HIGH_RISK_PERMISSIONS:
        if permissions.get(key, False) not in {True, False}:
            raise ConductorError(f"permissions.{key} must be boolean")
    if permissions.get("push", False):
        raise ConductorError("generic conductor does not execute pushes; push remains a human gate")
    stages = value["stages"]
    if not isinstance(stages, list) or not stages:
        raise ConductorError("generic manifest stages must be non-empty")
    ids: list[str] = []
    for stage in stages:
        if not isinstance(stage, dict):
            raise ConductorError("generic stage must be an object")
        for field in ("id", "type", "dependsOn", "timeoutSeconds", "maxAttempts"):
            if field not in stage:
                raise ConductorError(f"generic stage is missing {field}")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,63}", str(stage["id"])):
            raise ConductorError("generic stage id is invalid")
        ids.append(stage["id"])
        if stage["type"] not in AGENT_STAGE_TYPES | {"workspace_seed", "test", "commit", "human_gate"}:
            raise ConductorError(f"generic stage {stage['id']} type is invalid")
        if not isinstance(stage["dependsOn"], list) or not all(isinstance(item, str) for item in stage["dependsOn"]):
            raise ConductorError(f"generic stage {stage['id']} dependencies are invalid")
        if not isinstance(stage["timeoutSeconds"], int) or not 1 <= stage["timeoutSeconds"] <= 3600:
            raise ConductorError(f"generic stage {stage['id']} timeout is invalid")
        if not isinstance(stage["maxAttempts"], int) or not 1 <= stage["maxAttempts"] <= 5:
            raise ConductorError(f"generic stage {stage['id']} maxAttempts is invalid")
        if stage["type"] in AGENT_STAGE_TYPES:
            role = stage.get("role", stage["type"])
            provider = stage.get("provider", DEFAULT_PROVIDERS.get(role))
            if provider not in AGENT_BINARIES:
                raise ConductorError(f"generic stage {stage['id']} provider is invalid")
            stage["provider"] = provider
            if provider == "cursor" and stage["type"] in {"implementation", "repair"}:
                raise ConductorError(f"generic stage {stage['id']}: {CURSOR_WRITE_FORBIDDEN}")
            if not isinstance(stage.get("prompt"), str) or not stage["prompt"]:
                raise ConductorError(f"generic stage {stage['id']} prompt is required")
            if not isinstance(stage.get("maxTurns", 5), int) or not 1 <= stage.get("maxTurns", 5) <= 50:
                raise ConductorError(f"generic stage {stage['id']} maxTurns is invalid")
            if stage.get("emitAccumulatedDiff", False) not in {True, False}:
                raise ConductorError(f"generic stage {stage['id']} emitAccumulatedDiff is invalid")
            if stage.get("emitAccumulatedDiff", False) and stage["type"] not in {"implementation", "repair"}:
                raise ConductorError(f"generic stage {stage['id']} cannot emit an accumulated diff")
            if "finishReserveSeconds" in stage:
                reserve = stage["finishReserveSeconds"]
                if not isinstance(reserve, int) or not 1 <= reserve < stage["timeoutSeconds"]:
                    raise ConductorError(f"generic stage {stage['id']} finishReserveSeconds is invalid")
            context_paths = stage.get("contextPaths", [])
            if not isinstance(context_paths, list) or not all(
                isinstance(item, str) and item and not item.startswith("/") and ".." not in Path(item).parts
                for item in context_paths
            ):
                raise ConductorError(f"generic stage {stage['id']} contextPaths are invalid")
            attachments = stage.get("attachments", [])
            attachment_names: list[str] = []
            if not isinstance(attachments, list):
                raise ConductorError(f"generic stage {stage['id']} attachments are invalid")
            for attachment in attachments:
                if not isinstance(attachment, dict) or set(attachment) != {"path", "sha256", "name"}:
                    raise ConductorError(f"generic stage {stage['id']} attachment fields are invalid")
                relative = Path(attachment["path"]) if isinstance(attachment["path"], str) else Path("..")
                name = attachment["name"]
                if relative.is_absolute() or ".." in relative.parts or not relative.parts:
                    raise ConductorError(f"generic stage {stage['id']} attachment path is invalid")
                if not isinstance(name, str) or Path(name).name != name or name in {"", ".", ".."}:
                    raise ConductorError(f"generic stage {stage['id']} attachment name is invalid")
                if not isinstance(attachment["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", attachment["sha256"]):
                    raise ConductorError(f"generic stage {stage['id']} attachment sha256 is invalid")
                attachment_names.append(name)
            if len(attachment_names) != len(set(attachment_names)):
                raise ConductorError(f"generic stage {stage['id']} attachment names must be unique")
            if "recoveryPolicy" in stage:
                if stage["type"] not in {"implementation", "repair"}:
                    raise ConductorError(f"generic stage {stage['id']} recoveryPolicy is only valid on write stages")
                _validate_recovery_policy(stage["id"], stage["recoveryPolicy"], stage.get("allowedPaths", []))
        if stage["type"] == "review" and "repairPolicy" in stage:
            policy = stage["repairPolicy"]
            if not isinstance(policy, dict) or not isinstance(policy.get("maxRounds"), int) or not 1 <= policy["maxRounds"] <= 5:
                raise ConductorError(f"review stage {stage['id']} repairPolicy is invalid")
            provider = policy.get("provider", DEFAULT_PROVIDERS.get(policy.get("role", "implementation")))
            if provider not in AGENT_BINARIES:
                raise ConductorError(f"review stage {stage['id']} repair provider is invalid")
            policy["provider"] = provider
            if provider == "cursor" and not policy.get("readOnly", False):
                raise ConductorError(f"review stage {stage['id']}: {CURSOR_WRITE_FORBIDDEN}")
            if not isinstance(policy.get("prompt"), str) or not policy["prompt"]:
                raise ConductorError(f"review stage {stage['id']} repair prompt is required")
            if not isinstance(policy.get("maxTurns", 5), int) or not 1 <= policy.get("maxTurns", 5) <= 50:
                raise ConductorError(f"review stage {stage['id']} repair maxTurns is invalid")
            if not policy.get("readOnly", False) and (not isinstance(policy.get("allowedPaths"), list) or not policy["allowedPaths"]):
                raise ConductorError(f"review stage {stage['id']} repair requires allowedPaths")
        if stage["type"] in WRITE_STAGE_TYPES:
            if not isinstance(stage.get("allowedPaths"), list) or not stage["allowedPaths"]:
                raise ConductorError(f"write stage {stage['id']} requires exact allowedPaths")
        if stage["type"] == "test":
            command = stage.get("command")
            if not isinstance(command, list) or not command or not all(isinstance(item, str) and item for item in command):
                raise ConductorError(f"test stage {stage['id']} command is invalid")
            allowed = stage.get("allowedCommands", [])
            if command not in allowed:
                raise ConductorError(f"test stage {stage['id']} command is not explicitly allowed")
            preserve_paths = stage.get("preservePaths", [])
            if not isinstance(preserve_paths, list) or not all(
                isinstance(item, str) and item and not Path(item).is_absolute() and ".." not in Path(item).parts
                for item in preserve_paths
            ):
                raise ConductorError(f"test stage {stage['id']} preservePaths are invalid")
        if stage["type"] == "workspace_seed":
            if not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z-[a-z0-9-]+-[0-9a-f]{8}", str(stage.get("sourceRunId", ""))):
                raise ConductorError(f"workspace seed {stage['id']} sourceRunId is invalid")
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,63}", str(stage.get("sourceStageId", ""))):
                raise ConductorError(f"workspace seed {stage['id']} sourceStageId is invalid")
            if not isinstance(stage.get("expectedPatchSha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", stage["expectedPatchSha256"]):
                raise ConductorError(f"workspace seed {stage['id']} expectedPatchSha256 is invalid")
            if not isinstance(stage.get("allowedPaths"), list) or not stage["allowedPaths"]:
                raise ConductorError(f"workspace seed {stage['id']} requires exact allowedPaths")
            source_attempt = stage.get("sourceAttempt", "initial")
            if not isinstance(source_attempt, str) or not re.fullmatch(r"(initial|attempt-[0-9]{2})", source_attempt):
                raise ConductorError(f"workspace seed {stage['id']} sourceAttempt is invalid")
            if "expectedDiagnosticSha256" in stage:
                digest = stage["expectedDiagnosticSha256"]
                if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                    raise ConductorError(f"workspace seed {stage['id']} expectedDiagnosticSha256 is invalid")
        if stage["type"] == "human_gate":
            required = stage.get("requireAccepted")
            if required is not None:
                if not isinstance(required, list) or not required or not all(isinstance(item, str) for item in required):
                    raise ConductorError(f"human_gate {stage['id']} requireAccepted is invalid")
                if not set(required).issubset(set(stage["dependsOn"])):
                    raise ConductorError(f"human_gate {stage['id']} requireAccepted must be subset of dependsOn")
        gate = stage.get("gate")
        if gate is not None and gate not in HIGH_RISK_PERMISSIONS | {"custom"}:
            raise ConductorError(f"generic stage {stage['id']} gate is invalid")
        if gate in HIGH_RISK_PERMISSIONS and not permissions.get(gate, False):
            raise ConductorError(f"generic stage {stage['id']} requests unauthorized permission {gate}")
    if len(ids) != len(set(ids)):
        raise ConductorError("generic stage IDs must be unique")
    known = set(ids)
    for stage in stages:
        if not set(stage["dependsOn"]).issubset(known) or stage["id"] in stage["dependsOn"]:
            raise ConductorError(f"generic stage {stage['id']} dependencies are invalid")
        required = stage.get("requireAccepted")
        if required is not None and not set(required).issubset(known):
            raise ConductorError(f"generic stage {stage['id']} requireAccepted references unknown stages")
    topological_order(value)
    return value


def _validate_recovery_policy(stage_id: str, policy: Any, parent_paths: list[str]) -> None:
    if not isinstance(policy, dict):
        raise ConductorError(f"write stage {stage_id} recoveryPolicy is invalid")
    if not isinstance(policy.get("maxAttempts"), int) or not 1 <= policy["maxAttempts"] <= 3:
        raise ConductorError(f"write stage {stage_id} recoveryPolicy.maxAttempts is invalid")
    mode = policy.get("mode", "validate")
    if mode not in RECOVERY_MODES:
        raise ConductorError(f"write stage {stage_id} recoveryPolicy.mode is invalid")
    policy["mode"] = mode
    if not isinstance(policy.get("timeoutSeconds", 120), int) or not 1 <= policy.get("timeoutSeconds", 120) <= 1800:
        raise ConductorError(f"write stage {stage_id} recoveryPolicy.timeoutSeconds is invalid")
    if not isinstance(policy.get("maxTurns", 5), int) or not 1 <= policy.get("maxTurns", 5) <= 20:
        raise ConductorError(f"write stage {stage_id} recoveryPolicy.maxTurns is invalid")
    paths = policy.get("allowedPaths", parent_paths)
    if not isinstance(paths, list) or not paths:
        raise ConductorError(f"write stage {stage_id} recoveryPolicy.allowedPaths are invalid")
    if not set(paths).issubset(set(parent_paths)):
        raise ConductorError(f"write stage {stage_id} recoveryPolicy.allowedPaths cannot widen stage allowlist")
    policy["allowedPaths"] = paths


def _finish_reserve_seconds(stage: dict[str, Any]) -> int:
    if "finishReserveSeconds" in stage:
        return int(stage["finishReserveSeconds"])
    timeout = stage["timeoutSeconds"]
    preferred = max(30, min(120, timeout // 10))
    # Always leave at least half the stage budget for productive work.
    return min(preferred, max(1, timeout // 2))


def _work_budget_seconds(stage: dict[str, Any]) -> int:
    reserve = _finish_reserve_seconds(stage)
    budget = stage["timeoutSeconds"] - reserve
    if budget < 1:
        raise ConductorError(f"stage {stage['id']} finish reserve leaves no work budget")
    return budget


def _is_timeout_error(error: str) -> bool:
    return "timed out after" in error


def _is_hard_attempt_failure(error: str) -> bool:
    markers = (
        "outside allowedPaths",
        "mutated its isolated workspace",
        "wrong handoff",
        "recoveryPolicy.allowedPaths cannot widen",
    )
    return any(marker in error for marker in markers)


def _path_sha256(workspace: Path, relative: str) -> str:
    target = workspace / relative
    if not target.is_file() or target.is_symlink():
        return sha256_bytes(b"")
    return sha256_bytes(target.read_bytes())


def _preserve_diagnostic(
    *,
    run_dir: Path,
    stage_id: str,
    attempt: int,
    workspace: Path,
    reason: str,
    handoff_hash: str,
) -> dict[str, Any]:
    changed = _changed_paths(workspace)
    path_hashes = {path: _path_sha256(workspace, path) for path in changed}
    status_bytes = git(workspace, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    diff = git(workspace, "diff", "--binary", "HEAD")
    body = {
        "stageId": stage_id,
        "attempt": attempt,
        "reason": reason,
        "accepted": False,
        "handoffSha256": handoff_hash,
        "workspace": str(workspace.relative_to(run_dir)),
        "changedPaths": changed,
        "changedPathSha256": path_hashes,
        "workspaceStatusSha256": sha256_bytes(status_bytes),
        "diffSha256": sha256_bytes(diff),
    }
    diagnostic_hash = sha256_bytes(json.dumps(body, sort_keys=True, separators=(",", ":")).encode())
    body["diagnosticSha256"] = diagnostic_hash
    prefix = run_dir / "stages" / stage_id / f"attempt-{attempt:02d}"
    write_once(prefix.with_suffix(".diagnostic.json"), json.dumps(body, indent=2, sort_keys=True).encode() + b"\n")
    write_once(prefix.with_suffix(".diagnostic.diff.patch"), diff)
    write_once(prefix.with_suffix(".diagnostic.changed-files.json"), json.dumps(changed, indent=2).encode() + b"\n")
    write_once(run_dir / "workspaces" / stage_id / f"attempt-{attempt:02d}.diagnostic", (diagnostic_hash + "\n").encode())
    return body


def _verify_diagnostic_hash(workspace: Path, diagnostic: dict[str, Any]) -> None:
    changed = _changed_paths(workspace)
    if changed != diagnostic["changedPaths"]:
        raise ConductorError("diagnostic workspace changed-path set drifted before recovery")
    for path, expected in diagnostic["changedPathSha256"].items():
        if _path_sha256(workspace, path) != expected:
            raise ConductorError(f"diagnostic workspace file hash drifted before recovery: {path}")
    status_bytes = git(workspace, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    if sha256_bytes(status_bytes) != diagnostic["workspaceStatusSha256"]:
        raise ConductorError("diagnostic workspace status hash drifted before recovery")
    probe = {key: value for key, value in diagnostic.items() if key != "diagnosticSha256"}
    if sha256_bytes(json.dumps(probe, sort_keys=True, separators=(",", ":")).encode()) != diagnostic["diagnosticSha256"]:
        raise ConductorError("diagnostic artifact hash mismatch")


def _diagnostic_allowlist_clean(diagnostic: dict[str, Any], allowed_paths: list[str]) -> bool:
    return bool(diagnostic["changedPaths"]) and _paths_allowed(diagnostic["changedPaths"], allowed_paths)


def topological_order(manifest: dict[str, Any]) -> list[str]:
    remaining = {stage["id"]: set(stage["dependsOn"]) for stage in manifest["stages"]}
    order: list[str] = []
    while remaining:
        ready = [stage_id for stage_id, deps in remaining.items() if not deps]
        if not ready:
            raise ConductorError("generic manifest DAG contains a cycle")
        for stage_id in ready:
            order.append(stage_id)
            remaining.pop(stage_id)
        for deps in remaining.values():
            deps.difference_update(ready)
    return order


def _changed_paths(snapshot: Path) -> list[str]:
    raw = git(snapshot, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    paths: list[str] = []
    for entry in [item for item in raw.split(b"\0") if item]:
        text = entry.decode("utf-8", errors="replace")
        paths.append(text[3:])
    return sorted(paths)


def _paths_allowed(paths: list[str], patterns: list[str]) -> bool:
    return all(any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns) for path in paths)


def _changed_state(workspace: Path, paths: list[str]) -> str:
    records: list[dict[str, Any]] = []
    for relative in paths:
        path = workspace / relative
        if path.is_symlink():
            records.append({"path": relative, "type": "symlink", "target": os.readlink(path)})
        elif path.is_file():
            records.append({"path": relative, "type": "file", "sha256": sha256_bytes(path.read_bytes()), "mode": path.stat().st_mode & 0o777})
        else:
            records.append({"path": relative, "type": "missing"})
    return sha256_bytes(json.dumps(records, sort_keys=True, separators=(",", ":")).encode())


def _workspace_patch(workspace: Path, *, accumulated: bool = False) -> tuple[list[str], bytes]:
    git(workspace, "add", "-A")
    base = "HEAD^" if accumulated else "HEAD"
    changed = [item.decode() for item in git(workspace, "diff", "--cached", "--name-only", "-z", base).split(b"\0") if item]
    return sorted(changed), git(workspace, "diff", "--cached", "--binary", base)


def _input_manifest(stage: dict[str, Any], accepted: dict[str, dict[str, Any]]) -> tuple[dict[str, str], str]:
    inputs = {dependency: accepted[dependency]["artifactSha256"] for dependency in stage["dependsOn"]}
    encoded = json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()
    return inputs, sha256_bytes(encoded)


def _create_workspace(base_snapshot: Path, destination: Path) -> None:
    if destination.exists():
        raise ConductorError(f"isolated workspace destination already exists: {destination}")
    shutil.copytree(base_snapshot, destination, symlinks=True)
    if not (destination / ".git").is_dir():
        raise ConductorError(f"isolated workspace copy has no Git metadata: {destination}")
    exclude = destination / ".git" / "info" / "exclude"
    with exclude.open("a", encoding="utf-8") as handle:
        handle.write("\n.conductor/\n")


def _build_handoff(
    *, run_dir: Path, workspace: Path, stage: dict[str, Any], accepted: dict[str, dict[str, Any]],
    instructions: str, suffix: str = "",
) -> tuple[Path, str, dict[str, Any]]:
    name = stage["id"] + suffix
    handoff = run_dir / "handoffs" / name
    write_once(handoff / "instructions.md", instructions.encode() + b"\n")
    files: list[dict[str, str]] = [{"path": "instructions.md", "sha256": sha256_bytes((instructions + "\n").encode())}]
    for dependency in stage["dependsOn"]:
        record = accepted[dependency]
        dependency_dir = handoff / "dependencies" / dependency
        accepted_bytes = json.dumps(record, indent=2, sort_keys=True).encode() + b"\n"
        write_once(dependency_dir / "accepted.json", accepted_bytes)
        files.append({"path": str((dependency_dir / "accepted.json").relative_to(handoff)), "sha256": sha256_bytes(accepted_bytes)})
        for relative in record.get("artifactFiles", []):
            source = run_dir / relative
            if not source.is_file():
                raise ConductorError(f"accepted dependency artifact is missing: {relative}")
            target = dependency_dir / "artifacts" / Path(relative).name
            data = source.read_bytes()
            write_once(target, data)
            files.append({"path": str(target.relative_to(handoff)), "sha256": sha256_bytes(data)})
            if (target.name == "diff.patch" or target.name.endswith(".diff.patch")) and data:
                completed = run_command(["git", "apply", "--check", str(target)], cwd=workspace, check=False)
                if completed.returncode == 0:
                    run_command(["git", "apply", str(target)], cwd=workspace)
    conductor_root = run_dir.parent.parent.resolve()
    for attachment in stage.get("attachments", []):
        candidate = conductor_root / attachment["path"]
        source = candidate.resolve()
        if candidate.is_symlink() or conductor_root not in source.parents or not source.is_file():
            raise ConductorError(f"static attachment is outside conductor evidence or unsafe: {attachment['path']}")
        data = source.read_bytes()
        if sha256_bytes(data) != attachment["sha256"]:
            raise ConductorError(f"static attachment hash mismatch: {attachment['path']}")
        target = handoff / "attachments" / attachment["name"]
        write_once(target, data)
        files.append({"path": str(target.relative_to(handoff)), "sha256": attachment["sha256"]})
    tracked = [item.decode() for item in git(workspace, "ls-files", "--cached", "--others", "--exclude-standard", "-z").split(b"\0") if item]
    copied_context: set[str] = set()
    for pattern in stage.get("contextPaths", []):
        matches = sorted(path for path in tracked if fnmatch.fnmatchcase(path, pattern))
        if not matches:
            raise ConductorError(f"handoff contextPath matched no tracked file: {pattern}")
        for relative in matches:
            if relative in copied_context:
                continue
            source = workspace / relative
            if not source.is_file() or source.is_symlink():
                raise ConductorError(f"handoff context file is unsafe: {relative}")
            target = handoff / "context" / relative
            data = source.read_bytes()
            write_once(target, data)
            files.append({"path": str(target.relative_to(handoff)), "sha256": sha256_bytes(data)})
            copied_context.add(relative)
    manifest = {"stageId": stage["id"], "dependencies": stage["dependsOn"], "files": sorted(files, key=lambda item: item["path"])}
    digest = sha256_bytes(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode())
    manifest["handoffSha256"] = digest
    write_once(handoff / "manifest.json", json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n")
    visible = workspace / ".conductor" / "handoff"
    visible.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(handoff, visible)
    return handoff, digest, manifest


def _checkpoint_dependencies(workspace: Path) -> None:
    if not _changed_paths(workspace):
        return
    git(workspace, "add", "-A")
    run_command(
        ["git", "-c", "user.name=Foundry Conductor", "-c", "user.email=conductor@localhost", "commit", "-qm", "conductor dependency checkpoint"],
        cwd=workspace,
    )


def _materialize_workspace_seed(base_snapshot: Path, source_workspace: Path, destination: Path) -> tuple[list[str], bytes]:
    _create_workspace(base_snapshot, destination)
    changed = _changed_paths(source_workspace)
    for relative in changed:
        source = source_workspace / relative
        target = destination / relative
        if source.is_symlink():
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(os.readlink(source))
        elif source.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        elif not source.exists() and target.exists():
            target.unlink()
    git(destination, "add", "-A")
    return changed, git(destination, "diff", "--cached", "--binary", "HEAD")


def _stage_prompt(
    stage: dict[str, Any],
    handoff_hash: str,
    handoff_path: Path,
    write_allowed: bool,
    feedback: list[dict[str, Any]] | None = None,
    *,
    diagnostic: dict[str, Any] | None = None,
    finish_reserve_seconds: int | None = None,
    recovery_mode: str | None = None,
) -> str:
    boundary = "Read-only: do not modify any file." if not write_allowed else (
        "Controlled-write stage in a disposable snapshot. Modify only these allowed paths: "
        + json.dumps(stage.get("allowedPaths", []))
    )
    finish = finish_reserve_seconds if finish_reserve_seconds is not None else _finish_reserve_seconds(stage)
    work_budget = max(1, stage["timeoutSeconds"] - finish)
    test_policy = (
        "Do not run package test suites, typecheck, lint, or format. The conductor owns formal gates "
        "via exact allowedCommands. Manifest-authorized executable test commands (none means no test command): "
        + json.dumps(stage.get("allowedCommands", []))
    )
    retry_block = ""
    if diagnostic is not None:
        retry_block = f"""
RETRY / RECOVERY CONSTRAINTS:
Previous attempt {diagnostic['attempt']} ended without acceptance: {diagnostic['reason']}
Diagnostic artifact SHA-256 (NOT accepted): {diagnostic['diagnosticSha256']}
Observed unfinished changed paths (NOT accepted): {json.dumps(diagnostic.get('changedPaths', []))}
Do not rewrite already-validated accepted dependency artifacts.
Complete only unfinished checkpoint work within the exact allowedPaths above.
Do not widen allowedPaths. Do not claim acceptance of diagnostic-only work.
"""
    if recovery_mode in {"validate", "completion-prompt"}:
        retry_block += (
            "\nFINISH-AND-RETURN NOW: stop editing; serialize the required schema-valid acknowledgement "
            f"using the exact handoff digest. Recovery mode={recovery_mode}; diagnosticSha256 must remain binding.\n"
        )
    return f"""You are executing generic conductor stage `{stage['id']}` ({stage['type']}).
{boundary}
Do not access /Volumes, push, spend, perform external actions, run production, or invoke another model.
The provider adapter's sandboxed read-only file inspection tools are permitted for the workspace and
handoff only. {test_policy}
Work budget seconds before finish reserve: {work_budget}
Finish reserve seconds (schema serialization only): {finish}
Inspectable handoff folder: {handoff_path}
Canonical handoff SHA-256: {handoff_hash}
Read every handoff file before work. Explicitly copy this digest into `handoffSha256` and set
`workStarted=true` only after the handoff was read and work actually started.
Routed review findings: {json.dumps(feedback or [], sort_keys=True)}
{retry_block}
{stage.get('prompt', '')}

Return only the structured response required by the supplied schema. Reserve the finish window solely
for that schema-valid JSON acknowledgement. A pass requires zero findings and requiresHuman=false.
A review may return fail with actionable findings for automatic repair.
"""


def _build_stage_command(stage: dict[str, Any], snapshot: Path, prompt: str, schema: Path):
    return build_provider_command(
        stage["provider"],
        mode="controlled_write" if stage["type"] in {"implementation", "repair"} else "read_only",
        snapshot=snapshot, prompt=prompt, response_schema=schema,
        max_turns=stage.get("maxTurns", 5),
    )


def _append_event(path: Path, event: str, **details: Any) -> None:
    record = {"at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat().replace("+00:00", "Z"), "event": event, **details}
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND)
    try:
        os.write(descriptor, (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def run_dag(*, root: Path, manifest_path: Path, live: bool, live_confirmed: bool, resume_run_id: str | None = None) -> dict[str, Any]:
    manifest = validate_manifest(load_json(manifest_path))
    manifest_hash = sha256_bytes(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode())
    if live and not live_confirmed:
        raise ConductorError("live generic DAG run requires --confirm-live-models")
    source = Path(manifest["sourceRepository"]).expanduser().resolve()
    before = fingerprint_repo(source)
    verify_baseline(manifest, before)
    run_id = make_run_id(manifest["id"])
    run_dir = root / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    log = AppendOnlyLog(run_dir / "events.jsonl")
    log.append("dag_run_started", runId=run_id, manifestId=manifest["id"], live=live, resumeRunId=resume_run_id)
    write_once(run_dir / "manifest.json", json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n")
    write_once(run_dir / "source-before.json", json.dumps(asdict(before), indent=2).encode() + b"\n")
    snapshot = run_dir / "snapshot"
    create_tracked_snapshot(source, snapshot)
    order = topological_order(manifest)
    write_once(run_dir / "plan.json", json.dumps({"order": order, "providers": {stage["id"]: stage.get("provider") for stage in manifest["stages"]}}, indent=2, sort_keys=True).encode() + b"\n")
    stage_by_id = {stage["id"]: stage for stage in manifest["stages"]}
    accepted: dict[str, dict[str, Any]] = {}
    resume_dir = (root / "runs" / resume_run_id).resolve() if resume_run_id else None
    if resume_dir is not None and (resume_dir.parent != (root / "runs").resolve() or not resume_dir.is_dir()):
        raise ConductorError("generic resume run does not exist")
    resume_summary = load_json(resume_dir / "summary.json") if resume_dir else None
    if resume_summary is not None and resume_summary.get("manifestSha256") != manifest_hash:
        raise ConductorError("resume run uses a different generic manifest")
    accepted_record_hashes: dict[str, str] = {}
    status = "planned" if not live else "running"
    try:
        if live:
            for stage_id in order:
                stage = stage_by_id[stage_id]
                prior = resume_dir / "stages" / stage_id / "accepted.json" if resume_dir else None
                if prior is not None and prior.is_file():
                    expected_record_hash = resume_summary.get("acceptedRecordSha256", {}).get(stage_id)
                    if expected_record_hash != sha256_bytes(prior.read_bytes()):
                        raise ConductorError(f"resume accepted artifact hash mismatch: {stage_id}")
                    record = load_json(prior)
                    if record.get("stageId") != stage_id:
                        raise ConductorError(f"resume artifact targets wrong stage: {stage_id}")
                    imported_artifacts: list[bytes] = []
                    artifact_hashes = record.get("artifactFileSha256", {})
                    for relative in record.get("artifactFiles", []):
                        source_artifact = resume_dir / relative
                        if not source_artifact.is_file():
                            raise ConductorError(f"resume accepted artifact file is missing: {relative}")
                        data = source_artifact.read_bytes()
                        if artifact_hashes and artifact_hashes.get(relative) != sha256_bytes(data):
                            raise ConductorError(f"resume accepted artifact file hash mismatch: {relative}")
                        write_once(run_dir / relative, data)
                        imported_artifacts.append(data)
                    if record.get("type") in AGENT_STAGE_TYPES and not artifact_hashes:
                        normalized = [relative for relative in record.get("artifactFiles", []) if relative.endswith(".normalized.json")]
                        if not normalized:
                            raise ConductorError(f"resume agent artifact has no normalized response: {stage_id}")
                        result = load_json(run_dir / normalized[-1])
                        recomputed = sha256_bytes(json.dumps(result, sort_keys=True).encode() + b"".join(imported_artifacts))
                        if recomputed != record.get("artifactSha256"):
                            raise ConductorError(f"resume accepted artifact content mismatch: {stage_id}")
                    accepted[stage_id] = record
                    accepted_record_hashes[stage_id] = expected_record_hash
                    write_once(run_dir / "stages" / stage_id / "accepted-import.json", json.dumps(record, indent=2, sort_keys=True).encode() + b"\n")
                    log.append("stage_imported", stageId=stage_id, artifactSha256=record["artifactSha256"], resumeRunId=resume_run_id)
                    continue
                inputs, input_hash = _input_manifest(stage, accepted)
                if stage["type"] == "human_gate" or stage.get("gate"):
                    approval = run_dir / "approvals" / f"{stage_id}.json"
                    prior_approval = resume_dir / "approvals" / f"{stage_id}.json" if resume_dir else None
                    if prior_approval is not None and prior_approval.is_file():
                        decision = load_json(prior_approval)
                        if decision.get("decision") == "refuse":
                            raise ConductorError(f"operator refused stage {stage_id}")
                        write_once(approval, json.dumps(decision, indent=2, sort_keys=True).encode() + b"\n")
                    missing_required = [item for item in stage.get("requireAccepted", []) if item not in accepted]
                    if missing_required:
                        raise ConductorError(
                            f"human_gate {stage_id} missing required accepted stages: {', '.join(missing_required)}"
                        )
                    if not approval.is_file():
                        status = "waiting_for_approval"
                        log.append("human_gate_waiting", stageId=stage_id, gate=stage.get("gate", "custom"), inputArtifactSha256=input_hash)
                        break
                artifact_files: list[str] = []
                test_result: dict[str, Any] | None = None
                if stage["type"] in AGENT_STAGE_TYPES:
                    def invoke_agent(
                        active_stage: dict[str, Any], workspace: Path, handoff_path: Path,
                        handoff_hash: str, prefix: Path, feedback: list[dict[str, Any]] | None = None,
                        *,
                        timeout_seconds: int | None = None,
                        diagnostic: dict[str, Any] | None = None,
                        recovery_mode: str | None = None,
                        baseline_paths_override: list[str] | None = None,
                    ) -> dict[str, Any]:
                        baseline_paths = baseline_paths_override if baseline_paths_override is not None else _changed_paths(workspace)
                        write_allowed = active_stage["type"] in {"implementation", "repair"}
                        prompt = _stage_prompt(
                            active_stage, handoff_hash, workspace / ".conductor" / "handoff",
                            write_allowed, feedback,
                            diagnostic=diagnostic,
                            finish_reserve_seconds=_finish_reserve_seconds(active_stage) if write_allowed else None,
                            recovery_mode=recovery_mode,
                        )
                        command = _build_stage_command(active_stage, workspace, prompt, root / "schemas" / "generic-stage-result.schema.json")
                        write_once(prefix.with_suffix(".prompt.txt"), prompt.encode() + b"\n")
                        write_once(prefix.with_suffix(".command.json"), json.dumps(redact_command(command), indent=2, sort_keys=True).encode() + b"\n")
                        operation_id = active_stage["id"]
                        log.append("provider_work_started", stageId=stage_id, operationId=operation_id, provider=active_stage["provider"], handoffSha256=handoff_hash, workspace=str(workspace))
                        budget = timeout_seconds if timeout_seconds is not None else active_stage["timeoutSeconds"]
                        completed = run_command(command.argv, cwd=workspace, timeout_seconds=budget, check=False)
                        write_once(prefix.with_suffix(".stdout"), completed.stdout)
                        write_once(prefix.with_suffix(".stderr"), completed.stderr)
                        if completed.returncode != 0:
                            raise ConductorError(f"provider exited with code {completed.returncode}")
                        result = parse_structured_response(completed.stdout, validate_stage_result)
                        if result["handoffSha256"] != handoff_hash:
                            raise ConductorError("provider acknowledged the wrong handoff digest")
                        changed = _changed_paths(workspace)
                        if active_stage["type"] in {"reconnaissance", "review"} and changed != baseline_paths:
                            raise ConductorError("read-only generic stage mutated its isolated workspace")
                        if active_stage["type"] in {"implementation", "repair"} and not all(
                            path in baseline_paths or any(fnmatch.fnmatchcase(path, pattern) for pattern in active_stage.get("allowedPaths", []))
                            for path in changed
                        ):
                            raise ConductorError("generic stage changed a path outside allowedPaths")
                        if active_stage["type"] in {"implementation", "repair"} and changed == baseline_paths:
                            raise ConductorError("controlled-write generic stage produced no changed artifact")
                        write_once(prefix.with_suffix(".normalized.json"), json.dumps(result, indent=2, sort_keys=True).encode() + b"\n")
                        log.append("provider_handoff_acknowledged", stageId=stage_id, operationId=operation_id, provider=active_stage["provider"], handoffSha256=handoff_hash)
                        log.append("provider_completed", stageId=stage_id, operationId=operation_id, provider=active_stage["provider"], status=result["status"], findingCount=len(result["findings"]))
                        return result

                    accepted_result = None
                    result = None
                    last_attempt_error = None
                    last_diagnostic: dict[str, Any] | None = None
                    workspace: Path | None = None
                    handoff_hash = ""
                    recovery_policy = stage.get("recoveryPolicy") if stage["type"] in {"implementation", "repair"} else None
                    recovery_used = 0
                    write_stage = stage["type"] in {"implementation", "repair"}
                    for attempt in range(1, stage["maxAttempts"] + 1):
                        workspace = run_dir / "workspaces" / stage_id / f"attempt-{attempt:02d}"
                        _create_workspace(snapshot, workspace)
                        handoff_path, handoff_hash, _ = _build_handoff(
                            run_dir=run_dir, workspace=workspace, stage=stage, accepted=accepted,
                            instructions=stage["prompt"], suffix=f"-attempt-{attempt:02d}" if attempt > 1 else "",
                        )
                        _checkpoint_dependencies(workspace)
                        workspace_baseline_paths = _changed_paths(workspace)
                        prefix = run_dir / "stages" / stage_id / f"attempt-{attempt:02d}"
                        log.append(
                            "stage_attempt_started",
                            stageId=stage_id,
                            attempt=attempt,
                            provider=stage["provider"],
                            handoffSha256=handoff_hash,
                            workspace=str(workspace.relative_to(run_dir)),
                            workBudgetSeconds=_work_budget_seconds(stage) if write_stage else stage["timeoutSeconds"],
                            finishReserveSeconds=_finish_reserve_seconds(stage) if write_stage else 0,
                        )
                        try:
                            result = invoke_agent(
                                stage, workspace, handoff_path, handoff_hash, prefix,
                                diagnostic=last_diagnostic if attempt > 1 else None,
                                timeout_seconds=_work_budget_seconds(stage) if write_stage else stage["timeoutSeconds"],
                                baseline_paths_override=workspace_baseline_paths,
                            )
                            accepted_result = result
                            break
                        except ConductorError as exc:
                            last_attempt_error = str(exc)
                            log.append("stage_attempt_failed", stageId=stage_id, attempt=attempt, error=str(exc))
                            if _is_hard_attempt_failure(str(exc)):
                                raise
                            diagnostic = _preserve_diagnostic(
                                run_dir=run_dir, stage_id=stage_id, attempt=attempt,
                                workspace=workspace, reason=str(exc), handoff_hash=handoff_hash,
                            )
                            last_diagnostic = diagnostic
                            log.append(
                                "stage_diagnostic_preserved",
                                stageId=stage_id,
                                attempt=attempt,
                                diagnosticSha256=diagnostic["diagnosticSha256"],
                                changedPaths=diagnostic["changedPaths"],
                                accepted=False,
                            )
                            recovered = False
                            if recovery_policy and recovery_used < recovery_policy["maxAttempts"] and write_stage:
                                recovery_used += 1
                                mode = recovery_policy["mode"]
                                log.append(
                                    "stage_recovery_started",
                                    stageId=stage_id,
                                    attempt=attempt,
                                    recoveryAttempt=recovery_used,
                                    mode=mode,
                                    diagnosticSha256=diagnostic["diagnosticSha256"],
                                )
                                if mode == "reject":
                                    log.append(
                                        "stage_recovery_rejected",
                                        stageId=stage_id,
                                        diagnosticSha256=diagnostic["diagnosticSha256"],
                                        reason="recoveryPolicy.mode=reject",
                                    )
                                elif not _diagnostic_allowlist_clean(diagnostic, recovery_policy["allowedPaths"]):
                                    log.append(
                                        "stage_recovery_rejected",
                                        stageId=stage_id,
                                        diagnosticSha256=diagnostic["diagnosticSha256"],
                                        reason="diagnostic paths outside recovery allowlist or empty",
                                    )
                                else:
                                    try:
                                        _verify_diagnostic_hash(workspace, diagnostic)
                                        recovery_stage = dict(stage)
                                        recovery_stage["maxTurns"] = recovery_policy.get("maxTurns", 5)
                                        recovery_stage["timeoutSeconds"] = recovery_policy.get(
                                            "timeoutSeconds", _finish_reserve_seconds(stage)
                                        )
                                        recovery_stage["allowedPaths"] = recovery_policy["allowedPaths"]
                                        recovery_prefix = run_dir / "stages" / stage_id / f"attempt-{attempt:02d}-recovery-{recovery_used:02d}"
                                        recovery_result = invoke_agent(
                                            recovery_stage, workspace, handoff_path, handoff_hash, recovery_prefix,
                                            diagnostic=diagnostic,
                                            timeout_seconds=recovery_stage["timeoutSeconds"],
                                            recovery_mode=mode,
                                            baseline_paths_override=workspace_baseline_paths,
                                        )
                                        if recovery_result["status"] != "pass":
                                            raise ConductorError("recovery completion did not pass")
                                        changed = _changed_paths(workspace)
                                        if not _paths_allowed(changed, recovery_policy["allowedPaths"]):
                                            raise ConductorError("generic stage changed a path outside allowedPaths")
                                        accepted_result = recovery_result
                                        recovered = True
                                        log.append(
                                            "stage_recovery_accepted",
                                            stageId=stage_id,
                                            diagnosticSha256=diagnostic["diagnosticSha256"],
                                            recoveryAttempt=recovery_used,
                                        )
                                    except ConductorError as recovery_exc:
                                        log.append(
                                            "stage_recovery_rejected",
                                            stageId=stage_id,
                                            diagnosticSha256=diagnostic["diagnosticSha256"],
                                            reason=str(recovery_exc),
                                        )
                                        last_attempt_error = str(recovery_exc)
                            if recovered:
                                break
                            continue
                    if accepted_result is None:
                        raise ConductorError(f"generic stage {stage_id} exhausted its bounded attempts: {last_attempt_error}")

                    normalized_candidates = sorted((run_dir / "stages" / stage_id).glob("*.normalized.json"))
                    if not normalized_candidates:
                        raise ConductorError(f"generic stage {stage_id} missing normalized response artifact")
                    normalized_path = normalized_candidates[-1]
                    artifact_files.append(str(normalized_path.relative_to(run_dir)))
                    repair_policy = stage.get("repairPolicy")
                    round_number = 0
                    while stage["type"] == "review" and accepted_result["status"] == "fail" and repair_policy:
                        round_number += 1
                        if round_number > repair_policy["maxRounds"]:
                            raise ConductorError(f"review stage {stage_id} exhausted its bounded repair rounds")
                        findings = accepted_result["findings"]
                        log.append("review_findings_routed", stageId=stage_id, round=round_number, responsibleProvider=repair_policy["provider"], findings=findings)
                        repair_stage = {
                            "id": stage_id + "-repair", "type": "reconnaissance" if repair_policy.get("readOnly", False) else "repair",
                            "provider": repair_policy["provider"], "dependsOn": stage["dependsOn"],
                            "prompt": repair_policy["prompt"], "allowedPaths": repair_policy.get("allowedPaths", []),
                            "attachments": stage.get("attachments", []), "contextPaths": stage.get("contextPaths", []),
                            "allowedCommands": repair_policy.get("allowedCommands", []),
                            "timeoutSeconds": repair_policy.get("timeoutSeconds", stage["timeoutSeconds"]), "maxAttempts": 1,
                            "maxTurns": repair_policy.get("maxTurns", 5),
                        }
                        repair_workspace = run_dir / "workspaces" / stage_id / f"repair-{round_number:02d}"
                        _create_workspace(snapshot, repair_workspace)
                        repair_instructions = repair_policy["prompt"] + "\n\nActionable review findings:\n" + json.dumps(findings, indent=2)
                        repair_handoff, repair_hash, _ = _build_handoff(
                            run_dir=run_dir, workspace=repair_workspace, stage=repair_stage,
                            accepted=accepted, instructions=repair_instructions, suffix=f"-repair-{round_number:02d}",
                        )
                        _checkpoint_dependencies(repair_workspace)
                        repair_prefix = run_dir / "stages" / stage_id / f"repair-{round_number:02d}"
                        repair_result = invoke_agent(repair_stage, repair_workspace, repair_handoff, repair_hash, repair_prefix, findings)
                        if repair_result["status"] != "pass":
                            raise ConductorError(f"repair for {stage_id} round {round_number} did not pass")
                        repair_changed, repair_diff = _workspace_patch(repair_workspace)
                        repair_diff_path = run_dir / "stages" / stage_id / f"repair-{round_number:02d}.diff.patch"
                        repair_manifest_path = run_dir / "stages" / stage_id / f"repair-{round_number:02d}.changed-files.json"
                        write_once(repair_diff_path, repair_diff)
                        write_once(repair_manifest_path, json.dumps(repair_changed, indent=2).encode() + b"\n")
                        artifact_files.extend([str(repair_prefix.with_suffix(".normalized.json").relative_to(run_dir)), str(repair_diff_path.relative_to(run_dir)), str(repair_manifest_path.relative_to(run_dir))])
                        synthetic_id = f"{stage_id}-repair-{round_number:02d}"
                        synthetic_record = {"stageId": synthetic_id, "artifactSha256": sha256_bytes(repair_diff + json.dumps(repair_result, sort_keys=True).encode()), "artifactFiles": artifact_files[-3:]}
                        rereview_accepted = dict(accepted)
                        rereview_accepted[synthetic_id] = synthetic_record
                        rereview_stage = dict(stage)
                        rereview_stage["dependsOn"] = stage["dependsOn"] + [synthetic_id]
                        review_workspace = run_dir / "workspaces" / stage_id / f"review-{round_number + 1:02d}"
                        _create_workspace(snapshot, review_workspace)
                        review_handoff, review_hash, _ = _build_handoff(
                            run_dir=run_dir, workspace=review_workspace, stage=rereview_stage,
                            accepted=rereview_accepted, instructions=stage["prompt"], suffix=f"-review-{round_number + 1:02d}",
                        )
                        _checkpoint_dependencies(review_workspace)
                        review_prefix = run_dir / "stages" / stage_id / f"review-{round_number + 1:02d}"
                        accepted_result = invoke_agent(stage, review_workspace, review_handoff, review_hash, review_prefix)
                        artifact_files.append(str(review_prefix.with_suffix(".normalized.json").relative_to(run_dir)))
                    if accepted_result["status"] != "pass":
                        raise ConductorError(f"generic stage {stage_id} did not reach pass")
                    if workspace is None:
                        raise ConductorError(f"generic stage {stage_id} missing active workspace")
                    active_workspace = workspace
                    changed, diff = _workspace_patch(active_workspace, accumulated=stage.get("emitAccumulatedDiff", False))
                    changed_path = run_dir / "stages" / stage_id / "changed-files.json"
                    diff_path = run_dir / "stages" / stage_id / "diff.patch"
                    write_once(changed_path, json.dumps(changed, indent=2).encode() + b"\n")
                    write_once(diff_path, diff)
                    artifact_files.extend([str(changed_path.relative_to(run_dir)), str(diff_path.relative_to(run_dir))])
                    payload = json.dumps(accepted_result, sort_keys=True).encode()
                    payload += b"".join((run_dir / relative).read_bytes() for relative in artifact_files)
                elif stage["type"] == "workspace_seed":
                    source_run = (root / "runs" / stage["sourceRunId"]).resolve()
                    if source_run.parent != (root / "runs").resolve() or not source_run.is_dir():
                        raise ConductorError(f"workspace seed source run does not exist: {stage_id}")
                    source_summary = load_json(source_run / "summary.json")
                    if source_summary.get("status") != "failed" or source_summary.get("sourceUnchanged") is not True:
                        raise ConductorError(f"workspace seed source run is not a safe failed run: {stage_id}")
                    source_attempt = stage.get("sourceAttempt", "initial")
                    source_workspace = source_run / "workspaces" / stage["sourceStageId"] / source_attempt
                    if not source_workspace.is_dir():
                        raise ConductorError(f"workspace seed source workspace is missing: {stage_id}")
                    if stage.get("expectedDiagnosticSha256"):
                        marker = source_run / "workspaces" / stage["sourceStageId"] / f"{source_attempt}.diagnostic"
                        diagnostic_path = source_run / "stages" / stage["sourceStageId"] / f"{source_attempt}.diagnostic.json"
                        if not marker.is_file() or not diagnostic_path.is_file():
                            raise ConductorError(f"workspace seed {stage_id} missing diagnostic evidence")
                        diagnostic = load_json(diagnostic_path)
                        if diagnostic.get("diagnosticSha256") != stage["expectedDiagnosticSha256"]:
                            raise ConductorError(f"workspace seed {stage_id} diagnostic hash mismatch")
                        if diagnostic.get("accepted") is not False:
                            raise ConductorError(f"workspace seed {stage_id} diagnostic must be unaccepted")
                        _verify_diagnostic_hash(source_workspace, diagnostic)
                    seed_workspace = run_dir / "workspaces" / stage_id / "seed"
                    changed, seed_patch = _materialize_workspace_seed(snapshot, source_workspace, seed_workspace)
                    if not _paths_allowed(changed, stage["allowedPaths"]):
                        raise ConductorError(f"workspace seed {stage_id} includes a path outside allowedPaths")
                    if sha256_bytes(seed_patch) != stage["expectedPatchSha256"]:
                        raise ConductorError(f"workspace seed {stage_id} patch hash mismatch")
                    stage_dir = run_dir / "stages" / stage_id
                    diff_path = stage_dir / "diff.patch"
                    changed_path = stage_dir / "changed-files.json"
                    write_once(diff_path, seed_patch)
                    write_once(changed_path, json.dumps(changed, indent=2).encode() + b"\n")
                    artifact_files.extend([str(changed_path.relative_to(run_dir)), str(diff_path.relative_to(run_dir))])
                    payload = seed_patch
                    log.append(
                        "workspace_seed_imported",
                        stageId=stage_id,
                        sourceRunId=stage["sourceRunId"],
                        sourceStageId=stage["sourceStageId"],
                        sourceAttempt=source_attempt,
                        patchSha256=stage["expectedPatchSha256"],
                        diagnosticSha256=stage.get("expectedDiagnosticSha256"),
                        changedPaths=changed,
                    )
                elif stage["type"] == "test":
                    test_workspace = run_dir / "workspaces" / stage_id / "test"
                    _create_workspace(snapshot, test_workspace)
                    _build_handoff(
                        run_dir=run_dir, workspace=test_workspace, stage=stage, accepted=accepted,
                        instructions="Execute exactly this gate command: " + json.dumps(stage["command"]),
                    )
                    pre_status = git(test_workspace, "status", "--porcelain=v1")
                    pre_paths = _changed_paths(test_workspace)
                    pre_state = _changed_state(test_workspace, pre_paths)
                    preserved_before: dict[str, bytes] = {}
                    for relative in stage.get("preservePaths", []):
                        preserved = test_workspace / relative
                        if not preserved.is_file() or preserved.is_symlink():
                            raise ConductorError(f"test stage {stage_id} preservePath is missing or unsafe: {relative}")
                        preserved_before[relative] = preserved.read_bytes()
                    completed = run_command(stage["command"], cwd=test_workspace, timeout_seconds=stage["timeoutSeconds"], check=False)
                    post_status = git(test_workspace, "status", "--porcelain=v1")
                    post_paths = _changed_paths(test_workspace)
                    post_state = _changed_state(test_workspace, post_paths)
                    for relative, original in preserved_before.items():
                        preserved = test_workspace / relative
                        if not preserved.is_file() or preserved.read_bytes() != original:
                            raise ConductorError(f"test stage {stage_id} changed preserved path: {relative}")
                    if post_status != pre_status or post_paths != pre_paths or post_state != pre_state:
                        raise ConductorError(f"test stage {stage_id} changed tracked source or expanded the diff")
                    stage_dir = run_dir / "stages" / stage_id
                    outputs = {
                        "stdout": completed.stdout, "stderr": completed.stderr,
                        "pre-gate-status.txt": pre_status, "post-gate-status.txt": post_status,
                    }
                    for filename, data in outputs.items():
                        target = stage_dir / filename
                        write_once(target, data)
                        artifact_files.append(str(target.relative_to(run_dir)))
                    if completed.returncode != 0:
                        raise ConductorError(f"test stage {stage_id} failed")
                    payload = b"".join(outputs.values())
                    test_result = {
                        "command": stage["command"], "returnCode": completed.returncode,
                        "stdoutFile": str((stage_dir / "stdout").relative_to(run_dir)),
                        "stdoutSha256": sha256_bytes(completed.stdout),
                        "stderrFile": str((stage_dir / "stderr").relative_to(run_dir)),
                        "stderrSha256": sha256_bytes(completed.stderr),
                    }
                elif stage["type"] == "commit":
                    changed = _changed_paths(snapshot)
                    if not _paths_allowed(changed, stage["allowedPaths"]):
                        raise ConductorError("commit stage includes a path outside allowedPaths")
                    git(snapshot, "add", "-A")
                    run_command(["git", "-c", "user.name=Foundry Conductor", "-c", "user.email=conductor@localhost", "commit", "-m", stage.get("message", stage_id)], cwd=snapshot)
                    payload = git(snapshot, "rev-parse", "HEAD")
                else:
                    payload = json.dumps({"approved": True, "stageId": stage_id}).encode()
                record = {"stageId": stage_id, "type": stage["type"], "provider": stage.get("provider"), "inputArtifactSha256": input_hash, "artifactSha256": sha256_bytes(payload), "artifactFiles": artifact_files, "accepted": True}
                if test_result is not None:
                    record["testResult"] = test_result
                record["artifactFileSha256"] = {
                    relative: sha256_bytes((run_dir / relative).read_bytes()) for relative in record["artifactFiles"]
                }
                accepted_bytes = json.dumps(record, indent=2, sort_keys=True).encode() + b"\n"
                write_once(run_dir / "stages" / stage_id / "accepted.json", accepted_bytes)
                accepted[stage_id] = record
                accepted_record_hashes[stage_id] = sha256_bytes(accepted_bytes)
                log.append("stage_accepted", **record)
            else:
                status = "complete"
    except ConductorError as exc:
        status = "failed"
        error = str(exc)
        log.append("dag_run_failed", error=error)
    after = fingerprint_repo(source)
    unchanged = before == after
    if not unchanged:
        status = "failed_source_changed"
    summary = {"runId": run_id, "runDirectory": str(run_dir), "status": status, "live": live, "manifestSha256": manifest_hash, "order": order, "acceptedStages": list(accepted), "acceptedRecordSha256": accepted_record_hashes, "testResults": {stage_id: record["testResult"] for stage_id, record in accepted.items() if "testResult" in record}, "sourceUnchanged": unchanged, "snapshotClean": snapshot_is_clean(snapshot)}
    if "error" in locals(): summary["error"] = error
    write_once(run_dir / "source-after.json", json.dumps(asdict(after), indent=2).encode() + b"\n")
    write_once(run_dir / "summary.json", json.dumps(summary, indent=2, sort_keys=True).encode() + b"\n")
    test_lines = "\n".join(
        f"- `{stage_id}`: rc={record['testResult']['returnCode']}, output `{record['testResult']['stdoutFile']}`"
        for stage_id, record in accepted.items() if "testResult" in record
    ) or "- none"
    sheet = f"# Conductor decision sheet\n\nRun: `{run_id}`\n\nStatus: **{status}**\n\nAccepted stages: {', '.join(accepted) or 'none'}\n\n## Test results\n\n{test_lines}\n\nSource unchanged: `{str(unchanged).lower()}`\n"
    write_once(run_dir / "decision-sheet.md", sheet.encode())
    log.append("dag_run_finished", status=status, sourceUnchanged=unchanged)
    return summary


def doctor_dag(manifest: dict[str, Any]) -> dict[str, Any]:
    validate_manifest(manifest)
    source = Path(manifest["sourceRepository"]).expanduser().resolve()
    actual = fingerprint_repo(source)
    checks: list[dict[str, Any]] = []
    try:
        verify_baseline(manifest, actual)
        checks.append({"check": "baseline", "status": "pass", "observed": actual.head})
    except ConductorError as exc:
        checks.append({"check": "baseline", "status": "fail", "detail": str(exc)})
    providers = sorted({stage.get("provider") for stage in manifest["stages"] if stage.get("provider")})
    for provider in providers:
        resolved = resolve_binary(provider)
        checks.append({"check": f"binary:{provider}", "status": "pass" if resolved else "fail", "observed": resolved})
    checks.append({"check": "default-no-action", "status": "pass", "observed": "plan and run without --live invoke no providers"})
    checks.append({"check": "push-policy", "status": "pass", "observed": "push is never executed by generic runner"})
    return {"ok": all(item["status"] == "pass" for item in checks), "source": asdict(actual), "order": topological_order(manifest), "checks": checks}


def interact(*, root: Path, run_id: str, action: str, stage_id: str | None = None, message: str | None = None) -> dict[str, Any]:
    run_dir = (root / "runs" / run_id).resolve()
    if run_dir.parent != (root / "runs").resolve() or not run_dir.is_dir():
        raise ConductorError("run does not exist")
    if action == "status":
        return load_json(run_dir / "summary.json")
    if action == "evidence":
        return {"runId": run_id, "files": sorted(str(path.relative_to(run_dir)) for path in run_dir.rglob("*") if path.is_file())}
    if action == "message":
        if not message:
            raise ConductorError("message text is required")
        path = run_dir / "messages" / f"{int(time.time() * 1000)}.json"
        record = {"message": message, "sha256": sha256_bytes(message.encode())}
        write_once(path, json.dumps(record, indent=2, sort_keys=True).encode() + b"\n")
        _append_event(run_dir / "events.jsonl", "operator_message", messageSha256=record["sha256"])
        return record
    if action in {"approve", "refuse"}:
        if not stage_id:
            raise ConductorError("stage id is required")
        record = {"stageId": stage_id, "decision": action, "message": message or ""}
        write_once(run_dir / "approvals" / f"{stage_id}.json", json.dumps(record, indent=2, sort_keys=True).encode() + b"\n")
        _append_event(run_dir / "events.jsonl", f"operator_{action}", stageId=stage_id)
        return record
    raise ConductorError("unsupported run interaction")
