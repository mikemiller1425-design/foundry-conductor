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
        if stage["type"] not in AGENT_STAGE_TYPES | {"test", "commit", "human_gate"}:
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
            if not isinstance(stage.get("prompt"), str) or not stage["prompt"]:
                raise ConductorError(f"generic stage {stage['id']} prompt is required")
            context_paths = stage.get("contextPaths", [])
            if not isinstance(context_paths, list) or not all(
                isinstance(item, str) and item and not item.startswith("/") and ".." not in Path(item).parts
                for item in context_paths
            ):
                raise ConductorError(f"generic stage {stage['id']} contextPaths are invalid")
        if stage["type"] == "review" and "repairPolicy" in stage:
            policy = stage["repairPolicy"]
            if not isinstance(policy, dict) or not isinstance(policy.get("maxRounds"), int) or not 1 <= policy["maxRounds"] <= 5:
                raise ConductorError(f"review stage {stage['id']} repairPolicy is invalid")
            provider = policy.get("provider", DEFAULT_PROVIDERS.get(policy.get("role", "implementation")))
            if provider not in AGENT_BINARIES:
                raise ConductorError(f"review stage {stage['id']} repair provider is invalid")
            policy["provider"] = provider
            if not isinstance(policy.get("prompt"), str) or not policy["prompt"]:
                raise ConductorError(f"review stage {stage['id']} repair prompt is required")
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
    topological_order(value)
    return value


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


def _input_manifest(stage: dict[str, Any], accepted: dict[str, dict[str, Any]]) -> tuple[dict[str, str], str]:
    inputs = {dependency: accepted[dependency]["artifactSha256"] for dependency in stage["dependsOn"]}
    encoded = json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()
    return inputs, sha256_bytes(encoded)


def _create_workspace(base_snapshot: Path, destination: Path) -> None:
    run_command(["git", "clone", "-q", "--no-hardlinks", str(base_snapshot), str(destination)], cwd=base_snapshot.parent, timeout_seconds=120)
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
    tracked = [item.decode() for item in git(workspace, "ls-files", "-z").split(b"\0") if item]
    for pattern in stage.get("contextPaths", []):
        matches = sorted(path for path in tracked if fnmatch.fnmatchcase(path, pattern))
        if not matches:
            raise ConductorError(f"handoff contextPath matched no tracked file: {pattern}")
        for relative in matches:
            source = workspace / relative
            if not source.is_file() or source.is_symlink():
                raise ConductorError(f"handoff context file is unsafe: {relative}")
            target = handoff / "context" / relative
            data = source.read_bytes()
            write_once(target, data)
            files.append({"path": str(target.relative_to(handoff)), "sha256": sha256_bytes(data)})
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
            if target.name.endswith(".diff.patch") and data:
                completed = run_command(["git", "apply", "--check", str(target)], cwd=workspace, check=False)
                if completed.returncode == 0:
                    run_command(["git", "apply", str(target)], cwd=workspace)
    manifest = {"stageId": stage["id"], "dependencies": stage["dependsOn"], "files": sorted(files, key=lambda item: item["path"])}
    digest = sha256_bytes(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode())
    manifest["handoffSha256"] = digest
    write_once(handoff / "manifest.json", json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n")
    visible = workspace / ".conductor" / "handoff"
    visible.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(handoff, visible)
    return handoff, digest, manifest


def _stage_prompt(stage: dict[str, Any], handoff_hash: str, handoff_path: Path, write_allowed: bool, feedback: list[dict[str, Any]] | None = None) -> str:
    boundary = "Read-only: do not modify any file." if not write_allowed else (
        "Controlled-write stage in a disposable snapshot. Modify only these allowed paths: "
        + json.dumps(stage.get("allowedPaths", []))
    )
    return f"""You are executing generic conductor stage `{stage['id']}` ({stage['type']}).
{boundary}
Do not access /Volumes, push, spend, perform external actions, run production, or invoke another model.
You may execute only these exact commands: {json.dumps(stage.get('allowedCommands', []))}
Inspectable handoff folder: {handoff_path}
Canonical handoff SHA-256: {handoff_hash}
Read every handoff file before work. Explicitly copy this digest into `handoffSha256` and set
`workStarted=true` only after the handoff was read and work actually started.
Routed review findings: {json.dumps(feedback or [], sort_keys=True)}

{stage.get('prompt', '')}

Return only the structured response required by the supplied schema. A pass requires zero findings
and requiresHuman=false. A review may return fail with actionable findings for automatic repair.
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
                    if not approval.is_file():
                        status = "waiting_for_approval"
                        log.append("human_gate_waiting", stageId=stage_id, gate=stage.get("gate", "custom"), inputArtifactSha256=input_hash)
                        break
                if stage["type"] in AGENT_STAGE_TYPES:
                    def invoke_agent(
                        active_stage: dict[str, Any], workspace: Path, handoff_path: Path,
                        handoff_hash: str, prefix: Path, feedback: list[dict[str, Any]] | None = None,
                    ) -> dict[str, Any]:
                        baseline_paths = _changed_paths(workspace)
                        prompt = _stage_prompt(
                            active_stage, handoff_hash, workspace / ".conductor" / "handoff",
                            active_stage["type"] in {"implementation", "repair"}, feedback,
                        )
                        command = _build_stage_command(active_stage, workspace, prompt, root / "schemas" / "generic-stage-result.schema.json")
                        write_once(prefix.with_suffix(".prompt.txt"), prompt.encode() + b"\n")
                        write_once(prefix.with_suffix(".command.json"), json.dumps(redact_command(command), indent=2, sort_keys=True).encode() + b"\n")
                        operation_id = active_stage["id"]
                        log.append("provider_work_started", stageId=stage_id, operationId=operation_id, provider=active_stage["provider"], handoffSha256=handoff_hash, workspace=str(workspace))
                        completed = run_command(command.argv, cwd=workspace, timeout_seconds=active_stage["timeoutSeconds"], check=False)
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

                    workspace = run_dir / "workspaces" / stage_id / "initial"
                    _create_workspace(snapshot, workspace)
                    handoff_path, handoff_hash, _ = _build_handoff(
                        run_dir=run_dir, workspace=workspace, stage=stage, accepted=accepted,
                        instructions=stage["prompt"],
                    )
                    accepted_result = None
                    result = None
                    last_attempt_error = None
                    for attempt in range(1, stage["maxAttempts"] + 1):
                        prefix = run_dir / "stages" / stage_id / f"attempt-{attempt:02d}"
                        log.append("stage_attempt_started", stageId=stage_id, attempt=attempt, provider=stage["provider"], handoffSha256=handoff_hash)
                        try:
                            result = invoke_agent(stage, workspace, handoff_path, handoff_hash, prefix)
                            accepted_result = result
                            break
                        except ConductorError as exc:
                            last_attempt_error = str(exc)
                            log.append("stage_attempt_failed", stageId=stage_id, attempt=attempt, error=str(exc))
                            if "outside allowedPaths" in str(exc) or "mutated its isolated workspace" in str(exc) or "wrong handoff" in str(exc):
                                raise
                    if accepted_result is None:
                        raise ConductorError(f"generic stage {stage_id} exhausted its bounded attempts: {last_attempt_error}")

                    artifact_files: list[str] = []
                    normalized_path = run_dir / "stages" / stage_id / f"attempt-{attempt:02d}.normalized.json"
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
                            "allowedCommands": repair_policy.get("allowedCommands", []),
                            "timeoutSeconds": repair_policy.get("timeoutSeconds", stage["timeoutSeconds"]), "maxAttempts": 1,
                        }
                        repair_workspace = run_dir / "workspaces" / stage_id / f"repair-{round_number:02d}"
                        _create_workspace(snapshot, repair_workspace)
                        repair_instructions = repair_policy["prompt"] + "\n\nActionable review findings:\n" + json.dumps(findings, indent=2)
                        repair_handoff, repair_hash, _ = _build_handoff(
                            run_dir=run_dir, workspace=repair_workspace, stage=repair_stage,
                            accepted=accepted, instructions=repair_instructions, suffix=f"-repair-{round_number:02d}",
                        )
                        repair_prefix = run_dir / "stages" / stage_id / f"repair-{round_number:02d}"
                        repair_result = invoke_agent(repair_stage, repair_workspace, repair_handoff, repair_hash, repair_prefix, findings)
                        if repair_result["status"] != "pass":
                            raise ConductorError(f"repair for {stage_id} round {round_number} did not pass")
                        repair_changed = _changed_paths(repair_workspace)
                        repair_diff = git(repair_workspace, "diff", "--binary", "HEAD")
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
                        review_prefix = run_dir / "stages" / stage_id / f"review-{round_number + 1:02d}"
                        accepted_result = invoke_agent(stage, review_workspace, review_handoff, review_hash, review_prefix)
                        artifact_files.append(str(review_prefix.with_suffix(".normalized.json").relative_to(run_dir)))
                    if accepted_result["status"] != "pass":
                        raise ConductorError(f"generic stage {stage_id} did not reach pass")
                    active_workspace = workspace
                    changed = _changed_paths(active_workspace)
                    diff = git(active_workspace, "diff", "--binary", "HEAD")
                    changed_path = run_dir / "stages" / stage_id / "changed-files.json"
                    diff_path = run_dir / "stages" / stage_id / "diff.patch"
                    write_once(changed_path, json.dumps(changed, indent=2).encode() + b"\n")
                    write_once(diff_path, diff)
                    artifact_files.extend([str(changed_path.relative_to(run_dir)), str(diff_path.relative_to(run_dir))])
                    payload = json.dumps(accepted_result, sort_keys=True).encode()
                    payload += b"".join((run_dir / relative).read_bytes() for relative in artifact_files)
                elif stage["type"] == "test":
                    completed = run_command(stage["command"], cwd=snapshot, timeout_seconds=stage["timeoutSeconds"], check=False)
                    write_once(run_dir / "stages" / stage_id / "stdout", completed.stdout)
                    write_once(run_dir / "stages" / stage_id / "stderr", completed.stderr)
                    if completed.returncode != 0:
                        raise ConductorError(f"test stage {stage_id} failed")
                    payload = completed.stdout + completed.stderr
                elif stage["type"] == "commit":
                    changed = _changed_paths(snapshot)
                    if not _paths_allowed(changed, stage["allowedPaths"]):
                        raise ConductorError("commit stage includes a path outside allowedPaths")
                    git(snapshot, "add", "-A")
                    run_command(["git", "-c", "user.name=Foundry Conductor", "-c", "user.email=conductor@localhost", "commit", "-m", stage.get("message", stage_id)], cwd=snapshot)
                    payload = git(snapshot, "rev-parse", "HEAD")
                else:
                    payload = json.dumps({"approved": True, "stageId": stage_id}).encode()
                record = {"stageId": stage_id, "type": stage["type"], "provider": stage.get("provider"), "inputArtifactSha256": input_hash, "artifactSha256": sha256_bytes(payload), "artifactFiles": artifact_files if stage["type"] in AGENT_STAGE_TYPES else [], "accepted": True}
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
    summary = {"runId": run_id, "runDirectory": str(run_dir), "status": status, "live": live, "manifestSha256": manifest_hash, "order": order, "acceptedStages": list(accepted), "acceptedRecordSha256": accepted_record_hashes, "sourceUnchanged": unchanged, "snapshotClean": snapshot_is_clean(snapshot)}
    if "error" in locals(): summary["error"] = error
    write_once(run_dir / "source-after.json", json.dumps(asdict(after), indent=2).encode() + b"\n")
    write_once(run_dir / "summary.json", json.dumps(summary, indent=2, sort_keys=True).encode() + b"\n")
    sheet = f"# Conductor decision sheet\n\nRun: `{run_id}`\n\nStatus: **{status}**\n\nAccepted stages: {', '.join(accepted) or 'none'}\n\nSource unchanged: `{str(unchanged).lower()}`\n"
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
