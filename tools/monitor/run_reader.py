"""Read-only reader for the live stage monitor.

The reader never opens a file under ``runs/`` for writing and never spawns a
subprocess; it only parses the evidence a run already wrote.  The optional
``.monitor-cache`` directory named by ``CACHE_DIRNAME`` is the sole location a
caller may write to, and it is safe to delete at any time.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

CACHE_DIRNAME = ".monitor-cache"
WAITING_FOR_RUN = "waiting for run"
QUEUED, RUNNING, ACCEPTED, FAILED, SKIPPED = "queued", "running", "accepted", "failed", "skipped"
STAGE_STARTED_EVENTS = {"stage_attempt_started", "provider_work_started"}
STAGE_FAILED_EVENTS = {"stage_attempt_failed"}
RUN_FAILED_EVENTS = {"dag_run_failed"}
FAILED_STATUS = "failed"
MAX_ERROR_CHARS = 240


def empty_board(message: str = WAITING_FOR_RUN) -> dict[str, Any]:
    """A board with no run behind it."""
    return {
        "runId": None, "status": None, "live": None, "sourceUnchanged": None,
        "runDirectory": None, "decisionSheet": None, "stages": [], "message": message,
    }


def select_run_directory(root: Path, task: str) -> Path | None:
    """Newest ``runs/*-<task>-*`` directory by mtime, or None when there is no run."""
    runs = (Path(root) / "runs").resolve()
    if not runs.is_dir():
        return None
    candidates = [
        path for path in runs.glob(f"*-{task}-*")
        if path.is_dir() and path.resolve().parent == runs
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda path: (path.stat().st_mtime, path.name))


def short_error(text: Any) -> str | None:
    """One short line of error text, never a stack dump."""
    if not isinstance(text, str) or not text.strip():
        return None
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    line = lines[-1] if lines[0].startswith("Traceback (most recent call last)") else lines[0]
    line = " ".join(line.split())
    return line if len(line) <= MAX_ERROR_CHARS else line[: MAX_ERROR_CHARS - 3] + "..."


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _read_events(path: Path) -> list[dict[str, Any]]:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    events: list[dict[str, Any]] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            events.append(record)
    return events


def _topological_order(stages: list[Any]) -> list[str]:
    """Kahn layering over dependsOn, matching the runner; declaration order on a cycle."""
    remaining = {
        stage["id"]: {dep for dep in stage.get("dependsOn", []) if isinstance(dep, str)}
        for stage in stages if isinstance(stage, dict) and isinstance(stage.get("id"), str)
    }
    declared = list(remaining)
    order: list[str] = []
    while remaining:
        ready = [stage_id for stage_id, deps in remaining.items() if not deps - set(order)]
        if not ready:
            return declared
        for stage_id in ready:
            order.append(stage_id)
            remaining.pop(stage_id)
    return order


def _string_list(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _stage_order(summary: dict[str, Any] | None, manifest: dict[str, Any] | None,
                 plan: dict[str, Any] | None) -> list[str]:
    """summary.json order when it carries one, otherwise manifest.json, otherwise plan.json."""
    stages = (manifest or {}).get("stages")
    for candidate in (
        _string_list((summary or {}).get("order")),
        _topological_order(stages if isinstance(stages, list) else []),
        _string_list((plan or {}).get("order")),
    ):
        if candidate:
            return candidate
    return []


def _roles(manifest: dict[str, Any] | None) -> dict[str, str]:
    stages = (manifest or {}).get("stages")
    if not isinstance(stages, list):
        return {}
    roles: dict[str, str] = {}
    for stage in stages:
        if not isinstance(stage, dict) or not isinstance(stage.get("id"), str):
            continue
        role = stage.get("role", stage.get("type"))
        if isinstance(role, str) and role:
            roles[stage["id"]] = role
    return roles


def _named_stage(error: str | None, order: list[str], accepted: list[str]) -> str | None:
    """The stage id the run error names, if it names one."""
    if not error:
        return None
    named = [
        stage_id for stage_id in order
        if re.search(rf"(?<![A-Za-z0-9_-]){re.escape(stage_id)}(?![A-Za-z0-9_-])", error)
    ]
    if not named:
        return None
    unaccepted = [stage_id for stage_id in named if stage_id not in accepted]
    return unaccepted[0] if unaccepted else named[0]


def read_board(root: Path, task: str) -> dict[str, Any]:
    """The monitor board for the newest run of ``task``, read only from run evidence."""
    run_dir = select_run_directory(Path(root), task)
    if run_dir is None:
        return empty_board()

    summary = _read_json(run_dir / "summary.json")
    manifest = _read_json(run_dir / "manifest.json")
    plan = _read_json(run_dir / "plan.json")
    events = _read_events(run_dir / "events.jsonl")
    sheet = run_dir / "decision-sheet.md"

    order = _stage_order(summary, manifest, plan)
    board = {
        "runId": (summary or {}).get("runId") or run_dir.name,
        "status": (summary or {}).get("status"),
        "live": (summary or {}).get("live"),
        "sourceUnchanged": (summary or {}).get("sourceUnchanged"),
        "runDirectory": str(run_dir),
        "decisionSheet": str(sheet) if sheet.is_file() else None,
        "stages": [], "message": None,
    }
    if not order:
        # Nothing on disk says which stages exist yet; never invent them.
        board["message"] = WAITING_FOR_RUN
        return board

    started: set[str] = set()
    last_update: dict[str, str] = {}
    stage_errors: dict[str, str] = {}
    run_error = short_error((summary or {}).get("error"))
    for record in events:
        stage_id = record.get("stageId")
        event = record.get("event")
        if isinstance(stage_id, str):
            if isinstance(record.get("at"), str):
                last_update[stage_id] = record["at"]
            if event in STAGE_STARTED_EVENTS:
                started.add(stage_id)
            if event in STAGE_FAILED_EVENTS:
                text = short_error(record.get("error"))
                if text:
                    stage_errors[stage_id] = text
        elif event in RUN_FAILED_EVENTS and run_error is None:
            run_error = short_error(record.get("error"))

    accepted = _string_list((summary or {}).get("acceptedStages"))
    roles = _roles(manifest)
    failed_stage = None
    if (summary or {}).get("status") == FAILED_STATUS:
        failed_stage = _named_stage(run_error, order, accepted)
    after_failure = False

    for stage_id in order:
        if after_failure:
            state, error = SKIPPED, None
        elif stage_id == failed_stage:
            state, error = FAILED, run_error or stage_errors.get(stage_id)
            after_failure = True
        elif stage_id in accepted:
            state, error = ACCEPTED, None
        elif stage_id in started:
            state, error = RUNNING, stage_errors.get(stage_id)
        else:
            state, error = QUEUED, None
        board["stages"].append({
            "id": stage_id, "role": roles.get(stage_id), "state": state,
            "lastUpdate": last_update.get(stage_id), "error": error,
        })
    return board
