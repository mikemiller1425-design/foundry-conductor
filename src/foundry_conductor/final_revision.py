from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .core import (
    AppendOnlyLog, ConductorError, create_tracked_snapshot, fingerprint_repo,
    load_json, make_run_id, sha256_bytes, snapshot_is_clean, verify_baseline, write_once,
)
from .reconcile import _invoke, validate_reconciliation_task


DEFECT_IDS = tuple(f"DEFECT-{number:03d}" for number in range(1, 90))
LOCATION_FIELDS = {"lineStart", "lineEnd", "exactText"}
ROW_FIELDS = {"defectId", "status", "revisedDraftLocation", "closure", "explanation"}
REVIEW_FIELDS = {
    "verdict", "draftSha256", "ledgerSha256", "confirmedDefectCount",
    "allDefectIdsPresentExactlyOnce", "allSubstantivelyResolved", "allProofsExecutable",
    "noBoundaryWeakened", "noNewFindings", "summary", "findings", "requiresHuman",
}


def _load_reusable(paths: tuple[Path, ...], validator: Any, label: str) -> tuple[dict[str, Any], Path] | None:
    existing = [path for path in paths if path.is_file()]
    if not existing:
        return None
    values = [validator(load_json(path)) for path in existing]
    if any(value != values[0] for value in values[1:]):
        raise ConductorError(f"conflicting reusable {label} artifacts")
    return values[0], existing[0]


def _validate_location(value: Any, draft_lines: list[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != LOCATION_FIELDS:
        raise ConductorError(f"{label} fields do not match the schema")
    start, end, exact = value["lineStart"], value["lineEnd"], value["exactText"]
    if not isinstance(start, int) or isinstance(start, bool) or not isinstance(end, int) or isinstance(end, bool):
        raise ConductorError(f"{label} line bounds must be integers")
    if start < 1 or end < start or end > len(draft_lines):
        raise ConductorError(f"{label} line bounds do not exist in the revised draft")
    if not isinstance(exact, str) or not exact:
        raise ConductorError(f"{label} exactText must be non-empty")
    observed = "\n".join(draft_lines[start - 1:end])
    if observed != exact:
        raise ConductorError(f"{label} exactText does not match the revised draft")


def validate_closure_ledger(value: Any, draft: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != 89:
        raise ConductorError("closure ledger must contain exactly 89 rows")
    draft_lines = draft.splitlines()
    observed_ids: list[str] = []
    for index, row in enumerate(value, start=1):
        if not isinstance(row, dict) or set(row) != ROW_FIELDS:
            raise ConductorError(f"closure ledger row {index} fields do not match the schema")
        defect_id = row["defectId"]
        if not isinstance(defect_id, str):
            raise ConductorError(f"closure ledger row {index} defectId is invalid")
        observed_ids.append(defect_id)
        if row["status"] not in {"resolved", "unresolved"}:
            raise ConductorError(f"closure ledger {defect_id} status is invalid")
        _validate_location(row["revisedDraftLocation"], draft_lines, f"{defect_id} revised location")
        closure = row["closure"]
        if not isinstance(closure, dict) or set(closure) != {"kind", "location"}:
            raise ConductorError(f"closure ledger {defect_id} closure fields do not match the schema")
        if closure["kind"] not in {"contract", "invariant", "fixture", "proof", "gate", "stop_condition"}:
            raise ConductorError(f"closure ledger {defect_id} closure kind is invalid")
        _validate_location(closure["location"], draft_lines, f"{defect_id} closure location")
        if not isinstance(row["explanation"], str) or not row["explanation"].strip() or len(row["explanation"]) > 800:
            raise ConductorError(f"closure ledger {defect_id} explanation is invalid")
    if tuple(observed_ids) != DEFECT_IDS:
        raise ConductorError("closure ledger must contain DEFECT-001 through DEFECT-089 exactly once in order")
    return value


def validate_final_revision_response(value: Any) -> dict[str, Any]:
    fields = {"status", "draft", "closureLedger", "notes", "requiresHuman"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ConductorError("final revision response fields do not match the schema")
    if value["status"] not in {"drafted", "blocked"} or not isinstance(value["draft"], str):
        raise ConductorError("final revision status or draft is invalid")
    if not isinstance(value["notes"], list) or not all(isinstance(note, str) for note in value["notes"]):
        raise ConductorError("final revision notes are invalid")
    if not isinstance(value["requiresHuman"], bool):
        raise ConductorError("final revision requiresHuman is invalid")
    if value["status"] == "drafted":
        if not value["draft"].strip() or value["requiresHuman"]:
            raise ConductorError("drafted final revision requires a draft and no human decision")
        validate_closure_ledger(value["closureLedger"], value["draft"])
    elif value["closureLedger"] not in ([], None):
        raise ConductorError("blocked final revision must not claim a closure ledger")
    return value


def validate_final_review(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != REVIEW_FIELDS:
        raise ConductorError("final review fields do not match the schema")
    if value["verdict"] not in {"pass", "fail", "blocked"}:
        raise ConductorError("final review verdict is invalid")
    for field in ("draftSha256", "ledgerSha256"):
        if not isinstance(value[field], str) or not re.fullmatch(r"[0-9a-f]{64}", value[field]):
            raise ConductorError(f"final review {field} is invalid")
    if not isinstance(value["confirmedDefectCount"], int) or isinstance(value["confirmedDefectCount"], bool):
        raise ConductorError("final review confirmedDefectCount is invalid")
    booleans = (
        "allDefectIdsPresentExactlyOnce", "allSubstantivelyResolved", "allProofsExecutable",
        "noBoundaryWeakened", "noNewFindings", "requiresHuman",
    )
    if not all(isinstance(value[field], bool) for field in booleans):
        raise ConductorError("final review confirmation fields must be booleans")
    if not isinstance(value["summary"], str) or not value["summary"].strip():
        raise ConductorError("final review summary is invalid")
    if not isinstance(value["findings"], list):
        raise ConductorError("final review findings must be an array")
    finding_fields = {"defectId", "category", "message", "requiredChange"}
    for finding in value["findings"]:
        if not isinstance(finding, dict) or set(finding) != finding_fields:
            raise ConductorError("final review finding fields do not match the schema")
        if finding["defectId"] is not None and finding["defectId"] not in DEFECT_IDS:
            raise ConductorError("final review finding defectId is invalid")
        if not all(isinstance(finding[field], str) and finding[field] for field in ("category", "message", "requiredChange")):
            raise ConductorError("final review finding text is invalid")
    if value["verdict"] == "pass":
        confirmations = [value[field] for field in booleans[:-1]]
        if value["confirmedDefectCount"] != 89 or not all(confirmations):
            raise ConductorError("pass requires explicit 89-of-89 closure confirmation")
        if value["findings"] or value["requiresHuman"]:
            raise ConductorError("pass requires zero findings and requiresHuman=false")
    elif not value["findings"] and not value["requiresHuman"]:
        raise ConductorError("non-pass final review requires findings or human decision")
    return value


def _author_prompt(candidate: str, inventory: str, proposed: str, bindings: dict[str, str]) -> str:
    return f"""You are Claude, the sole author of one final Package 2a authorization-prompt revision.
Work only in the disposable tracked snapshot. Do not edit files, access /Volumes, invoke another
model, implement Package 2a, perform external actions, commit, or push.

The operator-authorized bindings are:
{json.dumps(bindings, indent=2, sort_keys=True)}

Revise the complete candidate exactly once to resolve every authoritative DEFECT-001 through
DEFECT-089. Do not omit, weaken, reinterpret, further deduplicate, or silently merge a defect.
The 89 defect blocks in the proposed authorization are authoritative inputs and must be treated
byte-for-byte as supplied. Preserve every existing governance and scope boundary.

Return only the complete revised authorization prompt in `draft`. Do not produce a closure ledger
in this stage. The conductor will freeze the accepted draft hash and perform closure extraction and
review in separate non-mutating stages. Produce the complete prompt, not a patch or commentary.

<candidate sha256="{bindings['candidateSha256']}">
{candidate}
</candidate>

<defect-inventory sha256="{bindings['defectInventorySha256']}">
{inventory}
</defect-inventory>

<authoritative-proposed-authorization sha256="{bindings['proposedAuthorizationSha256']}">
{proposed}
</authoritative-proposed-authorization>

Return only the structured response required by the supplied schema.
"""


def validate_draft_only(value: Any) -> dict[str, Any]:
    fields = {"status", "draft", "notes", "requiresHuman"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ConductorError("final draft response fields do not match the schema")
    if value["status"] not in {"drafted", "blocked"} or not isinstance(value["draft"], str):
        raise ConductorError("final draft status or draft is invalid")
    if not isinstance(value["notes"], list) or not all(isinstance(item, str) for item in value["notes"]):
        raise ConductorError("final draft notes are invalid")
    if not isinstance(value["requiresHuman"], bool):
        raise ConductorError("final draft requiresHuman is invalid")
    if value["status"] == "drafted" and (not value["draft"].strip() or value["requiresHuman"]):
        raise ConductorError("accepted final draft requires content and requiresHuman=false")
    return value


def validate_ledger_packet(value: Any, draft: str, draft_hash: str, expected_ids: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"draftSha256", "rows"}:
        raise ConductorError("closure ledger packet fields do not match the schema")
    if value["draftSha256"] != draft_hash:
        raise ConductorError("closure ledger packet draft digest mismatch")
    rows = value["rows"]
    if not isinstance(rows, list) or [row.get("defectId") if isinstance(row, dict) else None for row in rows] != list(expected_ids):
        raise ConductorError("closure ledger packet defect IDs do not match its assigned range")
    # Reuse the full validator by padding only after structural validation would be unsafe;
    # validate each packet row directly against its immutable draft locations instead.
    draft_lines = draft.splitlines()
    for index, row in enumerate(rows, start=1):
        if not isinstance(row, dict) or set(row) != ROW_FIELDS:
            raise ConductorError(f"closure ledger packet row {index} fields do not match the schema")
        if row["status"] not in {"resolved", "unresolved"}:
            raise ConductorError(f"closure ledger {row['defectId']} status is invalid")
        _validate_location(row["revisedDraftLocation"], draft_lines, f"{row['defectId']} revised location")
        closure = row["closure"]
        if not isinstance(closure, dict) or set(closure) != {"kind", "location"} or closure["kind"] not in {"contract", "invariant", "fixture", "proof", "gate", "stop_condition"}:
            raise ConductorError(f"closure ledger {row['defectId']} closure is invalid")
        _validate_location(closure["location"], draft_lines, f"{row['defectId']} closure location")
        if not isinstance(row["explanation"], str) or not row["explanation"].strip() or len(row["explanation"]) > 800:
            raise ConductorError(f"closure ledger {row['defectId']} explanation is invalid")
    return value


def validate_review_packet(value: Any, draft_hash: str, ledger_hash: str, expected_ids: tuple[str, ...]) -> dict[str, Any]:
    fields = {"verdict", "draftSha256", "ledgerSha256", "reviewedDefectIds", "allSubstantivelyResolved", "allProofsExecutable", "noBoundaryWeakened", "noNewFindings", "summary", "findings", "requiresHuman"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ConductorError("final review packet fields do not match the schema")
    if value["draftSha256"] != draft_hash or value["ledgerSha256"] != ledger_hash:
        raise ConductorError("final review packet digest mismatch")
    if value["reviewedDefectIds"] != list(expected_ids):
        raise ConductorError("final review packet defect coverage mismatch")
    if value["verdict"] not in {"pass", "fail", "blocked"} or not isinstance(value["summary"], str) or not value["summary"]:
        raise ConductorError("final review packet verdict or summary is invalid")
    confirmations = ("allSubstantivelyResolved", "allProofsExecutable", "noBoundaryWeakened", "noNewFindings")
    if not all(isinstance(value[field], bool) for field in confirmations) or not isinstance(value["requiresHuman"], bool) or not isinstance(value["findings"], list):
        raise ConductorError("final review packet confirmation fields are invalid")
    if value["verdict"] == "pass" and (not all(value[field] for field in confirmations) or value["findings"] or value["requiresHuman"]):
        raise ConductorError("final review packet pass requires complete confirmations and zero findings")
    if value["verdict"] != "pass" and not value["findings"] and not value["requiresHuman"]:
        raise ConductorError("non-pass final review packet requires findings or human decision")
    return value


def _ledger_prompt(draft: str, draft_hash: str, defects: list[dict[str, Any]]) -> str:
    ids = [item["defectId"] for item in defects]
    return f"""You are Claude performing non-mutating closure-ledger extraction for one bounded
packet. Do not revise, rewrite, or propose replacement text for the frozen draft. Do not edit files,
access /Volumes, invoke another model, implement, commit, push, or perform external actions.

Frozen draft SHA-256: {draft_hash}
Assigned defect IDs, in required output order: {json.dumps(ids)}

For each assigned defect, determine whether the frozen draft substantively closes its exact
requiredChange. Return one row per assigned ID. Use one-based inclusive line locations with
exactText copied exactly from complete draft lines. Use `unresolved` rather than inventing or
stretching a closure. This stage may describe only the frozen draft; it may not mutate it.

<assigned-defects>{json.dumps(defects, indent=2, sort_keys=True)}</assigned-defects>
<frozen-draft sha256="{draft_hash}">{draft}</frozen-draft>
Return only the structured response required by the supplied schema.
"""


def _review_packet_prompt(reviewer: str, draft: str, draft_hash: str, ledger_hash: str, defects: list[dict[str, Any]], rows: list[dict[str, Any]]) -> str:
    ids = [item["defectId"] for item in defects]
    return f"""You are the {reviewer} independent reviewer for one bounded final-closure packet.
Do not modify the frozen draft or ledger. Work read-only; do not access /Volumes, invoke another
model, implement, commit, push, or perform external actions.

Audit the complete frozen draft for the assigned defects and their exact ledger rows. Confirm each
requiredChange is substantively resolved, proofs are executable and sufficiently specified, no
boundary was weakened, and no new finding was introduced. Copy hashes and assigned IDs exactly.
Use pass only with all confirmations true, zero findings, and requiresHuman=false.

Draft SHA-256: {draft_hash}
Ledger SHA-256: {ledger_hash}
Assigned IDs: {json.dumps(ids)}
<assigned-defects>{json.dumps(defects, indent=2, sort_keys=True)}</assigned-defects>
<assigned-ledger-rows>{json.dumps(rows, indent=2, sort_keys=True)}</assigned-ledger-rows>
<complete-frozen-draft>{draft}</complete-frozen-draft>
Return only the structured response required by the supplied schema.
"""


def _review_prompt(reviewer: str, draft: str, draft_hash: str, ledger: str, ledger_hash: str) -> str:
    return f"""You are the {reviewer} independent final reviewer. Work only in the disposable
tracked snapshot. Do not edit files, access /Volumes, invoke another model, implement Package 2a,
perform external actions, commit, or push.

Audit the entire revised draft and exact closure ledger together. Explicitly verify all 89 defect
IDs occur exactly once, every row is substantively resolved, every required proof is executable and
sufficiently specified, no governance or scope boundary was weakened, and no new finding exists.
A generic pass is invalid. Copy both hashes exactly. Use pass only with confirmedDefectCount=89,
all five confirmations true, zero findings, and requiresHuman=false.

<revised-draft sha256="{draft_hash}">
{draft}
</revised-draft>

<closure-ledger sha256="{ledger_hash}">
{ledger}
</closure-ledger>

Return only the structured response required by the supplied schema.
"""


def run_final_revision(
    *, root: Path, task_path: Path, source_run_id: str, candidate_sha256: str,
    defect_inventory_sha256: str, proposed_authorization_sha256: str,
    live: bool, live_confirmed: bool, resume_run_id: str | None = None,
) -> dict[str, Any]:
    task = load_json(task_path)
    validate_reconciliation_task(task)
    if live and not live_confirmed:
        raise ConductorError("live final revision requires --confirm-live-models")
    bindings = {
        "sourceRunId": source_run_id, "candidateSha256": candidate_sha256,
        "defectInventorySha256": defect_inventory_sha256,
        "proposedAuthorizationSha256": proposed_authorization_sha256,
    }
    for key in ("candidateSha256", "defectInventorySha256", "proposedAuthorizationSha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", bindings[key]):
            raise ConductorError(f"{key} is invalid")
    resume_dir: Path | None = None
    if resume_run_id is not None:
        resume_dir = (root / "runs" / resume_run_id).resolve()
        if resume_dir.parent != (root / "runs").resolve() or not resume_dir.is_dir():
            raise ConductorError("final revision resume run does not exist")
        resume_summary = load_json(resume_dir / "summary.json")
        if any(resume_summary.get(key) != value for key, value in bindings.items()):
            raise ConductorError("final revision resume bindings do not match")
        if resume_summary.get("sourceUnchanged") is not True or resume_summary.get("snapshotClean") is not True:
            raise ConductorError("final revision resume run did not preserve its boundaries")
    source_dir = (root / "runs" / source_run_id).resolve()
    if source_dir.parent != (root / "runs").resolve() or not source_dir.is_dir():
        raise ConductorError("final revision source run does not exist")
    source_summary = load_json(source_dir / "summary.json")
    if source_summary.get("status") != "ready_for_operator_decision" or source_summary.get("sourceUnchanged") is not True or source_summary.get("snapshotClean") is not True:
        raise ConductorError("final revision source run did not complete safely")
    candidate_path = source_dir / "candidate.md"
    inventory_path = source_dir / "final" / "defect-inventory.json"
    proposed_path = source_dir / "final" / "proposed-final-revision-authorization.md"
    artifacts = ((candidate_path, candidate_sha256), (inventory_path, defect_inventory_sha256), (proposed_path, proposed_authorization_sha256))
    for path, expected in artifacts:
        if not path.is_file() or sha256_bytes(path.read_bytes()) != expected:
            raise ConductorError(f"bound artifact hash mismatch: {path.name}")
    inventory_value = load_json(inventory_path)
    if inventory_value.get("candidateSha256") != candidate_sha256 or inventory_value.get("defectCount") != 89:
        raise ConductorError("defect inventory is not the bound 89-defect candidate inventory")
    if [item.get("defectId") for item in inventory_value.get("defects", [])] != list(DEFECT_IDS):
        raise ConductorError("defect inventory IDs are not exactly DEFECT-001 through DEFECT-089")

    source_repo = Path(task["sourceRepository"]).expanduser().resolve()
    before = fingerprint_repo(source_repo)
    verify_baseline(task, before)
    run_id = make_run_id("package-2a-final-revision")
    run_dir = root / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    log = AppendOnlyLog(run_dir / "events.jsonl")
    log.append("final_revision_started", runId=run_id, **bindings)
    write_once(run_dir / "bindings.json", json.dumps(bindings, indent=2, sort_keys=True).encode() + b"\n")
    write_once(run_dir / "source-before.json", json.dumps(asdict(before), indent=2).encode() + b"\n")
    snapshot = run_dir / "snapshot"
    create_tracked_snapshot(source_repo, snapshot)
    summary: dict[str, Any] = {"runId": run_id, "runDirectory": str(run_dir), "live": live, **bindings}
    try:
        if not live:
            summary["status"] = "planned"
        else:
            candidate = candidate_path.read_text(encoding="utf-8")
            inventory = inventory_path.read_text(encoding="utf-8")
            proposed = proposed_path.read_text(encoding="utf-8")
            reusable_author = _load_reusable(
                tuple(resume_dir / name for name in ("author-claude.normalized.json", "author-import.json")) if resume_dir else tuple(),
                validate_draft_only, "final author",
            )
            if reusable_author is not None:
                revision, prior_author = reusable_author
                import_record = {
                    "resumeRunId": resume_run_id,
                    "normalizedSha256": sha256_bytes(prior_author.read_bytes()),
                }
                write_once(run_dir / "author-import.json", json.dumps(revision, indent=2, sort_keys=True).encode() + b"\n")
                write_once(run_dir / "author-import-evidence.json", json.dumps(import_record, indent=2, sort_keys=True).encode() + b"\n")
                log.append("final_author_imported", **import_record)
            else:
                if resume_dir is not None and (resume_dir / "author-claude.stdout").is_file():
                    raise ConductorError("Claude final revision attempt already exists and is not reusable")
                revision = _invoke(
                    agent="claude", snapshot=snapshot,
                    prompt=_author_prompt(candidate, inventory, proposed, bindings),
                    schema_path=root / "schemas" / "final-draft-only.schema.json",
                    validator=validate_draft_only,
                    prefix=run_dir / "author-claude", timeout_seconds=task["timeoutSeconds"],
                    max_turns=task["authorMaxTurns"], log=log,
                )
            if revision["status"] != "drafted":
                raise ConductorError("Claude blocked the final revision")
            draft = revision["draft"]
            draft_bytes = draft.encode()
            draft_hash = sha256_bytes(draft_bytes)
            write_once(run_dir / "revised-draft.md", draft_bytes)
            draft_record = {"draftSha256": draft_hash, "accepted": True}
            write_once(run_dir / "draft-validation.json", json.dumps(draft_record, indent=2, sort_keys=True).encode() + b"\n")
            log.append("final_draft_accepted", **draft_record)

            defect_values = inventory_value["defects"]
            packets = [defect_values[index:index + 18] for index in range(0, 89, 18)]
            ledger: list[dict[str, Any]] = []
            for ordinal, defects in enumerate(packets, start=1):
                expected_ids = tuple(item["defectId"] for item in defects)
                prefix = run_dir / "ledger" / f"packet-{ordinal:02d}-claude"
                validator = lambda value, ids=expected_ids: validate_ledger_packet(value, draft, draft_hash, ids)
                reusable_packet = _load_reusable(
                    tuple(resume_dir / "ledger" / name for name in (f"packet-{ordinal:02d}-claude.normalized.json", f"packet-{ordinal:02d}-claude-import.json")) if resume_dir else tuple(),
                    validator, f"closure packet {ordinal}",
                )
                if reusable_packet is not None:
                    packet_result, prior_packet = reusable_packet
                    write_once(prefix.with_name(prefix.name + "-import.json"), json.dumps(packet_result, indent=2, sort_keys=True).encode() + b"\n")
                    log.append("closure_packet_imported", packet=ordinal, resumeRunId=resume_run_id, normalizedSha256=sha256_bytes(prior_packet.read_bytes()))
                else:
                    packet_result = _invoke(
                        agent="claude", snapshot=snapshot,
                        prompt=_ledger_prompt(draft, draft_hash, defects),
                        schema_path=root / "schemas" / "closure-ledger-packet.schema.json",
                        validator=validator, prefix=prefix,
                        timeout_seconds=task["timeoutSeconds"], max_turns=task["authorMaxTurns"], log=log,
                    )
                ledger.extend(packet_result["rows"])
                log.append("closure_packet_validated", packet=ordinal, defectIds=list(expected_ids), draftSha256=draft_hash)
            validate_closure_ledger(ledger, draft)
            if any(row["status"] != "resolved" for row in ledger):
                unresolved = [row["defectId"] for row in ledger if row["status"] != "resolved"]
                raise ConductorError("closure ledger contains unresolved defects: " + ", ".join(unresolved))
            ledger_bytes = json.dumps(ledger, indent=2, sort_keys=True).encode() + b"\n"
            ledger_hash = sha256_bytes(ledger_bytes)
            write_once(run_dir / "closure-ledger.json", ledger_bytes)
            closure_record = {"rowCount": 89, "resolvedCount": 89, "draftSha256": draft_hash, "ledgerSha256": ledger_hash}
            write_once(run_dir / "closure-validation.json", json.dumps(closure_record, indent=2, sort_keys=True).encode() + b"\n")
            log.append("closure_ledger_validated", **closure_record)
            verdicts: dict[str, dict[str, Any]] = {}
            ledger_text = ledger_bytes.decode()
            for reviewer in task["reviewers"]:
                packet_attestations: list[dict[str, Any]] = []
                for ordinal, defects in enumerate(packets, start=1):
                    expected_ids = tuple(item["defectId"] for item in defects)
                    rows = [row for row in ledger if row["defectId"] in expected_ids]
                    prefix = run_dir / "reviews" / reviewer / f"packet-{ordinal:02d}"
                    validator = lambda value, ids=expected_ids: validate_review_packet(value, draft_hash, ledger_hash, ids)
                    reusable_packet = _load_reusable(
                        tuple(resume_dir / "reviews" / reviewer / name for name in (f"packet-{ordinal:02d}.normalized.json", f"packet-{ordinal:02d}-import.json")) if resume_dir else tuple(),
                        validator, f"{reviewer} review packet {ordinal}",
                    )
                    if reusable_packet is not None:
                        packet_review, prior_packet = reusable_packet
                        write_once(prefix.with_name(prefix.name + "-import.json"), json.dumps(packet_review, indent=2, sort_keys=True).encode() + b"\n")
                        log.append("final_review_packet_imported", reviewer=reviewer, packet=ordinal, resumeRunId=resume_run_id, normalizedSha256=sha256_bytes(prior_packet.read_bytes()))
                    else:
                        packet_review = _invoke(
                            agent=reviewer, snapshot=snapshot,
                            prompt=_review_packet_prompt(reviewer, draft, draft_hash, ledger_hash, defects, rows),
                            schema_path=root / "schemas" / "final-review-packet.schema.json",
                            validator=validator, prefix=prefix,
                            timeout_seconds=task["timeoutSeconds"], max_turns=task["reviewerMaxTurns"], log=log,
                        )
                    if packet_review["verdict"] != "pass":
                        raise ConductorError(f"{reviewer} did not pass final review packet {ordinal}")
                    packet_attestations.append(packet_review)
                    log.append("final_review_packet_passed", reviewer=reviewer, packet=ordinal, defectIds=list(expected_ids), draftSha256=draft_hash, ledgerSha256=ledger_hash)
                covered_ids = [defect_id for result in packet_attestations for defect_id in result["reviewedDefectIds"]]
                if covered_ids != list(DEFECT_IDS):
                    raise ConductorError(f"{reviewer} packet attestations do not cover all 89 defects exactly once")

                reusable_review = _load_reusable(
                    tuple(resume_dir / name for name in (f"aggregate-review-{reviewer}.normalized.json", f"aggregate-review-{reviewer}-import.json")) if resume_dir else tuple(),
                    validate_final_review, f"{reviewer} aggregate review",
                )
                if reusable_review is not None:
                    review, prior_review = reusable_review
                    import_record = {
                        "resumeRunId": resume_run_id, "reviewer": reviewer,
                        "normalizedSha256": sha256_bytes(prior_review.read_bytes()),
                    }
                    write_once(run_dir / f"aggregate-review-{reviewer}-import.json", json.dumps(review, indent=2, sort_keys=True).encode() + b"\n")
                    log.append("final_review_imported", **import_record)
                else:
                    aggregate_context = json.dumps(packet_attestations, indent=2, sort_keys=True)
                    review = _invoke(
                        agent=reviewer, snapshot=snapshot,
                        prompt=_review_prompt(reviewer, draft, draft_hash, ledger_text, ledger_hash)
                        + "\n<validated-packet-attestations>\n" + aggregate_context + "\n</validated-packet-attestations>\n",
                        schema_path=root / "schemas" / "final-revision-review.schema.json",
                        validator=validate_final_review,
                        prefix=run_dir / f"aggregate-review-{reviewer}", timeout_seconds=task["timeoutSeconds"],
                        max_turns=task["reviewerMaxTurns"], log=log,
                    )
                if review["draftSha256"] != draft_hash or review["ledgerSha256"] != ledger_hash:
                    raise ConductorError(f"{reviewer} final review digest mismatch")
                if review["verdict"] != "pass":
                    raise ConductorError(f"{reviewer} did not pass the final revision")
                verdicts[reviewer] = review
                log.append("final_review_passed", reviewer=reviewer, draftSha256=draft_hash, ledgerSha256=ledger_hash, confirmedDefectCount=89)
            write_once(run_dir / "final" / "package-2a-authorization-prompt.md", draft_bytes)
            summary.update({"status": "ready_for_operator_decision", "draftSha256": draft_hash, "ledgerSha256": ledger_hash, "closureRowCount": 89, "resolvedCount": 89, "reviewVerdicts": {key: value["verdict"] for key, value in verdicts.items()}})
            log.append("final_authorization_prompt_emitted", draftSha256=draft_hash, ledgerSha256=ledger_hash)
    except ConductorError as exc:
        summary["status"] = "failed"
        summary["error"] = str(exc)
        log.append("final_revision_failed", error=str(exc))
    after = fingerprint_repo(source_repo)
    summary["sourceUnchanged"] = before == after
    summary["snapshotClean"] = snapshot_is_clean(snapshot)
    write_once(run_dir / "source-after.json", json.dumps(asdict(after), indent=2).encode() + b"\n")
    if not summary["sourceUnchanged"]:
        summary["status"] = "failed_source_changed"
    if not summary["snapshotClean"]:
        summary["status"] = "failed_snapshot_mutated"
    write_once(run_dir / "summary.json", json.dumps(summary, indent=2, sort_keys=True).encode() + b"\n")
    log.append("final_revision_finished", status=summary["status"], sourceUnchanged=summary["sourceUnchanged"], snapshotClean=summary["snapshotClean"])
    return summary
