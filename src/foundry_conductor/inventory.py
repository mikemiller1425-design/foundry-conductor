from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .core import (
    AppendOnlyLog,
    ConductorError,
    create_tracked_snapshot,
    fingerprint_repo,
    load_json,
    make_run_id,
    parse_structured_response,
    sha256_bytes,
    snapshot_is_clean,
    verify_baseline,
    write_once,
)
from .reconcile import _invoke, validate_reconciliation_task


PACKETS: tuple[dict[str, Any], ...] = (
    {
        "id": "hashing-identity",
        "title": "Hashing identity, numeric constraints, and cross-field refinements",
        "ranges": ((56, 132), (256, 272), (275, 308), (320, 341), (397, 417), (442, 465)),
    },
    {
        "id": "coverage-truth",
        "title": "Coverage counts, completion, cancellation, and uncertainty",
        "ranges": ((56, 71), (133, 187), (200, 244), (256, 308), (342, 380), (397, 417), (442, 465)),
    },
    {
        "id": "roots-and-paths",
        "title": "Roots, absolute and relative paths, and display exposure",
        "ranges": ((21, 71), (133, 159), (188, 199), (245, 308), (313, 319), (342, 380), (397, 457)),
    },
    {
        "id": "scanner-security",
        "title": "Scanner read-only security, fixtures, and allowed paths",
        "ranges": ((21, 68), (256, 319), (377, 428), (430, 457)),
    },
    {
        "id": "governance-boundaries",
        "title": "Governance, evidence, stop conditions, and downstream exclusions",
        "ranges": ((1, 71), (245, 255), (377, 465)),
    },
)


def validate_traceability_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "verdict", "candidateSha256", "entries", "gaps", "requiresHuman"
    }:
        raise ConductorError("traceability response fields do not match the schema")
    if value["verdict"] not in {"complete", "blocked"}:
        raise ConductorError("traceability verdict is invalid")
    if not isinstance(value["candidateSha256"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", value["candidateSha256"]
    ):
        raise ConductorError("traceability candidateSha256 is invalid")
    if not isinstance(value["entries"], list) or not value["entries"]:
        raise ConductorError("traceability entries must be non-empty")
    entry_fields = {
        "requirementId", "requirement", "candidateLocations", "packetIds", "status", "notes"
    }
    packet_ids = {packet["id"] for packet in PACKETS}
    for entry in value["entries"]:
        if not isinstance(entry, dict) or set(entry) != entry_fields:
            raise ConductorError("traceability entry fields do not match the schema")
        if not all(isinstance(entry[key], str) for key in ("requirementId", "requirement", "notes")):
            raise ConductorError("traceability entry text fields are invalid")
        if not entry["requirementId"] or not entry["requirement"]:
            raise ConductorError("traceability entry identifiers and requirements must be non-empty")
        if entry["status"] not in {"covered", "gap", "contradiction"}:
            raise ConductorError("traceability entry status is invalid")
        if not isinstance(entry["candidateLocations"], list) or not all(
            isinstance(item, str) and item for item in entry["candidateLocations"]
        ):
            raise ConductorError("traceability candidateLocations are invalid")
        if not isinstance(entry["packetIds"], list) or not entry["packetIds"] or not set(
            entry["packetIds"]
        ).issubset(packet_ids):
            raise ConductorError("traceability packetIds are invalid")
    if not isinstance(value["gaps"], list) or not all(
        isinstance(item, str) and item for item in value["gaps"]
    ):
        raise ConductorError("traceability gaps are invalid")
    if not isinstance(value["requiresHuman"], bool):
        raise ConductorError("traceability requiresHuman must be boolean")
    return value


def validate_packet_review(value: Any) -> dict[str, Any]:
    required = {
        "verdict", "candidateSha256", "packetId", "packetSha256", "summary", "findings", "requiresHuman"
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ConductorError("packet review fields do not match the schema")
    if value["verdict"] not in {"pass", "findings_complete", "blocked"}:
        raise ConductorError("packet review verdict is invalid")
    for key in ("candidateSha256", "packetSha256"):
        if not isinstance(value[key], str) or not re.fullmatch(r"[0-9a-f]{64}", value[key]):
            raise ConductorError(f"packet review {key} is invalid")
    if not isinstance(value["packetId"], str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9-]+", value["packetId"]
    ):
        raise ConductorError("packet review packetId is invalid")
    if not isinstance(value["summary"], str) or not value["summary"]:
        raise ConductorError("packet review summary must be non-empty")
    if not isinstance(value["findings"], list) or not isinstance(value["requiresHuman"], bool):
        raise ConductorError("packet review findings or requiresHuman is invalid")
    finding_fields = {
        "severity", "category", "dedupKey", "message", "requiredChange", "evidenceLocations"
    }
    for finding in value["findings"]:
        if not isinstance(finding, dict) or set(finding) != finding_fields:
            raise ConductorError("packet finding fields do not match the schema")
        if finding["severity"] not in {"warning", "error"}:
            raise ConductorError("packet finding severity is invalid")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]+", str(finding["dedupKey"])):
            raise ConductorError("packet finding dedupKey is invalid")
        for key in ("category", "message", "requiredChange"):
            if not isinstance(finding[key], str) or not finding[key]:
                raise ConductorError(f"packet finding {key} must be non-empty")
        if not isinstance(finding["evidenceLocations"], list) or not finding["evidenceLocations"] or not all(
            isinstance(item, str) and item for item in finding["evidenceLocations"]
        ):
            raise ConductorError("packet finding evidenceLocations are invalid")
    if value["verdict"] == "pass" and (value["findings"] or value["requiresHuman"]):
        raise ConductorError("packet pass requires zero findings and no human decision")
    if value["verdict"] == "findings_complete" and not value["findings"]:
        raise ConductorError("findings_complete requires at least one finding")
    if value["verdict"] == "blocked" and not value["requiresHuman"]:
        raise ConductorError("blocked packet review requires a human decision")
    return value


def _packet_text(candidate: str, ranges: tuple[tuple[int, int], ...]) -> str:
    lines = candidate.splitlines()
    parts: list[str] = []
    for start, end in ranges:
        if start < 1 or end < start or end > len(lines):
            raise ConductorError(f"packet range {start}-{end} is outside the candidate")
        parts.append(f"<!-- candidate-lines:{start}-{end} -->\n" + "\n".join(lines[start - 1:end]))
    return "\n\n".join(parts).strip() + "\n"


def _traceability_prompt(candidate: str, candidate_hash: str, packets: list[dict[str, Any]]) -> str:
    packet_manifest = json.dumps(
        [{"packetId": item["id"], "title": item["title"], "ranges": item["ranges"]} for item in packets],
        indent=2,
    )
    return f"""You are Claude. Produce a traceability matrix only for the preserved Package 2a candidate.

Do not revise, rewrite, patch, or propose replacement candidate text. Do not
begin implementation, access /Volumes, edit files, invoke another model, or
perform external actions. Work only in the disposable read-only snapshot.

Candidate SHA-256: {candidate_hash}

Map every material requirement, invariant, proof, stop condition, evidence
obligation, and exclusion in the candidate to candidate section/line locations
and one or more packet IDs. Mark contradictions and gaps honestly. The matrix
is review navigation, not a verdict and not a repair plan.

Packet manifest:
{packet_manifest}

<candidate sha256="{candidate_hash}">
{candidate}
</candidate>

Return only the structured response required by the supplied schema. Copy the
candidate digest exactly. Use `complete` unless the matrix itself cannot be
completed; candidate gaps belong in entries/gaps and do not by themselves make
the matrix blocked.
"""


def _packet_review_prompt(
    *, reviewer: str, packet: dict[str, Any], packet_text: str, packet_hash: str,
    candidate_hash: str, traceability: dict[str, Any], known_finding: dict[str, Any] | None,
) -> str:
    if reviewer == "codex":
        focus = "Audit governance, security, implementability, proof sufficiency, and internal contradictions."
    else:
        focus = "Audit consumer-facing contract completeness and every frontend truth dependency without designing frontend work."
    trace_entries = [
        entry for entry in traceability["entries"] if packet["id"] in entry["packetIds"]
    ]
    known = "none"
    if known_finding is not None and packet["id"] == "roots-and-paths":
        known = json.dumps(known_finding, indent=2, sort_keys=True)
    return f"""You are the {reviewer} reviewer for one packet in an exhaustive,
read-only Package 2a defect inventory. Do not revise the candidate, propose a
replacement prompt, begin implementation, edit files, access /Volumes, invoke
another model, or perform external actions.

Candidate SHA-256: {candidate_hash}
Packet: {packet['id']} — {packet['title']}
Packet SHA-256: {packet_hash}

{focus}

Audit every statement in this packet and its relationships to the supplied
traceability entries. Use `pass` only if this packet has no finding. Use
`findings_complete` when you have exhaustively listed every finding in the
packet. Use `blocked` only if the packet cannot be audited. Findings must use a
stable lowercase `dedupKey`; use the same key for the same underlying defect.

Known preserved defect for deduplication (do not repeat it unless you add a
materially distinct issue):
{known}

Relevant traceability entries:
{json.dumps(trace_entries, indent=2, sort_keys=True)}

<packet id="{packet['id']}" sha256="{packet_hash}" candidate-sha256="{candidate_hash}">
{packet_text}
</packet>

Return only the structured response required by the supplied schema. Copy all
three identifiers exactly.
"""


def _known_path_finding(source_round: Path, candidate_hash: str) -> dict[str, Any]:
    review = load_json(source_round / "review-codex.normalized.json")
    if review.get("draftSha256") != candidate_hash:
        raise ConductorError("known Codex finding targets the wrong candidate")
    findings = review.get("findings")
    if not isinstance(findings, list) or not findings:
        raise ConductorError("preserved run does not contain the known path finding")
    source = findings[0]
    return {
        "severity": source["severity"],
        "category": source["category"],
        "dedupKey": "roots-absolute-path-scope",
        "message": source["message"],
        "requiredChange": source["requiredChange"],
        "evidenceLocations": ["candidate §5 C-5b", "candidate proof 45", "preserved Codex review"],
        "sources": [{"kind": "preserved", "reviewer": "codex", "packetId": "roots-and-paths"}],
    }


def _consolidate(
    known: dict[str, Any], reviews: dict[str, dict[str, dict[str, Any]]],
    traceability: dict[str, Any],
) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {known["dedupKey"]: dict(known)}
    for entry in traceability["entries"]:
        if entry["status"] == "covered":
            continue
        key = "traceability-" + re.sub(r"[^a-z0-9]+", "-", entry["requirementId"].lower()).strip("-")
        grouped[key] = {
            "severity": "error",
            "category": "traceability " + entry["status"],
            "dedupKey": key,
            "message": entry["requirement"] + (f" — {entry['notes']}" if entry["notes"] else ""),
            "requiredChange": "Resolve the traceability " + entry["status"] + " before implementation authorization.",
            "evidenceLocations": entry["candidateLocations"] or ["Claude traceability matrix"],
            "sources": [{"kind": "traceability", "reviewer": "claude", "packetId": packet_id}
                        for packet_id in entry["packetIds"]],
        }
    for packet_id, packet_reviews in reviews.items():
        for reviewer, review in packet_reviews.items():
            for finding in review["findings"]:
                key = finding["dedupKey"]
                source = {"kind": "packet-review", "reviewer": reviewer, "packetId": packet_id}
                if key not in grouped:
                    grouped[key] = {**finding, "sources": [source]}
                else:
                    grouped[key]["sources"].append(source)
                    grouped[key]["evidenceLocations"] = sorted(set(
                        grouped[key]["evidenceLocations"] + finding["evidenceLocations"]
                    ))
                    if finding["severity"] == "error":
                        grouped[key]["severity"] = "error"
    inventory: list[dict[str, Any]] = []
    for index, key in enumerate(sorted(grouped), start=1):
        item = grouped[key]
        item["defectId"] = f"DEFECT-{index:03d}"
        inventory.append(item)
    return inventory


def _proposed_authorization(candidate_hash: str, inventory: list[dict[str, Any]]) -> str:
    defects = "\n\n".join(
        f"### {item['defectId']} — {item['dedupKey']}\n\n"
        f"- Severity: {item['severity']}\n- Problem: {item['message']}\n"
        f"- Required change: {item['requiredChange']}"
        for item in inventory
    )
    return f"""# PROPOSED — NOT AUTHORIZED — Package 2a single final-revision prompt

This proposal authorizes nothing unless the operator separately issues it.

Resume from candidate SHA-256 `{candidate_hash}`. Claude may make exactly one
revision limited to the consolidated defects below. Preserve every other
candidate decision and boundary. Do not begin Package 2a implementation.

{defects}

After revision, Codex and Cursor must review the same resulting digest and each
return a schema-valid pass with zero findings and `requiresHuman=false`.
Any finding, invalid response, hash mismatch, source drift, or snapshot
mutation stops the workflow without another revision.

This proposed authorization does not permit Foundry writes, NAS access,
Package 2a implementation, external actions, pushes, or Package 2b–2d work.
Emit a final Package 2a authorization prompt only after both reviews pass, then
stop for the operator's decision.
"""


def run_defect_inventory(
    *, root: Path, task_path: Path, source_run_id: str, candidate_sha256: str,
    live: bool, live_confirmed: bool, traceability_run_id: str | None = None,
    packet_review_run_id: str | None = None,
    additional_cursor_attempt_packet: str | None = None,
) -> dict[str, Any]:
    task = load_json(task_path)
    validate_reconciliation_task(task)
    if live and not live_confirmed:
        raise ConductorError("live defect inventory requires --confirm-live-models")
    packet_ids = {packet["id"] for packet in PACKETS}
    if additional_cursor_attempt_packet is not None and additional_cursor_attempt_packet not in packet_ids:
        raise ConductorError("additional Cursor attempt packet is not in the review packet list")
    if additional_cursor_attempt_packet is not None and packet_review_run_id is None:
        raise ConductorError(
            "additional Cursor attempt requires --resume-packet-reviews-from"
        )
    if not re.fullmatch(r"[0-9a-f]{64}", candidate_sha256):
        raise ConductorError("candidate SHA-256 is invalid")
    if not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z-[a-z0-9-]+-[0-9a-f]{8}", source_run_id):
        raise ConductorError("source run id is invalid")
    if traceability_run_id is not None and not re.fullmatch(
        r"[0-9]{8}T[0-9]{6}Z-[a-z0-9-]+-[0-9a-f]{8}", traceability_run_id
    ):
        raise ConductorError("traceability run id is invalid")
    if packet_review_run_id is not None and not re.fullmatch(
        r"[0-9]{8}T[0-9]{6}Z-[a-z0-9-]+-[0-9a-f]{8}", packet_review_run_id
    ):
        raise ConductorError("packet review run id is invalid")
    source_dir = (root / "runs" / source_run_id).resolve()
    if source_dir.parent != (root / "runs").resolve() or not source_dir.is_dir():
        raise ConductorError("source run does not exist")
    source_summary = load_json(source_dir / "summary.json")
    source_task = load_json(source_dir / "task.json")
    if source_task.get("expectedHead") != task["expectedHead"]:
        raise ConductorError("source run used a different Foundry baseline")
    if source_summary.get("sourceUnchanged") is not True or source_summary.get("snapshotClean") is not True:
        raise ConductorError("source run did not preserve its boundaries")
    matching_candidates = [
        path for path in source_dir.glob("round-*/candidate.md")
        if sha256_bytes(path.read_bytes()) == candidate_sha256
    ]
    if len(matching_candidates) != 1:
        raise ConductorError("candidate digest does not identify exactly one preserved round")
    candidate_path = matching_candidates[0]
    source_round = candidate_path.parent
    try:
        source_round_number = int(source_round.name.removeprefix("round-"))
    except ValueError as exc:
        raise ConductorError("preserved candidate round name is invalid") from exc
    candidate = candidate_path.read_text(encoding="utf-8")
    if sha256_bytes(candidate.encode()) != candidate_sha256:
        raise ConductorError("candidate bytes do not match the authorized digest")

    source_repo = Path(task["sourceRepository"]).expanduser().resolve()
    before = fingerprint_repo(source_repo)
    verify_baseline(task, before)
    run_id = make_run_id("package-2a-defect-inventory")
    run_dir = root / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    log = AppendOnlyLog(run_dir / "events.jsonl")
    log.append("defect_inventory_started", runId=run_id, sourceRunId=source_run_id, live=live)
    write_once(run_dir / "task.json", json.dumps(task, indent=2, sort_keys=True).encode() + b"\n")
    write_once(run_dir / "source-before.json", json.dumps(asdict(before), indent=2).encode() + b"\n")
    snapshot = run_dir / "snapshot"
    create_tracked_snapshot(source_repo, snapshot)
    known = _known_path_finding(source_round, candidate_sha256)
    seed = {
        "sourceRunId": source_run_id,
        "sourceRound": source_round_number,
        "candidateSha256": candidate_sha256,
        "candidateArtifactSha256": sha256_bytes(candidate_path.read_bytes()),
        "knownFinding": known,
    }
    write_once(run_dir / "seed.json", json.dumps(seed, indent=2, sort_keys=True).encode() + b"\n")
    write_once(run_dir / "candidate.md", candidate.encode())
    packet_records: list[dict[str, Any]] = []
    packet_values: list[dict[str, Any]] = []
    for definition in PACKETS:
        text = _packet_text(candidate, definition["ranges"])
        digest = sha256_bytes(text.encode())
        packet = {**definition, "text": text, "sha256": digest}
        packet_values.append(packet)
        packet_dir = run_dir / "packets" / definition["id"]
        write_once(packet_dir / "packet.md", text.encode())
        record = {
            "packetId": definition["id"], "title": definition["title"],
            "ranges": definition["ranges"], "packetSha256": digest,
            "candidateSha256": candidate_sha256,
        }
        write_once(packet_dir / "manifest.json", json.dumps(record, indent=2, sort_keys=True).encode() + b"\n")
        packet_records.append(record)
    write_once(run_dir / "packet-manifest.json", json.dumps(packet_records, indent=2, sort_keys=True).encode() + b"\n")

    imported_reviews: dict[str, dict[str, dict[str, Any]]] = {}
    review_attempt_counts: dict[str, int] = {}
    if packet_review_run_id is not None:
        review_dir = (root / "runs" / packet_review_run_id).resolve()
        if review_dir.parent != (root / "runs").resolve() or not review_dir.is_dir():
            raise ConductorError("packet review run does not exist")
        review_summary = load_json(review_dir / "summary.json")
        if review_summary.get("candidateSha256") != candidate_sha256:
            raise ConductorError("packet review run targets a different candidate")
        if review_summary.get("sourceUnchanged") is not True or review_summary.get("snapshotClean") is not True:
            raise ConductorError("packet review run did not preserve its boundaries")
        prior_counts = review_summary.get("reviewAttemptCounts", {})
        if not isinstance(prior_counts, dict):
            raise ConductorError("packet review attempt counts are invalid")
        review_attempt_counts = {
            str(key): int(value) for key, value in prior_counts.items()
            if isinstance(value, int) and value >= 0
        }
        imported_hashes: dict[str, dict[str, str]] = {}
        for packet in packet_values:
            prior_manifest = load_json(review_dir / "packets" / packet["id"] / "manifest.json")
            if prior_manifest.get("candidateSha256") != candidate_sha256 or prior_manifest.get(
                "packetSha256"
            ) != packet["sha256"]:
                raise ConductorError(f"packet review run {packet['id']} manifest does not match")
            packet_imports: dict[str, dict[str, Any]] = {}
            packet_hashes: dict[str, str] = {}
            for reviewer in task["reviewers"]:
                key = f"{packet['id']}/{reviewer}"
                normalized_path = review_dir / "packets" / packet["id"] / f"review-{reviewer}.normalized.json"
                import_path = review_dir / "packets" / packet["id"] / f"review-{reviewer}-import.json"
                stdout_path = review_dir / "packets" / packet["id"] / f"review-{reviewer}.stdout"
                review_paths = [path for path in (normalized_path, import_path) if path.is_file()]
                if review_paths:
                    reviews = [validate_packet_review(load_json(path)) for path in review_paths]
                    if len(reviews) == 2 and reviews[0] != reviews[1]:
                        raise ConductorError(
                            f"conflicting completed {reviewer} reviews for {packet['id']}"
                        )
                    review = reviews[0]
                    if (
                        review["candidateSha256"] != candidate_sha256
                        or review["packetId"] != packet["id"]
                        or review["packetSha256"] != packet["sha256"]
                    ):
                        raise ConductorError(f"imported {reviewer} review targets the wrong packet")
                    packet_imports[reviewer] = review
                    packet_hashes[reviewer] = sha256_bytes(
                        json.dumps(review, sort_keys=True, separators=(",", ":")).encode()
                    )
                    review_attempt_counts[key] = max(review_attempt_counts.get(key, 0), 1)
                elif stdout_path.is_file():
                    review_attempt_counts[key] = max(review_attempt_counts.get(key, 0), 1)
            if packet_imports:
                imported_reviews[packet["id"]] = packet_imports
                imported_hashes[packet["id"]] = packet_hashes
        packet_import = {
            "packetReviewRunId": packet_review_run_id,
            "candidateSha256": candidate_sha256,
            "normalizedReviewSha256": imported_hashes,
            "reviewAttemptCounts": review_attempt_counts,
        }
        write_once(
            run_dir / "packet-review-import.json",
            json.dumps(packet_import, indent=2, sort_keys=True).encode() + b"\n",
        )
        log.append("packet_reviews_imported", **packet_import)

    summary: dict[str, Any] = {
        "runId": run_id, "runDirectory": str(run_dir), "live": live,
        "status": "planned" if not live else "running", "candidateSha256": candidate_sha256,
        "sourceRunId": source_run_id, "packets": packet_records,
        "reviewAttemptCounts": review_attempt_counts,
    }
    try:
        if not live:
            summary["status"] = "planned"
        else:
            if traceability_run_id is None:
                traceability = _invoke(
                    agent="claude", snapshot=snapshot,
                    prompt=_traceability_prompt(candidate, candidate_sha256, packet_values),
                    schema_path=root / "schemas" / "traceability-result.schema.json",
                    validator=validate_traceability_result,
                    prefix=run_dir / "traceability" / "claude", timeout_seconds=task["timeoutSeconds"],
                    max_turns=task["authorMaxTurns"], log=log,
                )
            else:
                trace_dir = (root / "runs" / traceability_run_id).resolve()
                if trace_dir.parent != (root / "runs").resolve() or not trace_dir.is_dir():
                    raise ConductorError("traceability run does not exist")
                trace_summary = load_json(trace_dir / "summary.json")
                if trace_summary.get("candidateSha256") != candidate_sha256:
                    raise ConductorError("traceability run targets a different candidate")
                if trace_summary.get("sourceUnchanged") is not True or trace_summary.get("snapshotClean") is not True:
                    raise ConductorError("traceability run did not preserve its boundaries")
                raw_path = trace_dir / "traceability" / "claude.stdout"
                raw = raw_path.read_bytes()
                traceability = parse_structured_response(raw, validate_traceability_result)
                trace_import = {
                    "traceabilityRunId": traceability_run_id,
                    "candidateSha256": candidate_sha256,
                    "rawStdoutSha256": sha256_bytes(raw),
                    "normalizedSha256": sha256_bytes(
                        json.dumps(traceability, sort_keys=True).encode()
                    ),
                }
                write_once(
                    run_dir / "traceability" / "import.json",
                    json.dumps(trace_import, indent=2, sort_keys=True).encode() + b"\n",
                )
                write_once(
                    run_dir / "traceability" / "claude.normalized.json",
                    json.dumps(traceability, indent=2, sort_keys=True).encode() + b"\n",
                )
                summary["traceabilityImport"] = trace_import
                log.append("traceability_imported", **trace_import)
            if traceability["candidateSha256"] != candidate_sha256:
                raise ConductorError("Claude traceability targets the wrong candidate")
            if traceability["verdict"] == "blocked":
                summary["status"] = "blocked_traceability"
            else:
                reviews: dict[str, dict[str, dict[str, Any]]] = {}
                for packet in packet_values:
                    packet_reviews: dict[str, dict[str, Any]] = {}
                    for reviewer in task["reviewers"]:
                        if reviewer in imported_reviews.get(packet["id"], {}):
                            review = imported_reviews[packet["id"]][reviewer]
                            write_once(
                                run_dir / "packets" / packet["id"] / f"review-{reviewer}-import.json",
                                json.dumps(review, indent=2, sort_keys=True).encode() + b"\n",
                            )
                        else:
                            key = f"{packet['id']}/{reviewer}"
                            attempts = review_attempt_counts.get(key, 0)
                            if attempts >= 2:
                                if not (
                                    packet["id"] == additional_cursor_attempt_packet
                                    and reviewer == "cursor"
                                    and attempts == 2
                                ):
                                    raise ConductorError(f"{key} exhausted its two bounded attempts")
                                log.append(
                                    "additional_packet_attempt_authorized",
                                    packetId=packet["id"], reviewer=reviewer,
                                    priorAttemptCount=attempts, authorizedAttemptCount=attempts + 1,
                                )
                            review_attempt_counts[key] = attempts + 1
                            review = _invoke(
                                agent=reviewer, snapshot=snapshot,
                                prompt=_packet_review_prompt(
                                    reviewer=reviewer, packet=packet, packet_text=packet["text"],
                                    packet_hash=packet["sha256"], candidate_hash=candidate_sha256,
                                    traceability=traceability, known_finding=known,
                                ),
                                schema_path=root / "schemas" / "packet-review-result.schema.json",
                                validator=validate_packet_review,
                                prefix=run_dir / "packets" / packet["id"] / f"review-{reviewer}",
                                timeout_seconds=task["timeoutSeconds"], max_turns=task["reviewerMaxTurns"],
                                log=log,
                            )
                        if review["candidateSha256"] != candidate_sha256:
                            raise ConductorError(f"{reviewer} packet review targets the wrong candidate")
                        if review["packetId"] != packet["id"] or review["packetSha256"] != packet["sha256"]:
                            raise ConductorError(f"{reviewer} packet review targets the wrong packet")
                        packet_reviews[reviewer] = review
                    reviews[packet["id"]] = packet_reviews
                    verdict_record = {
                        "packetId": packet["id"],
                        "reviewers": {
                            reviewer: {"verdict": review["verdict"], "findingCount": len(review["findings"]),
                                       "requiresHuman": review["requiresHuman"]}
                            for reviewer, review in packet_reviews.items()
                        },
                    }
                    write_once(
                        run_dir / "packets" / packet["id"] / "verdicts.json",
                        json.dumps(verdict_record, indent=2, sort_keys=True).encode() + b"\n",
                    )
                    log.append("packet_reviewed", **verdict_record)
                inventory = _consolidate(known, reviews, traceability)
                inventory_record = {
                    "candidateSha256": candidate_sha256,
                    "status": "complete",
                    "defectCount": len(inventory),
                    "defects": inventory,
                }
                write_once(
                    run_dir / "final" / "defect-inventory.json",
                    json.dumps(inventory_record, indent=2, sort_keys=True).encode() + b"\n",
                )
                proposed = _proposed_authorization(candidate_sha256, inventory)
                write_once(run_dir / "final" / "proposed-final-revision-authorization.md", proposed.encode())
                summary.update({
                    "status": "ready_for_operator_decision", "defectCount": len(inventory),
                    "packetVerdicts": {
                        packet_id: {reviewer: review["verdict"] for reviewer, review in packet_reviews.items()}
                        for packet_id, packet_reviews in reviews.items()
                    },
                })
                log.append("defect_inventory_completed", defectCount=len(inventory))
    except ConductorError as exc:
        summary["status"] = "failed"
        summary["error"] = str(exc)
        log.append("defect_inventory_failed", error=str(exc))
    after = fingerprint_repo(source_repo)
    unchanged = before == after
    write_once(run_dir / "source-after.json", json.dumps(asdict(after), indent=2).encode() + b"\n")
    summary["sourceUnchanged"] = unchanged
    summary["snapshotClean"] = snapshot_is_clean(snapshot)
    if not unchanged:
        summary["status"] = "failed_source_changed"
    write_once(run_dir / "summary.json", json.dumps(summary, indent=2, sort_keys=True).encode() + b"\n")
    log.append(
        "defect_inventory_finished", status=summary["status"], sourceUnchanged=unchanged,
        snapshotClean=summary["snapshotClean"],
    )
    return summary
