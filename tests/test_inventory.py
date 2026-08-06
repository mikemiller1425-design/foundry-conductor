from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from foundry_conductor.core import ConductorError, fingerprint_repo
from foundry_conductor.inventory import (
    PACKETS,
    run_defect_inventory,
    validate_packet_review,
    validate_traceability_result,
)


def command(repo: Path, *argv: str) -> None:
    subprocess.run(argv, cwd=repo, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class InventoryTests(unittest.TestCase):
    def make_repo(self, root: Path) -> Path:
        repo = root / "source"
        repo.mkdir()
        command(repo, "git", "init", "-q", "-b", "main")
        for relative in (
            "docs/decision.md", "docs/map.md", "docs/threat.md", "docs/package1.md", "CHANGELOG.md"
        ):
            path = repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(relative + "\n", encoding="utf-8")
        command(repo, "git", "add", "-A")
        command(
            repo, "git", "-c", "user.name=Test", "-c", "user.email=test@localhost",
            "commit", "-qm", "fixture",
        )
        return repo

    def make_task(self, repo: Path) -> dict:
        return {
            "schemaVersion": 1,
            "workflow": "bounded_reconciliation",
            "id": "test-inventory",
            "sourceRepository": str(repo),
            "expectedBranch": "main",
            "expectedHead": fingerprint_repo(repo).head,
            "permissions": {"repositoryWrite": False, "nasAccess": False, "push": False, "liveModelCalls": True},
            "author": "claude",
            "reviewers": ["codex", "cursor"],
            "maxRounds": 3,
            "authorMaxTurns": 5,
            "reviewerMaxTurns": 5,
            "timeoutSeconds": 30,
            "objective": "Inventory only.",
            "authoritativeSources": ["docs/decision.md", "docs/map.md", "docs/threat.md", "docs/package1.md", "CHANGELOG.md"],
            "reviewerFocus": {"codex": "governance", "cursor": "consumer truth"},
        }

    def make_preserved_run(self, root: Path, task: dict) -> tuple[str, str]:
        run_id = "20260101T000000Z-test-inventory-abcdef12"
        run_dir = root / "runs" / run_id
        round_dir = run_dir / "round-06"
        round_dir.mkdir(parents=True)
        (run_dir / "task.json").write_text(json.dumps(task), encoding="utf-8")
        (run_dir / "summary.json").write_text(json.dumps({
            "status": "failed", "sourceUnchanged": True, "snapshotClean": True,
            "rounds": [{"round": number} for number in range(1, 6)],
        }), encoding="utf-8")
        candidate = "\n".join(f"line {number}" for number in range(1, 466)) + "\n"
        candidate_hash = hashlib.sha256(candidate.encode()).hexdigest()
        (round_dir / "candidate.md").write_text(candidate, encoding="utf-8")
        (round_dir / "review-codex.normalized.json").write_text(json.dumps({
            "verdict": "revise", "draftSha256": candidate_hash, "summary": "revise",
            "findings": [{
                "severity": "error", "category": "paths", "message": "absolute path claim is false",
                "requiredChange": "narrow the path claim",
            }], "requiresHuman": False,
        }), encoding="utf-8")
        return run_id, candidate_hash

    def test_packet_review_status_rules(self) -> None:
        value = {
            "verdict": "pass", "candidateSha256": "a" * 64,
            "packetId": "hashing-identity", "packetSha256": "b" * 64,
            "summary": "pass", "findings": [], "requiresHuman": False,
        }
        self.assertEqual(value, validate_packet_review(value))
        value["verdict"] = "findings_complete"
        with self.assertRaisesRegex(Exception, "at least one"):
            validate_packet_review(value)

    def test_inventory_packetizes_reviews_and_consolidates_known_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = self.make_repo(root)
            task = self.make_task(repo)
            task_path = root / "task.json"
            task_path.write_text(json.dumps(task), encoding="utf-8")
            run_id, candidate_hash = self.make_preserved_run(root, task)
            traceability = {
                "verdict": "complete", "candidateSha256": candidate_hash,
                "entries": [{
                    "requirementId": "R-1", "requirement": "all requirements",
                    "candidateLocations": ["candidate"],
                    "packetIds": [packet["id"] for packet in PACKETS],
                    "status": "covered", "notes": "",
                }], "gaps": [], "requiresHuman": False,
            }
            trace_id = "20260101T000001Z-package-2a-defect-inventory-bcdef123"
            trace_dir = root / "runs" / trace_id
            (trace_dir / "traceability").mkdir(parents=True)
            (trace_dir / "summary.json").write_text(json.dumps({
                "candidateSha256": candidate_hash,
                "sourceUnchanged": True,
                "snapshotClean": True,
            }), encoding="utf-8")
            (trace_dir / "traceability" / "claude.stdout").write_text(
                json.dumps({"result": json.dumps(traceability)}), encoding="utf-8"
            )
            calls: list[tuple[str, str]] = []

            def invoke_side_effect(**kwargs):
                calls.append((kwargs["agent"], kwargs["prefix"].name))
                prompt = kwargs["prompt"]
                packet_id = next(packet["id"] for packet in PACKETS if f"Packet: {packet['id']}" in prompt)
                packet_hash = next(packet["sha256"] for packet in packet_records if packet["id"] == packet_id)
                return {
                    "verdict": "pass", "candidateSha256": candidate_hash,
                    "packetId": packet_id, "packetSha256": packet_hash,
                    "summary": "complete", "findings": [], "requiresHuman": False,
                }

            packet_records = []
            from foundry_conductor.inventory import _packet_text
            candidate = (root / "runs" / run_id / "round-06" / "candidate.md").read_text()
            for definition in PACKETS:
                text = _packet_text(candidate, definition["ranges"])
                packet_records.append({**definition, "sha256": hashlib.sha256(text.encode()).hexdigest()})
            review_resume_id = "20260101T000002Z-package-2a-defect-inventory-cdef1234"
            review_resume_dir = root / "runs" / review_resume_id
            (review_resume_dir / "summary.json").parent.mkdir(parents=True)
            (review_resume_dir / "summary.json").write_text(json.dumps({
                "candidateSha256": candidate_hash,
                "sourceUnchanged": True,
                "snapshotClean": True,
                "reviewAttemptCounts": {},
            }), encoding="utf-8")
            passing_reviews = {
                ("hashing-identity", "codex"),
                ("hashing-identity", "cursor"),
                ("coverage-truth", "codex"),
            }
            for packet in packet_records:
                packet_dir = review_resume_dir / "packets" / packet["id"]
                packet_dir.mkdir(parents=True)
                (packet_dir / "manifest.json").write_text(json.dumps({
                    "candidateSha256": candidate_hash,
                    "packetSha256": packet["sha256"],
                }), encoding="utf-8")
                for reviewer in ("codex", "cursor"):
                    if (packet["id"], reviewer) in passing_reviews:
                        (packet_dir / f"review-{reviewer}.normalized.json").write_text(json.dumps({
                            "verdict": "pass", "candidateSha256": candidate_hash,
                            "packetId": packet["id"], "packetSha256": packet["sha256"],
                            "summary": "complete", "findings": [], "requiresHuman": False,
                        }), encoding="utf-8")
            (review_resume_dir / "packets" / "coverage-truth" / "review-cursor.stdout").write_text(
                "invalid", encoding="utf-8"
            )
            with patch("foundry_conductor.inventory._invoke", side_effect=invoke_side_effect):
                result = run_defect_inventory(
                    root=root, task_path=task_path, source_run_id=run_id,
                    candidate_sha256=candidate_hash, live=True, live_confirmed=True,
                    traceability_run_id=trace_id,
                    packet_review_run_id=review_resume_id,
                )
            self.assertEqual("ready_for_operator_decision", result["status"])
            self.assertEqual(7, len(calls))
            self.assertEqual(0, sum(1 for agent, _ in calls if agent == "claude"))
            self.assertEqual(4, sum(1 for agent, _ in calls if agent == "cursor"))
            self.assertEqual(2, result["reviewAttemptCounts"]["coverage-truth/cursor"])
            inventory = json.loads(
                (Path(result["runDirectory"]) / "final" / "defect-inventory.json").read_text()
            )
            self.assertEqual(1, inventory["defectCount"])
            self.assertEqual("roots-absolute-path-scope", inventory["defects"][0]["dedupKey"])
            proposed = (
                Path(result["runDirectory"]) / "final" / "proposed-final-revision-authorization.md"
            ).read_text()
            self.assertIn("PROPOSED — NOT AUTHORIZED", proposed)
            self.assertIn(candidate_hash, proposed)

    def test_traceability_validator_accepts_complete_matrix(self) -> None:
        value = {
            "verdict": "complete", "candidateSha256": "a" * 64,
            "entries": [{
                "requirementId": "R-1", "requirement": "requirement",
                "candidateLocations": ["§1"], "packetIds": ["governance-boundaries"],
                "status": "covered", "notes": "",
            }], "gaps": [], "requiresHuman": False,
        }
        self.assertEqual(value, validate_traceability_result(value))
        value["requiresHuman"] = True
        self.assertEqual(value, validate_traceability_result(value))

    def test_second_generation_resume_reuses_imported_reviews(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = self.make_repo(root)
            task = self.make_task(repo)
            task_path = root / "task.json"
            task_path.write_text(json.dumps(task), encoding="utf-8")
            source_run_id, candidate_hash = self.make_preserved_run(root, task)
            candidate = (root / "runs" / source_run_id / "round-06" / "candidate.md").read_text()
            from foundry_conductor.inventory import _packet_text
            packet_hashes = {
                packet["id"]: hashlib.sha256(_packet_text(candidate, packet["ranges"]).encode()).hexdigest()
                for packet in PACKETS
            }

            trace_id = "20260101T000001Z-package-2a-defect-inventory-bcdef123"
            trace_dir = root / "runs" / trace_id
            (trace_dir / "traceability").mkdir(parents=True)
            (trace_dir / "summary.json").write_text(json.dumps({
                "candidateSha256": candidate_hash, "sourceUnchanged": True, "snapshotClean": True,
            }), encoding="utf-8")
            traceability = {
                "verdict": "complete", "candidateSha256": candidate_hash,
                "entries": [{
                    "requirementId": "R-1", "requirement": "all requirements",
                    "candidateLocations": ["candidate"],
                    "packetIds": [packet["id"] for packet in PACKETS],
                    "status": "covered", "notes": "",
                }], "gaps": [], "requiresHuman": False,
            }
            (trace_dir / "traceability" / "claude.stdout").write_text(
                json.dumps({"result": json.dumps(traceability)}), encoding="utf-8"
            )

            review_id = "20260101T000002Z-package-2a-defect-inventory-cdef1234"
            review_dir = root / "runs" / review_id
            (review_dir / "summary.json").parent.mkdir(parents=True)
            counts = {f"{packet['id']}/{reviewer}": 1 for packet in PACKETS for reviewer in task["reviewers"]}
            (review_dir / "summary.json").write_text(json.dumps({
                "candidateSha256": candidate_hash, "sourceUnchanged": True, "snapshotClean": True,
                "reviewAttemptCounts": counts,
            }), encoding="utf-8")
            for packet in PACKETS:
                packet_dir = review_dir / "packets" / packet["id"]
                packet_dir.mkdir(parents=True)
                (packet_dir / "manifest.json").write_text(json.dumps({
                    "candidateSha256": candidate_hash, "packetSha256": packet_hashes[packet["id"]],
                }), encoding="utf-8")
                for reviewer in task["reviewers"]:
                    review = {
                        "verdict": "pass", "candidateSha256": candidate_hash,
                        "packetId": packet["id"], "packetSha256": packet_hashes[packet["id"]],
                        "summary": "complete", "findings": [], "requiresHuman": False,
                    }
                    (packet_dir / f"review-{reviewer}-import.json").write_text(
                        json.dumps(review), encoding="utf-8"
                    )

            with patch("foundry_conductor.inventory._invoke") as invoke:
                result = run_defect_inventory(
                    root=root, task_path=task_path, source_run_id=source_run_id,
                    candidate_sha256=candidate_hash, live=True, live_confirmed=True,
                    traceability_run_id=trace_id, packet_review_run_id=review_id,
                )
            invoke.assert_not_called()
            self.assertEqual("ready_for_operator_decision", result["status"])
            self.assertEqual(counts, result["reviewAttemptCounts"])
            conflict_path = review_dir / "packets" / "hashing-identity" / "review-codex.normalized.json"
            conflicting = json.loads(
                (review_dir / "packets" / "hashing-identity" / "review-codex-import.json").read_text()
            )
            conflicting["summary"] = "different completed review"
            conflict_path.write_text(json.dumps(conflicting), encoding="utf-8")
            with self.assertRaisesRegex(ConductorError, "conflicting completed codex reviews"):
                run_defect_inventory(
                    root=root, task_path=task_path, source_run_id=source_run_id,
                    candidate_sha256=candidate_hash, live=True, live_confirmed=True,
                    traceability_run_id=trace_id, packet_review_run_id=review_id,
                )
            conflict_path.unlink()
            coverage_cursor = (
                review_dir / "packets" / "coverage-truth" / "review-cursor-import.json"
            )
            coverage_cursor.unlink()
            counts["coverage-truth/cursor"] = 2
            (review_dir / "summary.json").write_text(json.dumps({
                "candidateSha256": candidate_hash, "sourceUnchanged": True,
                "snapshotClean": True, "reviewAttemptCounts": counts,
            }), encoding="utf-8")

            def coverage_cursor_review(**kwargs):
                self.assertEqual("cursor", kwargs["agent"])
                return {
                    "verdict": "pass", "candidateSha256": candidate_hash,
                    "packetId": "coverage-truth",
                    "packetSha256": packet_hashes["coverage-truth"],
                    "summary": "complete", "findings": [], "requiresHuman": False,
                }

            with patch(
                "foundry_conductor.inventory._invoke", side_effect=coverage_cursor_review
            ) as invoke:
                authorized = run_defect_inventory(
                    root=root, task_path=task_path, source_run_id=source_run_id,
                    candidate_sha256=candidate_hash, live=True, live_confirmed=True,
                    traceability_run_id=trace_id, packet_review_run_id=review_id,
                    additional_cursor_attempt_packet="coverage-truth",
                )
            self.assertEqual(1, invoke.call_count)
            self.assertEqual(3, authorized["reviewAttemptCounts"]["coverage-truth/cursor"])
            events = (
                Path(authorized["runDirectory"]) / "events.jsonl"
            ).read_text(encoding="utf-8")
            self.assertIn('"event":"additional_packet_attempt_authorized"', events)
            with self.assertRaisesRegex(ConductorError, "not in the review packet list"):
                run_defect_inventory(
                    root=root, task_path=task_path, source_run_id=source_run_id,
                    candidate_sha256=candidate_hash, live=True, live_confirmed=True,
                    traceability_run_id=trace_id, packet_review_run_id=review_id,
                    additional_cursor_attempt_packet="not-a-packet",
                )
