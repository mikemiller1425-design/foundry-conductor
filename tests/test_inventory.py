from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from foundry_conductor.core import fingerprint_repo
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
            with patch("foundry_conductor.inventory._invoke", side_effect=invoke_side_effect):
                result = run_defect_inventory(
                    root=root, task_path=task_path, source_run_id=run_id,
                    candidate_sha256=candidate_hash, live=True, live_confirmed=True,
                    traceability_run_id=trace_id,
                )
            self.assertEqual("ready_for_operator_decision", result["status"])
            self.assertEqual(10, len(calls))
            self.assertEqual(0, sum(1 for agent, _ in calls if agent == "claude"))
            self.assertEqual(5, sum(1 for agent, _ in calls if agent == "cursor"))
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
