from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from foundry_conductor.core import ConductorError, fingerprint_repo
from foundry_conductor.final_revision import (
    DEFECT_IDS, run_final_revision, validate_closure_ledger,
    validate_final_review, validate_final_revision_response,
)


def command(repo: Path, *argv: str) -> None:
    subprocess.run(argv, cwd=repo, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class FinalRevisionTests(unittest.TestCase):
    def make_repo(self, root: Path) -> Path:
        repo = root / "source"
        repo.mkdir()
        command(repo, "git", "init", "-q", "-b", "main")
        (repo / "source.md").write_text("source\n", encoding="utf-8")
        command(repo, "git", "add", "source.md")
        command(repo, "git", "-c", "user.name=Test", "-c", "user.email=test@localhost", "commit", "-qm", "fixture")
        return repo

    def task(self, repo: Path) -> dict:
        return {
            "schemaVersion": 1, "workflow": "bounded_reconciliation", "id": "test-final",
            "sourceRepository": str(repo), "expectedBranch": "main",
            "expectedHead": fingerprint_repo(repo).head,
            "permissions": {"repositoryWrite": False, "nasAccess": False, "push": False, "liveModelCalls": True},
            "author": "claude", "reviewers": ["codex", "cursor"], "maxRounds": 3,
            "authorMaxTurns": 5, "reviewerMaxTurns": 5, "timeoutSeconds": 30,
            "objective": "final", "authoritativeSources": ["source.md"],
            "reviewerFocus": {"codex": "governance", "cursor": "consumer"},
        }

    def ledger(self, *, status: str = "resolved") -> list[dict]:
        return [{
            "defectId": defect_id, "status": status,
            "revisedDraftLocation": {"lineStart": 1, "lineEnd": 1, "exactText": "# Final"},
            "closure": {"kind": "contract", "location": {"lineStart": 2, "lineEnd": 2, "exactText": "Contract closes all rows."}},
            "explanation": "The cited contract supplies the required closure.",
        } for defect_id in DEFECT_IDS]

    def passing_review(self, draft_hash: str = "a" * 64, ledger_hash: str = "b" * 64) -> dict:
        return {
            "verdict": "pass", "draftSha256": draft_hash, "ledgerSha256": ledger_hash,
            "confirmedDefectCount": 89, "allDefectIdsPresentExactlyOnce": True,
            "allSubstantivelyResolved": True, "allProofsExecutable": True,
            "noBoundaryWeakened": True, "noNewFindings": True,
            "summary": "Explicitly confirmed 89 of 89 closures.", "findings": [],
            "requiresHuman": False,
        }

    def test_ledger_enforces_exact_ids_locations_and_fields(self) -> None:
        draft = "# Final\nContract closes all rows."
        ledger = self.ledger()
        self.assertEqual(ledger, validate_closure_ledger(ledger, draft))
        cases = []
        missing = copy.deepcopy(ledger[:-1]); cases.append((missing, "exactly 89"))
        duplicate = copy.deepcopy(ledger); duplicate[-1]["defectId"] = "DEFECT-088"; cases.append((duplicate, "exactly once"))
        reordered = copy.deepcopy(ledger); reordered[0], reordered[1] = reordered[1], reordered[0]; cases.append((reordered, "exactly once"))
        bad_line = copy.deepcopy(ledger); bad_line[0]["revisedDraftLocation"]["lineStart"] = 3; cases.append((bad_line, "do not exist"))
        bad_text = copy.deepcopy(ledger); bad_text[0]["closure"]["location"]["exactText"] = "invented"; cases.append((bad_text, "does not match"))
        bad_kind = copy.deepcopy(ledger); bad_kind[0]["closure"]["kind"] = "claim"; cases.append((bad_kind, "kind is invalid"))
        bad_explanation = copy.deepcopy(ledger); bad_explanation[0]["explanation"] = ""; cases.append((bad_explanation, "explanation is invalid"))
        extra = copy.deepcopy(ledger); extra[0]["extra"] = True; cases.append((extra, "fields do not match"))
        for value, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(ConductorError, message):
                validate_closure_ledger(value, draft)

    def test_author_response_rejects_unverifiable_or_human_draft(self) -> None:
        value = {"status": "drafted", "draft": "# Final\nContract closes all rows.", "closureLedger": self.ledger(), "notes": [], "requiresHuman": False}
        self.assertEqual(value, validate_final_revision_response(value))
        human = copy.deepcopy(value); human["requiresHuman"] = True
        with self.assertRaisesRegex(ConductorError, "no human decision"):
            validate_final_revision_response(human)
        malformed = copy.deepcopy(value); malformed["closureLedger"][0]["status"] = "closed"
        with self.assertRaisesRegex(ConductorError, "status is invalid"):
            validate_final_revision_response(malformed)

    def test_review_requires_explicit_89_of_89_pass(self) -> None:
        value = self.passing_review()
        self.assertEqual(value, validate_final_review(value))
        mutations = {
            "count": ("confirmedDefectCount", 88),
            "unresolved": ("allSubstantivelyResolved", False),
            "proof": ("allProofsExecutable", False),
            "boundary": ("noBoundaryWeakened", False),
            "new": ("noNewFindings", False),
            "ids": ("allDefectIdsPresentExactlyOnce", False),
            "human": ("requiresHuman", True),
        }
        for name, (field, replacement) in mutations.items():
            invalid = copy.deepcopy(value); invalid[field] = replacement
            with self.subTest(name=name), self.assertRaises(ConductorError):
                validate_final_review(invalid)
        finding = copy.deepcopy(value)
        finding["findings"] = [{"defectId": None, "category": "new", "message": "new finding", "requiredChange": "fix"}]
        with self.assertRaisesRegex(ConductorError, "zero findings"):
            validate_final_review(finding)

    def test_bound_workflow_emits_only_after_matching_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = self.make_repo(root)
            task_path = root / "task.json"
            task_path.write_text(json.dumps(self.task(repo)), encoding="utf-8")
            run_id = "20260101T000000Z-package-2a-defect-inventory-abcdef12"
            run_dir = root / "runs" / run_id
            (run_dir / "final").mkdir(parents=True)
            candidate = b"candidate\n"
            inventory = {"candidateSha256": hashlib.sha256(candidate).hexdigest(), "defectCount": 89, "defects": [{"defectId": defect_id} for defect_id in DEFECT_IDS]}
            proposed = b"authoritative defects\n"
            (run_dir / "candidate.md").write_bytes(candidate)
            (run_dir / "final" / "defect-inventory.json").write_text(json.dumps(inventory), encoding="utf-8")
            (run_dir / "final" / "proposed-final-revision-authorization.md").write_bytes(proposed)
            (run_dir / "summary.json").write_text(json.dumps({"status": "ready_for_operator_decision", "sourceUnchanged": True, "snapshotClean": True}), encoding="utf-8")
            draft = "# Final\nContract closes all rows."
            ledger = self.ledger()
            ledger_bytes = json.dumps(ledger, indent=2, sort_keys=True).encode() + b"\n"
            draft_hash = hashlib.sha256(draft.encode()).hexdigest()
            ledger_hash = hashlib.sha256(ledger_bytes).hexdigest()
            calls = []
            def invoke(**kwargs):
                calls.append(kwargs["agent"])
                prefix_name = kwargs["prefix"].name
                prefix_parts = kwargs["prefix"].parts
                if prefix_name == "author-claude":
                    response = {"status": "drafted", "draft": draft, "notes": [], "requiresHuman": False}
                elif "ledger" in prefix_parts:
                    ordinal = int(prefix_name.split("-")[1])
                    response = {"draftSha256": draft_hash, "rows": ledger[(ordinal - 1) * 18:ordinal * 18]}
                elif "reviews" in prefix_parts:
                    ordinal = int(prefix_name.split("-")[1])
                    ids = list(DEFECT_IDS[(ordinal - 1) * 18:ordinal * 18])
                    response = {
                        "verdict": "pass", "draftSha256": draft_hash,
                        "ledgerSha256": ledger_hash, "reviewedDefectIds": ids,
                        "allSubstantivelyResolved": True, "allProofsExecutable": True,
                        "noBoundaryWeakened": True, "noNewFindings": True,
                        "summary": "packet pass", "findings": [], "requiresHuman": False,
                    }
                else:
                    response = self.passing_review(draft_hash, ledger_hash)
                kwargs["prefix"].parent.mkdir(parents=True, exist_ok=True)
                kwargs["prefix"].with_suffix(".normalized.json").write_text(
                    json.dumps(response), encoding="utf-8"
                )
                return response
            with patch("foundry_conductor.final_revision._invoke", side_effect=invoke):
                result = run_final_revision(
                    root=root, task_path=task_path, source_run_id=run_id,
                    candidate_sha256=hashlib.sha256(candidate).hexdigest(),
                    defect_inventory_sha256=hashlib.sha256((run_dir / "final" / "defect-inventory.json").read_bytes()).hexdigest(),
                    proposed_authorization_sha256=hashlib.sha256(proposed).hexdigest(),
                    live=True, live_confirmed=True,
                )
            self.assertEqual(18, len(calls))
            self.assertEqual(6, calls.count("claude"))
            self.assertEqual(6, calls.count("codex"))
            self.assertEqual(6, calls.count("cursor"))
            self.assertEqual("ready_for_operator_decision", result["status"])
            self.assertEqual(89, result["closureRowCount"])
            self.assertEqual(draft.encode(), (Path(result["runDirectory"]) / "final" / "package-2a-authorization-prompt.md").read_bytes())
            with patch("foundry_conductor.final_revision._invoke") as resumed_invoke:
                resumed = run_final_revision(
                    root=root, task_path=task_path, source_run_id=run_id,
                    candidate_sha256=hashlib.sha256(candidate).hexdigest(),
                    defect_inventory_sha256=hashlib.sha256((run_dir / "final" / "defect-inventory.json").read_bytes()).hexdigest(),
                    proposed_authorization_sha256=hashlib.sha256(proposed).hexdigest(),
                    live=True, live_confirmed=True,
                    resume_run_id=result["runId"],
                )
            resumed_invoke.assert_not_called()
            self.assertEqual("ready_for_operator_decision", resumed["status"])

    def test_bound_artifact_mismatch_fails_before_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = self.make_repo(root)
            task_path = root / "task.json"; task_path.write_text(json.dumps(self.task(repo)))
            run_id = "20260101T000000Z-package-2a-defect-inventory-abcdef12"
            run_dir = root / "runs" / run_id; (run_dir / "final").mkdir(parents=True)
            (run_dir / "summary.json").write_text(json.dumps({"status": "ready_for_operator_decision", "sourceUnchanged": True, "snapshotClean": True}))
            (run_dir / "candidate.md").write_text("candidate")
            (run_dir / "final" / "defect-inventory.json").write_text("{}")
            (run_dir / "final" / "proposed-final-revision-authorization.md").write_text("proposal")
            with patch("foundry_conductor.final_revision._invoke") as invoke, self.assertRaisesRegex(ConductorError, "hash mismatch"):
                run_final_revision(root=root, task_path=task_path, source_run_id=run_id, candidate_sha256="a" * 64, defect_inventory_sha256="b" * 64, proposed_authorization_sha256="c" * 64, live=True, live_confirmed=True)
            invoke.assert_not_called()


if __name__ == "__main__":
    unittest.main()
