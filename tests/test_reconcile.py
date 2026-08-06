from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from foundry_conductor.core import ConductorError, fingerprint_repo
from foundry_conductor.reconcile import (
    author_prompt,
    run_reconciliation,
    validate_reconciliation_task,
    validate_review_response,
)


def command(repo: Path, *argv: str) -> None:
    subprocess.run(argv, cwd=repo, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def digest(draft: str) -> str:
    return hashlib.sha256((draft.strip() + "\n").encode()).hexdigest()


class ReconciliationTests(unittest.TestCase):
    def make_repo(self, root: Path) -> Path:
        repo = root / "source"
        repo.mkdir()
        command(repo, "git", "init", "-q", "-b", "main")
        (repo / "governance.md").write_text("authoritative\n", encoding="utf-8")
        command(repo, "git", "add", "governance.md")
        command(
            repo,
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@localhost",
            "commit",
            "-qm",
            "fixture",
        )
        return repo

    def make_task(self, repo: Path) -> dict:
        return {
            "schemaVersion": 1,
            "workflow": "bounded_reconciliation",
            "id": "test-reconciliation",
            "sourceRepository": str(repo),
            "expectedBranch": "main",
            "expectedHead": fingerprint_repo(repo).head,
            "permissions": {
                "repositoryWrite": False,
                "nasAccess": False,
                "push": False,
                "liveModelCalls": True,
            },
            "author": "claude",
            "reviewers": ["codex", "cursor"],
            "maxRounds": 3,
            "authorMaxTurns": 5,
            "timeoutSeconds": 30,
            "objective": "Draft only.",
            "authoritativeSources": ["governance.md"],
            "reviewerFocus": {"codex": "governance", "cursor": "contract"},
        }

    def write_task(self, root: Path, task: dict) -> Path:
        path = root / "task.json"
        path.write_text(json.dumps(task), encoding="utf-8")
        return path

    def test_rejects_more_than_three_rounds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self.make_repo(Path(temporary))
            task = self.make_task(repo)
            task["maxRounds"] = 4
            with self.assertRaisesRegex(ConductorError, "maxRounds"):
                validate_reconciliation_task(task)

    def test_rejects_write_permission(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self.make_repo(Path(temporary))
            task = self.make_task(repo)
            task["permissions"]["repositoryWrite"] = True
            with self.assertRaisesRegex(ConductorError, "repositoryWrite=false"):
                validate_reconciliation_task(task)

    def test_pass_review_requires_zero_findings(self) -> None:
        value = {
            "verdict": "pass",
            "draftSha256": "a" * 64,
            "summary": "pass",
            "findings": [
                {
                    "severity": "warning",
                    "category": "scope",
                    "message": "problem",
                    "requiredChange": "fix it",
                }
            ],
            "requiresHuman": False,
        }
        with self.assertRaisesRegex(ConductorError, "zero findings"):
            validate_review_response(value)

    def test_revision_prompt_contains_prior_draft_and_feedback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self.make_repo(Path(temporary))
            task = self.make_task(repo)
            prompt = author_prompt(
                task,
                round_number=2,
                prior_draft="old draft",
                feedback=[{"reviewer": "codex", "requiredChange": "tighten scope"}],
            )
            self.assertIn("old draft", prompt)
            self.assertIn("tighten scope", prompt)

    def test_two_round_reconciliation_requires_matching_pass_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = self.make_repo(root)
            task_path = self.write_task(root, self.make_task(repo))
            draft_one = "draft one"
            draft_two = "draft two"
            revise = {
                "verdict": "revise",
                "draftSha256": digest(draft_one),
                "summary": "revise",
                "findings": [
                    {
                        "severity": "error",
                        "category": "scope",
                        "message": "too broad",
                        "requiredChange": "narrow it",
                    }
                ],
                "requiresHuman": False,
            }
            pass_one = {
                "verdict": "pass",
                "draftSha256": digest(draft_one),
                "summary": "pass",
                "findings": [],
                "requiresHuman": False,
            }
            pass_two = {
                "verdict": "pass",
                "draftSha256": digest(draft_two),
                "summary": "pass",
                "findings": [],
                "requiresHuman": False,
            }
            responses = [
                {"status": "drafted", "draft": draft_one, "notes": [], "requiresHuman": False},
                revise,
                pass_one,
                {"status": "drafted", "draft": draft_two, "notes": [], "requiresHuman": False},
                pass_two,
                pass_two,
            ]
            with patch("foundry_conductor.reconcile._invoke", side_effect=responses):
                result = run_reconciliation(
                    root=root,
                    task_path=task_path,
                    live=True,
                    live_confirmed=True,
                )
            self.assertEqual("ready_for_operator_decision", result["status"])
            self.assertEqual(2, result["round"])
            self.assertEqual(digest(draft_two), result["draftSha256"])
            self.assertEqual(2, len(result["rounds"]))

    def test_wrong_review_hash_stops_failed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = self.make_repo(root)
            task_path = self.write_task(root, self.make_task(repo))
            responses = [
                {"status": "drafted", "draft": "draft", "notes": [], "requiresHuman": False},
                {
                    "verdict": "pass",
                    "draftSha256": "0" * 64,
                    "summary": "pass",
                    "findings": [],
                    "requiresHuman": False,
                },
            ]
            with patch("foundry_conductor.reconcile._invoke", side_effect=responses):
                result = run_reconciliation(
                    root=root,
                    task_path=task_path,
                    live=True,
                    live_confirmed=True,
                )
            self.assertEqual("failed", result["status"])
            self.assertIn("wrong draft", result["error"])


if __name__ == "__main__":
    unittest.main()
