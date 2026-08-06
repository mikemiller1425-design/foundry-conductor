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
    _invoke,
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
            "reviewerMaxTurns": 5,
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
            self.assertIn("requiresHuman", prompt)

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

    def test_seeded_draft_skips_duplicate_author_call(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = self.make_repo(root)
            task = self.make_task(repo)
            task_path = self.write_task(root, task)
            seed_id = "20260101T000000Z-test-reconciliation-abcdef12"
            seed_dir = root / "runs" / seed_id
            (seed_dir / "round-01").mkdir(parents=True)
            (seed_dir / "task.json").write_text(json.dumps(task), encoding="utf-8")
            (seed_dir / "summary.json").write_text(
                json.dumps({"sourceUnchanged": True, "snapshotClean": True}),
                encoding="utf-8",
            )
            seeded_draft = "preserved draft"
            (seed_dir / "round-01" / "author-claude.normalized.json").write_text(
                json.dumps(
                    {
                        "status": "drafted",
                        "draft": seeded_draft,
                        "notes": ["review carefully"],
                        "requiresHuman": True,
                    }
                ),
                encoding="utf-8",
            )
            passing = {
                "verdict": "pass",
                "draftSha256": digest(seeded_draft),
                "summary": "pass",
                "findings": [],
                "requiresHuman": False,
            }
            with patch("foundry_conductor.reconcile._invoke", side_effect=[passing, passing]) as invoked:
                result = run_reconciliation(
                    root=root,
                    task_path=task_path,
                    live=True,
                    live_confirmed=True,
                    seed_run_id=seed_id,
                )
            self.assertEqual("ready_for_operator_decision", result["status"])
            self.assertEqual(2, invoked.call_count)
            self.assertEqual(seed_id, result["seedRunId"])

    def test_reviewed_round_resume_skips_completed_author_and_reviews(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = self.make_repo(root)
            task = self.make_task(repo)
            task_path = self.write_task(root, task)
            reviewed_id = "20260101T000000Z-test-reconciliation-abcdef12"
            reviewed_dir = root / "runs" / reviewed_id
            round_dir = reviewed_dir / "round-01"
            round_dir.mkdir(parents=True)
            (reviewed_dir / "task.json").write_text(json.dumps(task), encoding="utf-8")
            draft_one = "reviewed draft\n"
            draft_one_hash = digest(draft_one)
            round_record = {
                "round": 1,
                "draftSha256": draft_one_hash,
                "authorRequiresHuman": False,
                "reviewers": {
                    "codex": {"verdict": "revise", "requiresHuman": False, "findingCount": 1},
                    "cursor": {"verdict": "pass", "requiresHuman": False, "findingCount": 0},
                },
            }
            (reviewed_dir / "summary.json").write_text(
                json.dumps(
                    {
                        "sourceUnchanged": True,
                        "snapshotClean": True,
                        "rounds": [round_record],
                    }
                ),
                encoding="utf-8",
            )
            (round_dir / "candidate.md").write_text(draft_one, encoding="utf-8")
            revise = {
                "verdict": "revise",
                "draftSha256": draft_one_hash,
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
            passing_one = {
                "verdict": "pass",
                "draftSha256": draft_one_hash,
                "summary": "pass",
                "findings": [],
                "requiresHuman": False,
            }
            for reviewer, review in {"codex": revise, "cursor": passing_one}.items():
                (round_dir / f"review-{reviewer}.normalized.json").write_text(
                    json.dumps(review), encoding="utf-8"
                )
            draft_two = "revised draft"
            passing_two = {
                "verdict": "pass",
                "draftSha256": digest(draft_two),
                "summary": "pass",
                "findings": [],
                "requiresHuman": False,
            }
            responses = [
                {"status": "drafted", "draft": draft_two, "notes": [], "requiresHuman": False},
                passing_two,
                passing_two,
            ]
            with patch("foundry_conductor.reconcile._invoke", side_effect=responses) as invoked:
                result = run_reconciliation(
                    root=root,
                    task_path=task_path,
                    live=True,
                    live_confirmed=True,
                    reviewed_run_id=reviewed_id,
                )
            self.assertEqual("ready_for_operator_decision", result["status"])
            self.assertEqual(3, invoked.call_count)
            self.assertEqual(reviewed_id, result["reviewedRunId"])
            self.assertEqual([1, 2], [entry["round"] for entry in result["rounds"]])

    def test_partial_resume_invokes_only_missing_review(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = self.make_repo(root)
            task = self.make_task(repo)
            task_path = self.write_task(root, task)
            partial_id = "20260101T000000Z-test-reconciliation-abcdef12"
            partial_dir = root / "runs" / partial_id
            round_dir = partial_dir / "round-01"
            round_dir.mkdir(parents=True)
            (partial_dir / "task.json").write_text(json.dumps(task), encoding="utf-8")
            (partial_dir / "summary.json").write_text(
                json.dumps({"sourceUnchanged": True, "snapshotClean": True, "rounds": []}),
                encoding="utf-8",
            )
            draft = "partially reviewed draft"
            draft_hash = digest(draft)
            author = {"status": "drafted", "draft": draft, "notes": [], "requiresHuman": False}
            passing = {
                "verdict": "pass",
                "draftSha256": draft_hash,
                "summary": "pass",
                "findings": [],
                "requiresHuman": False,
            }
            (round_dir / "author-claude.normalized.json").write_text(
                json.dumps(author), encoding="utf-8"
            )
            (round_dir / "candidate.md").write_text(draft.strip() + "\n", encoding="utf-8")
            (round_dir / "review-codex.normalized.json").write_text(
                json.dumps(passing), encoding="utf-8"
            )
            with patch("foundry_conductor.reconcile._invoke", return_value=passing) as invoked:
                result = run_reconciliation(
                    root=root,
                    task_path=task_path,
                    live=True,
                    live_confirmed=True,
                    partial_run_id=partial_id,
                )
            self.assertEqual("ready_for_operator_decision", result["status"])
            self.assertEqual(1, invoked.call_count)
            self.assertEqual("cursor", invoked.call_args.kwargs["agent"])
            self.assertEqual(partial_id, result["partialRunId"])

    def test_partial_imported_review_is_not_reused_on_next_draft(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = self.make_repo(root)
            task = self.make_task(repo)
            task_path = self.write_task(root, task)
            partial_id = "20260101T000000Z-test-reconciliation-abcdef12"
            partial_dir = root / "runs" / partial_id
            round_dir = partial_dir / "round-01"
            round_dir.mkdir(parents=True)
            (partial_dir / "task.json").write_text(json.dumps(task), encoding="utf-8")
            (partial_dir / "summary.json").write_text(
                json.dumps({"sourceUnchanged": True, "snapshotClean": True, "rounds": []}),
                encoding="utf-8",
            )
            draft_one = "first draft"
            hash_one = digest(draft_one)
            (round_dir / "author-claude.normalized.json").write_text(
                json.dumps(
                    {"status": "drafted", "draft": draft_one, "notes": [], "requiresHuman": False}
                ),
                encoding="utf-8",
            )
            (round_dir / "candidate.md").write_text(draft_one + "\n", encoding="utf-8")
            pass_one = {
                "verdict": "pass",
                "draftSha256": hash_one,
                "summary": "pass",
                "findings": [],
                "requiresHuman": False,
            }
            (round_dir / "review-codex.normalized.json").write_text(
                json.dumps(pass_one), encoding="utf-8"
            )
            revise_one = {
                "verdict": "revise",
                "draftSha256": hash_one,
                "summary": "revise",
                "findings": [
                    {
                        "severity": "error",
                        "category": "contract",
                        "message": "missing field",
                        "requiredChange": "add it",
                    }
                ],
                "requiresHuman": False,
            }
            draft_two = "second draft"
            pass_two = {
                "verdict": "pass",
                "draftSha256": digest(draft_two),
                "summary": "pass",
                "findings": [],
                "requiresHuman": False,
            }
            responses = [
                revise_one,
                {"status": "drafted", "draft": draft_two, "notes": [], "requiresHuman": False},
                pass_two,
                pass_two,
            ]
            with patch("foundry_conductor.reconcile._invoke", side_effect=responses) as invoked:
                result = run_reconciliation(
                    root=root,
                    task_path=task_path,
                    live=True,
                    live_confirmed=True,
                    partial_run_id=partial_id,
                )
            self.assertEqual("ready_for_operator_decision", result["status"])
            self.assertEqual(["cursor", "claude", "codex", "cursor"], [
                call.kwargs["agent"] for call in invoked.call_args_list
            ])

    def test_cursor_invocation_records_and_sends_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = self.make_repo(root)
            schema = root / "review-schema.json"
            schema.write_text(json.dumps({"type": "object", "required": ["verdict"]}), encoding="utf-8")
            prefix = root / "evidence" / "review-cursor"
            completed = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps(
                    {
                        "verdict": "pass",
                        "draftSha256": "a" * 64,
                        "summary": "pass",
                        "findings": [],
                        "requiresHuman": False,
                    }
                ).encode(),
                stderr=b"",
            )
            from foundry_conductor.core import AppendOnlyLog

            log = AppendOnlyLog(root / "events.jsonl")
            with patch("foundry_conductor.reconcile.resolve_binary", return_value="cursor-agent"), patch(
                "foundry_conductor.reconcile.run_command", return_value=completed
            ):
                _invoke(
                    agent="cursor",
                    snapshot=snapshot,
                    prompt="review this",
                    schema_path=schema,
                    validator=validate_review_response,
                    prefix=prefix,
                    timeout_seconds=30,
                    max_turns=5,
                    log=log,
                )
            recorded = prefix.with_suffix(".prompt.txt").read_text(encoding="utf-8")
            self.assertIn("required-json-schema", recorded)
            self.assertIn('"verdict"', recorded)


if __name__ == "__main__":
    unittest.main()
