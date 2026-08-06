from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from foundry_conductor.core import (
    ConductorError,
    build_agent_command,
    create_tracked_snapshot,
    fingerprint_repo,
    snapshot_is_clean,
    validate_task,
)


def command(repo: Path, *argv: str) -> None:
    subprocess.run(argv, cwd=repo, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class ConductorTests(unittest.TestCase):
    def make_repo(self, root: Path) -> Path:
        repo = root / "source"
        repo.mkdir()
        command(repo, "git", "init", "-q", "-b", "main")
        (repo / "tracked.txt").write_text("tracked\n", encoding="utf-8")
        command(repo, "git", "add", "tracked.txt")
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

    def task(self, repo: Path) -> dict:
        return {
            "schemaVersion": 1,
            "id": "test-readonly",
            "mode": "read_only",
            "sourceRepository": str(repo),
            "expectedBranch": "main",
            "expectedHead": fingerprint_repo(repo).head,
            "permissions": {
                "repositoryWrite": False,
                "nasAccess": False,
                "push": False,
                "liveModelCalls": False,
            },
            "agents": ["codex"],
            "timeoutSeconds": 30,
            "prompt": "Inspect read-only.",
        }

    def test_read_only_policy_rejects_repository_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self.make_repo(Path(temporary))
            task = self.task(repo)
            task["permissions"]["repositoryWrite"] = True
            with self.assertRaisesRegex(ConductorError, "repositoryWrite=false"):
                validate_task(task)

    def test_snapshot_excludes_untracked_and_preserves_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = self.make_repo(root)
            (repo / "untracked.txt").write_text("private\n", encoding="utf-8")
            before = fingerprint_repo(repo)
            snapshot = root / "snapshot"
            create_tracked_snapshot(repo, snapshot)
            self.assertTrue((snapshot / "tracked.txt").exists())
            self.assertFalse((snapshot / "untracked.txt").exists())
            self.assertTrue(snapshot_is_clean(snapshot))
            self.assertEqual(before, fingerprint_repo(repo))

    def test_commands_target_snapshot_not_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = root / "snapshot"
            snapshot.mkdir()
            schema = root / "schema.json"
            schema.write_text(json.dumps({"type": "object"}), encoding="utf-8")
            built = build_agent_command(
                "codex",
                snapshot=snapshot,
                prompt="probe",
                response_schema=schema,
            )
            self.assertIn(str(snapshot), built.argv)
            self.assertIn("read-only", built.argv)

    def test_cursor_command_uses_plan_mode_and_snapshot_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = root / "snapshot"
            snapshot.mkdir()
            schema = root / "schema.json"
            schema.write_text(json.dumps({"type": "object"}), encoding="utf-8")
            built = build_agent_command(
                "cursor",
                snapshot=snapshot,
                prompt="probe",
                response_schema=schema,
            )
            self.assertIn("plan", built.argv)
            self.assertIn("enabled", built.argv)
            self.assertIn(str(snapshot), built.argv)


if __name__ == "__main__":
    unittest.main()
