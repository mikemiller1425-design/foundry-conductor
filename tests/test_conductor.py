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
    parse_agent_result,
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

    def test_claude_schema_omits_unsupported_draft_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = root / "snapshot"
            snapshot.mkdir()
            schema = root / "schema.json"
            schema.write_text(
                json.dumps({"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"}),
                encoding="utf-8",
            )
            built = build_agent_command(
                "claude",
                snapshot=snapshot,
                prompt="probe",
                response_schema=schema,
            )
            schema_argument = built.argv[built.argv.index("--json-schema") + 1]
            self.assertNotIn("$schema", json.loads(schema_argument))
            self.assertEqual("5", built.argv[built.argv.index("--max-turns") + 1])

    def test_parses_cursor_result_wrapped_in_fenced_json(self) -> None:
        response = {
            "type": "result",
            "result": """```json
{"status":"pass","summary":"Readable.","findings":[],"requiresHuman":false}
```""",
        }
        parsed = parse_agent_result(json.dumps(response).encode())
        self.assertEqual("pass", parsed["status"])

    def test_parses_cursor_result_with_prose_prefix(self) -> None:
        response = {
            "type": "result",
            "result": (
                "Inspection complete. "
                '{"status":"pass","summary":"Readable.","findings":[],"requiresHuman":false}'
            ),
        }
        parsed = parse_agent_result(json.dumps(response).encode())
        self.assertEqual("pass", parsed["status"])

    def test_parses_codex_jsonl_agent_message(self) -> None:
        response = (
            '{"type":"thread.started","thread_id":"test"}\n'
            '{"type":"item.completed","item":{"type":"agent_message","text":"'
            '{\\"status\\":\\"pass\\",\\"summary\\":\\"Readable.\\",'
            '\\"findings\\":[],\\"requiresHuman\\":false}"}}\n'
        )
        parsed = parse_agent_result(response.encode())
        self.assertEqual("pass", parsed["status"])


if __name__ == "__main__":
    unittest.main()
