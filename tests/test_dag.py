from __future__ import annotations

import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from foundry_conductor.core import AgentCommand, ConductorError, fingerprint_repo
from foundry_conductor.dag import interact, run_dag, topological_order, validate_manifest


def command(repo: Path, *argv: str) -> None:
    subprocess.run(argv, cwd=repo, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class DagTests(unittest.TestCase):
    def repo(self, root: Path) -> Path:
        repo = root / "source"; repo.mkdir()
        command(repo, "git", "init", "-q", "-b", "main")
        (repo / "README.md").write_text("fixture\n")
        command(repo, "git", "add", "README.md")
        command(repo, "git", "-c", "user.name=Test", "-c", "user.email=test@localhost", "commit", "-qm", "fixture")
        return repo

    def manifest(self, repo: Path) -> dict:
        return {
            "schemaVersion": 1, "workflow": "generic_dag", "id": "test-dag",
            "sourceRepository": str(repo), "expectedBranch": "main", "expectedHead": fingerprint_repo(repo).head,
            "permissions": {"push": False, "nasAccess": False, "externalActions": False, "spending": False, "destructive": False, "productionExecution": False},
            "stages": [
                {"id": "backend-read", "type": "reconnaissance", "role": "general", "dependsOn": [], "prompt": "read", "timeoutSeconds": 30, "maxAttempts": 2},
                {"id": "contract-read", "type": "reconnaissance", "role": "contract", "dependsOn": ["backend-read"], "prompt": "read", "timeoutSeconds": 30, "maxAttempts": 1},
                {"id": "security-review", "type": "review", "role": "security", "dependsOn": ["backend-read", "contract-read"], "prompt": "review", "timeoutSeconds": 30, "maxAttempts": 1},
            ],
        }

    def test_default_roles_and_dag_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            value = validate_manifest(self.manifest(self.repo(Path(temporary))))
            self.assertEqual("claude", value["stages"][0]["provider"])
            self.assertEqual("cursor", value["stages"][1]["provider"])
            self.assertEqual("codex", value["stages"][2]["provider"])
            self.assertEqual(["backend-read", "contract-read", "security-review"], topological_order(value))

    def test_rejects_cycles_push_and_unlisted_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            value = self.manifest(self.repo(Path(temporary)))
            value["stages"][0]["dependsOn"] = ["security-review"]
            with self.assertRaisesRegex(ConductorError, "cycle"):
                validate_manifest(value)
            value = self.manifest(Path(temporary) / "source"); value["permissions"]["push"] = True
            with self.assertRaisesRegex(ConductorError, "does not execute pushes"):
                validate_manifest(value)
            value = self.manifest(Path(temporary) / "source")
            value["stages"] = [{"id": "tests", "type": "test", "dependsOn": [], "timeoutSeconds": 10, "maxAttempts": 1, "command": ["echo", "ok"], "allowedCommands": []}]
            with self.assertRaisesRegex(ConductorError, "not explicitly allowed"):
                validate_manifest(value)

    def test_plan_invokes_no_provider(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); repo = self.repo(root)
            path = root / "manifest.json"; path.write_text(json.dumps(self.manifest(repo)))
            with patch("foundry_conductor.dag._build_stage_command") as build:
                result = run_dag(root=root, manifest_path=path, live=False, live_confirmed=False)
            build.assert_not_called()
            self.assertEqual("planned", result["status"])
            self.assertTrue(result["sourceUnchanged"])

    def test_live_handoff_retry_and_resume_never_repeat_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); repo = self.repo(root)
            path = root / "manifest.json"; path.write_text(json.dumps(self.manifest(repo)))
            attempts = {"backend-read": 0, "contract-read": 0, "security-review": 0}
            def build(stage, snapshot, prompt, schema):
                return AgentCommand(stage["provider"], "fake", ["fake", stage["id"], prompt])
            def execute(argv, **kwargs):
                stage_id, prompt = argv[1], argv[2]
                attempts[stage_id] += 1
                digest = re.search(r"Combined input artifact SHA-256: ([0-9a-f]{64})", prompt).group(1)
                valid = not (stage_id == "backend-read" and attempts[stage_id] == 1)
                stdout = json.dumps({"status": "pass", "inputArtifactSha256": digest, "summary": "ok", "findings": [], "requiresHuman": False}).encode() if valid else b"invalid"
                return subprocess.CompletedProcess(argv, 0, stdout, b"")
            with patch("foundry_conductor.dag._build_stage_command", side_effect=build), patch("foundry_conductor.dag.run_command", side_effect=execute):
                first = run_dag(root=root, manifest_path=path, live=True, live_confirmed=True)
            self.assertEqual("complete", first["status"])
            self.assertEqual(2, attempts["backend-read"])
            self.assertEqual(1, attempts["contract-read"])
            self.assertEqual(1, attempts["security-review"])
            with patch("foundry_conductor.dag._build_stage_command") as build_again:
                second = run_dag(root=root, manifest_path=path, live=True, live_confirmed=True, resume_run_id=first["runId"])
            build_again.assert_not_called()
            self.assertEqual("complete", second["status"])

    def test_write_path_violation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); repo = self.repo(root)
            manifest = self.manifest(repo)
            manifest["stages"] = [{"id": "write", "type": "implementation", "role": "general", "dependsOn": [], "prompt": "write", "allowedPaths": ["allowed/**"], "timeoutSeconds": 30, "maxAttempts": 1}]
            path = root / "manifest.json"; path.write_text(json.dumps(manifest))
            def build(stage, snapshot, prompt, schema): return AgentCommand("claude", "fake", ["fake", prompt])
            def execute(argv, cwd, **kwargs):
                (cwd / "forbidden.txt").write_text("bad")
                digest = re.search(r"Combined input artifact SHA-256: ([0-9a-f]{64})", argv[1]).group(1)
                value = {"status": "pass", "inputArtifactSha256": digest, "summary": "ok", "findings": [], "requiresHuman": False}
                return subprocess.CompletedProcess(argv, 0, json.dumps(value).encode(), b"")
            with patch("foundry_conductor.dag._build_stage_command", side_effect=build), patch("foundry_conductor.dag.run_command", side_effect=execute):
                result = run_dag(root=root, manifest_path=path, live=True, live_confirmed=True)
            self.assertEqual("failed", result["status"])
            self.assertIn("outside allowedPaths", result["error"])

    def test_human_gate_waits_and_resumes_only_after_approval(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); repo = self.repo(root)
            manifest = self.manifest(repo)
            manifest["stages"] = [{"id": "release-gate", "type": "human_gate", "gate": "externalActions", "dependsOn": [], "timeoutSeconds": 30, "maxAttempts": 1}]
            path = root / "manifest.json"; path.write_text(json.dumps(manifest))
            waiting = run_dag(root=root, manifest_path=path, live=True, live_confirmed=True)
            self.assertEqual("waiting_for_approval", waiting["status"])
            approval = root / "runs" / waiting["runId"] / "approvals" / "release-gate.json"
            approval.parent.mkdir(parents=True)
            approval.write_text(json.dumps({"stageId": "release-gate", "decision": "approve", "message": "approved"}))
            resumed = run_dag(root=root, manifest_path=path, live=True, live_confirmed=True, resume_run_id=waiting["runId"])
            self.assertEqual("complete", resumed["status"])

    def test_status_message_refuse_and_evidence_are_append_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); repo = self.repo(root)
            path = root / "manifest.json"; path.write_text(json.dumps(self.manifest(repo)))
            planned = run_dag(root=root, manifest_path=path, live=False, live_confirmed=False)
            self.assertEqual("planned", interact(root=root, run_id=planned["runId"], action="status")["status"])
            message = interact(root=root, run_id=planned["runId"], action="message", message="operator context")
            self.assertRegex(message["sha256"], r"^[0-9a-f]{64}$")
            refused = interact(root=root, run_id=planned["runId"], action="refuse", stage_id="security-review", message="no")
            self.assertEqual("refuse", refused["decision"])
            evidence = interact(root=root, run_id=planned["runId"], action="evidence")
            self.assertTrue(any(name.startswith("messages/") for name in evidence["files"]))
            self.assertIn("approvals/security-review.json", evidence["files"])


if __name__ == "__main__": unittest.main()
