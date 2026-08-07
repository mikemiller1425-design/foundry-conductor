from __future__ import annotations

import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from foundry_conductor.core import AgentCommand, ConductorError, fingerprint_repo, run_command as real_run_command
from foundry_conductor.dag import _build_handoff, interact, run_dag, topological_order, validate_manifest, validate_stage_result


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
            value = self.manifest(Path(temporary) / "source")
            value["stages"] = [{"id": "nas", "type": "human_gate", "gate": "nasAccess", "dependsOn": [], "timeoutSeconds": 10, "maxAttempts": 1}]
            with self.assertRaisesRegex(ConductorError, "unauthorized permission nasAccess"):
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
                if argv[0] == "git":
                    return real_run_command(argv, **kwargs)
                stage_id, prompt = argv[1], argv[2]
                attempts[stage_id] += 1
                digest = re.search(r"Canonical handoff SHA-256: ([0-9a-f]{64})", prompt).group(1)
                valid = not (stage_id == "backend-read" and attempts[stage_id] == 1)
                stdout = json.dumps({"status": "pass", "handoffSha256": digest, "workStarted": True, "summary": "ok", "findings": [], "requiresHuman": False}).encode() if valid else b"invalid"
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
                if argv[0] == "git":
                    return real_run_command(argv, cwd=cwd, **kwargs)
                (cwd / "forbidden.txt").write_text("bad")
                digest = re.search(r"Canonical handoff SHA-256: ([0-9a-f]{64})", argv[1]).group(1)
                value = {"status": "pass", "handoffSha256": digest, "workStarted": True, "summary": "ok", "findings": [], "requiresHuman": False}
                return subprocess.CompletedProcess(argv, 0, json.dumps(value).encode(), b"")
            with patch("foundry_conductor.dag._build_stage_command", side_effect=build), patch("foundry_conductor.dag.run_command", side_effect=execute):
                result = run_dag(root=root, manifest_path=path, live=True, live_confirmed=True)
            self.assertEqual("failed", result["status"])
            self.assertIn("outside allowedPaths", result["error"])

    def test_fake_handoff_acknowledgements_are_rejected(self) -> None:
        base = {"status": "pass", "handoffSha256": "a" * 64, "workStarted": True, "summary": "ok", "findings": [], "requiresHuman": False}
        self.assertEqual(base, validate_stage_result(base))
        fake = dict(base); fake["workStarted"] = False
        with self.assertRaisesRegex(ConductorError, "work started"):
            validate_stage_result(fake)

    def test_wrong_handoff_digest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); repo = self.repo(root)
            manifest = self.manifest(repo); manifest["stages"] = manifest["stages"][:1]
            manifest["stages"][0]["maxAttempts"] = 1
            path = root / "manifest.json"; path.write_text(json.dumps(manifest))
            def build(stage, snapshot, prompt, schema): return AgentCommand("claude", "fake", ["fake"])
            value = {"status": "pass", "handoffSha256": "0" * 64, "workStarted": True, "summary": "fake", "findings": [], "requiresHuman": False}
            def execute(argv, **kwargs):
                if argv[0] == "git": return real_run_command(argv, **kwargs)
                return subprocess.CompletedProcess(argv, 0, json.dumps(value).encode(), b"")
            with patch("foundry_conductor.dag._build_stage_command", side_effect=build), patch("foundry_conductor.dag.run_command", side_effect=execute):
                result = run_dag(root=root, manifest_path=path, live=True, live_confirmed=True)
            self.assertEqual("failed", result["status"])
            self.assertIn("wrong handoff digest", result["error"])

    def test_missing_dependency_artifact_fails_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); repo = self.repo(root)
            snapshot = root / "snapshot"
            real_run_command(["git", "clone", "-q", str(repo), str(snapshot)], cwd=root)
            workspace = root / "workspace"
            real_run_command(["git", "clone", "-q", str(repo), str(workspace)], cwd=root)
            with (workspace / ".git" / "info" / "exclude").open("a") as handle:
                handle.write("\n.conductor/\n")
            stage = {"id": "consumer", "dependsOn": ["producer"]}
            accepted = {"producer": {"stageId": "producer", "artifactSha256": "a" * 64, "artifactFiles": ["missing.json"]}}
            with self.assertRaisesRegex(ConductorError, "artifact is missing"):
                _build_handoff(run_dir=root, workspace=workspace, stage=stage, accepted=accepted, instructions="inspect")

    def test_handoff_contains_canonical_context_and_dependency_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); repo = self.repo(root)
            workspace = root / "workspace"
            real_run_command(["git", "clone", "-q", str(repo), str(workspace)], cwd=root)
            with (workspace / ".git" / "info" / "exclude").open("a") as handle:
                handle.write("\n.conductor/\n")
            artifact = root / "stages" / "producer" / "result.normalized.json"
            artifact.parent.mkdir(parents=True); artifact.write_text('{"summary":"readable"}\n')
            accepted = {"producer": {"stageId": "producer", "artifactSha256": "a" * 64, "artifactFiles": [str(artifact.relative_to(root))]}}
            stage = {"id": "consumer", "dependsOn": ["producer"], "contextPaths": ["README.md"]}
            handoff, digest, manifest = _build_handoff(run_dir=root, workspace=workspace, stage=stage, accepted=accepted, instructions="inspect")
            self.assertEqual("fixture\n", (handoff / "context" / "README.md").read_text())
            self.assertIn("readable", (handoff / "dependencies" / "producer" / "artifacts" / artifact.name).read_text())
            self.assertEqual(digest, json.loads((handoff / "manifest.json").read_text())["handoffSha256"])
            self.assertTrue(any(item["path"] == "context/README.md" for item in manifest["files"]))

    def test_controlled_write_cannot_pass_without_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); repo = self.repo(root)
            manifest = self.manifest(repo)
            manifest["stages"] = [{"id": "write", "type": "implementation", "role": "general", "dependsOn": [], "prompt": "write", "allowedPaths": ["README.md"], "timeoutSeconds": 30, "maxAttempts": 1}]
            path = root / "manifest.json"; path.write_text(json.dumps(manifest))
            def build(stage, snapshot, prompt, schema): return AgentCommand("claude", "fake", ["fake", prompt])
            def execute(argv, **kwargs):
                if argv[0] == "git": return real_run_command(argv, **kwargs)
                digest = re.search(r"Canonical handoff SHA-256: ([0-9a-f]{64})", argv[1]).group(1)
                value = {"status": "pass", "handoffSha256": digest, "workStarted": True, "summary": "claimed", "findings": [], "requiresHuman": False}
                return subprocess.CompletedProcess(argv, 0, json.dumps(value).encode(), b"")
            with patch("foundry_conductor.dag._build_stage_command", side_effect=build), patch("foundry_conductor.dag.run_command", side_effect=execute):
                result = run_dag(root=root, manifest_path=path, live=True, live_confirmed=True)
            self.assertEqual("failed", result["status"])
            self.assertIn("produced no changed artifact", result["error"])

    def test_review_findings_route_to_repair_and_rereview(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); repo = self.repo(root)
            manifest = self.manifest(repo)
            manifest["stages"] = [
                {"id": "producer", "type": "reconnaissance", "role": "general", "dependsOn": [], "prompt": "produce", "timeoutSeconds": 30, "maxAttempts": 1},
                {"id": "review", "type": "review", "role": "governance", "dependsOn": ["producer"], "prompt": "review", "timeoutSeconds": 30, "maxAttempts": 1,
                 "repairPolicy": {"role": "general", "prompt": "repair finding", "allowedPaths": ["README.md"], "maxRounds": 2}},
            ]
            path = root / "manifest.json"; path.write_text(json.dumps(manifest))
            review_calls = 0
            def build(stage, snapshot, prompt, schema): return AgentCommand(stage["provider"], "fake", ["fake", stage["id"], prompt])
            def execute(argv, cwd, **kwargs):
                nonlocal review_calls
                if argv[0] == "git": return real_run_command(argv, cwd=cwd, **kwargs)
                stage_id, prompt = argv[1], argv[2]
                digest = re.search(r"Canonical handoff SHA-256: ([0-9a-f]{64})", prompt).group(1)
                status, findings = "pass", []
                if stage_id == "review-repair":
                    (cwd / "README.md").write_text("fixture\nrepaired\n")
                if stage_id == "review":
                    review_calls += 1
                    if review_calls == 1:
                        status, findings = "fail", [{"severity": "error", "message": "actionable correction"}]
                    else:
                        self.assertIn("repaired", (cwd / "README.md").read_text())
                value = {"status": status, "handoffSha256": digest, "workStarted": True, "summary": "reviewed", "findings": findings, "requiresHuman": False}
                return subprocess.CompletedProcess(argv, 0, json.dumps(value).encode(), b"")
            with patch("foundry_conductor.dag._build_stage_command", side_effect=build), patch("foundry_conductor.dag.run_command", side_effect=execute):
                result = run_dag(root=root, manifest_path=path, live=True, live_confirmed=True)
            self.assertEqual("complete", result["status"])
            self.assertEqual(2, review_calls)
            events = (Path(result["runDirectory"]) / "events.jsonl").read_text()
            self.assertIn('"event":"review_findings_routed"', events)
            self.assertIn('"responsibleProvider":"claude"', events)

    def test_repair_round_exhaustion_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); repo = self.repo(root)
            manifest = self.manifest(repo)
            manifest["stages"] = [{"id": "review", "type": "review", "role": "governance", "dependsOn": [], "prompt": "review", "timeoutSeconds": 30, "maxAttempts": 1,
                "repairPolicy": {"role": "general", "prompt": "repair", "readOnly": True, "maxRounds": 1}}]
            path = root / "manifest.json"; path.write_text(json.dumps(manifest))
            def build(stage, snapshot, prompt, schema): return AgentCommand(stage["provider"], "fake", ["fake", stage["id"], prompt])
            def execute(argv, **kwargs):
                if argv[0] == "git": return real_run_command(argv, **kwargs)
                digest = re.search(r"Canonical handoff SHA-256: ([0-9a-f]{64})", argv[2]).group(1)
                is_review = argv[1] == "review"
                value = {"status": "fail" if is_review else "pass", "handoffSha256": digest, "workStarted": True, "summary": "done", "findings": [{"severity": "error", "message": "still wrong"}] if is_review else [], "requiresHuman": False}
                return subprocess.CompletedProcess(argv, 0, json.dumps(value).encode(), b"")
            with patch("foundry_conductor.dag._build_stage_command", side_effect=build), patch("foundry_conductor.dag.run_command", side_effect=execute):
                result = run_dag(root=root, manifest_path=path, live=True, live_confirmed=True)
            self.assertEqual("failed", result["status"])
            self.assertIn("exhausted its bounded repair rounds", result["error"])

    def test_human_gate_waits_and_resumes_only_after_approval(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); repo = self.repo(root)
            manifest = self.manifest(repo)
            manifest["permissions"]["externalActions"] = True
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
