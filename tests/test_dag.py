from __future__ import annotations

import json
import hashlib
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from foundry_conductor.core import AgentCommand, ConductorError, fingerprint_repo, run_command as real_run_command
from foundry_conductor.dag import _build_handoff, _create_workspace, _materialize_workspace_seed, _workspace_patch, interact, run_dag, topological_order, validate_manifest, validate_stage_result


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
            value = self.manifest(Path(temporary) / "source"); value["stages"][0]["maxTurns"] = 51
            with self.assertRaisesRegex(ConductorError, "maxTurns is invalid"):
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

    def test_partial_resume_imports_readable_artifacts_without_reinvoking_completed_providers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); repo = self.repo(root)
            path = root / "manifest.json"; path.write_text(json.dumps(self.manifest(repo)))
            calls = {"backend-read": 0, "contract-read": 0, "security-review": 0}
            allow_review = False
            def build(stage, snapshot, prompt, schema): return AgentCommand(stage["provider"], "fake", ["fake", stage["id"], prompt])
            def execute(argv, **kwargs):
                if argv[0] == "git": return real_run_command(argv, **kwargs)
                stage_id, prompt = argv[1], argv[2]; calls[stage_id] += 1
                digest = re.search(r"Canonical handoff SHA-256: ([0-9a-f]{64})", prompt).group(1)
                if stage_id == "security-review" and not allow_review:
                    return subprocess.CompletedProcess(argv, 0, b"invalid", b"")
                value = {"status": "pass", "handoffSha256": digest, "workStarted": True, "summary": stage_id, "findings": [], "requiresHuman": False}
                return subprocess.CompletedProcess(argv, 0, json.dumps(value).encode(), b"")
            with patch("foundry_conductor.dag._build_stage_command", side_effect=build), patch("foundry_conductor.dag.run_command", side_effect=execute):
                first = run_dag(root=root, manifest_path=path, live=True, live_confirmed=True)
                self.assertEqual("failed", first["status"])
                allow_review = True
                second = run_dag(root=root, manifest_path=path, live=True, live_confirmed=True, resume_run_id=first["runId"])
            self.assertEqual("complete", second["status"])
            self.assertEqual(1, calls["backend-read"]); self.assertEqual(1, calls["contract-read"])
            self.assertEqual(2, calls["security-review"])
            imported = Path(second["runDirectory"]) / "stages" / "backend-read" / "attempt-01.normalized.json"
            self.assertTrue(imported.is_file()); self.assertEqual("backend-read", json.loads(imported.read_text())["summary"])

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

    def test_static_attachments_reject_traversal_and_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            conductor = Path(temporary) / "conductor"; run_dir = conductor / "runs" / "run"; run_dir.mkdir(parents=True)
            repo = self.repo(Path(temporary)); workspace = Path(temporary) / "workspace"
            real_run_command(["git", "clone", "-q", str(repo), str(workspace)], cwd=Path(temporary))
            manifest = self.manifest(repo)
            manifest["stages"][0]["attachments"] = [{"path": "../secret", "sha256": "a" * 64, "name": "brief.md"}]
            with self.assertRaisesRegex(ConductorError, "attachment path is invalid"):
                validate_manifest(manifest)
            evidence = conductor / "runs" / "evidence.md"; evidence.write_text("brief\n")
            stage = {"id": "consumer", "dependsOn": [], "attachments": [{"path": "runs/evidence.md", "sha256": "0" * 64, "name": "brief.md"}]}
            with self.assertRaisesRegex(ConductorError, "attachment hash mismatch"):
                _build_handoff(run_dir=run_dir, workspace=workspace, stage=stage, accepted={}, instructions="inspect")
            good_run = conductor / "runs" / "good"; good_run.mkdir()
            stage["attachments"][0]["sha256"] = hashlib.sha256(evidence.read_bytes()).hexdigest()
            handoff, digest, manifest_value = _build_handoff(run_dir=good_run, workspace=workspace, stage=stage, accepted={}, instructions="inspect")
            self.assertEqual("brief\n", (handoff / "attachments" / "brief.md").read_text())
            self.assertEqual(digest, json.loads((handoff / "manifest.json").read_text())["handoffSha256"])
            self.assertTrue(any(item["path"] == "attachments/brief.md" for item in manifest_value["files"]))

    def test_gate_ignores_ignored_artifacts_but_rejects_tracked_diff_expansion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); repo = self.repo(root)
            (repo / ".gitignore").write_text(".gate-cache/\n"); (repo / "pnpm-lock.yaml").write_text("lock\n")
            command(repo, "git", "add", ".gitignore", "pnpm-lock.yaml")
            command(repo, "git", "-c", "user.name=Test", "-c", "user.email=test@localhost", "commit", "-qm", "gate fixture")
            manifest = self.manifest(repo)
            manifest["stages"] = [{"id": "gate", "type": "test", "dependsOn": [], "command": ["fake-gate"], "allowedCommands": [["fake-gate"]], "preservePaths": ["pnpm-lock.yaml"], "timeoutSeconds": 30, "maxAttempts": 1}]
            path = root / "manifest.json"; path.write_text(json.dumps(manifest))
            mutate_tracked = False
            def execute(argv, cwd, **kwargs):
                if argv[0] == "git": return real_run_command(argv, cwd=cwd, **kwargs)
                (cwd / ".gate-cache").mkdir(); (cwd / ".gate-cache" / "result").write_text("ignored")
                if mutate_tracked: (cwd / "README.md").write_text("expanded\n")
                return subprocess.CompletedProcess(argv, 0, b"1 passed, 0 failed, 0 skipped\n", b"")
            with patch("foundry_conductor.dag.run_command", side_effect=execute):
                clean = run_dag(root=root, manifest_path=path, live=True, live_confirmed=True)
                self.assertEqual("complete", clean["status"])
                mutate_tracked = True
                expanded = run_dag(root=root, manifest_path=path, live=True, live_confirmed=True)
            self.assertEqual("failed", expanded["status"])
            self.assertIn("expanded the diff", expanded["error"])

    def test_failed_workspace_seed_is_hash_bound_and_allowlisted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); repo = self.repo(root)
            source_run_id = "20260807T000000Z-failed-seed-deadbeef"
            source_run = root / "runs" / source_run_id
            workspace = source_run / "workspaces" / "author-stage" / "initial"
            workspace.parent.mkdir(parents=True)
            real_run_command(["git", "clone", "-q", str(repo), str(workspace)], cwd=root)
            (workspace / "README.md").write_text("provisional model work\n")
            (source_run / "summary.json").write_text(json.dumps({"status": "failed", "sourceUnchanged": True}))
            preview = root / "preview"
            changed, patch_bytes = _materialize_workspace_seed(repo, workspace, preview)
            self.assertEqual(["README.md"], changed)
            manifest = self.manifest(repo)
            manifest["stages"] = [{
                "id": "seed", "type": "workspace_seed", "dependsOn": [], "timeoutSeconds": 30, "maxAttempts": 1,
                "sourceRunId": source_run_id, "sourceStageId": "author-stage",
                "expectedPatchSha256": hashlib.sha256(patch_bytes).hexdigest(), "allowedPaths": ["README.md"],
            }]
            path = root / "manifest.json"; path.write_text(json.dumps(manifest))
            result = run_dag(root=root, manifest_path=path, live=True, live_confirmed=True)
            self.assertEqual("complete", result["status"])
            seed_patch = Path(result["runDirectory"]) / "stages" / "seed" / "diff.patch"
            self.assertEqual(patch_bytes, seed_patch.read_bytes())
            manifest["stages"][0]["expectedPatchSha256"] = "0" * 64
            path.write_text(json.dumps(manifest))
            mismatch = run_dag(root=root, manifest_path=path, live=True, live_confirmed=True)
            self.assertEqual("failed", mismatch["status"])
            self.assertIn("patch hash mismatch", mismatch["error"])

    def test_workspace_patch_includes_new_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); repo = self.repo(root)
            (repo / "new.txt").write_text("new model artifact\n")
            changed, patch_bytes = _workspace_patch(repo)
            self.assertIn("new.txt", changed)
            self.assertIn(b"new model artifact", patch_bytes)

    def test_workspace_copy_is_isolated_from_disposable_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); repo = self.repo(root); workspace = root / "workspace"
            _create_workspace(repo, workspace)
            (workspace / "README.md").write_text("workspace only\n")
            self.assertEqual("fixture\n", (repo / "README.md").read_text())
            self.assertEqual("workspace only\n", (workspace / "README.md").read_text())

    def test_canonical_dependency_diff_is_applied_before_context_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); repo = self.repo(root)
            producer = root / "producer"; real_run_command(["git", "clone", "-q", str(repo), str(producer)], cwd=root)
            (producer / "new-contract.ts").write_text("export const value = 1;\n")
            _, patch_bytes = _workspace_patch(producer)
            patch_path = root / "stages" / "producer" / "diff.patch"
            patch_path.parent.mkdir(parents=True); patch_path.write_bytes(patch_bytes)
            workspace = root / "consumer"; real_run_command(["git", "clone", "-q", str(repo), str(workspace)], cwd=root)
            accepted = {"producer": {"stageId": "producer", "artifactSha256": "a" * 64, "artifactFiles": [str(patch_path.relative_to(root))]}}
            stage = {"id": "consumer", "dependsOn": ["producer"], "contextPaths": ["new-contract.ts"]}
            handoff, _, _ = _build_handoff(run_dir=root, workspace=workspace, stage=stage, accepted=accepted, instructions="inspect")
            self.assertEqual("export const value = 1;\n", (workspace / "new-contract.ts").read_text())
            self.assertEqual((workspace / "new-contract.ts").read_bytes(), (handoff / "context" / "new-contract.ts").read_bytes())

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
