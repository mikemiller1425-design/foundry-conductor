from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import ConductorError, doctor, execute_task, load_json
from .inventory import run_defect_inventory
from .reconcile import run_reconciliation


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def task_path(root: Path, task: str) -> Path:
    candidate = Path(task)
    if candidate.exists():
        return candidate.resolve()
    if not candidate.suffix:
        candidate = root / "tasks" / f"{task}.json"
    else:
        candidate = root / "tasks" / candidate.name
    if not candidate.exists():
        raise ConductorError(f"task not found: {task}")
    return candidate


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="foundryctl",
        description="Policy-gated Foundry agent conductor (read-only phase)",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    doctor_parser = subcommands.add_parser("doctor", help="check policy, baseline, and CLIs")
    doctor_parser.add_argument("task", nargs="?", default="readonly-triad-smoke")

    plan_parser = subcommands.add_parser("plan", help="create a no-model dry run and evidence record")
    plan_parser.add_argument("task", nargs="?", default="readonly-triad-smoke")

    run_parser = subcommands.add_parser("run", help="run a task; defaults to a no-model dry run")
    run_parser.add_argument("task", nargs="?", default="readonly-triad-smoke")
    run_parser.add_argument("--live", action="store_true", help="actually invoke configured agents")
    run_parser.add_argument(
        "--confirm-live-models",
        action="store_true",
        help="confirm that live model calls may consume account/API usage",
    )

    reconcile_parser = subcommands.add_parser(
        "reconcile",
        help="run a bounded read-only author/reviewer reconciliation",
    )
    reconcile_parser.add_argument(
        "task",
        nargs="?",
        default="package-2a-authorization-reconciliation",
    )
    reconcile_parser.add_argument("--live", action="store_true")
    reconcile_parser.add_argument(
        "--resume-draft-from",
        metavar="RUN_ID",
        help="continue from a completed Claude draft in an earlier append-only run",
    )
    reconcile_parser.add_argument(
        "--resume-reviewed-from",
        metavar="RUN_ID",
        help="continue from the last completed reviewed round in an earlier append-only run",
    )
    reconcile_parser.add_argument(
        "--allow-one-additional-round",
        action="store_true",
        help="with --resume-reviewed-from, permit exactly one explicitly authorized round beyond maxRounds",
    )
    reconcile_parser.add_argument(
        "--resume-partial-from",
        metavar="RUN_ID",
        help="continue an incomplete round from its preserved draft and valid reviews",
    )
    reconcile_parser.add_argument(
        "--resume-failed-reviewed-from",
        metavar="RUN_ID",
        help="continue from a failed round with a preserved draft and at least one valid review",
    )
    reconcile_parser.add_argument(
        "--expected-draft-sha256",
        help="bind an extra-round resume to the operator-authorized candidate digest",
    )
    reconcile_parser.add_argument(
        "--allow-cursor-schema-repair",
        action="store_true",
        help="permit one Cursor-only schema repair against an unchanged candidate digest",
    )
    reconcile_parser.add_argument(
        "--confirm-live-models",
        action="store_true",
        help="confirm that live model calls may consume account/API usage",
    )

    inventory_parser = subcommands.add_parser(
        "inventory", help="run a packetized read-only Package 2a defect inventory"
    )
    inventory_parser.add_argument(
        "task", nargs="?", default="package-2a-authorization-reconciliation"
    )
    inventory_parser.add_argument("--from-run", required=True, metavar="RUN_ID")
    inventory_parser.add_argument("--candidate-sha256", required=True)
    inventory_parser.add_argument(
        "--resume-traceability-from", metavar="RUN_ID",
        help="import a preserved schema-valid Claude matrix without invoking Claude again",
    )
    inventory_parser.add_argument("--live", action="store_true")
    inventory_parser.add_argument("--confirm-live-models", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    root = project_root()
    try:
        selected_task = task_path(root, args.task)
        if args.command == "inventory":
            result = run_defect_inventory(
                root=root,
                task_path=selected_task,
                source_run_id=args.from_run,
                candidate_sha256=args.candidate_sha256,
                live=args.live,
                live_confirmed=args.confirm_live_models,
                traceability_run_id=args.resume_traceability_from,
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result["status"] in {"planned", "ready_for_operator_decision"} else 3
        if args.command == "doctor":
            result = doctor(load_json(selected_task))
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result["ok"] else 2
        if args.command == "reconcile":
            result = run_reconciliation(
                root=root,
                task_path=selected_task,
                live=args.live,
                live_confirmed=args.confirm_live_models,
                seed_run_id=args.resume_draft_from,
                reviewed_run_id=args.resume_reviewed_from,
                partial_run_id=args.resume_partial_from,
                allow_one_additional_round=args.allow_one_additional_round,
                failed_reviewed_run_id=args.resume_failed_reviewed_from,
                expected_draft_sha256=args.expected_draft_sha256,
                allow_cursor_schema_repair=args.allow_cursor_schema_repair,
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result["status"] in {"planned", "ready_for_operator_decision"} else 3
        if args.command == "plan":
            result = execute_task(
                root=root,
                task_path=selected_task,
                live=False,
                live_confirmed=False,
            )
        else:
            result = execute_task(
                root=root,
                task_path=selected_task,
                live=args.live,
                live_confirmed=args.confirm_live_models,
            )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except ConductorError as exc:
        print(f"foundryctl: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
