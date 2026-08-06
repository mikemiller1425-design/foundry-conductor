from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import ConductorError, doctor, execute_task, load_json
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
        "--confirm-live-models",
        action="store_true",
        help="confirm that live model calls may consume account/API usage",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    root = project_root()
    try:
        selected_task = task_path(root, args.task)
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
