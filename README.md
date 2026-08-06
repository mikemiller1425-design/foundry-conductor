# Foundry Conductor

Foundry Conductor is a standalone local orchestration tool for Claude Code,
Cursor Agent, and Codex. Version 0.1 is deliberately limited to **read-only**
tasks.

It never gives an agent the live Foundry checkout as its working directory.
Instead, it exports the accepted Git `HEAD` into a disposable tracked-file
snapshot under an append-only run directory. Untracked Foundry files, runtime
databases, mounted volumes, and Git history are excluded from that snapshot.

## Safety boundary

Version 0.1 rejects any task that permits:

- repository writes;
- NAS access;
- pushes; or
- any mode other than `read_only`.

Live model calls require both a task policy that permits them and the explicit
`--live --confirm-live-models` command-line flags. Running without `--live`
creates a complete dry-run plan without contacting a model provider.

This is protection against accidental workflow expansion, not a general OS
security sandbox. The source checkout is protected primarily by never being
used as an agent working directory and by before/after Git-state verification.

## Terminal usage

```sh
cd /Users/macmini/Documents/GitHub/foundry-conductor

# Check the accepted baseline, required CLIs, and authentication. No model calls.
./foundryctl doctor

# Create a disposable snapshot, command plan, and evidence record. No model calls.
./foundryctl plan

# Same safe default as plan.
./foundryctl run

# Future explicit connectivity probe. May consume provider/account usage.
./foundryctl run --live --confirm-live-models
```

Run evidence is stored under `runs/<run-id>/`:

```text
events.jsonl          append-only lifecycle events
task.json             exact task policy
plan.json             redacted commands
source-before.json    Foundry baseline fingerprint
source-after.json     post-run Foundry fingerprint
snapshot/             disposable tracked-file export
responses/            immutable stdout/stderr records for live runs
                      plus schema-validated normalized JSON on success
summary.json          final machine-readable result
```

The `runs/` directory is ignored by Git because it may contain large or
sensitive model responses. Preserve or archive selected evidence deliberately.

## Current task

`tasks/readonly-triad-smoke.json` pins Foundry to:

```text
branch: main
HEAD: c1607ad3068504438281f3e667d7fef4c9cc2db2
```

The task permits only a minimal repository-name connectivity probe against the
disposable snapshot. It does not authorize Package 2a, NAS access, code
changes, commits, pushes, external actions, or model invocation through
Foundry itself.

## Tests

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The tests prove that write permissions are rejected, untracked source files do
not enter snapshots, snapshot creation leaves the source fingerprint unchanged,
Codex commands target the snapshot with a read-only sandbox, and Cursor is
forced into plan mode with its sandbox enabled.

## Next authorization boundary

Do not add write-mode tasks yet. The next step after all three CLI probes pass
is a separately authorized, controlled-write design using isolated worktrees,
allowed-path enforcement, bounded repair rounds, independent review, and no
automatic push.
