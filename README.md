# Foundry Conductor

Foundry Conductor is a standalone manifest-driven DAG orchestrator for Claude
Code, Cursor Agent, and Codex. The generic runner supports read-only discovery,
controlled writes in disposable Git snapshots, independent review, repair,
tests, isolated local commits, explicit human gates, and accepted-artifact
resume. It never pushes.

It never gives an agent the live Foundry checkout as its working directory.
Instead, it exports the accepted Git `HEAD` into a disposable tracked-file
snapshot under an append-only run directory. Untracked Foundry files, runtime
databases, mounted volumes, and Git history are excluded from that snapshot.

## Safety boundary

The generic runner defaults every irreversible or external permission to false:

- NAS access, external actions, spending, destructive operations, and
  production execution require a manifest-declared human gate;
- push is never executed by the conductor;
- controlled-write stages operate only in a disposable snapshot and are
  checked against their exact `allowedPaths` after execution;
- test commands must exactly match a manifest `allowedCommands` entry.

Live model calls require both a task policy that permits them and the explicit
`--live --confirm-live-models` command-line flags. Running without `--live`
creates a complete dry-run plan without contacting a model provider.

This is protection against accidental workflow expansion, not a general OS
security sandbox. The source checkout is protected primarily by never being
used as an agent working directory and by before/after Git-state verification.

## Terminal usage

```sh
cd /Users/macmini/Documents/GitHub/foundry-conductor

# Generic DAG doctor. No model calls.
./foundryctl doctor generic-triad-smoke

# Create a disposable snapshot, command plan, and evidence record. No model calls.
./foundryctl plan generic-triad-smoke

# Same safe default as plan.
./foundryctl run generic-triad-smoke

# Future explicit connectivity probe. May consume provider/account usage.
./foundryctl run generic-triad-smoke --live --confirm-live-models

# Inspect a run or its immutable evidence.
./foundryctl status <run-id>
./foundryctl evidence <run-id>

# Append operator context or decide an explicitly declared gate.
./foundryctl message <run-id> "context for the next stage"
./foundryctl approve <run-id> <stage-id> --message "approved boundary"
./foundryctl refuse <run-id> <stage-id> --message "refused boundary"

# Resume without repeating accepted stages.
./foundryctl resume generic-triad-smoke --from-run <run-id> \
  --live --confirm-live-models

# Bounded read-only Package 2a prompt reconciliation.
./foundryctl reconcile
./foundryctl reconcile --live --confirm-live-models

# Continue from an already-preserved Claude draft without regenerating it.
./foundryctl reconcile --live --confirm-live-models \
  --resume-draft-from <prior-run-id>

# Only after a separate operator authorization for one extra bounded round.
./foundryctl reconcile --live --confirm-live-models \
  --resume-reviewed-from <prior-run-id> --allow-one-additional-round \
  --expected-draft-sha256 <sha256> --allow-cursor-schema-repair

# After explicit authorization, resume a failed reviewed round by exact digest
# and permit at most one Cursor-only schema repair on the revised draft.
./foundryctl reconcile --live --confirm-live-models \
  --resume-failed-reviewed-from <prior-run-id> \
  --expected-draft-sha256 <sha256> --allow-one-additional-round \
  --allow-cursor-schema-repair

# Packetized exhaustive defect inventory; never revises or issues the candidate.
./foundryctl inventory --live --confirm-live-models \
  --from-run <prior-run-id> --candidate-sha256 <sha256>

# Resume packet reviews from a preserved matrix response without recalling Claude.
./foundryctl inventory --live --confirm-live-models \
  --from-run <candidate-run-id> --candidate-sha256 <sha256> \
  --resume-traceability-from <matrix-run-id> \
  --resume-packet-reviews-from <review-run-id>
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
decision-sheet.md     concise operator-facing status
stages/*/accepted.json immutable accepted-stage artifacts and hashes
handoffs/<stage>/      physical canonical handoff: instructions, selected
                      tracked context, readable dependency responses/diffs,
                      accepted records, and manifest SHA-256
workspaces/<stage>/    isolated per-stage Git clone of the disposable snapshot
messages/             append-only operator messages
approvals/            append-only human gate decisions
```

## Generic manifest

Set `workflow` to `generic_dag` and declare a DAG in `stages`. Dependencies are
topologically ordered and their accepted artifact hashes are injected into the
next stage automatically. Accepted stages are never invoked again on resume.

Stage types are `reconnaissance`, `implementation`, `review`, `repair`,
`workspace_seed`, `test`, `commit`, and `human_gate`. Implementation and repair
require `allowedPaths`; test requires an exact `command` also present in
`allowedCommands`.

Large controlled-write work should be split into independently accepted
checkpoints, each with its own narrow allowlist, timeout/retry budget, handoff
digest, schema acknowledgement, changed-file manifest, patch, and accepted
artifact hash. Soft failures (timeouts, invalid schema) preserve a diagnostic
workspace and artifact hash that is never treated as accepted input. Retries
always start from a fresh clone of the last accepted dependency baseline.
Optional `recoveryPolicy` may reject a diagnostic, hash-verify it and issue a
bounded completion prompt, or convert it only after allowlist-clean validation.
Write stages reserve finish time for schema serialization (`finishReserveSeconds`)
and instruct providers not to run package test suites; conductor `test` gates own
formal verification. Cursor remains read-only (reconnaissance/review). Codex owns
orchestration/security/patch review and routes repairs onto narrow Claude
checkpoints. `human_gate` may declare `requireAccepted` so the final gate cannot
pass unless every listed checkpoint, test gate, and review is accepted.

Provider routing is adapter-neutral. A stage may set `provider` explicitly.
Otherwise the role policy is:

- Claude: `backend`, `general`, `implementation`;
- Cursor: `frontend`, `contract`, `contract_dependency`;
- Codex: `governance`, `security`, `review`, `integration`.

A stage may declare `contextPaths` to place exact tracked files in its physical
handoff. Every provider must return the canonical handoff digest and explicitly
confirm work started. The conductor records provider-specific start,
acknowledgement, completion, findings-routing, and acceptance events. Downstream
handoffs contain readable normalized responses, changed-file manifests, binary
diffs, and safe context copies—not hashes alone.

Agent stages may also declare static `attachments` with a conductor-relative
path, canonical SHA-256, and handoff filename. Attachments are accepted only
from beneath the conductor repository, reject traversal and symlinks, are
hash-verified before a single append-only copy, and participate in the canonical
handoff digest.

A review can declare `repairPolicy`. A schema-valid fail with actionable findings
is accepted for routing to the responsible provider, followed by an isolated
bounded repair and rereview. Repairs are applied only inside the next disposable
workspace. The loop ends on a clean pass or a declared maximum-round failure.
Accepted artifacts are hash-verified on resume and never reinvoked.

Test stages run in their own reconstructed workspace against dependency diffs.
Their exact command must appear in `allowedCommands`; optional `preservePaths`
remain byte-identical. The conductor rejects any tracked diff expansion while
allowing ignored build/test artifacts, and records stdout, stderr, pre/post
status, hashes, and return codes in the final machine summary and decision sheet.

Use `tasks/generic-visible-acceptance.json` for the live read-only triad proof;
it deliberately exercises one review-to-repair-to-rereview route and stops at an
unapproved final integration gate. `tasks/foundry-next-batch-plan.json` is the
prepared Package 2a/2c plan split into independently accepted Claude checkpoints
(contracts, scanner, fixtures/tests, evidence/docs), Cursor read-only preparation,
narrow Codex reviews, conductor-owned evidence/final gates, and a final human gate.

## Profiles

The generic DAG runner lives in `foundry_conductor.dag` and is the default
reusable product. Package-specific reconciliation, defect inventory, and the
89-defect certified-authorization machinery are isolated historical profiles;
they do not alter generic manifest semantics or provider routing.

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

The tests cover DAG order, provider roles, physical handoff content and digests,
wrong or fake acknowledgements, missing artifacts, exact path and command
policies, read-only mutation, empty controlled writes, review/repair routing,
exhausted rounds, accepted-artifact resume, human-gate bypass, source safety,
timeout diagnostic preservation, unaccepted-work isolation, recovery hash
binding, retry path non-widening, finish-reserve prompts, and final-gate
`requireAccepted` enforcement.

## Human-only boundaries

Push remains manual and outside the runner. NAS access, external actions,
spending, destructive operations, and production execution require an explicit
manifest gate and an append-only `approve` decision. The bundled smoke manifest
declares none of them and cannot perform them.

## Phase 0.2 reconciliation

The `reconcile` command runs a maximum of three rounds:

1. Claude drafts a complete authorization prompt.
2. Codex and Cursor independently review the exact same draft SHA-256.
3. Required changes are merged and returned to Claude.
4. Both reviewers must return schema-valid `pass` verdicts with zero findings
   against the same final digest.

Every prompt, raw response, normalized response, digest, round manifest, and
verdict is written once under the run directory. A successful run writes the
candidate to `final/package-2a-authorization-prompt.md` and stops for the
operator. It does not execute the candidate prompt.
test
test
test
