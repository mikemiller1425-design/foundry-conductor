# foundry-conductor — what lives here

This repo runs one isolated ticket at a time.
Models propose. This tool isolates. You merge. Make only labels PRs.

## You run these

- `./foundryctl` — doctor / plan / run a task
- `./foundry-advance spec` — turn Foundry/SPEC.md into one task, then doctor + plan. Stops. No --live.

## Folders

- `tasks/` — tickets (one JSON each). This is the work queue.
- `runs/` — evidence from a run. Local only. Not the product.
- `tools/monitor/` — the TV. `python3 tools/monitor/server.py --root . --port 8787`
- `src/` — conductor code. Do not use as a chat cwd.
- `schemas/` — required JSON shapes agents must return.
- `docs/` — specs for this repo (SPEC-ADVANCE.md).
- `bin/` — helper entrypoints.

## Do not put here

- Live Foundry app code
- Make scenarios
- NAS / spend / push from a model
- Chat transcripts as source of truth

## Loop

SPEC.md (in Foundry) → foundry-advance spec → tasks/<id>.json → foundryctl run --live → you review PR → Make stamps the label.
