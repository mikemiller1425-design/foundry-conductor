# foundry-conductor — what lives here

This repo isolates one ticket at a time.
It does not own the product folder. The product is a **slice package** in its own repo.

Models propose. This tool isolates. You merge. Make only labels PRs.

## Words

- **Pile** — messy checkout people used to call a planet (`bee-bootstrap`).
- **Card** — filled Universal Workflow Build Spec (trigger, stop, proof).
- **Ticket** — `tasks/<id>.json`. Conductor queue only.
- **Slice package** — standalone folder/repo that runs one job (`biz-by-zip`). That is the product.

## You run these

- `./foundryctl` — doctor / plan / run a task
- `./foundry-advance spec` — turn a SPEC.md into one task, then doctor + plan. Stops. No --live.

## Folders

- `tasks/` — tickets (one JSON each). Queue, not the product.
- `runs/` — evidence from a run. Local only.
- `tools/monitor/` — the TV.
- `src/` — conductor code. Not a chat cwd.
- `schemas/` — JSON shapes agents must return.
- `docs/` — `SPEC-ADVANCE.md`, `SLICE-PACKAGE.md`.
- `bin/` — helper entrypoints.

## Pin rule (the miss we hit)

`sourceRepository` must be the slice checkout or a disposable snapshot of the pile paths listed on the card.
Never pin Foundry just because SPEC.md sat in Foundry.
Foundry holds the SPEC slot. It is not the work tree for BEE slices.

## Do not put here

- Live app code for a slice (`biz-by-zip` lives in its own repo)
- The pile (`bee-bootstrap`)
- Make scenarios
- NAS / spend / push from a model
- Chat transcripts as source of truth

## Loop (aligned)

Filled card + proof of an already-working command in the pile
→ SPEC.md (Foundry slot is just the mailbox)
→ foundry-advance spec → tasks/<id>.json
→ doctor + plan (no live until pin is the slice)
→ copy listed paths into the slice repo
→ first test is the card's fake ZIP, inside the slice folder

Live run against Foundry for a BEE slice is a miss, not a pass.
