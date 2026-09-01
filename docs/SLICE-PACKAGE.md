# Slice package

The product of extract-then-package. Not a conductor ticket.

## Shape

```
<slice-id>/
  README.md      # the filled card
  CARD.md        # same card in markdown
  SPEC.md        # fences for advance only
  src/           # copied working code only
  fixtures/      # proof ZIP / fixture provider
  data/          # gitignored runtime
  run.sh         # one command
```

## Card must include before any tool runs

- Trigger / stop / one-sentence outcome
- Source path in the pile
- Proof command + proof output already seen
- Copy list
- Do-not-copy list (`node_modules`, `data/`, live Places, send, analyzer, evolver)
- One run command for the new folder

## First slice

`biz-by-zip` — https://github.com/mikemiller1425-design/biz-by-zip

Job: one US ZIP in, deduped businesses out. Fixture provider only.
Source pile: `~/Desktop/Development/bee-bootstrap/engine`
Copy candidates: `src/stages/s01_targeting`, `src/stages/s02_discovery`, `src/stages/s03_dedupe`, `src/providers/discovery`, matching tests/fixtures.

## Conductor role

Tickets plan the copy and the first test.
They do not implement BEE inside Foundry.
They do not become the slice folder.
