# foundry-advance

One local command: SPEC.md to one task JSON, then doctor, then plan. Stop.

No --live. No push. No Make. No Cursor. No Codex.

## Command
./foundry-advance spec

## Must do
1. Read Foundry/SPEC.md
2. Copy SPEC into a disposable folder. Do not use live Foundry as cwd.
3. Call Claude CLI with a fixed prompt. Output one generic_dag task JSON only.
4. If JSON is invalid, fail. Do not write tasks/.
5. Write foundry-conductor/tasks/<id>.json. Refuse overwrite unless --replace.
6. ./foundryctl doctor <id>
7. If doctor ok, ./foundryctl plan <id>
8. Open decision-sheet.md. Exit.

## Must not do
Live run, git commit, push, PR, merge, Make, monitor UI.

## Pass
- One SPEC in, one task file out
- doctor ok then plan status planned
- Existing task file without --replace is refused
- Chatty Claude output does not land in tasks/
- Foundry tree not written by the model
