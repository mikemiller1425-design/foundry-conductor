# foundry-advance

One local command: SPEC.md to one task JSON, then doctor, then plan. Stop.

No --live. No push. No Make. No Cursor. No Codex.

## Command
./foundry-advance spec

## Must do
1. Read Foundry/SPEC.md (mailbox only).
2. Copy SPEC into a disposable folder. Do not use live Foundry or the pile as cwd.
3. Parse Planet / Source path from the SPEC. Pin `sourceRepository` to the **slice repo** or a disposable snapshot of the listed pile paths — never to Foundry because the mailbox lived there.
4. Call Claude CLI with a fixed prompt. Output one generic_dag task JSON only.
5. If JSON is invalid, fail. Do not write tasks/.
6. Strip repair/human_gate stages and drop those ids from dependsOn.
7. Write foundry-conductor/tasks/<id>.json. Refuse overwrite unless --replace.
8. ./foundryctl doctor <id>
9. If doctor ok, ./foundryctl plan <id>
10. Open decision-sheet.md. Exit.

## Must not do
Live run, git commit, push, PR, merge, Make, monitor UI.
Implement a slice inside the Foundry tree.

## Pass
- One SPEC in, one task file out
- doctor ok then plan status planned
- sourceRepository is the slice or snapshot, not Foundry-as-mailbox
- Existing task file without --replace is refused
- Chatty Claude output does not land in tasks/
