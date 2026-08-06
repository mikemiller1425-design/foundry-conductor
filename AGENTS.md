# Foundry Conductor rules

- The conductor repository is independent of the Foundry product repository.
- Read-only tasks must operate on a disposable `git archive` snapshot, never in the source checkout.
- Never infer permission to push, access a mounted volume, spend money, or widen a package scope.
- Runtime evidence is append-only under `runs/`; do not rewrite an existing run.
- A missing agent binary, baseline mismatch, source-repository drift, invalid response, or snapshot mutation is a failure, not a warning to bypass.
- Do not add a write workflow until the operator authorizes one explicitly.
