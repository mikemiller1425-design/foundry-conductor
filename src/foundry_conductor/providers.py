from __future__ import annotations

from pathlib import Path

from .core import AgentCommand, build_agent_command


def build_provider_command(
    provider: str, *, mode: str, snapshot: Path, prompt: str,
    response_schema: Path, max_turns: int,
) -> AgentCommand:
    """Provider-neutral adapter boundary used only by the generic DAG runner."""
    command = build_agent_command(
        provider, snapshot=snapshot, prompt=prompt,
        response_schema=response_schema, max_turns=max_turns,
    )
    if mode == "read_only":
        return command
    argv = command.argv.copy()
    if provider == "codex":
        argv[argv.index("read-only")] = "workspace-write"
    elif provider == "cursor":
        argv[argv.index("plan")] = "agent"
    elif provider == "claude":
        argv[argv.index("plan")] = "acceptEdits"
        argv[argv.index("Read,Glob,Grep")] = "Read,Glob,Grep,Edit,Write"
    return AgentCommand(name=command.name, executable=command.executable, argv=argv)
