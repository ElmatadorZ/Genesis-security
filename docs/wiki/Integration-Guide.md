# Integration Guide

How to put Genesis Security into an existing agent: SkynetClaw, a custom loop, or a framework.

## Where the gate goes

```
 you ──T1──▶ ┌──────────────┐        ┌───────────────────────────┐
             │  agent loop   │──────▶│ gate.pre_tool_call / guard │──▶ tools
 web/files ─▶│ (LLM decides) │        └───────────────────────────┘
   │         └──────────────┘                     │
   └─▶ gate.on_external_content                    └─▶ audit chain
```

There are exactly five places to touch:

| # | Where | Hook |
|---|---|---|
| 1 | Session start | `gate.audit.verify(checkpoint=...)` |
| 2 | Anything from outside enters the context | `gate.on_external_content(...)` |
| 3 | Before every tool runs | `@gate.guard(name)` or `gate.pre_tool_call(...)` |
| 4 | Agent ↔ agent | `gate.make_envelope(...)` / `gate.on_agent_message(...)` |
| 5 | Before memory / skill writes and loads | `gate.on_memory_write(...)` / `gate.on_skill_load(...)` |

## Step by step

### 1. One gate per process

```python
from genesis_security import GenesisSecurityGate, AuditTrail

gate = GenesisSecurityGate.from_env(
    audit=AuditTrail("logs/audit.jsonl"),
    owner_confirm=ask_owner,
)
```

Strikes, quarantine and the replay cache live on the gate object, so share one instance across your agents in the same process.

### 2. Verify the log at startup

```python
import json, pathlib
cp_path = pathlib.Path.home() / ".genesis" / "checkpoint.json"       # outside the agent's workspace
cp = json.loads(cp_path.read_text()) if cp_path.exists() else None
ok, n = gate.audit.verify(checkpoint=cp)
if not ok:
    raise SystemExit("Audit chain broken (GSX-13). Investigate before running agents.")
```

And at shutdown (or on a timer): `cp_path.write_text(json.dumps(gate.audit.checkpoint()))`. Even better, send it to your phone.

### 3. Wrap every tool, without exception

```python
TOOLS = {
    "read_file":    gate.guard("read_file")(read_file),
    "write_file":   gate.guard("write_file")(write_file),
    "http_request": gate.guard("http_request")(http_request),
    "shell_exec":   gate.guard("shell_exec")(shell_exec),
}
```

A tool the model can reach without the gate is a hole. If your framework registers tools itself, wrap the functions before registering them.

### 4. Tag `origin_tier` at the dispatch point

The model returns a tool call. Your loop decides who that call came from:

```python
def dispatch(tool_call, turn):
    origin = Tier.T1 if turn.is_direct_owner_request and not turn.saw_external_content else Tier.T3
    ctx = {"agent": turn.agent, "task_id": turn.task_id, "origin_tier": origin,
           "touches_private": tool_call.name in PRIVATE_DATA_TOOLS}
    try:
        return TOOLS[tool_call.name](tool_call.args, ctx)
    except PermissionError as e:
        return f"[refused by security gate] {e}"     # give the model the refusal as a tool result
```

Being conservative here costs you a few extra HOLDs. Being generous gives attackers a way in.

Returning the refusal as a tool result (not crashing) lets the model explain to you what it wanted to do.

### 5. Route outside content through the gate

```python
page, v = gate.on_external_content(url, html, task_id=turn.task_id)
turn.saw_external_content = True
messages.append({"role": "user", "content": page.value})
```

### 6. Load the brain into the agent

Give the agent `skill/SKILL.md` as a Claude Skill (or system prompt). The agent then refuses most bad actions *before* they reach the gate, and the gate catches the rest.

## Framework notes

| Framework style | Where to hook |
|---|---|
| Plain loop (Anthropic / OpenAI SDK tool use) | Your `dispatch` function, as above |
| Decorator-registered tools | Apply `@gate.guard(name)` *under* the framework's decorator so the gate runs first |
| Class-based tools with `run(self, **kwargs)` | Call `gate.pre_tool_call(self.name, kwargs, ctx)` at the top of `run` and raise if `not v.allowed` |
| Multi-agent frameworks | Wrap the message bus: sign in `send`, verify in `receive` ([Multi-Agent Messaging](Multi-Agent-Messaging)) |
| MCP clients | Gate the client's `call_tool`; pin each server's tool descriptions ([Skill and Plugin Pinning](Skill-and-Plugin-Pinning)) |

## Full example

[`examples/skynetclaw_integration.py`](https://github.com/ElmatadorZ/Genesis-security/blob/main/examples/skynetclaw_integration.py) runs end to end: audit check, guarded tools, a malicious page, a blocked T3 action, and an owner-confirmed delete.

## Checklist

- [ ] One gate instance, created from env
- [ ] Audit verified at startup, checkpoint stored off-machine
- [ ] Every tool wrapped
- [ ] `origin_tier` set at dispatch, conservative by default
- [ ] All external content through `on_external_content`
- [ ] Agent messages signed and verified with `recipient=`
- [ ] Memory writes through `on_memory_write`
- [ ] Skills and MCP descriptions pinned
- [ ] Policy file reviewed: allowlist short, irreversible tools listed
- [ ] `genesis-security redteam` returns 0 in your environment
