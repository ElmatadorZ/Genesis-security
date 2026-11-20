# Brain Adapters

The body is rule-based: fast, predictable, and blind to meaning. A **brain** is a second opinion with judgement, usually an LLM running `skill/SKILL.md`.

## The contract

```python
def brain(event: dict) -> dict | None: ...
```

`event` looks like:

```python
{"event": "tool_call",              # external_content | tool_call | agent_message | memory_write | skill_load
 "verdict": {...},                  # the body's verdict so far (as a dict)
 "ctx": {"tool": "...", "agent": "...", "origin_tier": 1, ...}}   # small scalar fields only
```

Return one of:

- `None` → no opinion
- `{"verdict": "HOLD", "reason": "..."}` → make it at least HOLD
- `{"verdict": "BLOCK", "reason": "..."}` → block

### Guarantees

- **The brain can only tighten.** ALLOW → HOLD/BLOCK is possible. BLOCK → ALLOW is ignored.
- **Fail closed.** If the brain raises, times out, or returns something that isn't a dict → **BLOCK**.
- The brain is called for ALLOW, ALLOW_SANITIZED and HOLD verdicts. Already-blocked events skip it.
- The brain receives the verdict and small context fields, not raw content or full arguments. A HOLD reason includes a short, secret-redacted preview of the arguments (up to 160 characters), so attacker text can reach the reviewer in small amounts. That's safe by construction: the worst a manipulated brain can do is say ALLOW, and ALLOW from a brain is ignored.

## Claude (API)

```python
from examples.claude_brain_adapter import make_claude_brain
gate = GenesisSecurityGate.from_env(brain=make_claude_brain(events=("tool_call", "memory_write")))
```

Needs `ANTHROPIC_API_KEY`. Model: `GENESIS_BRAIN_MODEL` (default `claude-haiku-5-5`). Uses `SKILL.md` as the system prompt. Stdlib `urllib` only.

## Ollama (local, offline)

```python
from examples.ollama_brain_adapter import make_ollama_brain
gate = GenesisSecurityGate.from_env(brain=make_ollama_brain("llama3.1"))
```

Uses `OLLAMA_HOST` (default `http://localhost:11434`) with JSON output mode. If Ollama isn't running, every reviewed event is blocked (fail closed). Start Ollama before your agents.

Local models are weaker judges. Treat them as an extra tripwire, not a replacement for the body.

## Rule brains

A brain doesn't have to be a model:

```python
def no_trading_after_hours(event):
    if event["event"] == "tool_call" and event["ctx"].get("tool") == "place_order" and market_closed():
        return {"verdict": "BLOCK", "reason": "market closed"}
    return None
```

## Chaining

```python
def chain(*brains):
    rank = {None: 0, "HOLD": 1, "BLOCK": 2}
    def run(event):
        results = [b(event) for b in brains]
        return max(results, key=lambda r: rank[(r or {}).get("verdict")], default=None)
    return run

gate = GenesisSecurityGate.from_env(brain=chain(no_trading_after_hours, make_claude_brain()))
```

Put cheap rule brains first. If any brain raises, the whole chain raises and the gate blocks.

## Cost and latency

Each reviewed event is one model call. Limit `events=` to the hooks that matter (usually `tool_call` and `memory_write`), and prefer a small, fast model. The body already handles the clear-cut cases.
