# Verdicts and the Human Gate

## The four verdicts

| Verdict | Meaning | `@guard` behaviour |
|---|---|---|
| `ALLOW` | Every layer passed | Runs the tool |
| `ALLOW_SANITIZED` | Allowed, but with cleaned input | Runs with `verdict.sanitized_args` if present |
| `HOLD` | The owner must decide | Calls `owner_confirm` → becomes ALLOW or BLOCK. Without a callback, the tool does **not** run |
| `BLOCK` | Refused | Raises `PermissionError` |

`verdict.allowed` is `True` for ALLOW and ALLOW_SANITIZED only.

## Verdict fields

| Field | Example |
|---|---|
| `verdict` | `"HOLD"` |
| `gsx` | `["GSX-06"]` — threat classes, see [Threat Model](Threat-Model) |
| `severity` | `"S1"` … `"S4"` |
| `reason` | `"irreversible action needs owner confirmation → delete_file {\"path\": \"old.md\"}"` |
| `sanitized_args` | `{"content": "- [fact][source:T3] Gold closed higher"}` |
| `requires_owner` | `True` |
| `layer_trace` | `["L0:origin=T1 …", "L1:clean", "L2:traces to owner", "L4:irreversible=True flags=[]"]` |

## Severity

| Level | Meaning | Suggested response |
|---|---|---|
| **S1** | A secret would have left, or an irreversible action came from T3 | Stop all agents, rotate keys, keep the audit log, investigate |
| **S2** | Injection or escalation attempt that got as far as a tool call or signed message | Quarantine the agent, review its recent actions |
| **S3** | Caught and blocked or held as designed | Note it in your daily review |
| **S4** | Informational | — |

## Fail-closed guarantees

None of these ever results in ALLOW:

- The brain raises, times out, or returns something that isn't a dict
- `owner_confirm` raises
- `origin_tier` is missing (→ T3) or malformed (→ error)
- A message has no signature, a bad signature, no nonce/timestamp, or is a replay
- The audit chain can't be verified (you decide what to do; the integration example refuses to start)

## The Human Gate

A HOLD means "a human should look at this". You supply the human:

```python
def owner_confirm(verdict, ctx) -> bool: ...
```

- `verdict.reason` contains a short, **secret-redacted** preview of the call (`tool {"arg": ...}`, 160 characters max), so you know what you're approving.
- `ctx` is the tool-call context (`agent`, `task_id`, `origin_tier`, `tool`, …).
- Return `True` to allow, `False` to block. Exceptions count as `False`.

### Terminal

```python
def owner_confirm(verdict, ctx):
    return input(f"[HOLD] {verdict.reason}\nAllow? [y/N] ").strip().lower() == "y"
```

### Phone notification (pattern)

```python
def owner_confirm(verdict, ctx, timeout=120):
    request_id = send_to_phone(f"{ctx.get('agent')}: {verdict.reason}")   # Telegram / LINE / ntfy
    answer = wait_for_reply(request_id, timeout=timeout)                 # None on timeout
    return answer == "yes"                                               # timeout → False → BLOCK
```

### Policy-based auto-decisions

```python
def owner_confirm(verdict, ctx):
    if ctx.get("tool") == "delete_file" and str(ctx.get("_args_preview", "")).find("/tmp/") != -1:
        return True                       # temp files: fine
    return ask_on_phone(verdict, ctx)     # everything else: ask
```

Keep auto-approval rules narrow. Every rule you add here is a rule an attacker can aim for.

### Not running unattended

With no `owner_confirm`, HOLD stays HOLD and guarded tools raise `PermissionError`. That's the right default for agents that run while you're away: irreversible actions wait for you.
