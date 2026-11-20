# Extending

Every extension keeps two guarantees: **fail closed**, and **nothing loosens a body verdict**.

## Without writing code

| Want to… | Change |
|---|---|
| Detect your own credentials | `[secrets].patterns` |
| Make a tool wait for you | add it to `[tools].irreversible` |
| Treat a tool as sending data out | add it to `[egress].tools` |
| Let a read-only tool browse anywhere | add it to `[egress].open_tools` |
| Allow a shell command | `[shell].allowlist` + its dangerous options in `[shell.deny_args]` |
| Tighten agent messaging | lower `hop_budget`, `max_age_s`, `quarantine_after` |

## Custom brain (semantic or rule checks)

Any `brain(event) -> dict | None` can tighten verdicts. Use it for business rules (position limits, office hours, spend caps), a classifier, a local model, or another service. See [Brain Adapters](Brain-Adapters).

```python
DAILY_LIMIT = 3
orders_today = 0

def order_cap(event):
    global orders_today
    if event["event"] == "tool_call" and event["ctx"].get("tool") == "place_order":
        if orders_today >= DAILY_LIMIT:
            return {"verdict": "BLOCK", "reason": "daily order cap reached"}
        if event["verdict"]["verdict"] in ("ALLOW", "HOLD"):
            orders_today += 1
    return None
```

## Custom Human Gate

`owner_confirm(verdict, ctx) -> bool` can route to a terminal, phone, desktop dialog, a second approver, or narrow auto-approval rules. Return `False` on timeout. See [Verdicts and the Human Gate](Verdicts-and-the-Human-Gate).

## Subclassing the gate

Override narrow, documented helpers. Don't copy `pre_tool_call`.

```python
from genesis_security import GenesisSecurityGate

class MyGate(GenesisSecurityGate):
    def _shell_refusal(self, cmd: str) -> str | None:
        reason = super()._shell_refusal(cmd)          # keep the built-in rules
        if reason:
            return reason
        if "/etc/" in cmd or "~/.ssh" in cmd:
            return "sensitive path"
        return None
```

Always call `super()` first, so your subclass can only add refusals.

## New hooks for your own events

Use `gate.audit.record(...)` and the scanner to give new event types the same treatment:

```python
from genesis_security import Verdict, scan_injection

def on_calendar_invite(gate, invite_text: str) -> Verdict:
    status, gsx, hits = scan_injection(invite_text)
    v = Verdict("BLOCK" if status == "injected" else "ALLOW", gsx, "S3" if gsx else "S4",
                f"calendar invite scan={status}", layer_trace=[f"L1:{status}"])
    gate.audit.record("calendar_invite", {"verdict": v.__dict__})
    return v
```

## Logs and monitoring

The audit log is JSONL. Tail it into Loki, Elastic, a SIEM, or a script that pings your phone on `severity == "S1"`. Keep checkpoints off-machine. See [Audit Trail and Checkpoints](Audit-Trail-and-Checkpoints).

## Every rule needs an attacker

When you add a defence, add a case to `genesis_security/redteam.py` that fails without it and passes with it. See [Red Team Guide](Red-Team-Guide#writing-a-case).
