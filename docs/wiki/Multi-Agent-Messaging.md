# Multi-Agent Messaging

In a multi-agent system, a message from another agent is only as trustworthy as what that agent read. Genesis Security signs every message and checks it on arrival.

## Sending

```python
env = gate.make_envelope(
    frm="risk",                 # sender name
    to="executor",              # intended recipient
    task_id="task-42",
    body=msg,                   # the message text (signed, not stored in the envelope)
    scope=["read:market"],      # permissions this message relies on
    hop=incoming_hop + 1,       # how many agent-to-agent hops so far
    taint=Tier.T3 if msg_uses_web_data else Tier.T2,
)
send(env, msg)
```

The envelope contains `from, to, task_id, capability_scope, hop, taint, ts, nonce, sig`. `sig` is HMAC-SHA256 over the sorted envelope plus the body.

## Receiving

```python
tier, v = gate.on_agent_message(env, msg, granted_scope={"read:market"}, recipient="executor")
if not v.allowed:
    drop(msg, reason=v.reason)
else:
    handle(msg, origin_tier=tier)       # T2, or T3 if tainted
```

| Check | Fails as |
|---|---|
| No envelope or no `sig` | `ALLOW_SANITIZED`, tier **T3** — read as data only |
| Signature doesn't match (forged or edited) | **BLOCK** GSX-07 |
| Missing `ts` / `nonce` | **BLOCK** GSX-07 |
| Older or newer than `agents.max_age_s` (default 300 s) | **BLOCK** GSX-07 |
| Nonce already seen (replay) | **BLOCK** GSX-07 |
| `to` ≠ `recipient` | **BLOCK** GSX-07 |
| Sender is quarantined | **BLOCK** GSX-07 |
| `hop` ≥ `agents.hop_budget` | **BLOCK** GSX-10 |
| `capability_scope` contains anything not in `granted_scope` | **BLOCK** GSX-11 |
| Body is injected | **BLOCK** |

The returned `tier` is at least T2, and T3 if the envelope says the content is tainted. Use it as `origin_tier` for any action the receiving agent takes **because of** this message.

## Scopes

Scopes are strings you define, e.g. `read:market`, `trade:paper`, `trade:live`, `write:memory`. The receiver passes `granted_scope`: what this sender is allowed to ask for. Scope can only be widened by you (T0/T1), by changing what you pass as `granted_scope`. An agent can't grant itself `trade:live` by writing it into an envelope.

## Hops

Each forward should increase `hop`. Messages at or above `hop_budget` are dropped, which stops infinite ping-pong and runaway delegation chains.

## Keys and trust zones

One HMAC key proves "signed by someone holding this key", not "signed by agent X". Any agent holding the key can sign as any other, or reset `hop` and `taint`. To limit that:

- Agents that read T3 content (Readers) and agents that act (Executors) should be in **different trust zones with different keys**: one gate per zone.
- Messages crossing zones are verified by the receiving zone's gate. A message signed with the other zone's key fails as a forgery.

Per-agent keys are on the [Roadmap](Roadmap).

## Replay protection scope

The nonce cache is kept in memory on the gate. It doesn't survive a restart or span processes. `max_age_s` limits the window: after a restart, a captured message can be replayed only until it's `max_age_s` old. Lower it if your agents talk in real time. A shared nonce store is on the [Roadmap](Roadmap).
