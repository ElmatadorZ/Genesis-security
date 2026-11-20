# Audit Trail and Checkpoints

Every verdict the gate makes is appended to a JSONL audit log. If something goes wrong, this is how you find out what happened, and the log is built so that an attacker can't quietly rewrite it.

## What an entry looks like

```json
{"ts": 1763625600.12, "event": "tool_call",
 "payload": {"verdict": {"verdict": "BLOCK", "gsx": ["GSX-02","GSX-05"], "severity": "S2",
             "reason": "action requested by untrusted content, not by owner", "...": "..."},
             "ctx": {"tool": "delete_file", "agent": "scout", "task_id": "t1", "origin_tier": 3}},
 "prev": "9be1…", "alg": "hmac-sha256", "hash": "4c0a…"}
```

Logged: event type, verdict, threat classes, severity, reason (secrets redacted), trace, and small scalar context fields.
**Not logged:** raw tool arguments, external content, message bodies, memory content, or context keys starting with `_`.

## How tampering is detected

| Attack | Detected by |
|---|---|
| Edit an entry | Its hash no longer matches |
| Delete or reorder entries | `prev` links break |
| Rewrite the whole file and recompute hashes | Hashes are **HMAC-SHA256** keyed from `GENESIS_SECURITY_KEY`. Without the key, recomputed hashes don't verify |
| Cut entries off the end | **Checkpoint**: the log is shorter than the stored count, or the hash at that position differs |
| Delete the whole log (and rotated files) | **Checkpoint**: expected N entries, found 0 |

The audit key is derived from your main key (`HMAC(key, "genesis-security/audit/v1")`), so one secret covers both uses.

## Checkpoints

A checkpoint is `{"count": N, "head": "<hash of entry N>"}`. Store it **where your agents can't write**: your phone, another machine, a private gist, a password manager note.

```bash
genesis-security checkpoint logs/audit.jsonl > ~/safe/cp.json
genesis-security verify-audit logs/audit.jsonl --checkpoint ~/safe/cp.json
# intact=True entries=1834 checkpoint=1790
```

```python
cp = gate.audit.checkpoint()                 # raises if the chain is already broken
ok, n = gate.audit.verify(checkpoint=cp)
```

Take a checkpoint at the end of each session, or every N minutes for long-running agents. Verify at the start of the next session.

## Concurrency and rotation

- Writes are serialised with an OS file lock (`fcntl` on Linux/macOS, `msvcrt` on Windows). Many agents in many processes can share one log.
- Each write reads only the tail of the file, so writes stay fast as the log grows.
- When the file passes `max_bytes` (default 10 MB) it is renamed to `audit.jsonl.1`, `.2`, … and the new file continues the same chain. `verify` walks all files in order.

```python
AuditTrail("logs/audit.jsonl", max_bytes=50_000_000)
```

## Shipping logs elsewhere

The log is plain JSONL, so you can tail it into Grafana Loki, a SIEM, or a spreadsheet. Useful queries:

- `severity == "S1"` → page yourself
- `gsx contains "GSX-07"` → someone is impersonating agents
- `layer_trace contains "quarantine:"` → an agent was quarantined

## If verification fails

1. Stop the agents. Don't write more entries to the log.
2. Copy the log and rotated files somewhere safe.
3. `verify` reports how many entries were valid before the break. Look at the entry right after that.
4. Assume the key may be exposed. Rotate `GENESIS_SECURITY_KEY` and start a new log.
