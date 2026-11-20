# Quickstart

Five minutes from install to a guarded agent.

## 1. Watch the loop work

```bash
genesis-security demo
```

Twelve attacks go through the loop: a web page with hidden instructions, an agent trying to post your API key, a chained shell command, a forged agent message, scope escalation, an agent loop, memory poisoning, and an attacker editing the audit log. Each prints its verdict and the layers it passed through:

```
[BLOCK]    2. Scout tries outbound POST suggested by the page
    gsx=['GSX-02', 'GSX-05'] sev=S2
    reason=action requested by untrusted content, not by owner
    trace=L0:origin=T3 args=T1 task=T3 -> L1:clean -> L2:action originates from T3
```

## 2. Attack your own install

```bash
genesis-security redteam
```

45 attack cases. `PASS` means the attack was stopped. `MISS` lines are informational: the L1 scanner didn't recognise a rephrased injection, and the matching `-L2` line shows the action was still blocked. The exit code is the number of real failures. It should be 0.

## 3. Guard a tool

```python
from genesis_security import GenesisSecurityGate, Tier

def ask_owner(verdict, ctx) -> bool:
    return input(f"[HOLD] {verdict.reason}\nAllow? [y/N] ").strip().lower() == "y"

gate = GenesisSecurityGate.from_env(owner_confirm=ask_owner)   # needs GENESIS_SECURITY_KEY

@gate.guard("read_file")
def read_file(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()

@gate.guard("delete_file")
def delete_file(path: str) -> str:
    import os; os.remove(path); return f"deleted {path}"

me = {"agent": "main", "task_id": "t1", "origin_tier": Tier.T1}

read_file({"path": "notes.md"}, me)             # ALLOW — you asked, reversible
delete_file({"path": "old.md"}, me)             # HOLD  — you're asked to confirm
delete_file({"path": "old.md"},                 # BLOCK — the request came from content
            {**me, "origin_tier": Tier.T3})     #         → PermissionError
```

## 4. Feed it untrusted content

```python
page, verdict = gate.on_external_content("https://news.example/x", html, task_id="t1")
print(verdict.verdict, verdict.gsx)   # e.g. ALLOW_SANITIZED ['GSX-01', 'GSX-02']
llm_input = page.value                # wrapped: <untrusted source=... scan=...> ... </untrusted>
```

## 5. Check the log

```bash
genesis-security checkpoint genesis_security_audit.jsonl > cp.json
genesis-security verify-audit genesis_security_audit.jsonl --checkpoint cp.json
```

Keep `cp.json` somewhere your agents can't write.

## Where next

- Put it into a real agent: [Integration Guide](Integration-Guide)
- Copy a setup for your use case: [Recipes](Recipes)
- Understand why it decided what it did: [The Security Loop](The-Security-Loop)
