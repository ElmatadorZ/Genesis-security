# Architecture

```
genesis_security/
├── tiers.py      L0 primitives: Tier (T0–T3), Tainted, Verdict
├── scanner.py    L1 heuristic injection scanner (EN + TH)
├── policy.py     Policy loaded from TOML
├── default_policy.toml
├── gate.py       GenesisSecurityGate: L2–L5 + five hooks + @guard
├── audit.py      Append-only SHA-256 chain, file lock, rotation
├── demo.py       12 scenarios
└── cli.py        genesis-security command
skill/SKILL.md    Brain: Cognitive OS for Claude
```

## Design rules

1. **Fail closed.** No verdict, brain error, owner-callback crash → BLOCK.
2. **Brain may only tighten.** A semantic reviewer can turn ALLOW into HOLD/BLOCK, never the reverse.
3. **Taint only rises.** Once content has passed through T3 it stays T3, through any number of agents.
4. **Structure beats pattern matching.** L1 regex is a tripwire; L2 (origin) and L3 (egress, secrets, shell, scope) are the wall.
5. **Logs carry no secrets.** The audit trail stores verdicts and small context fields, never raw arguments or content.

## Verdicts

| Verdict | Meaning | Body action |
|---|---|---|
| ALLOW | all layers passed | run |
| ALLOW_SANITIZED | run with cleaned input (`sanitized_args`) or as wrapped data | run cleaned |
| HOLD | owner must decide | `owner_confirm` → ALLOW or BLOCK; no callback = stays HOLD (not run) |
| BLOCK | refused | raise `PermissionError` |

## Severity

S1 secret leaving / irreversible from T3 · S2 injection or escalation · S3 caught & blocked · S4 informational

See [threat-model.md](threat-model.md) for the GSX table and the Genesis Mind / SkynetClaw component map.
