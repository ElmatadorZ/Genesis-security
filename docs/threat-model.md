# Threat model

## Trust tiers

| Tier | Source | May |
|---|---|---|
| T0 | system prompt, owner config | set policy |
| T1 | owner, directly | give tasks, approve the Human Gate |
| T2 | internal agent with valid signature | send results and requests; cannot widen scope |
| T3 | web, files, email, tool output, MCP results, unsigned agents | be read as data only |

## GSX threat classes

| ID | Threat | Enforced by |
|---|---|---|
| GSX-01 | Direct prompt injection | scanner L1, gate L2 |
| GSX-02 | Indirect injection (web, files, tool output) | `on_external_content`, L2 origin check |
| GSX-03 | Forged authority ("[SYSTEM]", "owner approved") | scanner L1 |
| GSX-04 | Tool poisoning / MCP rug-pull | `on_skill_load` pinning (apply to tool descriptions too) |
| GSX-05 | Confused deputy | L2 origin check, shell allowlist |
| GSX-06 | Data exfiltration | L3 egress allowlist, secret patterns, trifecta |
| GSX-07 | Agent impersonation | HMAC envelopes |
| GSX-08 | Memory / Genome poisoning | `on_memory_write` fact-only from T3 |
| GSX-09 | Goal drift | brain (SKILL.md L4); not enforceable by regex |
| GSX-10 | Loops / resource exhaustion | hop budget |
| GSX-11 | Privilege escalation chain | scope check |
| GSX-12 | Supply-chain skill injection | SHA-256 pins + scan |
| GSX-13 | Audit tampering | hash chain, `verify-audit` |

## Genesis Mind / SkynetClaw component map

| Component | Main surface | GSX | Mitigation |
|---|---|---|---|
| Volition / Core Will | goal overwritten from T3 | 09 | goals from T0/T1 only; diff every plan revision |
| Agent Council | fake members, collusion | 07, 11 | envelopes, scope caps, separate Sentinel |
| Shadow Gate | told to skip | 03 | non-skippable in SKILL.md |
| Echo Memory / MemoryStore | poisoning | 08 | `on_memory_write` |
| Affective Genome | long-term bias via emotional content | 08, 09 | T3 events don't reweight the council |
| AuditTrail | edit / delete | 13 | hash chain, verify at session start |
| SkynetClaw tools | injection → shell, exfil | 02, 05, 06 | `@gate.guard` on every tool |
| Skill / plugin loader | malicious SKILL.md | 12 | `genesis-security pin`, `on_skill_load` |
| MCP connectors | description changes after install | 04 | pin description hashes |

## Not covered

- Attackers holding the HMAC key or write access to policy files
- Tools that bypass the gate
- Model-level jailbreaks that don't involve tool use (the brain layer helps; the body can't)
- Host compromise — use OS sandboxing and least-privilege credentials
