# Changelog

## Unreleased (1.1.0)

### Security — behaviour change (GS-AUD-03, issues #2 #3)

**What changed:** policies are now validated strictly, and a policy that fails to load puts the gate in **deny-all**.

| Before (≤ 1.0.0) | After (1.1.0) |
|---|---|
| Missing sections became empty lists. A policy without `[tools]` made nothing irreversible; without `[secrets]`, nothing was treated as a secret | `[egress]`, `[tools]`, `[secrets]` are required; a missing one is a load error |
| Unknown keys and typo'd sections (`[tool]`) were ignored | Load error, with a "did you mean…?" hint |
| Invalid regex crashed with `re.error`; wrong types were coerced or ignored | Load error naming the key |
| `Policy.load()` raised on unreadable files / bad TOML with raw exceptions | Always `PolicyError` with `.errors` listing every problem |
| `GENESIS_SECURITY_POLICY` with a broken file raised at start-up | Gate starts in **deny-all**: every tool call, message, memory write and skill load is BLOCK; one `policy_load_failed` audit event; error logged |

**Am I affected?** Run `genesis-security policy check <your policy>`. If it prints `OK`, nothing changes for you.

Shipped under the security-compatibility policy (ADR-0008 §3, Governance R4): stricter-only, announced here.

### Added
- `genesis-security policy check FILE...` — validates policy files, lists every problem, exit 1 if any is invalid
- `GenesisSecurityGate(policy_path=...)`, `gate.status()`, `gate.policy_ok`, `PolicyError`
- Red-team cases P1–P4 (policy integrity); 49 cases total
- 29 regression tests (`tests/test_policy_validation.py`), committed before the fix and failing on 1.0.0

## 1.0.0 — 2026-11-20

First public release.

- L0–L5 gate with five hooks: external content, tool calls, agent messages, memory writes, skill loads
- 13 threat classes (GSX-01 … GSX-13)
- HMAC-signed agent envelopes with scope, hop budget, and taint propagation
- Append-only SHA-256 audit chain with file locking (POSIX + Windows) and rotation
- TOML policy, env-based key loading, fail-closed brain adapters for Claude (API) and Ollama (local)
- CLI: `demo`, `scan`, `verify-audit`, `keygen`, `pin`, `policy`
- Thai-aware injection scanning (handles NFKC splitting of สระอำ)
- Red-team hardened before release (see docs/redteam-report.md): 22 bypasses found across two rounds and fixed —
  wrapper breakout, URL/egress evasions, encoded and split secrets, `python -c` / `git -c`,
  agent message replay / misdelivery / staleness, memory rule phrasing, audit rewrite / truncation / deletion
- HMAC-keyed audit chain, `checkpoint` command, `verify-audit --checkpoint`
- `genesis-security redteam` command; red-team suite runs in CI
- 43 unit tests + 45 red-team cases, stdlib only
