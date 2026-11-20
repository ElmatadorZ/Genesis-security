# Changelog

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
