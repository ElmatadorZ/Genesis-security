# Changelog

## 1.0.0 — 2026-11-20

First public release.

- L0–L5 gate with five hooks: external content, tool calls, agent messages, memory writes, skill loads
- 13 threat classes (GSX-01 … GSX-13)
- HMAC-signed agent envelopes with scope, hop budget, and taint propagation
- Append-only SHA-256 audit chain with file locking (POSIX + Windows) and rotation
- TOML policy, env-based key loading, fail-closed brain adapter for Claude
- CLI: `demo`, `scan`, `verify-audit`, `keygen`, `pin`, `policy`
- Thai-aware injection scanning (handles NFKC splitting of สระอำ)
- 42 unit tests, stdlib only
