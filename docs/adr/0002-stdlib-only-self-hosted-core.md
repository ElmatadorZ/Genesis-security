# ADR-0002: Stdlib-only, self-hosted core

- Status: **Accepted** (records the v1.0 design)
- Date: 2026-11-25

## Context

A security component's own supply chain is part of its attack surface. The owner's architecture principle is sovereign: no third-party frameworks.

## Decision

- Core has **zero runtime dependencies** beyond the CPython standard library (3.11+).
- Core runs fully offline and self-hosted. Cloud services are optional integrations, never requirements.
- Optional adapters (model APIs, MCP) live in separate modules and use stdlib HTTP.
- Build-time and test-time tooling may use third-party packages if they never ship in the runtime.

## Consequences

- Cryptography is limited to what `hashlib`/`hmac`/`secrets` provide: HMAC-SHA256 yes; Ed25519 signatures no. Public-key policy signing (ADR-0004) and asymmetric agent identity (ADR-0005) must either use HMAC with key distribution, or accept an *optional* extra. This trade-off is revisited in ADR-0005.
- Persistence uses stdlib `sqlite3` (ADR-0006).
- No async framework; `asyncio` wrappers only.
