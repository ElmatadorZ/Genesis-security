# ADR-0002: Stdlib-only core; optional asymmetric cryptography

- Decision: **Proposed**
- Implementation: **Records existing code** (stdlib-only); the optional crypto extra is **Not approved**
- Date: 2026-11-25 · Revised 2026-11-25 after review (PR #1)

## Context

A security component's own supply chain is part of its attack surface, and the owner's architecture principle is sovereign: no third-party frameworks. But the Python standard library has **no public-key signatures** (no Ed25519, no ECDSA). HMAC-SHA256 is a message *authentication* code: whoever can verify can also forge. It is not a substitute for a digital signature when the verifier must not be able to sign.

## Decision

1. **Core has zero runtime dependencies** beyond CPython 3.11+. Core runs fully offline and self-hosted.
2. **Core security properties are defined only in terms of what Core can provide**: HMAC-SHA256, SHA-256, HKDF built on `hmac`, `secrets`, `sqlite3`. No Core guarantee depends on public-key crypto.
3. **Asymmetric cryptography is kept in the architecture as an optional, isolated extra** (`genesis-security[crypto]`), not as a Core requirement:
   - Used only where verifier ≠ signer matters: enterprise policy signing (ADR-0004 mode B) and per-agent identities that verifiers check without secrets (ADR-0005 option).
   - Behind a narrow interface (`Signer`, `Verifier`) so the dependency never reaches the rest of Core.
   - Candidate implementation chosen by a separate ADR (dependency review, pinning, SBOM).
   - **Absent extra → the feature is unavailable and the gate refuses configurations that require it.** It never silently falls back to HMAC.
4. Build-time and test-time tooling may use third-party packages if they never ship in the runtime.

## Consequences

- Self-hosted users keep a zero-dependency runtime with honest, HMAC-scoped guarantees.
- Enterprise deployments that need author/verifier separation accept one audited, pinned dependency, by explicit choice.
- Documentation must state for every signature-like feature whether it is HMAC (shared secret) or asymmetric.
