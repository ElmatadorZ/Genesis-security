# ADR-0004: Schema-validated, optionally signed policy; load failure = deny all

- Status: **Proposed**
- Date: 2026-11-25
- Closes: GS-AUD-03, GS-AUD-04

## Context

v1.0 turns missing sections into empty sets and ignores unknown keys. A typo (`[tool]` for `[tools]`) silently removes every irreversible rule (GS-AUD-03). Anyone able to edit the file can widen the allowlist undetected (GS-AUD-04).

## Decision

1. **Schema.** A versioned policy schema (`schema = 2`) validated at load by stdlib code: required sections, types, allowed keys, value constraints (no wildcard hosts unless `allow_wildcards = true`).
2. **Strict by default.** Unknown keys, missing required sections, invalid regexes → load error.
3. **Fail closed.** A gate whose policy failed to load enters **deny-all**: every tool call `BLOCK`, every message T3, with a loud error and an audit entry.
4. **Signed policy (optional, recommended).** `genesis-security policy sign` writes `policy.toml.sig` = HMAC-SHA256 under a *policy key* separate from the agent key. The runtime verifies before use. Unsigned policy is allowed only when `GENESIS_SECURITY_REQUIRE_SIGNED_POLICY` is unset (default off in v2.0, on in Enterprise).
5. **Policy fingerprint** is written to the ledger at load, so audits show which policy each verdict ran under.

## Consequences

- Misconfiguration fails safe; the cost is availability, which is visible immediately.
- HMAC signing means the verifier holds the signing key; true separation of signer/verifier needs asymmetric crypto — see ADR-0002 consequences.
