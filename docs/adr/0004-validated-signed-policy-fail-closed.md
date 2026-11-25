# ADR-0004: Validated policy; HMAC authentication vs asymmetric signing; deny-all on failure

- Decision: **Proposed**
- Implementation: **Not approved** (Governance D5)
- Date: 2026-11-25 · Revised 2026-11-25 after review (PR #1)
- Closes: GS-AUD-03, GS-AUD-04

## Context

v1.0 turns missing sections into empty sets and ignores unknown keys; a typo silently removes protections (GS-AUD-03). Anyone able to edit the file can widen the allowlist undetected (GS-AUD-04). The first draft of this ADR proposed HMAC "signing", which over-stated what HMAC gives: a verifier holding the HMAC key can also forge.

## Decision

### 1. Validation before use

- Policies declare `schema = <int>` and `policy_version = "<string>"`. Missing either → load error.
- Strict validation by stdlib code: required sections, types, allowed keys, closed capability set, value constraints (no wildcard hosts unless `allow_wildcards = true`), every regex compiled.
- Validation runs **before** any part of the policy is used. A policy object exists only if validation passed.

### 2. Two integrity modes, named for what they prove

| Mode | Mechanism | Proves | Does **not** prove | For |
|---|---|---|---|---|
| **A. Policy authentication** (Core) | HMAC-SHA256 under a dedicated *policy key*, separate from agent and audit keys | The file was produced by a holder of the policy key and not modified since | That the author is not the runtime host. **Anyone who obtains the policy key — including an attacker who compromises the runtime host — can produce valid policies** | Self-hosted deployments that trust the operator and the runtime machine |
| **B. Policy signing** (optional `[crypto]` extra, ADR-0002) | Asymmetric signature (e.g. Ed25519); runtime holds only the public key | The file was signed by the policy author's private key, which the runtime never holds | Protection if the author's key is stolen | Organizations that separate policy authors from runtime operators |

- The configuration names the mode explicitly (`integrity = "none" | "hmac" | "signature"`). No silent fallback from B to A, or from A to none.
- `integrity = "none"` is allowed in Core v2.0 for local development and logs `NOT SECURE ENFORCEMENT` at load. Enterprise defaults to B.

### 3. Canonical fingerprint

`policy_fp = SHA-256(canonical bytes)`, where canonical bytes are the parsed policy re-serialized deterministically: keys sorted, UTF-8, normalized numbers and booleans, no comments or whitespace. Signatures (A or B) cover the canonical bytes, so formatting changes don't break them and semantic changes always do.

### 4. Load, change and reload

- **Initial load fails** (missing, unreadable, invalid TOML, schema error, integrity failure) → the gate enters **deny-all**: every tool call `BLOCK`, every memory write and skill load `BLOCK`, every agent message `BLOCK`, external content still wrapped as T3. Not merely "tier T3": no action of any kind is permitted.
- **Reload is atomic:** parse, validate and verify the new policy fully into a new object; swap a single reference only if all checks pass. In-flight decisions finish under the policy they started with.
- **Reload fails** → keep the **current** policy (never a more permissive one, never the packaged default), emit `policy_reload_failed` audit event and a loud error.
- **Every change is audited:** `policy_loaded` / `policy_reloaded` events carry old and new `policy_fp`, `policy_version`, integrity mode and who triggered it.
- Each verdict's ledger entry carries the `policy_fp` it was decided under (ADR-0007).
- **Downgrade protection:** a reload whose `policy_version` is lower than the current one is refused unless explicitly forced by an operator command, which is itself audited.

## Consequences

- Misconfiguration fails safe; the cost is availability, which is visible immediately.
- Documentation and the CLI must call mode A "authentication", never "signing".
- Mode B adds the only optional dependency in the architecture (ADR-0002).
