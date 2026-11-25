# ADR-0005: Agent identity, credentials and authorization — separated

- Decision: **Proposed** · Reviewer direction: URI identity approved in principle (architecture review round 2, 2026-11-25)
- Implementation: **Not approved**
- Date: 2026-11-25 · Revised twice after review (PR #1 round 1; round 2)
- Closes: GS-AUD-06, GS-AUD-07

## Context

All agents share one HMAC key: any key holder can sign as anyone and rewrite `hop`/`taint`/flow state (GS-AUD-06). Any 16-byte string is accepted as a key (GS-AUD-07). v1 agent IDs are free-form strings that mix "who" with "how it proves it".

Industry work on agent identity is converging on workload-identity standards: the IETF draft [draft-ietf-wimse-aims](https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/) describes AI agents using SPIFFE, WIMSE, OAuth and OpenID SSF. It is an **Internet-Draft, not an RFC**, and may change.

## Decision

### 1. Three things, three lifecycles

| Concept | What it is | Example | Changes when |
|---|---|---|---|
| **Identity** | A stable name for an agent | `spiffe://genesis.local/agents/skynet` | The agent is retired or renamed — never on key rotation |
| **Credential** | Proof that a sender controls the identity | HMAC key derived for that identity (Core v2.0) | Rotation, revocation, compromise |
| **Authorization** | What the identity may do | Roles, scopes, capabilities, flow readers (ADR-0003, ADR-0009) | Policy changes |

Code, policy and audit refer to **identities**. Only the credential provider touches keys.

### 2. Identity format

- An identity is a URI: `spiffe://<trust-domain>/<path>`. The SPIFFE ID shape is used because it is widely deployed and simple; Genesis validates the shape itself (stdlib), it does not depend on SPIFFE software.
- `trust-domain`: lowercase DNS-like label set chosen by the operator (`genesis.local` by default for self-hosted). Path segments `[a-z0-9._-]`, max 255 characters total, NFC.
- **No secrets, tokens or credentials in an identity URI.** Ever. The validator rejects query strings, fragments and userinfo.
- The owner is an identity too (`spiffe://<td>/owner` or a named human principal), so flow readers (ADR-0009) and audit records use one namespace.
- v1 string IDs map to `spiffe://genesis.local/agents/<id>` during migration.

### 3. Credentials: provider interface

```
CredentialProvider
  sign(identity, epoch, bytes) -> signature        # sender side
  verify(identity, epoch, bytes, signature) -> bool
  rotate(identity) / revoke(identity, epoch|all)
```

- **Default provider (Core v2.0): HMAC-SHA256** with keys derived by HKDF (below).
- Future providers plug in behind the same interface: asymmetric keys with the `[crypto]` extra (ADR-0002), and WIMSE/SPIFFE credentials (X.509-SVID, JWT-SVID or WIMSE tokens) when those specifications stabilise.
- **Documentation must not claim WIMSE or SPIFFE support** because identities look like SPIFFE IDs. The claim is limited to: *identity format compatible with SPIFFE IDs; credential providers designed for future interoperability.*

### 4. Key provenance, not key guessing

Entropy cannot be measured from bytes, so the runtime only accepts keys whose format shows they came from a CSPRNG tool:

- `genesis-security keygen` emits `gsk1_<base64url(32 bytes from secrets.token_bytes)>_<crc>`.
- Only `gskN_` keys are accepted; hex, raw text, passwords and padded values are refused whatever their length. Low-diversity checks remain as a backstop, not an entropy guarantee.

### 5. Derivation: HKDF-SHA256 with domain separation

```
PRK      = HKDF-Extract(salt = deployment_id_bytes, IKM = master_key)
K_ident  = HKDF-Expand(PRK, info, L = 32)
info     = "genesis-security/v1/agent-signing" || 0x00
           || len(identity_uri) as 2-byte big-endian || identity_uri (UTF-8, NFC)
           || epoch as 4-byte big-endian
```

- Length-prefixed fields: no two (identity, epoch) pairs can produce the same `info`.
- Separate labels per purpose: `…/agent-signing`, `…/audit-chain`, `…/policy-auth`, `…/state-integrity`.
- Known-answer test vectors ship with the implementation.

### 6. Storage and access

- Master key only with the operator and verifying gate: env var or a `0600` file owned by the runtime user (Windows: owner-only ACL). Refuse to start on wider permissions.
- Each agent process receives only its own `K_ident`.
- Keys never appear in logs, reasons, audit entries or exceptions.

### 7. Rotation and revocation (credential lifecycle — identity unchanged)

- `epoch` (uint32) is part of the signed envelope. Rotation advances it; verifiers accept `current` and `current − 1` for `rotation_overlap_s` (default 1 h).
- Revocation list `(identity, epoch | all)` in the state store; effective immediately; `BLOCK` + audit.
- Master key compromise: new `deployment_id` salt, re-issue all credentials, new audit chain anchored to the old final checkpoint. Identities stay the same.

## Consequences

- A compromised worker can no longer impersonate others; audit and policy speak in stable identities.
- With the HMAC provider, the verifying gate remains a secret holder; asymmetric or WIMSE providers can remove that later without changing identities.
- Migration: v1 string IDs and hex keys are converted by a migration command; v1.x warns, v2.0 refuses old formats.
