# ADR-0005: Per-agent keys via HKDF; key provenance; rotation and revocation

- Decision: **Proposed**
- Implementation: **Not approved** (Governance D5)
- Date: 2026-11-25 · Revised 2026-11-25 after review (PR #1)
- Closes: GS-AUD-06, GS-AUD-07

## Context

All agents share one HMAC key: any key holder can sign as anyone and rewrite `hop`/`taint` (GS-AUD-06). Any 16-byte string is accepted as a key (GS-AUD-07). The first draft proposed `HMAC(master, "agent/" + id + "/" + epoch)` and a 32-byte minimum; review correctly noted that the derivation lacked a standard KDF, unambiguous encoding and domain separation, and that **length is not entropy**.

## Decision

### 1. Key provenance, not key guessing

The entropy of a byte string **cannot be measured** from the bytes. Instead the runtime only accepts keys whose *format* shows they came from a CSPRNG tool:

- `genesis-security keygen` emits `gsk1_<base64url(32 random bytes from secrets.token_bytes)>_<crc>` — a versioned prefix, 256 bits from the OS CSPRNG, and a checksum against typos.
- The runtime accepts **only** this format (and future `gskN_` versions). Hex strings, raw text, passwords and padded values are refused, whatever their length.
- Low-diversity sanity checks (e.g. all bytes equal, < 16 distinct byte values) still refuse obviously broken keys, but they are a backstop, not an entropy guarantee.
- Documentation says plainly: keys must come from `keygen` or another CSPRNG; the format check prevents accidents, not determined misuse.

### 2. Derivation: HKDF-SHA256 with domain separation

Per-agent keys use HKDF (RFC 5869) with SHA-256, implemented with stdlib `hmac`:

```
PRK      = HKDF-Extract(salt = deployment_id_bytes, IKM = master_key)
K_agent  = HKDF-Expand(PRK, info, L = 32)
info     = "genesis-security/v1/agent-signing" || 0x00
           || len(agent_id) as 2-byte big-endian || agent_id (UTF-8, NFC)
           || epoch as 4-byte big-endian
```

- Length-prefixed fields make the encoding unambiguous (`"a/b" + "1"` can never equal `"a" + "/b1"`).
- `agent_id`: `^[a-z0-9][a-z0-9._-]{0,63}$`, NFC, compared byte-wise.
- Separate `info` labels for every purpose: `…/agent-signing`, `…/audit-chain`, `…/policy-auth`, `…/state-integrity`. One key is never used for two purposes.
- Known-answer test vectors are published with the implementation.

### 3. Storage and access

- The **master key** lives only with the operator and the verifying gate: an environment variable or a file with mode `0600` owned by the runtime user (Windows: ACL to that user only). The runtime refuses to start if the key file is group/world-readable.
- **Agent processes receive only their own `K_agent`**, never the master key.
- Keys never appear in logs, verdict reasons, audit entries or exceptions (existing redaction + tests).
- OS keychain / HSM / KMS backends are an Enterprise extension behind a `KeyProvider` interface.

### 4. Verification

The verifying gate derives `K_sender` from the envelope's `from` and `epoch` and checks `sig`. A message from A signed with B's key fails. Signature checks use constant-time comparison.

### 5. Epochs, rotation and revocation

- `epoch` is an unsigned 32-bit integer, part of the signed envelope.
- **Rotation:** the operator advances the deployment epoch; verifiers accept `current` and `current − 1` for an overlap window (`rotation_overlap_s`, default 1 hour), then only `current`.
- **Revocation:** a revocation list of `(agent_id, epoch_or_all)` in the state store (ADR-0006). Revoked → `BLOCK` + audit event. Revocation takes effect immediately; it does not wait for the overlap window.
- **Master key compromise:** rotate the master key (new `deployment_id` salt), re-issue all agent keys, start a new audit chain anchored to the old one's final checkpoint.

### 6. Asymmetric option

With the `[crypto]` extra (ADR-0002), agents may hold private signing keys and verifiers only public keys, removing the master key from verifying gates. The envelope format reserves an `alg` field for this.

## Consequences

- A compromised worker agent can no longer impersonate others or forge envelopes for them.
- With HMAC, the verifying gate remains a high-value secret holder; the asymmetric option removes that.
- Existing v1 keys (hex or text) are refused in v2.0; v1.x warns. `keygen` output from v1 (hex) can be converted with a migration command.
