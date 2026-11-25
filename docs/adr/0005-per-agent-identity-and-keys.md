# ADR-0005: Agent identity, credentials and authorization — separated

- Decision: **Proposed** · Reviewer direction: URI identity approved in principle (architecture review round 2, 2026-11-25)
- Implementation: **Not approved**
- Date: 2026-11-25 · Revised after PR #1 round 1, review round 2, and PR #8 batch 1 rounds 1 and 2
- Closes: GS-AUD-06, GS-AUD-07

## Context

All agents share one HMAC key: any key holder can sign as anyone and rewrite `hop`/`taint`/flow state (GS-AUD-06). Any 16-byte string is accepted as a key (GS-AUD-07). v1 agent IDs are free-form strings that mix "who" with "how it proves it".

Industry work on agent identity is converging on workload-identity standards: the IETF draft [draft-ietf-wimse-aims](https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/) describes AI agents using SPIFFE, WIMSE, OAuth and OpenID SSF. It is an **Internet-Draft, not an RFC**, and may change.

## Decision

### 1. Three things, three lifecycles

| Concept | What it is | Example | Changes when |
|---|---|---|---|
| **Identity** | A stable name for an agent | `spiffe://genesis.local/agents/skynet` | The agent is retired or renamed — never on key rotation |
| **Credential** | Proof that a message was produced for that identity by the party holding its key | HMAC key derived for that identity (Core v2.0) | Rotation, revocation, compromise |
| **Authorization** | What the identity may do | Roles, scopes, capabilities, flow readers (ADR-0003, ADR-0009) | Policy changes |

Code, policy and audit refer to **identities**. Only credential providers touch keys.

### 2. Identity format and canonicalization

An identity is a URI of the form `spiffe://<trust-domain>/<path>` (SPIFFE ID shape; Genesis validates it with stdlib code and does not depend on SPIFFE software). Validation **rejects** anything ambiguous instead of normalising it, so two different strings can never name the same identity:

| Rule | Reject if |
|---|---|
| Scheme | not exactly lowercase `spiffe` |
| Trust domain | Checked as a DNS name, label by label: each label 1–63 characters of `[a-z0-9-]`, no leading or trailing hyphen in **any** label, no label beginning `xn--` (IDN look-alikes are out of scope), no empty label (so no leading, trailing or double dot), at least two labels, last label not all-digits (no IP literals), whole name ≤ 253 characters. This is **stricter than the SPIFFE specification** (which also allows `_`); a valid SPIFFE ID may therefore be rejected, deliberately |
| Path | empty; empty segment (`//`); `.` or `..` segment; trailing `/`; characters outside `[a-z0-9._-]` per segment |
| Encoding | any `%` (no percent-encoding at all); non-ASCII |
| Components | userinfo, port, query or fragment present |
| Length | whole URI > 2048 bytes |

- **No secrets, tokens or credentials in an identity URI.** The rules above make it structurally impossible to carry a query or userinfo.
- The owner is an identity too (`spiffe://<td>/owner` or a named human principal).
- v1 string IDs map to `spiffe://genesis.local/agents/<id>` during migration (IDs that fail the rules are rejected, not rewritten).

### 3. Credentials: providers bound to one identity at provisioning (closes R1 last point, supports B1)

```
CredentialProvider            # one instance per identity, created at provisioning
  identity -> str             # fixed; cannot be changed after creation
  sign(bytes) -> signature    # no identity argument
  epoch -> int

CredentialVerifier
  verify(claimed_identity, epoch, bytes, signature) -> bool
```

- `sign()` has **no identity parameter**: a provider can only sign for the identity it was provisioned with. Agent A's provider cannot produce a signature that verifies as Agent B by passing a different argument.
- The verifier derives the key for the **claimed** identity and checks the signature; a signature made with A's key never verifies under B's identity.
- **Who holds providers (ADR-0009 §2):** in mode 02 with an out-of-process runtime, providers live in the **Security Runtime**, which signs envelopes on the agent's behalf from recorded state; agent processes hold no signing credential. In-process deployments place the provider in the agent's process and therefore do not defend against compromised agent code (stated in ADR-0009 §2).
- **Default provider (Core v2.0): HMAC-SHA256** with keys derived by HKDF (§5). Future providers plug in behind the same interfaces: asymmetric keys with the `[crypto]` extra (ADR-0002), and WIMSE/SPIFFE credentials when those specifications stabilise.
- **Documentation must not claim WIMSE or SPIFFE support** because identities look like SPIFFE IDs. The claim is limited to: *identity format compatible with SPIFFE IDs; credential providers designed for future interoperability.*

### 4. Key generation, format and provisioning (closes R1)

- `genesis-security keygen` generates keys with `secrets.token_bytes(32)` (the OS CSPRNG) and emits `gsk1_<base64url(32 bytes)>_<crc32 hex>`.
- **The key format validates encoding and version, and the checksum catches typing errors. The format does not prove entropy or provenance**: anyone can produce a well-formed `gsk1_` string from a weak source. Low-diversity checks (e.g. all bytes equal) reject obviously broken values but are not an entropy test.
- Assurance comes from the **provisioning process**, which the runtime enforces where it can:
  - keys are generated only by `keygen` (or a documented external CSPRNG/KMS);
  - keys never appear in logs, verdict reasons, audit entries, exceptions or command history (`keygen` writes to a file or stdout on request, never to the ledger);
  - master-key files: mode `0600` owned by the runtime user (Windows: owner-only ACL); the runtime refuses to start on wider permissions;
  - each provider receives only the derived key for its own identity, never the master key;
  - the binding identity ↔ derived key is recorded at provisioning (identity, epoch, key fingerprint = first 8 bytes of SHA-256 of the key, never the key).

### 5. Derivation: HKDF-SHA256 with domain separation

HKDF as specified in RFC 5869, implemented with stdlib `hmac` (the implementation must pass RFC 5869 Test Case 1).

```
PRK      = HKDF-Extract(salt = deployment_id, IKM = master_key)
K_ident  = HKDF-Expand(PRK, info, L = 32)
info     = label (ASCII) || 0x00
           || len(identity_uri) as 2-byte big-endian || identity_uri (UTF-8, validated per §2)
           || epoch as 4-byte big-endian
label    = "genesis-security/v1/agent-signing"
```

- **`deployment_id`:** 16 bytes from `secrets.token_bytes(16)`, generated once at `genesis-security init`, stored in the state store `meta` table and in the operator's backup; used raw (not hex) as the salt; **never reused** across deployments; changes only when the master key is rotated after a compromise (§7).
- Length-prefixed fields: no two `(identity, epoch)` pairs can produce the same `info`.
- One label per purpose: `…/agent-signing`, `…/audit-chain`, `…/policy-auth`, `…/state-integrity`. A key is never used for two purposes.

**Test vectors** (for implementations to reproduce; `master_key = 00 01 02 … 1f` (32 bytes), `deployment_id = 00112233445566778899aabbccddeeff`):

| Step | Input | Output (hex) |
|---|---|---|
| PRK | — | `cc37ab72b2ba5af2d3a971ef4ec17da33f14bfe2bc8cb6f53aa78ff3f9e1d400` |
| K_ident | `spiffe://genesis.local/agents/skynet`, epoch 1 | `ea0e38a2b42b8326489a970210e9d0ee67464487801afecc65af7892f7578610` |
| K_ident | `spiffe://genesis.local/agents/skynet`, epoch 2 | `ebf9e53d50a27c17dd6fc08996b78cf59b374e0c12090a7535f57d1b8b73b1cc` |
| K_ident | `spiffe://genesis.local/agents/scout`, epoch 1 | `5879d8d07716225a4505745cb5d6b49f980f2ee23db4b7d453d27a68a5b1842e` |

These were computed with the same construction after it reproduced RFC 5869 Test Case 1 (PRK `0777…b3e5`, OKM `3cb2…7185865`).

### 6. Envelope binding

The signed bytes of every envelope include: sender identity, receiver identity, epoch, `session_id`, `task_id`, flow-state reference and digest (ADR-0009 §2), `hop`, scope, `policy_id` / `policy_version` / `schema_version` / `policy_fp`, timestamp and nonce. Changing any of them invalidates the signature. Replay protection: nonce uniqueness in the state store and a freshness window (ADR-0006 §3).

### 7. Epochs, rotation and revocation (credential lifecycle — identity unchanged)

- **Epochs are per identity**, uint32, stored in the state store with the **highest epoch ever issued** for that identity.
- Rotation for one identity increments its epoch; a deployment-wide rotation increments every identity's epoch.
- Verifiers accept `current` and `current − 1` during `rotation_overlap_s` (default 1 h), then only `current`.
- **No rollback during operation:** the verifier refuses any epoch lower than `current − 1`, and refuses `current − 1` after the overlap ends; the runtime never writes a lower highest-epoch.
- **Restore is treated as master-key rotation.** A highest-epoch value restored together with the store cannot prove that no higher epoch was issued after the backup, so Core does not rely on it. `genesis-security restore` marks the store `restored`; the runtime refuses to start until `genesis-security rotate --after-restore` generates a **new master key and new `deployment_id`**, re-provisions every provider, and starts a new audit chain whose first entry records the restore. The new chain is anchored to the old one **only** to a checkpoint obtained from outside the restored store — one the operator exported and kept separately (`genesis-security checkpoint --export`), or an external anchor. A checkpoint read from the restored store itself may predate the true last entry and is not used as an anchor. If no such checkpoint exists, the first entry states `continuity: unverified`, and reports say the history before the restore cannot be shown complete. Credentials issued before the restore — at any epoch — derive from the old master key and no longer verify, so a rolled-back epoch counter cannot revive them.
- **Silent rollback is out of Core scope.** Someone with write access to the store and its backups can roll both back without using `restore`; Core cannot detect that. Detection needs an anchor outside the store (an externally published audit checkpoint, an OS keychain or hardware monotonic counter); this is an Enterprise option. Write access to the store already defeats revocation, so the threat model treats the store's integrity as a precondition (ADR-0006).
- **Revocation:** `(identity, epoch | all)` in the state store, effective immediately, `BLOCK` + audit, independent of the overlap window.
- **Master key compromise:** generate a new master key **and** a new `deployment_id`, re-provision all providers at the next epoch, start a new audit chain anchored to an exported checkpoint under the same rule as restore. Identities do not change.

## Consequences

- A compromised or manipulated agent cannot sign as another agent; with an out-of-process runtime it cannot sign at all.
- With the HMAC provider the verifying runtime holds the master key; asymmetric or WIMSE providers can remove that later without changing identities.
- Migration: v1 string IDs and hex keys are converted by a migration command; v1.x warns, v2.0 refuses old formats.
