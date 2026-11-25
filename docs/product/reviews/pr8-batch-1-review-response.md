# PR #8 batch 1 (ADR-0005, ADR-0009) — response to review

Review decision received: **Changes Requested** — 4 BLOCKERs, 4 REQUIRED, 3 ADR-0005 additions (2026-11-25). Fixed in the order requested: B1 → B2 → B3/B4 → R1–R4 → additions. All ADRs remain **Proposed**; implementation not approved.

## BLOCKERs

| ID | Finding | Resolution | Where |
|---|---|---|---|
| **B1** | A signature proves who signed, not that the flow state is true; A can sign `classes = {}` | Flow state is recorded and attested **by the Security Runtime**, never authored by agents. In mode 02 agents hold no envelope-signing credential; the runtime builds envelopes from store-recorded state. Receivers raise to the **store-recorded** sender state; envelopes can only raise. Missing/mismatched evidence → owner-only + T3 + GSX-07 | ADR-0009 §2; ADR-0005 §3; backlog P1-19 (AC 2–6), P1-22a |
| **B2** | Confidentiality and integrity conflated | Two axes: confidentiality (classes, readers; join = union/intersection) and integrity (tier, provenance; meet = least trusted). Cross-case tests required | ADR-0009 §1, §3; backlog P1-19 AC 1 |
| **B3** | Race between concurrent read and egress | Pre-raise before a read runs; release data only after commit; egress decision read + record under `BEGIN IMMEDIATE`; side effect only after commit; every failure → BLOCK. Restart, lock and write-failure tests required | ADR-0009 §4; backlog P1-19 AC 7 |
| **B4** | URL check alone insufficient | Sink resolution policy: gateway performs egress; canonicalization with BLOCK on ambiguity; exact scheme/host/port/path/method; redirects off (or same-sink only); single DNS resolution, no private ranges; env proxies ignored; principal verified by TLS (pin/mTLS optional); recipient fields allowlisted; `onward_sharing_basis` records assumption vs contract vs technical control | ADR-0009 §5; backlog P1-20 AC 2–3 |

## REQUIRED

| ID | Resolution | Where |
|---|---|---|
| **R1** | Wording adopted: format validates encoding/version, does not prove entropy or provenance. Provisioning rules (CSPRNG via `secrets.token_bytes(32)`, no logging, permissions, own-key-only, identity↔key binding recorded by fingerprint). `sign()` has no identity argument; providers are bound to one identity at provisioning | ADR-0005 §3, §4 |
| **R2** | Declassification taxonomy: model may only request; runtime automatic never; human-approved and owner-authorized scoped policy rules only. Required record fields; single-use tokens bound to session, class, scope, nonce, expiry | ADR-0009 §8; backlog P1-20 AC 4 |
| **R3** | Envelopes carry `policy_id`, `policy_version`, `schema_version`, `policy_fp`; table of receiver actions (unknown class → owner-only; unknown reader dropped → BLOCK on egress; newer schema → BLOCK; other deployment → owner-only, T3; receiver never lowers) | ADR-0009 §10; ADR-0005 §6 |
| **R4** | Runtime-generated session/task IDs; parent references; clean task needs single-use owner approval and does not change the parent; inputs into a session carry origin state; cross-session transfers logged | ADR-0009 §10; backlog P1-19 AC 8 |

## ADR-0005 additions

| Item | Resolution |
|---|---|
| HKDF salt | `deployment_id` = 16 CSPRNG bytes at `init`, used raw, stored in state `meta` + operator backup, never reused, changes only on master-key compromise rotation (§5) |
| Epoch | Per identity, highest-issued stored; deployment-wide rotation bumps all; no rollback below `current − 1`, including after restore (§7) |
| URI canonicalization | Reject, never normalise: scheme, trust domain, segment rules; no `%`, no non-ASCII, no userinfo/port/query/fragment (§2) |
| HKDF test vectors | Implementation reproduces RFC 5869 Test Case 1; Genesis vectors for two identities and two epochs published (§5) |

## Where we qualify the review

1. **B1 has a process-boundary precondition.** Runtime attestation defeats a manipulated model in every deployment, but defeats **compromised agent code** only when the runtime runs out of process: Python has no memory isolation inside one process. ADR-0009 §2 states this and limits the cross-agent claim to out-of-process runtimes. Cross-host relays need runtime-to-runtime attestation (Enterprise, out of Core v2.0 scope).
2. **B2 wording.** The review says combining "must not raise confidentiality automatically". Read literally, that would let private + public data become less restricted than private data. We implemented the intended rule: combining never **lowers** confidentiality (it only adds classes and narrows readers) and never **raises** integrity.
3. ~~B3 is closed mainly by ordering.~~ Withdrawn in round 2 (see below).

## Consistency edits outside batch 1

So that batches 2 and 3 do not contradict the revised ADRs: threat model F3, F4 (+F4b–F4e), F7 (+F7b); architecture deployment shapes (out-of-process runtime); backlog P1-19, P1-20, P1-22a acceptance criteria. These will be reviewed with batches 2 and 3.

## Round 2 (2026-11-25) — Changes Requested: B3, B4 open; B1 clarify; R3 expand

| Item | Resolution | Where |
|---|---|---|
| **B3** stale authorization | Corrected wording: *the read-release ordering closes the race between data disclosure and flow-state elevation; egress authorization still requires a version-bound permit and revalidation before the external side effect to prevent stale authorization.* Added: frozen payload + digest; single-use permit bound to session, sink, payload digest, state version, policy fp, short expiry; revalidate-and-consume transaction immediately before sending, re-evaluating if the version changed; at-most-once restart rules (`issued` → expired, `consumed` without outcome → `unknown`, never auto-retried). No claim that a transaction makes a network call atomic. New tests listed | ADR-0009 §4, §11 |
| **B4.1** principal ≠ hostname | Verification levels named separately with what each proves; `spiffe://` principal allowed only with `mtls-spiffe`, otherwise policy load fails; `mtls-spiffe` rejected as unsupported until its conformance tests pass | ADR-0009 §5.8 |
| **B4.2** recipient fields | `recipient_mode` fixed/fields; locations header, query, path, body (JSON Pointer), form, metadata (to/cc/bcc, channel, thread); every occurrence and array element checked; `arguments_closed = true` required in mode 02; tools with selectors the gateway cannot see are unsupported in mode 02 | ADR-0009 §5.9 |
| **B4.3** pooling | Pool keyed by sink, verified IP, port, verification mode, pins; no cross-sink reuse, no HTTP/2 coalescing; closed on policy reload, sink change and after bounded lifetime | ADR-0009 §5.6 |
| **B1** clarity | Runtime is the technical signer, signing on behalf of the agent identity; signature does not prove the agent produced the state; sender identity checked against the session's store record; "shared store" defined as one authoritative store writable only by the deployment's runtimes | ADR-0009 §2 |
| **B2** invariant | Readers are always derived from the receiver's policy for the session's classes plus valid grants; never taken from agents, tools or envelopes | ADR-0009 §1, §10 |
| **R3** fingerprint | `policy_id` (per deployment), `policy_version`, `policy_fp` = SHA-256 of RFC 8785 canonical JSON of the validated policy; comparison table (same / previous / unknown); receiver never imports sender rules | ADR-0009 §10 |
| ADR-0005 restore | Restore treated as master-key rotation (new master + `deployment_id`, re-provision); silent store+backup rollback stated as undetectable in Core, needs an external anchor (Enterprise) | ADR-0005 §7 |
| ADR-0005 URI labels | Per-label DNS rules (1–63, hyphen not at either end of any label, no `xn--`, ≥2 labels, no all-digit TLD, ≤253); stated as stricter than SPIFFE | ADR-0005 §2 |

Only these points were changed; batches 2 and 3 untouched except the backlog acceptance criteria for P1-19/P1-20 below.

## Round 3 (2026-11-25) — B1, B3, B4.1, ADR-0005 accepted; B2 formula, R3 downgrade, B4.2 scope open

| Priority | Item | Resolution | Where |
|---|---|---|---|
| 1 | **B2** grants widened readers across classes | Formula corrected to `⋂_c (policy.readers(c) ∪ grants(session, c))`; grants stored per class; empty classes → normal Gate rules; invariant sentence adopted; accounts/payroll worked example | ADR-0009 §1, §8 |
| 1 | **R3** downgrade | Durable current + previous `(version, fp)` pairs; version and fp checked together; table covers older, inconsistent, newer and unknown; receiver always evaluates under its current policy | ADR-0009 §10 |
| 1 | **B4.2** scope | `arguments_closed` covers every location; protocol-managed headers gateway-only; `allow` grammar = exact or trailing `*`; single decode, no normalisation; duplicates and undeclared locations BLOCK | ADR-0009 §5.9 |
| 2 | B3 versions | Permit and ledger carry issued / revalidated / consumed versions | ADR-0009 §4 |
| 2 | B3 exact bytes | Digest is over the wire bytes the gateway's own serialiser writes; no post-digest transformation; compared at send | ADR-0009 §4 |
| 2 | B4.3 proxy DNS, pool identity | `CONNECT <verified IP>`; hostname-only proxies unsupported in mode 02; mTLS pool keyed by client SVID, epoch, trust-bundle fp, closed immediately on change; SPKI example marked placeholder | ADR-0009 §5.6–5.7 |
| 2 | R3 RFC 8785 | Effective policy with defaults; I-JSON subset enforced before hashing; conformance by RFC examples + vectors, not `json.dumps` | ADR-0009 §10 |
| 2 | ADR-0005 anchor | Anchor only to a checkpoint from outside the restored store; otherwise `continuity: unverified` | ADR-0005 §7 |
| 3 | Tests | P1-19 AC 7c, 7d, 9b, 9c; P1-20 AC 2; P1-22a AC 1f | backlog |

Reviewer's agreement that B1 needs the out-of-process precondition, and that the review was of pasted text rather than an independent check of commits or CI, is noted.

## Round 4 (2026-11-25) — B2, B3.1, B4.3, ADR-0005 anchor accepted; R3, B4.2 small changes; B3.2 clarify

| Item | Resolution | Where |
|---|---|---|
| R3.1 monotonic install | Strictly increasing `policy_version` per `policy_id`; lower or reused versions rejected; new lineage only via audited owner operation `policy new-lineage` | ADR-0009 §10 |
| R3.2 integer range | −(2⁵³ − 1) … 2⁵³ − 1 inclusive; ±2⁵³ rejected; boundary tests | ADR-0009 §10; backlog 9c |
| B4.2.1 duplicates after decoding | Duplicates detected on decoded keys | ADR-0009 §5.9 step 4 |
| B4.2.2 parse order, delimiters | Gateway is the only encoder (structured fields); for supplied URLs/forms: split on raw structure → decode once → reject reserved/encoded delimiters → dedupe → re-encode; no re-decoding inside the boundary; remote decoding stated as outside it | ADR-0009 §5.9 |
| B4.2.3 JSON recursion | Recursive at every depth, keys compared after unescaping | ADR-0009 §5.9 |
| B3.2 wording | One immutable buffer; digest = HTTP application bytes, not TLS ciphertext; verified before the first byte; the same buffer object is written; no re-serialisation | ADR-0009 §4 |
| B2 scope note | Grants already stored as (session_id, class, scope); scope checked on every use (§8 tokens) | — |
