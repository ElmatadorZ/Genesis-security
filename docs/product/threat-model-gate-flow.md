# Threat model — Gate + Flow mode (ADR-0009)

| | |
|---|---|
| Date | 2026-11-25 · aligned with the Batch 1 architecture baseline (ADR-0005, ADR-0009 at commit `556224e` + errata) |
| Applies to | Enforcement mode 02 · Gate + Flow |
| Extends | [Product spec §2a](product-spec-v1.md#2a-threat-model-who-is-trusted-who-is-the-attacker) · threat catalogue GSX-01…10 ([threat model](../threat-model.md)) |
| Status | Proposed, like the ADRs it follows |

## Assets

1. Data of declared private classes (`private:*`) and the owner's control over who receives it.
2. The integrity of flow state, permits, grants and policy versions in the authoritative state store.
3. The identity of senders (agent identities) and of sinks (verified destinations).

## Attacker goals

1. Get private data to a destination that is not an effective reader.
2. Get the runtime to lower flow state, or to act on stale state, without the owner.
3. Make egress reach a destination other than the one that was authorized.
4. Make the runtime evaluate under rules other than the owner's current policy.

## Attacker capabilities by deployment

| Attacker | In-process library | Out-of-process runtime |
|---|---|---|
| Manipulated model (prompt injection, poisoned tool output) | In scope | In scope |
| Compromised agent code | **Not defended** (no memory isolation in one Python process) | In scope |
| Malicious tool or MCP server | In scope for egress through the gateway | In scope for egress through the gateway |
| Network attacker (DNS, proxy, TLS) | In scope | In scope |
| Write access to the state store or its backups | Out of scope (precondition) | Out of scope (precondition) |
| Compromised runtime or host | Out of scope | Out of scope |

## Attacks and responses

| # | Attack | Response in Gate + Flow | Residual |
|---|---|---|---|
| F1 | Model re-encodes a secret (rot13, base64, XOR, unicode tricks, paraphrase) and sends it to an allowlisted host | Destination checked against effective readers; content not inspected (ADR-0009 §6) | None inside the boundary |
| F2 | Send to an allowed domain on an endpoint that forwards to third parties | Sinks are exact scheme/host/port/path/method; `onward_sharing` with a declared basis (§5) | Sink honours `onward_sharing` only to its declared basis |
| F3 | Start a new turn, task or session to "forget" what was read | Runtime-generated IDs with parent references; clean task needs single-use owner approval and leaves the parent unchanged; inputs carry origin state (§10) | — |
| F4 | Launder through another agent (A reads, sends to B, B exfiltrates) | Runtime records A's state and signs on A's behalf; B's runtime raises B to A's store-recorded state; envelopes only raise (§2) | In-process: compromised agent code can reach keys and store |
| F4b | Agent claims clean flow state (`classes = {}`) | Agents never author or sign flow state in mode 02; missing or mismatched store evidence → owner-only, T3 (§2) | Same in-process caveat |
| F5 | Unsigned message or unverifiable provenance | Owner-only, T3, `GSX-07` (§2, §10) | — |
| F6 | Mix classes to find a permissive reader | Readers = intersection over classes (§1, §7) | — |
| F7 | Ask the model to declassify, or replay an old approval | Owner-only declassification; single-use tokens bound to session, class, scope, nonce, expiry (§8) | Owner approving a manipulated request (human factor) |
| F7c | Use a grant for one class to release another class | Grants apply per class before the intersection (§1 formula, §8) | — |
| F8 | Tool reads private data without a `produces` declaration | Defaults to `private:unclassified` (owner-only) and T3 (§3) | Utility loss until declared |
| F9 | Egress outside the gateway (direct socket, subprocess, other process) | Out of guarantee; start-up refusal for in-process tools outside the gateway, OS egress rules required, `doctor` reports (§9) | **Real residual** — deployment responsibility |
| F10 | Leak by choosing *which* allowed action to take | Not prevented by Flow | Addressed only by Plan-Constrained Execution (mode 03) |
| F11 | Covert or timing channels inside an allowed sink | Not prevented | Out of scope |
| F12 | Corrupt or delete flow state | Store errors → BLOCK; tampering detectable through the ledger (ADR-0006, -0007) | Write access to the store is a precondition violation |
| **Ordering and authorization** | | | |
| F13 | Race: egress authorized before a concurrent private read is recorded | Pre-raise before the read, release after commit (§4 read path) | — |
| F14 | Stale authorization: state rises between authorization and the side effect | Version-bound single-use permit; revalidate and re-evaluate before sending (§4) | Outcome may be `unknown` after a crash; never retried automatically |
| F15 | Swap or modify the payload after authorization | Digest over one immutable buffer, verified before the first byte; same buffer written; no re-serialisation (§4) | — |
| F16 | Reuse a permit for another session, sink or payload, or after restart | Permits single-use, bound, short-lived; `issued` permits expire on restart (§4) | — |
| **Destination** | | | |
| F17 | Redirect to another host | Redirects off; if enabled, every hop must resolve to the same sink (§5) | — |
| F18 | DNS rebinding, or reuse of a connection opened for another destination | One resolution per connection; pool keyed by sink, IP, port, verification and client identity; closed on change (§5.5–5.6) | — |
| F19 | Proxy resolves a different address | `CONNECT <verified IP>` only; hostname-only proxies unsupported in mode 02 (§5.7) | — |
| F20 | Claim a stronger destination identity than proven (e.g. a SPIFFE principal over plain TLS) | Verification levels named by what they prove; `spiffe://` principal only with `mtls-spiffe`, otherwise policy rejected (§5.8) | Identity no stronger than the declared level |
| F21 | Switch the recipient through an unchecked field (body, header, query, metadata, channel, thread) | `recipient_mode`, recipient fields in every location, `arguments_closed`, gateway-only protocol headers (§5.9) | Tools whose recipient selection the gateway cannot see are unsupported in mode 02 |
| F22 | Parser differentials: duplicate keys, double encoding, encoded delimiters, dot segments, ambiguous URLs, alternate IP spellings | Gateway is the only encoder; strict split-then-decode-once parsing; duplicates on decoded keys; authority rules; unique host spellings (§5.9) | Remote server's own decoding is outside the boundary — covered by rejecting values whose meaning could change |
| **Policy and identity** | | | |
| F23 | Envelope from an older, inconsistent or unknown policy state | Version and fingerprint checked together; receiver always evaluates under its current policy (§10) | — |
| F24 | Install an older policy version to roll back rules | Strictly increasing `policy_version` per `policy_id`; new lineage only by audited owner operation (§10) | — |
| F25 | Forge a sender identity or sign as another agent | Identity-bound providers held by the runtime; `sign()` has no identity argument; sender checked against session ownership (ADR-0005 §3, ADR-0009 §2) | In-process caveat |
| F26 | Revive old credentials by restoring an older store | Restore forces master-key and `deployment_id` rotation; old credentials no longer verify (ADR-0005 §7) | Silent rollback of store and backups is undetectable without an external anchor (Enterprise) |

## Trust assumptions

- Policy (`data_classes`, `sinks`, `produces`, argument schemas) is correct and integrity-protected (ADR-0004).
- All network and messaging egress of the agent passes through the Execution Gateway (§9).
- For cross-agent guarantees, the runtime runs out of process, and only the runtimes of one deployment can write the authoritative state store.
- The owner reads declassification prompts before approving.

## Not claimed

No security claim here is evidence: each response above becomes a claim only when its acceptance tests ([backlog](backlog.md), [traceability](traceability-adr-backlog.md)) pass on the implementation. Implementation is not approved.
