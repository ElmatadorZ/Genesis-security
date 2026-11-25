# Traceability — security invariants → ADR → backlog → tests

| | |
|---|---|
| Baseline | Batch 1 architecture baseline: ADR-0005 and ADR-0009 as accepted at PR #8 Rev7 (`556224e`) plus errata E1–E2 |
| Status | Proposed. Implementation **not approved**. A row becomes a security claim only when its tests pass on the implementation and are shown failing on the code before it |
| Rule | Every invariant has at least one owning task and at least one negative test. A task with no invariant, or an invariant with no test, is a review finding |

Test kinds: **U** unit · **P** property-based · **C** concurrency (threads + processes) · **R** restart / fault injection · **N** network fixture (local TLS server, DNS stub, proxy) · **A** adversarial suite (Genesis supplementary + AgentDojo, P1-23).

## Identity and credentials

| ID | Invariant | ADR | Task / AC | Tests |
|---|---|---|---|---|
| INV-01 | An identity is a validated URI; ambiguous forms are rejected, never normalised | 0005 §2 | P1-22a AC 1d | U (every rejection row), P (round-trip: accepted ⇒ unchanged) |
| INV-02 | A provider signs only for the identity it was provisioned with; `sign()` takes no identity | 0005 §3 | P1-22a AC 1b | U, A (sign-as-other attempts) |
| INV-03 | In mode 02 out-of-process, agent processes hold no signing credential | 0005 §3, 0009 §2 | P1-22a AC 1 | U (process inspection), A |
| INV-04 | Key derivation is HKDF-SHA256 with length-prefixed `info`; reproduces RFC 5869 TC1 and Genesis vectors | 0005 §5 | P1-22a AC 1c | U (vectors) |
| INV-05 | Epochs never decrease during operation; restore forces master-key and `deployment_id` rotation | 0005 §7 | P1-22a AC 1e, 1f | U, R (restore drill) |
| INV-06 | A new audit chain is anchored only to a checkpoint from outside the restored store, else `continuity: unverified` | 0005 §7 | P1-22a AC 1f | R |

## Flow state

| ID | Invariant | ADR | Task / AC | Tests |
|---|---|---|---|---|
| INV-10 | Confidentiality only rises on combination (classes ∪, readers ∩); integrity only falls (least trusted) | 0009 §1 | P1-19 AC 1 | P (random class/tier sets), U (cross cases) |
| INV-11 | `effective_readers = ⋂_c (policy.readers(c) ∪ grants(session, c))`, computed from the receiver's current policy; readers are never input | 0009 §1 | P1-19 AC 7b, 7c | P, U (accounts/payroll), A (injected readers) |
| INV-12 | Empty `classes` → normal Gate rules; the empty intersection is never evaluated | 0009 §1, §6 | P1-19 AC 1 | U |
| INV-13 | Flow state is recorded and attested by the runtime; agents cannot lower their own or others' state | 0009 §2 | P1-19 AC 2, 3, 5 | U, A |
| INV-14 | Envelopes can only raise the receiver; missing or mismatched store evidence → owner-only, T3 | 0009 §2 | P1-19 AC 6 | U, R (store unavailable) |
| INV-15 | Every signed envelope field (classes, readers, sources, hop, session, policy fields) is covered by the signature | 0005 §6, 0009 §2 | P1-19 AC 4 | P (bit-flip every field) |
| INV-16 | Undeclared tool output is `private:unclassified` and T3 | 0009 §3 | P1-18, P1-19 | U |
| INV-17 | Session and task IDs are runtime-generated; clean tasks need single-use owner approval and leave the parent unchanged | 0009 §10 | P1-19 AC 8 | U, A |

## Ordering and authorization

| ID | Invariant | ADR | Task / AC | Tests |
|---|---|---|---|---|
| INV-20 | Read data is released only after its raise is committed | 0009 §4 | P1-19 AC 7 | C, R |
| INV-21 | Egress needs a single-use permit bound to session, sink, payload digest, version and policy fingerprint | 0009 §4 | P1-19 AC 7 | U, C (double consume) |
| INV-22 | If the version changed before sending, the decision is re-evaluated; the ledger records issued, revalidated and consumed versions | 0009 §4 | P1-19 AC 7, 7d | C, U |
| INV-23 | The hashed buffer is the buffer written; the digest is verified before the first byte; no re-serialisation | 0009 §4 | P1-19 AC 7d | U, N (wire capture) |
| INV-24 | On restart `issued` permits expire unexecuted; unknown outcomes are never retried automatically | 0009 §4 | P1-19 AC 7 | R |
| INV-25 | Any store, lock or write failure → BLOCK | 0009 §4, §9 | P1-19 AC 7, P1-20 AC 5 | R (fault injection) |

## Destination

| ID | Invariant | ADR | Task / AC | Tests |
|---|---|---|---|---|
| INV-30 | The resolved sink, not the agent's claim, is checked; exact scheme, host, port, path prefix, method | 0009 §5.1–5.3 | P1-20 AC 2 | U, N |
| INV-31 | Redirects off by default; enabled redirects must stay within the same sink | 0009 §5.4 | P1-20 AC 2 | N |
| INV-32 | One DNS resolution per connection, private ranges refused unless declared; pool keyed by sink, IP, port, verification and client identity; closed on change | 0009 §5.5–5.6 | P1-20 AC 2 | N (rebinding stub, pool reuse) |
| INV-33 | Proxies receive `CONNECT <verified IP>` only | 0009 §5.7 | P1-20 AC 2 | N (proxy fixture) |
| INV-34 | Verification levels are enforced and reported by name; `spiffe://` principal only with `mtls-spiffe`; `mtls-spiffe` rejected until conformant | 0009 §5.8 | P1-20 AC 2 | U (policy load), N |
| INV-35 | Recipients are checked in every declared location and array element; `arguments_closed` covers every location; protocol headers gateway-only | 0009 §5.9 | P1-20 AC 2 | U, A |
| INV-36 | Structured fields: schema validation, no control characters, gateway encodes. Ready-made strings: authority rules (absolute URLs only), split-then-decode-once, duplicates on decoded keys, dot segments however written | 0009 §5.9 | P1-20 AC 2 | U, P (fuzz parser differentials), A |
| INV-37 | Host classified before comparison; one accepted spelling each for IPv4, IPv6 (RFC 5952) and hostname; the policy loader and the gateway share one validator | 0009 §5.9 | P1-20 AC 2 | U, P |
| INV-38 | `onward_sharing` is reported with its basis and never presented as proof | 0009 §5.10 | P1-20 AC 3 | U (report output) |

## Declassification, policy, boundary

| ID | Invariant | ADR | Task / AC | Tests |
|---|---|---|---|---|
| INV-40 | Only the owner declassifies; model requests change nothing; no automatic declassification | 0009 §8 | P1-20 AC 4 | U, A |
| INV-41 | Approval tokens are single-use, bound to session, class, scope, nonce, expiry | 0009 §8 | P1-20 AC 4 | U, C |
| INV-42 | Version and fingerprint are checked together; the receiver always evaluates under its current policy | 0009 §10 | P1-19 AC 9, 9b | U |
| INV-43 | `policy_version` strictly increases per `policy_id`; new lineage only by audited owner operation | 0009 §10 | P1-19 AC 9d | U |
| INV-44 | `policy_fp` = SHA-256 of RFC 8785 JCS over the effective policy in the enforced I-JSON subset (safe integers, ASCII keys) | 0009 §10 | P1-19 AC 9c | U (RFC examples, boundaries ±(2⁵³−1)) |
| INV-45 | Mode 02 refuses to start with in-process egress tools outside the gateway; `doctor` reports what it verified and what it could not | 0009 §9 | P1-21 | U, A |
| INV-46 | Guarantees are reported only at the level actually deployed (in-process vs out-of-process; verification level) | 0009 §2, §11 | P1-21 | U (doctor output) |

## Coverage check

| Check | Result at this baseline |
|---|---|
| Invariants without a task | 0 |
| Invariants without a negative test | 0 |
| Tasks in P1-18…P1-23 with no invariant | P1-22b (hardening/migration — will inherit INV-01…06), P1-23 (evaluation harness — measures, asserts no invariant) |
| Utility cost | Not an invariant; measured in the [evaluation plan](evaluation-plan-agentdojo.md) |
