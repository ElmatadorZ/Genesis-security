# Traceability — security invariants → ADR → backlog → test specifications

| | |
|---|---|
| Baseline | Batch 1 architecture baseline (ADR-0005, ADR-0009 at PR #8 Rev7, `556224e`) plus errata E1–E7 |
| Status | Proposed. Implementation **not approved**. Nothing here is evidence that a control works |
| Rule | Every invariant has an owning task and at least one **negative** test specification (an attack or failure that must be refused). An invariant without one is a review finding |

## Status lifecycle

Each invariant and each test moves through these states; a state may be claimed only with the evidence named.

| State | Meaning | Evidence required |
|---|---|---|
| `MAPPED` | Invariant linked to an ADR section and a backlog task | This document |
| `TEST_SPECIFIED` | Test ID, scenario, preconditions and expected result written | Test specification below |
| `IMPLEMENTED` | Test code exists in the repository | Path to the test |
| `PASS_VERIFIED` | Test passes on the implementation in CI | CI run link |
| `REGRESSION_VERIFIED` | Test shown **failing** on the code before the fix and passing after | Both CI runs linked |

**At this baseline every invariant and every test below is `TEST_SPECIFIED`. None is `IMPLEMENTED`.** Earlier wording ("invariants without a negative test: 0") overstated this: it counted test *kinds*, not tests; it is withdrawn.

Test kinds: **U** unit · **P** property-based · **C** concurrency (threads + processes) · **R** restart / fault injection · **N** network fixture (local TLS server, DNS stub, proxy) · **A** adversarial suite (P1-23).

## Invariants

| ID | Invariant | ADR | Task / AC | Tests |
|---|---|---|---|---|
| INV-01 | Identity is a validated URI; ambiguous forms rejected, never normalised | 0005 §2 | P1-22a 1d | GS-ID-001, 002 |
| INV-02 | A provider signs only for its provisioned identity; `sign()` has no identity argument | 0005 §3 | P1-22a 1b | GS-ID-003 |
| INV-03 | Mode 02 out-of-process: agent processes hold no signing credential | 0005 §3, 0009 §2 | P1-22a 1 | GS-ID-004 |
| INV-04 | HKDF-SHA256 with length-prefixed `info`; RFC 5869 TC1 and Genesis vectors reproduced | 0005 §5 | P1-22a 1c | GS-ID-005 |
| INV-05 | Epochs never decrease; restore forces master-key and `deployment_id` rotation | 0005 §7 | P1-22a 1e, 1f | GS-ID-006, 007 |
| INV-06 | New audit chain anchored only to a checkpoint from outside the restored store, else `continuity: unverified` | 0005 §7 | P1-22a 1f | GS-ID-008 |
| INV-07 | Revocation or rotation takes effect immediately: messages BLOCK, pooled connections using the credential close, unconsumed permits are void | 0005 §7, 0009 §4, §5.6 | P1-22a, P1-20 | GS-ID-009, GS-EGRESS-006 |
| INV-10 | Confidentiality only rises on combination; integrity only falls | 0009 §1 | P1-19 1 | GS-FLOW-001, 002 |
| INV-11 | `effective_readers = ⋂_c (policy.readers(c) ∪ grants(session, c))` from the receiver's current policy; grants match session, class, destination and the request's capability; readers never taken as input | 0009 §1, §8 | P1-19 7b, 7c | GS-FLOW-003, 004, 005, 006 |
| INV-12 | Empty `classes` → normal Gate rules; empty intersection never evaluated | 0009 §1, §6 | P1-19 1 | GS-FLOW-007 |
| INV-13 | Flow state recorded and attested by the runtime; agents cannot lower their own or others' state | 0009 §2 | P1-19 2, 3, 5 | GS-FLOW-008, 009 |
| INV-14 | Envelopes only raise; missing or mismatched store evidence → owner-only, T3 | 0009 §2 | P1-19 6 | GS-FLOW-010 |
| INV-15 | Every envelope field is covered by the signature | 0005 §6, 0009 §2 | P1-19 4 | GS-FLOW-011 |
| INV-16 | Undeclared tool output is `private:unclassified` and T3 | 0009 §3 | P1-18, P1-19 | GS-FLOW-012 |
| INV-17 | Runtime-generated session/task IDs; clean task needs single-use owner approval, parent unchanged | 0009 §10 | P1-19 8 | GS-FLOW-013 |
| INV-20 | Read data released only after its raise is committed | 0009 §4 | P1-19 7 | GS-ORDER-001, 002 |
| INV-21 | Egress needs a single-use permit bound to session, sink, digest, version, policy fp | 0009 §4 | P1-19 7 | GS-ORDER-003, 004 |
| INV-22 | Version changed → re-evaluate; ledger records issued / revalidated / consumed versions | 0009 §4 | P1-19 7, 7d | GS-ORDER-005 |
| INV-23 | Hashed buffer is the written buffer; digest verified before the first byte | 0009 §4 | P1-19 7d | GS-ORDER-006 |
| INV-24 | Restart: `issued` permits expire unexecuted; unknown outcomes never auto-retried | 0009 §4 | P1-19 7 | GS-ORDER-007, 008 |
| INV-25 | Any store, lock or write failure → BLOCK, no side effect | 0009 §4, §9 | P1-19 7, P1-20 5 | GS-STORE-001, 002 |
| INV-30 | Resolved sink checked: exact scheme, host, port, path prefix, method | 0009 §5.1–5.3 | P1-20 2 | GS-EGRESS-001 |
| INV-31 | Redirects off; enabled hops must match the same sink on every dimension | 0009 §5.4 | P1-20 2 | GS-EGRESS-002, 003 |
| INV-32 | One DNS resolution per connection; private ranges refused; pool keyed by sink, IP, port, verification, pins, client SVID, credential epoch, trust-bundle fp; closed immediately on change | 0009 §5.5–5.6 | P1-20 2 | GS-EGRESS-004, 005, 006, 007 |
| INV-33 | Proxies receive `CONNECT <verified IP>` only | 0009 §5.7 | P1-20 2 | GS-EGRESS-008 |
| INV-34 | Verification levels enforced and reported by name; `spiffe://` only with `mtls-spiffe` | 0009 §5.8 | P1-20 2 | GS-EGRESS-009, 010 |
| INV-35 | Recipients checked in every location and array element; `arguments_closed` everywhere; protocol headers gateway-only | 0009 §5.9 | P1-20 2 | GS-EGRESS-011, 012, 013 |
| INV-36 | Input parsing per input class (table below) | 0009 §5.9 | P1-20 2 | GS-PARSER-001 … 014 |
| INV-37 | Host classified before comparison; one accepted spelling each; policy loader and gateway share one validator | 0009 §5.9 | P1-20 2 | GS-PARSER-015 … 018 |
| INV-38 | `onward_sharing` reported with its basis and never as proof | 0009 §5.10 | P1-20 3 | GS-EGRESS-014 |
| INV-40 | Only the owner declassifies; model requests change nothing | 0009 §8 | P1-20 4 | GS-DECL-001 |
| INV-41 | Grants single-use (or bounded uses), bound to session, class, readers, actions, nonce, expiry; use consumed with the permit | 0009 §8 | P1-20 4 | GS-DECL-002, 003, 004 |
| INV-42 | Policy compatibility rules of §10 (lineage, version, fp, schema, unknown class, envelope readers) | 0009 §10 | P1-19 9, 9b | GS-POLICY-001 … 007 |
| INV-43 | `policy_version` strictly increases per `policy_id` | 0009 §10 | P1-19 9d | GS-POLICY-008 |
| INV-44 | `policy_fp` = SHA-256 of RFC 8785 JCS over the effective policy in the enforced I-JSON subset | 0009 §10 | P1-19 9c | GS-POLICY-009, 010 |
| INV-45 | Mode 02 refuses to start with *known* egress tools outside the gateway (detection only) | 0009 §9 | P1-21 | GS-BOUND-001 |
| INV-46 | Guarantees reported only at the level actually deployed | 0009 §2, §11 | P1-21 | GS-BOUND-002 |
| INV-47 | `doctor` reports the egress boundary as exactly one of `enforced (probe)`, `configured (unverified)`, `not enforced`, `unknown`, from evidence | 0009 §9 | P1-21 | GS-BOUND-003, 004, 005 |
| INV-48 | Receiver recomputes its own effective-policy fp; mismatch with the stored fp → refuse mode 02 / reject install | 0009 §10 | P1-19 9 | GS-POLICY-011 |
| INV-49 | Policy events follow ledger schema 1; drift, stale, mismatch, unknown are distinct | 0009 §10 | P1-19 9b | GS-POLICY-012 |

### INV-36 — expected behaviour per input class

| Input class | Rule set | Must BLOCK (examples) | Must allow (examples) |
|---|---|---|---|
| Structured fields | Schema per field; no CR, LF, NUL or control characters; gateway encodes | CR/LF in a header value; field not in schema; type mismatch | `to = "user@example.com"` in metadata when schema and `allow` permit |
| Absolute URL | Authority validation → strict parsing | userinfo, fragment, `http://`, `//host`, host ≠ sink, wrong/empty/leading-zero port, `\` or whitespace in authority | `https://api.bank.example/v1/transfers/` for that sink |
| Query string | Strict parsing only (no authority rules) | duplicate keys after decoding; `%25xx`; reserved characters in decoded keys or recipient values | `a=1&b=2` with declared keys |
| Form body | Strict parsing only, `+` → space then percent-decode | duplicate fields after decoding; `+` or reserved characters in decoded recipient values | declared fields with plain values |
| JSON body | Gateway parser; recursive duplicate detection after unescaping | duplicate keys at any depth; `"to"` beside `"to"` | nested objects without duplicates |
| Headers | Case-insensitive duplicate detection; protocol headers gateway-only | `To` and `to`; agent-supplied `Host` or `Content-Length` | declared headers once each |
| Path (any source) | Split on raw `/`, decode once, check decoded segments | `.`/`..` literal, `%2E%2E`, `.%2E`, `%2e.`; `//`; decoded `/ \ ? #` in a segment | declared prefix with plain segments; trailing slash exactly as the sink's `path_prefix` declares |

## Test specifications (negative unless marked +)

| Test ID | Inv. | Kind | Scenario / preconditions | Expected result |
|---|---|---|---|---|
| GS-ID-001 | 01 | U | Each rejection row of ADR-0005 §2 (uppercase scheme, `%`, userinfo, `..` segment, `xn--` label, label > 63, …) | Rejected; no normalised form returned |
| GS-ID-002 | 01 | P | Random valid identities | Accepted unchanged (round-trip) — **+** |
| GS-ID-003 | 02 | U | Provider for A asked to produce a signature that verifies as B | Impossible through the API; a signature by A never verifies under B |
| GS-ID-004 | 03 | U | Inspect agent process environment, files and memory-mapped key stores in out-of-process mode | No signing key, no master key |
| GS-ID-005 | 04 | U | RFC 5869 TC1 and the three Genesis vectors | Outputs match exactly |
| GS-ID-006 | 05 | U | Verifier receives epoch below `current − 1`, and `current − 1` after the overlap | Rejected |
| GS-ID-007 | 05 | R | Restore an older store; start runtime | Refuses until `rotate --after-restore`; pre-restore credentials (any epoch) fail afterwards |
| GS-ID-008 | 06 | R | Restore with and without an exported checkpoint | Anchored chain only with exported checkpoint; otherwise first entry `continuity: unverified` |
| GS-ID-009 | 07 | U | Revoke identity A; A's next envelope | BLOCK + audit, immediately, inside the overlap window |
| GS-FLOW-001 | 10 | P | Random class/tier sets combined | Classes ⊇ inputs, readers ⊆ inputs, tier = least trusted |
| GS-FLOW-002 | 10 | U | `private:accounts`/T1 combined with public/T3 | Result carries `private:accounts` **and** T3 |
| GS-FLOW-003 | 11 | U | accounts {owner, bank-api}, payroll {owner, hr-api}; grant bank-api for accounts; send to bank-api | BLOCK (payroll forbids bank-api) |
| GS-FLOW-004 | 11 | U | Grant for class `accounts` to sink A; request to sink B | BLOCK |
| GS-FLOW-005 | 11 | U | Grant lists action `network`; request has capability `message` | BLOCK |
| GS-FLOW-006 | 11 | A | Agent or envelope supplies a `readers` field naming an attacker sink | Ignored; BLOCK |
| GS-FLOW-007 | 12 | U | Session with no classes | Normal Gate rules apply; no flow error |
| GS-FLOW-008 | 13 | A | Agent A, after reading private data, requests an envelope claiming `classes = {}` | Receiver raised to A's recorded state |
| GS-FLOW-009 | 13 | A | Agent A attempts to send an envelope for B's session | Rejected (session ownership check) |
| GS-FLOW-010 | 14 | R | Store record missing / digest mismatch / version older than envelope | Receiver owner-only, T3, `GSX-07` |
| GS-FLOW-011 | 15 | P | Flip each bit of each signed envelope field | Signature fails for every flip |
| GS-FLOW-012 | 16 | U | Tool without `produces` returns data | Session gains `private:unclassified`, T3 |
| GS-FLOW-013 | 17 | U | Caller supplies its own session ID; clean task without approval; clean task with approval | Rejected; rejected; accepted and parent unchanged |
| GS-ORDER-001 | 20 | C | Worker A reads private data while worker B requests egress, same session, threads and processes | B's egress never authorized against a state missing A's read |
| GS-ORDER-002 | 20 | R | Crash between pre-raise and release | State stays raised; nothing released |
| GS-ORDER-003 | 21 | C | Two workers consume the same permit | Exactly one succeeds |
| GS-ORDER-004 | 21 | U | Permit used for another session, sink or payload; expired permit | Rejected each time |
| GS-ORDER-005 | 22 | C | State raised between authorization and revalidation so the sink is no longer a reader | Re-evaluated, permit revoked, BLOCK; ledger shows issued ≠ revalidated version |
| GS-ORDER-006 | 23 | U | Mutate the buffer after the digest is taken | BLOCK before the first byte is written |
| GS-ORDER-007 | 24 | R | Crash after authorization, before consume | On restart permit `expired`; call not executed |
| GS-ORDER-008 | 24 | R | Crash after consume, before outcome | Outcome `unknown`; no automatic retry |
| GS-STORE-001 | 25 | R | Store write failure before permit commit | BLOCK; no side effect |
| GS-STORE-002 | 25 | R | Lock timeout during revalidation | BLOCK; no side effect |
| GS-EGRESS-001 | 30 | N | Allowed host with wrong path, port, method or scheme | BLOCK |
| GS-EGRESS-002 | 31 | N | Redirect to another host | Aborted before any body is sent |
| GS-EGRESS-003 | 31 | N | Redirect on the same host to another port, path prefix or verified identity | Aborted |
| GS-EGRESS-004 | 32 | N | DNS stub returns a different address on second lookup | Connection uses the first, checked address only |
| GS-EGRESS-005 | 32 | N | Resolution to a private/loopback/link-local address for an undeclared sink | BLOCK |
| GS-EGRESS-006 | 07, 32 | N | Rotate the client credential while a pooled mTLS connection is open | Connection closed immediately; next request opens a new verified connection |
| GS-EGRESS-007 | 32 | N | Change the trust bundle or a pin with pooled connections open; and two sinks on one host | Affected connections closed at once; no cross-sink reuse |
| GS-EGRESS-008 | 33 | N | Proxy fixture records CONNECT targets; hostname-only proxy | Only `CONNECT <IP>:<port>`; hostname-only proxy rejected in mode 02 |
| GS-EGRESS-009 | 34 | U | Policy with `spiffe://` principal and `tls-hostname` | Policy rejected at load |
| GS-EGRESS-010 | 34 | N | `tls-spki-pin` sink presented a valid certificate with a different key | BLOCK; report names the level |
| GS-EGRESS-011 | 35 | U | Recipient changed in an undeclared header, query key, body member, metadata field | BLOCK |
| GS-EGRESS-012 | 35 | U | Array recipient field with one disallowed element | BLOCK |
| GS-EGRESS-013 | 35 | U | Agent supplies `Host`, `Content-Length` or `Transfer-Encoding` | BLOCK |
| GS-EGRESS-014 | 38 | U | Report for a sink with `onward_sharing_basis = "assumption"` | Report shows "assumption"; no guarantee wording |
| GS-PARSER-001 | 36 | U | `?beneficiary=acct-owner&benefici%61ry=acct-attacker` | BLOCK (duplicate after decoding) |
| GS-PARSER-002 | 36 | U | Form body with duplicate field after decoding | BLOCK |
| GS-PARSER-003 | 36 | U | JSON `{"message":{"to":"a","to":"b"}}` | BLOCK |
| GS-PARSER-004 | 36 | U | JSON with `"to"` and `"to"` in one object | BLOCK |
| GS-PARSER-005 | 36 | U | Headers `To` and `to` | BLOCK |
| GS-PARSER-006 | 36 | U | Paths `/api/../admin`, `/api/%2E%2E/admin`, `/api/.%2E/admin`, `/api/%2e./admin` | BLOCK, all four |
| GS-PARSER-007 | 36 | U | Path with `//` | BLOCK |
| GS-PARSER-008 | 36 | U | `%2F`, `%5C`, `%3F`, `%23` inside a path segment | BLOCK |
| GS-PARSER-009 | 36 | U | `%25xx` in any component | BLOCK |
| GS-PARSER-010 | 36 | U | CR, LF, NUL in any structured field | BLOCK |
| GS-PARSER-011 | 36 | U | Structured metadata `to = "user@example.com"` | Allowed when schema and `allow` permit — **+** |
| GS-PARSER-012 | 36 | U | Same address as recipient inside a ready-made URL | BLOCK |
| GS-PARSER-013 | 36 | U | Absolute URL with userinfo, fragment, `http://`, `//host`, wrong/empty/leading-zero port, `\` in authority | BLOCK, each |
| GS-PARSER-014 | 36 | U | Standalone query string and form body | Authority rules not applied; strict parsing applied |
| GS-PARSER-015 | 37 | U | IPv4 `010.0.0.1`, `0x0a.0.0.1`, `167772161`, `10.1` | BLOCK |
| GS-PARSER-016 | 37 | U | IPv6 non-RFC 5952 spelling, embedded IPv4, zone ID | BLOCK |
| GS-PARSER-017 | 37 | U | Hostname request to an IP-literal sink, and the reverse | BLOCK |
| GS-PARSER-018 | 37 | P | Same random inputs through the policy loader's and the gateway's validators | Identical accept/reject results |
| GS-DECL-001 | 40 | A | Model asks to declassify | Logged; state unchanged |
| GS-DECL-002 | 41 | C | Two permits race to use a grant with `uses_left = 1` | Exactly one consumes it |
| GS-DECL-003 | 41 | U | Token used in another session, for another class, after expiry | Rejected |
| GS-DECL-004 | 41 | U | Grant use counted when its permit is revoked (not consumed) | Use not counted; grant still available |
| GS-POLICY-001 | 42 | U | Envelope with a different `policy_id` | Owner-only, T3; `flow.policy_unknown` |
| GS-POLICY-002 | 42 | U | Version older than the receiver's previous | Owner-only, T3; `flow.policy_stale` |
| GS-POLICY-003 | 42 | U | Same version as current, different fp | Owner-only, T3; `flow.policy_mismatch` alert |
| GS-POLICY-004 | 42 | U | Newer `schema_version` than supported | BLOCK |
| GS-POLICY-005 | 42 | U | Newer `policy_version` than installed | Owner-only, T3; receiver does not install or select it |
| GS-POLICY-006 | 42 | U | Envelope with an unknown class | Class treated as `private:unclassified` |
| GS-POLICY-007 | 42 | U | Envelope naming an unknown reader | Ignored; that reader unreachable |
| GS-POLICY-008 | 43 | U | Install lower or reused `policy_version` | Rejected |
| GS-POLICY-009 | 44 | U | RFC 8785 examples within the subset; Genesis fingerprint vectors | Match exactly |
| GS-POLICY-010 | 44 | U | Effective policy with ±2⁵³, a float, a non-ASCII key | Rejected before hashing; ±(2⁵³ − 1) accepted |
| GS-POLICY-011 | 48 | R | Stored fp differs from the fp of the loaded effective policy | Mode 02 refuses to start / install rejected |
| GS-POLICY-012 | 49 | U | Drive each non-matching case | One event each, with the schema-1 fields; drift, stale, mismatch, unknown distinct |
| GS-BOUND-001 | 45 | U | In-process network tool registered outside the gateway in mode 02 | Start-up refused |
| GS-BOUND-002 | 46 | U | In-process deployment report | Cross-agent guarantee not claimed; limitation stated |
| GS-BOUND-003 | 47 | N | Agent context with a firewall that allows only the gateway; probe | `enforced (probe)` |
| GS-BOUND-004 | 47 | N | Agent context with direct internet access | `not enforced`; reports carry the caveat |
| GS-BOUND-005 | 47 | U | Probe cannot run | `configured (unverified)` or `unknown`; never `enforced` |

## Coverage at this baseline

| Measure | Value |
|---|---|
| Invariants | 40 |
| Invariants with at least one negative test **specification** | 40 — all `TEST_SPECIFIED`, none `IMPLEMENTED` |
| Test specifications | 85 (83 negative, 2 positive controls) |
| Tasks in P1-18…P1-23 with no invariant | P1-22b (hardening/migration — inherits INV-01…07), P1-23 (evaluation harness — measures, asserts nothing) |
| Utility cost | Not an invariant; measured in the [evaluation plan](evaluation-plan-agentdojo.md) |
