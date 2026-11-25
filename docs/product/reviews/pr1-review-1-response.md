# PR #1 — response to architecture & security review, round 1

Review verdict received: **Changes Requested** (2026-11-25). This file maps every point to the change made, or explains where we disagree. No source code was changed.

## Required changes before merge

| # | Review point | Change | Where |
|---|---|---|---|
| 1 | ADR-0001: define verdict ordering and transitions; runtime validates, brain doesn't assign | Verdict meanings, strictness order, full transition matrix (brain × owner), invariants I1–I4, single `apply_transition` path, owner approval as the only loosening transition and only `HOLD → ALLOW` after the brain | ADR-0001; backlog P1-15 |
| 2 | ADR-0002: HMAC ≠ digital signature; keep asymmetric option without forcing a dependency | Core guarantees defined only in HMAC terms; optional isolated `[crypto]` extra behind `Signer`/`Verifier`; no silent fallback | ADR-0002 |
| 3 | ADR-0003: runtime-verified capability registry; authenticated provenance; canonicalization incl. wrappers; compat mode not permanent or accidental | §1 registry owned by validated policy + runtime binding; §4 signed provenance chain, conservative to T3, `provenance=caller` in v1.x; §5 text/URL/shell canonicalization and wrapper/indirect execution; §6 explicit opt-in + env acknowledgement, v3.0 removal, fix window (proposals R1–R3, pending owner) | ADR-0003; backlog P1-16, P1-17 |
| 4 | ADR-0004: HMAC threat model honest; split HMAC authentication vs asymmetric signing; schema first, version, canonical fingerprint, audited changes, atomic reload, no fallback to more permissive; deny-all must BLOCK all actions | Modes A (authentication) and B (signing) with what each does and does not prove; `schema` + `policy_version`; canonical bytes; load/reload/failure events; atomic swap; failed reload keeps current; downgrade protection; deny-all now explicitly BLOCKs tools, memory, skills **and** messages | ADR-0004; spec FR-POL-3/5; backlog P1-04 |
| 5 | ADR-0005: standard KDF, domain separation, unambiguous encoding, entropy ≠ length, key storage, revocation/epochs | HKDF-SHA256 (RFC 5869) with per-purpose `info` labels and length-prefixed fields; key *provenance* format `gsk1_…`; file permissions; agent processes get only their own key; epoch overlap window; immediate revocation; master-key compromise procedure; KATs | ADR-0005; spec FR-ID-2; backlog P1-07 |
| 6 | ADR-0006: isolation, WAL/durability, permissions, busy/locks, corruption, migration, backup, multi-process; atomic replay; no GIL reliance | Schema; `BEGIN IMMEDIATE`; replay decided by a UNIQUE constraint (`ON CONFLICT DO NOTHING` + `changes()`); WAL + `synchronous=FULL`; busy → BLOCK; `0600`/ACL; `quick_check` + non-permissive recovery; forward-only audited migration; online backup and post-restore envelope cutoff; tests on 3.13t | ADR-0006 |
| 7 | ADR-0007: non-conflicting failure contract; no execution before commit; integrity ≠ anchoring ≠ immutability | Fixed order decide → commit → execute; per-API contract table; three properties with who can defeat each; wording rule "tamper-evident", never "tamper-proof" | ADR-0007 |
| 8 | ADR-0008: security fixes may break compatibility | Security-compatibility policy: stricter-only behaviour changes in minor/patch with advisory + migration notice; supported-versions window; compat modes never a supported security configuration; release statements on independent review | ADR-0008 |
| 9 | ADR README: one status vocabulary | Two fields — Decision (Proposed/Accepted/Rejected/Deprecated/Superseded) and Implementation (Records existing code/Not approved/Approved/Implemented); "approved in principle" moved to *owner direction*. All ADRs remain **Proposed**; none moved to Accepted | ADR README + every ADR header |

## Cross-document issues

| Issue | Change |
|---|---|
| Governance D1 ↔ ADR-0003 | Every D1 condition appears verbatim in ADR-0003 §6; review additions are recorded as pending proposals R1–R4 in Governance, not as decisions |
| Security versioning | Spec §9: v1.x and compat mode are never claimed as secure enforcement; ADR-0008 §3 |
| Threat model | New spec §2a: trusted actors, untrusted principals, attackers, and what is out of scope |
| Release gates | Spec §7: evidence, evidence owner and approver per gate; G4/G5/G9 need someone other than the author |
| Finding → fix → test → gate | Audit report: traceability matrix for GS-AUD-01…16 |
| GS-AUD-14 ↔ ADR-0003 | Covered by ADR-0003 §3 `message` capability; traceability row links P1-10 and issue #5 |

## Where we disagree or qualify

1. **Key entropy cannot be "defined" by checking a key.** No test on a byte string can establish 256 bits of entropy. ADR-0005 therefore enforces *key provenance* (only `keygen`-format keys) and keeps low-diversity checks as a backstop, and says so explicitly.
2. **ADR-0007's original two behaviours were not contradictory** — `pre_tool_call` and `@guard` are different APIs — but the sentence was ambiguous. It is now a per-API table.
3. **ADR-0004 deny-all already blocked every tool call** in the first draft; the review is right that "messages become T3" was too weak, and messages, memory writes and skill loads are now BLOCK too.
4. **Provenance has a hard limit**: the runtime sees what the model was shown, not what it acted on. ADR-0003 §4 states this and chooses the conservative default.

## Not changed by this response

- PR #1 merge: still pending owner approval after re-review.
- Phase 1 code: still not approved (Governance D5).
- No ADR status moved to Accepted.
