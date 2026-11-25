# Architecture Decision Records

Format: [Michael Nygard's ADR template](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions) — Context, Decision, Consequences.

## Status vocabulary

Every ADR carries **two separate fields**. One says whether the *decision* stands; the other says whether *code* may follow it. Nothing moves from Proposed to Accepted automatically: only the owner changes a status, in a reviewed PR.

**Decision status** (exactly one):

| Status | Meaning |
|---|---|
| **Proposed** | Under review. Not binding. May still change |
| **Accepted** | Binding. Implementations must follow it |
| **Rejected** | Considered and declined; kept for the record |
| **Deprecated** | No longer recommended; not yet replaced |
| **Superseded by ADR-NNNN** | Replaced by a later ADR |

**Implementation status** (exactly one):

| Status | Meaning |
|---|---|
| **Records existing code** | Describes behaviour already shipped |
| **Not approved** | No code changes may be made for it yet |
| **Approved** | Code changes may start |
| **Implemented in vX.Y** | Shipped, with linked tests |

An ADR may additionally cite **owner direction** (e.g. "approved in principle", Governance D1). Owner direction is input to the review; it is not a decision status.

## Index

| ADR | Title | Decision | Implementation | Closes |
|---|---|---|---|---|
| [0001](0001-runtime-is-final-authority.md) | The runtime is the final authority; verdict transitions | Proposed | Records existing code (matrix: Not approved) | — |
| [0002](0002-stdlib-only-self-hosted-core.md) | Stdlib-only core; optional asymmetric crypto | Proposed | Records existing code | — |
| [0003](0003-default-deny-capability-authorization.md) | Default deny, runtime-owned capability registry, authenticated provenance | Proposed (owner direction: approved in principle, D1) | Not approved | GS-AUD-01, -02, -09, -14 |
| [0004](0004-validated-signed-policy-fail-closed.md) | Validated policy; HMAC authentication vs asymmetric signing; deny-all on failure | Proposed | Not approved | GS-AUD-03, -04 |
| [0005](0005-per-agent-identity-and-keys.md) | Per-agent keys via HKDF; key provenance; rotation and revocation | Proposed | Not approved | GS-AUD-06, -07 |
| [0006](0006-persistent-state-store.md) | Persistent security state in SQLite | Proposed | Not approved | GS-AUD-05, -12 |
| [0007](0007-audit-ledger-write-before-act.md) | Audit ledger: commit before act; failure contract; integrity ≠ immutability | Proposed | Not approved | GS-AUD-11 |
| [0008](0008-public-api-and-semver.md) | Public API, SemVer and the security-compatibility policy | Proposed | Not approved | GS-AUD-13 |

New ADRs: copy the structure of an existing one, take the next number, open a PR.
