# Architecture Decision Records

Format: [Michael Nygard's ADR template](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions) — Context, Decision, Consequences. Status is one of *Proposed*, *Accepted*, *Superseded*.

| ADR | Title | Status | Closes |
|---|---|---|---|
| [0001](0001-runtime-is-final-authority.md) | The runtime is the final authority; models may only tighten | Accepted (records v1.0 design) | — |
| [0002](0002-stdlib-only-self-hosted-core.md) | Stdlib-only, self-hosted core | Accepted (records v1.0 design) | — |
| [0003](0003-default-deny-capability-authorization.md) | Default deny with capability-based tool authorization | Accepted in principle | GS-AUD-01, -02, -09, -14 |
| [0004](0004-validated-signed-policy-fail-closed.md) | Schema-validated, optionally signed policy; load failure = deny all | Proposed | GS-AUD-03, -04 |
| [0005](0005-per-agent-identity-and-keys.md) | Per-agent identity, key strength and rotation | Proposed | GS-AUD-06, -07 |
| [0006](0006-persistent-state-store.md) | Persistent security state in SQLite | Proposed | GS-AUD-05, -12 |
| [0007](0007-audit-ledger-write-before-act.md) | Audit ledger: record before act, defined failure | Proposed | GS-AUD-11 |
| [0008](0008-public-api-and-semver.md) | Public API surface and semantic versioning | Proposed | GS-AUD-13 |

New ADRs: copy the structure of an existing one, take the next number, open a PR.
