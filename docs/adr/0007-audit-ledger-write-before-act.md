# ADR-0007: Audit ledger — record before act, defined failure

- Status: **Proposed**
- Date: 2026-11-25
- Closes: GS-AUD-11

## Context

v1.0 records every verdict before returning it, which is correct, but a failed write escapes as a raw OS exception (GS-AUD-11). Enterprise users also need to know which policy and which code version produced each verdict.

## Decision

1. Ledger write failure → `Verdict("BLOCK", reason="audit unavailable")` returned to the caller and a `GenesisSecurityError` subclass raised by `@guard`. Never a bare OS error.
2. Each entry adds `policy_fp` (ADR-0004), `runtime_version` and `agent_key_epoch` (ADR-0005).
3. Optional external anchoring: periodic checkpoint export through a pluggable sink (file on another volume, webhook, git notes).
4. Stable export schema (`schema_version`) for SIEM ingestion; field names frozen within a major version.

## Consequences

- An unavailable ledger stops all actions — the intended trade-off for P4.
