# ADR-0008: Public API surface and semantic versioning

- Status: **Proposed**
- Date: 2026-11-25
- Closes: GS-AUD-13

## Context

Integrators need to know what they can depend on. v1.0 has no stated public surface, and the documented extension point `_shell_refusal` is private.

## Decision

1. **Public API** = names exported from `genesis_security/__init__.py`, the CLI commands and flags, the policy schema, the audit export schema, and the envelope format. Everything else is internal.
2. **Semantic versioning.** Breaking changes only in a new major version. Deprecations warn for at least one minor release before removal.
3. Extension points become public and documented: `ShellRules`, `Brain`, `OwnerConfirm`, `StateStore`, `AuditSink`.
4. `CHANGELOG.md` gains *Breaking*, *Deprecated*, *Security* sections. Security fixes get a GitHub Security Advisory.

## Consequences

- v2.0 is the first release that makes these promises; v1.x is best-effort.
