# ADR-0008: Public API, SemVer and the security-compatibility policy

- Decision: **Proposed**
- Implementation: **Not approved** (Governance D5)
- Date: 2026-11-25 · Revised 2026-11-25 after review (PR #1)
- Closes: GS-AUD-13

## Context

Integrators need to know what they can depend on. v1.0 has no stated public surface, and the documented extension point `_shell_refusal` is private. Review raised a second need: SemVer must never become a reason to keep insecure behaviour.

## Decision

### 1. Public API

The public API is: names exported from `genesis_security/__init__.py`; CLI commands and flags; the policy schema; the audit export schema; the envelope format; and the documented extension interfaces (`ShellRules`, `Brain`, `OwnerConfirm`, `StateStore`, `AuditSink`, `KeyProvider`). Everything else is internal and may change at any time.

### 2. Semantic versioning

Breaking changes to the public API only in a new major version. Deprecations warn for at least one minor release before removal. `CHANGELOG.md` has *Breaking*, *Deprecated*, *Security* sections.

### 3. Security-compatibility policy (security overrides compatibility)

1. **A security fix may change behaviour in a minor or patch release** when keeping the old behaviour would leave users exposed. In that case, and only that case, SemVer compatibility yields to security.
2. Such a release ships with: a **GitHub Security Advisory** (CVE when applicable), a **migration notice** at the top of the changelog under *Security — behaviour change*, the exact behaviour before and after, and how to detect affected deployments (e.g. a shadow-mode report or a `policy check` warning).
3. The change is always **toward stricter** behaviour. A release never loosens a default to restore compatibility.
4. Where possible the stricter behaviour is first shipped as a warning in the same release, but never when the warning period would itself leave a known exploitable gap.
5. **Security-supported versions** are listed in `SECURITY.md`: the latest major receives all fixes; the previous major receives security fixes for a fixed window after the new major ships (window length is an owner decision; proposed 6 months, see ADR-0003 §6).
6. **Compatibility modes** (e.g. v1-compat) are never a supported *security* configuration. A vulnerability that exists only because a compatibility mode is enabled may be answered by documentation rather than a fix.

### 4. Release statements

Release notes state, for every release: whether it was independently reviewed (Governance D3, gate G9) and which release gates passed, with links to evidence. "Not independently reviewed" is written out when true.

## Consequences

- v2.0 is the first release that makes these promises; v1.x is best-effort.
- Users get stability for features and fast, explicit changes for security.
