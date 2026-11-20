# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Use GitHub's private reporting: **Security → Report a vulnerability** on this repository.
Include: affected version, a minimal reproduction (canary strings, not live payloads), and impact.

You should get a first reply within 7 days. Fixes are released as patch versions and credited in
[CHANGELOG.md](CHANGELOG.md) unless you ask to stay anonymous.

## In scope

- Bypasses of L2/L3 structural rules (actions from T3 executing, secrets leaving, shell metachar passing)
- Signature or scope checks that can be forged
- Audit chain edits that `verify-audit` does not detect
- Fail-open behaviour (an error that results in ALLOW)

## Out of scope

- New phrasings that evade the L1 regex scanner alone, when L2/L3 still block the action.
  These are welcome as normal issues or pull requests with a test case.
- Attacks that require the HMAC key or write access to the policy file.

## Supported versions

| Version | Supported |
|---|---|
| 1.x | ✅ |
