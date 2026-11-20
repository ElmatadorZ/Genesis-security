# Contributing

## Set up

```bash
git clone https://github.com/<you>/Genesis-security.git
cd Genesis-security
pip install -e .
python -m unittest discover -s tests -t .
genesis-security redteam
```

## Principles

These are not style preferences. Pull requests that break them won't be merged.

1. **Stdlib only.** No runtime dependencies. The project follows a sovereign-architecture principle: everything is built in-house and auditable.
2. **Fail closed.** Every new error path ends in BLOCK, never ALLOW.
3. **The brain may only tighten.** Nothing may loosen a body verdict.
4. **Brain and body stay separate.** Reasoning goes in `skill/SKILL.md`; enforcement goes in `genesis_security/`.
5. **Every defence has an attacker.** A new rule ships with a red-team case that fails without it and passes with it.
6. **Inert payloads only.** Canary strings, fake keys, `*.example` hosts.
7. **No secrets in logs.** Anything new written to the audit log goes through redaction.

## Pull request checklist

- [ ] Unit tests pass: `python -m unittest discover -s tests -t .`
- [ ] Red team: `genesis-security redteam` returns 0
- [ ] New behaviour has a unit test and, if security-relevant, a red-team case
- [ ] Docs updated: README, wiki page, `CHANGELOG.md`
- [ ] Works on Windows (CI runs Windows; avoid POSIX-only calls without a fallback)

## Good first contributions

- New L1 phrasings (especially Thai and other languages), each with a test
- Secret patterns for common services
- `owner_confirm` adapters (Telegram, LINE, ntfy)
- Recipes for frameworks you use

## Reporting security issues

Bypasses of L2/L3, signature or scope forgeries, undetected audit edits, or fail-open paths: report privately via **Security → Report a vulnerability** on the repository. Don't open a public issue. L1-only evasions can be normal issues.

## License

Contributions are accepted under the [Apache License 2.0](https://github.com/ElmatadorZ/Genesis-security/blob/main/LICENSE).
