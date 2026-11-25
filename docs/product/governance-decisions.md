# Genesis Security — Governance Decision v1.0

| | |
|---|---|
| Date | 2026-11-25 |
| Decided by | Owner (Bunyawat Dechanon / ElmatadorZ) |
| Inputs | [Baseline audit](../audit/2026-11-25-baseline-audit.md), [Product spec v1.0](product-spec-v1.md) §10 |
| Development model | **Engineering-led, not feature-led** |

> **Project rule:** Never trust a security claim without reproducible evidence.

## Decisions

| # | Question | Decision | Status |
|---|---|---|---|
| D1 | Is default-deny a breaking change? | Yes. Ship in **v2.0**, with a compatibility path in v1.x under the conditions below | **Approved in principle** |
| D2 | May essential security be held back for Enterprise? | **No.** Every edition gets the full security core | **Approved** |
| D3 | Who reviews independently (gate G9)? | Two layers: internal independent review + external security review | **Reviewer pending** |
| D4 | Planning tool | GitHub is the single source of truth (PRs, Issues, ADRs, release gates). No whiteboard until there are several people or workstreams | **Approved** |
| D5 | May Phase 1 source code changes start? | **Not yet.** Phase 1 items may be *prepared* (issues, designs, test plans); code changes wait for PR #1 review and approval | **Approved** |

## D1 — Default-deny transition

| Version | Behaviour |
|---|---|
| v1.x | **Compatibility mode** with warnings |
| v2.0 | Default-deny is the default |
| v2.0 strict | All bypass paths closed; every failure fails closed |

Conditions (binding on the implementation):

1. **Warnings must say plainly that the policy is not secure.** In compatibility mode every undeclared-tool call logs a warning that contains the words `NOT SECURE ENFORCEMENT`, and the audit entry records `mode=compat`.
2. **A compatibility check before upgrading.** A shadow mode that evaluates v2.0 rules alongside v1.x and reports what *would* be blocked, without blocking (backlog P1-13).
3. **Compatibility mode may never be presented as secure enforcement** — not in docs, release notes, README badges or marketing.
4. **A migration guide** for existing users ships with the first v1.x release that warns (backlog P1-14).
5. v1.x behaviour must not change silently; any change that can stop an existing deployment is announced in the changelog under *Breaking*.

## D2 — Security is never behind a paywall

**Must be in every edition (Community/Core included):**

- Default-deny
- Policy validation
- Fail-closed behaviour
- Tool authorization
- Prompt-injection defence
- Identity verification
- Audit integrity
- Security updates for significant vulnerabilities

**Enterprise sells operations and convenience:**

- Centralized management
- Multi-agent fleet management
- Enterprise reporting
- SIEM integration
- SSO and organizational governance
- Compliance evidence management
- Enterprise support

Rationale: Genesis Security must not sell basic safety back to its users.

## D3 — Independent review

| Layer | Who | Counts toward G9? |
|---|---|---|
| **Internal independent review** | Someone who did not write the module under review | No — required per module before merge to a release branch |
| **External security review** | People or a team not involved in development; penetration testing and vulnerability review | **Yes** |

AI assistants used on this project (including the one that wrote the code and the one reviewing it) may do adversarial review, code analysis and test design. **They are not counted as independent external auditors.**

G9 is mandatory before any release that claims to be independently reviewed. A release without G9 must say "not independently reviewed".

## Approved for preparation (no code changes yet)

Tracked as GitHub Issues, in this order:

1. P1-03 — Policy schema validation
2. Fail-closed policy loading (part of P1-03)
3. P1-01 — Unknown-tool default-deny
4. P1-02 — Tool identity and capability-based (semantic) authorization
5. P1-11 + red-team additions — Regression and adversarial tests

Preparation = issue with design notes, acceptance criteria and test plan. Implementation starts when D5 changes to approved.
