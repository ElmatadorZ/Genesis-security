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
| D5 | May Phase 1 source code changes start? | Initially "not yet". **Updated 2026-11-25 (13:42): owner approves merging PR #1 and starting v1.1 code**, one PR per work item, each with a regression test shown failing on `main` first | **Approved — code may start (v1.1)** |

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

## Approved work order

Tracked as GitHub Issues, in this order (code approved for v1.1 on 2026-11-25, see D5):

1. P1-03 — Policy schema validation
2. Fail-closed policy loading (part of P1-03)
3. P1-01 — Unknown-tool default-deny
4. P1-02 — Tool identity and capability-based (semantic) authorization
5. P1-11 + red-team additions — Regression and adversarial tests

Each item is one PR with its regression test shown failing on `main` first. D5 was approved on 2026-11-25.

## Additions from architecture review (R1–R4)

Raised in the PR #1 review and written into ADR-0003 §6 / ADR-0008 §3. **Approved by the owner on 2026-11-25**; they extend D1.

| # | Proposal | Owner decision |
|---|---|---|
| R1 | Compatibility mode in v2.0 needs an explicit named setting **and** an environment acknowledgement; either missing → strict | **Approved** 2026-11-25 |
| R2 | Compatibility mode removed in v3.0 | **Approved** 2026-11-25 |
| R3 | v1.x security-fix window after v2.0 ships: **6 months** | **Approved** 2026-11-25 |
| R4 | Security fixes may change behaviour in minor/patch releases, always toward stricter, with advisory + migration notice | **Approved** 2026-11-25 |

## Architecture review round 3 — clarifications (2026-11-25)

| Item | Decision / status |
|---|---|
| Split v2.0-alpha | **Approved**: alpha.1 *Core Enforcement* (default-deny, capability registry, information flow, readers, cross-agent taint, fail-closed + audit); alpha.2 *Integration & Validation* (MCP adapter, AgentDojo, adversarial + regression testing, identity/credential hardening, docs + migration). Item placement preliminary until confirmed. No date pressure: alpha.1 ships only when its gate passes |
| PR #7 (v1.1 code) | **Separate review**; not blocked by the earlier "not approved", which referred to v2.0 architecture implementation only. D5 is not blanket approval of all code |
| PR #8 (architecture docs) | Under review; its approval does not substitute for PR #7's |
| Phase 1 — v2.0 core implementation | **Not approved** |
| Owner-only declassification; undeclared data = private; action-selection leakage as residual risk | **Agreed** |

