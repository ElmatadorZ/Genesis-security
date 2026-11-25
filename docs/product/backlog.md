# Implementation backlog

Ordered by phase. Each item: what, why (finding / requirement / ADR), and **acceptance criteria** that a reviewer can check. An item is done only when its criteria pass in CI and a red-team or conformance case covers it.

Size: S ≈ ≤ 1 day · M ≈ 2–4 days · L ≈ 1–2 weeks (solo builder pace, rough).

## Phase 0 — Baseline and architecture ✅ (this PR) · 0b pending

| ID | Item | Status |
|---|---|---|
| P0-01 | Read-only audit of every module, workflows, docs | Done: [baseline audit](../audit/2026-11-25-baseline-audit.md) |
| P0-02 | Threat-model review against OWASP Agentic Top 10 | Done: [spec §8](product-spec-v1.md#8-standards-alignment-mapping-not-certification) |
| P0-03 | Bypass-path probes | Done: [probe script](../audit/baseline_probe_2026-11-25.py) |
| P0-04 | ADRs for v2.0 architecture | Done: [ADR 0001–0008](../adr/) |
| P0-05 | **0b:** evaluate OWASP Agent Control Standard and AISVS 1.0 chapters relevant to agents; record adopt/map/ignore as ADR-0009 | Open · M |

## Phase 1 — Harden the security core (target: Core v2.0)

> **Status:** approved for *preparation* only ([Governance D5](governance-decisions.md)). No source changes until PR #1 is reviewed and D5 is approved.

Gate to leave Phase 1: release gates G1–G6 and G8 pass; 0 open High findings.

| ID | Item | Closes | Size | Acceptance criteria |
|---|---|---|---|---|
| **P1-01** | Tool registry + **default deny** | GS-AUD-01 · FR-AUTH-1 · ADR-0003 | L | 1. Undeclared tool → `BLOCK`, reason names the tool. 2. `strict=false` (v1.x) logs a `DeprecationWarning` and keeps v1 behaviour. 3. Red-team case: `wire_money` undeclared → BLOCK. 4. Existing 45 red-team cases still pass with a migrated default policy. |
| **P1-02** | **Capability-bound rules** (`exec`, `network`, `message`, `delete`, `money`) | GS-AUD-02 · FR-AUTH-2/3 · ADR-0003 | L | 1. A tool named `run_command` with `capabilities=["exec"]` gets every shell rule. 2. Command found via `command_arg`; missing arg → BLOCK. 3. Rename test: same tool under 5 different names → identical verdicts. 4. Red-team cases D1–D4 rewritten to use a non-`shell_exec` name and still pass. |
| **P1-03** | **Policy schema v2, strict validation, deny-all on load failure** | GS-AUD-03 · FR-POL-1/2 · ADR-0004 | M | 1. Unknown key, wrong type, bad regex, missing required section → load error naming file, line/key. 2. Gate with failed policy: every tool BLOCK, every message T3, one audit entry `policy_load_failed`. 3. Probe "policy with only `[egress]`" → load error, not ALLOW. 4. `genesis-security policy check FILE` exits non-zero on these. |
| P1-04 | Signed policy (HMAC) + policy fingerprint in ledger | GS-AUD-04 · FR-POL-3 · ADR-0004 | M | 1. `policy sign` / verify round-trip. 2. One-byte edit → load fails (deny-all) when signing required. 3. Every ledger entry carries `policy_fp`. |
| **P1-05** | **Persistent state store** (SQLite) | GS-AUD-05 · FR-ST-1/2 · ADR-0006 | M | 1. Quarantine survives process restart. 2. Replay of one envelope from 2 processes × 32 threads → exactly 1 ALLOW. 3. Store unavailable → BLOCK. 4. `quarantine list/release` CLI; release is audited. |
| P1-06 | Per-agent keys + epochs + revocation | GS-AUD-06 · FR-ID-1/3 · ADR-0005 | L | 1. Message from A signed with B's derived key → BLOCK. 2. Old epoch accepted only within overlap window. 3. Revoked agent → BLOCK. 4. Red-team: forged sender, epoch replay, revoked sender. |
| P1-07 | Key strength enforcement | GS-AUD-07 · FR-ID-2 · ADR-0005 | S | 1. Text keys and keys < 32 bytes refused (v2.0) / warned (v1.x). 2. `keygen` output always accepted. |
| P1-08 | Defined ledger failure → BLOCK + `GenesisSecurityError` | GS-AUD-11 · FR-AUD-1 · ADR-0007 | S | 1. Unwritable ledger: `pre_tool_call` returns BLOCK; `@guard` raises `AuditUnavailable`. 2. No raw `OSError` escapes public API (test). |
| P1-09 | Concurrency hardening + free-threaded CI | GS-AUD-12 · NFR-3 | M | 1. Locks or store-backed atomics for all shared state. 2. CI job on CPython 3.13t runs the concurrency tests. |
| P1-10 | Recipient allowlists for `message` capability | GS-AUD-14 · FR-AUTH-4 | S | 1. Email to unlisted domain → HOLD with domain in reason. 2. Channel IDs supported via `destination_args`. |
| P1-11 | Conformance suite (separate from red team) | G3 · NFR-4 | M | 1. One test per failure scenario: brain error, owner error, store error, ledger error, policy error, malformed tier, missing key. 2. Every case asserts BLOCK/HOLD. 3. Runs in CI. |
| P1-12 | Latency benchmark in CI | NFR-2 | S | p95 ≤ 2 ms for a declared, allowed tool on CI runners; regression > 20 % fails the job. |
| P1-13 | **Shadow mode** — pre-upgrade compatibility check | Governance D1 · ADR-0003 | M | 1. `mode=shadow` runs v2.0 rules beside v1.x and never changes a v1.x verdict. 2. Report lists each call that v2.0 would BLOCK/HOLD, with reason. 3. `genesis-security policy shadow-report LOG` summarises it. |
| P1-14 | **Migration guide** v1 → v2 | Governance D1 | S | 1. Ships with the first warning release. 2. Covers tool declarations, capabilities, shadow mode, key upgrade. 3. Contains no claim that compatibility mode is secure. |

## Phase 2 — Integration ecosystem

| ID | Item | Closes | Size | Acceptance criteria |
|---|---|---|---|---|
| P2-01 | **Provenance helper** (`Turn`/`Context` API that derives `origin_tier`) | GS-AUD-09 · FR-INT-2 | M | 1. Messages from owner, tool results, fetched content and agent envelopes produce the right tier without manual tagging. 2. Integration example uses no hand-written `origin_tier`. |
| P2-02 | Public API freeze + semver policy | GS-AUD-13 · FR-INT-1 · ADR-0008 | S | 1. `__all__` audited; private extension points promoted. 2. Deprecation policy in docs. |
| P2-03 | MCP security gateway | FR-INT-3 · ASI04 | L | 1. Gates `tools/call` per server and tool. 2. Pins tool descriptions; change → tool disabled + owner notified. 3. Per-server scopes. |
| P2-04 | Adapters: Claude, OpenAI, Gemini, Ollama tool loops | FR-INT-4 | M | 1. Each adapter routes every tool call through the gate. 2. Same red-team suite passes through each adapter (mock model). |
| P2-05 | SkynetClaw reference integration | FR-INT-4 | M | 1. Every SkynetClaw tool declared in a policy file. 2. Startup verifies ledger checkpoint. 3. Documented in wiki. |
| P2-06 | Rate limits / budgets per agent and task | ASI08 | M | Tool-call, token and money budgets; exceeded → BLOCK + audit. |

## Phase 3 — Enterprise operations (Commercial)

Start only after Core v2.0 ships and has external users.

| ID | Item | Acceptance criteria (summary) |
|---|---|---|
| P3-01 | Central policy management with signed bundles | Runtimes pull and verify bundles; rollback to previous bundle |
| P3-02 | Operator RBAC | Separate roles for policy author, approver, auditor |
| P3-03 | Dashboard | Verdicts, strikes, quarantines over time; drill-down to ledger entry |
| P3-04 | SIEM export (JSON schema; OCSF/CEF mapping) | Stable fields; sample Loki/Elastic/Splunk configs |
| P3-05 | Incident response runbooks + kill switch | One command quarantines an agent fleet-wide |
| P3-06 | Multi-tenant isolation | Tenant-scoped keys, policies, ledgers; cross-tenant tests |
| P3-07 | Compliance evidence packs | AISVS / Agentic Top 10 mapping with linked test results |

## Phase 4 — Independent validation and release

| ID | Item | Gate | Acceptance criteria |
|---|---|---|---|
| P4-01 | **External red team / security review** | G9 | Report received; every finding triaged; Critical/High fixed before release |
| P4-02 | Fuzzing of policy loader, envelope parser, URL/secret detection | G1, G3 | Stdlib-based fuzz harness runs in CI nightly; crashes → issues |
| P4-03 | Regression suite pinned to every past finding | G6 | One test per GS-AUD and red-team ID |
| P4-04 | Pin GitHub Actions by commit SHA; least-privilege tokens | GS-AUD-08 | All `uses:` pinned; Dependabot/renovate for actions only |
| P4-05 | SBOM (CycloneDX), signed tag, published hashes | G10 · GS-AUD-08 | Release assets include SBOM + SHA-256; tag signed |
| P4-06 | Security advisory process | G8 | GitHub private reporting on; advisory template; CVE process documented |

## Approved preparation order (Governance v1.0)

P1-03 (schema + fail-closed loading) → P1-01 (unknown-tool default-deny) → P1-02 (tool identity and capability authorization) → P1-11 + red-team additions. P1-13/P1-14 ship with the first v1.x release that warns.

## Earlier suggestion for the next three PRs

1. **P1-03** (policy schema, deny-all on failure) — smallest change that removes a High finding and is a prerequisite for P1-01/02.
2. **P1-01 + P1-02** together (tool registry, default deny, capabilities) — removes the other two High findings.
3. **P1-05 + P1-08** (state store, defined ledger failure).
