# Genesis Security — Product Specification v1.0

| | |
|---|---|
| Status | **Draft for owner review** |
| Date | 2026-11-25 |
| Owner | Bunyawat Dechanon (ElmatadorZ) |
| Inputs | Product direction from the owner (2026-11-25), [baseline audit](../audit/2026-11-25-baseline-audit.md), v1.0.0 code |
| Related | [Architecture](architecture.md) · [ADRs](../adr/) · [Backlog](backlog.md) |

## 1. Product

**Genesis Security — the independent security infrastructure for autonomous AI.**

A security enforcement layer that decides what AI agents may trust, access, execute and communicate, and that stays in control when the model makes a wrong decision.

### Principles (normative)

| # | Principle | What it means in code |
|---|---|---|
| P1 | **Models participate. The runtime governs.** | Only the runtime issues verdicts. A model or brain may make a verdict stricter, never looser (ADR-0001). |
| P2 | **External content is data, never authority.** | Nothing that arrives as content can grant a tier, a scope, an approval or a policy change. |
| P3 | **No privileged action without policy authorization.** | Default deny: a tool runs only if policy declares it and its capabilities (ADR-0003). |
| P4 | **Every security decision is auditable.** | Every verdict is in a tamper-evident ledger, with no secrets in it (ADR-0007). |
| P5 | **Fail closed.** | Errors, timeouts, missing config and unknown inputs never result in ALLOW (ADR-0004). |
| P6 | **Never trust a security claim without reproducible evidence.** | Alignment with a framework is stated as a mapping with tests, never as certification. Every claim links to a test anyone can rerun. |

## 2. Problem and users

Autonomous agents read untrusted content and then act with real permissions. Model-level defences reduce how often an agent is fooled; they cannot guarantee it won't be. Teams need a layer outside the model that enforces limits regardless.

| Persona | Needs |
|---|---|
| **Solo builder / researcher** (e.g. SkynetClaw, local Ollama agents) | Drop-in protection, zero dependencies, works offline, understandable in an afternoon |
| **Product engineering team** shipping an agent feature | Stable SDK, policy as code, CI-friendly tests, clear failure modes |
| **Security / platform team** at an organization | Central policy, per-agent identity, evidence for auditors, SIEM feed, incident response |
| **Auditor / buyer** | Mapping to recognised frameworks, reproducible test evidence, signed releases |

## 2a. Threat model: who is trusted, who is the attacker

| Actor | Trust | Can | Cannot (by design) |
|---|---|---|---|
| **Owner** (person who runs the deployment) | Trusted (T1) | Give tasks, approve HOLDs, author policy | — |
| **Operator** (holds master/policy/audit keys, runs the host) | Trusted for Core; *separable* only with mode B signing and external anchoring | Change policy, rotate keys, release quarantine | Forge a mode-B policy without the author key; rewrite an externally anchored ledger undetected |
| **Runtime host OS** | Trusted (outside our control) | — | — |
| **Agents** (Genesis Mind, SkynetClaw, MCP clients, external agents) | **Untrusted principals** with identities and scopes | Propose tool calls and messages within their scopes | Declare capabilities, widen scopes, sign as another agent, approve their own HOLDs |
| **Models / brains** | **Untrusted advisors** | Propose stricter verdicts | Loosen any verdict (ADR-0001) |
| **Content authors** (web pages, files, emails, tool output, MCP results) | **Attacker** (T3) | Put text in front of agents | Authorize any action, grant tiers or scopes, change policy |
| **Compromised agent** | **Attacker** holding one agent's key | Act within that agent's scopes until quarantined/revoked | Impersonate other agents (ADR-0005), act after revocation |
| **Attacker with host or key access** | **Out of scope for Core guarantees** | Everything the operator can | Defeat mode-B policy signing or external anchors (see ADR-0004, ADR-0007) |

Guarantees in this spec hold against the attackers above **only** for actions routed through the runtime. Tools reachable without the gateway are outside every guarantee.

## 3. Scope

**In scope (Core, v1.x → v2.0):** policy-governed tool gating · trust tiers and taint · agent identity and signed messaging · memory and supply-chain guards · tamper-evident audit ledger · red-team and conformance suites · Python SDK and CLI · adapters for Claude, OpenAI, Gemini, Ollama and MCP.

**Out of scope:** model training or fine-tuning · content moderation of model output for harms unrelated to agent actions · OS sandboxing (Genesis Security *decides*; the OS *isolates*; we integrate with sandboxes, we don't replace them) · detection that depends on a hosted service.

## 4. Editions

One security core; editions differ in operations, not in protection.

| Edition | Licence | Contents | Status |
|---|---|---|---|
| **Genesis Security Core** | Apache 2.0 | Runtime, policy engine, SDK, CLI, adapters, red-team and conformance suites | Exists (v1.0.0); hardening in Phase 1 |
| **Genesis Security Enterprise** | Commercial | Central policy management, RBAC for operators, dashboard, SIEM connectors, compliance evidence packs, multi-tenant isolation, support SLA | Phase 3, after Core v2.0 |
| **Genesis Security Cloud** | Commercial | Managed gateway, hosted policy control, fleet monitoring | Future; not before Enterprise has paying users |

**Rule (Governance D2, approved):** default-deny, policy validation, fail-closed behaviour, tool authorization, prompt-injection defence, identity verification, audit integrity and security updates for significant vulnerabilities are in every edition. Enterprise sells management at scale, SSO and governance, reporting, evidence and support.

## 5. Functional requirements

Each requirement has an ID used by the backlog and by tests. **MUST** items gate Core v2.0.

### Authorization
- **FR-AUTH-1 (MUST)** Default deny: a tool call is refused unless the tool is declared in policy.
- **FR-AUTH-2 (MUST)** Each declared tool states capabilities (`read`, `write`, `delete`, `network`, `exec`, `money`, `message`) and whether it is irreversible; checks follow capabilities, not tool names.
- **FR-AUTH-3 (MUST)** Exec-capable tools get shell rules (metacharacters, command allowlist, dangerous options) whatever they are named and whichever argument holds the command.
- **FR-AUTH-4 (MUST)** Network/message-capable tools have every destination (URL host, email domain, channel ID) checked against allowlists.
- **FR-AUTH-5 (SHOULD)** Per-agent scopes: an agent may call only the tools its role grants.

### Policy
- **FR-POL-1 (MUST)** Policy is validated against a schema at load. Unknown keys, wrong types and missing required sections are load errors (strict mode default).
- **FR-POL-2 (MUST)** A policy that fails to load leaves the gate in deny-all, never allow-all.
- **FR-POL-3 (SHOULD)** Policy integrity: HMAC *authentication* in Core (mode A) or asymmetric *signing* with the optional extra (mode B); the runtime verifies before use and never falls back silently (ADR-0004).
- **FR-POL-5 (MUST)** Atomic reload; a failed reload keeps the current policy and never falls back to a more permissive one; every load, reload and failure is an audit event (ADR-0004).
- **FR-POL-4 (SHOULD)** `genesis-security policy check` lints a policy and warns about risky grants (e.g. `node`, `find`, wildcard hosts).

### Identity
- **FR-ID-1 (MUST)** Per-agent keys: a message signed by agent A cannot verify as agent B.
- **FR-ID-2 (MUST)** Only keys in the `keygen` format (256 bits from the OS CSPRNG, versioned prefix, checksum) are accepted; passwords and padded text are refused regardless of length. Length is not treated as proof of entropy (ADR-0005).
- **FR-ID-3 (SHOULD)** Key rotation with an overlap window; revocation list.

### State
- **FR-ST-1 (MUST)** Nonces, strikes, quarantine and task taint persist across restarts (stdlib SQLite).
- **FR-ST-2 (MUST)** State shared safely by multiple processes on one host.

### Audit
- **FR-AUD-1 (MUST)** Every verdict committed before the action runs; no execution path exists without a committed record. Failure contract per API in ADR-0007 (`pre_tool_call` returns BLOCK; `@guard` raises `AuditUnavailableError`).
- **FR-AUD-2 (MUST)** Keyed hash chain, checkpoints, truncation/deletion detection (exists).
- **FR-AUD-3 (SHOULD)** Export in a SIEM-friendly schema (JSON lines with stable field names; CEF/OCSF mapping documented).

### Integration
- **FR-INT-1 (MUST)** Stable, versioned public API (ADR-0008).
- **FR-INT-2 (MUST)** Provenance helper that derives `origin_tier` from message sources, so integrators don't hand-tag it.
- **FR-INT-3 (SHOULD)** MCP gateway: gate `tools/call`, pin tool descriptions, enforce per-server scopes.
- **FR-INT-4 (SHOULD)** Adapters for Claude, OpenAI, Gemini and Ollama tool-calling loops; SkynetClaw reference integration.

## 6. Non-functional requirements

| ID | Requirement | Target |
|---|---|---|
| NFR-1 | Runtime dependencies in Core | 0 (stdlib only) |
| NFR-2 | Gate decision latency, p95, local, excluding brain | ≤ 2 ms |
| NFR-3 | Platforms | Linux, macOS, Windows; CPython 3.11–3.13 (+ free-threaded build tested) |
| NFR-4 | Fail-closed coverage | Every failure scenario in the conformance suite ends in BLOCK/HOLD |
| NFR-5 | Secrets in logs | None, verified by test |
| NFR-6 | Self-hosted | Fully functional offline |

## 7. Release gates (proposed criteria, not results)

Core v2.0 ships only when all pass. Current status is in the [baseline audit](../audit/2026-11-25-baseline-audit.md#release-gate-status-from-the-product-spec).

| Gate | Criterion | Evidence (must be linked in the release notes) | Owner of evidence | Approver |
|---|---|---|---|---|
| G1 | 0 unauthorized tool executions across red-team + conformance suites, **default policy** | CI JSON report for the release commit | Maintainer | Owner |
| G2 | 0 open Critical/High findings | Findings register with status per ID ([traceability](../audit/2026-11-25-baseline-audit.md#traceability-finding--decision--work--test--gate)) | Maintainer | Owner |
| G3 | Every failure scenario fails closed | Conformance suite report | Maintainer | Owner |
| G4 | Replay, forged identity, cross-agent signing resisted | Adversarial test report | Maintainer | Internal independent reviewer (D3) |
| G5 | Audit edit, rewrite, truncation, deletion, rollback detected; anchoring documented | Test report | Maintainer | Internal independent reviewer |
| G6 | No regression across releases | CI history for every merged PR | CI | Owner |
| G7 | Quickstart works on a clean machine, Linux/macOS/Windows | CI job + one manual run log | Maintainer | Owner |
| G8 | Public API versioned; deprecation + security-compatibility policy published | `SECURITY.md`, ADR-0008, changelog | Maintainer | Owner |
| G9 | Independent external review completed; every finding triaged | External report (or written "not independently reviewed") | External reviewer | Owner |
| G10 | SBOM, signed tag, published hashes | Release assets | Maintainer | Owner |

Until a second maintainer exists, "Maintainer" is the owner plus AI assistance; that is why G4, G5 and G9 require someone else's sign-off.

## 8. Standards alignment (mapping, not certification)

Genesis Security is designed to align with these frameworks. **Alignment is a self-assessed mapping backed by tests. None of these bodies certifies products, and Genesis Security makes no claim of certification.**

| Framework | Status (checked 2026-11-25) | Used for |
|---|---|---|
| [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/) (ASI01–ASI10) | Released December 2025 | Primary threat taxonomy; GSX ↔ ASI mapping below |
| [OWASP Top 10 for LLM Applications 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) | Released 2026 | LLM-level risks (prompt injection, sensitive disclosure, excessive agency, supply chain) |
| [OWASP AISVS 1.0](https://github.com/OWASP/AISVS) (Artificial Intelligence Security Verification Standard) | Stable 1.0 | Testable requirements; conformance suite cites AISVS IDs |
| [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) | **Beta** (v0.1, labelled 2025) | MCP gateway design; revisit when final |
| NIST AI RMF 1.0 | Final | Governance language for Enterprise evidence packs |
| [NIST SP 800-218 SSDF](https://csrc.nist.gov/projects/ssdf/publications) | v1.1 final; **v1.2 is a public draft** (Dec 2025) | Project's own secure development process; track v1.2. SP 800-218A for the GenAI profile |
| OWASP GenAI Security Project — Agent Control Standard (ACS) | New (2026); not yet reviewed by us | **To evaluate** in Phase 0b: may overlap with our policy model |

### GSX ↔ OWASP Agentic Top 10

| OWASP ASI | Genesis Security coverage today | After Phase 1 |
|---|---|---|
| ASI01 Agent Goal Hijack | L2 origin check, `<untrusted>` wrapping, brain (GSX-01/02/03/09) | + provenance helper (FR-INT-2) |
| ASI02 Tool Misuse & Exploitation | Irreversible HOLD, egress + secret checks — **but default-allow (GS-AUD-01)** | Default deny + capabilities |
| ASI03 Identity & Privilege Abuse | Scope check, shared-key envelopes (GSX-07/11) | Per-agent keys, per-agent scopes |
| ASI04 Agentic Supply Chain | Skill / description pinning (GSX-04/12) | + MCP gateway pinning |
| ASI05 Unexpected Code Execution | Shell rules — **name-bound (GS-AUD-02)** | Capability-bound exec rules |
| ASI06 Memory & Context Poisoning | `on_memory_write` facts-only from T3 (GSX-08) | unchanged |
| ASI07 Insecure Inter-Agent Communication | HMAC, nonce, freshness, recipient, hop budget | + per-agent identity, persistent nonces |
| ASI08 Cascading Failures | Hop budget, quarantine (GSX-10) | + persistent quarantine, rate limits (Phase 2) |
| ASI09 Human-Agent Trust Exploitation | Human Gate with redacted previews | + approval UX guidance, previews per capability |
| ASI10 Rogue Agents | Strikes → quarantine | + persistent state, per-agent kill switch |

## 9. What we will not claim

- "Certified", "compliant" or "OWASP-approved".
- "Prevents prompt injection". We claim: injected content cannot authorize actions through the gate.
- Any test result we haven't run and published.
- That v1.x, or v2.x with compatibility mode enabled, provides secure enforcement. v1.x and compat mode are labelled `NOT SECURE ENFORCEMENT`; only v2.0 strict/default-deny is.

## 10. Decisions

Recorded in [Governance Decision v1.0](governance-decisions.md) (2026-11-25):

1. **Default-deny in v2.0** — approved in principle, with a v1.x compatibility mode under binding conditions (clear "NOT SECURE ENFORCEMENT" warnings, a shadow compatibility check, a migration guide, never presented as secure).
2. **No security behind a paywall** — approved; the full list of what every edition must include is in D2.
3. **External reviewer** — pending. Two layers: internal independent review + external security review. AI assistants are not counted as independent auditors.
4. **Phase 1 code** — approved to start with v1.1 (D5, updated 2026-11-25).

Review additions R1–R4 (compat-mode opt-in, v3.0 removal, 6-month v1.x fix window, security over compatibility) were approved on 2026-11-25 — see [Governance](governance-decisions.md#additions-from-architecture-review-r1r4). Phase 1 code was approved to start with v1.1 (D5).

Still open: **ACS overlap** (adopt, map to, or ignore the OWASP Agent Control Standard) — backlog P0-05.
