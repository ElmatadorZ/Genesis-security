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
| P6 | **No security claims without evidence.** | Alignment with a framework is stated as a mapping with tests, never as certification. |

## 2. Problem and users

Autonomous agents read untrusted content and then act with real permissions. Model-level defences reduce how often an agent is fooled; they cannot guarantee it won't be. Teams need a layer outside the model that enforces limits regardless.

| Persona | Needs |
|---|---|
| **Solo builder / researcher** (e.g. SkynetClaw, local Ollama agents) | Drop-in protection, zero dependencies, works offline, understandable in an afternoon |
| **Product engineering team** shipping an agent feature | Stable SDK, policy as code, CI-friendly tests, clear failure modes |
| **Security / platform team** at an organization | Central policy, per-agent identity, evidence for auditors, SIEM feed, incident response |
| **Auditor / buyer** | Mapping to recognised frameworks, reproducible test evidence, signed releases |

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

**Rule:** no protection that Core users need to be safe is held back for Enterprise. Enterprise sells management at scale, evidence and support.

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
- **FR-POL-3 (SHOULD)** Policies can be signed; the runtime verifies the signature before use.
- **FR-POL-4 (SHOULD)** `genesis-security policy check` lints a policy and warns about risky grants (e.g. `node`, `find`, wildcard hosts).

### Identity
- **FR-ID-1 (MUST)** Per-agent keys: a message signed by agent A cannot verify as agent B.
- **FR-ID-2 (MUST)** Key strength enforced (≥ 32 random bytes); weak text keys refused.
- **FR-ID-3 (SHOULD)** Key rotation with an overlap window; revocation list.

### State
- **FR-ST-1 (MUST)** Nonces, strikes, quarantine and task taint persist across restarts (stdlib SQLite).
- **FR-ST-2 (MUST)** State shared safely by multiple processes on one host.

### Audit
- **FR-AUD-1 (MUST)** Every verdict recorded before the action runs; if the record can't be written, the verdict is BLOCK with a defined error.
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

| Gate | Criterion | Evidence |
|---|---|---|
| G1 | 0 unauthorized tool executions across red-team + conformance suites, **default policy** | CI report |
| G2 | 0 open Critical/High findings | Findings register |
| G3 | Every failure scenario fails closed | Conformance suite |
| G4 | Replay, forged identity, cross-agent signing resisted | Adversarial tests |
| G5 | Audit edits, rewrite, truncation, deletion, rollback detected | Tests |
| G6 | No regression across releases | CI on every PR |
| G7 | Quickstart works on a clean machine, all three OSes | CI + manual |
| G8 | Public API versioned; deprecation policy published | Docs |
| G9 | Independent review completed; findings triaged | External report |
| G10 | SBOM, signed tag, published hashes | Release assets |

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

## 10. Open decisions for the owner

1. **Breaking change for v2.0.** Default deny (ADR-0003) breaks every v1 integration that relies on undeclared tools. Proposal: v1.x keeps current behaviour with a deprecation warning; v2.0 flips the default.
2. **Enterprise boundary.** Confirm the "no protection held back" rule (§4).
3. **External reviewer** for gate G9: who, and when.
4. **ACS overlap.** Adopt, map to, or ignore the OWASP Agent Control Standard after evaluation.
