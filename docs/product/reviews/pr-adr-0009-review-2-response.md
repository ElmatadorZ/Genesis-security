# Architecture review round 2 — response

Review input: "Architecture Review Decision", 2026-11-25 — documentation PR approved; ADR-0009, URI identity, MCP gateway promotion and AgentDojo evaluation approved in principle; Plan-Constrained Execution approved for beta design; source code for these items not approved.

## Requested documents

| Requested | Delivered |
|---|---|
| `ADR-0009-turn-level-information-flow.md` | `docs/adr/0009-turn-level-information-flow.md` (repository naming convention: no `ADR-` prefix) |
| Revise ADR-0005 | Identity / credential / authorization split; SPIFFE-ID-shaped URIs; no secrets in URIs; identity stable across rotation; `CredentialProvider` with HMAC default; explicit "no WIMSE/SPIFFE support claim" |
| Revise Architecture v2.0 | Three enforcement modes on one core; Flow component; MCP as an adapter with no security logic; enforcement-boundary row |
| Roadmap v2.0-alpha / beta | Reviewer's order kept; alpha split into alpha.1 / alpha.2 (proposal, see below) |
| AgentDojo evaluation plan | `docs/product/evaluation-plan-agentdojo.md` — arms A/B/C, AgentDojo metrics with their own definitions, Genesis metrics separately, pre-registered ≤ 20 pp *Maximum Acceptable Benign Task Regression*, supplementary suite |
| Threat model for Gate + Flow | `docs/product/threat-model-gate-flow.md` — F1–F12 with residuals |
| Acceptance criteria for readers, taint propagation, egress | Backlog P1-18 … P1-23 |

## Technical points adopted

| Review point | Where |
|---|---|
| Flow state accumulates over turns/tasks, not per turn | ADR-0009 §1 |
| Intersection of readers when classes combine | §4 |
| Propagation across agents with authenticated provenance | §6 |
| Readers are principals and sink policies, not domains | §3 |
| Enforcement boundary + fail-closed | §8 |
| Plan authorization ≠ constrained execution ≠ CFI; name it "Plan-Constrained Execution"; plan hash covers security-relevant detail; branching/retry/timeout/expiry/emergency stop; MT5 still needs market-risk controls | Architecture; spec FR-PLAN-1/2; backlog P2-07 |
| MCP gateway uses the shared Policy Engine and Execution Gateway; three modes are not three codebases | Architecture; backlog P2-03 |
| "Max acceptable benign task regression" ≠ false positive rate | Evaluation plan |
| Principles: label strength = enforcement boundary; never confuse detection with enforcement | Spec P7, P8; ADR-0009 |

## Additions not in the review

1. **Declassification (ADR-0009 §7).** Without an owner-only way to lower flow state, a session that read private data could never send anything again.
2. **Default class is private (`private:unclassified`).** An undeclared reading tool must not make data public by omission.
3. **Control-flow leakage named as a residual** (choosing which allowed action to take reveals information); only mode 03 addresses it.

## Proposal needing the owner

**Split v2.0-alpha into alpha.1 and alpha.2.** The review placed six items in alpha and also asked that alpha not become too large for one developer; both cannot hold. alpha.1 = structural core + identity URI; alpha.2 = flow + MCP + evaluation.

## Status note

The review states "PR #1 merge: pending full review" and "Source code implementation: not approved". Repository state differs: the owner approved merging PR #1 and starting v1.1 code on 2026-11-25 (Governance D5, updated). PR #1 is merged; PR #7 (v1.1 policy validation) is open and unmerged. This PR changes neither; the owner should confirm whether the review's "not approved" applies to v1.1 (PR #7) or only to the new ADR-0009/0005 work.
