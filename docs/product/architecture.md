# Architecture — target for Core v2.0

Status: **proposed** (see [ADRs](../adr/)). Today's code implements the Runtime box except the parts marked *new*. Revised 2026-11-25 after architecture review round 2 (three enforcement modes on one core; MCP as an adapter of the Execution Gateway; information-flow state, ADR-0009; identity/credential split, ADR-0005), and aligned with the Batch 1 architecture baseline (PR #8, Rev7 accepted).

```mermaid
flowchart TB
  subgraph CP[Control plane — Enterprise, Phase 3]
    PM[Policy management<br/>authenticated or signed bundles]
    IDM[Identity & credentials<br/>URI identities, credential providers]
    GOV[Governance<br/>operator RBAC, approvals]
  end

  subgraph RT[Security runtime — Core, self-hosted, stdlib only]
    direction TB
    PROV[Identity & provenance<br/>URI identities, tiers, envelopes]
    POL[Policy engine — new<br/>schema-validated, default deny,<br/>capabilities, scopes]
    DET[Threat detection<br/>L1 tripwire, secrets, egress]
    GW[Execution gateway<br/>tool / MCP / API guard, Human Gate]
    FLOW[Flow state — new<br/>session data classes,<br/>readers, declassification]
    ST[(State store — new, authoritative<br/>SQLite: nonces, strikes, quarantine,<br/>flow state, permits, grants,<br/>policy versions, epochs)]
    LED[(Audit ledger<br/>HMAC chain, checkpoints)]
    PROV --> POL --> DET --> FLOW --> GW
    POL -.reads.-> ST
    FLOW -.reads/writes.-> ST
    GW --> LED
  end

  BR[Brain — optional<br/>Claude / OpenAI / Gemini / Ollama<br/>may only tighten]
  AG[Agents<br/>Genesis Mind · SkynetClaw · MCP clients · external agents]
  MCPA[MCP adapter — new<br/>no security engine of its own]
  TOOLS[Tools & MCP servers]
  OBS[Observability — Enterprise<br/>SIEM export, dashboard, metrics]

  AG -- every tool call, message, memory write --> PROV
  BR -. tighten only .-> GW
  GW -- allowed calls only --> TOOLS
  MCPA -- tools/call --> GW
  PM -- validated policy --> POL
  IDM -- public keys / secrets --> PROV
  LED --> OBS
```

## Three enforcement modes, one core

| Mode | For | Adds | Shares |
|---|---|---|---|
| **01 · Gate** (default) | Everyone; drop-in | Tool authorization, default-deny, policy enforcement | Security core, identity, policy engine, Execution Gateway, audit ledger |
| **02 · Gate + Flow** (advanced) | Developers handling private data | Session information-flow state, readers = principals and sinks, declassification (ADR-0009) | same |
| **03 · Plan-Constrained** (high-assurance deployments) | High-stakes agents (e.g. trading) | Approved plan hash, deterministic executor checking step, transition, arguments, capability (v2.0-beta design) | same |

Rules: one codebase; a mode is a configuration of the same engine, never a fork. The MCP gateway and any other front-end (HTTP sidecar, SDK decorator) **call the same Policy Engine and Execution Gateway**; none has its own security logic.

Plan-Constrained Execution is not called control-flow integrity (CFI) until its properties are proven; human approval of a plan plus an LLM choosing steps is not CFI. It is also not market-risk control: trading deployments still need position and exposure limits, a kill switch and broker-side risk controls.

## Egress path in mode 02 (ADR-0009 §4–§5)

```
agent request ─► sink resolution (canonical URL / structured fields, verification level, recipients, closed arguments)
              ─► freeze: one immutable request buffer, SHA-256 digest
              ─► authorize (BEGIN IMMEDIATE): effective readers at state version v → permit + ledger
              ─► revalidate & consume (BEGIN IMMEDIATE): re-evaluate if version changed; single use
              ─► verify digest, write the same buffer to TLS (CONNECT to verified IP if proxied)
              ─► record outcome (sent / failed / unknown) with issued / revalidated / consumed versions
```

## Dependency chain

Build order — each stage relies only on the stages before it; none may be implemented on assumptions about a later one:

Identity & credentials (ADR-0005) → trusted runtime & authoritative state store (ADR-0006, ADR-0009 §2) → audit ledger (ADR-0007) → information-flow engine (ADR-0009 §1, §3, §7, §8, §10) → sink resolution & Execution Gateway (ADR-0009 §4–§6, ADR-0003) → authenticated & authorized execution.

The ledger sits **before** execution in this chain because recording is **write-before-act** (ADR-0007), in two phases:

| Phase | Recorded | If recording fails |
|---|---|---|
| **Before the side effect** | Authorization decision, permit issue (with ledger commit), permit revalidation and consumption | BLOCK — no side effect |
| **After the side effect** | Execution outcome (`sent` / `failed`) with issued, revalidated and consumed versions | Outcome recorded as `unknown` at the next opportunity (including restart); never retried automatically |

## Authority rule

The runtime is the final authority. Agents and brains *propose*; the runtime *decides*. No path exists from model output to a looser verdict, a new scope, a new tier or a policy change (ADR-0001).

## Request path (tool call)

Full sequence for every tool call; steps 4a and 4b run only in modes 02 and 03.


1. **Provenance.** Determine `origin_tier` from the authenticated provenance chain (ADR-0003 §4) and the caller's identity (ADR-0005).
2. **Policy.** Look up the tool. Not declared → BLOCK (default deny). Load capabilities and scopes; check the agent's role allows it.
3. **Detection.** L1 scan of arguments; secret detection on decoded views; destination checks for every network/message capability.
4. **Capability rules.** `exec` → shell rules; `network`/`message` → allowlists; `delete`/`money`/irreversible → Human Gate.
4a. **Flow (mode 02+).** Resolve the destination to a verified sink (ADR-0009 §5). If the session holds private classes, the sink must be in `effective_readers(session)` = ⋂ over classes of (policy readers ∪ per-class grants) (§1); else BLOCK. On ALLOW the egress follows the permit path below.
4b. **Plan (mode 03).** The call must match the next allowed step of the approved plan; else HOLD/BLOCK.
5. **Brain (optional).** May tighten.
6. **Ledger.** Record the verdict. If recording fails → BLOCK.
7. **Gateway.** Run the tool only on ALLOW / ALLOW_SANITIZED (or owner-approved HOLD).

## Boundaries

| Boundary | Trust assumption |
|---|---|
| Runtime ↔ host OS | Runtime trusts the OS; OS isolation (containers, users, network rules) is the integrator's job |
| Runtime ↔ policy | Policy is trusted **only if** it validates (and, when signing is on, verifies) |
| Runtime ↔ agents | Agents are untrusted principals with URI identities, credentials and scopes |
| Enforcement boundary | Guarantees cover only actions and egress that pass through the Execution Gateway; deployments must route all agent egress through it (ADR-0009 §9) |
| Runtime ↔ state store | The store is authoritative and writable only by the runtimes of one deployment; agents cannot reach it. Its integrity is a precondition, not something the runtime can prove (ADR-0005 §7, ADR-0009 §2) |
| Gateway ↔ remote server | The gateway controls the bytes, the address and the verified identity; the remote server's own parsing and onward sharing are outside the boundary (ADR-0009 §5) |
| Runtime ↔ brain | Brain is an untrusted advisor that can only tighten |
| Runtime ↔ ledger readers | Readers can verify integrity with the key; they cannot forge entries without it |

## Deployment shapes

| Shape | When |
|---|---|
| **In-process library** (today) | Single-process agents, SkynetClaw, notebooks. Protects against manipulated models, **not** compromised agent code (no memory isolation in one process) |
| **Out-of-process runtime** (required for mode 02 cross-agent guarantees) | Runtime as a separate process/OS user holding credentials and the state store; agents request, the runtime records, signs and enforces (ADR-0009 §2) |
| **Local sidecar / gateway** (Phase 2, optional) | Agents in other languages; MCP gateway between clients and servers |
| **Central control plane + many runtimes** (Phase 3) | Organizations with fleets of agents |

Cloud-hosted operation is deliberately deferred: it adds cost and attack surface before the core is proven.
