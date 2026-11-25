# Architecture — target for Core v2.0

Status: **proposed** (see [ADRs](../adr/)). Today's v1.0 code implements the Runtime box except the parts marked *new*.

```mermaid
flowchart TB
  subgraph CP[Control plane — Enterprise, Phase 3]
    PM[Policy management<br/>signed policy bundles]
    IDM[Identity & key management<br/>per-agent keys, rotation]
    GOV[Governance<br/>operator RBAC, approvals]
  end

  subgraph RT[Security runtime — Core, self-hosted, stdlib only]
    direction TB
    PROV[Identity & provenance<br/>tiers T0–T3, taint, envelopes]
    POL[Policy engine — new<br/>schema-validated, default deny,<br/>capabilities, scopes]
    DET[Threat detection<br/>L1 tripwire, secrets, egress]
    GW[Execution gateway<br/>tool / MCP / API guard, Human Gate]
    ST[(State store — new<br/>SQLite: nonces, strikes,<br/>quarantine, taint)]
    LED[(Audit ledger<br/>HMAC chain, checkpoints)]
    PROV --> POL --> DET --> GW
    POL -.reads.-> ST
    GW --> LED
  end

  BR[Brain — optional<br/>Claude / OpenAI / Gemini / Ollama<br/>may only tighten]
  AG[Agents<br/>Genesis Mind · SkynetClaw · MCP clients · external agents]
  TOOLS[Tools & MCP servers]
  OBS[Observability — Enterprise<br/>SIEM export, dashboard, metrics]

  AG -- every tool call, message, memory write --> PROV
  BR -. tighten only .-> GW
  GW -- allowed calls only --> TOOLS
  PM -- signed policy --> POL
  IDM -- public keys / secrets --> PROV
  LED --> OBS
```

## Authority rule

The runtime is the final authority. Agents and brains *propose*; the runtime *decides*. No path exists from model output to a looser verdict, a new scope, a new tier or a policy change (ADR-0001).

## Request path (tool call)

1. **Provenance.** Determine `origin_tier` (from the SDK helper, FR-INT-2) and taint of every argument.
2. **Policy.** Look up the tool. Not declared → BLOCK (default deny). Load capabilities and scopes; check the agent's role allows it.
3. **Detection.** L1 scan of arguments; secret detection on decoded views; destination checks for every network/message capability.
4. **Capability rules.** `exec` → shell rules; `network`/`message` → allowlists; `delete`/`money`/irreversible → Human Gate.
5. **Brain (optional).** May tighten.
6. **Ledger.** Record the verdict. If recording fails → BLOCK.
7. **Gateway.** Run the tool only on ALLOW / ALLOW_SANITIZED (or owner-approved HOLD).

## Boundaries

| Boundary | Trust assumption |
|---|---|
| Runtime ↔ host OS | Runtime trusts the OS; OS isolation (containers, users, network rules) is the integrator's job |
| Runtime ↔ policy | Policy is trusted **only if** it validates (and, when signing is on, verifies) |
| Runtime ↔ agents | Agents are untrusted principals with identities and scopes |
| Runtime ↔ brain | Brain is an untrusted advisor that can only tighten |
| Runtime ↔ ledger readers | Readers can verify integrity with the key; they cannot forge entries without it |

## Deployment shapes

| Shape | When |
|---|---|
| **In-process library** (today) | Single-process agents, SkynetClaw, notebooks |
| **Local sidecar / gateway** (Phase 2, optional) | Agents in other languages; MCP gateway between clients and servers |
| **Central control plane + many runtimes** (Phase 3) | Organizations with fleets of agents |

Cloud-hosted operation is deliberately deferred: it adds cost and attack surface before the core is proven.
