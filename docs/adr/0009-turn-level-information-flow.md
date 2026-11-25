# ADR-0009: Session information-flow state ("Gate + Flow")

- Decision: **Proposed** · Owner/reviewer direction: approved in principle (architecture review round 2, 2026-11-25)
- Implementation: **Not approved**
- Date: 2026-11-25
- Related: ADR-0003 (capabilities, provenance), ADR-0005 (identity), ADR-0007 (ledger); threat model: [Gate + Flow](../product/threat-model-gate-flow.md)

## Context

Genesis Security v1 gates individual tool calls. Its residual risk R6 — a secret re-encoded (rot13, gzip, XOR) and sent to an **allowlisted** host — cannot be closed by inspecting content, because encodings are unbounded.

Research systems close this class with information-flow control. CaMeL attaches capabilities to every value and enforces policies at tool-call time; on AgentDojo it solved 77% of tasks with provable security versus 84% undefended ([Debenedetti et al., 2025](https://arxiv.org/abs/2503.18813)). That works because values flow through CaMeL's own interpreter.

**Genesis is a gate, not an interpreter.** When a model reads private data and writes new text, the output is a fresh string: a per-value label cannot survive the model. A first proposal to add per-value "Readers" labels was withdrawn for this reason.

> **Principle:** A security label is only as strong as the enforcement boundary that preserves it.

## Decision

### 1. Flow state is accumulated, not per-message

The runtime keeps a **flow state** per *session* (and per *task* inside a session). Each time an action **reads** data of a declared class, the flow state is raised; it never falls by itself.

```
flow_state = {
  classes:  set of data classes read so far          e.g. {"private:accounts", "private:notes"}
  readers:  intersection of the readers of those classes (see §3)
  sources:  provenance records that raised it (ADR-0003 §4)
}
```

- A new turn **inherits** the session's flow state. Starting a new turn does not clean it.
- A new task inherits from its parent session unless the owner starts it explicitly as a clean task (audited).
- Flow state is stored in the state store (ADR-0006) so it survives restarts.

### 2. Data classes and sources are declared in policy (schema 2)

```toml
[data_classes."private:accounts"]
readers = ["spiffe://genesis.local/owner", "sink:bank-api"]

[data_classes."private:notes"]
readers = ["spiffe://genesis.local/owner", "sink:notes-store"]

[tools.read_statement]
capabilities = ["read"]
produces = ["private:accounts"]          # reading through this tool raises flow state
```

- Only the validated policy declares classes and which tools produce them (ADR-0003 §1). Agents and models cannot.
- A tool that reads data without a `produces` declaration produces the default class `private:unclassified`, whose readers are the owner only. **Default is private, not public.**

### 3. Readers are principals and sinks, not host names

A reader is either a **principal** (an identity URI, ADR-0005) or a **named sink**:

```toml
[sinks."sink:bank-api"]
tool        = "http_request"
destination = "https://api.bank.example/v1/transfers"   # exact scheme + host + path prefix
principal   = "spiffe://bank.example/api"                # who receives the data there
onward_sharing = false                                   # sink policy: endpoint does not forward to third parties
```

- Allowing a **domain** is not allowing a **recipient**. `api.company.com` may have an endpoint that forwards data to third parties. A sink names the endpoint path, the receiving principal, and whether it may forward onward.
- A sink with `onward_sharing = true` may receive only data classes whose readers explicitly include `sink:<name>+onward`.

### 4. Combining data: intersection

When a session has read several classes, the permitted readers are the **intersection** of their readers. Reading `private:accounts` and `private:notes` above leaves only `spiffe://genesis.local/owner`. An empty intersection means no egress at all until declassification (§7).

### 5. Egress enforcement

For every call with a `network` or `message` capability (ADR-0003 §3):

1. Resolve the call's destination to a sink or principal using the canonical URL / recipient (ADR-0003 §5). Unresolvable → **BLOCK**.
2. If the session's flow state is empty (no private class read) → normal Gate rules.
3. Otherwise the destination must be in `flow_state.readers` → else **BLOCK** (`GSX-06`, reason names the class and the sink). Not HOLD: the owner widens readers through policy or declassification, never by approving a single leak.
4. Content is **not** inspected for this decision. rot13, base64, unicode transformations or paraphrase change nothing: the destination is what is checked.

### 6. Propagation across agents

- Envelopes (ADR-0005) carry the sender's flow state (`classes`, plus a digest of `sources`), covered by the signature.
- The receiver's session flow state is raised to include the sender's. An unsigned or unverifiable message raises the receiver to `private:unclassified` (owner-only) as a precaution.
- A relay agent cannot lower flow state: the envelope is checked against the sender's recorded state in the shared state store where available; a mismatch is a `GSX-07` event.

### 7. Declassification

Flow state falls only through **declassification**: an explicit owner action (CLI, Human Gate with a dedicated prompt, or policy rule) that names the class, the session and the reason. It is recorded in the ledger. A model or agent can request declassification; only the owner grants it. Without this, a session that touched private data could never send anything again.

### 8. Enforcement boundary

The guarantees in this ADR hold **only for egress that passes through the Execution Gateway**. The ADR therefore requires:

- Deployments declare their enforcement boundary: which processes may reach the network or messaging systems.
- In Gate + Flow mode the runtime refuses to start if the agent process has an unconstrained network tool registered outside the gateway (detectable in-process); for out-of-process tools, the deployment guide requires OS-level egress rules (firewall, container network policy) that permit only the gateway. `genesis-security doctor` checks what it can and reports the rest as unverified.
- Any failure to read or write flow state → **BLOCK** (fail closed).

## What this does and does not guarantee

| Guaranteed (within the boundary) | Not guaranteed |
|---|---|
| Data of a declared class cannot reach a sink or principal outside its readers through the gateway, regardless of encoding | Egress that bypasses the gateway (direct sockets, other processes) |
| Combining classes narrows, never widens, who may receive | Correct classification: a tool that should produce `private:*` but is declared without it falls back to `private:unclassified`, not to public |
| Flow state survives turns, tasks (unless explicitly clean), restarts and agent relays | Covert channels inside an allowed sink (timing, choice among allowed actions) |
| Only the owner lowers flow state, and every lowering is audited | Leakage through *actions* that carry no data payload but reveal information by being taken (e.g. "buy if balance > X") — this is control-flow leakage, addressed only by Plan-Constrained Execution |

## Consequences

- Closes residual risk R6 for traffic inside the boundary, by structure instead of detection.
- Utility cost: sessions that read private data become restricted. The cost is measured, not assumed — see the [evaluation plan](../product/evaluation-plan-agentdojo.md) metric *Maximum Acceptable Benign Task Regression*.
- Requires schema 2 policies with `data_classes`, `sinks` and `produces`.
- Confidence that this is the most valuable next control: **65 %, unearned** (no experiment yet). Revisit after the evaluation.

> **Principle:** Never confuse detection with enforcement.
