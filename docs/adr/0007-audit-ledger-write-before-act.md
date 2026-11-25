# ADR-0007: Audit ledger — commit before act; failure contract; integrity ≠ immutability

- Decision: **Proposed**
- Implementation: **Not approved** (Governance D5)
- Date: 2026-11-25 · Revised 2026-11-25 after review (PR #1)
- Closes: GS-AUD-11

## Context

v1.0 records every verdict before returning it, but a failed write escapes as a raw OS exception (GS-AUD-11). The first draft of this ADR mixed two API behaviours in one sentence, and called the ledger "tamper-evident" without separating what a keyed hash chain can and cannot prove.

## Decision

### 1. Ordering: commit before act

For every action the order is fixed:

1. Decide (L0–L5, transitions per ADR-0001).
2. **Commit** the verdict to the ledger (write + flush + `fsync`).
3. Only if the committed verdict permits it, execute the tool.
4. Commit an outcome record (`executed` / `failed`, duration) — best effort; failure here is logged loudly but cannot un-run the tool.

There is **no code path** in which a tool executes before step 2 succeeds, and **no fallback** that executes a tool when step 2 fails.

### 2. Failure contract — one rule per API

| API | When the ledger commit fails |
|---|---|
| `pre_tool_call(...)` → `Verdict` | **Returns** `Verdict("BLOCK", gsx=["GSX-13"], reason="audit unavailable")`. Does not raise |
| `@gate.guard(name)` wrapper | **Raises** `AuditUnavailableError` (subclass of `GenesisSecurityError`). The wrapped tool is not called |
| `on_agent_message`, `on_memory_write`, `on_skill_load` | Return `BLOCK` (and tier T3 where applicable). Do not raise |
| Gateway / MCP proxy | Returns a tool error to the client; the upstream tool is not called |

The two behaviours do not conflict: `pre_tool_call` is a decision API and always answers with a verdict; `@guard` is an execution API and signals refusal by raising, as it already does for any non-allowed verdict. **No raw `OSError` escapes any public API** (tested).

### 3. Entry contents

Each entry adds `policy_fp` (ADR-0004), `runtime_version`, `agent_key_epoch` (ADR-0005), `provenance` (ADR-0003) and the transition record (ADR-0001). Secrets are never written (existing redaction + tests).

### 4. Three different properties — never conflated

| Property | Mechanism | What it gives | Who can defeat it |
|---|---|---|---|
| **Integrity detection** (Core) | HMAC-SHA256 chain under the audit key (HKDF label `…/audit-chain`), checkpoints | Detects edit, reorder, deletion, truncation (with checkpoint) by anyone **without the audit key** | Anyone who holds **both** write access to the ledger **and** the audit key can rebuild a valid chain |
| **External anchoring** (Core, optional sink) | Periodic checkpoints exported to a location the runtime cannot rewrite: another machine, the owner's phone, git notes in a remote repo, a timestamping service | Detects a rebuilt chain that no longer matches an earlier anchored head | Defeated only if the attacker also controls every anchor location |
| **Immutable storage** (Enterprise / deployment) | Write-once media or object lock (WORM), append-only remote log service | Entries cannot be altered after write, even by the key holder | Defeated only by the storage provider |

Documentation, CLI output and marketing say "integrity-protected" or "tamper-evident", never "tamper-proof", unless immutable storage is configured and named.

### 5. Export

Stable export schema (`schema_version`) for SIEM ingestion; field names frozen within a major version (ADR-0008).

## Consequences

- An unavailable ledger stops all actions — the intended trade-off for principle P4.
- Real tamper resistance against a host compromise requires external anchoring or immutable storage; Core makes anchoring easy and says so honestly.
