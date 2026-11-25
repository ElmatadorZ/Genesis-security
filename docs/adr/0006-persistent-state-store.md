# ADR-0006: Persistent security state in SQLite

- Status: **Proposed**
- Date: 2026-11-25
- Closes: GS-AUD-05, GS-AUD-12

## Context

Strikes, quarantine, task taint and the replay-nonce cache live in Python dicts: lost on restart, unshared between processes, and thread safety relies on the GIL.

## Decision

1. A `StateStore` interface with a stdlib `sqlite3` implementation (WAL mode, one file per deployment) and an in-memory implementation for tests.
2. Tables: `nonces(nonce PK, ts)`, `strikes(agent PK, count, updated)`, `quarantine(agent PK, since, reason)`, `task_taint(task PK, tier, ts)`.
3. Nonce insert uses `INSERT … ON CONFLICT DO NOTHING` and checks the row count: atomic replay detection across threads and processes.
4. Expiry by `max_age_s` (nonces) and configurable TTL (taint).
5. Releasing quarantine is an explicit, audited operator action (`genesis-security quarantine release <agent>`).
6. Store errors → `BLOCK` (fail closed).

## Consequences

- Quarantine and replay protection survive restarts and span processes on one host.
- Multi-host fleets need a shared store (Enterprise, Phase 3).
