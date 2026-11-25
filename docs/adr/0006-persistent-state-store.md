# ADR-0006: Persistent security state in SQLite

- Decision: **Proposed**
- Implementation: **Not approved** (Governance D5)
- Date: 2026-11-25 · Revised 2026-11-25 after review (PR #1)
- Closes: GS-AUD-05, GS-AUD-12

## Context

Strikes, quarantine, task taint and the replay-nonce cache live in Python dicts: lost on restart, unshared between processes, and their thread safety relies on the GIL. **No security property may depend on interpreter implementation details.**

## Decision

### 1. Interface and backends

A `StateStore` interface with two implementations: `SQLiteStateStore` (stdlib `sqlite3`) for single-node deployments, and `MemoryStateStore` for tests only (refused by the runtime unless `test_mode=True`). Multi-host shared state is out of Core scope (Enterprise, Phase 3).

### 2. Schema (v1)

```sql
CREATE TABLE meta       (key TEXT PRIMARY KEY, value TEXT NOT NULL);           -- schema_version, deployment_id
CREATE TABLE nonces     (nonce TEXT PRIMARY KEY, sender TEXT NOT NULL, ts REAL NOT NULL);
CREATE TABLE strikes    (agent TEXT PRIMARY KEY, count INTEGER NOT NULL, updated REAL NOT NULL);
CREATE TABLE quarantine (agent TEXT PRIMARY KEY, since REAL NOT NULL, reason TEXT NOT NULL);
CREATE TABLE revocations(agent TEXT NOT NULL, epoch INTEGER, since REAL NOT NULL, PRIMARY KEY(agent, epoch));
CREATE TABLE task_taint (task TEXT PRIMARY KEY, tier INTEGER NOT NULL, ts REAL NOT NULL);
```

### 3. Transactions and atomic replay detection

- Every state change is one transaction started with `BEGIN IMMEDIATE` (takes the write lock up front: no lost updates between read and write).
- **Replay check is a single statement:** `INSERT INTO nonces(nonce, sender, ts) VALUES (?, ?, ?) ON CONFLICT(nonce) DO NOTHING`, then `changes() == 1` ⇒ first sighting; `0` ⇒ replay ⇒ `BLOCK`. The uniqueness constraint in SQLite, not Python, decides — correct across threads, processes and interpreters without a GIL.
- Strike increment and quarantine insertion happen in the **same** transaction, so a crash cannot record a strike without the resulting quarantine.
- Isolation: SQLite transactions are serializable for writers; readers in WAL mode see a consistent snapshot.

### 4. Durability configuration

`PRAGMA journal_mode = WAL` · `PRAGMA synchronous = FULL` (a committed nonce or quarantine survives power loss; we accept the latency) · `PRAGMA foreign_keys = ON` · `PRAGMA busy_timeout = 5000`.

### 5. Locking and contention

- `busy_timeout` 5 s; on `SQLITE_BUSY` after the timeout → the operation fails → **`BLOCK`** (fail closed), with an audit event.
- One connection per thread; connections are never shared across threads or processes.
- Tested with N processes × M threads, on CPython with the GIL and on the free-threaded build (3.13t+).

### 6. File permissions

The database and its `-wal` / `-shm` files are created with mode `0600` (POSIX) or an owner-only ACL (Windows). The runtime refuses to open a store readable or writable by other users.

### 7. Integrity and corruption recovery

- `PRAGMA quick_check` at start-up; failure → the runtime refuses to start in enforcing mode (deny-all) until an operator acts.
- **Recovery is never automatic and never permissive.** `genesis-security state recover` creates a fresh store; quarantine and revocation are re-imported from the last good backup **or** from the audit ledger (which records every quarantine and revocation event). Lost nonces are covered by `max_age_s`: the runtime refuses all envelopes older than the recovery time.

### 8. Schema migration

`meta.schema_version` checked at open. Migrations are forward-only, run in one transaction, back up the file first, and are recorded in the audit ledger. A store with a **newer** schema than the runtime → refuse to start.

### 9. Backup and restore

`genesis-security state backup` uses the SQLite online backup API (consistent snapshot while running). Restore is an offline operator action. Restoring an older backup can resurrect old nonces' *absence*: after a restore, the runtime refuses envelopes older than the restore time.

## Consequences

- Quarantine, revocation and replay protection survive restarts and span processes on one host.
- `synchronous=FULL` costs latency per state write; benchmarked against NFR-2 (P1-12).
- Multi-host fleets need a shared store with the same semantics (Enterprise).
