# API Reference

```python
from genesis_security import (
    GenesisSecurityGate, AuditTrail, Policy, Tier, Tainted, Verdict, scan_injection, verify_chain,
)
```

---

## `GenesisSecurityGate`

```python
GenesisSecurityGate(hmac_key: bytes, policy: Policy | None = None, audit: AuditTrail | None = None,
                    brain: Callable[[dict], dict | None] | None = None,
                    owner_confirm: Callable[[Verdict, dict], bool] | None = None)
```

| Parameter | Default | |
|---|---|---|
| `hmac_key` | — | At least 16 bytes. Signs envelopes; the audit key is derived from it |
| `policy` | packaged default | See [Policy Reference](Policy-Reference) |
| `audit` | `AuditTrail("genesis_security_audit.jsonl")` | If the trail has no key, the gate sets the derived audit key |
| `brain` | `None` | See [Brain Adapters](Brain-Adapters) |
| `owner_confirm` | `None` | Called for HOLD verdicts. See [Verdicts and the Human Gate](Verdicts-and-the-Human-Gate) |
| `policy_path` | `None` | Load and validate a policy file. On any error the gate enters **deny-all** instead of raising (since v1.1). Mutually exclusive with `policy` |

### `status() -> dict` · `policy_ok` (since v1.1)

`{"policy_ok", "policy_error", "policy_source", "policy_version", "mode", "quarantined"}`. `mode` is `"enforcing"` or `"deny-all"`.

### `GenesisSecurityGate.from_env(**kw)`

Reads `GENESIS_SECURITY_KEY` (hex, or raw text if not hex), and optionally `GENESIS_SECURITY_POLICY` (loaded as `policy_path`, so a broken file means deny-all) and `GENESIS_SECURITY_AUDIT`. Keyword arguments override them. Raises `RuntimeError` if the key is missing.

### `on_external_content(source: str, content: str, task_id: str = "-") -> tuple[Tainted, Verdict]`

Wraps content as T3 (`<untrusted …>`), escapes wrapper tags inside it, scans it, and marks `task_id` as tainted. See [External Content](External-Content).

### `pre_tool_call(tool: str, args: dict, ctx: dict) -> Verdict`

Runs L0–L5 for a tool call. `args` may contain nested `Tainted` values. `ctx` keys: `origin_tier` (required in practice; missing = T3), `agent`, `task_id`, `touches_private`. See [Guarding Tools](Guarding-Tools).

### `guard(tool_name: str)`

Decorator. The wrapped function is called as `wrapped(args: dict, ctx: dict)`. Runs the tool if allowed, otherwise raises `PermissionError("[GenesisSecurity] VERDICT [gsx]: reason")`.

### `make_envelope(frm, to, task_id, body, scope, hop=0, taint=Tier.T2) -> dict`

Returns a signed envelope with `from, to, task_id, capability_scope, hop, taint, ts, nonce, sig`.

### `on_agent_message(envelope, body, granted_scope, recipient=None) -> tuple[Tier, Verdict]`

Verifies signature, freshness, nonce, recipient, quarantine, hop budget, scope and body. Returns the tier to use as `origin_tier` for actions caused by this message. See [Multi-Agent Messaging](Multi-Agent-Messaging).

### `on_memory_write(path: str, content: str, src_tier: Tier) -> Verdict`

See [Memory Protection](Memory-Protection). For T3 facts, `verdict.sanitized_args["content"]` holds the tagged line to store.

### `on_skill_load(path: str, content: str, pinned_sha256: str | None) -> Verdict`

See [Skill and Plugin Pinning](Skill-and-Plugin-Pinning).

### `sign(body: str) -> str`

HMAC-SHA256 hex of `body` with the gate key.

### State attributes

| Attribute | Type | |
|---|---|---|
| `policy` | `Policy` | |
| `audit` | `AuditTrail` | |
| `strikes` | `dict[str, int]` | Injection strikes per agent |
| `quarantined` | `set[str]` | Quarantined agents |
| `task_taint` | `dict[str, Tier]` | Tasks that have seen T3 content |

---

## `Verdict`

Dataclass: `verdict: str`, `gsx: list[str]`, `severity: str`, `reason: str`, `sanitized_args: dict | None`, `requires_owner: bool`, `layer_trace: list[str]`.
Property `allowed` → `True` for `ALLOW` and `ALLOW_SANITIZED`. Constructing a `Verdict` with an unknown verdict string raises `ValueError`.

## `Tier`

`IntEnum`: `T0 = 0`, `T1 = 1`, `T2 = 2`, `T3 = 3`. Higher = less trusted.

## `Tainted`

Dataclass: `value: Any`, `tier: Tier`, `source: str = "unknown"`. Method `merge(other) -> Tier` returns the higher tier.

---

## `AuditTrail`

```python
AuditTrail(path="genesis_security_audit.jsonl", max_bytes=10_000_000, key: bytes | None = None)
```

| Method | |
|---|---|
| `record(event: str, payload: dict) -> str` | Append an entry under a file lock; returns its hash |
| `files() -> list[Path]` | Rotated files (oldest first), then the live file |
| `checkpoint() -> dict` | `{"count", "head"}`. Raises `RuntimeError` if the chain is already broken |
| `verify(checkpoint=None) -> tuple[bool, int]` | `(intact, valid_entries)`. With a checkpoint, also detects truncation and deletion |

`verify_chain(files, key=None, checkpoint=None) -> tuple[bool, int]` verifies an explicit list of files.
`genesis_security.audit.derive_audit_key(master_key) -> bytes` derives the audit key the gate uses.

---

## `Policy`

Dataclass with the fields described in [Policy Reference](Policy-Reference).

| Method | |
|---|---|
| `Policy.load(path=None)` | Load a TOML file, or the packaged default when `path` is `None` |
| `Policy.default()` | Same as `load()` |
| `Policy.from_dict(d)` | Validate and build from a parsed TOML dict |

`PolicyError(ValueError)` — raised by `load` / `from_dict`; `.errors` lists every problem, `.path` the file (since v1.1). `genesis_security.policy.validate(d) -> list[str]` returns the problems without raising.

---

## `scan_injection(text: str) -> tuple[str, list[str], list[str]]`

Returns `(status, gsx_ids, hits)`. `status` is `"clean"`, `"suspicious"` or `"injected"`. `hits` names the signals found (`override`, `role_swap`, `forged_authority`, `ai_directed`, `exfil_request`, `audit_tamper`, `urgency`, `zero_width_chars`, `hidden_html`, `long_base64`).

---

## Module `genesis_security.redteam`

`main() -> int` runs all cases, prints a table and returns the number of security failures. `CASES` is the list of `(id, title, informational, fn)` tuples. See [Red Team Guide](Red-Team-Guide).
