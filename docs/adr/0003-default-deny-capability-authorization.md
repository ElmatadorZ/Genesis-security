# ADR-0003: Default deny, runtime-owned capability registry, authenticated provenance

- Decision: **Proposed** · Owner direction: approved in principle ([Governance D1](../product/governance-decisions.md#d1--default-deny-transition))
- Implementation: **Not approved** (Governance D5)
- Date: 2026-11-25 · Revised 2026-11-25 after review (PR #1)
- Closes: GS-AUD-01, GS-AUD-02, GS-AUD-09, GS-AUD-14

## Context

v1.0 allows any tool it doesn't know (GS-AUD-01) and applies shell rules only to a tool literally named `shell_exec` with argument `cmd` (GS-AUD-02). Rules keyed on names are bypassed by renaming. `origin_tier` is whatever the caller passes (GS-AUD-09). Principle P3 requires the opposite: nothing privileged runs unless policy authorizes it.

## Decision

### 1. The capability registry belongs to the runtime

- Tool declarations live **only in the validated (and optionally signed) policy** (ADR-0004). Agents, models, tool descriptions, MCP servers and SDK callers **cannot declare, extend or modify** capabilities at run time.
- At start-up the runtime binds each declared tool name to the **callable it wraps** (`@gate.guard` / gateway registration). A call for a name with no binding, or a binding whose policy entry is missing, is `BLOCK`.
- Declaration shape:

  ```toml
  [tools.run_command]
  capabilities = ["exec"]
  command_arg  = "cmd"
  irreversible = true

  [tools.http_get]
  capabilities     = ["network"]
  destination_args = ["url"]

  [tools.send_email]
  capabilities     = ["message"]
  destination_args = ["to", "cc", "bcc"]
  irreversible     = true
  ```

- Capabilities are a closed set defined by Core: `read`, `write`, `delete`, `network`, `message`, `exec`, `money`. Unknown capability → policy load error.

### 2. Default deny

An undeclared tool → `BLOCK` (`GSX-02`, "tool not declared in policy").

### 3. Rules follow capabilities, never names

| Capability | Rules |
|---|---|
| `exec` | Canonicalize the command (§5), then metacharacters, command allowlist, `deny_args`, indirect-execution rules. Irreversible by default |
| `network` | Host allowlist on `destination_args`, URL scan of every argument at any depth, secret detection on decoded views |
| `message` | Recipient-domain / channel allowlist on `destination_args`, secret detection. Irreversible by default |
| `delete`, `money` | Irreversible (Human Gate) |
| `read`, `write` | Path allowlist (if configured), secret detection on `write` |

A tool may hold several capabilities; it gets the union of their rules.

### 4. Authenticated provenance replaces caller-supplied `origin_tier`

`origin_tier` stops being an argument the caller sets. The SDK builds it from a **provenance chain** of signed records:

- Each input enters through a typed constructor: `OwnerMessage` (T1, requires an owner credential configured by the operator), `ToolResult`, `FetchedContent` (T3), `AgentMessage` (verified envelope; tier from ADR-0005 identity).
- The runtime signs each record (HMAC, ADR-0005 key) and links the records a model turn consumed.
- A tool call's origin tier = **the least trusted record in the chain the model saw in that turn**, unless the integrator explicitly scopes the call to a single owner record.
- No record → T3. An unverifiable record → T3 and an audit event.

Limit, stated plainly: the runtime cannot see inside the model. It knows what the model *was shown*, not what it *acted on*. The chain therefore errs toward T3: if a turn contained any T3 record, actions from that turn are T3 unless scoped to an owner record. This is conservative by design.

v1.x keeps the `origin_tier` argument for compatibility; it is marked unauthenticated in the audit log (`provenance=caller`).

### 5. Canonicalization before checks

Checks run on the **canonical form** of each argument, never the raw string:

- **Text:** Unicode NFKC, zero-width characters removed, percent-decoding (repeated until stable, max 3 rounds), then checks; both raw and canonical forms are scanned for secrets.
- **URLs:** parsed once with a single parser; scheme lower-cased; host lower-cased and IDNA-encoded; userinfo, backslashes, control characters, mixed-script hosts → malformed → `HOLD`. The host used for the allowlist is the host the HTTP client will actually connect to (the gateway passes the canonical URL to the tool, not the raw one).
- **Shell:** `shlex.split` with POSIX rules; reject on parse error; resolve the executable's basename; apply rules to the *effective* command after stripping wrappers:
  - **Wrapper / indirect execution** — `env`, `nice`, `nohup`, `timeout`, `sudo`, `xargs`, `sh -c`, `bash -c`, `cmd /c`, `powershell -Command`, `python -c`, `node -e`, `perl -e`, `ruby -e`, `find -exec`, `git -c` — either refused outright (default) or unwrapped and re-checked, per policy.
  - Script execution (`python script.py`, `sh script.sh`) is `exec` of content not covered by the allowlist → `HOLD` with the script path and its SHA-256 shown to the owner.
- Canonicalization is a single shared module with its own fuzz tests (P4-02).

### 6. Compatibility mode (binding conditions from Governance D1, plus review)

- v1.x **compatibility mode**: undeclared tools keep v1 behaviour; every such call logs a warning containing `NOT SECURE ENFORCEMENT`; audit records `mode=compat`.
- **No accidental enabling.** In v2.0, compatibility mode requires an explicit, named setting (`compat_mode = "v1-insecure"`) **and** an environment acknowledgement (`GENESIS_SECURITY_ACCEPT_INSECURE_COMPAT=1`). Either missing → strict.
- **Shadow mode** (`mode=shadow`): evaluates v2.0 rules beside v1.x, reports what would be blocked, never changes a v1.x verdict.
- Compatibility mode is never described as secure enforcement anywhere.
- **Sunset** (Governance R2, R3 — approved): compatibility mode is removed in v3.0. v1.x receives security fixes for **6 months** after v2.0 ships, stated in the release policy (ADR-0008).
- A migration guide ships with the first warning release.

## Consequences

- Closes the rename bypass, default-allow and caller-asserted provenance gaps.
- Integrators declare tools and route inputs through typed constructors — more setup, offset by `policy init` and SDK helpers.
- Provenance is conservative: some legitimate actions become T3 and need owner approval or explicit owner scoping.
- Breaking change at v2.0 (Governance D1).
