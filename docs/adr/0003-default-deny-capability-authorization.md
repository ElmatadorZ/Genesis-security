# ADR-0003: Default deny with capability-based tool authorization

- Status: **Accepted in principle** ([Governance D1](../product/governance-decisions.md#d1--default-deny-transition)); implementation not yet approved
- Date: 2026-11-25
- Closes: GS-AUD-01, GS-AUD-02, GS-AUD-09, GS-AUD-14

## Context

v1.0 allows any tool it doesn't know (GS-AUD-01) and applies shell rules only to a tool literally named `shell_exec` with argument `cmd` (GS-AUD-02). Rules keyed on names are bypassed by renaming. Principle P3 requires the opposite: nothing privileged runs unless policy authorizes it.

## Decision

1. **Tool registry in policy.** Every tool must be declared:

   ```toml
   [tools.run_command]
   capabilities = ["exec"]
   command_arg = "cmd"          # which argument holds the command
   irreversible = true

   [tools.http_get]
   capabilities = ["network"]
   destination_args = ["url"]

   [tools.send_email]
   capabilities = ["message"]
   destination_args = ["to", "cc", "bcc"]
   irreversible = true
   ```

2. **Default deny.** An undeclared tool → `BLOCK` (`GSX-02`, reason "tool not declared in policy").
3. **Rules follow capabilities, not names.** `exec` → shell rules on `command_arg`; `network` → URL host allowlist on `destination_args` *and* URL scan of all args; `message` → recipient-domain allowlist (`[egress].recipient_domains`); `delete`, `money` → irreversible by default.
4. **Per-agent roles** (`[roles.<name>].tools = [...]`) limit which declared tools an agent may call.
5. **Provenance helper** in the SDK derives `origin_tier` from the message chain, so integrators stop hand-tagging (closes GS-AUD-09 at the API level).
6. **Migration** (binding conditions from Governance D1):
   - v1.x **compatibility mode**: undeclared tools keep v1 behaviour but every call logs a warning containing `NOT SECURE ENFORCEMENT`, and the audit entry records `mode=compat`.
   - **Shadow mode** (`mode=shadow`): evaluates v2.0 rules alongside v1.x and reports what would be blocked, without blocking — the pre-upgrade compatibility check.
   - Compatibility mode is never described as secure enforcement anywhere.
   - A migration guide ships with the first warning release.
   - v2.0: default-deny is the default; `strict = true` additionally removes every compatibility path.

## Consequences

- Closes the rename bypass and default-allow gaps.
- Integrators must declare tools — more setup, offset by `genesis-security policy init` scanning a tool list and generating declarations to review.
- Breaking change at v2.0 (spec §10, decision 1).
