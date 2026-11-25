# ADR-0003: Default deny with capability-based tool authorization

- Status: **Proposed**
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
6. **Migration.** v1.x: undeclared tools log a deprecation warning and keep v1 behaviour unless `strict = true`. v2.0: strict is the default.

## Consequences

- Closes the rename bypass and default-allow gaps.
- Integrators must declare tools — more setup, offset by `genesis-security policy init` scanning a tool list and generating declarations to review.
- Breaking change at v2.0 (spec §10, decision 1).
