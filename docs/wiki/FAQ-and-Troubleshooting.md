# FAQ and Troubleshooting

## General

**Is this a prompt-injection detector?**
Partly. L1 detects common injection phrasing, but the important layers don't depend on detection at all. L2 blocks any action that doesn't trace back to you, however the injection was worded.

**Does it work with models other than Claude?**
Yes. The body is model-agnostic. The brain (`SKILL.md`) can be used as a system prompt for any capable model, and there's an Ollama adapter for local models.

**Does it work without the brain?**
Yes. The brain is optional and can only make things stricter.

**Why no dependencies?**
Fewer things to audit, nothing to supply-chain-attack, and it runs anywhere Python 3.11 runs. That's also the Genesis Mind sovereign-architecture principle.

**Is it production-ready?**
It's v1.0, red-teamed and tested on Linux and Windows. Read [Limitations and Residual Risk](Limitations-and-Residual-Risk) and use it alongside OS sandboxing and least-privilege credentials, not instead of them.

## Errors

**`RuntimeError: Set GENESIS_SECURITY_KEY`**
`from_env()`, `checkpoint` and `verify-audit` need the key. Create one with `genesis-security keygen`. See [Installation](Installation#create-your-key).

**Every action is blocked and the log says `policy failed to load: deny-all`**
Your policy file is missing, unreadable, not valid TOML, or fails validation. Run `genesis-security policy check <file>`: it lists every problem. Fix them and restart. This is deliberate (v1.1): a broken policy never silently becomes "no restrictions".

**`PolicyError` when loading a policy that worked on v1.0**
v1.0 accepted partial policies and ignored unknown keys, which could silently disable protections (GS-AUD-03). Add the missing sections (`[egress]`, `[tools]`, `[secrets]`) or fix the reported keys. Start from `genesis-security policy`.

**`ValueError: hmac_key must be at least 16 bytes`**
Use `genesis-security keygen` (32 bytes) instead of a short password.

**`verify-audit` says `intact=False` right after I set things up**
You verified with a different key than the one that wrote the log (the chain is keyed). Use the same `GENESIS_SECURITY_KEY`. If you changed keys on purpose, start a new log file.

**`ValueError: 99 is not a valid Tier` / `'T1' is not a valid Tier`**
`origin_tier` must be a `Tier` or an int 0–3. Use `Tier.T1`, not the string `"T1"`.

**`PermissionError: [GenesisSecurity] HOLD …`**
A HOLD with no `owner_confirm` callback. Pass `owner_confirm=` to the gate, or handle the HOLD yourself with `pre_tool_call`.

**`UnicodeEncodeError` on Windows**
Fixed in the CLI (it forces UTF-8). In your own scripts, run with `set PYTHONIOENCODING=utf-8` or call `sys.stdout.reconfigure(encoding="utf-8")`.

**`tomllib` not found**
You're on Python < 3.11. Upgrade.

## Behaviour

**Every shell command asks me.**
By design: `shell_exec` is irreversible. Remove it from `[tools].irreversible` only if the command allowlist is very small and has no code-execution options.

**A URL I expected to work is held.**
Its host isn't in `[egress].allowlist` (exact match: `www.example.com` ≠ `example.com`), or the tool should be in `open_tools`. Malformed URLs (backslashes, spaces, `%` in the host) are always held.

**My agent got quarantined.**
It tripped injection rules `quarantine_after` times (it was probably reading attacker content and repeating it into tool calls). Review its recent audit entries, then release it with `gate.quarantined.discard(name)` and `gate.strikes.pop(name, None)`.

**Messages between my agents are refused as stale.**
Their clocks differ by more than `max_age_s`, or messages queue for longer than that. Sync clocks or raise `max_age_s`.

**A fact from the web was refused by `on_memory_write`.**
It contained a rule-like word (e.g. `never`, `always`, `ต้อง`). Intentional for T3. Rephrase it, or store it yourself as T1.

**The brain blocks everything.**
It's unreachable or erroring (fail closed). Look for `brain:error` in `layer_trace`. Check `ANTHROPIC_API_KEY`, or that Ollama is running.
