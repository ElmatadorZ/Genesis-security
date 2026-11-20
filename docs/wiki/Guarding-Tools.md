# Guarding Tools

## Two ways to gate a tool

**Decorator** (runs the tool when allowed, raises otherwise):

```python
@gate.guard("http_request")
def http_request(url: str, body: str = "") -> str: ...

http_request({"url": "https://api.anthropic.com/v1/messages", "body": "..."}, ctx)
```

The wrapped function takes `(args: dict, ctx: dict)`. `Tainted` values inside `args` are unwrapped before your function sees them. If the verdict carries `sanitized_args`, those are passed instead.

**Direct call** (just the verdict, you decide what to do):

```python
v = gate.pre_tool_call("http_request", args, ctx)
if v.allowed:
    ...
else:
    log.warning("%s %s %s", v.verdict, v.gsx, v.reason)
```

## The context dict

| Key | Required | Meaning |
|---|---|---|
| `origin_tier` | **yes** (missing = T3) | Who asked for this action. See [Trust Tiers and Taint](Trust-Tiers-and-Taint) |
| `agent` | recommended | Name of the acting agent. Used for strikes and quarantine |
| `task_id` | recommended | Links this call to external content seen in the same task |
| `touches_private` | optional | `True` if the call carries private data. Enables the trifecta check |
| anything else | optional | Small scalar values are copied into the audit log. Keys starting with `_` are not logged |

## What gets checked

### Origin (L2)

`origin_tier` T3 → **BLOCK**. This alone stops most indirect injection.

### Egress (L3)

A call is treated as **egress** if the tool is listed in `egress.tools`, or if **any URL appears anywhere in its arguments** (any depth, any tool name).

For every URL found:

- host in `egress.allowlist` → fine
- tool in `egress.open_tools` → fine (for read-only search tools)
- host not allowlisted → **HOLD**
- malformed host (backslash, whitespace, control characters, `%`) → **HOLD**

For egress tools, bare values like `evil.example/path` and `//evil.example` are also treated as URLs.

Hosts are compared exactly and in lowercase. `api.anthropic.com.evil.example`, `api.anthropic.com@evil.example` and Cyrillic look-alikes all fail.

### Secrets (L3)

For egress calls, the arguments are checked against `secrets.patterns` in several forms:

- the raw JSON of the arguments
- all string values joined together (catches a secret split across two arguments)
- url-decoded
- base64-decoded tokens (standard and url-safe)
- hex-decoded tokens

A match → **BLOCK**, severity **S1**. Secrets are redacted from `verdict.reason` and never written to the audit log.

### The lethal trifecta

Private data + untrusted content + a way out, in the same step. If the call is egress **and** `ctx["touches_private"]` is true **and** T3 data is in play (tainted arguments or a task that saw external content), the call is **HOLD**.

### Shell (L3)

For the tool named `shell_exec` (argument `cmd`):

1. Any of `; & | ` $ > <`, newline or carriage return → **BLOCK**
2. Command parsed with `shlex`. Unparseable → **BLOCK**
3. First word not in `shell.allowlist` → **BLOCK**
4. Any option in `shell.deny_args[command]` → **BLOCK**. Matches `-c`, `-cCODE`, `--upload-pack=x` and `--upload-pack x`
5. Otherwise → `shell_exec` is irreversible by default → **HOLD**, with the command shown to the owner

### Irreversible tools (L4)

Tools in `tools.irreversible` always **HOLD**, even when you asked for them yourself. Add anything that deletes, sends, pays, orders, publishes or changes permissions.

## Strikes and quarantine

A BLOCK caused by injection (GSX-01/02/03) gives the acting agent one strike. At `agents.quarantine_after` strikes (default 2), the agent is quarantined: every later tool call and message from it is blocked for the life of the gate.

```python
gate.quarantined        # {'scout'}
gate.strikes            # {'scout': 2}
gate.quarantined.discard("scout"); gate.strikes.pop("scout")   # release, after you've reviewed it
```

## Naming tools

The gate keys rules on tool *names*. Keep names stable and specific. If you rename `send_email` to `email_out`, update `egress.tools` and `tools.irreversible` too. A HOLD on an unexpected tool is usually the sign of a rename.
