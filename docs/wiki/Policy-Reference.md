# Policy Reference

The policy is a TOML file. Start from the default:

```bash
genesis-security policy > my_policy.toml
```

Load it with `Policy.load("my_policy.toml")` or `GENESIS_SECURITY_POLICY=my_policy.toml`, and validate it first:

```bash
genesis-security policy check my_policy.toml
```

**Validation is strict (since v1.1).** `[egress]`, `[tools]` and `[secrets]` are required; `[shell]` and `[agents]` are optional and use the defaults below. Unknown sections or keys, wrong types, invalid regexes, empty `secrets.patterns` and wildcard hosts are errors, and every problem is listed at once (with "did you mean…?" hints for typos).

**A policy that fails to load puts the gate in deny-all.** Every tool call, agent message, memory write and skill load is blocked, `gate.status()["policy_ok"]` is `False`, one `policy_load_failed` audit event is written and an error is logged. The gate never falls back to the packaged default to authorize anything.

## `[egress]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `allowlist` | list of hosts | `["api.anthropic.com", "localhost"]` | Hosts any tool may reach without asking. Exact, lowercase match. No wildcards |
| `tools` | list of tool names | `http_request, send_email, send_message, git_push, webhook` | Tools that move data out even without a URL in their arguments. Secret checks always apply; bare `host/path` values are treated as URLs |
| `open_tools` | list of tool names | `[]` | Tools allowed to reach **any** host (e.g. read-only search). Secret and trifecta checks still apply |

## `[tools]`

| Key | Default | Meaning |
|---|---|---|
| `irreversible` | `delete_file, send_email, send_message, transfer_funds, git_push, place_order, change_permissions, shell_exec` | Always HOLD for the owner, even when the owner asked |

## `[shell]`

Applies to the tool named `shell_exec` with argument `cmd`.

| Key | Default | Meaning |
|---|---|---|
| `allowlist` | `ls, cat, grep, python, pytest, git` | Allowed first words |
| `[shell.deny_args]` | `python = ["-c"]`, `git = ["-c", "--config", "--upload-pack", "--receive-pack", "--exec", "--config-env"]`, `grep = ["--pre"]` | Options that turn an allowed command into arbitrary code execution |

Always refused, regardless of policy: `; & | ` $ > <`, newline, carriage return, unparseable quoting.

When adding commands, think about their code-execution options: `find -exec`, `tar --to-command`, `awk 'system()'`, `node -e`, `ruby -e`, `perl -e`, `npm run`, `make`. If you can't list them, don't allowlist the command. Make it a dedicated tool with fixed arguments instead.

## `[agents]`

| Key | Default | Meaning |
|---|---|---|
| `hop_budget` | `5` | Messages with `hop` ≥ this are dropped |
| `quarantine_after` | `2` | Injection strikes before an agent is quarantined |
| `max_age_s` | `300` | Signed messages older (or newer) than this are refused; also bounds the replay window after a restart |

## `[secrets]`

| Key | Meaning |
|---|---|
| `patterns` | Python regexes. Matched against the raw arguments, all string values joined, and url-, base64- and hex-decoded views. Used for egress blocking, memory blocking and redaction in logs and HOLD previews |

Defaults:

```toml
patterns = [
  'sk-[A-Za-z0-9_-]{16,}',
  '(?i)(api[_-]?key|secret|token|password)\s*[=:]\s*\S{6,}',
  '-----BEGIN [A-Z ]*PRIVATE KEY-----',
  'GENESIS_TEST_KEY=\S+',
]
```

Add the formats of your own credentials: exchange API keys, MT5 passwords, bot tokens, internal IDs. Test a pattern with:

```python
import re; re.compile(r'your-pattern').search("sample")
```

## A tight production example

```toml
[egress]
allowlist = ["api.anthropic.com"]
tools = ["http_request", "send_email", "send_message", "git_push", "webhook", "post_tweet"]
open_tools = ["web_search"]

[tools]
irreversible = ["delete_file", "send_email", "send_message", "git_push", "post_tweet",
                "place_order", "close_position", "transfer_funds", "shell_exec", "change_permissions"]

[shell]
allowlist = ["ls", "cat", "rg", "pytest"]

[agents]
hop_budget = 3
quarantine_after = 1
max_age_s = 60

[secrets]
patterns = ['sk-[A-Za-z0-9_-]{16,}', '(?i)(api[_-]?key|secret|token|password)\s*[=:]\s*\S{6,}',
            '-----BEGIN [A-Z ]*PRIVATE KEY-----', '[0-9]{8,10}:[A-Za-z0-9_-]{35}']   # last: Telegram bot token
```
