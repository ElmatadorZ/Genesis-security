# Recipes

Ready-to-adapt setups. Each one is a policy snippet plus the wiring that matters.

---

## Coding agent (shell, git, files)

```toml
[shell]
allowlist = ["ls", "cat", "grep", "python", "pytest", "git", "rg"]
[shell.deny_args]
python = ["-c"]
git    = ["-c", "--config", "--upload-pack", "--receive-pack", "--exec", "--config-env"]
grep   = ["--pre"]
[tools]
irreversible = ["shell_exec", "delete_file", "git_push"]
[egress]
allowlist = ["api.anthropic.com", "pypi.org", "files.pythonhosted.org", "github.com"]
```

- Every shell command is shown to you before it runs (`shell_exec` is irreversible).
- Chains (`;`, `&&`, `|`), `$()` and backticks are refused outright.
- Treat README files, issues and code comments in repositories you didn't write as **external content**. They're a common place to hide instructions.

---

## Research / browsing agent

```toml
[egress]
allowlist  = ["api.anthropic.com"]
open_tools = ["web_search", "fetch_page"]      # may reach any host
tools      = ["http_request", "send_email"]
```

```python
html = fetch_page({"url": url}, me)
page, _ = gate.on_external_content(url, html, task_id=task)
```

- The agent can read anything, but pages can't make it act: anything it decides because of a page is `origin_tier=T3`.
- Secrets are still checked on `open_tools` calls, so a search query can't carry your key out.
- Mark calls that include your private notes with `touches_private=True` so the trifecta check applies.

---

## Trading bot (MT5, exchanges)

```toml
[tools]
irreversible = ["place_order", "modify_order", "close_position", "transfer_funds", "withdraw"]
[egress]
allowlist = ["api.anthropic.com", "localhost"]
[agents]
hop_budget = 3
max_age_s = 30            # signals go stale fast
```

```python
# risk agent → executor
env = gate.make_envelope("risk", "executor", task, signal, ["read:market", "trade:paper"])
tier, v = gate.on_agent_message(env, signal, granted_scope={"read:market", "trade:paper"},
                                recipient="executor")
```

- News and social content can inform analysis, but can't place orders: `origin_tier=T3`.
- Separate scopes for `trade:paper` and `trade:live`. Only you add `trade:live` to `granted_scope`.
- Add a rule brain for hard limits (max position size, trading hours, daily loss). See [Brain Adapters](Brain-Adapters#rule-brains).
- Every order needs your confirmation unless you deliberately auto-approve a narrow case (e.g. paper trading only) in `owner_confirm`.

---

## Email / customer-support agent

```toml
[tools]
irreversible = ["send_email", "send_message", "forward_email", "delete_email", "refund"]
[secrets]
patterns = ['sk-[A-Za-z0-9_-]{16,}', '(?i)(api[_-]?key|secret|token|password)\s*[=:]\s*\S{6,}',
            'ORD-[0-9]{8}-[A-Z]{4}']           # add your own internal identifiers
```

- Every incoming email goes through `on_external_content`. Phishing emails are the classic indirect injection.
- Replies and forwards wait for you. The preview in the HOLD reason shows recipient and subject.
- Add your own internal secret formats to `[secrets]`.

---

## Multi-agent council (Genesis Mind, SkynetClaw)

```
Scout/Reader (reads T3)  ──signed, taint=T3──▶  Analyst  ──signed──▶  Executor (tools)
                                                   ▲
                               Sentinel (answers only to T0/T1, runs verify-audit)
```

- Scouts never hold egress or memory-write tools.
- Messages carrying web-derived content are sent with `taint=Tier.T3`. The executor treats actions based on them as T3.
- Readers and executors use **different keys** (separate gates) so a compromised reader can't sign as the analyst.
- `hop_budget` stops delegation loops. Quarantine removes an agent that keeps tripping injection rules.

---

## Personal knowledge base / long-term memory

```python
v = gate.on_memory_write("/kb/notes.md", text, src_tier=Tier.T3 if from_web else Tier.T1)
```

- Web clippings become `[fact][source:T3]` lines. Rule-like text from the web is refused.
- Your own notes (T1) are stored as written.

---

## Local / offline agents (Ollama)

```python
from examples.ollama_brain_adapter import make_ollama_brain
gate = GenesisSecurityGate.from_env(brain=make_ollama_brain("llama3.1"))
```

Same enforcement, no cloud calls. Keep `egress.allowlist` to `["localhost"]` if nothing should leave the machine.

---

## CI: stop injected text before it reaches a model

```yaml
- name: Scan prompts and knowledge base
  run: genesis-security scan prompts/*.md kb/**/*.md
```

Exit code 2 (injected) fails the build. Exit code 1 (suspicious) can be allowed with `|| [ $? -eq 1 ]` if you prefer.
