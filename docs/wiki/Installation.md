# Installation

## Requirements

- Python **3.11 or newer** (uses `tomllib` from the standard library)
- No third-party packages, by design

## Install

From GitHub:

```bash
pip install git+https://github.com/ElmatadorZ/Genesis-security.git
```

From a clone (recommended if you want the examples and the brain skill file):

```bash
git clone https://github.com/ElmatadorZ/Genesis-security.git
cd Genesis-security
pip install .            # or: pip install -e .   for development
```

Check it:

```bash
genesis-security --version
genesis-security demo
genesis-security redteam      # exit code 0 = no security failures
```

If `genesis-security` is not on your PATH, use `python -m genesis_security …` instead.

## Create your key

The gate signs agent messages and the audit log with one secret. Generate it once and keep it out of your repository.

**Linux / macOS**

```bash
export GENESIS_SECURITY_KEY=$(genesis-security keygen)
```

**Windows PowerShell**

```powershell
$env:GENESIS_SECURITY_KEY = genesis-security keygen
# persist for your user:
[Environment]::SetEnvironmentVariable("GENESIS_SECURITY_KEY", $env:GENESIS_SECURITY_KEY, "User")
```

Store it like any other credential (password manager, OS keychain, `.env` file that is git-ignored). Anyone with this key can sign agent messages and rewrite the audit chain.

## Optional environment variables

| Variable | Purpose |
|---|---|
| `GENESIS_SECURITY_KEY` | **Required** by `GenesisSecurityGate.from_env()` and `verify-audit` / `checkpoint` |
| `GENESIS_SECURITY_POLICY` | Path to your policy TOML (see [Policy Reference](Policy-Reference)) |
| `GENESIS_SECURITY_AUDIT` | Path to the audit log, e.g. `logs/audit.jsonl` |
| `ANTHROPIC_API_KEY` | Only for the Claude brain adapter |
| `GENESIS_BRAIN_MODEL` | Model name for a brain adapter |
| `OLLAMA_HOST` | Ollama URL for the local brain adapter (default `http://localhost:11434`) |

## Install the brain (Claude Skill)

The file `skill/SKILL.md` is a Claude Skill. Add it to Claude as a skill (or use it as a system prompt for another model) so the agent itself reasons with the same rules the body enforces. The brain adapters in `examples/` load it automatically.

Next: [Quickstart](Quickstart)
