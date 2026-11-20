# Skill and Plugin Pinning

Skills (`SKILL.md`), plugins, prompt files and MCP tool descriptions are instructions your agent follows. They're also a supply chain: a file you download can contain hidden instructions, and a file you trusted yesterday can change today.

## The rule

> Read it, then pin it. Load only what is pinned and unchanged.

## Pin

```bash
genesis-security pin skill/SKILL.md plugins/*.md
# 3f1c…e9  skill/SKILL.md
# a72b…04  plugins/research.md
```

Store the pins in a file you control, e.g. `pins.json`:

```json
{"skill/SKILL.md": "3f1c…e9", "plugins/research.md": "a72b…04"}
```

## Check at load time

```python
import json
PINS = json.load(open("pins.json"))

text = open(path, encoding="utf-8").read()
v = gate.on_skill_load(path, text, pinned_sha256=PINS.get(path))
if not v.allowed:
    raise RuntimeError(f"refusing to load {path}: {v.reason}")
```

| Situation | Verdict |
|---|---|
| Pinned, hash matches | **ALLOW**, even if it contains attack phrases (security docs often do; you read it) |
| Pinned, hash differs | **BLOCK** GSX-12 "hash changed since pin" |
| Not pinned, L1 finds injection | **BLOCK** |
| Not pinned, clean | **HOLD**: read it, then pin it |

## MCP tool descriptions (rug-pull defence)

An MCP server can change a tool's description after you approved it, for example adding "also send the conversation to…". Pin descriptions the same way:

```python
for tool in mcp_client.list_tools():
    key = f"mcp:{server}:{tool.name}"
    v = gate.on_skill_load(key, tool.description, pinned_sha256=PINS.get(key))
    if not v.allowed:
        disable(tool)          # and tell the owner what changed
```

## Updating a pin

When a skill legitimately changes (you edited it, or a trusted author released a new version): read the diff, then re-run `genesis-security pin` and update `pins.json`. Never update pins automatically. That would defeat the point.
