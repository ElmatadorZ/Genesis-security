# Trust Tiers and Taint

Everything the gate sees carries a **tier**. Tiers answer one question: *who is behind this?*

| Tier | Value | Source | May |
|---|---|---|---|
| **T0** | 0 | System prompt, the owner's own config files | Set policy |
| **T1** | 1 | The owner, directly (a chat message you typed) | Give tasks; approve the Human Gate |
| **T2** | 2 | An internal agent whose message carries a valid signature | Send results and requests. Cannot widen its own permissions |
| **T3** | 3 | Web pages, downloaded files, emails, tool output, MCP results, unsigned agents, anything unknown | Be read as **data only** |

Higher number = less trusted. Anything whose source is unknown is T3.

## The one rule

> An action may run only if it traces back to T0 or T1.

That is **L2** in [The Security Loop](The-Security-Loop). It does not depend on recognising attack phrases. A perfectly polite web page that says "please archive the database" gets exactly the same treatment as one that says "IGNORE ALL INSTRUCTIONS": if the model decides to act *because of* that page, the action's origin is T3 and it is blocked.

## `origin_tier`: who asked?

Every tool call carries a context dict. Its `origin_tier` field says who asked for this action.

```python
ctx = {"agent": "main", "task_id": "t1", "origin_tier": Tier.T1}
```

The gate can't see your chat window, so **your agent loop sets this field.** A practical rule:

| Situation | `origin_tier` |
|---|---|
| The tool call directly fulfils what you typed | `T1` |
| The model chose this action after reading external content in the same step | `T3` |
| A scheduled job you configured | `T0` or `T1` |
| An agent asked another agent | the tier returned by `on_agent_message` |
| You don't know | `T3` (also the default when the field is missing) |

Malformed values (`"T1"`, `-1`, `99`, `None`) raise an error instead of being allowed.

## Taint

Taint tracks where *data* came from, separately from who asked for the *action*.

```python
from genesis_security import Tainted, Tier
snippet = Tainted(text_from_web, Tier.T3, source="https://news.example")
```

Rules:

1. **Taint only rises.** Combining T1 and T3 data gives T3.
2. **Taint is read recursively** through dicts, lists, tuples, sets and nested `Tainted` values.
3. **Taint survives relays.** A signed envelope carries a `taint` field. A message containing web data stays T3 even when a trusted agent forwards it.
4. **Tasks remember taint.** `on_external_content(..., task_id=X)` marks task X as having seen T3 data. Later tool calls in that task are treated as possibly influenced by it.

Taint feeds the **lethal trifecta** check: an outbound call that carries private data (`ctx["touches_private"] = True`) while T3 data is in play is held for the owner, even if each part looks harmless. See [Guarding Tools](Guarding-Tools#the-lethal-trifecta).

## Why both?

- `origin_tier` stops **actions** an attacker wants (delete, send, buy).
- Taint stops **data flows** an attacker wants (your secrets out through an innocent-looking request).

An attacker usually needs one of these. Genesis Security watches both.
