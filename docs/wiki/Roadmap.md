# Roadmap

Ideas for future versions, grouped by theme. Nothing here is promised on a date. Contributions are welcome: open an issue to discuss before large changes.

## Hardening

| Item | Closes |
|---|---|
| **Per-agent keys and key rotation.** Each agent signs with its own key, so a compromised agent can't sign as others | Shared-key limitation (GSX-07, GSX-11) |
| **Shared nonce store** (SQLite, stdlib). Replay protection survives restarts and spans processes | Per-process replay window |
| **Automatic checkpoint export** to phone, a second machine or git notes | Manual checkpoint step (GSX-13) |
| **MCP tool-description pinning helper** with a readable diff of what changed | GSX-04 |
| **Rate limits and spend budgets** per agent and task: tool calls, tokens, money | GSX-10 and runaway costs |
| **Unicode confusables folding** (TR39) in L1 | Homoglyph evasion of the scanner |

## Usability

| Item | |
|---|---|
| `async` versions of every hook | For asyncio agent loops |
| Policy hot-reload and `genesis-security policy check` | Lint a policy, warn about risky allowlists (`find`, `node`, …) |
| Ready-made `owner_confirm` adapters | Telegram, LINE, ntfy, desktop notifications, with timeouts |
| Audit viewer | A local HTML report of verdicts, strikes and quarantines over time |
| PyPI release | `pip install genesis-security` |

## Intelligence

| Item | |
|---|---|
| **Taint through model output** | Mark LLM answers derived from T3 input as T3 automatically |
| **Goal-drift detector** (GSX-09) | Compare each plan revision to the owner's original request |
| **Brain evaluation set** | Labelled events to measure how well a brain tightens without false positives |
| **Shared red-team corpus** (EN + TH) | Versioned attack phrasings contributed by users, run in CI |

## Done in 1.0.0

- L0–L5 gate with five hooks
- Signed agent envelopes with nonce, timestamp, recipient, scope, hop budget, taint
- HMAC-keyed audit chain with checkpoints, file locking and rotation
- Decoded-view secret detection (base64, hex, url-encoding, split arguments)
- Claude and Ollama brain adapters
- 45-case red-team suite in CI on Linux and Windows
