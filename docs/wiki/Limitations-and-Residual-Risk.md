# Limitations and Residual Risk

Read this before you rely on Genesis Security. Security tools that oversell themselves are dangerous.

## What it doesn't do

| Limitation | Why | What to do |
|---|---|---|
| **L1 misses rephrased injections** (homoglyphs, spacing, synonyms, encoded instructions, rephrased Thai) | Regex can't enumerate language | Rely on L2/L3. The red team shows they block the resulting actions. Add a brain for semantic review |
| **It only protects tools routed through it** | A tool the model can reach directly bypasses everything | Wrap every tool; audit your tool registry |
| **`origin_tier` is set by your code** | The library can't see who typed what | Set it at one dispatch point; default to T3 when unsure |
| **Custom encodings to allowlisted hosts get through** (rot13, gzip, XOR…) | Encodings are unbounded | Keep `egress.allowlist` short; only hosts you fully trust |
| **One HMAC key proves "holder of the key", not "agent X"** | Shared-key design | Separate keys (gates) per trust zone; per-agent keys are on the roadmap |
| **Replay protection is per process** | In-memory nonce cache | `max_age_s` bounds the window; shared store on the roadmap |
| **Goal drift (GSX-09) isn't enforced by the body** | Needs judgement, not patterns | Use the brain; goal-drift detector on the roadmap |
| **It's not a sandbox** | It decides; the OS enforces | Run agents with least-privilege credentials, containers or VMs, and network egress rules |
| **Model-only jailbreaks** (no tool involved) | Nothing to gate | The brain (`SKILL.md`) helps; the body can't |

## Accepted residual risks from the red team

| Case | What gets through | Why accepted |
|---|---|---|
| A1–A4, A6 (scan) | L1 doesn't recognise those phrasings | The L2 case for each one passes: the action is blocked |
| R6 | A rot13-encoded secret sent to an **allowlisted** host | Unbounded encodings; R7 confirms the same attack to an unlisted host is held |

## Assumptions

- The attacker does **not** have `GENESIS_SECURITY_KEY`, write access to your policy or pins, or control of the host.
- Your checkpoint is stored where agents can't write.
- `owner_confirm` really reaches you, and you read what you approve.

If any of these is false, the guarantees on the other pages don't hold.

## False positives you may see

- **HOLD on every shell command.** By design: `shell_exec` is irreversible. Narrow auto-approvals in `owner_confirm` if you must.
- **HOLD on a URL you expected to work.** The host isn't in `egress.allowlist`, or the tool should be in `open_tools`.
- **T3 facts refused in memory.** The rule detector is broad on purpose for T3 (e.g. any `ต้อง` / `never`). Rephrase, or have the owner store it as T1.
- **Unexpected BLOCK from a brain.** The brain was down (fail closed) or genuinely objected. Check `layer_trace` for `brain:error`.
