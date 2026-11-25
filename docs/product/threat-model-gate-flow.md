# Threat model — Gate + Flow mode (ADR-0009)

| | |
|---|---|
| Date | 2026-11-25 |
| Applies to | Enforcement mode 02 · Gate + Flow |
| Extends | [Product spec §2a](product-spec-v1.md#2a-threat-model-who-is-trusted-who-is-the-attacker) |

## Asset

Data of declared private classes (`private:*`), and the owner's control over who receives it.

## Attacker goals

1. Get private data to a principal not among its readers.
2. Get the runtime to lower flow state without the owner.
3. Make egress look like it goes to an allowed sink when it does not.

## Attacks and responses

| # | Attack | Response in Gate + Flow | Residual |
|---|---|---|---|
| F1 | Model re-encodes a secret (rot13, base64, XOR, unicode tricks, paraphrase) and sends it to an allowlisted host | Destination checked against flow-state readers; content not relevant (ADR-0009 §5) | None inside the boundary |
| F2 | Send to an allowed domain on an endpoint that forwards to third parties | Readers are sinks with exact endpoint + principal + `onward_sharing` (§3) | Mis-declared sink policy |
| F3 | Start a new turn, task or session to "forget" what was read | Runtime-generated session/task IDs with parent references; clean task needs single-use owner approval and does not change the parent; data entering a new session carries its origin state (ADR-0009 §10) | — |
| F4 | Launder through another agent (A reads, sends to B, B exfiltrates) | Runtime records A's state and builds/signs the envelope; B's runtime raises B to A's **store-recorded** state; envelopes can only raise (ADR-0009 §2) | In-process deployments: compromised agent code can reach the runtime's key and store (out-of-process runtime required for this guarantee) |
| F4b | Agent lies about its own flow state (`classes = {}`) | Agents do not author or sign flow state in mode 02; missing/mismatched store evidence → owner-only, T3 | Same in-process caveat |
| F4c | Race: egress authorized before a concurrent private read is recorded | Pre-raise before read, release after commit; egress decision under the same write lock (ADR-0009 §4) | — |
| F4d | Redirect, DNS rebinding, proxy, encoded path, recipient switched in body/header | Sink resolution: gateway performs egress, redirects off, single DNS resolution, proxies ignored, channel-verified principal, recipient fields checked (ADR-0009 §5) | `onward_sharing` honoured only to its declared basis |
| F4e | Confuse confidentiality and integrity (trusted secret vs untrusted public text) | Two axes: confidentiality joins (union/intersection), integrity meets (least trusted) (ADR-0009 §1) | — |
| F5 | Unsigned message or unverifiable provenance | Treated as `private:unclassified` (owner-only) | — |
| F6 | Mix classes to find a permissive reader | Intersection of readers (§4) | — |
| F7 | Ask the model to declassify, or replay an old approval | Only owner declassifies; approvals are single-use tokens bound to session, class, scope, nonce and expiry (ADR-0009 §8) | Owner approving a manipulated request (human factor) |
| F7b | Envelope from a different policy version or unknown class | Unknown class → owner-only; unknown reader dropped; newer schema → BLOCK; other deployment → owner-only, T3 (ADR-0009 §10) | — |
| F8 | Tool that reads private data but has no `produces` declaration | Defaults to `private:unclassified` (owner-only), not public | Utility loss until declared |
| F9 | Egress outside the gateway (direct socket, subprocess, other process) | Out of guarantee; start-up check in-process, OS egress rules required, `doctor` reports (§8) | **Real residual** — deployment responsibility |
| F10 | Leak by choosing *which* allowed action to take (control-flow leakage) | Not prevented by Flow | Addressed only by Plan-Constrained Execution (mode 03) |
| F11 | Covert/timing channels inside an allowed sink | Not prevented | Out of scope |
| F12 | Corrupt or delete flow state | State store errors → BLOCK; tampering detectable via ledger (ADR-0006, -0007) | Host compromise (out of scope) |

## Trust assumptions

- Policy (`data_classes`, `sinks`, `produces`) is correct and integrity-protected (ADR-0004).
- All network and messaging egress of the agent passes through the Execution Gateway.
- The owner reads declassification prompts before approving.
