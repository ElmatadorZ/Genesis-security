# ADR-0001: The runtime is the final authority; verdict transitions

- Decision: **Proposed**
- Implementation: **Records existing code** for points 1–3; the transition validator (point 4) is **Not approved**
- Date: 2026-11-25 · Revised 2026-11-25 after review (PR #1)

## Context

Agents act on model output, and models can be manipulated by content they read. A security layer that a model can argue with is just another agent we hope behaves. v1.0 already lets a brain only tighten verdicts, but the rule is implicit in code (an `order` dict in `gate._finish`) and the meaning of `ALLOW_SANITIZED` and `HOLD` in transitions is not written down.

## Decision

1. Only the runtime issues verdicts.
2. Advisors (a brain, an owner callback, a policy hook) **return proposals**; they never assign a verdict. The runtime validates each proposal against the transition matrix below and applies it or discards it.
3. Any advisor error, timeout, malformed reply or disallowed proposal is handled as stated in the matrix. It is never treated as ALLOW.
4. A single function `apply_transition(current, proposal, source) -> Verdict` implements the matrix. It is the only code path that changes a verdict after L5, and every applied or discarded proposal is recorded in the ledger.

### Verdict meaning

| Verdict | Meaning | Tool runs? |
|---|---|---|
| `ALLOW` | Every layer passed | Yes, with the original arguments |
| `ALLOW_SANITIZED` | Passed **only** with runtime-produced `sanitized_args` (or, for content, the wrapped form) | Yes, with `sanitized_args` only. Never with the original arguments |
| `HOLD` | A human decision is required | No, unless the owner approves (see below) |
| `BLOCK` | Refused | Never |

### Strictness order

`ALLOW` < `ALLOW_SANITIZED` < `HOLD` < `BLOCK`

### Transition matrix

Rows = verdict produced by L0–L5. Columns = proposal source. Cells = resulting verdict.

| From \ Proposal | Brain proposes `HOLD` | Brain proposes `BLOCK` | Brain proposes `ALLOW` / `ALLOW_SANITIZED` / anything else | Brain error / timeout / non-dict | Owner approves | Owner denies / errors / times out |
|---|---|---|---|---|---|---|
| `ALLOW` | `HOLD` | `BLOCK` | `ALLOW` (proposal discarded, logged) | `BLOCK` | n/a | n/a |
| `ALLOW_SANITIZED` | `HOLD` | `BLOCK` | `ALLOW_SANITIZED` (discarded) | `BLOCK` | n/a | n/a |
| `HOLD` | `HOLD` | `BLOCK` | `HOLD` (discarded) | `BLOCK` | `ALLOW`* | `BLOCK` |
| `BLOCK` | `BLOCK` | `BLOCK` | `BLOCK` (discarded) | `BLOCK` | **not offered** | `BLOCK` |

\* **Owner approval is the only loosening transition in the system**, and only `HOLD → ALLOW`. It runs **after** the brain, so a brain-proposed `BLOCK` can never be turned into `ALLOW` by an owner callback. The approval is recorded with the approver identity (Phase 3: authenticated operator). If the HOLD carried `sanitized_args`, approval yields `ALLOW_SANITIZED` with those arguments, never the originals.

Invariants (tested as properties):

- I1. No transition moves from `BLOCK` to anything else.
- I2. No advisor other than an owner approval moves a verdict to a less strict one.
- I3. Owner approval applies only to `HOLD`.
- I4. `ALLOW_SANITIZED` never executes with unsanitized arguments.

## Consequences

- Security does not depend on model cooperation (principle P1).
- A malfunctioning brain reduces availability (more BLOCKs), never safety.
- A brain cannot rescue a false positive; owners resolve those through the Human Gate or policy.
- v1.0 already matches rows 1–4 for the brain; the validator (point 4) and property tests I1–I4 are Phase 1 work.
