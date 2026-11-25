# ADR-0001: The runtime is the final authority; models may only tighten

- Status: **Accepted** (records the v1.0 design)
- Date: 2026-11-25

## Context

Agents act on model output. Models can be manipulated by content they read. A security layer that a model can argue with is another agent we hope behaves.

## Decision

1. Only the runtime issues verdicts (`ALLOW`, `ALLOW_SANITIZED`, `HOLD`, `BLOCK`).
2. A brain (any model or rule engine) may move a verdict toward `BLOCK`; any attempt to move it toward `ALLOW` is ignored.
3. Any brain error, timeout or malformed reply results in `BLOCK`.
4. Nothing reachable from model output or content can change tiers, scopes, policy or keys.

## Consequences

- Security does not depend on model cooperation (principle P1).
- A malfunctioning brain degrades availability (more BLOCKs), never safety.
- Semantic detection is limited to tightening; a brain cannot rescue a false positive. Owners resolve those through the Human Gate or policy.
