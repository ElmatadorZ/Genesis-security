# Production roadmap

| | |
|---|---|
| Date | 2026-11-25 |
| Approved by | Owner (Governance D5 updated, R1–R4) |
| Goal | Production-grade runtime that is **easy for non-specialists**, **good for developers**, and **trustworthy for organizations** |

## Three audiences, one security core

| Audience | What they need | What we build |
|---|---|---|
| **Everyday users** (run an agent someone else built, or a Claude Skill) | Safe by default; no policy expertise | `genesis-security init` wizard (asks a few questions, writes policy + key), `doctor` (explains misconfiguration in plain language, TH/EN), phone approvals (Telegram / LINE / ntfy), readable HOLD messages |
| **Developers** | Stable API; integrate in ~10 minutes | Provenance-aware SDK (no hand-set `origin_tier`), adapters for Claude / OpenAI / Gemini / Ollama / MCP, `policy check` for CI, pytest-free test helpers, typed public API |
| **Organizations** | Proven, auditable, supportable | All High findings closed, default-deny, persistent state, per-agent keys, signed releases + SBOM, PyPI, external review (G9) |

Limits, stated up front: people who don't write agents benefit through the Claude Skill or through agents that ship with Genesis Security (e.g. SkynetClaw). "Independently reviewed" requires G9; until then every release says "not independently reviewed".

## Releases (gated, not dated)

| Release | Contents | Closes | Gate to ship | Size (solo) |
|---|---|---|---|---|
| **v1.1** — non-breaking hardening | Policy schema validation + deny-all on load failure (P1-03); `NOT SECURE ENFORCEMENT` warnings for undeclared tools (compat); shadow mode (P1-13); `init` + `doctor`; migration guide (P1-14) | GS-AUD-03 | Red team 0 failures; new regression tests shown failing on v1.0.0; CI Linux + Windows | 1–2 weeks |
| **v2.0-alpha** | Default-deny + capability registry (P1-01/02), canonicalization (P1-16), verdict transition validator (P1-15), SQLite state (P1-05), ledger failure contract (P1-08), concurrency on 3.13t (P1-09), recipient allowlists (P1-10), conformance suite (P1-11) | 01, 02, 05, 10*, 11, 12, 14 | G1, G2 (High), G3, G6 | 4–6 weeks |
| **v2.0-beta** | Per-agent keys via HKDF + key format (P1-06/07), provenance chain (P1-17), policy authentication + atomic reload (P1-04), adapters (P2-04), MCP gateway (P2-03), SkynetClaw reference (P2-05), phone approvals | 04, 06, 07, 09 | G4, G5, G7, G8 | 4–6 weeks |
| **v2.0 GA** | API freeze (P2-02), actions pinned by SHA + SBOM + signed tag (P4-04/05), fuzzing (P4-02), advisory process (P4-06), PyPI | 08, 13 | G1–G10 (G9 or an explicit "not independently reviewed") | depends on reviewer |

\* GS-AUD-10 (self-review) closes only with G9.

## How every change is made

1. One PR per backlog item, linked to its issue.
2. The PR's first commit adds tests that **fail on `main`** (the CI run is linked in the PR).
3. The fix makes them pass; red team stays at 0 failures; CI passes on Linux and Windows.
4. Behaviour changes toward stricter are announced under *Security — behaviour change* in the changelog (R4).
5. Docs and wiki updated in the same PR.
