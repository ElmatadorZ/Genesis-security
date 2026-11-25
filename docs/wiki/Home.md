# Genesis Security Wiki

**A defensive runtime for AI agents and multi-agent systems.**

> External content is data, never a command.
> Claude Skill = brain, Python = body, never merged.

Genesis Security sits between an AI agent and its tools. Every action the agent takes must trace back to its owner. Instructions hidden in web pages, files, emails, tool output or other agents' messages are treated as data, so they cannot trigger actions on their own.

## Start here

| If you want to… | Read |
|---|---|
| Install it and see it work in five minutes | [Installation](Installation) → [Quickstart](Quickstart) |
| Understand the model | [Trust Tiers and Taint](Trust-Tiers-and-Taint) → [The Security Loop](The-Security-Loop) → [Verdicts and the Human Gate](Verdicts-and-the-Human-Gate) |
| Protect an existing agent | [Integration Guide](Integration-Guide) → [Guarding Tools](Guarding-Tools) |
| Copy a setup for your kind of agent | [Recipes](Recipes) |
| Look up a function, setting or command | [API Reference](API-Reference) · [Policy Reference](Policy-Reference) · [CLI Reference](CLI-Reference) |
| Know what it does **not** protect against | [Limitations and Residual Risk](Limitations-and-Residual-Risk) |
| Build on it | [Extending](Extending) · [Roadmap](Roadmap) · [Contributing](Contributing) |
| อ่านภาษาไทย | [ภาษาไทย](ภาษาไทย) |

## At a glance

| | |
|---|---|
| **Language** | Python 3.11+ |
| **Dependencies** | none (stdlib only) |
| **Platforms** | Linux, macOS, Windows |
| **Hooks** | external content · tool calls · agent messages · memory writes · skill loads |
| **Threat classes** | 13 ([GSX-01 … GSX-13](Threat-Model)) |
| **Red team** | 49 cases ship with the package, 0 failures, run in CI |
| **License** | Apache 2.0 |

## The two layers

| Layer | Lives in | Role |
|---|---|---|
| **Brain** | [`skill/SKILL.md`](https://github.com/ElmatadorZ/Genesis-security/blob/main/skill/SKILL.md) | A Cognitive OS that tells Claude (or another LLM) how to classify trust, spot injection, reason about intent, and refuse. |
| **Body** | [`genesis_security/`](https://github.com/ElmatadorZ/Genesis-security/tree/main/genesis_security) | Python that **enforces** verdicts: trust tiers, tool gating, signed agent messages, memory guards, a tamper-evident audit log. Fail-closed. |

The body works without the brain. The brain makes the body stricter. It can never make it more permissive. See [Brain Adapters](Brain-Adapters).

## Origin

Genesis Security is part of the **Genesis Mind** ecosystem by Bunyawat Dechanon (ElmatadorZ). It was designed by mapping the attack surfaces of Genesis Mind and the SkynetClaw agent (Volition, Agent Council, Shadow Gate, Echo Memory, Affective Genome, AuditTrail and the tool layer) and building a defence for each. See [Threat Model](Threat-Model).
