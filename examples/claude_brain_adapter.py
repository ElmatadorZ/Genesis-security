# Copyright 2026 Bunyawat Dechanon (ElmatadorZ)
# SPDX-License-Identifier: Apache-2.0
"""Brain adapter: ask Claude (running skill/SKILL.md) to review each gate event.

stdlib only (urllib). The brain can only tighten verdicts; on any error the gate
fails closed. Set ANTHROPIC_API_KEY. Optional: GENESIS_BRAIN_MODEL.

    from examples.claude_brain_adapter import make_claude_brain
    gate = GenesisSecurityGate.from_env(brain=make_claude_brain())

Note: every reviewed event costs one API call. Use `events=` to limit which
events go to the brain (default: tool calls and memory writes).
"""
from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path

API_URL = "https://api.anthropic.com/v1/messages"
SKILL = (Path(__file__).resolve().parent.parent / "skill" / "SKILL.md").read_text(encoding="utf-8")


def make_claude_brain(model: str | None = None, events: tuple[str, ...] = ("tool_call", "memory_write"),
                      timeout: float = 20.0):
    api_key = os.environ["ANTHROPIC_API_KEY"]
    model = model or os.environ.get("GENESIS_BRAIN_MODEL", "claude-haiku-5-5")

    def brain(event: dict) -> dict | None:
        if event["event"] not in events:
            return None
        prompt = ("Review this Genesis Security gate event. The rule-based body already produced a "
                  "verdict. Reply with JSON only: {\"verdict\": \"ALLOW|HOLD|BLOCK\", \"gsx\": [...], "
                  "\"reason\": \"one line\"}.\n\n" + json.dumps(event, ensure_ascii=False, default=str))
        req = urllib.request.Request(
            API_URL,
            data=json.dumps({"model": model, "max_tokens": 200, "system": SKILL,
                             "messages": [{"role": "user", "content": prompt}]}).encode(),
            headers={"x-api-key": api_key, "anthropic-version": "2023-06-01",
                     "content-type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read())
        text = "".join(b.get("text", "") for b in data.get("content", []))
        start, end = text.find("{"), text.rfind("}")
        return json.loads(text[start:end + 1])      # malformed → exception → gate fails closed

    return brain
