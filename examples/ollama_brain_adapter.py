# Copyright 2026 Bunyawat Dechanon (ElmatadorZ)
# SPDX-License-Identifier: Apache-2.0
"""Brain adapter for a local model via Ollama (no cloud, stdlib only).

    from examples.ollama_brain_adapter import make_ollama_brain
    gate = GenesisSecurityGate.from_env(brain=make_ollama_brain("llama3.1"))

Like every brain, it can only tighten verdicts; errors and malformed replies fail closed.
Local models are weaker judges than Claude — treat this as an extra tripwire, not the wall.
"""
from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path

SKILL = (Path(__file__).resolve().parent.parent / "skill" / "SKILL.md").read_text(encoding="utf-8")


def make_ollama_brain(model: str | None = None, host: str | None = None,
                      events: tuple[str, ...] = ("tool_call", "memory_write"), timeout: float = 30.0):
    model = model or os.environ.get("GENESIS_BRAIN_MODEL", "llama3.1")
    host = host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")

    def brain(event: dict) -> dict | None:
        if event["event"] not in events:
            return None
        payload = {
            "model": model, "stream": False, "format": "json",
            "messages": [
                {"role": "system", "content": SKILL},
                {"role": "user", "content": "Review this gate event. Reply JSON only: "
                 "{\"verdict\": \"ALLOW|HOLD|BLOCK\", \"gsx\": [], \"reason\": \"one line\"}\n\n"
                 + json.dumps(event, ensure_ascii=False, default=str)},
            ],
        }
        req = urllib.request.Request(f"{host}/api/chat", data=json.dumps(payload).encode(),
                                     headers={"content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(json.loads(r.read())["message"]["content"])

    return brain
