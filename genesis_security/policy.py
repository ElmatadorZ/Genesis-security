# Copyright 2026 Bunyawat Dechanon (ElmatadorZ)
# SPDX-License-Identifier: Apache-2.0
"""Policy: what is allowed, loaded from TOML (stdlib tomllib)."""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path


@dataclass
class Policy:
    egress_allowlist: set[str] = field(default_factory=set)
    egress_tools: set[str] = field(default_factory=set)
    open_tools: set[str] = field(default_factory=set)
    irreversible_tools: set[str] = field(default_factory=set)
    shell_allowlist: set[str] = field(default_factory=set)
    shell_deny_args: dict[str, list[str]] = field(default_factory=dict)
    hop_budget: int = 5
    quarantine_after: int = 2
    max_age_s: float = 300.0
    secret_patterns: list[re.Pattern] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "Policy":
        eg, sh, ag = d.get("egress", {}), d.get("shell", {}), d.get("agents", {})
        return cls(
            egress_allowlist={h.lower() for h in eg.get("allowlist", [])},
            egress_tools=set(eg.get("tools", [])),
            open_tools=set(eg.get("open_tools", [])),
            irreversible_tools=set(d.get("tools", {}).get("irreversible", [])),
            shell_allowlist=set(sh.get("allowlist", [])),
            shell_deny_args={k: list(v) for k, v in sh.get("deny_args", {}).items()},
            hop_budget=int(ag.get("hop_budget", 5)),
            quarantine_after=int(ag.get("quarantine_after", 2)),
            max_age_s=float(ag.get("max_age_s", 300)),
            secret_patterns=[re.compile(p) for p in d.get("secrets", {}).get("patterns", [])],
        )

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Policy":
        """Load a policy file. With no path, load the packaged default_policy.toml."""
        if path is None:
            text = resources.files("genesis_security").joinpath("default_policy.toml").read_text("utf-8")
        else:
            text = Path(path).read_text("utf-8")
        return cls.from_dict(tomllib.loads(text))

    @classmethod
    def default(cls) -> "Policy":
        return cls.load()
