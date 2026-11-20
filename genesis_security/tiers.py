# Copyright 2026 Bunyawat Dechanon (ElmatadorZ)
# SPDX-License-Identifier: Apache-2.0
"""L0 primitives: trust tiers, tainted values, verdicts."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional


class Tier(IntEnum):
    """Trust tiers. Higher number = less trusted."""
    T0 = 0  # system / owner config
    T1 = 1  # owner direct message
    T2 = 2  # verified internal agent
    T3 = 3  # external: web, files, tool output, unverified agents


@dataclass
class Tainted:
    """A value that remembers its worst-trust origin. Taint only goes up."""
    value: Any
    tier: Tier
    source: str = "unknown"

    def merge(self, other: "Tainted") -> Tier:
        return Tier(max(self.tier, other.tier))


VERDICTS = ("ALLOW", "ALLOW_SANITIZED", "HOLD", "BLOCK")


@dataclass
class Verdict:
    verdict: str
    gsx: list[str] = field(default_factory=list)
    severity: str = "S4"
    reason: str = ""
    sanitized_args: Optional[dict] = None
    requires_owner: bool = False
    layer_trace: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.verdict not in VERDICTS:
            raise ValueError(f"unknown verdict {self.verdict!r}")

    @property
    def allowed(self) -> bool:
        return self.verdict in ("ALLOW", "ALLOW_SANITIZED")
