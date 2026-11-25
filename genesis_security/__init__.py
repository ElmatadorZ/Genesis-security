# Copyright 2026 Bunyawat Dechanon (ElmatadorZ)
# SPDX-License-Identifier: Apache-2.0
"""Genesis Security — defensive runtime for AI agents and multi-agent systems.

Brain = skill/SKILL.md (Claude). Body = this package. Never merged.
"""
from .audit import AuditTrail, verify_chain
from .gate import GenesisSecurityGate
from .policy import Policy, PolicyError
from .scanner import scan_injection
from .tiers import Tainted, Tier, Verdict

__version__ = "1.1.0.dev0"
__all__ = ["AuditTrail", "GenesisSecurityGate", "Policy", "PolicyError", "Tainted", "Tier", "Verdict",
           "scan_injection", "verify_chain", "__version__"]
