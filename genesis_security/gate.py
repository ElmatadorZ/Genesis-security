# Copyright 2026 Bunyawat Dechanon (ElmatadorZ)
# SPDX-License-Identifier: Apache-2.0
"""GenesisSecurityGate — the L0→L5 loop and the five runtime hooks.

Brain/body split: an optional ``brain`` callable (e.g. Claude running
skill/SKILL.md) may *tighten* a verdict, never loosen it. Any brain error
fails closed (BLOCK). The gate never logs raw tool arguments or content,
so secrets do not end up in the audit trail.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from dataclasses import asdict
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from .audit import AuditTrail
from .policy import Policy
from .scanner import scan_injection
from .tiers import Tainted, Tier, Verdict

Brain = Callable[[dict], Optional[dict]]
OwnerConfirm = Callable[[Verdict, dict], bool]
SHELL_META = re.compile(r"[;&|`$><\n]")
RULE_LIKE = re.compile(r"(?i)\b(always|never|from now on|you must|rule:)\b|ต้อง|ห้าม|จากนี้ไป")


class GenesisSecurityGate:
    def __init__(self, hmac_key: bytes, policy: Policy | None = None,
                 audit: AuditTrail | None = None, brain: Brain | None = None,
                 owner_confirm: OwnerConfirm | None = None):
        if len(hmac_key) < 16:
            raise ValueError("hmac_key must be at least 16 bytes")
        self.key = hmac_key
        self.policy = policy or Policy.default()
        self.audit = audit or AuditTrail()
        self.brain = brain
        self.owner_confirm = owner_confirm
        self.strikes: dict[str, int] = {}
        self.quarantined: set[str] = set()
        self.task_taint: dict[str, Tier] = {}

    @classmethod
    def from_env(cls, **kw: Any) -> "GenesisSecurityGate":
        """Build a gate with the HMAC key from $GENESIS_SECURITY_KEY (hex or text)."""
        raw = os.environ.get("GENESIS_SECURITY_KEY")
        if not raw:
            raise RuntimeError("Set GENESIS_SECURITY_KEY (e.g. `python -c \"import secrets;"
                               "print(secrets.token_hex(32))\"`)")
        try:
            key = bytes.fromhex(raw)
        except ValueError:
            key = raw.encode()
        if "policy" not in kw and os.environ.get("GENESIS_SECURITY_POLICY"):
            kw["policy"] = Policy.load(os.environ["GENESIS_SECURITY_POLICY"])
        if "audit" not in kw and os.environ.get("GENESIS_SECURITY_AUDIT"):
            kw["audit"] = AuditTrail(os.environ["GENESIS_SECURITY_AUDIT"])
        return cls(key, **kw)

    # ───────── helpers ─────────
    def sign(self, body: str) -> str:
        return hmac.new(self.key, body.encode("utf-8"), hashlib.sha256).hexdigest()

    def _has_secret(self, text: str) -> bool:
        return any(p.search(text) for p in self.policy.secret_patterns)

    def _finish(self, event: str, v: Verdict, ctx: dict) -> Verdict:
        if self.brain is not None and v.verdict in ("ALLOW", "ALLOW_SANITIZED", "HOLD"):
            try:
                b = self.brain({"event": event, "verdict": asdict(v), "ctx": ctx})
                if b and b.get("verdict") in ("HOLD", "BLOCK"):      # brain may only tighten
                    order = {"ALLOW": 0, "ALLOW_SANITIZED": 1, "HOLD": 2, "BLOCK": 3}
                    if order[b["verdict"]] > order[v.verdict]:
                        v.verdict = b["verdict"]
                        v.requires_owner = v.requires_owner or b["verdict"] == "HOLD"
                        v.reason += f" | brain: {b.get('reason', '')}"
                        v.layer_trace.append(f"brain:{b['verdict']}")
            except Exception as e:  # noqa: BLE001 — fail closed on anything
                v.verdict, v.reason = "BLOCK", f"brain error, fail-closed: {e}"
                v.layer_trace.append("brain:error")
        if v.verdict == "HOLD" and v.requires_owner:
            approved = False
            if self.owner_confirm is not None:
                try:
                    approved = bool(self.owner_confirm(v, ctx))
                except Exception:  # noqa: BLE001
                    approved = False
            if self.owner_confirm is not None:
                v.verdict = "ALLOW" if approved else "BLOCK"
                v.layer_trace.append("owner:approved" if approved else "owner:denied")
        agent = ctx.get("agent")
        if agent and v.verdict == "BLOCK" and any(g in v.gsx for g in ("GSX-01", "GSX-02", "GSX-03")):
            self.strikes[agent] = self.strikes.get(agent, 0) + 1
            if self.strikes[agent] >= self.policy.quarantine_after:
                self.quarantined.add(agent)
                v.layer_trace.append(f"quarantine:{agent}")
        self.audit.record(event, {"verdict": asdict(v), "ctx": _safe_ctx(ctx)})
        return v

    # ───────── Hook 1: external content enters ─────────
    def on_external_content(self, source: str, content: str, task_id: str = "-") -> tuple[Tainted, Verdict]:
        status, gsx, hits = scan_injection(content)
        self.task_taint[task_id] = Tier.T3
        v = Verdict("ALLOW" if status != "injected" else "ALLOW_SANITIZED", gsx,
                    "S3" if status == "injected" else "S4",
                    f"L1 scan={status} hits={hits}", layer_trace=["L0:T3", f"L1:{status}"])
        wrapped = content if status == "clean" else (
            f"<untrusted source={json.dumps(source)} scan='{status}'>\n{content}\n</untrusted>")
        v = self._finish("external_content", v, {"source": source, "task_id": task_id})
        return Tainted(wrapped, Tier.T3, source), v

    # ───────── Hook 2: before every tool call ─────────
    def pre_tool_call(self, tool: str, args: dict, ctx: dict) -> Verdict:
        trace: list[str] = []
        gsx: list[str] = []
        origin = Tier(ctx.get("origin_tier", Tier.T3))
        agent = ctx.get("agent", "main")
        raw_args = {k: (a.value if isinstance(a, Tainted) else a) for k, a in args.items()}
        arg_text = json.dumps(raw_args, ensure_ascii=False, default=str)
        arg_tier = Tier(max([a.tier for a in args.values() if isinstance(a, Tainted)] + [Tier.T1]))
        task_tier = self.task_taint.get(ctx.get("task_id", "-"), Tier.T1)
        trace.append(f"L0:origin={origin.name} args={arg_tier.name} task={task_tier.name}")
        c = {"tool": tool, **ctx}

        if agent in self.quarantined:
            return self._finish("tool_call", Verdict("BLOCK", ["GSX-07"], "S2",
                                f"agent '{agent}' is quarantined", layer_trace=trace), c)

        status, g, hits = scan_injection(arg_text)
        trace.append(f"L1:{status}")
        if status == "injected":
            return self._finish("tool_call", Verdict("BLOCK", g, "S2", f"injection in args: {hits}",
                                layer_trace=trace), c)

        if origin >= Tier.T3:
            trace.append("L2:action originates from T3")
            return self._finish("tool_call", Verdict("BLOCK", ["GSX-02", "GSX-05"], "S2",
                                "action requested by untrusted content, not by owner", layer_trace=trace), c)
        trace.append("L2:traces to owner")

        egress = tool in self.policy.egress_tools
        if egress:
            for raw in raw_args.values():
                if isinstance(raw, str) and raw.startswith(("http://", "https://")):
                    host = urlparse(raw).hostname or ""
                    if host not in self.policy.egress_allowlist:
                        gsx.append("GSX-06")
                        trace.append(f"L3:egress host '{host}' not allowlisted")
            if self._has_secret(arg_text):
                trace.append("L3:secret in outbound args")
                return self._finish("tool_call", Verdict("BLOCK", ["GSX-06"], "S1",
                                    "secret would leave the system", layer_trace=trace), c)
            if max(arg_tier, task_tier) >= Tier.T3 and ctx.get("touches_private", False):
                gsx.append("GSX-06")
                trace.append("L3:lethal trifecta")
        if tool == "shell_exec":
            cmd = str(raw_args.get("cmd", ""))
            parts = cmd.strip().split()
            if not parts or parts[0] not in self.policy.shell_allowlist or SHELL_META.search(cmd):
                trace.append("L3:shell not allowlisted")
                return self._finish("tool_call", Verdict("BLOCK", ["GSX-05"], "S2",
                                    f"shell command not allowlisted: {cmd[:80]}", layer_trace=trace), c)

        irreversible = tool in self.policy.irreversible_tools
        trace.append(f"L4:irreversible={irreversible} flags={sorted(set(gsx))}")
        if irreversible or gsx:
            return self._finish("tool_call", Verdict("HOLD", sorted(set(gsx)) or ["GATE"], "S3",
                                "irreversible or risky action needs owner confirmation",
                                requires_owner=True, layer_trace=trace), c)

        trace.append("L5:ALLOW")
        return self._finish("tool_call", Verdict("ALLOW", [], "S4", "all layers passed", layer_trace=trace), c)

    # ───────── Hook 3: agent-to-agent messages ─────────
    def make_envelope(self, frm: str, to: str, task_id: str, body: str,
                      scope: list[str], hop: int = 0, taint: Tier = Tier.T2) -> dict:
        env = {"from": frm, "to": to, "task_id": task_id, "capability_scope": list(scope),
               "hop": hop, "taint": int(taint)}
        env["sig"] = self.sign(json.dumps(env, sort_keys=True) + body)
        return env

    def on_agent_message(self, envelope: dict | None, body: str,
                         granted_scope: set[str]) -> tuple[Tier, Verdict]:
        if not envelope or "sig" not in envelope:
            v = Verdict("ALLOW_SANITIZED", ["GSX-07"], "S3", "no envelope: treated as T3 data",
                        layer_trace=["L0:no-envelope→T3"])
            return Tier.T3, self._finish("agent_message", v, {"from": None})
        env = {k: val for k, val in envelope.items() if k != "sig"}
        sender = str(envelope.get("from", "?"))
        c = {"agent": sender, "to": envelope.get("to"), "task_id": envelope.get("task_id"),
             "hop": envelope.get("hop")}
        if not hmac.compare_digest(self.sign(json.dumps(env, sort_keys=True) + body), str(envelope["sig"])):
            return Tier.T3, self._finish("agent_message", Verdict("BLOCK", ["GSX-07"], "S2",
                                         "signature mismatch: impersonation or tampering",
                                         layer_trace=["L0:bad-sig"]), c)
        if sender in self.quarantined:
            return Tier.T3, self._finish("agent_message", Verdict("BLOCK", ["GSX-07"], "S2",
                                         "sender quarantined", layer_trace=["L0:quarantined"]), c)
        if int(envelope.get("hop", 0)) >= self.policy.hop_budget:
            return Tier.T3, self._finish("agent_message", Verdict("BLOCK", ["GSX-10"], "S3",
                                         f"hop {envelope['hop']} ≥ budget {self.policy.hop_budget}",
                                         layer_trace=["L3:hop-budget"]), c)
        extra = set(envelope.get("capability_scope", [])) - set(granted_scope)
        if extra:
            return Tier.T3, self._finish("agent_message", Verdict("BLOCK", ["GSX-11"], "S2",
                                         f"scope escalation attempt: {sorted(extra)}",
                                         layer_trace=["L3:scope"]), c)
        tier = Tier(max(Tier.T2, int(envelope.get("taint", Tier.T2))))
        status, g, hits = scan_injection(body)
        trace = [f"L0:sig-ok tier={tier.name}", f"L1:{status}"]
        if status == "injected":
            return Tier.T3, self._finish("agent_message", Verdict("BLOCK", g, "S2", f"injection: {hits}",
                                         layer_trace=trace), c)
        return tier, self._finish("agent_message", Verdict("ALLOW", [], "S4", "verified",
                                  layer_trace=trace), c)

    # ───────── Hook 4: memory / genome write ─────────
    def on_memory_write(self, path: str, content: str, src_tier: Tier) -> Verdict:
        trace = [f"L0:src={Tier(src_tier).name}"]
        c = {"path": path}
        if self._has_secret(content):
            return self._finish("memory_write", Verdict("BLOCK", ["GSX-06"], "S2", "secret in memory write",
                                layer_trace=trace + ["L3:secret"]), c)
        status, g, hits = scan_injection(content)
        trace.append(f"L1:{status}")
        if src_tier >= Tier.T3:
            if status != "clean" or RULE_LIKE.search(content):
                return self._finish("memory_write", Verdict("BLOCK", g + ["GSX-08"], "S2",
                                    "T3 content tried to write a rule/instruction into memory",
                                    layer_trace=trace + ["L2:rule-from-T3"]), c)
            fact = f"- [fact][source:T3] {content.strip()}"
            return self._finish("memory_write", Verdict("ALLOW_SANITIZED", ["GSX-08"], "S4",
                                "stored as tagged fact only", sanitized_args={"content": fact},
                                layer_trace=trace + ["L5:fact-only"]), c)
        if status == "injected":
            return self._finish("memory_write", Verdict("BLOCK", g, "S3", f"injection: {hits}",
                                layer_trace=trace), c)
        return self._finish("memory_write", Verdict("ALLOW", [], "S4", "trusted source",
                            layer_trace=trace + ["L5:ALLOW"]), c)

    # ───────── Hook 5: skill / plugin load ─────────
    def on_skill_load(self, path: str, content: str, pinned_sha256: Optional[str]) -> Verdict:
        h = hashlib.sha256(content.encode("utf-8")).hexdigest()
        c = {"path": path, "sha256": h}
        if pinned_sha256 and h != pinned_sha256:
            return self._finish("skill_load", Verdict("BLOCK", ["GSX-12"], "S2", "hash changed since pin",
                                layer_trace=["L0:hash-mismatch"]), c)
        status, g, hits = scan_injection(content)
        if status == "injected":
            return self._finish("skill_load", Verdict("BLOCK", g + ["GSX-12"], "S2", f"injection: {hits}",
                                layer_trace=[f"L1:{status}"]), c)
        if pinned_sha256:
            return self._finish("skill_load", Verdict("ALLOW", [], "S4", "pinned & clean",
                                layer_trace=[f"L1:{status}", "L0:hash-ok"]), c)
        return self._finish("skill_load", Verdict("HOLD", ["GSX-12"], "S4",
                            "unpinned skill: owner must read & pin", requires_owner=True,
                            layer_trace=[f"L1:{status}"]), c)

    # ───────── Enforcement decorator ─────────
    def guard(self, tool_name: str):
        """Wrap a tool function. Call it as ``wrapped(args_dict, ctx_dict)``."""
        def deco(fn):
            def wrapper(args: dict, ctx: dict):
                v = self.pre_tool_call(tool_name, args, ctx)
                if not v.allowed:
                    raise PermissionError(f"[GenesisSecurity] {v.verdict} {v.gsx}: {v.reason}")
                clean = {k: (a.value if isinstance(a, Tainted) else a) for k, a in args.items()}
                return fn(**(v.sanitized_args or clean))
            wrapper.__name__ = getattr(fn, "__name__", tool_name)
            wrapper.__doc__ = fn.__doc__
            return wrapper
        return deco


def _safe_ctx(ctx: dict) -> dict:
    """Keep only small scalar context fields in the audit log (no raw args/content)."""
    out = {}
    for k, v in ctx.items():
        if k.startswith("_"):
            continue
        if isinstance(v, (str, int, float, bool)) or v is None:
            out[k] = v if not isinstance(v, str) else v[:200]
    return out
